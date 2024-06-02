// Copyright 2024 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::{
    get_int_conf, get_step_conf, get_str_conf, get_str_slice_conf, Error, ProxyPlugin, Result,
};
use crate::config::{get_current_config, PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use bytesize::ByteSize;
use http::Method;
use log::debug;
use once_cell::sync::Lazy;
use pingora::cache::eviction::simple_lru::Manager;
use pingora::cache::eviction::EvictionManager;
use pingora::cache::lock::CacheLock;
use pingora::cache::predictor::{CacheablePredictor, Predictor};
use pingora::cache::{MemCache, Storage};
use pingora::proxy::Session;
use std::str::FromStr;
use url::Url;

// TODO mem cache is for test
static MEM_BACKEND: Lazy<MemCache> = Lazy::new(MemCache::new);
static PREDICTOR: Lazy<Predictor<32>> = Lazy::new(|| Predictor::new(128, None));
// meomory limit size
const MAX_MEMORY_SIZE: usize = 100 * 1024 * 1024;
static EVICTION_MANAGER: Lazy<Manager> = Lazy::new(|| {
    let size = if let Some(cache_max_size) = get_current_config().basic.cache_max_size {
        cache_max_size.as_u64() as usize
    } else {
        MAX_MEMORY_SIZE
    };
    Manager::new(size)
});
static CACHE_LOCK_ONE_SECOND: Lazy<CacheLock> =
    Lazy::new(|| CacheLock::new(std::time::Duration::from_secs(1)));
static CACHE_LOCK_TWO_SECONDS: Lazy<CacheLock> =
    Lazy::new(|| CacheLock::new(std::time::Duration::from_secs(2)));
static CACHE_LOCK_THREE_SECONDS: Lazy<CacheLock> =
    Lazy::new(|| CacheLock::new(std::time::Duration::from_secs(3)));

pub struct Cache {
    plugin_step: PluginStep,
    eviction: bool,
    predictor: bool,
    lock: u8,
    storage: &'static (dyn Storage + Sync),
    max_file_size: usize,
    namespace: Option<String>,
    headers: Option<Vec<String>>,
}

struct CacheParams {
    plpugin_step: PluginStep,
    eviction: bool,
    predictor: bool,
    lock: u8,
    max_file_size: usize,
    namespace: Option<String>,
    headers: Option<Vec<String>>,
}

impl TryFrom<&PluginConf> for CacheParams {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let step = get_step_conf(value);
        let all_params = get_str_conf(value, "value");
        let params = if !all_params.is_empty() {
            let url_info = Url::parse(&all_params).map_err(|e| Error::Invalid {
                category: PluginCategory::Cache.to_string(),
                message: e.to_string(),
            })?;
            let mut lock = 0;
            let mut eviction = false;
            let mut predictor = false;
            let mut max_file_size = 100 * 1024;
            let mut namespace = None;
            let mut headers = None;
            for (key, value) in url_info.query_pairs().into_iter() {
                match key.as_ref() {
                    "lock" => {
                        if let Ok(d) = value.parse::<u8>() {
                            lock = d;
                        }
                    }
                    "max_file_size" => {
                        if let Ok(v) = ByteSize::from_str(&value) {
                            max_file_size = v.0 as usize;
                        }
                    }
                    "eviction" => eviction = true,
                    "predictor" => predictor = true,
                    "namespace" => namespace = Some(value.to_string()),
                    "headers" => {
                        headers = Some(
                            value
                                .trim()
                                .split(',')
                                .map(|item| item.to_string())
                                .collect(),
                        )
                    }
                    _ => {}
                }
            }
            Self {
                plpugin_step: step,
                eviction,
                predictor,
                lock,
                max_file_size,
                namespace,
                headers,
            }
        } else {
            let lock = get_int_conf(value, "lock") as u8;
            let max_file_size = get_int_conf(value, "max_file_size") as usize;
            let namespace = get_str_conf(value, "namespace");
            let namespace = if namespace.is_empty() {
                None
            } else {
                Some(namespace)
            };
            let headers = get_str_slice_conf(value, "headers");
            let headers = if headers.is_empty() {
                None
            } else {
                Some(headers)
            };
            Self {
                plpugin_step: step,
                eviction: value.contains_key("eviction"),
                predictor: value.contains_key("predictor"),
                lock: lock.max(1),
                max_file_size: max_file_size.max(5 * 1024 * 1024),
                namespace,
                headers,
            }
        };
        if params.plpugin_step != PluginStep::Request {
            return Err(Error::Invalid {
                category: PluginCategory::Cache.to_string(),
                message: "Cache plugin should be executed at request step".to_string(),
            });
        }
        Ok(params)
    }
}

impl Cache {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!("new cache storage proxy plugin, params:{params:?}");
        let params = CacheParams::try_from(params)?;

        Ok(Self {
            storage: &*MEM_BACKEND,
            plugin_step: params.plpugin_step,
            eviction: params.eviction,
            lock: params.lock,
            max_file_size: params.max_file_size,
            namespace: params.namespace,
            headers: params.headers,
            predictor: params.predictor,
        })
    }
}

#[async_trait]
impl ProxyPlugin for Cache {
    #[inline]
    fn step(&self) -> String {
        self.plugin_step.to_string()
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::Cache
    }
    #[inline]
    async fn handle(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if step != self.plugin_step {
            return Ok(None);
        }
        if ![Method::GET, Method::HEAD].contains(&session.req_header().method) {
            return Ok(None);
        }
        let eviction = if self.eviction {
            None
        } else {
            Some(&*EVICTION_MANAGER as &'static (dyn EvictionManager + Sync))
        };

        let lock = match self.lock {
            1 => Some(&*CACHE_LOCK_ONE_SECOND),
            2 => Some(&*CACHE_LOCK_TWO_SECONDS),
            3 => Some(&*CACHE_LOCK_THREE_SECONDS),
            _ => None,
        };
        let predictor: Option<&'static (dyn CacheablePredictor + Sync)> = if self.predictor {
            Some(&*PREDICTOR)
        } else {
            None
        };
        session
            .cache
            .enable(self.storage, eviction, predictor, lock);
        if self.max_file_size > 0 {
            session.cache.set_max_file_size_bytes(self.max_file_size);
        }
        let mut keys = BytesMut::with_capacity(64);
        if let Some(namespace) = &self.namespace {
            keys.put(namespace.as_bytes());
            keys.put(&b":"[..]);
        }
        if let Some(headers) = &self.headers {
            for key in headers.iter() {
                let buf = session.get_header_bytes(key);
                if !buf.is_empty() {
                    keys.put(buf);
                    keys.put(&b":"[..]);
                }
            }
        }
        if !keys.is_empty() {
            let prefix = std::string::String::from_utf8_lossy(&keys).to_string();
            debug!("Cache prefix:{prefix}");
            ctx.cache_prefix = Some(prefix);
        }

        Ok(None)
    }
}
