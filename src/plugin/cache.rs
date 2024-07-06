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
    get_step_conf, get_str_conf, get_str_slice_conf, Error, Plugin, Result,
};
use crate::cache::{new_file_cache, new_tiny_ufo_cache, HttpCache};
use crate::config::{
    get_current_config, PluginCategory, PluginConf, PluginStep,
};
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use bytesize::ByteSize;
use http::Method;
use humantime::parse_duration;
use once_cell::sync::{Lazy, OnceCell};
use pingora::cache::eviction::simple_lru::Manager;
use pingora::cache::eviction::EvictionManager;
use pingora::cache::lock::CacheLock;
use pingora::cache::predictor::{CacheablePredictor, Predictor};
use pingora::cache::Storage;
use pingora::proxy::Session;
use std::str::FromStr;
use std::time::Duration;
use tracing::debug;

static CACHE_BACKEND: OnceCell<HttpCache> = OnceCell::new();
static PREDICTOR: Lazy<Predictor<32>> = Lazy::new(|| Predictor::new(128, None));
// meomory limit size
const MAX_MEMORY_SIZE: usize = 100 * 1024 * 1024;
static EVICTION_MANAGER: Lazy<Manager> = Lazy::new(|| {
    let size = if let Some(cache_max_size) =
        get_current_config().basic.cache_max_size
    {
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
    max_ttl: Option<Duration>,
    namespace: Option<String>,
    headers: Option<Vec<String>>,
}

impl TryFrom<&PluginConf> for Cache {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let cache = CACHE_BACKEND.get_or_try_init(|| {
            let basic_conf = &get_current_config().basic;
            let size = if let Some(cache_max_size) = basic_conf.cache_max_size {
                cache_max_size.as_u64() as usize
            } else {
                MAX_MEMORY_SIZE
            };
            let cache = if let Some(dir) = &basic_conf.cache_directory {
                new_file_cache(dir.as_str()).map_err(|e| Error::Invalid {
                    category: "cache_backend".to_string(),
                    message: e.to_string(),
                })?
            } else {
                new_tiny_ufo_cache(size.min(ByteSize::gb(1).as_u64() as usize))
            };
            Ok(cache)
        })?;
        let step = get_step_conf(value);

        let lock = get_str_conf(value, "lock");
        let lock = if !lock.is_empty() {
            parse_duration(&lock).map_err(|e| Error::Invalid {
                category: PluginCategory::Cache.to_string(),
                message: e.to_string(),
            })?
        } else {
            Duration::from_secs(1)
        };

        let max_ttl = get_str_conf(value, "max_ttl");
        let max_ttl = if !max_ttl.is_empty() {
            Some(parse_duration(&max_ttl).map_err(|e| Error::Invalid {
                category: PluginCategory::Cache.to_string(),
                message: e.to_string(),
            })?)
        } else {
            None
        };

        let max_file_size = get_str_conf(value, "max_file_size");
        let max_file_size = if !max_file_size.is_empty() {
            ByteSize::from_str(&max_file_size).map_err(|e| Error::Invalid {
                category: PluginCategory::Cache.to_string(),
                message: e.to_string(),
            })?
        } else {
            ByteSize::mb(1)
        };
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
        let params = Self {
            storage: cache,
            plugin_step: step,
            eviction: value.contains_key("eviction"),
            predictor: value.contains_key("predictor"),
            lock: lock.as_secs().max(1) as u8,
            max_ttl,
            max_file_size: max_file_size.as_u64() as usize,
            namespace,
            headers,
        };
        if params.plugin_step != PluginStep::Request {
            return Err(Error::Invalid {
                category: PluginCategory::Cache.to_string(),
                message: "Cache plugin should be executed at request step"
                    .to_string(),
            });
        }
        Ok(params)
    }
}

impl Cache {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new http cache plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for Cache {
    #[inline]
    fn step(&self) -> String {
        self.plugin_step.to_string()
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::Cache
    }
    #[inline]
    async fn handle_request(
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
        ctx.cache_max_ttl = self.max_ttl;
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
        let predictor: Option<&'static (dyn CacheablePredictor + Sync)> =
            if self.predictor {
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
            let prefix =
                std::str::from_utf8(&keys).unwrap_or_default().to_string();
            debug!("Cache prefix: {prefix}");
            ctx.cache_prefix = Some(prefix);
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::Cache;
    use crate::config::{PluginConf, PluginStep};
    use crate::plugin::Plugin;
    use crate::state::State;
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    #[test]
    fn test_cache_params() {
        let params = Cache::try_from(
            &toml::from_str::<PluginConf>(
                r###"
eviction = true
headers = ["Accept-Encoding"]
lock = "2s"
max_file_size = "100kb"
predictor = true
max_ttl = "1m"
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(true, params.eviction);
        assert_eq!(
            r#"Some(["Accept-Encoding"])"#,
            format!("{:?}", params.headers)
        );
        assert_eq!(2, params.lock);
        assert_eq!(100 * 1000, params.max_file_size);
        assert_eq!(60, params.max_ttl.unwrap().as_secs());
        assert_eq!(true, params.predictor);
    }
    #[tokio::test]
    async fn test_cache() {
        let cache = Cache::try_from(
            &toml::from_str::<PluginConf>(
                r###"
namespace = "pingap"
eviction = true
headers = ["Accept-Encoding"]
lock = "2s"
max_file_size = "100kb"
predictor = true
max_ttl = "1m"
"###,
            )
            .unwrap(),
        )
        .unwrap();

        assert_eq!("request", cache.step().to_string());
        assert_eq!("cache", cache.category().to_string());

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header =
            format!("GET /vicanso/pingap?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let mut ctx = State::default();
        cache
            .handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .unwrap();
        assert_eq!("pingap:gzip:", ctx.cache_prefix.unwrap());
        assert_eq!(true, session.cache.enabled());
        assert_eq!(100 * 1000, cache.max_file_size);
    }
}
