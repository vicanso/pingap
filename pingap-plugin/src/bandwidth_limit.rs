// Copyright 2024-2025 Tree xie.
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

use super::{Error, get_hash_key, get_str_conf};
use async_trait::async_trait;
use bytesize::ByteSize;
use fancy_regex::Regex;
use pingap_config::PluginConf;
use pingap_core::{BodyPace, Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::str::FromStr;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

const CATEGORY: &str = "bandwidth_limit";

/// Sends the body of a response no faster than so many bytes a second.
///
/// For a site that hands out large files: without it one client on a
/// fast line takes all the bandwidth there is, for as long as its
/// download lasts. The limit is per response, not per client: whoever
/// opens four connections gets four times the rate.
///
/// The plugin only says how fast. The pace is kept where a body is
/// written: by the proxy for a response from the upstream or the cache,
/// and by the `directory` plugin for a file it streams.
pub struct BandwidthLimit {
    /// Bytes a second.
    rate: u64,
    /// So many bytes of each response go out as fast as they can: a page
    /// is not slowed down for being served from the same place as a
    /// download.
    after: u64,
    /// Only requests whose path matches, where one is given.
    path: Option<Regex>,
    hash_value: String,
}

impl TryFrom<&PluginConf> for BandwidthLimit {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let invalid = |message: String| Error::Invalid {
            category: CATEGORY.to_string(),
            message,
        };
        let size = |key: &str| -> Result<Option<u64>> {
            let text = get_str_conf(value, key);
            let text = text.trim();
            if text.is_empty() {
                return Ok(None);
            }
            ByteSize::from_str(text)
                .map(|size| Some(size.as_u64()))
                .map_err(|e| invalid(format!("invalid {key}({text}): {e}")))
        };
        // No rate is no limit, and a plugin that does nothing is a slip.
        let rate = size("rate")?.filter(|rate| *rate > 0).ok_or_else(|| {
            invalid(
                "rate should be a size per second, more than 0 (like 1mb)"
                    .to_string(),
            )
        })?;
        let path = get_str_conf(value, "path");
        let path = if path.is_empty() {
            None
        } else {
            Some(
                Regex::new(&path)
                    .map_err(|e| invalid(format!("invalid path: {e}")))?,
            )
        };
        Ok(Self {
            rate,
            after: size("after")?.unwrap_or_default(),
            path,
            hash_value,
        })
    }
}

impl BandwidthLimit {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = pingap_config::masked_toml(params),
            "new bandwidth limit plugin"
        );
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for BandwidthLimit {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != PluginStep::Request {
            return Ok(RequestPluginResult::Skipped);
        }
        if let Some(path) = &self.path
            && !path
                .is_match(session.req_header().uri.path())
                .unwrap_or_default()
        {
            return Ok(RequestPluginResult::Skipped);
        }
        ctx.features.get_or_insert_default().body_pace =
            Some(BodyPace::new(self.rate, self.after));
        Ok(RequestPluginResult::Continue)
    }
}

register_plugin!("bandwidth_limit", BandwidthLimit);

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    fn new_plugin(conf: &str) -> Result<BandwidthLimit> {
        BandwidthLimit::new(&toml::from_str::<PluginConf>(conf).unwrap())
    }

    #[test]
    fn test_bandwidth_limit_params() {
        let plugin = new_plugin("rate = \"100kb\"").unwrap();
        assert_eq!((100_000, 0), (plugin.rate, plugin.after));
        let plugin = new_plugin(
            "rate = \"1 MiB\"\nafter = \"512kib\"\npath = \"^/files/\"",
        )
        .unwrap();
        assert_eq!((1024 * 1024, 512 * 1024), (plugin.rate, plugin.after));
        assert_eq!(true, plugin.path.is_some());

        for (conf, message) in [
            ("", "rate should be a size per second"),
            ("rate = \"0\"", "rate should be a size per second"),
            ("rate = \"fast\"", "invalid rate(fast)"),
            ("rate = \"1mb\"\nafter = \"soon\"", "invalid after(soon)"),
            ("rate = \"1mb\"\npath = \"(\"", "invalid path"),
        ] {
            let error = new_plugin(conf).err().unwrap().to_string();
            assert_eq!(true, error.contains(message), "{conf}: {error}");
        }
    }

    /// The plugin leaves the pace for whoever writes the body, on the
    /// requests it is for.
    #[tokio::test]
    async fn test_bandwidth_limit_sets_the_pace() {
        let plugin =
            new_plugin("rate = \"1kb\"\nafter = \"2kb\"\npath = \"^/files/\"")
                .unwrap();
        let paced = async |target: &str, step: PluginStep| {
            let input = format!("GET {target} HTTP/1.1\r\n\r\n");
            let mock_io = Builder::new().read(input.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let mut ctx = Ctx::default();
            plugin
                .handle_request(step, &mut session, &mut ctx)
                .await
                .unwrap();
            ctx.features.and_then(|features| features.body_pace)
        };
        assert_eq!(
            true,
            paced("/files/big.iso", PluginStep::Request).await.is_some()
        );
        assert_eq!(
            true,
            paced("/index.html", PluginStep::Request).await.is_none()
        );
        assert_eq!(
            true,
            paced("/files/big.iso", PluginStep::ProxyUpstream)
                .await
                .is_none()
        );
        // What it leaves there is the limit it was given: the first two
        // thousand bytes at once, a thousand a second after that.
        let mut pace =
            paced("/files/big.iso", PluginStep::Request).await.unwrap();
        assert_eq!(None, pace.delay(2000));
        let delay = pace.delay(500).unwrap();
        assert_eq!(true, (100..=500).contains(&delay.as_millis()), "{delay:?}");
    }
}
