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

use super::{
    DryRun, Error, RestrictionCategory, get_hash_key,
    get_restriction_category_conf, get_str_conf, get_str_slice_conf,
};
use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use pingap_config::PluginConf;
use pingap_core::{Ctx, HttpResponse, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use regex::RegexSet;
use std::borrow::Cow;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

const CATEGORY: &str = "ja4_restriction";

/// Lets requests through or turns them away by the JA4 fingerprint of
/// their TLS connection: what the client's TLS stack is, whatever its
/// `User-Agent` says. A script that calls itself a browser still shakes
/// hands the way its library does.
///
/// The fingerprint is there only on a TLS connection to a server with
/// `ja4 = true`. A request without one matches nothing: an allow list
/// turns it away, a deny list lets it through.
pub struct Ja4Restriction {
    plugin_step: PluginStep,
    /// The patterns, compiled into one set. A fingerprint written out in
    /// full is a pattern that matches itself.
    ja4_list: RegexSet,
    restriction_category: RestrictionCategory,
    forbidden_resp: HttpResponse,
    /// Requests are let through and the refusal is only logged.
    dry_run: DryRun,
    hash_value: String,
}

impl TryFrom<&PluginConf> for Ja4Restriction {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let invalid = |message: String| Error::Invalid {
            category: CATEGORY.to_string(),
            message,
        };
        let patterns = get_str_slice_conf(value, "ja4_list");
        // An empty allow list turns everything away, an empty deny list
        // nothing: either is a list that was not filled in.
        if patterns.is_empty() {
            return Err(invalid("ja4_list is required".to_string()));
        }
        let ja4_list = RegexSet::new(&patterns)
            .map_err(|e| invalid(format!("ja4_list: {e}")))?;

        let mut message = get_str_conf(value, "message");
        if message.is_empty() {
            message = "Request is forbidden".to_string();
        }

        Ok(Self {
            hash_value: get_hash_key(value),
            plugin_step: PluginStep::Request,
            ja4_list,
            restriction_category: get_restriction_category_conf(
                value, CATEGORY,
            )?,
            forbidden_resp: HttpResponse {
                status: StatusCode::FORBIDDEN,
                body: Bytes::from(message),
                ..Default::default()
            },
            dry_run: DryRun::new(value),
        })
    }
}

impl Ja4Restriction {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = pingap_config::masked_toml(params),
            "new ja4 restriction plugin"
        );
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for Ja4Restriction {
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
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }
        let found = ctx
            .conn
            .ja4
            .as_ref()
            .is_some_and(|ja4| self.ja4_list.is_match(ja4.ja4()));
        if !self.restriction_category.allows(found) {
            let fingerprint = |ctx: &mut Ctx| {
                ctx.conn
                    .ja4
                    .as_ref()
                    .map(|ja4| ja4.ja4().to_string())
                    .unwrap_or_default()
            };
            return Ok(self.dry_run.refuse(
                CATEGORY,
                session,
                ctx,
                self.forbidden_resp.clone(),
                fingerprint,
            ));
        }
        Ok(RequestPluginResult::Continue)
    }
}

register_plugin!("ja4_restriction", Ja4Restriction);

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_core::Ja4Fingerprint;
    use pingap_core::ja4::testing::{client_hello_body, spec_example_body};
    use pretty_assertions::assert_eq;
    use std::sync::Arc;
    use tokio_test::io::Builder;

    /// The fingerprint of the specification's example, a browser.
    const BROWSER: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";
    /// One of a hello with nothing in it, as a script might send.
    const SCRIPT: &str = "t00i000000_000000000000_000000000000";

    fn new_plugin(conf: &str) -> Result<Ja4Restriction> {
        Ja4Restriction::new(&toml::from_str::<PluginConf>(conf).unwrap())
    }

    /// The context of a request on a connection with the fingerprint of
    /// `hello`, or on one without.
    fn ctx_of(hello: Option<Vec<u8>>) -> Ctx {
        let mut ctx = Ctx::default();
        ctx.conn.ja4 = hello
            .and_then(|hello| Ja4Fingerprint::from_client_hello(&hello))
            .map(Arc::new);
        ctx
    }

    fn browser() -> Option<Vec<u8>> {
        Some(spec_example_body())
    }

    fn script() -> Option<Vec<u8>> {
        Some(client_hello_body(0x9999, &[], Some(&[])))
    }

    async fn run(
        plugin: &Ja4Restriction,
        ctx: &mut Ctx,
    ) -> RequestPluginResult {
        let input = b"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mock_io = Builder::new().read(input).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        plugin
            .handle_request(PluginStep::Request, &mut session, ctx)
            .await
            .unwrap()
    }

    #[test]
    fn test_ja4_restriction_params() {
        let plugin = new_plugin(&format!(
            "ja4_list = [\"{SCRIPT}\", \"^t12\"]\ntype = \"deny\"\n"
        ))
        .unwrap();
        assert_eq!(RestrictionCategory::Deny, plugin.restriction_category);
        assert_eq!(2, plugin.ja4_list.len());
        assert_eq!(false, plugin.dry_run.is_on());

        // allow is the default, as for the other restrictions
        let plugin =
            new_plugin(&format!("ja4_list = [\"{BROWSER}\"]\n")).unwrap();
        assert_eq!(RestrictionCategory::Allow, plugin.restriction_category);

        assert_eq!(
            "Plugin ja4_restriction invalid, message: ja4_list is required",
            new_plugin("type = \"deny\"\n").err().unwrap().to_string()
        );
        assert_eq!(
            true,
            new_plugin("ja4_list = [\"(\"]\n")
                .err()
                .unwrap()
                .to_string()
                .starts_with(
                    "Plugin ja4_restriction invalid, message: ja4_list:"
                )
        );
        assert_eq!(
            "Plugin ja4_restriction invalid, message: Invalid type(block), expect allow or deny",
            new_plugin("ja4_list = [\"^t13\"]\ntype = \"block\"\n")
                .err()
                .unwrap()
                .to_string()
        );
    }

    #[tokio::test]
    async fn test_ja4_restriction() {
        // the two hellos give the fingerprints the tests are written for
        assert_eq!(BROWSER, ctx_of(browser()).conn.ja4.unwrap().ja4());
        assert_eq!(SCRIPT, ctx_of(script()).conn.ja4.unwrap().ja4());

        let deny = new_plugin(&format!(
            "ja4_list = [\"{SCRIPT}\"]\ntype = \"deny\"\nmessage = \"no scripts\"\n"
        ))
        .unwrap();
        let RequestPluginResult::Respond(resp) =
            run(&deny, &mut ctx_of(script())).await
        else {
            panic!("a listed fingerprint is turned away");
        };
        assert_eq!(StatusCode::FORBIDDEN, resp.status);
        assert_eq!(Bytes::from_static(b"no scripts"), resp.body);
        assert_eq!(
            RequestPluginResult::Continue,
            run(&deny, &mut ctx_of(browser())).await
        );
        // no fingerprint matches nothing: a deny list lets it through
        assert_eq!(
            RequestPluginResult::Continue,
            run(&deny, &mut ctx_of(None)).await
        );

        // a pattern: every TLS 1.3 client with SNI
        let allow = new_plugin("ja4_list = [\"^t13d\"]\n").unwrap();
        assert_eq!(
            RequestPluginResult::Continue,
            run(&allow, &mut ctx_of(browser())).await
        );
        let RequestPluginResult::Respond(resp) =
            run(&allow, &mut ctx_of(script())).await
        else {
            panic!("a fingerprint the list does not allow is turned away");
        };
        assert_eq!(StatusCode::FORBIDDEN, resp.status);
        // and an allow list turns away what has no fingerprint
        let RequestPluginResult::Respond(_) =
            run(&allow, &mut ctx_of(None)).await
        else {
            panic!("no fingerprint is not one the list allows");
        };
    }

    /// In a dry run what would be turned away goes on.
    #[tokio::test]
    async fn test_ja4_restriction_dry_run() {
        let deny = new_plugin(&format!(
            "ja4_list = [\"{SCRIPT}\"]\ntype = \"deny\"\ndry_run = true\n"
        ))
        .unwrap();
        assert_eq!(true, deny.dry_run.is_on());
        assert_eq!(
            RequestPluginResult::Continue,
            run(&deny, &mut ctx_of(script())).await
        );

        // `dry_run` that is not a boolean is refused, like any value of
        // the wrong type, and not taken for false
        let conf = toml::from_str::<PluginConf>(
            "category = \"ja4_restriction\"\nja4_list = [\"^t13\"]\ndry_run = \"yes\"\n",
        )
        .unwrap();
        assert_eq!(
            "Plugin ja4_restriction invalid, message: dry_run must be true or false, got string \"yes\"",
            crate::get_plugin_factory()
                .create(&conf)
                .err()
                .unwrap()
                .to_string()
        );
    }
}
