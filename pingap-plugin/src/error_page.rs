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

use super::{Error, get_bool_conf, get_hash_key, get_str_slice_conf};
use async_trait::async_trait;
use bytes::Bytes;
use http::header::ACCEPT;
use http::{HeaderValue, StatusCode};
use pingap_config::PluginConf;
use pingap_core::{
    Ctx, HTTP_HEADER_CONTENT_HTML, HTTP_HEADER_CONTENT_JSON,
    HTTP_HEADER_CONTENT_TEXT, Plugin, ResponsePluginResult,
    new_upstream_status_error,
};
use pingora::http::ResponseHeader;
use pingora::proxy::Session;
use std::borrow::Cow;
use tracing::debug;

type Result<T, E = Error> = std::result::Result<T, E>;

const CATEGORY: &str = "error_page";

/// What a page is, which is how the message is written into it.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Kind {
    Html,
    Json,
    Text,
}

impl Kind {
    fn content_type(self) -> HeaderValue {
        match self {
            Kind::Html => HTTP_HEADER_CONTENT_HTML.1.clone(),
            Kind::Json => HTTP_HEADER_CONTENT_JSON.1.clone(),
            Kind::Text => HTTP_HEADER_CONTENT_TEXT.1.clone(),
        }
    }

    /// `text` as it may stand in a page of this kind. What a message
    /// says comes from the request in places - a host nobody serves, a
    /// path - and is not markup, nor the end of a JSON string.
    fn escape(self, text: &str) -> String {
        match self {
            Kind::Text => text.to_string(),
            Kind::Html => {
                let mut out = String::with_capacity(text.len());
                for c in text.chars() {
                    match c {
                        '&' => out.push_str("&amp;"),
                        '<' => out.push_str("&lt;"),
                        '>' => out.push_str("&gt;"),
                        '"' => out.push_str("&quot;"),
                        '\'' => out.push_str("&#39;"),
                        c => out.push(c),
                    }
                }
                out
            },
            // The text of a JSON string, without the quotes around it:
            // those are the page's.
            Kind::Json => {
                let quoted = serde_json::to_string(text).unwrap_or_default();
                quoted
                    .strip_prefix('"')
                    .and_then(|rest| rest.strip_suffix('"'))
                    .unwrap_or_default()
                    .to_string()
            },
        }
    }
}

/// Which statuses a page is for.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Statuses {
    /// One status.
    One(u16),
    /// A hundred of them: `4xx`, `5xx`.
    Class(u16),
}

impl Statuses {
    fn has(self, status: u16) -> bool {
        match self {
            Statuses::One(one) => one == status,
            Statuses::Class(class) => status / 100 == class,
        }
    }
}

struct Page {
    statuses: Statuses,
    kind: Kind,
    /// The page as it was given, `{{status}}` and `{{message}}` in it.
    template: String,
}

impl Page {
    fn render(&self, status: StatusCode, message: &str) -> Bytes {
        let page = self
            .template
            .replace("{{status}}", status.as_str())
            .replace("{{message}}", &self.kind.escape(message));
        Bytes::from(page)
    }
}

/// The pages of a location for the errors the proxy answers itself, in
/// place of the one page of the whole server (`basic.error_template`):
/// an API wants its errors as JSON and a site as a page of its own, and
/// one process serves both.
pub struct ErrorPage {
    /// In the order they are looked at: a page for one status ahead of
    /// one for its hundred.
    pages: Vec<Page>,
    /// A request that asks for JSON gets the error as JSON, whatever
    /// pages there are.
    json: bool,
    /// The pages take the place of what the upstream sends with their
    /// statuses as well, not only of what the proxy answers.
    intercept: bool,
    hash_value: String,
}

/// `value` as the page it is: the content of a file where it is the path
/// of one, and itself otherwise.
fn load_page(value: &str) -> std::result::Result<(Kind, String), String> {
    let is_path = ["/", "~/", "./", "../"]
        .iter()
        .any(|prefix| value.starts_with(prefix));
    if !is_path {
        // By what it starts with. Not `{{`: that is `{{status}}` or
        // `{{message}}` at the head of a line of text, and no object.
        let text = value.trim_start();
        let kind = match text.chars().next() {
            Some('<') => Kind::Html,
            Some('{') if !text.starts_with("{{") => Kind::Json,
            Some('[') => Kind::Json,
            _ => Kind::Text,
        };
        return Ok((kind, value.to_string()));
    }
    // Written as a path: a file that is not there is an error, and not
    // its name as the page.
    let path = pingap_util::resolve_path(value);
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("page {value} can not be read: {e}"))?;
    let kind = match std::path::Path::new(&path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("json") => Kind::Json,
        Some("txt") => Kind::Text,
        _ => Kind::Html,
    };
    Ok((kind, content))
}

impl TryFrom<&PluginConf> for ErrorPage {
    type Error = Error;

    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let invalid = |message: String| Error::Invalid {
            category: CATEGORY.to_string(),
            message,
        };
        let mut pages = vec![];
        for item in get_str_slice_conf(value, "pages").iter() {
            let parsed = item.split_once(':').and_then(|(statuses, page)| {
                let statuses = statuses.trim().to_ascii_lowercase();
                let statuses = match statuses.as_str() {
                    "4xx" => Statuses::Class(4),
                    "5xx" => Statuses::Class(5),
                    one => Statuses::One(
                        one.parse::<u16>()
                            .ok()
                            .filter(|status| (400..600).contains(status))?,
                    ),
                };
                Some((statuses, page.trim()))
            });
            let Some((statuses, page)) =
                parsed.filter(|(_, page)| !page.is_empty())
            else {
                return Err(invalid(format!(
                    "pages: {item:?} should be status:page, the status one from 400 to 599, 4xx or 5xx"
                )));
            };
            if pages.iter().any(|page: &Page| page.statuses == statuses) {
                return Err(invalid(format!(
                    "pages: there are two for {}",
                    item.split(':').next().unwrap_or_default().trim()
                )));
            }
            let (kind, template) = load_page(page).map_err(invalid)?;
            pages.push(Page {
                statuses,
                kind,
                template,
            });
        }
        // The page of one status ahead of the page of its hundred.
        pages.sort_by_key(|page| matches!(page.statuses, Statuses::Class(_)));
        let json = get_bool_conf(value, "json");
        if pages.is_empty() && !json {
            return Err(invalid(
                "there is nothing to answer with: set pages or json"
                    .to_string(),
            ));
        }
        // The statuses taken from the upstream are those of the pages:
        // `json` alone names none, and an API's own `422` with what is
        // wrong in it is not to be lost for the request asking for JSON.
        let intercept = get_bool_conf(value, "intercept");
        if intercept && pages.is_empty() {
            return Err(invalid(
                "intercept takes the statuses of pages from the upstream: set pages"
                    .to_string(),
            ));
        }
        Ok(Self {
            pages,
            json,
            intercept,
            hash_value,
        })
    }
}

/// Whether the request asks for JSON and not for a page: what a script
/// or an API client sends. A browser that takes anything asks for
/// `text/html` first.
fn asks_for_json(session: &Session) -> bool {
    let mut json = false;
    for value in session.req_header().headers.get_all(ACCEPT) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for media in value.split(',') {
            let media = media
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase();
            if media == "text/html" {
                return false;
            }
            if media == "application/json" || media.ends_with("+json") {
                json = true;
            }
        }
    }
    json
}

impl ErrorPage {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(
            params = pingap_config::masked_toml(params),
            "new error page plugin"
        );
        Self::try_from(params)
    }

    /// What this plugin answers `status` with, where it has something.
    fn page(
        &self,
        session: &Session,
        status: StatusCode,
        message: &str,
    ) -> Option<(HeaderValue, Bytes)> {
        if self.json && asks_for_json(session) {
            // Written out, for the status to come first as documented:
            // a map is in the order of its keys.
            let body = format!(
                "{{\"status\":{},\"message\":\"{}\"}}",
                status.as_u16(),
                Kind::Json.escape(message)
            );
            return Some((Kind::Json.content_type(), Bytes::from(body)));
        }
        self.pages
            .iter()
            .find(|page| page.statuses.has(status.as_u16()))
            .map(|page| {
                (page.kind.content_type(), page.render(status, message))
            })
    }
}

#[async_trait]
impl Plugin for ErrorPage {
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    fn error_page(
        &self,
        session: &Session,
        status: StatusCode,
        message: &str,
    ) -> Option<(HeaderValue, Bytes)> {
        self.page(session, status, message)
    }

    /// `intercept`: a response of the upstream with a status a page is
    /// for is answered by the proxy, with that page, and not passed on.
    ///
    /// Said as an error and at this step, so that the response is
    /// dropped whole, header and body, before it is cached or a byte of
    /// it is sent. Exchanging the body alone later does not do: a
    /// response that ends with its header - a `404` with nothing in it -
    /// has no body step for the page to go out with.
    fn handle_upstream_response(
        &self,
        _session: &mut Session,
        _ctx: &mut Ctx,
        upstream_response: &mut ResponseHeader,
    ) -> pingora::Result<ResponsePluginResult> {
        let status = upstream_response.status;
        if !self.intercept
            || !self
                .pages
                .iter()
                .any(|page| page.statuses.has(status.as_u16()))
        {
            return Ok(ResponsePluginResult::Unchanged);
        }
        Err(new_upstream_status_error(status))
    }
}

register_plugin!("error_page", ErrorPage);

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;

    fn new_plugin(conf: &str) -> Result<ErrorPage> {
        ErrorPage::new(&toml::from_str::<PluginConf>(conf).unwrap())
    }

    async fn new_session(headers: &str) -> Session {
        let input = format!("GET /api/users HTTP/1.1\r\n{headers}\r\n");
        let mock_io = Builder::new().read(input.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        session
    }

    fn answer(
        plugin: &ErrorPage,
        session: &Session,
        status: u16,
        message: &str,
    ) -> Option<(String, String)> {
        plugin
            .error_page(session, StatusCode::from_u16(status).unwrap(), message)
            .map(|(content_type, body)| {
                (
                    content_type.to_str().unwrap().to_string(),
                    String::from_utf8(body.to_vec()).unwrap(),
                )
            })
    }

    /// The page of a status, of its hundred, and none: the last is the
    /// server's own page.
    #[tokio::test]
    async fn test_error_pages() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("down.html");
        std::fs::write(&file, "<h1>{{status}}</h1><p>{{message}}</p>").unwrap();
        let plugin = new_plugin(&format!(
            "pages = [\"5xx: {}\", \"404:{{\\\"error\\\":\\\"{{{{message}}}}\\\",\\\"code\\\":{{{{status}}}}}}\", \" 429 : slow down\"]",
            file.display()
        ))
        .unwrap();
        let session = new_session("").await;
        let html = "text/html; charset=utf-8".to_string();
        let json = "application/json; charset=utf-8".to_string();
        let text = "text/plain; charset=utf-8".to_string();

        // the file, for every status of its hundred
        assert_eq!(
            Some((html.clone(), "<h1>502</h1><p>Bad Gateway</p>".to_string())),
            answer(&plugin, &session, 502, "Bad Gateway")
        );
        assert_eq!(
            Some((html.clone(), "<h1>504</h1><p>late</p>".to_string())),
            answer(&plugin, &session, 504, "late")
        );
        // what is written in the configuration itself, as what it is
        assert_eq!(
            Some((
                json.clone(),
                "{\"error\":\"no such page\",\"code\":404}".to_string()
            )),
            answer(&plugin, &session, 404, "no such page")
        );
        assert_eq!(
            Some((text, "slow down".to_string())),
            answer(&plugin, &session, 429, "Too Many Requests")
        );
        // no page for it
        assert_eq!(None, answer(&plugin, &session, 400, "Bad Request"));
        assert_eq!(None, answer(&plugin, &session, 403, "Forbidden"));

        // A message is text, in whatever it is put into.
        assert_eq!(
            Some((
                html,
                "<h1>502</h1><p>&lt;script&gt;&amp;&quot;&#39;</p>".to_string()
            )),
            answer(&plugin, &session, 502, "<script>&\"'")
        );
        assert_eq!(
            Some((
                json,
                "{\"error\":\"a \\\"b\\\"\\nc\",\"code\":404}".to_string()
            )),
            answer(&plugin, &session, 404, "a \"b\"\nc")
        );
    }

    /// `json`: who asks for JSON gets the error as JSON.
    #[tokio::test]
    async fn test_error_page_json() {
        let plugin =
            new_plugin("json = true\npages = [\"5xx:<h1>down</h1>\"]").unwrap();
        let json = "application/json; charset=utf-8".to_string();
        for (accept, expected) in [
            ("Accept: application/json\r\n", true),
            ("Accept: application/json, text/plain, */*\r\n", true),
            ("Accept: application/problem+json;q=0.9\r\n", true),
            ("accept: Application/JSON\r\n", true),
            // a browser
            (
                "Accept: text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8\r\n",
                false,
            ),
            ("Accept: */*\r\n", false),
            ("", false),
        ] {
            let session = new_session(accept).await;
            let (content_type, body) =
                answer(&plugin, &session, 502, "Bad \"Gateway\"").unwrap();
            assert_eq!(expected, content_type == json, "{accept}");
            if expected {
                assert_eq!(
                    "{\"status\":502,\"message\":\"Bad \\\"Gateway\\\"\"}",
                    body
                );
            } else {
                assert_eq!("<h1>down</h1>", body);
            }
        }
        // Also for a status no page is for; a page for those who want one
        // there is none then.
        let session = new_session("Accept: application/json\r\n").await;
        assert_eq!(true, answer(&plugin, &session, 404, "Not Found").is_some());
        let session = new_session("").await;
        assert_eq!(None, answer(&plugin, &session, 404, "Not Found"));
    }

    /// `intercept`: an upstream response with a status a page is for is
    /// stopped where its header comes in, as an error of that status,
    /// which is what the page of the location is then answered for.
    #[tokio::test]
    async fn test_error_page_intercept() {
        let intercept = async |conf: &str, request: &str, status: u16| {
            let plugin = new_plugin(conf).unwrap();
            let input = format!(
                "{request} / HTTP/1.1\r\nAccept: application/json\r\n\r\n"
            );
            let mock_io = Builder::new().read(input.as_bytes()).build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let mut ctx = Ctx::default();
            let mut resp = ResponseHeader::build(status, None).unwrap();
            // Whether a body follows makes no difference: an empty
            // response used to keep its status and get no page.
            resp.append_header("Content-Length", "0").unwrap();
            plugin.handle_upstream_response(&mut session, &mut ctx, &mut resp)
        };
        let conf = "intercept = true\njson = true\npages = [\"503:<h1>{{status}} {{message}}</h1>\", \"4xx:no\"]";
        for (method, status, message) in [
            ("GET", 503, "Service Unavailable"),
            // A `HEAD` too: the page of the proxy has a length to tell.
            ("HEAD", 503, "Service Unavailable"),
            ("GET", 404, "Not Found"),
            ("POST", 422, "Unprocessable Entity"),
        ] {
            let error = intercept(conf, method, status).await.unwrap_err();
            assert_eq!(&pingora::ErrorType::HTTPStatus(status), error.etype());
            // what the page has for `{{message}}`
            assert_eq!(true, error.to_string().contains(message), "{error}");
            // Not to be retried, and not an error of the upstream: a
            // stale response of the cache is for an upstream that failed.
            assert_eq!(false, error.retry());
            assert_eq!(&pingora::ErrorSource::Unset, error.esource());
        }

        // Not a status a page is for - `json` names none, also for a
        // request that asks for JSON -, not an error, and not without the
        // option.
        for (conf, status) in [
            (conf, 502),
            (conf, 200),
            (conf, 304),
            ("intercept = true\njson = true\npages = [\"503:down\"]", 422),
            ("json = true\npages = [\"503:<h1>down</h1>\"]", 503),
        ] {
            let result = intercept(conf, "GET", status).await.unwrap();
            assert_eq!(
                true,
                result == ResponsePluginResult::Unchanged,
                "{conf} {status}"
            );
        }
    }

    #[test]
    fn test_error_page_params() {
        for (conf, message) in [
            ("", "there is nothing to answer with"),
            ("pages = [\"404\"]", "should be status:page"),
            ("pages = [\"200:fine\"]", "should be status:page"),
            ("pages = [\"3xx:moved\"]", "should be status:page"),
            ("pages = [\"abc:x\"]", "should be status:page"),
            ("pages = [\"404:\"]", "should be status:page"),
            ("pages = [\"404:a\", \"404:b\"]", "there are two for 404"),
            ("pages = [\"5XX:a\", \"5xx:b\"]", "there are two for 5xx"),
            (
                "pages = [\"404:/nowhere/404.html\"]",
                "page /nowhere/404.html can not be read",
            ),
            // nothing it could take from the upstream
            (
                "json = true\nintercept = true",
                "intercept takes the statuses",
            ),
        ] {
            let error = new_plugin(conf).err().unwrap().to_string();
            assert_eq!(true, error.contains(message), "{conf}: {error}");
        }
        // One status ahead of its hundred, in whatever order they came.
        let plugin = new_plugin("pages = [\"5xx:all\", \"503:one\"]").unwrap();
        assert_eq!(Statuses::One(503), plugin.pages[0].statuses);
        assert_eq!(true, new_plugin("json = true").is_ok());
    }

    /// What a page written in the configuration is taken for.
    #[test]
    fn test_inline_page_kind() {
        for (page, kind) in [
            ("<h1>down</h1>", Kind::Html),
            ("  <!doctype html>", Kind::Html),
            ("{\"error\":\"{{message}}\"}", Kind::Json),
            ("[\"{{message}}\"]", Kind::Json),
            ("down", Kind::Text),
            // a placeholder at the head of a line of text is no object
            ("{{status}} {{message}}", Kind::Text),
            ("{{message}}", Kind::Text),
        ] {
            assert_eq!(kind, load_page(page).unwrap().0, "{page}");
        }
    }
}
