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
    Error, get_bool_conf, get_hash_key, get_plugin_factory, get_step_conf,
    get_str_conf, get_str_slice_conf,
};
use async_trait::async_trait;
use bytesize::ByteSize;
use ctor::ctor;
use glob::glob;
use http::{HeaderValue, StatusCode, header};
use humantime::parse_duration;
use path_absolutize::Absolutize;
use pingap_config::{PluginCategory, PluginConf};
use pingap_core::{Ctx, HTTP_HEADER_CONTENT_TEXT, Plugin, PluginStep};
use pingap_core::{
    HttpChunkResponse, HttpHeader, HttpResponse, RequestPluginResult,
    convert_headers,
};
use pingora::proxy::Session;
use std::borrow::Cow;
use std::fs::Metadata;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::UNIX_EPOCH;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tracing::debug;
use urlencoding::decode;

type Result<T, E = Error> = std::result::Result<T, E>;

/// Represents a parsed HTTP Range header
#[derive(Debug, Clone, Copy)]
struct ByteRange {
    start: u64,
    end: u64,
}

impl ByteRange {
    /// Returns the length of bytes in this range (inclusive)
    fn len(&self) -> u64 {
        self.end - self.start + 1
    }
}

/// Parses HTTP Range header value
///
/// # Arguments
/// * `range_header` - Range header value (e.g., "bytes=0-499")
/// * `file_size` - Total size of the file
///
/// # Returns
/// * `Some(ByteRange)` - Valid parsed range
/// * `None` - Invalid or unsupported range format
///
/// # Supported formats
/// - `bytes=start-end` (e.g., bytes=0-499)
/// - `bytes=start-` (e.g., bytes=500- means from 500 to end)
/// - `bytes=-suffix` (e.g., bytes=-500 means last 500 bytes)
fn parse_range_header(range_header: &str, file_size: u64) -> Option<ByteRange> {
    // Only support single range for now (not multipart/byteranges)
    let range_header = range_header.trim();
    if !range_header.starts_with("bytes=") {
        return None;
    }

    let range_spec = &range_header[6..]; // Skip "bytes="

    // Handle multiple ranges - for now just take the first one
    let range_spec = range_spec.split(',').next()?.trim();

    if let Some(suffix_str) = range_spec.strip_prefix('-') {
        let suffix: u64 = suffix_str.parse().ok()?;
        if suffix == 0 || suffix > file_size {
            return None;
        }
        Some(ByteRange {
            start: file_size - suffix,
            end: file_size - 1,
        })
    } else {
        // Normal range: bytes=start-end or bytes=start-
        let parts: Vec<&str> = range_spec.split('-').collect();
        if parts.len() != 2 {
            return None;
        }

        let start: u64 = parts[0].parse().ok()?;
        if start >= file_size {
            return None;
        }

        let end = if parts[1].is_empty() {
            // Open-ended range: bytes=500-
            file_size - 1
        } else {
            parts[1].parse::<u64>().ok()?.min(file_size - 1)
        };

        if end < start {
            return None;
        }

        Some(ByteRange { start, end })
    }
}

// Static HTML template for directory listing view
// Includes basic styling and JavaScript for date formatting
static WEB_HTML: &str = r###"<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8" />
        <style>
            * {
                margin: 0;
                padding: 0;
            }
            table {
                width: 100%;
            }
            a {
                color: #333;
            }
            .size {
                width: 180px;
                text-align: left;
            }
            .lastModified {
                width: 280px;
                text-align: right;
            }
            th, td {
                padding: 10px;
            }
            thead {
                background-color: #f0f0f0;
            }
            tr:nth-child(even) {
                background-color: #f0f0f0;
            }
        </style>
        <script type="text/javascript">
        function updateAllLastModified() {
            Array.from(document.getElementsByClassName("lastModified")).forEach((item) => {
                const date = new Date(item.innerHTML);
                if (isFinite(date)) {
                    item.innerHTML = date.toLocaleString();
                }
            });
        }
        document.addEventListener("DOMContentLoaded", (event) => {
          updateAllLastModified();
        });
        </script>
    </head>
    <body>
        <table border="0" cellpadding="0" cellspacing="0">
            <thead>
                <th class="name">File Name</th>
                <th class="size">Size</th>
                <th class="lastModified">Last Modified</th>
            </thread>
            <tbody>
                {{CONTENT}}
            </tobdy>
        </table>
    </body>
</html>
"###;

#[derive(Default)]
pub struct Directory {
    // Root directory path from which files will be served
    // Can be absolute or relative path
    path: PathBuf,

    // Default index file to serve when requesting directory root
    // Usually "index.html", must start with "/"
    index: String,

    // When true, generates HTML directory listings for folders
    // When false, returns 404 for directory requests (unless index file exists)
    autoindex: bool,

    // Size of chunks when streaming large files
    // If None or 0, defaults to 4096 bytes
    // Files smaller than chunk_size are sent in single response
    chunk_size: Option<usize>,

    // Cache-Control max-age directive in seconds
    // Controls how long browsers should cache the response
    max_age: Option<u32>,

    // When true, adds "private" to Cache-Control header
    // Prevents caching by shared caches (e.g., CDNs)
    cache_private: Option<bool>,

    // Character set for text/* content types
    // e.g., "utf-8", appended to Content-Type header
    charset: Option<String>,

    // Plugin execution phase (request or proxy_upstream)
    plugin_step: PluginStep,

    // Additional HTTP headers to include in responses
    headers: Option<Vec<HttpHeader>>,

    // When true, adds Content-Disposition: attachment
    // Forces browser to download rather than display inline
    download: bool,

    // Unique identifier for this plugin instance
    hash_value: String,
}

/// Reads file metadata and opens file for reading asynchronously
///
/// # Arguments
/// * `file` - PathBuf pointing to the file to be read
///
/// # Returns
/// * `Ok((Metadata, File))` - Tuple containing file metadata and opened file handle
/// * `Err` - IO error if file cannot be opened or is a directory
///
/// # Notes
/// - Returns NotFound error if path points to a directory
/// - File is opened in read-only mode
async fn get_data(
    file: &PathBuf,
) -> std::io::Result<(std::fs::Metadata, fs::File)> {
    let meta = fs::metadata(file).await?;

    // Don't serve directories directly
    if meta.is_dir() {
        return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
    }
    let f = fs::OpenOptions::new().read(true).open(file).await?;

    Ok((meta, f))
}

/// Generates response headers and determines caching behavior based on file metadata
///
/// # Arguments
/// * `file` - PathBuf of the file being served
/// * `meta` - File metadata for size and modification time
/// * `charset` - Optional character set to append to text/* content types
/// * `support_range` - Whether to add Accept-Ranges header
///
/// # Returns
/// * `(bool, usize, Vec<HttpHeader>)` where:
///   - bool: whether file is cacheable (false for HTML files)
///   - usize: file size in bytes
///   - Vec<HttpHeader>: generated headers including Content-Type and ETag
fn get_cacheable_and_headers_from_meta(
    file: &PathBuf,
    meta: &Metadata,
    charset: &Option<String>,
    support_range: bool,
) -> (bool, usize, Vec<HttpHeader>) {
    // Guess MIME type from file extension
    let result = mime_guess::from_path(file);
    let binding = result.first_or_octet_stream();
    let mut value = binding.to_string();

    // Add charset for text/* content types
    if let Some(charset) = charset {
        if value.starts_with("text/") {
            value = format!("{value}; charset={charset}");
        }
    }

    // HTML files are not cacheable to ensure fresh content
    let cacheable = !value.contains("text/html");

    // Build basic headers (Content-Type)
    let mut headers = if let Ok(value) = HeaderValue::from_str(&value) {
        vec![(header::CONTENT_TYPE, value)]
    } else {
        vec![]
    };

    // Get file size (platform-specific implementation)
    #[cfg(unix)]
    let size = meta.size() as usize;
    #[cfg(windows)]
    let size = meta.file_size() as usize;

    // Generate ETag based on file size and modification time
    if let Ok(mod_time) = meta.modified() {
        let value = mod_time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if value > 0 {
            let etag = format!(r###"W/"{size:x}-{value:x}""###);
            if let Ok(value) = HeaderValue::from_str(&etag) {
                headers.push((header::ETAG, value));
            }
        }
    }

    // Add Accept-Ranges header to indicate support for range requests
    if support_range {
        if let Ok(value) = HeaderValue::from_str("bytes") {
            headers.push((header::ACCEPT_RANGES, value));
        }
    }

    (cacheable, size, headers)
}

impl TryFrom<&PluginConf> for Directory {
    type Error = Error;

    /// Attempts to create Directory instance from plugin configuration
    ///
    /// # Arguments
    /// * `value` - Raw plugin configuration
    ///
    /// # Returns
    /// * `Result<Directory>` - Configured instance or validation error
    ///
    /// # Notes
    /// - Validates execution step (must be request or proxy_upstream)
    /// - Converts and validates all configuration parameters
    /// - Sets appropriate defaults
    fn try_from(value: &PluginConf) -> Result<Self> {
        let hash_value = get_hash_key(value);
        let step = get_step_conf(value, PluginStep::Request);

        let chunk_size = if let Ok(chunk_size) =
            ByteSize::from_str(&get_str_conf(value, "chunk_size"))
        {
            chunk_size.0
        } else {
            4096
        };
        let chunk_size = if chunk_size > 0 {
            Some(chunk_size as usize)
        } else {
            None
        };
        let max_age = get_str_conf(value, "max_age");
        let max_age = if !max_age.is_empty() {
            Some(parse_duration(&max_age).unwrap_or_default().as_secs() as u32)
        } else {
            None
        };
        let charset = get_str_conf(value, "charset");
        let charset = if !charset.is_empty() {
            Some(charset)
        } else {
            None
        };
        let headers = convert_headers(&get_str_slice_conf(value, "headers"))
            .map_err(|e| Error::Invalid {
                category: PluginCategory::Directory.to_string(),
                message: e.to_string(),
            })?;

        let cache_private = get_bool_conf(value, "private");
        let cache_private = if cache_private { Some(true) } else { None };
        let mut index = get_str_conf(value, "index");
        if index.is_empty() {
            index = "index.html".to_string();
        }
        if !index.starts_with("/") {
            index = format!("/{index}");
        }
        let params = Self {
            hash_value,
            autoindex: get_bool_conf(value, "autoindex"),
            index,
            path: Path::new(&pingap_util::resolve_path(&get_str_conf(
                value, "path",
            )))
            .to_path_buf(),
            chunk_size,
            max_age,
            charset,
            cache_private,
            plugin_step: step,
            download: get_bool_conf(value, "download"),
            headers: Some(headers),
        };
        if ![PluginStep::Request, PluginStep::ProxyUpstream]
            .contains(&params.plugin_step)
        {
            return Err(Error::Invalid {
                category: PluginCategory::Directory.to_string(),
                message: "Directory serve plugin should be executed at request or proxy upstream step".to_string(),
            });
        }
        Ok(params)
    }
}

struct StreamOptions {
    headers: Vec<HttpHeader>,
    status: StatusCode,
    cacheable: bool,
    chunk_size: usize,
}

impl Directory {
    /// Creates a new Directory plugin instance from configuration
    ///
    /// # Arguments
    /// * `params` - Plugin configuration parameters
    ///
    /// # Returns
    /// * `Result<Directory>` - Configured plugin instance or error
    ///
    /// # Notes
    /// - Validates configuration parameters
    /// - Sets default values for optional parameters
    /// - Resolves relative paths to absolute
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new serve static file plugin");
        Self::try_from(params)
    }

    fn apply_custom_headers(&self, file: &Path, headers: &mut Vec<HttpHeader>) {
        if self.download
            && let Some(filename) =
                file.file_name().map(|item| item.to_string_lossy())
        {
            if let Ok(val) = HeaderValue::from_str(&format!(
                r#"attachment; filename="{filename}""#
            )) {
                headers.push((header::CONTENT_DISPOSITION, val));
            }
        }
        if let Some(arr) = &self.headers {
            headers.extend(arr.clone());
        }
    }
    async fn send_streaming_response(
        &self,
        session: &mut Session,
        ctx: &mut Ctx,
        mut reader: impl tokio::io::AsyncRead + Unpin,
        opt: StreamOptions,
    ) -> pingora::Result<RequestPluginResult> {
        let mut resp = HttpChunkResponse::new(&mut reader);
        resp.chunk_size = opt.chunk_size;

        if opt.cacheable {
            resp.max_age = self.max_age;
        }
        resp.cache_private = self.cache_private;
        resp.headers = Some(opt.headers);

        ctx.state.status = Some(opt.status);
        resp.send(session).await?;
        Ok(RequestPluginResult::Respond(IGNORE_RESPONSE.clone()))
    }
}

static IGNORE_RESPONSE: LazyLock<HttpResponse> =
    LazyLock::new(|| HttpResponse {
        status: StatusCode::from_u16(999)
            .expect("Failed to create status code"),
        ..Default::default()
    });

/// Generates HTML directory listing page for a given directory
///
/// # Arguments
/// * `path` - Path to directory to generate listing for
///
/// # Returns
/// * `Ok(String)` - HTML content for directory listing
/// * `Err(String)` - Error message if listing cannot be generated
///
/// # Notes
/// - Skips hidden files (starting with '.')
/// - Includes file sizes and modification times
/// - Uses WEB_HTML template for consistent styling
fn get_autoindex_html(path: &Path) -> Result<String, String> {
    let path = path.to_string_lossy();
    let mut file_list_html = vec![];
    for entry in glob(&format!("{path}/*")).map_err(|e| e.to_string())? {
        let f = entry.map_err(|e| e.to_string())?;
        let filepath = f.to_string_lossy();
        let mut size = "".to_string();
        let mut last_modified = "".to_string();
        let mut is_file = false;
        if f.is_file() {
            is_file = true;
            #[cfg(unix)]
            let _ = f.metadata().map(|meta| {
                size = ByteSize(meta.size()).to_string();
                last_modified =
                    chrono::DateTime::from_timestamp(meta.mtime(), 0)
                        .unwrap_or_default()
                        .to_string();
            });
            #[cfg(windows)]
            let _ = f.metadata().map(|meta| {
                size = ByteSize(meta.file_size()).to_string();
                last_modified = chrono::DateTime::from_timestamp(
                    meta.last_write_time() as i64,
                    0,
                )
                .unwrap_or_default()
                .to_string();
            });
        }

        let name = f.file_name().unwrap_or_default().to_string_lossy();
        if name.is_empty() || name.starts_with('.') {
            continue;
        }

        let mut target = format!(
            "./{}",
            filepath.split('/').next_back().unwrap_or_default()
        );
        if !is_file {
            target += "/";
        }
        file_list_html.push(format!(
            r###"<tr>
                <td class="name"><a href="{target}">{name}</a></td>
                <td class="size">{size}</td>
                <td class="lastModified">{last_modified}</td>
            </tr>"###
        ));
    }

    Ok(WEB_HTML.replace("{{CONTENT}}", &file_list_html.join("\n")))
}

#[async_trait]
impl Plugin for Directory {
    /// Returns unique identifier for this plugin instance
    #[inline]
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    /// Handles incoming HTTP requests by serving static files
    ///
    /// # Arguments
    /// * `step` - Current execution step
    /// * `session` - HTTP session containing request details
    /// * `ctx` - Plugin context for storing state
    ///
    /// # Returns
    /// * `Result<Option<HttpResponse>>` where Some contains the response
    ///    or None if request should be handled by next plugin
    ///
    /// # Notes
    /// - Handles directory listings if autoindex enabled
    /// - Streams large files in chunks
    /// - Adds appropriate caching headers
    /// - Forces downloads if configured
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != self.plugin_step {
            return Ok(RequestPluginResult::Skipped);
        }
        let path_str = session.req_header().uri.path();
        let source_str = if !self.autoindex && path_str.len() <= 1 {
            &self.index
        } else {
            path_str
        };

        let decoded = decode(source_str).unwrap_or(Cow::Borrowed(source_str));
        let relative_path = decoded.strip_prefix('/').unwrap_or(&decoded);

        let file = match self.path.join(relative_path).absolutize() {
            Ok(file) => file.to_path_buf(),
            Err(e) => {
                return Ok(RequestPluginResult::Respond(
                    HttpResponse::unknown_error(e.to_string()),
                ));
            },
        };
        if !file.starts_with(&self.path) {
            let message = format!(
                "You do not have permission to access this resource, file: {path_str}"
            );
            let resp = HttpResponse::builder(StatusCode::FORBIDDEN)
                .body(message)
                .header(HTTP_HEADER_CONTENT_TEXT.clone())
                .no_store()
                .finish();
            return Ok(RequestPluginResult::Respond(resp));
        }

        debug!(file = format!("{file:?}"), "static file serve");

        if self.autoindex && file.is_dir() {
            let resp = match get_autoindex_html(&file) {
                Ok(html) => HttpResponse::html(html),
                Err(e) => HttpResponse::bad_request(e.to_string()),
            };
            return Ok(RequestPluginResult::Respond(resp));
        }

        let (meta, mut f) = match get_data(&file).await {
            Ok(data) => data,
            Err(err) => {
                let resp = if err.kind() == std::io::ErrorKind::NotFound {
                    HttpResponse::not_found("Not Found")
                } else {
                    HttpResponse::unknown_error("File access error")
                };
                return Ok(RequestPluginResult::Respond(resp));
            },
        };

        // generate response headers
        let (cacheable, size, mut headers) =
            get_cacheable_and_headers_from_meta(
                &file,
                &meta,
                &self.charset,
                true,
            );
        self.apply_custom_headers(&file, &mut headers);

        let range_header = session
            .req_header()
            .headers
            .get(header::RANGE)
            .and_then(|v| v.to_str().ok());
        let chunk_size = self.chunk_size.unwrap_or(4096).max(4096);

        // handle range request
        if let Some(range_str) = range_header {
            if let Some(range) = parse_range_header(range_str, size as u64) {
                let range_len = range.len() as usize;
                if let Ok(val) = HeaderValue::from_str(&format!(
                    "bytes {}-{}/{}",
                    range.start, range.end, size
                )) {
                    headers.push((header::CONTENT_RANGE, val));
                }
                if let Err(e) =
                    f.seek(std::io::SeekFrom::Start(range.start)).await
                {
                    return Ok(RequestPluginResult::Respond(
                        HttpResponse::unknown_error(e.to_string()),
                    ));
                }

                if range_len <= chunk_size {
                    let mut buffer = vec![0; range_len];
                    return match f.read_exact(&mut buffer).await {
                        Ok(_) => {
                            Ok(RequestPluginResult::Respond(HttpResponse {
                                status: StatusCode::PARTIAL_CONTENT,
                                headers: Some(headers),
                                body: buffer.into(),
                                ..Default::default()
                            }))
                        },
                        Err(e) => Ok(RequestPluginResult::Respond(
                            HttpResponse::unknown_error(e.to_string()),
                        )),
                    };
                } else {
                    headers.push((
                        header::CONTENT_LENGTH,
                        HeaderValue::from(range_len),
                    ));
                    let limited_reader = f.take(range.len());
                    return self
                        .send_streaming_response(
                            session,
                            ctx,
                            limited_reader,
                            StreamOptions {
                                headers,
                                status: StatusCode::PARTIAL_CONTENT,
                                cacheable,
                                chunk_size,
                            },
                        )
                        .await;
                }
            } else {
                if let Ok(val) =
                    HeaderValue::from_str(&format!("bytes */{size}"))
                {
                    headers.push((header::CONTENT_RANGE, val));
                }
                return Ok(RequestPluginResult::Respond(HttpResponse {
                    status: StatusCode::RANGE_NOT_SATISFIABLE,
                    headers: Some(headers),
                    ..Default::default()
                }));
            }
        }

        // handle normal request
        if size <= chunk_size {
            let mut buffer = vec![0; size];
            match f.read_exact(&mut buffer).await {
                Ok(_) => Ok(RequestPluginResult::Respond(HttpResponse {
                    status: StatusCode::OK,
                    max_age: self.max_age,
                    cache_private: self.cache_private,
                    headers: Some(headers),
                    body: buffer.into(),
                    ..Default::default()
                })),
                Err(e) => Ok(RequestPluginResult::Respond(
                    HttpResponse::bad_request(e.to_string()),
                )),
            }
        } else {
            // stream response
            headers.push((header::CONTENT_LENGTH, HeaderValue::from(size)));
            self.send_streaming_response(
                session,
                ctx,
                f,
                StreamOptions {
                    headers,
                    status: StatusCode::OK,
                    cacheable,
                    chunk_size,
                },
            )
            .await
        }
    }
}

#[ctor]
fn init() {
    get_plugin_factory()
        .register("directory", |params| Ok(Arc::new(Directory::new(params)?)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, PluginStep, RequestPluginResult};
    use pingora::proxy::Session;
    use pretty_assertions::{assert_eq, assert_ne};
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    #[cfg(windows)]
    use std::os::windows::fs::MetadataExt;
    use std::path::Path;
    use tokio_test::io::Builder;

    #[test]
    fn test_directory_params() {
        let params = Directory::try_from(
            &toml::from_str::<PluginConf>(
                r###"
step = "proxy_upstream"
path = "~/Downloads"
index = "/index.html"
autoindex = true
chunk_size = 1024
max_age = "10m"
private = true
charset = "utf8"
download = true
"###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!("proxy_upstream", params.plugin_step.to_string());
        assert_eq!(true, params.path.to_str().unwrap().ends_with("/Downloads"));
        assert_eq!("/index.html", params.index);
        assert_eq!(true, params.autoindex);
        assert_eq!(4096, params.chunk_size.unwrap_or_default());
        assert_eq!(600, params.max_age.unwrap_or_default());
        assert_eq!(true, params.cache_private.unwrap_or_default());
        assert_eq!(true, params.cache_private.unwrap_or_default());
        assert_eq!("utf8", params.charset.unwrap_or_default());
        assert_eq!(true, params.download);

        let result = Directory::try_from(
            &toml::from_str::<PluginConf>(
                r###"
step = "response"
path = "~/Downloads"
index = "/index.html"
autoindex = true
chunk_size = 1024
max_age = "10m"
private = true
charset = "utf8"
download = true
"###,
            )
            .unwrap(),
        );
        assert_eq!(
            "Plugin directory invalid, message: Directory serve plugin should be executed at request or proxy upstream step",
            result.err().unwrap().to_string()
        );
    }

    #[tokio::test]
    async fn test_new_directory() {
        let dir = Directory::new(
            &toml::from_str::<PluginConf>(
                r###"
path = "./"
chunk_size = 1024
max_age = "1h"
private = true
index = "/index.html"
autoindex = true
download = true
    "###,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(4096, dir.chunk_size.unwrap_or_default());
        assert_eq!(3600, dir.max_age.unwrap_or_default());
        assert_eq!(true, dir.cache_private.unwrap_or_default());
        assert_eq!("/index.html", dir.index);

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header =
            format!("GET /index.html?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = dir
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("result is not Respond");
        };
        assert_eq!(200, resp.status.as_u16());
        let headers = resp.headers.unwrap();
        assert_eq!(
            r#"("content-type", "text/html")"#,
            format!("{:?}", headers[0])
        );
        assert_eq!(
            r#"("accept-ranges", "bytes")"#,
            format!("{:?}", headers[2])
        );
        assert_eq!(
            r#"("content-disposition", "attachment; filename=\"index.html\"")"#,
            format!("{:?}", headers[3])
        );
        assert_eq!(true, !resp.body.is_empty());

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header = format!("GET / HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = dir
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut Ctx::default(),
            )
            .await
            .unwrap();
        let RequestPluginResult::Respond(resp) = result else {
            panic!("result is not Respond");
        };
        assert_eq!(200, resp.status.as_u16());
        assert_eq!(
            r#"("content-type", "text/html; charset=utf-8")"#,
            format!("{:?}", resp.headers.unwrap()[0])
        );
        assert_eq!(
            true,
            std::string::String::from_utf8_lossy(resp.body.as_ref())
                .contains("Cargo.toml")
        );
    }

    #[tokio::test]
    async fn test_get_data() {
        let file = Path::new("./index.html").to_path_buf();
        let (meta, _) = get_data(&file).await.unwrap();

        assert_ne!(0, meta.size());

        let (cacheable, _, headers) = get_cacheable_and_headers_from_meta(
            &file,
            &meta,
            &Some("utf-8".to_string()),
            false,
        );
        assert_eq!(false, cacheable);
        assert_eq!(
            true,
            format!("{headers:?}").contains(
                r###"("content-type", "text/html; charset=utf-8")"###
            )
        );
    }

    #[test]
    fn test_parse_range_header() {
        // Test normal range
        let range = parse_range_header("bytes=0-499", 1000).unwrap();
        assert_eq!(0, range.start);
        assert_eq!(499, range.end);

        // Test open-ended range
        let range = parse_range_header("bytes=500-", 1000).unwrap();
        assert_eq!(500, range.start);
        assert_eq!(999, range.end);

        // Test suffix range (last N bytes)
        let range = parse_range_header("bytes=-500", 1000).unwrap();
        assert_eq!(500, range.start);
        assert_eq!(999, range.end);

        // Test range beyond file size
        let range = parse_range_header("bytes=0-1999", 1000).unwrap();
        assert_eq!(0, range.start);
        assert_eq!(999, range.end);

        // Test invalid start position
        assert!(parse_range_header("bytes=1000-", 1000).is_none());

        // Test invalid format
        assert!(parse_range_header("invalid", 1000).is_none());
        assert!(parse_range_header("bytes=", 1000).is_none());

        // Test multipart range (only first part used)
        let range = parse_range_header("bytes=0-100,200-300", 1000).unwrap();
        assert_eq!(0, range.start);
        assert_eq!(100, range.end);
    }
}
