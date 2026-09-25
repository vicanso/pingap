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
    Error, get_bool_conf, get_hash_key, get_step_conf_in, get_str_conf,
    get_str_slice_conf,
};
use async_trait::async_trait;
use bytesize::ByteSize;
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
use std::fmt::Write as _;
use std::fs::Metadata;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::LazyLock;
use std::time::UNIX_EPOCH;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tracing::debug;
use urlencoding::decode;

type Result<T, E = Error> = std::result::Result<T, E>;

/// The smallest streaming chunk; smaller values only add syscalls.
const MIN_CHUNK_SIZE: u64 = 4096;

/// Whether an `If-None-Match` value names `etag`: `*`, or any listed tag
/// equal to it under the weak comparison (RFC 9110 §8.8.3.2), which
/// ignores a `W/` prefix on either side.
fn etag_matches(if_none_match: &str, etag: &str) -> bool {
    fn strip_weak(tag: &str) -> &str {
        let tag = tag.trim();
        tag.strip_prefix("W/").unwrap_or(tag)
    }
    let etag = strip_weak(etag);
    if_none_match.trim() == "*"
        || if_none_match
            .split(',')
            .any(|candidate| strip_weak(candidate) == etag)
}

/// Escapes the characters HTML gives meaning to, so a file name cannot
/// put markup into the listing.
fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

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

    // When false, a resolved file must still live under `path` after symlinks
    // are followed. Defaults to true, which is the historical behaviour and
    // what release-symlink layouts rely on.
    follow_symlinks: bool,

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

/// The response for a file system error: a missing file is a 404, the
/// rest (permissions, a name the file system rejects) a 500 that does not
/// echo the error.
fn io_error_response(err: &std::io::Error) -> HttpResponse {
    if err.kind() == std::io::ErrorKind::NotFound {
        HttpResponse::not_found("Not Found")
    } else {
        HttpResponse::unknown_error("File access error")
    }
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
    if let Some(charset) = charset
        && value.starts_with("text/")
    {
        value = format!("{value}; charset={charset}");
    }

    // HTML files are not cacheable to ensure fresh content
    let cacheable = !value.contains("text/html");

    // Build basic headers (Content-Type)
    let mut headers = if let Ok(value) = HeaderValue::from_str(&value) {
        vec![(header::CONTENT_TYPE, value)]
    } else {
        vec![]
    };

    let size = meta.len() as usize;

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
    if support_range && let Ok(value) = HeaderValue::from_str("bytes") {
        headers.push((header::ACCEPT_RANGES, value));
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
        let category = PluginCategory::Directory.to_string();
        let invalid = |message: String| Error::Invalid {
            category: category.clone(),
            message,
        };
        let step = get_step_conf_in(
            value,
            &category,
            PluginStep::Request,
            &[PluginStep::Request, PluginStep::ProxyUpstream],
        )?;

        // A size string (`64kb`) or a plain byte count. Either used to be
        // taken as the default when it did not parse, an integer included.
        let chunk_size = match value.get("chunk_size") {
            None => MIN_CHUNK_SIZE,
            Some(raw) => match (raw.as_integer(), raw.as_str()) {
                (Some(n), _) if n >= 0 => n as u64,
                (_, Some(s)) => {
                    ByteSize::from_str(s)
                        .map_err(|e| {
                            invalid(format!("invalid chunk_size: {e}"))
                        })?
                        .0
                },
                _ => {
                    return Err(invalid(
                        "chunk_size must be a size or a byte count".to_string(),
                    ));
                },
            },
        };
        let chunk_size = Some(chunk_size.max(MIN_CHUNK_SIZE) as usize);
        let max_age = get_str_conf(value, "max_age");
        let max_age = if !max_age.is_empty() {
            Some(
                parse_duration(&max_age)
                    .map_err(|e| invalid(format!("invalid max_age: {e}")))?
                    .as_secs() as u32,
            )
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
            .map_err(|e| invalid(e.to_string()))?;

        let cache_private = get_bool_conf(value, "private");
        let cache_private = if cache_private { Some(true) } else { None };
        let mut index = get_str_conf(value, "index");
        if index.is_empty() {
            index = "index.html".to_string();
        }
        if !index.starts_with("/") {
            index = format!("/{index}");
        }
        let path =
            Path::new(&pingap_util::resolve_path(&get_str_conf(value, "path")))
                .to_path_buf();
        // Resolve the root once so the per-request check compares two canonical
        // paths and therefore sees through symlinks. A root that does not exist
        // yet keeps its literal path; the lexical check still applies.
        let path = std::fs::canonicalize(&path).unwrap_or(path);

        // `follow_symlinks` defaults to true so an existing deployment that
        // symlinks content into the served tree keeps working.
        let follow_symlinks = !value.contains_key("follow_symlinks")
            || get_bool_conf(value, "follow_symlinks");

        Ok(Self {
            hash_value,
            autoindex: get_bool_conf(value, "autoindex"),
            index,
            path,
            chunk_size,
            max_age,
            charset,
            cache_private,
            plugin_step: step,
            download: get_bool_conf(value, "download"),
            follow_symlinks,
            headers: Some(headers),
        })
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
            && let Ok(val) = HeaderValue::from_str(&format!(
                r#"attachment; filename="{filename}""#
            ))
        {
            headers.push((header::CONTENT_DISPOSITION, val));
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

/// Generates the HTML directory listing page for `path`.
///
/// Entries are read asynchronously and sorted by name (a glob used to do
/// this, synchronously, and broke on a directory whose name held a glob
/// character). Dotfiles are skipped, names are escaped and hrefs
/// percent-encoded, so a file called `<script>` or `a b#c` is listed as
/// text and linked correctly.
async fn get_autoindex_html(path: &Path) -> std::io::Result<String> {
    let mut entries = Vec::new();
    let mut dir = fs::read_dir(path).await?;
    while let Some(entry) = dir.next_entry().await? {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.is_empty() || name.starts_with('.') {
            continue;
        }
        // An entry that vanished between the listing and the stat is
        // simply left out.
        let Ok(meta) = entry.metadata().await else {
            continue;
        };
        entries.push((name, meta));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut rows = String::with_capacity(entries.len() * 200);
    for (name, meta) in entries {
        let is_file = meta.is_file();
        let (size, last_modified) = if is_file {
            let modified = meta
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|elapsed| elapsed.as_secs() as i64)
                .unwrap_or_default();
            (
                ByteSize(meta.len()).to_string(),
                chrono::DateTime::from_timestamp(modified, 0)
                    .unwrap_or_default()
                    .to_string(),
            )
        } else {
            (String::new(), String::new())
        };
        let href = format!(
            "./{}{}",
            urlencoding::encode(&name),
            if is_file { "" } else { "/" }
        );
        let _ = write!(
            rows,
            r###"<tr>
                <td class="name"><a href="{href}">{}</a></td>
                <td class="size">{size}</td>
                <td class="lastModified">{last_modified}</td>
            </tr>
"###,
            escape_html(&name)
        );
    }

    Ok(WEB_HTML.replace("{{CONTENT}}", &rows))
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

        let decoded = decode(path_str).unwrap_or(Cow::Borrowed(path_str));
        let relative_path = decoded.strip_prefix('/').unwrap_or(&decoded);

        let file = match self.path.join(relative_path).absolutize() {
            Ok(file) => file.to_path_buf(),
            Err(e) => {
                return Ok(RequestPluginResult::Respond(
                    HttpResponse::unknown_error(e.to_string()),
                ));
            },
        };
        let forbidden = || {
            let message = format!(
                "You do not have permission to access this resource, file: {path_str}"
            );
            HttpResponse::builder(StatusCode::FORBIDDEN)
                .body(message)
                .header(HTTP_HEADER_CONTENT_TEXT.clone())
                .no_store()
                .finish()
        };
        if !file.starts_with(&self.path) {
            return Ok(RequestPluginResult::Respond(forbidden()));
        }
        // `absolutize` above is lexical, so it cannot see a symlink inside the
        // root that points outside it. Only enforce when the path resolves; a
        // path that does not exist cannot escape anywhere and is handled as a
        // 404 further down.
        if !self.follow_symlinks
            && let Ok(resolved) = fs::canonicalize(&file).await
            && !resolved.starts_with(&self.path)
        {
            return Ok(RequestPluginResult::Respond(forbidden()));
        }

        debug!(file = format!("{file:?}"), "static file serve");

        // One stat decides what the path is. A directory gets its listing
        // when `autoindex` is on, otherwise its `index` file: that used to
        // work for `/` alone, and `/docs/` was a 404 even with
        // `docs/index.html` in place.
        let file = match fs::metadata(&file).await {
            Ok(meta) if meta.is_dir() => {
                if self.autoindex {
                    let resp = match get_autoindex_html(&file).await {
                        Ok(html) => HttpResponse::html(html),
                        Err(err) => io_error_response(&err),
                    };
                    return Ok(RequestPluginResult::Respond(resp));
                }
                file.join(self.index.trim_start_matches('/'))
            },
            Ok(_) => file,
            Err(err) => {
                return Ok(RequestPluginResult::Respond(io_error_response(
                    &err,
                )));
            },
        };

        let (meta, mut f) = match get_data(&file).await {
            Ok(data) => data,
            Err(err) => {
                return Ok(RequestPluginResult::Respond(io_error_response(
                    &err,
                )));
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

        // A client revalidating with the ETag it was given gets a 304 and
        // no body; without this every conditional request re-sent the file.
        let etag = headers
            .iter()
            .find(|(name, _)| *name == header::ETAG)
            .and_then(|(_, value)| value.to_str().ok());
        if let Some(etag) = etag
            && session
                .req_header()
                .headers
                .get(header::IF_NONE_MATCH)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|if_none_match| etag_matches(if_none_match, etag))
        {
            return Ok(RequestPluginResult::Respond(HttpResponse {
                status: StatusCode::NOT_MODIFIED,
                max_age: if cacheable { self.max_age } else { None },
                cache_private: self.cache_private,
                headers: Some(headers),
                ..Default::default()
            }));
        }

        let range_header = session
            .req_header()
            .headers
            .get(header::RANGE)
            .and_then(|v| v.to_str().ok());
        let chunk_size = self.chunk_size.unwrap_or(MIN_CHUNK_SIZE as usize);

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

register_plugin!("directory", Directory);

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::PluginConf;
    use pingap_core::{Ctx, PluginStep, RequestPluginResult};
    use pingora::proxy::Session;
    use pretty_assertions::{assert_eq, assert_ne};
    use std::path::Path;
    use tokio_test::io::Builder;

    #[test]
    fn test_etag_matches() {
        assert_eq!(true, etag_matches(r#"W/"1-2""#, r#"W/"1-2""#));
        assert_eq!(true, etag_matches(r#""1-2""#, r#"W/"1-2""#));
        assert_eq!(true, etag_matches(r#""0-0", W/"1-2""#, r#"W/"1-2""#));
        assert_eq!(true, etag_matches("*", r#"W/"1-2""#));
        assert_eq!(false, etag_matches(r#"W/"1-3""#, r#"W/"1-2""#));
        assert_eq!(false, etag_matches("", r#"W/"1-2""#));
    }

    #[test]
    fn test_escape_html() {
        assert_eq!("a &amp; b", escape_html("a & b"));
        assert_eq!(
            "&lt;script&gt;&quot;x&quot;&#39;",
            escape_html("<script>\"x\"'")
        );
        assert_eq!("plain.txt", escape_html("plain.txt"));
    }

    async fn request(dir: &Directory, request: &str) -> HttpResponse {
        let mock_io = Builder::new().read(request.as_bytes()).build();
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
        resp
    }

    fn new_directory(root: &Path, extra: &str) -> Directory {
        Directory::new(
            &toml::from_str::<PluginConf>(&format!(
                "path = \"{}\"\n{extra}",
                root.to_string_lossy()
            ))
            .unwrap(),
        )
        .unwrap()
    }

    /// A conditional request with the ETag it was given is answered 304.
    #[tokio::test]
    async fn test_directory_not_modified() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("a.txt"), "hello").unwrap();
        let dir = new_directory(root.path(), "max_age = \"1h\"");

        let resp = request(&dir, "GET /a.txt HTTP/1.1\r\n\r\n").await;
        assert_eq!(200, resp.status.as_u16());
        let etag = resp
            .headers
            .as_ref()
            .unwrap()
            .iter()
            .find(|(name, _)| *name == header::ETAG)
            .map(|(_, value)| value.to_str().unwrap().to_string())
            .expect("an etag");
        assert_eq!(true, etag.starts_with("W/\""), "{etag}");

        let resp = request(
            &dir,
            &format!("GET /a.txt HTTP/1.1\r\nIf-None-Match: {etag}\r\n\r\n"),
        )
        .await;
        assert_eq!(304, resp.status.as_u16());
        assert_eq!(true, resp.body.is_empty());
        assert_eq!(Some(3600), resp.max_age);

        let resp = request(
            &dir,
            "GET /a.txt HTTP/1.1\r\nIf-None-Match: \"other\"\r\n\r\n",
        )
        .await;
        assert_eq!(200, resp.status.as_u16());
    }

    /// A directory serves its index file at any depth when `autoindex` is
    /// off, and a listing when it is on; listings escape and encode names.
    #[tokio::test]
    async fn test_directory_index_and_listing() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("docs")).unwrap();
        std::fs::write(root.path().join("docs/index.html"), "<h1>docs</h1>")
            .unwrap();
        std::fs::write(root.path().join("docs/b c.txt"), "b").unwrap();
        std::fs::write(root.path().join("docs/<a>.txt"), "a").unwrap();
        std::fs::write(root.path().join("docs/.hidden"), "h").unwrap();

        let dir = new_directory(root.path(), "");
        let resp = request(&dir, "GET /docs/ HTTP/1.1\r\n\r\n").await;
        assert_eq!(200, resp.status.as_u16());
        assert_eq!(b"<h1>docs</h1>".as_ref(), resp.body.as_ref());
        let resp = request(&dir, "GET /docs HTTP/1.1\r\n\r\n").await;
        assert_eq!(200, resp.status.as_u16());
        let resp = request(&dir, "GET /missing/ HTTP/1.1\r\n\r\n").await;
        assert_eq!(404, resp.status.as_u16());

        let dir = new_directory(root.path(), "autoindex = true");
        let resp = request(&dir, "GET /docs/ HTTP/1.1\r\n\r\n").await;
        assert_eq!(200, resp.status.as_u16());
        let html = String::from_utf8(resp.body.to_vec()).unwrap();
        // Sorted, escaped, percent-encoded, dotfiles left out.
        let a = html.find("&lt;a&gt;.txt").expect("escaped name");
        let b = html.find("b c.txt").expect("plain name");
        assert_eq!(true, a < b, "{html}");
        assert_eq!(true, html.contains("href=\"./b%20c.txt\""), "{html}");
        assert_eq!(true, html.contains("href=\"./%3Ca%3E.txt\""), "{html}");
        assert_eq!(false, html.contains("<a>.txt"), "{html}");
        assert_eq!(false, html.contains(".hidden"), "{html}");
    }

    #[test]
    fn test_directory_invalid_params() {
        for (conf, expect) in [
            ("chunk_size = \"lots\"", "invalid chunk_size"),
            ("chunk_size = true", "chunk_size must be"),
            ("max_age = \"soon\"", "invalid max_age"),
            ("step = \"response\"", "Invalid step(response)"),
        ] {
            let err = Directory::try_from(
                &toml::from_str::<PluginConf>(&format!(
                    "path = \"./\"\n{conf}"
                ))
                .unwrap(),
            )
            .err()
            .unwrap()
            .to_string();
            assert_eq!(true, err.contains(expect), "{conf}: {err}");
        }
        // Both spellings of a size are accepted, and floored.
        for conf in ["chunk_size = 1024", "chunk_size = \"1kb\""] {
            let params = Directory::try_from(
                &toml::from_str::<PluginConf>(&format!(
                    "path = \"./\"\n{conf}"
                ))
                .unwrap(),
            )
            .unwrap();
            assert_eq!(Some(4096), params.chunk_size, "{conf}");
        }
        let params = Directory::try_from(
            &toml::from_str::<PluginConf>(
                "path = \"./\"\nchunk_size = \"64kb\"",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(Some(64_000), params.chunk_size);
    }

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
            "Plugin directory invalid, message: Invalid step(response), expect one of: request, proxy_upstream",
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

    /// A symlink inside the served root that points outside it is not caught by
    /// the lexical `absolutize` check, so `follow_symlinks = false` has to
    /// resolve the real path.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_directory_symlink_escape() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.txt"), "secret").unwrap();

        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("public.txt"), "public").unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            root.path().join("escape.txt"),
        )
        .unwrap();

        let request = async |dir: &Directory, path: &str| {
            let input_header = format!("GET {path} HTTP/1.1\r\n\r\n");
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
            resp
        };

        let new_directory = |follow_symlinks: bool| {
            Directory::new(
                &toml::from_str::<PluginConf>(&format!(
                    r###"
path = "{}"
follow_symlinks = {follow_symlinks}
"###,
                    root.path().to_string_lossy()
                ))
                .unwrap(),
            )
            .unwrap()
        };

        // The default keeps following symlinks, so an existing deployment that
        // links content into the tree is unaffected.
        let dir = new_directory(true);
        assert_eq!(200, request(&dir, "/escape.txt").await.status.as_u16());

        let dir = new_directory(false);
        assert_eq!(200, request(&dir, "/public.txt").await.status.as_u16());
        assert_eq!(403, request(&dir, "/escape.txt").await.status.as_u16());
    }

    #[tokio::test]
    async fn test_get_data() {
        let file = Path::new("./index.html").to_path_buf();
        let (meta, _) = get_data(&file).await.unwrap();

        assert_ne!(0, meta.len());

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
