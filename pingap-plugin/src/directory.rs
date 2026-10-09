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
    Error, accepts_encoding, get_bool_conf, get_hash_key, get_step_conf_in,
    get_str_conf, get_str_slice_conf,
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
use std::path::{Component, Path, PathBuf};
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

/// What a `Range` header asks for, once checked against the file.
#[derive(Debug, Clone, Copy)]
enum RangeRequest {
    /// A range of the file: answered with a 206.
    Satisfiable(ByteRange),
    /// A well formed range that lies outside the file: a 416.
    Unsatisfiable,
    /// Not a byte range at all - another unit, or one that does not
    /// parse. RFC 9110 14.2 has the header ignored then and the whole file
    /// sent; these used to be a 416 too.
    Ignored,
}

/// Parses HTTP Range header value
///
/// # Arguments
/// * `range_header` - Range header value (e.g., "bytes=0-499")
/// * `file_size` - Total size of the file
///
/// # Supported formats
/// - `bytes=start-end` (e.g., bytes=0-499)
/// - `bytes=start-` (e.g., bytes=500- means from 500 to end)
/// - `bytes=-suffix` (e.g., bytes=-500 means last 500 bytes)
fn parse_range_header(range_header: &str, file_size: u64) -> RangeRequest {
    // Only support single range for now (not multipart/byteranges)
    let Some(range_spec) = range_header.trim().strip_prefix("bytes=") else {
        return RangeRequest::Ignored;
    };

    // Handle multiple ranges - for now just take the first one
    let range_spec = range_spec.split(',').next().unwrap_or_default().trim();

    if let Some(suffix_str) = range_spec.strip_prefix('-') {
        // The last `suffix` bytes, or the whole file when it has fewer:
        // RFC 9110 14.1.2. Asking for more than there is used to be a 416,
        // which is what a player gets that probes with `bytes=-65536`.
        let Ok(suffix) = suffix_str.parse::<u64>() else {
            return RangeRequest::Ignored;
        };
        let suffix = suffix.min(file_size);
        if suffix == 0 {
            return RangeRequest::Unsatisfiable;
        }
        return RangeRequest::Satisfiable(ByteRange {
            start: file_size - suffix,
            end: file_size - 1,
        });
    }
    // Normal range: bytes=start-end or bytes=start-
    let Some((first, last)) = range_spec.split_once('-') else {
        return RangeRequest::Ignored;
    };
    let Ok(start) = first.parse::<u64>() else {
        return RangeRequest::Ignored;
    };
    let last = if last.is_empty() {
        // Open-ended range: bytes=500-
        None
    } else {
        match last.parse::<u64>() {
            // `bytes=5-2` is not a range.
            Ok(last) if last >= start => Some(last),
            _ => return RangeRequest::Ignored,
        }
    };
    if start >= file_size {
        return RangeRequest::Unsatisfiable;
    }
    let end = last.map_or(file_size - 1, |last| last.min(file_size - 1));
    RangeRequest::Satisfiable(ByteRange { start, end })
}

/// Whether the `Range` of a request applies. With an `If-Range` it does
/// only while the client's copy is the current one, told by the entity tag
/// the file was sent with: a client resuming a download of a file that has
/// changed since gets the new file whole instead of a piece of it appended
/// to the old one. A date holds when it is the `Last-Modified` the file
/// was sent with, to the letter.
fn if_range_holds(
    if_range: Option<&HeaderValue>,
    etag: Option<&str>,
    last_modified: Option<&str>,
) -> bool {
    let Some(if_range) = if_range else {
        return true;
    };
    [etag, last_modified]
        .into_iter()
        .flatten()
        .any(|validator| if_range.as_bytes() == validator.as_bytes())
}

/// A coding a file may be kept in next to itself: `app.js.br` beside
/// `app.js`, see `Directory::precompressed`.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Precompressed {
    /// The `Content-Encoding`, as `Accept-Encoding` names it.
    coding: &'static str,
    /// What the name of the encoded file ends in.
    extension: &'static str,
}

impl Precompressed {
    fn from_name(name: &str) -> Option<Self> {
        let (coding, extension) = match name {
            "br" => ("br", "br"),
            "gzip" => ("gzip", "gz"),
            "zstd" => ("zstd", "zst"),
            _ => return None,
        };
        Some(Self { coding, extension })
    }
}

/// When the file was last changed, in seconds since the epoch.
fn modified_secs(meta: &Metadata) -> Option<u64> {
    meta.modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|elapsed| elapsed.as_secs())
        .filter(|secs| *secs > 0)
}

/// `secs` as the date of a `Last-Modified`.
fn http_date(secs: u64) -> Option<String> {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|time| time.format("%a, %d %b %Y %H:%M:%S GMT").to_string())
}

/// The seconds since the epoch of the date in an `If-Modified-Since`.
fn parse_http_date(value: &HeaderValue) -> Option<u64> {
    let time = chrono::DateTime::parse_from_rfc2822(value.to_str().ok()?);
    u64::try_from(time.ok()?.timestamp()).ok()
}

/// Whether `file`, under `root`, is in a place that begins with a dot:
/// `.env`, anything below `.git/`. `.well-known` is not one of them, it is
/// there to be asked for.
fn is_hidden(file: &Path, root: &Path) -> bool {
    file.strip_prefix(root).is_ok_and(|relative| {
        relative.components().any(|component| match component {
            Component::Normal(name) => {
                let name = name.to_string_lossy();
                name.starts_with('.') && name != ".well-known"
            },
            _ => false,
        })
    })
}

/// Makes the `Vary` of `headers` name `Accept-Encoding`: added to the one
/// that is there, or as a header of its own. Of several `Vary` in the
/// list the last is the one that is sent, so that is the one looked at.
fn vary_by_accept_encoding(headers: &mut Vec<HttpHeader>) {
    let Some((_, vary)) = headers
        .iter_mut()
        .rev()
        .find(|(name, _)| *name == header::VARY)
    else {
        headers
            .push((header::VARY, HeaderValue::from_static("Accept-Encoding")));
        return;
    };
    let Ok(current) = vary.to_str() else {
        return;
    };
    let covered = current.split(',').map(str::trim).any(|name| {
        name == "*" || name.eq_ignore_ascii_case("accept-encoding")
    });
    if !covered
        && let Ok(value) =
            HeaderValue::from_str(&format!("{current}, Accept-Encoding"))
    {
        *vary = value;
    }
}

/// Whether the error says that there is no such file, as opposed to one
/// that cannot be read.
fn is_missing(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

/// The redirect for a directory asked for without its closing slash, from
/// the uri the client used.
///
/// Its index page was served under that address, and every relative link
/// of the page - the entries of a listing included - then resolved one
/// level up. The target is relative, the last segment plus the slash, so
/// it is right as well when a proxy in front has taken a prefix off.
fn redirect_to_directory(uri: &http::Uri) -> HttpResponse {
    let name = uri.path().rsplit('/').next().unwrap_or_default();
    let mut target = format!("./{name}/");
    if let Some(query) = uri.query() {
        target.push('?');
        target.push_str(query);
    }
    match HeaderValue::from_str(&target) {
        Ok(value) => HttpResponse::builder(StatusCode::MOVED_PERMANENTLY)
            .header((header::LOCATION, value))
            .finish(),
        Err(_) => HttpResponse::not_found("Not Found"),
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

    // The file a request for something that does not exist is answered
    // with, as a 200: the page of a single page application, which has
    // routes of its own under the directory. Only for a path whose last
    // segment has no extension, so that a missing script or image is still
    // a 404 and not the page.
    fallback: Option<PathBuf>,

    // The codings a file may be kept in next to itself (`app.js.br`), in
    // the order they are preferred. A client that accepts one is sent that
    // file as it is.
    precompressed: Vec<Precompressed>,

    // Whether what begins with a dot is served: `.env`, anything below
    // `.git/`. Off unless set; `.well-known` is served either way.
    hidden: bool,

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
///
/// `file` is the file that was asked for and `meta` that of the file that
/// is sent, which with `coding` is the same content in that coding: the
/// type is the one of the former, the size and the validators those of the
/// latter.
fn get_cacheable_and_headers_from_meta(
    file: &PathBuf,
    meta: &Metadata,
    charset: &Option<String>,
    support_range: bool,
    coding: Option<&'static str>,
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

    // Generate ETag based on file size and modification time. The coding
    // is part of it: the same file in another coding is another answer,
    // and a cache must not take one for the other.
    if let Some(value) = modified_secs(meta) {
        let etag = match coding {
            Some(coding) => format!(r###"W/"{size:x}-{value:x}-{coding}""###),
            None => format!(r###"W/"{size:x}-{value:x}""###),
        };
        if let Ok(value) = HeaderValue::from_str(&etag) {
            headers.push((header::ETAG, value));
        }
        // For the clients and caches that go by the date: there was only
        // the entity tag.
        if let Some(value) =
            http_date(value).and_then(|date| HeaderValue::from_str(&date).ok())
        {
            headers.push((header::LAST_MODIFIED, value));
        }
    }
    if let Some(coding) = coding {
        headers
            .push((header::CONTENT_ENCODING, HeaderValue::from_static(coding)));
    }

    // Add Accept-Ranges header to indicate support for range requests. Not
    // on a file sent in a coding: a range is answered from the file as it
    // is, which is another representation than this one.
    if support_range && coding.is_none() {
        headers
            .push((header::ACCEPT_RANGES, HeaderValue::from_static("bytes")));
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
        let path = get_str_conf(value, "path");
        // An empty root is the prefix of every path, so the check that a
        // file is under the root passed for anything: the plugin served the
        // working directory, and `/../` whatever lies above it.
        if path.is_empty() {
            return Err(invalid("path is required".to_string()));
        }
        let path = Path::new(&pingap_util::resolve_path(&path)).to_path_buf();
        // Resolve the root once so the per-request check compares two canonical
        // paths and therefore sees through symlinks. A root that does not exist
        // yet keeps its literal path; the lexical check still applies.
        let path = std::fs::canonicalize(&path).unwrap_or(path);

        // `follow_symlinks` defaults to true so an existing deployment that
        // symlinks content into the served tree keeps working.
        let follow_symlinks = !value.contains_key("follow_symlinks")
            || get_bool_conf(value, "follow_symlinks");

        // A file of the directory, named from its root like a request
        // names one.
        let fallback = get_str_conf(value, "fallback");
        let fallback = if fallback.is_empty() {
            None
        } else {
            let file = path
                .join(fallback.trim_start_matches('/'))
                .absolutize()
                .map(|file| file.to_path_buf())
                .map_err(|e| invalid(format!("invalid fallback: {e}")))?;
            if !file.starts_with(&path) || file == path {
                return Err(invalid(
                    "fallback must be a file inside path".to_string(),
                ));
            }
            Some(file)
        };
        let precompressed = get_str_slice_conf(value, "precompressed")
            .iter()
            .map(|name| {
                Precompressed::from_name(name.trim()).ok_or_else(|| {
                    invalid(format!(
                        "invalid precompressed({name}), expect br, gzip or zstd"
                    ))
                })
            })
            .collect::<Result<Vec<_>>>()?;

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
            fallback,
            precompressed,
            hidden: get_bool_conf(value, "hidden"),
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
        debug!(
            params = pingap_config::masked_toml(params),
            "new serve static file plugin"
        );
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
    /// Whether `file` resolves to somewhere outside the root. Only looked
    /// at when `follow_symlinks` is off; a path that does not resolve
    /// cannot lead anywhere.
    async fn escapes_root(&self, file: &Path) -> bool {
        !self.follow_symlinks
            && fs::canonicalize(file)
                .await
                .is_ok_and(|resolved| !resolved.starts_with(&self.path))
    }
    /// The file to answer with in place of one that is not there: the
    /// `fallback`, when the request is for a path whose last segment has
    /// no extension. `/app/users/1` is a route of the page, `/app/main.js`
    /// a file that is missing.
    fn fallback_for(
        &self,
        requested: &str,
        err: &std::io::Error,
    ) -> Option<&PathBuf> {
        // A path that ends in a slash names a directory, whatever its
        // last segment looks like: `/v1.2/` is a route.
        self.fallback.as_ref().filter(|_| {
            is_missing(err)
                && (requested.ends_with('/')
                    || Path::new(requested).extension().is_none())
        })
    }
    /// The file `file` is kept as in a coding the client accepts, opened:
    /// the first of `precompressed`, in its order, that is acceptable and
    /// there. None for a request with a `Range`, which is for bytes of the
    /// file as it is.
    async fn precompressed_for(
        &self,
        session: &Session,
        file: &Path,
    ) -> Option<(&'static str, (Metadata, fs::File))> {
        if self.precompressed.is_empty() {
            return None;
        }
        let headers = &session.req_header().headers;
        if headers.contains_key(header::RANGE) {
            return None;
        }
        let accept_encoding = headers
            .get(header::ACCEPT_ENCODING)
            .and_then(|value| value.to_str().ok())?;
        for precompressed in self.precompressed.iter() {
            if !accepts_encoding(accept_encoding, precompressed.coding) {
                continue;
            }
            let mut name = file.as_os_str().to_os_string();
            name.push(".");
            name.push(precompressed.extension);
            let encoded = PathBuf::from(name);
            if self.escapes_root(&encoded).await {
                continue;
            }
            if let Ok(data) = get_data(&encoded).await {
                return Some((precompressed.coding, data));
            }
        }
        None
    }
    /// The answer to a HEAD: the headers the GET would have, `length` as
    /// the size of the body it would send, and no body. `cache` is whether
    /// the file may be cached, or `None` for an answer the GET sends
    /// without the plugin's cache headers.
    fn head_response(
        &self,
        status: StatusCode,
        mut headers: Vec<HttpHeader>,
        length: usize,
        cache: Option<bool>,
    ) -> HttpResponse {
        headers.push((header::CONTENT_LENGTH, HeaderValue::from(length)));
        HttpResponse {
            status,
            max_age: if cache == Some(true) {
                self.max_age
            } else {
                None
            },
            cache_private: cache.and(self.cache_private),
            headers: Some(headers),
            ..Default::default()
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
        // The status goes on the wire, not only into the access log: a
        // range larger than one chunk used to be answered `200 OK` with a
        // `Content-Range`, which a client takes for the whole file.
        resp.status = opt.status;

        if opt.cacheable {
            resp.max_age = self.max_age;
        }
        resp.cache_private = self.cache_private;
        resp.headers = Some(opt.headers);
        // A `bandwidth_limit` ahead of this plugin says how fast: the
        // proxy, which keeps the pace of what an upstream sends, never
        // sees this body.
        resp.pace = ctx
            .features
            .as_mut()
            .and_then(|features| features.body_pace.take());

        ctx.state.status = Some(opt.status);
        // The proxy never sees this response, so the plugins that set
        // headers on what other plugins answer (`cors`) are asked here.
        let mut header = resp.get_response_header()?;
        pingap_core::decorate_plugin_response(session, ctx, &mut header)
            .await?;
        resp.send_with_header(session, header).await?;
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
/// character). Dotfiles are skipped unless `hidden`, names are escaped and hrefs
/// percent-encoded, so a file called `<script>` or `a b#c` is listed as
/// text and linked correctly.
async fn get_autoindex_html(
    path: &Path,
    hidden: bool,
) -> std::io::Result<String> {
    let mut entries = Vec::new();
    let mut dir = fs::read_dir(path).await?;
    while let Some(entry) = dir.next_entry().await? {
        let name = entry.file_name().to_string_lossy().into_owned();
        // What is not served is not listed.
        if name.is_empty() || (!hidden && name.starts_with('.')) {
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
        // Files are read, nothing else: a POST or a DELETE used to be
        // answered like a GET, with a 200 and the file. An OPTIONS is told
        // so, with a 2xx: answered by this plugin, it may be the preflight
        // of a `cors` plugin listed after it, which adds its headers to
        // the answer and needs it to be a success.
        let method = &session.req_header().method;
        if method != http::Method::GET && method != http::Method::HEAD {
            let allow = (
                header::ALLOW,
                HeaderValue::from_static("GET, HEAD, OPTIONS"),
            );
            let resp = if method == http::Method::OPTIONS {
                HttpResponse::builder(StatusCode::NO_CONTENT)
                    .header(allow)
                    .finish()
            } else {
                HttpResponse::builder(StatusCode::METHOD_NOT_ALLOWED)
                    .header(allow)
                    .header(HTTP_HEADER_CONTENT_TEXT.clone())
                    .body("Method Not Allowed")
                    .no_store()
                    .finish()
            };
            return Ok(RequestPluginResult::Respond(resp));
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
        // As if it were not there: a `403` would say that it is, which is
        // why this comes before the check on where it leads.
        if !self.hidden && is_hidden(&file, &self.path) {
            return Ok(RequestPluginResult::Respond(HttpResponse::not_found(
                "Not Found",
            )));
        }
        // `absolutize` above is lexical, so it cannot see a symlink inside the
        // root that points outside it. Only enforce when the path resolves; a
        // path that does not exist cannot escape anywhere and is handled as a
        // 404 further down.
        if self.escapes_root(&file).await {
            return Ok(RequestPluginResult::Respond(forbidden()));
        }

        debug!(file = format!("{file:?}"), "static file serve");

        // One stat decides what the path is. A directory gets its listing
        // when `autoindex` is on, otherwise its `index` file: that used to
        // work for `/` alone, and `/docs/` was a 404 even with
        // `docs/index.html` in place.
        let resolved = match fs::metadata(&file).await {
            Ok(meta) if meta.is_dir() => {
                // By the address the client used, which is the one its
                // links resolve against: after a rewrite the path here is
                // another, and `/static` rewritten to `/assets` was sent
                // to `./assets/`, out of the location.
                let client_uri = ctx
                    .features
                    .as_ref()
                    .and_then(|features| features.original_uri.as_ref())
                    .unwrap_or(&session.req_header().uri);
                if !client_uri.path().ends_with('/') {
                    return Ok(RequestPluginResult::Respond(
                        redirect_to_directory(client_uri),
                    ));
                }
                if self.autoindex {
                    let resp =
                        match get_autoindex_html(&file, self.hidden).await {
                            Ok(html) => HttpResponse::html(html),
                            Err(err) => io_error_response(&err),
                        };
                    return Ok(RequestPluginResult::Respond(resp));
                }
                // The index file is a path of its own and is checked like
                // one. The check above saw the directory only, so an
                // `index.html` linking out of the root was served through
                // `/dir/` while `/dir/index.html` was refused.
                let index = file.join(self.index.trim_start_matches('/'));
                if self.escapes_root(&index).await {
                    return Ok(RequestPluginResult::Respond(forbidden()));
                }
                Ok(index)
            },
            Ok(_) => Ok(file),
            Err(err) => Err(err),
        };
        let opened = match resolved {
            Ok(file) => get_data(&file).await.map(|data| (file, data)),
            Err(err) => Err(err),
        };
        // Nothing there, a directory without its index included: the
        // fallback, where the path is one a page would route.
        let (file, (meta, f)) = match opened {
            Ok(opened) => opened,
            Err(err) => {
                let Some(fallback) = self.fallback_for(relative_path, &err)
                else {
                    return Ok(RequestPluginResult::Respond(
                        io_error_response(&err),
                    ));
                };
                if self.escapes_root(fallback).await {
                    return Ok(RequestPluginResult::Respond(forbidden()));
                }
                match get_data(fallback).await {
                    Ok(data) => (fallback.clone(), data),
                    Err(err) => {
                        return Ok(RequestPluginResult::Respond(
                            io_error_response(&err),
                        ));
                    },
                }
            },
        };
        // The same file in a coding the client takes, kept next to it.
        let (coding, meta, mut f) =
            match self.precompressed_for(session, &file).await {
                Some((coding, (meta, f))) => (Some(coding), meta, f),
                None => (None, meta, f),
            };

        // generate response headers
        let (cacheable, size, mut headers) =
            get_cacheable_and_headers_from_meta(
                &file,
                &meta,
                &self.charset,
                true,
                coding,
            );
        self.apply_custom_headers(&file, &mut headers);
        // Which of them is sent goes by what the request accepts, whether
        // or not this one got a coded file. After the configured headers:
        // a `Vary` among them is the one that is sent, and it has to say
        // this too.
        if !self.precompressed.is_empty() {
            vary_by_accept_encoding(&mut headers);
        }

        // A client revalidating with the ETag it was given gets a 304 and
        // no body; without this every conditional request re-sent the file.
        let validator = |wanted: header::HeaderName| {
            headers
                .iter()
                .find(|(name, _)| *name == wanted)
                .and_then(|(_, value)| value.to_str().ok())
        };
        let etag = validator(header::ETAG);
        let last_modified = validator(header::LAST_MODIFIED);
        let req_headers = &session.req_header().headers;
        let if_none_match = req_headers.get(header::IF_NONE_MATCH);
        // The entity tag where the client sent one, and only without it
        // the date: a copy no older than the file is current.
        let not_modified = match (if_none_match, etag) {
            (Some(if_none_match), Some(etag)) => if_none_match
                .to_str()
                .is_ok_and(|if_none_match| etag_matches(if_none_match, etag)),
            (Some(_), None) => false,
            (None, _) => req_headers
                .get(header::IF_MODIFIED_SINCE)
                .and_then(parse_http_date)
                .zip(modified_secs(&meta))
                .is_some_and(|(since, modified)| modified <= since),
        };
        if not_modified {
            return Ok(RequestPluginResult::Respond(HttpResponse {
                status: StatusCode::NOT_MODIFIED,
                max_age: if cacheable { self.max_age } else { None },
                cache_private: self.cache_private,
                headers: Some(headers),
                ..Default::default()
            }));
        }

        let range = match req_headers
            .get(header::RANGE)
            .and_then(|v| v.to_str().ok())
        {
            Some(value)
                if if_range_holds(
                    req_headers.get(header::IF_RANGE),
                    etag,
                    last_modified,
                ) =>
            {
                parse_range_header(value, size as u64)
            },
            _ => RangeRequest::Ignored,
        };
        let chunk_size = self.chunk_size.unwrap_or(MIN_CHUNK_SIZE as usize);
        // A HEAD is answered from the metadata. It used to go the way of
        // the GET, reading the file - all of it, chunk by chunk, for a
        // large one - for a body that is never sent.
        let is_head = session.req_header().method == http::Method::HEAD;

        // handle range request
        if let RangeRequest::Unsatisfiable = range {
            if let Ok(val) = HeaderValue::from_str(&format!("bytes */{size}")) {
                headers.push((header::CONTENT_RANGE, val));
            }
            return Ok(RequestPluginResult::Respond(HttpResponse {
                status: StatusCode::RANGE_NOT_SATISFIABLE,
                headers: Some(headers),
                ..Default::default()
            }));
        }
        if let RangeRequest::Satisfiable(range) = range {
            let range_len = range.len() as usize;
            if let Ok(val) = HeaderValue::from_str(&format!(
                "bytes {}-{}/{}",
                range.start, range.end, size
            )) {
                headers.push((header::CONTENT_RANGE, val));
            }
            if is_head {
                return Ok(RequestPluginResult::Respond(self.head_response(
                    StatusCode::PARTIAL_CONTENT,
                    headers,
                    range_len,
                    Some(cacheable),
                )));
            }
            if let Err(e) = f.seek(std::io::SeekFrom::Start(range.start)).await
            {
                return Ok(RequestPluginResult::Respond(
                    HttpResponse::unknown_error(e.to_string()),
                ));
            }

            if range_len <= chunk_size {
                let mut buffer = vec![0; range_len];
                return match f.read_exact(&mut buffer).await {
                    // With the cache headers of the file, like the range
                    // that is streamed: a short one came without them.
                    Ok(_) => Ok(RequestPluginResult::Respond(HttpResponse {
                        status: StatusCode::PARTIAL_CONTENT,
                        max_age: if cacheable { self.max_age } else { None },
                        cache_private: self.cache_private,
                        headers: Some(headers),
                        body: buffer.into(),
                        ..Default::default()
                    })),
                    Err(e) => Ok(RequestPluginResult::Respond(
                        HttpResponse::unknown_error(e.to_string()),
                    )),
                };
            }
            headers
                .push((header::CONTENT_LENGTH, HeaderValue::from(range_len)));
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

        if is_head {
            return Ok(RequestPluginResult::Respond(self.head_response(
                StatusCode::OK,
                headers,
                size,
                Some(cacheable),
            )));
        }

        // handle normal request
        if size <= chunk_size {
            let mut buffer = vec![0; size];
            match f.read_exact(&mut buffer).await {
                // Only for what may be cached: an html page read in one piece
                // used to get the `max-age` that a streamed one, and the
                // documentation, leave out.
                Ok(_) => Ok(RequestPluginResult::Respond(HttpResponse {
                    status: StatusCode::OK,
                    max_age: if cacheable { self.max_age } else { None },
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

    /// Regression: `max_age` is for what may be cached. A small html file,
    /// read in one piece, used to get it too.
    #[tokio::test]
    async fn test_directory_html_has_no_max_age() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("index.html"), "<html></html>")
            .unwrap();
        std::fs::write(root.path().join("app.js"), "let a = 1;").unwrap();
        let dir = new_directory(root.path(), "max_age = \"1h\"");

        let resp = request(&dir, "GET /index.html HTTP/1.1\r\n\r\n").await;
        assert_eq!(200, resp.status.as_u16());
        assert_eq!(None, resp.max_age);
        let resp = request(&dir, "GET / HTTP/1.1\r\n\r\n").await;
        assert_eq!(200, resp.status.as_u16());
        assert_eq!(None, resp.max_age);

        let resp = request(&dir, "GET /app.js HTTP/1.1\r\n\r\n").await;
        assert_eq!(200, resp.status.as_u16());
        assert_eq!(Some(3600), resp.max_age);
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
        // Regression: without a root every path counted as inside it.
        for conf in ["", "path = \"\""] {
            let err = Directory::try_from(
                &toml::from_str::<PluginConf>(conf).unwrap(),
            )
            .err()
            .unwrap()
            .to_string();
            assert_eq!(true, err.contains("path is required"), "{conf}: {err}");
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
        // The entity tag and the date of the file come in between.
        assert_eq!("etag", headers[1].0.as_str());
        assert_eq!("last-modified", headers[2].0.as_str());
        assert_eq!(
            r#"("accept-ranges", "bytes")"#,
            format!("{:?}", headers[3])
        );
        assert_eq!(
            r#"("content-disposition", "attachment; filename=\"index.html\"")"#,
            format!("{:?}", headers[4])
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
        // The index file of a directory inside the root, linking out.
        std::fs::create_dir(root.path().join("sub")).unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            root.path().join("sub/index.html"),
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
        assert_eq!(200, request(&dir, "/sub/").await.status.as_u16());

        let dir = new_directory(false);
        assert_eq!(200, request(&dir, "/public.txt").await.status.as_u16());
        assert_eq!(403, request(&dir, "/escape.txt").await.status.as_u16());
        // Regression: the directory is inside the root, its index file is
        // not. Asking for the directory used to serve it.
        assert_eq!(403, request(&dir, "/sub/index.html").await.status.as_u16());
        assert_eq!(403, request(&dir, "/sub/").await.status.as_u16());
        // Without the slash it is sent to the address above, no further.
        assert_eq!(301, request(&dir, "/sub").await.status.as_u16());
    }

    /// Regression: a HEAD went the way of the GET and read the file, the
    /// whole of a large one, for a body that is not sent. It is answered
    /// from the metadata, with the length the GET would send.
    #[tokio::test]
    async fn test_directory_head_does_not_read_the_file() {
        let root = tempfile::tempdir().unwrap();
        let size = 3 * MIN_CHUNK_SIZE as usize;
        std::fs::write(root.path().join("big.bin"), vec![b'a'; size]).unwrap();
        std::fs::write(root.path().join("small.txt"), "hello").unwrap();
        let dir = new_directory(root.path(), "max_age = \"1h\"");

        let head = async |path: &str, headers: &str| {
            let resp = request(
                &dir,
                &format!("HEAD {path} HTTP/1.1\r\n{headers}\r\n"),
            )
            .await;
            assert_eq!(true, resp.body.is_empty(), "{path}");
            let header = resp.new_response_header().unwrap();
            let value = |name: &str| {
                header
                    .headers
                    .get(name)
                    .map(|value| value.to_str().unwrap().to_string())
                    .unwrap_or_default()
            };
            (
                resp.status.as_u16(),
                value("content-length"),
                value("content-range"),
                value("cache-control"),
            )
        };

        // A streamed response used to report the status 999 here: it had
        // been written to the connection, chunk by chunk.
        let (status, length, _, cache) = head("/big.bin", "").await;
        assert_eq!(200, status);
        assert_eq!(size.to_string(), length);
        assert_eq!("public, max-age=3600", cache);

        let (status, length, _, cache) = head("/small.txt", "").await;
        assert_eq!(200, status);
        assert_eq!("5", length);
        assert_eq!("public, max-age=3600", cache);

        let (status, length, range, _) =
            head("/big.bin", "Range: bytes=0-99\r\n").await;
        assert_eq!(206, status);
        assert_eq!("100", length);
        assert_eq!(format!("bytes 0-99/{size}"), range);

        // The suffix is longer than the file: all of it.
        let (status, length, range, _) =
            head("/small.txt", "Range: bytes=-100\r\n").await;
        assert_eq!(206, status);
        assert_eq!("5", length);
        assert_eq!("bytes 0-4/5", range);
    }

    /// Regression: a response too large for one chunk is streamed, and the
    /// streamed header was always `200 OK` with `Transfer-Encoding: chunked`
    /// on top of the `Content-Length` - for a range too, which a client
    /// then takes for the whole file.
    #[tokio::test]
    async fn test_directory_streamed_response_header() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let root = tempfile::tempdir().unwrap();
        // Three chunks of the smallest chunk size.
        let size = 3 * MIN_CHUNK_SIZE as usize;
        std::fs::write(root.path().join("big.bin"), vec![b'a'; size]).unwrap();
        let dir = new_directory(root.path(), "");

        let fetch = async |headers: &str| {
            let (mut client, server) = tokio::io::duplex(1024 * 1024);
            client
                .write_all(
                    format!("GET /big.bin HTTP/1.1\r\n{headers}\r\n")
                        .as_bytes(),
                )
                .await
                .unwrap();
            let mut session = Session::new_h1(Box::new(server));
            session.read_request().await.unwrap();
            let mut ctx = Ctx::default();
            dir.handle_request(PluginStep::Request, &mut session, &mut ctx)
                .await
                .unwrap();
            drop(session);
            let mut buf = vec![];
            client.read_to_end(&mut buf).await.unwrap();
            let text = String::from_utf8_lossy(&buf).into_owned();
            let (head, body) = text.split_once("\r\n\r\n").unwrap();
            (head.to_ascii_lowercase(), body.len())
        };

        let range = 2 * MIN_CHUNK_SIZE as usize;
        let (head, body) =
            fetch(&format!("Range: bytes=0-{}\r\n", range - 1)).await;
        assert_eq!(true, head.starts_with("http/1.1 206 "), "{head}");
        assert_eq!(
            true,
            head.contains(&format!(
                "content-range: bytes 0-{}/{size}",
                range - 1
            )),
            "{head}"
        );
        assert_eq!(
            true,
            head.contains(&format!("content-length: {range}")),
            "{head}"
        );
        assert_eq!(false, head.contains("transfer-encoding"), "{head}");
        assert_eq!(range, body);

        // The whole file: 200, and one framing as well.
        let (head, body) = fetch("").await;
        assert_eq!(true, head.starts_with("http/1.1 200 "), "{head}");
        assert_eq!(
            true,
            head.contains(&format!("content-length: {size}")),
            "{head}"
        );
        assert_eq!(false, head.contains("transfer-encoding"), "{head}");
        assert_eq!(size, body);
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
            None,
        );
        assert_eq!(false, cacheable);
        assert_eq!(
            true,
            format!("{headers:?}").contains(
                r###"("content-type", "text/html; charset=utf-8")"###
            )
        );
    }

    fn header_of(resp: &HttpResponse, name: header::HeaderName) -> String {
        resp.headers
            .iter()
            .flatten()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.to_str().unwrap().to_string())
            .unwrap_or_default()
    }

    /// `fallback`: what is not there is answered with the page, where the
    /// path is one a page would route - and a file that is missing is
    /// still missing.
    #[tokio::test]
    async fn test_directory_fallback() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("index.html"), "<p>app</p>").unwrap();
        std::fs::write(root.path().join("main.js"), "let a = 1;").unwrap();
        std::fs::create_dir(root.path().join("empty")).unwrap();
        let get = async |dir: &Directory, path: &str| {
            let resp =
                request(dir, &format!("GET {path} HTTP/1.1\r\n\r\n")).await;
            (
                resp.status.as_u16(),
                String::from_utf8_lossy(&resp.body).to_string(),
            )
        };

        let app = new_directory(root.path(), "fallback = \"/index.html\"");
        let page = (200, "<p>app</p>".to_string());
        // Routes of the page, however deep, and a directory with no index.
        for path in [
            "/users",
            "/users/1",
            "/users/1/",
            "/v1.2/users",
            "/v1.2/",
            "/empty/",
        ] {
            assert_eq!(page, get(&app, path).await, "{path}");
        }
        // What is there is served as it is.
        assert_eq!(
            (200, "let a = 1;".to_string()),
            get(&app, "/main.js").await
        );
        // A file that is missing is a 404, not the page under its name.
        for path in ["/missing.js", "/assets/logo.png", "/users/1.json"] {
            assert_eq!(404, get(&app, path).await.0, "{path}");
        }
        // The page is html: sent as such, and not for caches to keep.
        let resp = request(&app, "GET /users HTTP/1.1\r\n\r\n").await;
        assert_eq!("text/html", header_of(&resp, header::CONTENT_TYPE));
        assert_eq!(None, resp.max_age);
        let head = request(&app, "HEAD /users HTTP/1.1\r\n\r\n").await;
        assert_eq!(StatusCode::OK, head.status);
        assert_eq!("10", header_of(&head, header::CONTENT_LENGTH));

        // Without it, as before.
        let plain = new_directory(root.path(), "");
        assert_eq!(404, get(&plain, "/users").await.0);
        // A fallback that is not there leaves the 404.
        let gone = new_directory(root.path(), "fallback = \"/app.html\"");
        assert_eq!(404, get(&gone, "/users").await.0);

        // It is a file of the directory.
        for fallback in ["/../index.html", "/", ""] {
            let conf = format!(
                "path = \"{}\"\nfallback = \"{fallback}\"",
                root.path().display()
            );
            let result =
                Directory::new(&toml::from_str::<PluginConf>(&conf).unwrap());
            assert_eq!(
                fallback.is_empty(),
                result.is_ok(),
                "{fallback:?}: {:?}",
                result.err().map(|e| e.to_string())
            );
        }
    }

    /// `precompressed`: a file kept in a coding next to itself is sent in
    /// that coding to a client that accepts it.
    #[tokio::test]
    async fn test_directory_precompressed() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("app.js"), "let answer = 42;").unwrap();
        std::fs::write(root.path().join("app.js.br"), "br-bytes").unwrap();
        std::fs::write(root.path().join("app.js.gz"), "gzip-data!").unwrap();
        std::fs::write(root.path().join("plain.css"), "a{}").unwrap();
        let dir = new_directory(
            root.path(),
            "precompressed = [\"br\", \"gzip\", \"zstd\"]",
        );
        let get = async |path: &str, headers: &str| {
            request(&dir, &format!("GET {path} HTTP/1.1\r\n{headers}\r\n"))
                .await
        };

        // The first of the list the client accepts, with the type of the
        // file that was asked for and the length of the one that is sent.
        let br = get("/app.js", "Accept-Encoding: gzip, br\r\n").await;
        assert_eq!(StatusCode::OK, br.status);
        assert_eq!("br-bytes", String::from_utf8_lossy(&br.body));
        assert_eq!("br", header_of(&br, header::CONTENT_ENCODING));
        assert_eq!("Accept-Encoding", header_of(&br, header::VARY));
        assert_eq!(
            true,
            header_of(&br, header::CONTENT_TYPE).contains("javascript")
        );
        // Ranges are of the file as it is: not offered on this one.
        assert_eq!("", header_of(&br, header::ACCEPT_RANGES));

        let gzip = get("/app.js", "Accept-Encoding: gzip, br;q=0\r\n").await;
        assert_eq!("gzip-data!", String::from_utf8_lossy(&gzip.body));
        assert_eq!("gzip", header_of(&gzip, header::CONTENT_ENCODING));

        // Not accepted, or no such file (zstd): the file as it is, and
        // still told apart by what the request accepts.
        for headers in [
            "",
            "Accept-Encoding: zstd\r\n",
            "Accept-Encoding: identity\r\n",
        ] {
            let plain = get("/app.js", headers).await;
            assert_eq!(
                "let answer = 42;",
                String::from_utf8_lossy(&plain.body),
                "{headers}"
            );
            assert_eq!("", header_of(&plain, header::CONTENT_ENCODING));
            assert_eq!("Accept-Encoding", header_of(&plain, header::VARY));
            assert_eq!("bytes", header_of(&plain, header::ACCEPT_RANGES));
        }
        let css = get("/plain.css", "Accept-Encoding: br\r\n").await;
        assert_eq!("a{}", String::from_utf8_lossy(&css.body));

        // Each coding is an answer of its own to a cache.
        let etags: Vec<String> = [&br, &gzip, &get("/app.js", "").await]
            .iter()
            .map(|resp| header_of(resp, header::ETAG))
            .collect();
        assert_eq!(true, etags[0].ends_with(r#"-br""#), "{etags:?}");
        assert_eq!(true, etags[1].ends_with(r#"-gzip""#), "{etags:?}");
        assert_ne!(etags[0], etags[2]);
        // Revalidating the coded file answers for the coded file.
        let fresh = get(
            "/app.js",
            &format!("Accept-Encoding: br\r\nIf-None-Match: {}\r\n", etags[0]),
        )
        .await;
        assert_eq!(StatusCode::NOT_MODIFIED, fresh.status);

        // A range is for bytes of the file itself.
        let range =
            get("/app.js", "Accept-Encoding: br\r\nRange: bytes=0-2\r\n").await;
        assert_eq!(StatusCode::PARTIAL_CONTENT, range.status);
        assert_eq!("let", String::from_utf8_lossy(&range.body));
        assert_eq!("", header_of(&range, header::CONTENT_ENCODING));

        // A HEAD says what the GET would send.
        let head = request(
            &dir,
            "HEAD /app.js HTTP/1.1\r\nAccept-Encoding: br\r\n\r\n",
        )
        .await;
        assert_eq!("8", header_of(&head, header::CONTENT_LENGTH));
        assert_eq!("br", header_of(&head, header::CONTENT_ENCODING));

        // A `Vary` of the configuration is kept, and says this as well.
        for (configured, sent) in [
            ("Vary: Origin", "Origin, Accept-Encoding"),
            ("Vary: accept-encoding, Origin", "accept-encoding, Origin"),
            ("Vary: *", "*"),
        ] {
            let dir = new_directory(
                root.path(),
                &format!(
                    "precompressed = [\"br\"]\nheaders = [\"{configured}\"]"
                ),
            );
            for headers in ["", "Accept-Encoding: br\r\n"] {
                let resp = request(
                    &dir,
                    &format!("GET /app.js HTTP/1.1\r\n{headers}\r\n"),
                )
                .await;
                // Of the headers of the response the last of a name is
                // the one that goes out.
                let vary = resp
                    .headers
                    .iter()
                    .flatten()
                    .rfind(|(name, _)| *name == header::VARY)
                    .map(|(_, value)| value.to_str().unwrap().to_string());
                assert_eq!(Some(sent.to_string()), vary, "{configured}");
            }
        }

        // Not set: the coded file is never looked for, and a request for
        // it by name gets it like any file.
        let plain = new_directory(root.path(), "");
        let resp = request(
            &plain,
            "GET /app.js HTTP/1.1\r\nAccept-Encoding: br\r\n\r\n",
        )
        .await;
        assert_eq!("let answer = 42;", String::from_utf8_lossy(&resp.body));
        assert_eq!("", header_of(&resp, header::VARY));

        let conf = format!(
            "path = \"{}\"\nprecompressed = [\"br\", \"deflate\"]",
            root.path().display()
        );
        assert_eq!(
            "Plugin directory invalid, message: invalid precompressed(deflate), expect br, gzip or zstd",
            Directory::new(&toml::from_str::<PluginConf>(&conf).unwrap())
                .err()
                .unwrap()
                .to_string()
        );
    }

    /// What begins with a dot is not served unless `hidden` says so.
    #[tokio::test]
    async fn test_directory_hidden_files() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(".env"), "SECRET=1").unwrap();
        std::fs::create_dir_all(root.path().join(".git")).unwrap();
        std::fs::write(root.path().join(".git/config"), "[core]").unwrap();
        std::fs::create_dir_all(root.path().join("a/.cache")).unwrap();
        std::fs::write(root.path().join("a/.cache/x.txt"), "x").unwrap();
        std::fs::create_dir_all(root.path().join(".well-known")).unwrap();
        std::fs::write(root.path().join(".well-known/security.txt"), "ok")
            .unwrap();
        std::fs::write(root.path().join("a/file.txt"), "file").unwrap();
        let status = async |dir: &Directory, path: &str| {
            request(dir, &format!("GET {path} HTTP/1.1\r\n\r\n"))
                .await
                .status
                .as_u16()
        };
        let hidden = [
            "/.env",
            "/.git/config",
            "/a/.cache/x.txt",
            "/a/../.env",
            "/%2eenv",
        ];

        let dir = new_directory(root.path(), "");
        for path in hidden {
            assert_eq!(404, status(&dir, path).await, "{path}");
        }
        assert_eq!(200, status(&dir, "/.well-known/security.txt").await);
        assert_eq!(200, status(&dir, "/a/file.txt").await);

        let open = new_directory(root.path(), "hidden = true");
        for path in hidden {
            assert_eq!(200, status(&open, path).await, "{path}");
        }
        // Listed where they are served, and only there.
        let listing = async |extra: &str| {
            let dir = new_directory(root.path(), extra);
            let resp = request(&dir, "GET / HTTP/1.1\r\n\r\n").await;
            String::from_utf8_lossy(&resp.body).contains(".env")
        };
        assert_eq!(false, listing("autoindex = true").await);
        assert_eq!(true, listing("autoindex = true\nhidden = true").await);
    }

    /// The date of a file is sent, and a client that has a copy no older
    /// is told so.
    #[tokio::test]
    async fn test_directory_last_modified() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("a.txt");
        std::fs::write(&file, "hello").unwrap();
        let modified =
            modified_secs(&std::fs::metadata(&file).unwrap()).unwrap();
        let dir = new_directory(root.path(), "");
        let get = async |headers: &str| {
            request(&dir, &format!("GET /a.txt HTTP/1.1\r\n{headers}\r\n"))
                .await
        };

        let resp = get("").await;
        let last_modified = header_of(&resp, header::LAST_MODIFIED);
        assert_eq!(http_date(modified).unwrap(), last_modified);
        assert_eq!(true, last_modified.ends_with(" GMT"), "{last_modified}");
        assert_eq!(
            Some(modified),
            parse_http_date(&HeaderValue::from_str(&last_modified).unwrap())
        );

        let since = |secs: u64| {
            format!("If-Modified-Since: {}\r\n", http_date(secs).unwrap())
        };
        // The copy is as new as the file, or newer.
        for secs in [modified, modified + 3600] {
            let resp = get(&since(secs)).await;
            assert_eq!(StatusCode::NOT_MODIFIED, resp.status);
            assert_eq!(true, resp.body.is_empty());
        }
        // Older, or not a date.
        assert_eq!(StatusCode::OK, get(&since(modified - 1)).await.status);
        assert_eq!(
            StatusCode::OK,
            get("If-Modified-Since: yesterday\r\n").await.status
        );
        // An entity tag, where there is one, is what counts.
        let stale = format!("If-None-Match: \"other\"\r\n{}", since(modified));
        assert_eq!(StatusCode::OK, get(&stale).await.status);

        // A range holds for the copy the date is of, to the letter.
        let range = |if_range: &str| {
            format!("Range: bytes=0-1\r\nIf-Range: {if_range}\r\n")
        };
        assert_eq!(
            StatusCode::PARTIAL_CONTENT,
            get(&range(&last_modified)).await.status
        );
        assert_eq!(
            StatusCode::OK,
            get(&range(&http_date(modified - 1).unwrap())).await.status
        );
    }

    /// Regression: a directory asked for without its closing slash got its
    /// index page under that address, and the relative links of the page -
    /// every entry of a listing among them - pointed one level up.
    #[tokio::test]
    async fn test_directory_redirects_to_closing_slash() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("docs")).unwrap();
        std::fs::write(root.path().join("docs/index.html"), "<h1>docs</h1>")
            .unwrap();

        for extra in ["", "autoindex = true"] {
            let dir = new_directory(root.path(), extra);
            let resp = request(&dir, "GET /docs HTTP/1.1\r\n\r\n").await;
            assert_eq!(301, resp.status.as_u16(), "{extra}");
            assert_eq!("./docs/", header_of(&resp, header::LOCATION));
            assert_eq!(true, resp.body.is_empty());

            let resp =
                request(&dir, "GET /docs?a=1&b=2 HTTP/1.1\r\n\r\n").await;
            assert_eq!(301, resp.status.as_u16());
            assert_eq!("./docs/?a=1&b=2", header_of(&resp, header::LOCATION));

            let resp = request(&dir, "GET /docs/ HTTP/1.1\r\n\r\n").await;
            assert_eq!(200, resp.status.as_u16());
        }
        // A file has no slash to add.
        let dir = new_directory(root.path(), "");
        let resp = request(&dir, "GET /docs/index.html HTTP/1.1\r\n\r\n").await;
        assert_eq!(200, resp.status.as_u16());

        // After a rewrite the redirect goes by what the client asked for,
        // path and query: `/static` served from `/docs` is sent to
        // `./static/`, not to `./docs/`, which is outside the location.
        let rewritten = async |original: &'static str| {
            let mock_io = Builder::new()
                .read(b"GET /docs?added=1 HTTP/1.1\r\n\r\n")
                .build();
            let mut session = Session::new_h1(Box::new(mock_io));
            session.read_request().await.unwrap();
            let mut ctx = Ctx::default();
            ctx.features.get_or_insert_default().original_uri =
                Some(http::Uri::from_static(original));
            let result = dir
                .handle_request(PluginStep::Request, &mut session, &mut ctx)
                .await
                .unwrap();
            let RequestPluginResult::Respond(resp) = result else {
                panic!("result is not Respond");
            };
            (resp.status.as_u16(), header_of(&resp, header::LOCATION))
        };
        assert_eq!(
            (301, "./static/?v=2".to_string()),
            rewritten("/static?v=2").await
        );
        // Asked for with the slash: nothing to add, whatever the path
        // became.
        assert_eq!((200, String::new()), rewritten("/static/").await);
    }

    /// Regression: every method was answered like a GET, a POST or a
    /// DELETE with a 200 and the file.
    #[tokio::test]
    async fn test_directory_allows_get_and_head_only() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("a.txt"), "hello").unwrap();
        let dir = new_directory(root.path(), "");

        for method in ["POST", "PUT", "DELETE", "PATCH"] {
            let resp = request(
                &dir,
                &format!(
                    "{method} /a.txt HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
                ),
            )
            .await;
            assert_eq!(405, resp.status.as_u16(), "{method}");
            assert_eq!("GET, HEAD, OPTIONS", header_of(&resp, header::ALLOW));
            assert_ne!(b"hello".as_ref(), resp.body.as_ref());
        }
        // An OPTIONS is answered, not refused: it may be a preflight that
        // a `cors` plugin after this one completes.
        let resp = request(&dir, "OPTIONS /a.txt HTTP/1.1\r\n\r\n").await;
        assert_eq!(204, resp.status.as_u16());
        assert_eq!("GET, HEAD, OPTIONS", header_of(&resp, header::ALLOW));
        assert_eq!(true, resp.body.is_empty());
        let resp = request(&dir, "GET /a.txt HTTP/1.1\r\n\r\n").await;
        assert_eq!(200, resp.status.as_u16());
        assert_eq!(b"hello".as_ref(), resp.body.as_ref());
        let resp = request(&dir, "HEAD /a.txt HTTP/1.1\r\n\r\n").await;
        assert_eq!(200, resp.status.as_u16());
        assert_eq!(true, resp.body.is_empty());
    }

    /// Regression: a `Range` that is no byte range was a 416, where RFC
    /// 9110 has it ignored; `If-Range` was not looked at; and a range short
    /// enough to be read in one piece came without the cache headers.
    #[tokio::test]
    async fn test_directory_range_semantics() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("a.txt"), "0123456789").unwrap();
        let dir = new_directory(root.path(), "max_age = \"1h\"");
        let get = async |headers: &str| {
            request(&dir, &format!("GET /a.txt HTTP/1.1\r\n{headers}\r\n"))
                .await
        };

        let resp = get("Range: bytes=2-5\r\n").await;
        assert_eq!(206, resp.status.as_u16());
        assert_eq!(b"2345".as_ref(), resp.body.as_ref());
        assert_eq!("bytes 2-5/10", header_of(&resp, header::CONTENT_RANGE));
        assert_eq!(Some(3600), resp.max_age);
        let etag = header_of(&resp, header::ETAG);

        // Not a range, so the whole file.
        for range in ["bytes=5-2", "items=0-1", "bytes=a-b", "bytes=-x"] {
            let resp = get(&format!("Range: {range}\r\n")).await;
            assert_eq!(200, resp.status.as_u16(), "{range}");
            assert_eq!(b"0123456789".as_ref(), resp.body.as_ref());
            assert_eq!("", header_of(&resp, header::CONTENT_RANGE));
        }
        // A range, but not of this file.
        for range in ["bytes=10-", "bytes=20-30", "bytes=-0"] {
            let resp = get(&format!("Range: {range}\r\n")).await;
            assert_eq!(416, resp.status.as_u16(), "{range}");
            assert_eq!("bytes */10", header_of(&resp, header::CONTENT_RANGE));
        }

        // `If-Range` with the tag of the file as it is: the range.
        let resp =
            get(&format!("Range: bytes=2-5\r\nIf-Range: {etag}\r\n")).await;
        assert_eq!(206, resp.status.as_u16());
        // With the tag of another version, or a date: the file.
        for if_range in ["W/\"1-1\"", "Wed, 21 Oct 2015 07:28:00 GMT"] {
            let resp =
                get(&format!("Range: bytes=2-5\r\nIf-Range: {if_range}\r\n"))
                    .await;
            assert_eq!(200, resp.status.as_u16(), "{if_range}");
            assert_eq!(b"0123456789".as_ref(), resp.body.as_ref());
        }

        // The HEAD of a short range carries the cache headers as well.
        let resp =
            request(&dir, "HEAD /a.txt HTTP/1.1\r\nRange: bytes=2-5\r\n\r\n")
                .await;
        assert_eq!(206, resp.status.as_u16());
        assert_eq!(Some(3600), resp.max_age);
    }

    /// Regression: a file larger than a chunk is written by the plugin
    /// itself and never passed the proxy, which is where `cors` sets its
    /// headers on what other plugins answer. A small file had them, a
    /// large one did not.
    #[tokio::test]
    async fn test_directory_streamed_response_is_decorated() {
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let root = tempfile::tempdir().unwrap();
        let size = 3 * MIN_CHUNK_SIZE as usize;
        std::fs::write(root.path().join("big.bin"), vec![b'a'; size]).unwrap();
        let dir = new_directory(root.path(), "");
        let cors: Arc<dyn Plugin> = Arc::new(
            crate::cors::Cors::new(
                &toml::from_str::<PluginConf>(
                    "allow_origin = \"https://a.io\"",
                )
                .unwrap(),
            )
            .unwrap(),
        );

        let (mut client, server) = tokio::io::duplex(1024 * 1024);
        client
            .write_all(b"GET /big.bin HTTP/1.1\r\nOrigin: https://a.io\r\n\r\n")
            .await
            .unwrap();
        let mut session = Session::new_h1(Box::new(server));
        session.read_request().await.unwrap();
        // What the proxy leaves in the context while the request plugins
        // of a location with such a plugin run.
        let mut ctx = Ctx {
            response_plugins: Some(Arc::from(vec![(Arc::from("cors"), cors)])),
            ..Default::default()
        };
        dir.handle_request(PluginStep::Request, &mut session, &mut ctx)
            .await
            .unwrap();
        drop(session);
        let mut buf = vec![];
        client.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).into_owned();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        let head = head.to_ascii_lowercase();
        assert_eq!(
            true,
            head.contains("access-control-allow-origin: https://a.io"),
            "{head}"
        );
        assert_eq!(size, body.len());
        // The list is back where the next response finds it.
        assert_eq!(true, ctx.response_plugins.is_some());
    }

    #[test]
    fn test_parse_range_header() {
        let range =
            |value: &str, size: u64| match parse_range_header(value, size) {
                RangeRequest::Satisfiable(range) => {
                    Ok((range.start, range.end))
                },
                RangeRequest::Unsatisfiable => Err("unsatisfiable"),
                RangeRequest::Ignored => Err("ignored"),
            };
        // Test normal range
        assert_eq!(Ok((0, 499)), range("bytes=0-499", 1000));

        // Test open-ended range
        assert_eq!(Ok((500, 999)), range("bytes=500-", 1000));

        // Test suffix range (last N bytes)
        assert_eq!(Ok((500, 999)), range("bytes=-500", 1000));

        // Regression: a suffix longer than the file is the whole file, not
        // an unsatisfiable range.
        assert_eq!(Ok((0, 999)), range("bytes=-1500", 1000));
        assert_eq!(Err("unsatisfiable"), range("bytes=-0", 1000));
        assert_eq!(Err("unsatisfiable"), range("bytes=-500", 0));

        // Test range beyond file size
        assert_eq!(Ok((0, 999)), range("bytes=0-1999", 1000));

        // Test invalid start position
        assert_eq!(Err("unsatisfiable"), range("bytes=1000-", 1000));

        // Regression: what is not a byte range is ignored, and used to be
        // unsatisfiable like a range past the end.
        for value in [
            "invalid",
            "bytes=",
            "bytes=5-2",
            "items=0-1",
            "bytes=a-",
            "bytes=-x",
        ] {
            assert_eq!(Err("ignored"), range(value, 1000), "{value}");
        }

        // Test multipart range (only first part used)
        assert_eq!(Ok((0, 100)), range("bytes=0-100,200-300", 1000));
    }
}
