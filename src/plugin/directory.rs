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
    get_bool_conf, get_hash_key, get_step_conf, get_str_conf,
    get_str_slice_conf, Error, Plugin, Result,
};
use crate::http_extra::{
    convert_headers, HttpChunkResponse, HttpHeader, HttpResponse,
};
use crate::state::State;
use async_trait::async_trait;
use bytesize::ByteSize;
use glob::glob;
use http::{header, HeaderValue, StatusCode};
use humantime::parse_duration;
use once_cell::sync::Lazy;
use pingap_config::{PluginCategory, PluginConf, PluginStep};
use pingora::proxy::Session;
use std::fs::Metadata;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::UNIX_EPOCH;
use substring::Substring;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tracing::{debug, error};
use urlencoding::decode;

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
    let content_type = HeaderValue::from_str(&value).unwrap();
    let mut headers = vec![(header::CONTENT_TYPE, content_type)];

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
            let etag = format!(r###"W/"{:x}-{:x}""###, size, value);
            headers.push((header::ETAG, HeaderValue::from_str(&etag).unwrap()));
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
}

static IGNORE_RESPONSE: Lazy<HttpResponse> = Lazy::new(|| HttpResponse {
    status: StatusCode::from_u16(999).unwrap(),
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
        }

        let name = f.file_name().unwrap_or_default().to_string_lossy();
        if name.is_empty() || name.starts_with('.') {
            continue;
        }

        let mut target =
            format!("./{}", filepath.split('/').last().unwrap_or_default());
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
    fn hash_key(&self) -> String {
        self.hash_value.clone()
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
        ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if step != self.plugin_step {
            return Ok(None);
        }
        let mut filename = session.req_header().uri.path().to_string();
        if !self.autoindex && filename.len() <= 1 {
            filename.clone_from(&self.index);
        }
        if let Ok(value) = decode(&filename) {
            filename.clone_from(&value.into_owned());
        }
        // convert to relative path
        let file = self.path.join(filename.substring(1, filename.len()));
        debug!(file = format!("{file:?}"), "static file serve");
        if self.autoindex && file.is_dir() {
            let resp = match get_autoindex_html(&file) {
                Ok(html) => HttpResponse::html(html.into()),
                Err(e) => HttpResponse::bad_request(e.to_string().into()),
            };
            return Ok(Some(resp));
        }

        // Content-Disposition: attachment; filename="example.pdf"

        let resp = match get_data(&file).await {
            Ok((meta, mut f)) => {
                let (cacheable, size, mut headers) =
                    get_cacheable_and_headers_from_meta(
                        &file,
                        &meta,
                        &self.charset,
                    );
                if self.download {
                    if let Ok(value) = HeaderValue::from_str(&format!(
                        r###"attachment; filename="{}""###,
                        file.file_name().unwrap_or_default().to_string_lossy()
                    )) {
                        headers.push((header::CONTENT_DISPOSITION, value));
                    }
                }
                if let Some(arr) = &self.headers {
                    headers.extend(arr.clone());
                }
                let chunk_size = self.chunk_size.unwrap_or_default().max(4096);
                if size <= chunk_size {
                    let mut buffer = vec![0; size];
                    match f.read(&mut buffer).await {
                        Ok(_) => HttpResponse {
                            status: StatusCode::OK,
                            max_age: self.max_age,
                            cache_private: self.cache_private,
                            headers: Some(headers),
                            body: buffer.into(),
                            ..Default::default()
                        },
                        Err(e) => {
                            error!(error = e.to_string(), "read data fail");
                            HttpResponse::bad_request(e.to_string().into())
                        },
                    }
                } else {
                    let mut resp = HttpChunkResponse::new(&mut f);
                    resp.chunk_size = chunk_size;
                    if cacheable {
                        resp.max_age = self.max_age;
                    }
                    resp.cache_private = self.cache_private;
                    resp.headers = Some(headers);
                    ctx.status = Some(StatusCode::OK);
                    resp.send(session).await?;
                    // TODO better way to handle chunk response
                    IGNORE_RESPONSE.clone()
                }
            },
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    HttpResponse::not_found("Not Found".into())
                } else {
                    HttpResponse::unknown_error("Get file data fail".into())
                }
            },
        };

        Ok(Some(resp))
    }
}

#[cfg(test)]
mod tests {
    use super::{get_cacheable_and_headers_from_meta, get_data, Directory};
    use crate::plugin::Plugin;
    use crate::state::State;
    use pingap_config::{PluginConf, PluginStep};
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
        assert_eq!("Plugin directory invalid, message: Directory serve plugin should be executed at request or proxy upstream step", result.err().unwrap().to_string());
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
index = "/pingap/index.html"
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
        assert_eq!("/pingap/index.html", dir.index);

        let headers = ["Accept-Encoding: gzip"].join("\r\n");
        let input_header =
            format!("GET /error.html?size=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        let result = dir
            .handle_request(
                PluginStep::Request,
                &mut session,
                &mut State::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_some());
        let resp = result.unwrap();
        assert_eq!(200, resp.status.as_u16());
        let headers = resp.headers.unwrap();
        assert_eq!(
            r#"("content-type", "text/html")"#,
            format!("{:?}", headers[0])
        );
        assert_eq!(
            r#"("content-disposition", "attachment; filename=\"error.html\"")"#,
            format!("{:?}", headers[2])
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
                &mut State::default(),
            )
            .await
            .unwrap();
        assert_eq!(true, result.is_some());
        let resp = result.unwrap();
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
        let file = Path::new("./error.html").to_path_buf();
        let (meta, _) = get_data(&file).await.unwrap();

        assert_ne!(0, meta.size());

        let (cacheable, _, headers) = get_cacheable_and_headers_from_meta(
            &file,
            &meta,
            &Some("utf-8".to_string()),
        );
        assert_eq!(false, cacheable);
        assert_eq!(
            true,
            format!("{headers:?}").contains(
                r###"("content-type", "text/html; charset=utf-8")"###
            )
        );
    }
}
