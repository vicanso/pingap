use crate::state::State;
use crate::utils;
use http::{header, HeaderValue};
use pingora::proxy::Session;
use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use substring::Substring;
use tokio::fs;
use url::Url;
use urlencoding::decode;

use crate::http_extra::{HttpChunkResponse, HttpHeader, HttpResponse};

#[derive(Default)]
pub struct Directory {
    path: PathBuf,
    chunk_size: Option<usize>,
    // max age of http response
    max_age: Option<u32>,
    // private for cache control
    cache_private: Option<bool>,
}

async fn get_data(file: &PathBuf) -> std::io::Result<(std::fs::Metadata, fs::File)> {
    let meta = fs::metadata(file).await?;

    if meta.is_dir() {
        return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
    }
    let f = fs::OpenOptions::new().read(true).open(file).await?;

    Ok((meta, f))
}

pub static FILE_PROTOCOL: &str = "file://";

fn get_headers_from_meta(file: &PathBuf, meta: &Metadata) -> Vec<HttpHeader> {
    let result = mime_guess::from_path(file);
    let content_type = HeaderValue::from_str(result.first_or_octet_stream().as_ref()).unwrap();
    let mut headers = vec![(header::CONTENT_TYPE, content_type)];

    if let Ok(mod_time) = meta.modified() {
        let value = mod_time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if value > 0 {
            let etag = format!(r###"W/"{:x}-{:x}""###, meta.size(), value);
            headers.push((header::ETAG, HeaderValue::from_str(&etag).unwrap()));
        }
    }
    headers
}

impl Directory {
    pub fn new(path: &str) -> Self {
        let mut new_path = path.substring(FILE_PROTOCOL.len(), path.len());
        let mut chunk_size = None;
        let mut max_age = None;
        let mut cache_private = None;
        if let Ok(url_info) = Url::parse(path) {
            let query = url_info.query().unwrap();
            if !query.is_empty() {
                new_path = new_path.substring(0, new_path.len() - query.len() - 1);
            }
            for (key, value) in url_info.query_pairs().into_iter() {
                match key.as_ref() {
                    "chunk_size" => {
                        if let Ok(v) = value.parse::<usize>() {
                            chunk_size = Some(v);
                        }
                    }
                    "max_age" => {
                        if let Ok(v) = value.parse::<u32>() {
                            max_age = Some(v);
                        }
                    }
                    "private" => cache_private = Some(false),
                    _ => {}
                }
            }
        };
        Directory {
            path: Path::new(&utils::resolve_path(new_path)).to_path_buf(),
            chunk_size,
            max_age,
            cache_private,
        }
    }
    pub async fn handle(&self, session: &mut Session, _ctx: &mut State) -> pingora::Result<bool> {
        let mut filename = session
            .req_header()
            .uri
            .path()
            .to_string()
            .max("/".to_string());
        if let Ok(value) = decode(&filename) {
            filename = value.into_owned().clone();
        }
        // convert to relative path
        let file = self.path.join(filename.substring(1, filename.len()));

        match get_data(&file).await {
            Ok((meta, mut f)) => {
                let headers = get_headers_from_meta(&file, &meta);
                let mut resp = HttpChunkResponse::new(&mut f);
                if let Some(chunk_size) = self.chunk_size {
                    resp.chunk_size = chunk_size;
                }
                resp.max_age = self.max_age;
                resp.cache_private = self.cache_private;
                resp.headers = Some(headers);
                resp.send(session).await?
            }
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    HttpResponse::not_found()
                } else {
                    HttpResponse::unknown_error()
                }
                .send(session)
                .await?
            }
        };

        Ok(true)
    }
}
