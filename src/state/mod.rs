use http::StatusCode;
use std::time::Instant;

pub struct State {
    pub http_version: u8,
    pub processing: i32,
    pub created_at: Instant,
    pub status: Option<StatusCode>,
    pub response_body_size: usize,
    pub response_size: usize,
    pub reused: bool,
    pub upstream_address: String,
    pub location_index: Option<usize>,
    pub remote_ip : String,
}

impl Default for State {
    fn default() -> Self {
        State {
            http_version: 1,
            processing: 0,
            status: None,
            created_at: Instant::now(),
            response_body_size: 0,
            response_size: 0,
            reused: false,
            upstream_address: "".to_string(),
            location_index: None,
        }
    }
}
