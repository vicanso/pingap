use http::StatusCode;
use std::time::Instant;

pub struct State {
    pub created_at: Instant,
    pub status: Option<StatusCode>,
    pub response_body_size: usize,
}

impl Default for State {
    fn default() -> Self {
        State {
            status: None,
            created_at: Instant::now(),
            response_body_size: 0,
        }
    }
}
