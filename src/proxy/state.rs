use std::time::Instant;

pub struct State {
    pub created_at: Instant,
}

impl Default for State {
    fn default() -> Self {
        State {
            created_at: Instant::now(),
        }
    }
}
