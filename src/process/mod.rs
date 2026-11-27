mod auto_restart;
mod cache_purge;
mod common;
mod docker_labels;
mod exit_mark;

pub use auto_restart::*;
pub use cache_purge::*;
pub use common::*;
pub use docker_labels::*;
#[cfg(test)]
pub(crate) use exit_mark::set_shutting_down_for_test;
pub use exit_mark::{
    ExitMark, ExitMarkService, Mark, abnormal_exit, install_panic_hook,
    is_shutting_down, remove_on_clean_exit,
};
