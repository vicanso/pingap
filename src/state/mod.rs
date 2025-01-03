// Copyright 2024 Tree xie.
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

use crate::service::SimpleServiceTaskFuture;
#[cfg(feature = "full")]
use snafu::Snafu;
use tracing::info;

mod ctx;
mod process;
#[cfg(feature = "full")]
mod prom;
pub use ctx::*;
pub use process::*;
#[cfg(feature = "full")]
pub use prom::{
    new_prometheus, new_prometheus_push_service, Prometheus,
    CACHE_READING_TIME, CACHE_WRITING_TIME,
};

#[cfg(feature = "full")]
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("{source}"))]
    Url { source: url::ParseError },
    #[snafu(display("{message}"))]
    Prometheus { message: String },
}
#[cfg(feature = "full")]
pub type Result<T, E = Error> = std::result::Result<T, E>;

pub fn new_performance_metrics_log_service() -> (String, SimpleServiceTaskFuture)
{
    let task: SimpleServiceTaskFuture = Box::new(move |_count: u32| {
        Box::pin({
            async move {
                let system_info = get_process_system_info();
                let (processing, accepted) = get_processing_accepted();
                info!(
                    threads = system_info.threads,
                    accepted,
                    processing,
                    used_memory = system_info.memory,
                    fd_count = system_info.fd_count,
                    tcp_count = system_info.tcp_count,
                    tcp6_count = system_info.tcp6_count,
                    "performance metrics"
                );
                Ok(true)
            }
        })
    });
    ("performanceMetricsLog".to_string(), task)
}
