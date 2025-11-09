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
use super::Error;
use prometheus::{Histogram, HistogramOpts, Opts};
use std::sync::LazyLock;
type Result<T, E = Error> = std::result::Result<T, E>;

fn new_histogram(
    server: &str,
    name: &str,
    help: &str,
    buckets: &[f64],
) -> Result<Histogram> {
    let mut opts = Opts::new(name, help);
    if !server.is_empty() {
        opts = opts.const_label("server", server);
    }
    let histogram = Histogram::with_opts(HistogramOpts {
        common_opts: opts,
        buckets: Vec::from(buckets),
    })
    .map_err(|e| Error::Prometheus {
        message: e.to_string(),
    })?;
    Ok(histogram)
}

pub static CACHE_READING_TIME: LazyLock<Box<Histogram>> = LazyLock::new(|| {
    Box::new(
        new_histogram(
            "",
            "pingap_cache_storage_read_time",
            "pingap cache storage read time(second)",
            &[0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0],
        )
        .expect("Failed to register CACHE_READING_TIME histogram metric"),
    )
});
pub static CACHE_WRITING_TIME: LazyLock<Box<Histogram>> = LazyLock::new(|| {
    Box::new(
        new_histogram(
            "",
            "pingap_cache_storage_write_time",
            "pingap cache storage write time(second)",
            &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
        )
        .expect("Failed to register CACHE_WRITING_TIME histogram metric"),
    )
});
