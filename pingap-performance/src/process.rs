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

use bytesize::ByteSize;
use memory_stats::memory_stats;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::process;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use sysinfo::MemoryRefreshKind;
use sysinfo::{RefreshKind, System};

static ACCEPTED: Lazy<AtomicU64> = Lazy::new(|| AtomicU64::new(0));
static PROCESSING: Lazy<AtomicI32> = Lazy::new(|| AtomicI32::new(0));

/// Increments the request acceptance and processing counters.
/// This should be called when a new request is received to track request metrics.
pub fn accept_request() {
    ACCEPTED.fetch_add(1, Ordering::Relaxed);
    PROCESSING.fetch_add(1, Ordering::Relaxed);
}

/// Decrements the request processing counter when a request completes.
/// This should be called when a request finishes processing to maintain accurate metrics.
pub fn end_request() {
    PROCESSING.fetch_sub(1, Ordering::Relaxed);
}

/// Returns a tuple of (currently processing requests, total accepted requests).
///
/// Returns:
/// - `i32`: Number of requests currently being processed
/// - `u64`: Total number of requests accepted since startup
pub fn get_processing_accepted() -> (i32, u64) {
    let processing = PROCESSING.load(Ordering::Relaxed);
    let accepted = ACCEPTED.load(Ordering::Relaxed);
    (processing, accepted)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProcessSystemInfo {
    /// Current memory usage in megabytes
    pub memory_mb: usize,
    /// Current memory usage as a human-readable string (e.g. "100 MB")
    pub memory: String,
    /// CPU architecture (e.g. "x86_64", "aarch64")
    pub arch: String,
    /// Number of logical CPU cores
    pub cpus: usize,
    /// Number of physical CPU cores
    pub physical_cpus: usize,
    /// Total system memory as a human-readable string
    pub total_memory: String,
    /// Used system memory as a human-readable string
    pub used_memory: String,
    /// Kernel version string
    pub kernel: String,
    /// Process ID of the current process
    pub pid: u32,
    /// Number of threads configured across all servers
    pub threads: i64,
    /// Number of open file descriptors (Linux only)
    pub fd_count: usize,
    /// Number of IPv4 TCP connections (Linux only)
    pub tcp_count: usize,
    /// Number of IPv6 TCP connections (Linux only)
    pub tcp6_count: usize,
}

/// Gathers and returns system information including memory usage, CPU details,
/// process statistics and network connection counts
pub fn get_process_system_info() -> ProcessSystemInfo {
    let pid = process::id();

    cfg_if::cfg_if! {
        if #[cfg(target_os = "linux")] {
            let (fd_count, tcp_count, tcp6_count, threads) = if let Ok(p) = procfs::process::Process::new(pid as i32) {
                let mut threads = -1_i64;
                if let Ok(stat) = p.stat() {
                    threads = stat.num_threads;
                }
                (
                    p.fd_count().unwrap_or_default(),
                    p.tcp().unwrap_or_default().len(),
                    p.tcp6().unwrap_or_default().len(),
                    threads,
                )
            } else {
                (0, 0, 0, -1_i64)
            };
        } else {
            let (fd_count, tcp_count, tcp6_count, threads) = (0, 0, 0, -1_i64);
        }
    }

    let mut memory = "".to_string();
    let mut memory_mb = 0;
    if let Some(value) = memory_stats() {
        memory_mb = value.physical_mem / (1024 * 1024);
        memory = ByteSize(value.physical_mem as u64).to_string();
    }
    let cpus = num_cpus::get();
    let physical_cpus = num_cpus::get_physical();
    let kind = MemoryRefreshKind::nothing().with_ram();
    let mut sys =
        System::new_with_specifics(RefreshKind::nothing().with_memory(kind));
    sys.refresh_memory();

    ProcessSystemInfo {
        memory,
        memory_mb,
        arch: System::cpu_arch(),
        cpus,
        physical_cpus,
        kernel: System::kernel_version().unwrap_or_default(),
        total_memory: ByteSize(sys.total_memory()).to_string(),
        used_memory: ByteSize(sys.used_memory()).to_string(),
        pid,
        threads,
        fd_count,
        tcp_count,
        tcp6_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_get_process_system_info() {
        let info = get_process_system_info();
        assert_eq!(true, info.memory_mb > 0);
        assert_eq!(true, !info.memory.is_empty());
        assert_eq!(true, !info.arch.is_empty());
        assert_eq!(true, info.cpus > 0);
        assert_eq!(true, info.physical_cpus > 0);
        assert_eq!(true, !info.kernel.is_empty());
        assert_eq!(true, info.pid != 0);
    }

    #[test]
    fn test_get_processing_accepted() {
        let (processing, accepted) = get_processing_accepted();
        assert_eq!(processing, 0);
        assert_eq!(accepted, 0);
        accept_request();
        let (processing, accepted) = get_processing_accepted();
        assert_eq!(processing, 1);
        assert_eq!(accepted, 1);
        end_request();
        let (processing, accepted) = get_processing_accepted();
        assert_eq!(processing, 0);
        assert_eq!(accepted, 1);
    }
}
