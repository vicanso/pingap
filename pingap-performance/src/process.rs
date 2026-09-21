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

use arc_swap::ArcSwapOption;
use bytesize::ByteSize;
use memory_stats::memory_stats;
use pingap_core::now_ms;
use serde::{Deserialize, Serialize};
use std::process;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use sysinfo::MemoryRefreshKind;
use sysinfo::{RefreshKind, System};

static ACCEPTED: AtomicU64 = AtomicU64::new(0);
static PROCESSING: AtomicI32 = AtomicI32::new(0);

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

#[derive(Serialize, Deserialize, Debug, Clone)]
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
    /// Number of OS threads in this process; `-1` where it cannot be read
    /// (everything but Linux)
    pub threads: i64,
    /// Number of open file descriptors (Linux only)
    pub fd_count: usize,
    /// Number of IPv4 TCP sockets in this process's network namespace, which
    /// includes any other process sharing it (Linux only)
    pub tcp_count: usize,
    /// Number of IPv6 TCP sockets in this process's network namespace, which
    /// includes any other process sharing it (Linux only)
    pub tcp6_count: usize,
}

/// The fields that cannot change while the process runs. `pid` is not among
/// them: pingora forks for daemon mode, and the child must report its own.
struct ConstantSystemInfo {
    arch: String,
    cpus: usize,
    physical_cpus: usize,
    kernel: String,
}

static CONSTANT_INFO: OnceLock<ConstantSystemInfo> = OnceLock::new();

fn constant_system_info() -> &'static ConstantSystemInfo {
    CONSTANT_INFO.get_or_init(|| ConstantSystemInfo {
        arch: System::cpu_arch(),
        cpus: num_cpus::get(),
        // Parses /proc/cpuinfo on Linux, so worth doing exactly once.
        physical_cpus: num_cpus::get_physical(),
        kernel: System::kernel_version().unwrap_or_default(),
    })
}

struct CachedProcessInfo {
    collected_at: u64,
    info: ProcessSystemInfo,
}

/// The most recent snapshot. Collecting one reads several `/proc` files, and
/// three consumers ask for it independently (a Prometheus scrape, the `stats`
/// plugin on every request to its path, and the metrics log task), so the
/// cost is bounded to one collection per `CACHE_TTL_MS` no matter how often
/// it is asked for. Lock-free, because a `Mutex` held by another thread at
/// `fork()` time would stay locked forever in the daemon.
static CACHED_INFO: ArcSwapOption<CachedProcessInfo> =
    ArcSwapOption::const_empty();

/// How long a collected snapshot is served before it is taken again. Well
/// under any scrape interval, so the exported values stay current.
const CACHE_TTL_MS: u64 = 1000;

/// Number of entries in a `/proc` socket table (`/proc/<pid>/net/tcp` and
/// friends): one header line, then one line per socket.
///
/// Counted rather than parsed on purpose. `procfs` builds a `Vec` of fully
/// parsed `TcpNetEntry` values, addresses, states and inodes included, only
/// for `.len()` to be taken - on a busy proxy that is every socket in the
/// network namespace, parsed and dropped, on every call.
#[cfg(target_os = "linux")]
#[inline]
fn count_table_lines(data: &[u8]) -> usize {
    data.iter()
        .filter(|byte| **byte == b'\n')
        .count()
        .saturating_sub(1)
}

#[cfg(target_os = "linux")]
fn count_socket_table(path: &str) -> usize {
    // `/proc` files report a size of zero, so read to end rather than
    // pre-allocating from the metadata.
    std::fs::read(path)
        .map(|data| count_table_lines(&data))
        .unwrap_or_default()
}

/// Gathers system information including memory usage, CPU details, process
/// statistics and network connection counts. Snapshots are cached for
/// [`CACHE_TTL_MS`].
pub fn get_process_system_info() -> ProcessSystemInfo {
    let now = now_ms();
    if let Some(cached) = CACHED_INFO.load_full()
        && now.saturating_sub(cached.collected_at) < CACHE_TTL_MS
    {
        return cached.info.clone();
    }
    let info = collect_process_system_info();
    CACHED_INFO.store(Some(Arc::new(CachedProcessInfo {
        collected_at: now,
        info: info.clone(),
    })));
    info
}

fn collect_process_system_info() -> ProcessSystemInfo {
    let pid = process::id();

    cfg_if::cfg_if! {
        if #[cfg(target_os = "linux")] {
            let (fd_count, threads) = match procfs::process::Process::myself() {
                Ok(p) => (
                    p.fd_count().unwrap_or_default(),
                    p.stat().map(|stat| stat.num_threads).unwrap_or(-1),
                ),
                Err(_) => (0, -1),
            };
            let tcp_count = count_socket_table("/proc/self/net/tcp");
            let tcp6_count = count_socket_table("/proc/self/net/tcp6");
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
    let kind = MemoryRefreshKind::nothing().with_ram();
    let mut sys =
        System::new_with_specifics(RefreshKind::nothing().with_memory(kind));
    sys.refresh_memory();

    let constant = constant_system_info();
    ProcessSystemInfo {
        memory,
        memory_mb,
        arch: constant.arch.clone(),
        cpus: constant.cpus,
        physical_cpus: constant.physical_cpus,
        kernel: constant.kernel.clone(),
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

        // The snapshot is cached, and the cached copy is the same data.
        let again = get_process_system_info();
        assert_eq!(info.pid, again.pid);
        assert_eq!(info.arch, again.arch);
    }

    /// The counters are global, so the test asserts on the change it makes
    /// rather than on absolute values another test could have moved.
    #[test]
    fn test_get_processing_accepted() {
        let (processing, accepted) = get_processing_accepted();
        accept_request();
        assert_eq!((processing + 1, accepted + 1), get_processing_accepted());
        end_request();
        assert_eq!((processing, accepted + 1), get_processing_accepted());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_count_table_lines() {
        // Header only: no sockets.
        assert_eq!(0, count_table_lines(b"  sl  local_address\n"));
        assert_eq!(
            2,
            count_table_lines(b"  sl  local_address\n  0: entry\n  1: entry\n")
        );
        // A truncated read must not underflow.
        assert_eq!(0, count_table_lines(b""));
        assert_eq!(0, count_table_lines(b"no newline"));
    }
}
