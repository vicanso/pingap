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
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use sysinfo::MemoryRefreshKind;
use sysinfo::{RefreshKind, System};

const REQUEST_COUNTER_SHARDS: usize = 16;

/// Per-thread-shard request counters, padded to 128 bytes so concurrent workers
/// never share cache lines across x86_64 or Apple Silicon cores.
#[repr(align(128))]
struct RequestCounterShard {
    processing: AtomicI64,
    accepted: AtomicU64,
}

impl RequestCounterShard {
    const fn new() -> Self {
        Self {
            processing: AtomicI64::new(0),
            accepted: AtomicU64::new(0),
        }
    }
}

static REQUEST_COUNTERS: [RequestCounterShard; REQUEST_COUNTER_SHARDS] =
    [const { RequestCounterShard::new() }; REQUEST_COUNTER_SHARDS];
static NEXT_SHARD: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static SHARD_INDEX: usize =
        NEXT_SHARD.fetch_add(1, Ordering::Relaxed) & (REQUEST_COUNTER_SHARDS - 1);
}

#[inline]
fn current_shard() -> &'static RequestCounterShard {
    let index = SHARD_INDEX.with(|idx| *idx);
    &REQUEST_COUNTERS[index]
}

/// Increments the request acceptance and processing counters.
/// This should be called when a new request is received to track request metrics.
pub fn accept_request() {
    let shard = current_shard();
    shard.accepted.fetch_add(1, Ordering::Relaxed);
    shard.processing.fetch_add(1, Ordering::Relaxed);
}

/// Decrements the request processing counter when a request completes.
/// This should be called when a request finishes processing to maintain accurate metrics.
pub fn end_request() {
    current_shard().processing.fetch_sub(1, Ordering::Relaxed);
}

/// Returns a tuple of (currently processing requests, total accepted requests).
///
/// Returns:
/// - `i32`: Number of requests currently being processed
/// - `u64`: Total number of requests accepted since startup
pub fn get_processing_accepted() -> (i32, u64) {
    let mut processing_sum: i64 = 0;
    let mut accepted_sum: u64 = 0;
    for shard in &REQUEST_COUNTERS {
        processing_sum += shard.processing.load(Ordering::Relaxed);
        accepted_sum += shard.accepted.load(Ordering::Relaxed);
    }
    (processing_sum.max(0) as i32, accepted_sum)
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
    let (total_memory, used_memory) = match System::new_with_specifics(
        RefreshKind::nothing().with_memory(kind),
    ) {
        Ok(mut sys) => {
            sys.refresh_memory();
            (
                ByteSize(sys.total_memory()).to_string(),
                ByteSize(sys.used_memory()).to_string(),
            )
        },
        // The host figures are unknown. The process's own `memory` above
        // still comes from `memory_stats`.
        Err(_) => (ByteSize(0).to_string(), ByteSize(0).to_string()),
    };

    let constant = constant_system_info();
    ProcessSystemInfo {
        memory,
        memory_mb,
        arch: constant.arch.clone(),
        cpus: constant.cpus,
        physical_cpus: constant.physical_cpus,
        kernel: constant.kernel.clone(),
        total_memory,
        used_memory,
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

    static TEST_COUNTER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The counters are global, so the test asserts on the change it makes
    /// rather than on absolute values another test could have moved.
    #[test]
    fn test_get_processing_accepted() {
        let _guard =
            TEST_COUNTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (processing, accepted) = get_processing_accepted();
        accept_request();
        assert_eq!((processing + 1, accepted + 1), get_processing_accepted());
        end_request();
        assert_eq!((processing, accepted + 1), get_processing_accepted());
    }

    #[test]
    fn test_get_processing_accepted_multithreaded() {
        let _guard =
            TEST_COUNTER_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert!(std::mem::align_of::<RequestCounterShard>() >= 128);
        assert!(std::mem::size_of::<RequestCounterShard>() >= 128);

        let (base_processing, base_accepted) = get_processing_accepted();
        let threads = 20usize;
        let per_thread = 100usize;
        let total = threads * per_thread;
        let barrier = Arc::new(std::sync::Barrier::new(threads));

        // Phase 1: each thread accepts `per_thread` requests on its shard,
        // synchronizes at the barrier while another set of fresh threads ends
        // them on different shards, verifying signed cross-shard cancellation.
        let mut accept_handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let barrier = barrier.clone();
            accept_handles.push(std::thread::spawn(move || {
                for _ in 0..per_thread {
                    accept_request();
                }
                barrier.wait();
            }));
        }
        for handle in accept_handles {
            handle.join().unwrap();
        }
        assert_eq!(
            (base_processing + total as i32, base_accepted + total as u64),
            get_processing_accepted()
        );

        let mut end_handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            end_handles.push(std::thread::spawn(move || {
                for _ in 0..per_thread {
                    end_request();
                }
            }));
        }
        for handle in end_handles {
            handle.join().unwrap();
        }
        assert_eq!(
            (base_processing, base_accepted + total as u64),
            get_processing_accepted()
        );
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
