# Pingap Cache

[Pingap](https://github.com/vicanso/pingap) 的 HTTP 缓存存储后端。

本 crate 实现两次 pingora 缓存存储接口——一次基于 [TinyUFO](https://github.com/cloudflare/pingora/tree/main/tinyufo) 的内存，一次基于磁盘——并通过单一 `new_cache_backend(directory)` 入口暴露。用户配置面对的是 [`cache` 插件](../plugins/cache.md)；本 crate 是其下的存储层。

## 后端

| `directory` value | Backend |
| --- | --- |
| `""` 或 `memory://…` | 内存 TinyUFO 缓存 |
| 其他任何值 | 以该路径为根的文件缓存 |

```rust
use pingap_cache::new_cache_backend;

let memory = new_cache_backend("memory://pingap?max_size=100mb&mode=default")?;
let file   = new_cache_backend("/opt/pingap/cache?inactive=1h&reading_max=1000")?;
```

后端是进程级单例：文件后端按目录字符串记忆化，内存后端恰好**一个**，由先请求者创建。

### 内存后端

TinyUFO 是 S3-FIFO 风格缓存，扫描抵抗好且无全局锁，比 LRU 更适合代理负载。

| Parameter | Default | Description |
| --- | --- | --- |
| `max_size` | 可用内存的 1/4，否则 256 MB，上限 1 GB | 缓存预算 |
| `mode` | `default` | TinyUFO 缓存模式 |

`max_size` **低于 10 MB 时解释为预算百分比**而非绝对大小——`max_size=20` 表示 20%。因检查的是字节值，`max_size=5mb` 也会进入百分比分支并钳到 100%，得到全部预算而非 5 MB。表示绝对大小时请用 10 MB 及以上。

`update_available_memory()` 由进程指标收集器调用，使默认预算跟踪机器（或容器限制）而非硬编码数。

### 文件后端

| Parameter | Default | Description |
| --- | --- | --- |
| `inactive` | 无 | 移除超过该时长未触碰的文件，无论是否仍新鲜 |
| `reading_max` | `10000` | 最大并发读 |
| `writing_max` | — | 最大并发写 |
| `cache_max` | `0` | 前置 TinyUFO 热层大小 |
| `cache_file_max_weight` | 256 页（1 MB） | 该层允许的最大条目 |
| `levels` | — | 目录嵌套层级，如 `levels=1:2`，避免巨大扁平目录 |

`new_storage_clear_service()` 返回周期性清扫 inactive 文件的后台服务。

## 命名空间

`cache` 插件的 `namespace` 选项隔离条目。文件后端下成为子目录——这正是命名空间级清除得以实现的基础：`HttpCacheStorage::purge_namespace` 遍历该目录，把每个对象从磁盘和 TinyUFO 热层一并移除（文件名就是缓存键哈希，同时也是内存层的键），并删掉清空后的目录。内存后端无法枚举条目，其 `purge_namespace` 返回"不支持"（`Ok(None)`）而不是静默什么都不做。`cache` 插件将此能力暴露为 `PURGE /*`。

## 指标

启用 `tracing` feature 时导出 Prometheus histogram：

| Metric | Meaning |
| --- | --- |
| `pingap_cache_reading_time` | 读取条目耗时 |
| `pingap_cache_writing_time` | 写入条目耗时 |

缓存读/写计数也通过 `Ctx` 按请求暴露，访问日志中可用 `{:cache_lookup_time}` 与 `{:cache_lock_time}`。

## 如何选择后端

| | Memory | File |
| --- | --- | --- |
| 延迟 | 最低 | 受磁盘约束 |
| 重启存活 | 否 | 是 |
| 容量 | 受 RAM 限制 | 受磁盘限制 |
| 淘汰 | LRU（`cache` 插件启用时） | Inactive 文件清扫 |

注意：仅当后端报告非零最大尺寸时才接线 LRU 淘汰，文件后端没有——文件缓存回收靠 `inactive` 清扫。

## 许可证

Apache-2.0。
