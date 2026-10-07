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

后端是进程级单例：每个目录一个文件后端，内存后端恰好**一个**，由先请求者创建。

文件后端归属于它的目录。同一个目录、相同的参数就是同一个后端，与路径的写法（`d`、`./d`）和参数的先后顺序无关。用不同的参数再次请求同一个目录（例如热更新时把 `inactive=1h` 改成 `7d`）会构建一个新的后端并接管这个目录：每小时的清扫按新的 `inactive` 执行，被替换的后端对仍在使用它的请求依然有效，但会释放自己的内存热层。因此指向同一个目录的两个 `cache` 插件应当使用相同的参数；参数不同时，由最后构建的那个插件决定目录如何清扫，另一个插件则没有内存热层可用。

`dry_run(|| ...)` 在不改动后端的前提下执行一个闭包：在它内部，`new_cache_backend` 只校验传入的设置并返回已有的后端（或一个替身），不创建目录、不替换后端、也不确定内存缓存的大小。admin 在保存 `cache` 插件之前用它做校验，因为校验发生在正在提供服务的进程里。

### 内存后端

TinyUFO 是 S3-FIFO 风格缓存，扫描抵抗好且无全局锁，比 LRU 更适合代理负载。

| Parameter | Default | Description |
| --- | --- | --- |
| `max_size` | 可用内存的 1/4，否则 256 MB，上限 1 GB | 缓存预算 |
| `mode` | `normal` | TinyUFO 变体：`normal`（也可写 `default`），或 `compact`——索引更小、速度略低 |

`max_size` 两种写法：

| 值 | 含义 |
| --- | --- |
| `max_size=20` | 预算的 20%——纯数字是百分比，超过 100 按 100 算 |
| `max_size=100mb` | 绝对大小——带单位的值按字面取，再小也是 |

`update_available_memory()` 在启动时调用一次，传入可用内存：机器报告的数值，并且不超过容器的内存限制（Linux 上是 cgroup 的限制），使默认预算跟随进程实际运行的环境而非硬编码数。以前只取机器的数值，容器限制小于它的四分之一时，缓存的大小会超过限制。不是容器自身的限制（例如 systemd 单元的 `MemoryMax=`）读不到，这种情况请显式设置 `max_size`。

条目的权重是它的大小按 4 KB 页向上取整（向下取整时，小对象为主的缓存实际占用可以到预算的两倍）。权重超过整个缓存容量的对象不放进内存：TinyUFO 会为了放它把其他条目全部淘汰。40 MB 及以上的对象按最大权重（256 MB）计算。

条目按 4 KB 页计重，因此按页算的预算也是缓存最多能容纳的条目数，TinyUFO 的索引与频率草图就按这个数字预估：256 MB 缓存只需几 MB，1 GB 上限约 16 MB。无法解析的参数（`max_size=lots`、`mode=tiny`）会让 `new_cache_backend` 报错，而不是静默使用默认值。

### 文件后端

| Parameter | Default | Description |
| --- | --- | --- |
| `inactive` | `48h` | 移除超过该时长未触碰的文件，无论是否仍新鲜 |
| `reading_max` | `10000` | 最大并发读；超限按**未命中**处理（回源），不返回 5xx |
| `writing_max` | `1000` | 最大并发写；超限**跳过**磁盘写入 |
| `cache_max` | `0` | 前置 TinyUFO 热层大小，单位 4 KB 页 |
| `cache_file_max_weight` | 256 页（1 MB） | 该层允许的最大条目，写入和从磁盘读出时都受此限制 |
| `levels` | — | 目录嵌套，最多两级、每级取键的 1 到 3 个字符，如 `levels=1:2`，避免巨大扁平目录；其他写法会被拒绝 |
| `max_size` | 无限制 | 磁盘总预算（如 `max_size=10gb`）；超出时按最久未访问优先淘汰文件 |

维持 `max_size` 的开销是：发现超预算的那次写入做一次目录遍历（在阻塞线程池上进行，不会卡住 worker 线程），然后按访问时间顺序删文件直到新对象放得下。淘汰进行期间到达的写入直接写，不等待。比整个预算还大的对象不会写入——为它清空整个缓存没有意义。磁盘用量是累加出来的估计值；这次目录遍历会把它校正为目录里的实际大小，手工删文件或同一个键写两次造成的偏差不会一直留着。

`new_storage_clear_service()` 返回周期性清扫 inactive 文件的后台服务。

“未触碰”和“最久未访问”看的是文件的访问时间。这个时间由缓存在读取对象时自己设置，每个对象大约一分钟一次，由内存热层应答的读取也会设置，不依赖文件系统的挂载方式。以前交给文件系统记录：热层应答的对象从不读磁盘，被请求得越多文件看起来越旧；用 `noatime` 挂载时 `inactive` 实际是从写入时算起。

缓存目录里可以有别的数据。统计用量、淘汰、清扫和清除都只处理缓存自己写的文件：缓存对象（文件名就是键，32 位小写十六进制）和写入时的临时文件（`<key>.<pid>.<seq>.tmp`）。其他文件原样保留，也不计入 `max_size`。别的程序的文件如果恰好也是这种名字（例如以 MD5 命名），无法区分，会被当成缓存对象处理，所以不要和这样的目录共用。

## 命名空间

`cache` 插件的 `namespace` 选项隔离条目。文件后端下成为子目录——这正是命名空间级清除得以实现的基础：`HttpCacheStorage::purge_namespace` 遍历该目录，把每个对象从磁盘移除，清空 TinyUFO 热层，并删掉清空后的目录。热层是整个清空的：它无法按命名空间查找，而且磁盘写入被跳过或失败的对象（超过 `writing_max`、比 `max_size` 还大、写盘出错）只在内存里，没有文件可以找到它。其他命名空间的对象之后从磁盘重新读入。内存后端无法枚举条目，其 `purge_namespace` 返回"不支持"（`Ok(None)`）而不是静默什么都不做。`cache` 插件将此能力暴露为 `PURGE /*`。

## 指标

启用 `tracing` feature 时导出 Prometheus histogram：

| Metric | Meaning |
| --- | --- |
| `pingap_cache_storage_read_time` | 从磁盘读取条目耗时 |
| `pingap_cache_storage_write_time` | 写入条目到磁盘耗时 |

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
