# Pingap Config

[Pingap](https://github.com/vicanso/pingap) 的配置模型、存储后端与格式转换。

Pingap 可配置的一切都表达为 `PingapConfig`。本 crate 拥有该类型、从某处加载它的代码、在代理启动前拒绝错误配置的校验，以及三种支持输入格式之间的转换。

## 配置模型

```rust
pub struct PingapConfig {
    pub basic: BasicConf,
    pub upstreams: HashMap<String, UpstreamConf>,
    pub locations: HashMap<String, LocationConf>,
    pub servers: HashMap<String, ServerConf>,
    pub plugins: HashMap<String, PluginConf>,
    pub certificates: HashMap<String, CertificateConf>,
    pub storages: HashMap<String, StorageConf>,
}
```

| Section | Purpose |
| --- | --- |
| `basic` | 进程级设置：线程、用户/组、pid 文件、日志、webhook、Sentry、Pyroscope、可信代理 |
| `servers` | 监听器：地址、TLS、HTTP/2、访问日志、指标、服务的 location |
| `locations` | 路由规则：主机/路径匹配、改写、头、插件、限制 |
| `upstreams` | 后端池：地址、发现、负载均衡、健康检查、超时、熔断 |
| `plugins` | 插件实例，按名称索引，`category` 选择实现 |
| `certificates` | TLS 证书，含 ACME 设置 |
| `storages` | 可被 `includes` 引用的可复用片段；ACME 也在此保存 challenge 状态 |

每个 section 实现 `Validate`。`pingap -t` 加载配置、运行全部校验器后退出——可在 CI 与重载前使用。

## 存储后端

由 `-c` / `PINGAP_CONF` 的值选择后端：

| Value | Backend | Layout | Hot reload |
| --- | --- | --- | --- |
| `/opt/pingap/pingap.toml` | 单文件 | `Single` | 轮询 |
| `/opt/pingap/conf`（目录） | 按类别分文件 | `MultiByType` | 轮询 |
| `/opt/pingap/conf?separation=true` | 每项一文件 | `MultiByItem` | 轮询 |
| `etcd://127.0.0.1:2379/pingap` | etcd | `MultiByItem` | 经 watch 流推送 |
| *(进程内)* | `MemoryStorage` | `Single` | 无 |

```bash
pingap -c /opt/pingap/conf --autoreload
pingap -c "etcd://127.0.0.1:2379/pingap?timeout=10s&connect_timeout=5s" --autoreload
pingap -c "/opt/pingap/conf?separation=true&enable_history=true"
```

文件后端（仅目录）查询参数：

| Parameter | Meaning |
| --- | --- |
| `separation=true` | 每项写入独立文件。除字面 `false` 外均视为 true。 |
| `enable_history=true` | 在配置旁保留历史版本（`<dir>-history`），供管理 UI 恢复。需要 `separation`。 |

`MemoryStorage` 支撑无配置文件的快速启动（`pingap --domain=… --upstream=…`）：配置由命令行合成并放在内存中，写入可选择镜像到文件，使 ACME 签发的证书在重启后仍可用。

### `Storage` trait

```rust
#[async_trait]
pub trait Storage: Send + Sync {
    async fn fetch(&self, key: &str) -> Result<String>;
    async fn save(&self, key: &str, value: &str) -> Result<()>;
    async fn delete(&self, key: &str) -> Result<()>;
    fn support_observer(&self) -> bool { false }
    fn support_history(&self) -> bool { false }
    // ...
}
```

在 `Single` 模式下，更新与删除都是读-改-写后一次 `save`，因此后端只需实现 `fetch` 与 `save`。`ConfigManager` 用互斥锁串行这些读改写，避免并发 admin 与 ACME 写入互相覆盖。

## 配置格式

同一配置可写为 TOML（规范）、HCL 或 KDL。加载目录时优先 `.toml`；没有则试 `.hcl`，再试 `.kdl`。HCL 与 KDL 在内存中转为 TOML，仅为输入格式——下游一律看到 TOML。

```toml
[upstreams.api]
addrs = ["api.github.com:443"]
discovery = "dns"
sni = "api.github.com"

[locations.github-api]
upstream = "api"
path = "/api"
rewrite = "^/api/(?<path>.+)$ /$1"

[servers.test]
addr = "127.0.0.1:6118"
locations = ["github-api"]
```

```hcl
server "test" {
  addr = "127.0.0.1:6118"

  location "github-api" {
    path    = "/api"
    rewrite = "^/api/(?<path>.+)$ /$1"

    upstream "api" {
      addrs     = ["api.github.com:443"]
      discovery = "dns"
      sni       = "api.github.com"
    }
  }
}
```

HCL 支持 `$ENV:NAME` 插值，密钥可来自环境而非文件：

```hcl
upstream "api" {
  addrs     = ["$ENV:PINGAP_API_ADDR"]
  discovery = "dns"
}
```

命令行转换与迁移：

```bash
pingap -c /opt/pingap/conf --to-hcl ./conf.hcl        # dump as HCL
pingap -c /opt/pingap/conf --to-kdl ./conf.kdl        # dump as KDL
pingap -c /opt/pingap/conf --sync etcd://127.0.0.1:2379/pingap   # file -> etcd
pingap --template > pingap.toml                       # starter config
pingap -c /opt/pingap/conf -t                         # validate and exit
```

## 热更新

`ConfigManager::support_observer()` 决定变更如何到达：

- **etcd** 返回 `true`，经 `etcd_client::WatchStream` 推送。
- **文件** 返回 `false`，按 `basic.auto_restart_check_interval` 轮询。

两者接入同一重载句柄；区别仅在投递机制。`--autoreload` 就地交换配置，适合容器。`--autorestart` 做零停机优雅重启，监听级变更需要它。

## Includes

`servers`、`locations` 与 `upstreams` 可接受命名 `storages` 条目的 `includes` 列表，其 TOML 内容合并进该 section。共享块（一组超时、公共头列表）可只定义一次。

```toml
[storages.commonTimeouts]
category = "config"
value = """
connection_timeout = "5s"
read_timeout = "30s"
"""

[upstreams.api]
addrs = ["10.0.0.1:8080"]
includes = ["commonTimeouts"]
```

`to_pingap_config(replace_include)` 控制是否展开 includes；管理 UI 读未展开形式以便编辑可读。

## 用法

```rust
use pingap_config::{new_config_manager, Validate};

let manager = new_config_manager("/opt/pingap/conf")?;
let config = manager.load_all().await?.to_pingap_config(true)?;
config.validate()?;
```

## 许可证

Apache-2.0。
