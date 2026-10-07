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

每个 section 实现 `Validate`。`pingap -t` 加载配置、运行全部校验器后退出——可在 CI 与重载前使用。除了校验器之外，它还会按启动时的方式构建每一个 upstream、location 和插件，所以未知的 `alpn`、加载不了的 `ca`、编译不过的路径或域名正则、格式不对的 `rewrite` 规则、无效的插件配置（包括类型写错的值），都在这一步报告，而不是等到下次启动。证书会和私钥一起加载，所以配了另一张证书的私钥也会在这里报告。校验器还会检查条目之间的引用：location 的 upstream 和插件、server 的 location，以及 `traffic_splitting` 插件的 upstream。`access_log` 既不是带占位符的格式、也不是预设名、也不是文件路径后跟这两者之一时，会被拒绝。它只读取配置，磁盘上的配置保持原样。

pingap 不认识的键和分段在读取时会被忽略。这不算错误，但会被报告：`--test`、启动、以及每次重载有变化的配置时，每一处都会打印一条告警，并给出最可能的正确写法：

```
config: unknown section [server], did you mean [servers]?
config: basic: unknown key "trusted_proxy", did you mean "trusted_proxies"?
config: location(api): unknown key "client_max_body_sizes", did you mean "client_max_body_size"?
```

条目的键是在展开 `includes` 之后检查的，所以 storage 片段里写错的键会报在引用它的条目上。插件的配置不做这项检查：插件接受哪些键由插件自己决定。

加上 `--strict`（或把 `PINGAP_STRICT` 设成任意非空值）后，上面每一处都变成错误：`pingap -t --strict` 以非零状态退出并列出全部问题，启动会失败，重载时运行中的配置保持不变并像其他重载失败一样上报，admin API 会拒绝引入未知键的修改。重启时这个开关会传给接替的进程。建议 CI 里的 `-t` 总是带上它：写错的键应该让流水线停下来，而不是被忽略过去。

## 存储后端

由 `-c` / `PINGAP_CONF` 的值选择后端：

| Value | Backend | Layout | Hot reload |
| --- | --- | --- | --- |
| `/opt/pingap/pingap.toml` | 单文件 | `Single` | 轮询 |
| `/opt/pingap/conf`（目录） | 按类别分文件 | `MultiByType` | 轮询 |
| `/opt/pingap/conf?separation=true` | 每项一文件 | `MultiByItem` | 轮询 |
| `etcd://127.0.0.1:2379/pingap` | etcd | `MultiByItem` | 经 watch 流推送 |
| *(进程内)* | `MemoryStorage` | `Single` | 无 |

尚不存在的路径按扩展名判定：`.toml`、`.hcl`、`.kdl` 视为单个配置文件，其余视为待创建的目录。Pingap 必须在路径存在之前就作出选择——把目录误判为文件会静默忽略 `separation`，并在该目录内写出 `pingap.toml`，导致之后每一次运行读到的都是它自己绝不会写出的布局。

```bash
pingap -c /opt/pingap/conf --autoreload
pingap -c "etcd://127.0.0.1:2379/pingap?timeout=10s&connect_timeout=5s" --autoreload
pingap -c "/opt/pingap/conf?separation=true&enable_history=true"
```

etcd URL 形如 `etcd://host:2379[,host2:2379]/prefix[?params]`；省略 prefix 时默认为 `/`，没有 host 的 URL 会被拒绝。参数有 `timeout`（默认 `10s`）、`connect_timeout`（默认 `5s`）、`user`、`password`、`enable_history`。存储只打开一个客户端并在所有请求间复用；请求失败时会用新连接重试一次。

- URL 里不写超时也有请求和建连的时限，watch 用的连接每 30 秒发一次 HTTP/2 ping 探活。以前两者都没有，连接被静默丢弃后，等在上面的轮询会一直挂着，排在它后面的保存也跟着挂住。
- 前缀下的键分页读取（每页 64 个键，值很大时自动减半，减到多少会记住供下次读取使用），各页按同一个 revision 读取，所以配置大小不再受单条 gRPC 消息（4 MiB）的限制。
- `enable_history=true` 时，每个键在 `<prefix>-history` 下保留最新的 100 个版本，写入新版本时清理更早的。删除键不会留下版本。
- 不支持通过 TLS 连接 etcd。

目录按其中所有 `*.toml` 文件加载（没有时依次找 `*.hcl`、`*.kdl`）。每个文件单独解析，再把各自的表合并成一份文档，因此语法错误会指出所在文件，文件里也可以使用任意 TOML 写法（顶层的 `upstreams.extra.addrs = [..]` 与 `[upstreams.extra]` 等价）。同一分类可以分散在多个文件里，但一个条目（以及 `[basic]`）只能定义在其中一个文件：同名条目出现在两个文件里会报错，并指出这两个文件。

每个文件只读一次。Kubernetes 用 ConfigMap 或 Secret 挂载的目录里，每个文件有三条路径可达（顶层的链接、`..data`、以及它背后带时间戳的目录）；名字以 `..` 开头的目录下的内容会被跳过，指向同一个文件的多条路径只算一次。

写文件时先把新内容写到旁边的临时文件，再改名覆盖，所以读取方（包括变更检查）看到的要么是旧内容、要么是新内容，不会读到半个文件。文件的权限和属主保持不变，符号链接会跟随到它指向的文件。无法改名覆盖（例如挂载进容器的单个配置文件）或无法保留属主时，退回为直接写入。

新建文件的权限不会比所在目录更宽（去掉执行位）：在只有属主能进入的配置目录（`0700`）里，新建的条目文件是 `0600`，为它新建的分类目录是 `0700`。这是上限，在创建文件时指定，所以进程的 umask 仍然会进一步收紧它。在进程有权限的情况下（以 root 启动、目录属于实际运行的用户），新文件的属主会设成目录的属主。历史目录按配置目录的权限创建，其中的副本不会比被复制的文件更宽。保存时用到的临时文件从创建那一刻起就是私有的。

导入配置（`POST /api/configs/import`、`--sync`）是整体替换：导入的配置里没有的条目会被删除，各种布局都一样。

尺寸按原值写回：`10MB` 保存为 `10 MB`，使用能整除它的最大单位。

文件后端（仅目录）查询参数：

| Parameter | Meaning |
| --- | --- |
| `separation=true` | 每项写入独立文件。除字面 `false` 外均视为 true。 |
| `enable_history=true` | 在配置旁保留历史版本（`<dir>-history`），供管理 UI 恢复。需要 `separation`。 |

### 布局归一化

每种布局写出的文件名不同，而配置目录是把其中**所有** toml 文件拼接起来加载的。因此**读取**接受任何布局——包括手写的、把所有 section 放在一个文件里的合并布局——但所有**写入**（`get`/`update`/`delete`、管理面板、ACME 证书保存）只按规范文件名寻址。非规范文件对写路径不可见：按名查找会落空（ACME 签发的证书会被静默丢失、每个周期重新签发直到撞上 CA 的限流——issue #213），而按类别写入会在它旁边写出同名表的第二份副本，之后整个目录解析报 `duplicate key`，行号在任何单个文件里都对不上。

`ConfigManager::migrate_layout` 负责处理这种情况。它在启动时、首次读取之前运行一次，把配置重写为规范布局，然后清理当前布局自己绝不会写出的文件——既包括其它布局的遗留（目录尚不存在时那次运行写下的 `pingap.toml`、separation 目录里的 `certificates.toml`），也包括合并的或任意命名的文件：

- 开启 `enable_history=true` 时，被清理的文件先复制进历史目录再删除；
- 否则重命名为 `<name>.toml.bak` —— 加载时只 glob `*.toml`，所以改名即可让它不再被读取。

只读取配置的命令（`--test`、`--to-hcl`、`--to-kdl`、`--sync`）不做迁移，按现有的布局加载。配置加载失败时这些命令直接报错退出，设置了 admin 地址（`--admin` 或 `PINGAP_ADMIN_ADDR`）也一样：“用空配置启动以便通过 admin 修复”只适用于要运行的服务，不适用于检查和复制。

两种方式都会在启动时打印被清理的路径。已经同时存在两种布局的目录无法自动迁移（哪一份表应该胜出是无从判断的），此时启动会报出冲突的文件名并保持原样，交由人工合并。

迁移特意放在任何写入之前：管理面板通过 `ConfigManager::update` 每次只改一项，手上没有其它项的数据，因而无法安全清理那个包含了所有其它项的文件——正是这次写入把"只有一种旧布局"的目录变成损坏状态。

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

同一配置可写为 TOML（规范）、HCL 或 KDL。加载目录时优先 `.toml`；没有则试 `.hcl`，再试 `.kdl`。HCL 与 KDL 在内存中转为 TOML，下游一律看到 TOML。

通过 pingap 做出的修改（admin、ACME 续期的证书）写成什么格式，取决于配置存放在哪里：

| 存放方式 | 修改写成 |
| --- | --- |
| TOML，单文件或目录 | TOML |
| 单个 `.hcl` 或 `.kdl` 文件 | 仍是该格式。整个文件按 pingap 自己的布局重写，手写的注释和嵌套结构不会保留。写入之前会先把要写的内容读回来比较，读回来和原配置不一致时拒绝保存，文件不变。 |
| 由 `.hcl` 或 `.kdl` 文件组成的目录 | 不写入：这样的目录是只读的，修改会被拒绝并报错。其中的文件由编写者自行组织，一个条目该写进哪个文件无从确定。请直接编辑这些文件，或者改用 TOML 存放配置，再通过 pingap 管理。ACME 在这样的目录上同样无法工作：账号、token 和证书都没有地方保存。 |

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

块写在它第一次被用到的地方：location 写在第一个列出它的 server 里，upstream 写在第一个引用它的 location 里。被多个 server 共用的 location（80 和 443 用同一组路由）因此只写一次，其余 server 按名字引用：

```hcl
server "http" {
  addr = "0.0.0.0:80"

  location "site" {
    upstream = "web"
  }
}

server "https" {
  addr      = "0.0.0.0:443"
  locations = ["site"]
}
```

KDL 里只有一个值的节点就是这个值，有多个值的节点是列表。固定为列表的字段（`addrs`、`locations`、`plugins`、`includes`、`modules`、`proxy_set_headers`、`proxy_add_headers`、`match_headers`、`match_query`、`match_cookies`、`trusted_proxies`、`webhook_notifications`）只有一个值时也是列表。其他字段（例如插件的字段）要表示只有一个元素的列表时，用 `item` 子节点，`--to-kdl` 输出的也是这种写法：

```text
plugin "blockList" {
    category "ip_restriction"
    type "deny"
    ip_list {
        item "1.2.3.4"
    }
}
```

插件里取字符串列表的配置项也接受单个字符串，所以 `ip_list "1.2.3.4"` 同样可用。

`$ENV:NAME` 不是通用的插值：只有证书的 `dns_service_url` 会读取它，和配置用哪种格式书写无关（见 [pingap-acme](acme.md)）。其他位置按字面处理，所以把地址写成 `"$ENV:PINGAP_API_ADDR"` 得到的是一个解析不了的地址。请求头的值可以用 `$NAME` 引用环境变量（见 `proxy_set_headers`）。

命令行转换与迁移：

```bash
pingap -c /opt/pingap/conf --to-hcl > conf.hcl        # dump as HCL
pingap -c /opt/pingap/conf --to-kdl > conf.kdl        # dump as KDL
pingap -c /opt/pingap/conf --sync etcd://127.0.0.1:2379/pingap   # file -> etcd
pingap --template > pingap.toml                       # starter config
pingap -c /opt/pingap/conf -t                         # validate and exit
```

## 热更新

`ConfigManager::support_observer()` 决定变更如何到达：

- **etcd** 返回 `true`，经 `etcd_client::WatchStream` 推送。监听使用独立的连接；连接中断或被服务端结束后会重新建立，etcd 持续不可达时重试间隔从 500ms 逐步增加到一分钟，恢复后立即再比较一次配置。不论监听是否正常，存储里的配置每隔 `basic.auto_restart_check_interval` 也会重新读取一次。监听的只是前缀之下的键：`/pingap` 不会再因为 `/pingap2` 或者自己的 `/pingap-history` 有写入而被唤醒。
- **文件** 返回 `false`，按 `basic.auto_restart_check_interval` 轮询。

两者接入同一重载句柄；区别仅在投递机制。每次轮询先读取原始文档（`ConfigManager::load_all_raw`）并计算 hash；只有文档相对上一轮有变化，或上一轮只允许热更新而这一轮允许重启时，才会解析、校验（校验会解析每个静态 upstream 的地址）并 diff。用来接替的新进程如果加载不了配置，或者插件创建失败，会直接退出，原进程继续服务，带不带 `--admin` 都一样。热更新对“需要构建的部分”要么全部生效要么都不生效：upstream、location 或插件有变化时，先像 `pingap -t` 那样把它们全部构建一遍（不在工作线程上，也不影响正在运行的对象），失败时（正则编译不过、插件选项类型不对、地址解析不了）运行中的配置保持不变。失败只报告一次（日志和 `reload_config_fail` 通知），同一份文档每分钟重试一次，以便挡路的因素自己消失时（比如当时解析不了的域名）能恢复。以前各分类是依次替换的，其中一个失败时其他的已经生效，例如 location 指向了一个并不存在的 upstream。如果某个分类在替换过程中仍然失败，它在运行中的配置（以及 admin 展示的配置）里保持原样，server 的路由也不会用构建失败的 location 重建，文档下一次变化时会重试。被删除的 upstream 会保留到指向它的 location 换掉之后。只涉及 `storages` 的修改不会触发重启：存储条目本身不产生任何效果，其他条目通过 include 引用它时，变化体现在引用它的条目上。以文件路径给出的证书按同样的周期检查：配置文档没有变化时，会对这类证书的文件计算 hash，文件被替换（例如 certbot 续期）的证书会重新加载。这和其他重载一样需要 `--autoreload` 或 `--autorestart`。配置里同时有 ACME 证书时同样有效：只会改动来自文件的证书。重载改了什么，会以两份配置的差异写入日志并发送到 webhook。差异里的凭据会替换成校验值（`secret = "crc32:8D9A1B2C"`），这样值变了仍然能看出来：包括 `secret`、`password`、`token`、`key`、`keys`、`authorizations` 这类键的值，任何 URL 里的用户名和密码，带密钥的 URL（`webhook`、`sentry`、`*_url`）的查询串或路径，`Authorization` 这类请求头的值，以及 storage 里保存的内容。插件在 debug 级别打印的配置同样处理。`--autoreload` 就地交换配置，适合容器。location 的修改同时对路由生效：只要 location 有变化，server 用来匹配的域名和路径索引就会重建。`--autorestart` 做零停机优雅重启，监听级变更需要它。这次重启以“就绪”为交接依据：新进程一旦准备好接管监听 socket，就通过 `<upgrade_sock>.ready` 回报，旧进程此时才向自己发退出信号；`basic.restart_ready_timeout`（默认 1m）限定等待时长，超时则放弃本次重启。`basic.working_directory` 指定守护进程 `chdir` 的目录。

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

`to_pingap_config(replace_include)` 控制是否展开 includes；管理 UI 读未展开形式以便编辑可读。`--to-hcl`、`--to-kdl`、`--sync` 输出的也是未展开的形式：条目保留自己的 `includes`，片段里的键仍然只在片段这一处定义。片段的键覆盖条目自身的键，靠后的 include 覆盖靠前的。引用了不存在的 `storages` 条目、或条目内容不是合法 TOML 的 include，会在加载配置时报错（`upstream(api): include(commonTimeouts) is not found`），而不再被静默忽略。

## 用法

```rust
use pingap_config::{new_config_manager, Validate};

let manager = new_config_manager("/opt/pingap/conf")?;
let config = manager.load_all().await?.to_pingap_config(true)?;
config.validate()?;
```

## 许可证

Apache-2.0。
