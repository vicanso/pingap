# admin

提供内嵌 Web 管理界面与配置 REST API。位于 `pingap` 二进制（`src/plugin/admin.rs`），因为需要配置管理器、证书/上游提供者与重启机制。

- **步骤：** `request`（固定）
- **注册名：** `admin`

多数人从不手写本插件——`--admin` 命令行标志会构建等价配置。显式声明用于把管理 UI 挂在已有 server 的路径前缀下。

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `admin`。 |
| `path` | string | `""` | 管理 UI 挂载的 URL 前缀。尾部 `/` 会去掉。 |
| `authorizations` | string[] | `[]` | `user:password` 的 Base64，用户名和密码都不能为空，其他内容会被拒绝。**为空则完全禁用认证。** |
| `max_age` | duration | `2d` | 签名令牌允许的时钟偏差。 |
| `ip_fail_limit` | int | `10` | 每 IP 失败次数上限，之后封锁 5 分钟。 |

## 通过命令行

```bash
pingap -c /opt/pingap/conf --admin=pingap:123123@127.0.0.1:3018

# or, mounted under a prefix on an existing listener
pingap -c /opt/pingap/conf --admin=pingap:123123@0.0.0.0:80/pingap
```

等价环境变量：`PINGAP_ADMIN_ADDR`、`PINGAP_ADMIN_USER`、`PINGAP_ADMIN_PASSWORD`。

凭证写成 `user:password`，或者在用户名的位置写 `user:password` 的 Base64。只有用户名、没有密码，且用户名又不是这样的 Base64 值时（`--admin=root@127.0.0.1:3018`）是错误，进程不会启动。在 URL 里有特殊含义的字符用百分号编码（`p@ss` 写成 `p%40ss`），密码取解码后的值。

## 作为插件

```toml
[plugins.admin]
category = "admin"
path = "/pingap"
authorizations = ["cGluZ2FwOjEyMzEyMw=="]   # pingap:123123
max_age = "1h"
ip_fail_limit = 5

[locations.admin]
path = "/pingap"
plugins = ["admin"]
weight = 2000

[servers.main]
addr = "0.0.0.0:80"
locations = ["admin", "app"]
```

## 认证

API 不使用 HTTP Basic。每个请求携带：

```
Authorization: <token>:<unix-seconds>
token = hex(sha256("<user>:<password>:<unix-seconds>"))
```

`<unix-seconds>` 须在代理时钟的 `max_age` 内，令牌按常量时间比较。Web UI 在登录后为你计算。

admin 前缀下的路径分两类。`/api` 及其下的路径是接口，一律需要令牌。其余路径都是内嵌界面的文件，无需认证即可访问（登录页要靠它们加载），没有对应文件时返回 `404`。接口只能通过 `/api` 访问：不带该前缀的 `/configs/...` 不会被当成接口处理。

登录失败达到 `ip_fail_limit` 次后，该 IP 会收到 `403 Forbidden, too many failures` 并封锁 5 分钟。只有带了 `Authorization` 但校验不通过的 API 请求才算一次登录失败；不带凭据的请求返回 `401`，不计数，所以页面在令牌过期后继续轮询不会把用户锁在外面。封锁只作用于 API：UI 的静态文件照常加载，admin 与业务共用一个 server 时，admin 前缀之外的路径不受影响。

## API

所有路由相对于 `<path>/api`。

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/configs/{category}` | 读取某类别配置 |
| `POST` | `/configs/{category}/{name}` | 创建或更新一条 |
| `POST` | `/configs/import` | 导入整份配置 |
| `DELETE` | `/configs/{category}/{name}` | 删除一条 |
| `GET` | `/config-history/{category}/{name}` | 历史版本（存储后端支持时） |
| `GET` | `/basic` | 进程信息、启用特性（含 TLS 后端名 `openssl` / `rustls`）、支持的插件、上游健康 |
| `GET` | `/certificates` | 已加载证书的解析信息 |
| `POST` | `/aes` | UI 用于密钥的 AES 加解密辅助 |
| `POST` | `/restart` | 触发优雅重启 |

`{category}` 为 `basic`、`server`、`location`、`upstream`、`plugin`、`certificate`、`storage` 之一。向其他分类 `POST` 返回 `400`（UI 保存 basic 配置时用的名字 `pingap` 等同于 `basic`）。

### 写入时的校验

如果写入之后存储里的配置通不过 `pingap -t`，`POST` 会以 `400` 拒绝。校验的不只是这一个条目：还包括条目之间的引用（location 的 upstream 和插件、server 的 location），以及只有构建条目才能发现的问题——编译不过的路径或域名正则、类型写错的插件选项、与证书不配对的私钥。`POST /configs/import` 按同样的方式校验，导入的内容本身必须是一份完整有效的配置；内容为空，或者顶层出现 pingap 不认识的分段（把 `[upstreams.x]` 写成 `[upstream.x]`）时会被拒绝，否则存储里的配置会被整体替换成空的。

校验时会像启动时那样构建 upstream、location、插件和证书，但不会影响正在运行的代理：`cache` 插件的校验不创建目录，也不改动正在使用的缓存后端。校验可能要解析域名、读取文件，所以不在处理请求的工作线程上执行。

“写入之后的配置”带来两点：

- 被引用的条目要先存在：先建 upstream，再建引用它的 location。
- 存储里的配置本来就无效时（手工改过，或由旧版本写入），只要条目本身能解析就接受修改，这样可以通过 admin 逐条修复。配置恢复有效之后，完整校验重新生效。

被其他条目引用的条目不能 `DELETE`：被 location 或 `traffic_splitting` 插件引用的 upstream、被 server 列出的 location、被 location 列出的插件、被 `includes` 引用的 storage。检查读的是存储里的配置，而不是进程当前运行的配置，所以在控制面板节点和没有开 `--autoreload` 的节点上同样有效。

```bash
TS=$(date +%s)
TOKEN=$(printf 'pingap:123123:%s' "$TS" | shasum -a 256 | cut -d' ' -f1)
curl -H "Authorization: $TOKEN:$TS" http://127.0.0.1:3018/api/basic
```

## 控制面板模式

`pingap --cp --admin=user:pass@127.0.0.1:3018` 只运行管理节点：在共享后端（通常是 etcd）管理配置，自身不代理流量。数据面实例监视同一后端并热更新。

控制面板节点写入时只校验条目之间的引用和 location 的匹配规则，不构建 upstream、插件和证书，也不按自身构建包含哪些插件类别来判断配置：构建需要读取文件（`ca`、以路径给出的证书），而这些文件在实际运行配置的机器上。如果存储里的配置引用了控制面板节点上根本没有的文件，这份配置在该节点上整体通不过校验，此时写入只做逐条校验。

## 使用说明

- **空的 `authorizations` 会禁用认证。** 切勿把此类实例暴露到 localhost 之外。
- API 可改证书、上游与 server，并可重启进程。绑定私有接口，或在 admin location 前加 [`ip_restriction`](ip_restriction.md)。
- 经 API 写入的配置进入 `-c` 指向的后端。`file://` 存储下，用 `--upstream` 启动的无配置文件快速启动没有可编辑的后端存储，UI 无法改配置。
- 令牌嵌入时间戳但不绑定请求；它是 bearer 凭证。请通过 TLS 提供管理 UI。
- `/configs/{category}/{name}` 与 `/config-history/{category}/{name}` 都需要 name 段；省略会返回错误而非结果。
