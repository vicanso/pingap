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
| `authorizations` | string[] | `[]` | `user:password` 的 Base64。**为空则完全禁用认证。** |
| `max_age` | duration | `2d` | 签名令牌允许的时钟偏差。 |
| `ip_fail_limit` | int | `10` | 每 IP 失败次数上限，之后封锁 5 分钟。 |

## 通过命令行

```bash
pingap -c /opt/pingap/conf --admin=pingap:123123@127.0.0.1:3018

# or, mounted under a prefix on an existing listener
pingap -c /opt/pingap/conf --admin=pingap:123123@0.0.0.0:80/pingap
```

等价环境变量：`PINGAP_ADMIN_ADDR`、`PINGAP_ADMIN_USER`、`PINGAP_ADMIN_PASSWORD`。

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

登录页静态资源（`/`、`*.js`、`*.css`、`*.png`）无需认证以便加载登录屏。`/api` 下一律需要认证，因此无法用看起来像静态后缀的路径绕过 API。

达到 `ip_fail_limit` 次失败后，该 IP 会收到 `403 Forbidden, too many failures` 并封锁 5 分钟。

## API

所有路由相对于 `<path>/api`。

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/configs/{category}` | 读取某类别配置 |
| `POST` | `/configs/{category}/{name}` | 创建或更新一条 |
| `POST` | `/configs/import` | 导入整份配置 |
| `DELETE` | `/configs/{category}/{name}` | 删除一条 |
| `GET` | `/config-history/{category}/{name}` | 历史版本（存储后端支持时） |
| `GET` | `/basic` | 进程信息、启用特性、支持的插件、上游健康 |
| `GET` | `/certificates` | 已加载证书的解析信息 |
| `POST` | `/aes` | UI 用于密钥的 AES 加解密辅助 |
| `POST` | `/restart` | 触发优雅重启 |

`{category}` 为 `basic`、`server`、`location`、`upstream`、`plugin`、`certificate`、`storage` 之一。

```bash
TS=$(date +%s)
TOKEN=$(printf 'pingap:123123:%s' "$TS" | shasum -a 256 | cut -d' ' -f1)
curl -H "Authorization: $TOKEN:$TS" http://127.0.0.1:3018/api/basic
```

## 控制面板模式

`pingap --cp --admin=user:pass@127.0.0.1:3018` 只运行管理节点：在共享后端（通常是 etcd）管理配置，自身不代理流量。数据面实例监视同一后端并热更新。

## 使用说明

- **空的 `authorizations` 会禁用认证。** 切勿把此类实例暴露到 localhost 之外。
- API 可改证书、上游与 server，并可重启进程。绑定私有接口，或在 admin location 前加 [`ip_restriction`](ip_restriction.md)。
- 经 API 写入的配置进入 `-c` 指向的后端。`file://` 存储下，用 `--upstream` 启动的无配置文件快速启动没有可编辑的后端存储，UI 无法改配置。
- 令牌嵌入时间戳但不绑定请求；它是 bearer 凭证。请通过 TLS 提供管理 UI。
- `/configs/{category}/{name}` 与 `/config-history/{category}/{name}` 都需要 name 段；省略会返回错误而非结果。
