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
| `authorizations` | string[] | `[]` | `user:password` 的 Base64，用户名和密码都不能为空，其他内容会被拒绝。**它和 `readonly_authorizations`、两个 token 列表都为空时，完全没有认证。** |
| `readonly_authorizations` | string[] | `[]` | 格式相同，只能查看、不能修改的账号。 |
| `tokens` | string[] | `[]` | API token，每项是 `名称:<token 的 sha256 十六进制>`。 |
| `readonly_tokens` | string[] | `[]` | 格式相同，只能读取、不能修改的 token。 |
| `max_age` | duration | `2d` | 签名令牌的有效期，从令牌里带的时间算起。 |
| `ip_fail_limit` | int | `10` | 每 IP 失败次数上限，之后封锁 5 分钟。 |

## 通过命令行

```bash
pingap -c /opt/pingap/conf --admin=pingap:123123@127.0.0.1:3018

# or, mounted under a prefix on an existing listener
pingap -c /opt/pingap/conf --admin=pingap:123123@0.0.0.0:80/pingap
```

等价环境变量：`PINGAP_ADMIN_ADDR`、`PINGAP_ADMIN_USER`、`PINGAP_ADMIN_PASSWORD`。机器上的其他用户能看到进程列表时，建议用环境变量：进程的命令行是公开的，环境变量不是。优雅重启时同样如此——来自环境变量的设置（这三个，以及 `PINGAP_CONF`）由新进程继承，不会被写成命令行参数。

其他账号写在地址后面的参数里，每种有几个就写几次：

```bash
pingap -c /opt/pingap/conf \
  --admin="pingap:123123@127.0.0.1:3018?readonly=bob:s3cret&token=ci:5e88...d8&readonly_token=monitor:9c2b...7d"
```

| 参数 | 含义 |
| --- | --- |
| `readonly` | 只能看、不能改的账号：`user:password`，或者它的 Base64。 |
| `token` | 可写的 API token：`名称:<token 的 sha256>`。 |
| `readonly_token` | 只读的 API token。 |
| `max_age` | 一次登录的有效期（默认 `2d`）。 |

它们就是插件的 `readonly_authorizations`、`tokens`、`readonly_tokens`（见下文），校验规则也相同。`PINGAP_ADMIN_ADDR` 同样可以带这些参数。写在这里的密码中，`&`、`#`、`%` 要用百分号编码（`%26`、`%23`、`%25`）；其他字符（包括 `+`）按原样读取。

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

按代理的时钟，`<unix-seconds>` 不能早于 `max_age` 之前，也不能比现在超前 5 分钟以上（`max_age` 更小时以它为准）。这 5 分钟是留给两边时钟误差的。浏览器的时钟比代理快出这么多（或者代理的时钟慢了这么多）时，密码正确也登录不了：这时的 `401` 会在响应体里说明原因，登录页会显示出来，而且不计入登录失败次数，因为根本没有比对凭据。以前这个时间往前往后都允许 `max_age`，所以用两天后的时间做出来的令牌能用四天。令牌按常量时间比较，Web UI 在登录后为你计算。

admin 前缀下的路径分两类。`/api` 及其下的路径是接口，一律需要令牌。其余路径都是内嵌界面的文件，无需认证即可访问（登录页要靠它们加载），没有对应文件时返回 `404`。接口只能通过 `/api` 访问：不带该前缀的 `/configs/...` 不会被当成接口处理。

登录失败达到 `ip_fail_limit` 次后，该 IP 会收到 `403 Forbidden, too many failures` 并封锁 5 分钟。只有带了 `Authorization` 但校验不通过的 API 请求才算一次登录失败；不带凭据的请求返回 `401`，不计数，所以页面在令牌过期后继续轮询不会把用户锁在外面。因为所带的时间太旧或超前而被拒绝的请求同样不计。封锁只作用于 API：UI 的静态文件照常加载，admin 与业务共用一个 server 时，admin 前缀之外的路径不受影响。

## 角色、API token 与审计日志

```toml
[plugins.admin]
category = "admin"
authorizations = ["YWxpY2U6czNjcmV0"]            # alice:s3cret —— 可以修改
readonly_authorizations = ["Ym9iOnMzY3JldA=="]   # bob:s3cret   —— 只能查看
tokens = ["deploy:4f0a...e1"]                    # 名称:sha256(token)
readonly_tokens = ["monitor:9c2b...7d"]
```

- **只读**的账号和 token 可以访问接口的全部 `GET`，不能做任何修改：`/configs` 下的 `POST`、`DELETE`（包括导入）和 `POST /restart` 返回 `403 Forbidden, this account is read-only`。它们能读到 admin 展示的一切，包括配置里的各种凭据：这个角色的意思是“改不坏东西”，不是“看不到密钥”。界面上不再显示这类账号做不了的操作——保存、删除、新建、导入、恢复历史版本、重启——并提示当前账号是只读的。这只是为了看的人方便：这类账号能做什么由接口决定，和页面显示什么无关。
- 一个用户名只能出现在两个列表之一，token 的名称不能重复。只配了只读的账号或 token、没有任何可写的时，插件会被拒绝：那样谁也改不了任何东西。
- **API token** 给不经过登录页的调用方用——部署脚本、监控：

  ```bash
  token=$(openssl rand -hex 32)                 # 把它交给脚本
  printf %s "$token" | shasum -a 256            # 把它写进配置
  curl -H "Authorization: Bearer $token" http://127.0.0.1:3018/api/configs/upstream
  ```

  配置里存的是摘要而不是 token 本身，所以读到配置的人拿不到 token；它有多长就有多难猜，所以应该用工具生成而不是自己想一个。删掉对应的那一项就是吊销，随插件重载生效，不用动密码。不认识的 token 和错误的密码一样算一次登录失败，计入 `ip_fail_limit`。
- **每次修改都会留下一行**应用日志，被拒绝的也算：

  ```text
  INFO main::admin: admin audit user="alice" ip="10.0.0.7" method="POST" path="/configs/upstream/api" status=204
  INFO main::admin: admin audit user="token:monitor" ip="10.0.0.9" method="POST" path="/restart" status=403
  ```

  `user` 是账号名，token 是 `token:<名称>`，没有配凭据的 admin 是 `anonymous`；`ip` 是统计登录失败时用的那个地址。具体改了什么在重载时的输出里——日志行 `current config diff from hot reload config` 和 webhook 的 `diff_config` 通知——那里有差异内容，凭据已遮蔽。
- **页面和接口的响应**都带 `X-Frame-Options: DENY` 和 `Content-Security-Policy: frame-ancestors 'none'`（别的网站不能把它们嵌进 frame，再把在那边的点击变成这边的点击），以及 `X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`。由 server 自己的错误页回答的错误（`/api/aes`、`/api/config-history` 收到解析不了的请求）不带这些头。
- `--admin` 参数里写一个可写账号，另外三类写在地址后面的参数里（见上文）。
- **历史记录。** 配置开启 `enable_history=true`（见 [pingap-config](../crates/config.md)）之后，每个条目的页面上可以看到它之前的版本——最新的在前，带着各自被替换的时间——并可以一键把条目恢复成当时的样子。文件配置的每一种布局和 etcd 都支持。每个条目最多显示 20 个版本；和后一个版本相同的不重复显示。

还没有的：除上面这条之外针对页面本身的内容安全策略。

## 不设凭据时

`--admin=127.0.0.1:3018`（不带用户名和密码）是在自己机器上运行 admin 的常见方式。此时 API 对任何到达它的请求都会应答，而这台机器上的浏览器会替用户打开的每一个页面把请求送到它面前。以下两类请求会以 `403` 拒绝，启动日志里也会有一条 admin 没有凭据的警告：

- **来自其他站点的写入。** 其他站点的页面可以发出一个它读不到应答的 `POST`（表单，或 `no-cors` 模式的 `fetch`），而保存配置或触发重启只需要请求被执行。`GET`/`HEAD` 以外的请求，只要浏览器标明它来自其他源就拒绝：`Sec-Fetch-Site` 不是 `same-origin` 或 `none`；浏览器不发送这个头时（访问 localhost 以外的明文 http 地址），则要求 `Origin` 与请求的 `Host` 一致。两个头都没有的客户端（例如 `curl`）不是浏览器，正常处理。
- **不属于本机的域名。** 页面所在的域名被其所有者改指向 `127.0.0.1`（DNS 重绑定）之后，在浏览器看来它就是 admin 自己的页面，可以读出配置和其中的私钥。对于从 loopback 地址进来的连接，`Host` 必须是 IP 地址、`localhost` 或 `.localhost` 下的名字；其他名字访问整个 API 都会被拒绝。UI 的静态文件仍然可以访问。

设置了凭据之后这两条都不再适用：每个请求都需要的令牌，其他站点的页面加不上这个请求头，重绑定的页面也不知道密钥。loopback 上不设凭据的 admin 如果确实要通过域名访问（同一台机器上的反向代理原样转发 `Host`、`/etc/hosts` 里的条目），解决办法同样是设置用户名和密码。

监听在网络地址上且不设凭据的 admin 不在保护范围内：它通过网络里的任意名字被访问，名字无从校验，能连上的人都能使用。容器里的 admin 把端口发布到宿主机的 `127.0.0.1` 也属于这种情况：在容器内部，连接到达的是容器自己的地址而不是 loopback，域名校验不会生效。这种情况请设置凭据。

## API

所有路由相对于 `<path>/api`。

请求体最多读取 8 MiB，超过时返回 `413`。

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/configs/{category}` | 读取某类别配置 |
| `POST` | `/configs/{category}/{name}` | 创建或更新一条 |
| `POST` | `/configs/import` | 导入整份配置 |
| `DELETE` | `/configs/{category}/{name}` | 删除一条 |
| `GET` | `/config-history/{category}/{name}` | 历史版本（存储后端支持时） |
| `GET` | `/basic` | 进程信息、启用特性（含 TLS 后端名 `openssl` / `rustls`）、支持的插件、上游健康 |
| `GET` | `/certificates` | 已加载证书的域名、颁发者、有效期和 ACME 来源。不包含证书本身和私钥：以前这两项都在响应里，配置里只写了文件路径的私钥也会从文件里读出来返回。 |
| `POST` | `/aes` | UI 用于密钥的 AES 加解密辅助 |
| `POST` | `/restart` | 触发优雅重启 |

`/basic` 描述的是进程本身：其中的 `user`、`group`、`config_hash` 取自运行中的配置，而不是存储里的；UI 每隔几秒请求一次，所以它不读存储。控制面板节点不运行配置：那里的 `user`、`group` 每次请求时从存储读取，`config_hash` 是空配置的哈希。

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

- **空的 `authorizations` 会禁用认证。** 切勿把此类实例暴露到 localhost 之外；此时哪些请求会被拒绝、哪些不会，见[不设凭据时](#不设凭据时)。
- API 可改证书、上游与 server，并可重启进程。绑定私有接口，或在 admin location 前加 [`ip_restriction`](ip_restriction.md)。
- 经 API 写入的配置进入 `-c` 指向的后端。`file://` 存储下，用 `--upstream` 启动的无配置文件快速启动没有可编辑的后端存储，UI 无法改配置。
- 令牌嵌入时间戳但不绑定请求；它是 bearer 凭证。请通过 TLS 提供管理 UI。
- `/configs/{category}/{name}` 与 `/config-history/{category}/{name}` 都需要 name 段；省略会返回错误而非结果。
