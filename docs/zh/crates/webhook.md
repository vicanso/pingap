# Pingap Webhook

[Pingap](https://github.com/vicanso/pingap) 的出站通知。

当发生有运维意义的事件时——证书即将过期、上游变不健康、配置重载成功或失败——Pingap 发出通知。本 crate 把这些通知投递到聊天室、通过 [ntfy](https://ntfy.sh/) 推送到手机，或者发到 HTTP 端点，无需一直盯着日志。

它实现 `pingap_core::Notification`，因此工作区其余部分只依赖该 trait。

## 配置

```toml
[basic]
webhook = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxxxx"
webhook_type = "wecom"
webhook_notifications = [
    "backend_status",
    "lets_encrypt",
    "reload_config_fail",
    "restart_fail",
    "service_discover_fail",
    "tls_validity",
]
```

| Key | Description |
| --- | --- |
| `webhook` | 目标 URL。空则禁用通知。 |
| `webhook_type` | `wecom`、`dingtalk`、`ntfy`，或其他值表示通用 JSON POST。 |
| `webhook_notifications` | 要投递的类别，`["*"]` 表示全部。**未列出的类别会被丢弃。** |
| `webhook_batch_window` | 间隔不超过该时长的通知合并为一条（默认 `10s`，`0s` 关闭合并）。 |
| `webhook_batch_max_events` | 一条消息最多合并的通知数（默认 `5`，`1` 关闭合并）。 |
| `webhook_min_level` | 低于这个级别的通知不发送：`info`（默认）、`warn` 或 `error`。 |
| `webhook_headers` | 请求头，每项 `Name: value`：接收方要求的 token 等。 |
| `webhook_secret` | 用来签名的密钥，见[签名](#签名)。 |
| `webhook_template` | 消息文本模板，替换内置的文本，见[模板](#模板)。 |
| `webhook_retries` | 发送失败后重试的次数（默认 `0`，最多 `10`）。 |

## 类别

| Category | Raised when |
| --- | --- |
| `backend_status` | 后端健康状态变化 |
| `upstream_status` | 上游整体健康变化 |
| `service_discover_fail` | DNS 或 Docker 发现失败 |
| `tls_validity` | 证书接近过期 |
| `parse_certificate_fail` | 配置的证书无法解析 |
| `lets_encrypt` | ACME 下单成功或失败 |
| `diff_config` | 检测到配置变更 |
| `reload_config` / `reload_config_fail` | 热更新结果。存储里的配置校验不通过时、以及存储根本读不到时（etcd 不可达、文件权限被改）也会发 `reload_config_fail`：在开始出问题时发一次，不是每一轮都发。`--autoreload` 下出现了要用 HTTP-01 验证的证书（新增的，或者改成这种验证方式的）、而进程没有 80 端口的 server 时，也会发一条 `warn` 级别的 `reload_config_fail`；`--autoreload` 下出现其他只有重启才能生效的变更（server 的 `addr`、`[basic]` 的大部分键）时同样如此：消息里列出哪些变更在等重启，同一组变更只发一次 |
| `restart` / `restart_fail` | 优雅重启结果 |
| `abnormal_exit` | 上一次运行没有正常退出——崩溃、panic 或被强制结束——之后被监管方重新拉起，见[异常退出](#异常退出) |

每条通知带类别、级别（`Info`、`Warn`、`Error`）、标题与消息。载荷还含主机名与本地 IP 列表，多实例部署时可区分报告节点。

## 异常退出

正在服务的进程会留下一个标记：一个记着 pid 和启动时间的小文件，停止时删掉它。优雅停止（SIGTERM，也就是 `docker stop`、`systemctl stop` 发出的信号）在开始的那一刻就删掉，所以宽限期还没结束就被监管方用 SIGKILL 结束的停止，仍然算正常停止；快速停止（SIGINT）在结束时删掉。启动时如果发现标记还在，说明上一次运行没有结束：进程崩溃、panic，或者被强制结束（内存不足），之后被 docker、systemd 等监管方重新拉起。这次启动会以 `Error` 级别报出来：写日志、发 `abnormal_exit` 通知，并在本次运行期间显示在管理后台首页。panic 会带上消息和发生的位置；被强制结束的进程来不及写下更多信息。

- 为了应用配置变更而做的重启，以及带 `-u` 的升级，都不算异常退出：新进程接手的是仍在运行的旧进程，并用自己的标记覆盖旧进程的。进程只删除自己的标记，所以新进程之后崩溃了（比如新配置让它挂掉），下一次启动会报出来。
- 同一台机器上的每个实例有自己的标记，按配置所在位置（`-c`）命名，放在 pid 文件所在目录（`basic.pid_file`；不设置时依次取 `/run`、`/var/run`、`/tmp` 中第一个可写的）；那里写不了时放在临时目录。另一个仍在运行的进程用了同一个标记时，会打印告警，不当作崩溃，并且不写自己的标记。
- 标记要在进程结束后保留下来。docker 的重启策略重启的是同一个容器，文件都在；重新创建的容器（修改后 `docker compose up`、Kubernetes 重启的容器）需要把 `basic.pid_file` 放在卷上（Kubernetes 用 `emptyDir`），否则不会报出来。机器重启会清空 `/run`，紧接在重启之前的崩溃也不会报出来。
- 控制面节点（`--cp`）不做这项检查。

## 通知来自哪一套部署

有多套部署时（每个地域一个集群、生产和预发并存），`pingap-7d9f5c6b8-x2k4q` 这样的主机名看不出是哪一套在报。`[basic]` 的两项设置用来说明这一点。每条通知的内置文本都会带上它们以及 pingap 的版本号；用了 `webhook_template` 时，模板里写了哪些就带哪些：

```toml
[basic]
name = "edge-sh-prod"                           # 不设置时是 `pingap`
labels = ["cluster:sh-prod", "env:prod", "region:cn-east"]
```

- `name` 是通知的发送方：聊天消息的第一行、JSON 里的 `name`，ntfy 里放在标题前面（`edge-sh-prod: Upstream unhealthy`）。只能是一行，最长 64 字节。
- `labels` 是自由的：任何能区分各套部署的标记，每项 `键:值`。最多 16 个，键由字母、数字、`_` 和 `-` 组成（最长 32），值是一行文本（最长 128 字节）。它们是聊天消息里的一行（`labels: cluster=sh-prod, env=prod`）、JSON 里的 `labels` 对象，在 ntfy 里是 tag（`cluster=sh-prod`，值里的逗号写成空格）。ntfy 的 tag 总共只收 512 字节：放不下的标签会写在消息正文里。
- 多套部署共用一份配置时（多个集群的节点连同一个 etcd），不同的部分从环境变量取：`name = "$ENV:PINGAP_NAME"`、`labels = ["cluster:$ENV:CLUSTER", "env:prod"]`。要先在每个节点上设好变量，再往配置里加这个标签：变量没设置属于配置错误，缺少变量的节点会整个不接受这次配置变更。
- 两者都在 pingap 启动时读取：修改后需要重启生效，`--autoreload` 会把它报告为等待重启的变更。

同样的名称和标签可以输出到访问日志（[pingap-logger](logger.md)），也会作为链路追踪的属性（[pingap-otel](otel.md)）。

## 合并发送

短时间内的多条通知会合并成一条，上游抖动或一次改动多个条目的重载只会收到一条消息而不是五条：

- 相邻两条通知间隔不超过 `webhook_batch_window`（默认 **10 秒**）就进入同一批；每来一条都会重新计时，所以一批在安静这么久之后发出；
- 一批最多 `webhook_batch_max_events`（默认 **5**）条，凑满立即发出。

单独到达的通知在等待 10 秒后按原来的格式发出，内容不变。合并后的消息取批内最高级别，类别列出批内所有类别（如 `backend_status,upstream_status`），标题相同时沿用，不同时写为 `N notifications`，正文每条通知一行并编号：

```
1. [error] backend_status: upstream api(10.0.0.1:8080) becomes unhealthy
2. [error] backend_status: upstream api(10.0.0.2:8080) becomes unhealthy
3. [info] reload_config: Upstream(api) is modified
```

允许列表在合并之前逐条生效，被丢弃的类别不占名额。合并后的发送在后台任务里完成，`notify` 返回时不代表已投递。停止 pingap 时尚在收集的一批会在退出前发出：优雅退出（SIGTERM、SIGQUIT）在开始退出时立即发送，快速退出（SIGINT）在进程结束前发送，后者最多等待 5 秒。这两个键和其他 `webhook*` 键一样支持热更新；`webhook_batch_window = "0s"`（或 `webhook_batch_max_events = 1`）表示每条立即发送。以库方式使用时用 `WebhookNotificationSender::with_batch(window, max_events)` 设置同样的策略。

## 格式

| `webhook_type` | Payload |
| --- | --- |
| `wecom` | 企业微信 markdown 消息，按级别着色 |
| `dingtalk` | 钉钉 markdown 消息 |
| `ntfy` | [ntfy](https://ntfy.sh/) 的消息，按级别设置优先级和图标，见 [ntfy](#ntfy) |
| 其他 | 通用 JSON POST：一个对象，包含 `name`（`basic.name`，不设置时是 `pingap`）、`title`、`level`（`info`、`warn`、`error`）、`category`、`message`、`hostname`、`ip`（本机地址，以 `;` 分隔）、`version`（pingap 的版本）和 `labels`（一个对象，`{"cluster": "sh-prod"}`，没有标签时为空）。以前其中没有 `title`，`name` 也不管配置了什么都是 `pingap`。 |

`Warn` 与 `Error` 用警告色；`Info` 以评论样式渲染。

## ntfy

[ntfy](https://ntfy.sh/) 把消息推送到订阅了某个 topic 的手机和浏览器，可以用 ntfy.sh，也可以用自己部署的服务。`webhook` 填 topic 的地址：

```toml
[basic]
webhook = "https://ntfy.sh/my-pingap-alerts"
webhook_type = "ntfy"
webhook_notifications = ["backend_status", "tls_validity", "reload_config_fail"]
```

在 ntfy.sh 上，知道 topic 名字的人都能读写它：取一个猜不到的名字，或者使用受保护的 topic。

| 通知里的 | 在 ntfy 里 |
| --- | --- |
| 级别 `info` / `warn` / `error` | 优先级 `3`（默认）/ `4`（高）/ `5`（最高），以及第一个标签，ntfy 把它显示成标题前面的图标：ℹ️ / ⚠️ / 🚨 |
| 标题 | 标题；通知本身没有标题时（大多数通知如此）用类别代替。设置了 `basic.name` 时放在它前面：`edge-sh-prod: Upstream unhealthy` |
| 类别 | 标签；合并了多条通知的消息每个类别一个标签，订阅时可以只看其中几种 |
| `basic.labels` | 每个一个 tag，`cluster=sh-prod` |
| 消息 | 正文，后面跟主机名、本机地址和 pingap 的版本 |

- **受保护的 topic**：把令牌放在 `webhook_headers` 里（`"Authorization: Bearer tk_..."`），或者把用户名和密码写在 url 里（`https://user:password@ntfy.example.com/alerts`，字母和数字以外的字符要做百分号编码：`p@ss` 写成 `p%40ss`）。
- **ntfy 支持的其他请求头**可以用同样的方式对所有消息设置：`"X-Markdown: yes"` 搭配用 markdown 写的 `webhook_template`，`"X-Click: https://..."`、`"X-Icon: ..."`、`"X-Email: ..."`。标题、优先级和标签始终是上表里的，不受请求头影响。
- 正文超过 4000 字节会被截断，截断处有一个 `…`；正文里大部分是引号和换行时会截得更短。ntfy 的上限是 4096 字节，更长的会被变成附件或者被拒绝；配置重载的差异（`diff_config`）很容易超过这个长度。
- 消息以 JSON 的形式发到服务地址（url 去掉 topic 的部分），ntfy 只在那里接受这种格式。url 里 `?` 后面的内容会一起带上，ntfy 会像读请求头一样读它：`?auth=...`、`?delay=30m`。
- 不是 topic 地址的 url 在检查配置时就会被拒绝：没有 topic（`https://ntfy.sh`）、结尾是 ntfy 不接受的 topic 名或它自己保留的名字（`app`、`docs`、`v1` 等）、订阅用的地址（`.../mytopic/json`）、带 `#` 的地址。
- ntfy 用它生成的那条消息作为回答时，才算投递成功。返回 `200` 但内容不是这样的，日志里记为失败：那是别的服务的页面，或者是 url 被重定向（比如跳到 `https`）之后得到的内容，这种情况下消息并没有送达。

## 过滤

通知的类别在 `webhook_notifications` 里，**并且**级别不低于 `webhook_min_level`，才会发送。列表里的 `"*"` 代表全部类别，包括以后版本新增的：把每个类别都写出来的列表，只在下一个新类别出现之前是完整的，新类别会被不声不响地丢掉。它是单独的一项，不是通配模式：`"reload_*"` 不对应任何类别。在 admin 里把类别全部选中，保存下来的就是 `"*"`。两个条件都是在合并之前对每条通知单独判断的，被过滤掉的通知不占合并的名额。

```toml
[basic]
webhook_notifications = ["backend_status", "tls_validity", "reload_config_fail"]
webhook_min_level = "warn"      # 后端恢复健康的通知是 `info`
```

```toml
[basic]
webhook_notifications = ["*"]   # 全部类别……
webhook_min_level = "warn"      # ……里级别是 warn 及以上的
```

## 模板

`webhook_template` 替换内置的文本。可用的占位符：`{{title}}`、`{{message}}`、`{{level}}`、`{{category}}`、`{{hostname}}`、`{{ip}}`、`{{name}}`（`basic.name`）、`{{version}}`、`{{labels}}`（全部标签，`cluster=sh-prod, env=prod`）、`{{label.<键>}}`（其中一个，这套部署没有这个标签时为空）和 `{{count}}`（这条消息合并了几条通知）。

- `wecom` 和 `dingtalk`：模板就是显示出来的 markdown：

  ```toml
  webhook_template = "**{{title}}** ({{level}})\n\n{{message}}\n\n{{hostname}}"
  ```

- `ntfy`：模板是消息的正文，按原样显示。标题、优先级和标签仍然是内置的。

- 其他类型：模板是请求的**整个正文**，填入的内容按 JSON 字符串的文本转义——每个占位符要放在引号里（`{{count}}` 这样的数字可以不加引号）。这样可以把请求做成接收方要求的格式，比如 Slack：

  ```toml
  webhook_template = '{"text":"[{{level}}] {{title}}: {{message}}","username":"{{name}}@{{hostname}}"}'
  ```

  正文按 `application/json` 发送，除非 `webhook_headers` 里指定了别的 `Content-Type`。

## 签名

- **`dingtalk`**：`webhook_secret` 是开启了“加签”的机器人的密钥。每次请求的 url 上会带 `timestamp` 和 `sign`，算法和钉钉文档一致：用密钥对 `<timestamp>\n<secret>` 做 HMAC-SHA256，再 base64。
- **自己的接收服务**（`wecom`、`dingtalk`、`ntfy` 之外的类型）：对正文签名，请求带 `X-Pingap-Signature: sha256=<hex>`，值是用密钥对正文做的 HMAC-SHA256。接收方对收到的字节做同样的计算并比较。
- **`wecom`** 和 **`ntfy`** 没有签名机制，这个密钥在那里不起作用。

## 投递

- 响应状态码小于 `400` 即算投递成功。`wecom` 和 `dingtalk` 还会读取响应内容：这两者不管怎么处理请求都返回 `200`，在正文里说明是否接受（`{"errcode":310000,"errmsg":"sign not match"}`）。`errcode` 不是 `0` 时按失败记日志，带上错误码和说明。以前这种情况被记成发送成功。`ntfy` 用状态码回答，并在正文里说明原因，日志里会一起记下：`status 403 Forbidden: forbidden`。
- 配了 `webhook_retries` 时，没有得到响应、或者响应是 `5xx` / `429` 的请求会重发这么多次：间隔 1 秒、2 秒、4 秒……最长 5 分钟。接收方明确拒绝的（其他 `4xx`、`errcode`）不重发。其中包括表示“消息太多”的 `errcode`：两种聊天机器人对这种情况同样返回 `200`，这里不区分错误码。重试在后台进行：发出通知的一方不等它，下一条消息也不等，所以正在重试的消息可能比后产生的消息晚到。每条失败的消息各有一个任务，直到投递成功或者放弃。

## 用法

```rust
use pingap_webhook::WebhookNotificationSender;

let sender = WebhookNotificationSender::new(
    "https://example.com/hook".to_string(),
    "wecom".to_string(),
    vec!["backend_status".to_string(), "tls_validity".to_string()],
);
```

## 说明

- `webhook_notifications` 是允许列表。留空会静默一切，即使设了 `webhook`——这是“为什么收不到告警”的常见原因。`["*"]` 表示全部放行。
- 所有 `webhook*` 键均支持热更新（`--autoreload` / `--autorestart`）：修改后无需重启即生效，已在运行的上游、服务发现与证书检查发出的通知也按新配置投递。此时尚在收集的一批仍按收集时的配置发出。
- 证书过期警告（`tls_validity`）针对需要人工更换的证书：`certificates.<name>.buffer_days` 是提前多少天开始告警（不设置时为 7 天）。设置了 `acme` 的证书由 ACME 任务续期，出问题时发的是 `lets_encrypt` 通知；只有到期前一周仍未续上时才会收到这项告警。见 [pingap-acme](acme.md)。
- 投递是尽力而为：失败会记日志，只按 `webhook_retries` 的次数重试，默认不重试。pingap 停止时还在重试中的通知会丢失。把 webhook 当作指标与日志之上的便利，而非唯一告警路径。
- `webhook_secret` 和 `webhook_headers` 在日志，以及写进日志、发给 webhook 的配置差异里显示为校验和，和 `webhook` 的 url 里的 key 一样。admin 里是原样显示。
- 只支持一个 webhook：不支持多个目标各自配置类型和过滤条件。

## 许可证

Apache-2.0。
