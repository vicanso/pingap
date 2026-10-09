# error_page

按 location 定制代理自己应答的错误（没有可用的上游、请求被限流拒绝等）的页面，取代整个 server 共用的那一张（`basic.error_template`）。API 需要 JSON 格式的错误，站点需要自己的错误页，而它们由同一个进程提供。

- **步骤：** 没有自己的步骤：应答错误时被查询；开了 `intercept` 时检查上游每个响应的状态码
- **注册名：** `error_page`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `error_page`。 |
| `pages` | string[] | `[]` | `状态码:页面`。状态码是 `400` 到 `599` 中的一个，或者用 `4xx` / `5xx` 表示一整类；页面是文件路径，或者直接写内容。 |
| `json` | bool | `false` | 请求要的是 JSON 时，错误以 `{"status":502,"message":"Bad Gateway"}` 返回，不管有没有配置页面。 |
| `intercept` | bool | `false` | 这些页面同样替换**上游**以 `pages` 中的状态码返回的内容。需要配置 `pages`。 |

`pages` 和 `json` 至少要配一个。

## 示例

```toml
# 站点：自己的错误页
[plugins.sitePages]
category = "error_page"
pages = [
    "404:/etc/pingap/pages/404.html",
    "5xx:/etc/pingap/pages/down.html",
]

# API：要 JSON 的给 JSON，其余给一行文本
[plugins.apiErrors]
category = "error_page"
json = true
pages = ["5xx:service unavailable ({{status}})"]

[locations.site]
upstream = "site"
plugins = ["sitePages"]

[locations.api]
upstream = "api"
path = "/api"
plugins = ["apiErrors"]
```

## 页面

- **文件或内容。** 以 `/`、`~/`、`./`、`../` 开头的是文件路径，在构建插件时读取：文件不存在是配置错误（`pingap -t` 能发现）。文件不会被监视：改过的页面要等插件重新构建才生效，也就是插件自身的配置有变化或者进程重启的时候——插件没有变化的重载会继续使用已经读入的页面。其他写法就是页面内容本身。
- **类型**：文件按扩展名——`.json` 是 `application/json`，`.txt` 是 `text/plain`，其余是 `text/html`；写在配置里的内容按开头判断：`<` 是 HTML，`{` 或 `[` 是 JSON，其余是纯文本。以占位符开头的内容（`{{status}} {{message}}`）是纯文本。
- 页面里的 **`{{status}}` 和 `{{message}}`** 会被替换成状态码和代理对这个错误的说明：状态码的标准原因短语，或者（代理或插件给出的 `4xx`）写给客户端看的消息（哪条限制、哪条路由）。消息会按所在页面的类型转义（HTML 或 JSON 字符串）：它的一部分可能来自请求。转义覆盖的是文本该出现的位置：HTML 里元素的文本或带引号的属性值，JSON 里的字符串（`"error":"{{message}}"`）。不要把它放进 `<script>`、URL 或不带引号的属性里，也不要放在 JSON 的引号之外。
- **单个状态码的页面**优先于它所在那一类的页面，和书写顺序无关。没有对应页面的状态码使用 server 自己的页面，和没有这个插件时一样。

## 行为

- **`json`**：请求的 `Accept` 里有 `application/json`（或 `+json` 类型）且没有 `text/html` 时，视为要 JSON。浏览器会先要 `text/html`，拿到的是页面；`curl` 要的是 `*/*`，拿到的也是页面。
- 这些页面对该 location 上代理应答的所有错误生效，不管是 location 的哪个插件拦下了请求，也不管 `error_page` 排在列表的什么位置。状态码、location 的插件加在响应上的头（`cors`、开了 `always` 的 `response_headers`）以及 `X-Pingap-EType` 头，都和 server 自己的错误页一样。
- location 的错误包括在任何插件运行之前就拒绝请求的那些：`client_max_body_size` 的 `413` 和 `max_processing` 的 `429`。
- **不开 `intercept`** 时，上游的响应就是上游的，状态码和内容都不动。**开了之后**，上游响应的状态码在 `pages` 里有对应页面时，上游的响应头和正文都被丢弃，由代理自己应答这个状态码，和应答它自己的错误一样：用页面——开了 `json` 且请求要 JSON 时用 JSON——`{{message}}` 是状态码的原因短语。`HEAD` 请求得到页面的响应头。只配 `json` 不会拦截上游的任何响应：API 自己的 `422` 保留说明错误原因的正文，除非为它列了页面。
- 被拦截的响应还有这些影响：
  - 上游的响应头和正文一起丢弃：`Retry-After`、`Set-Cookie`、`401` 的 `WWW-Authenticate`。客户端需要这些头的状态码不要列进来。
  - 不会写入缓存，即使上游允许缓存：这类请求每次都会到达上游。
  - 上游响应的剩余部分不再读取，所以这条到上游的连接会被关闭、不复用；HTTP/1.1 下客户端的连接在页面发完后关闭（`Connection: close`），和代理过程中出错的请求一样。HTTP/2 客户端的连接保留。
  - `5xx` 且缓存里有过期响应并允许 `stale-if-error` 时，由缓存应答，和没有这个插件时一样。
  - 这个状态码照常计入后端（健康统计、熔断器），访问日志照常记录；错误日志里没有对应的行。
- 插件自己应答的响应（认证插件的 `401`、`mock`）属于那个插件，不会被替换。
- 没有匹配到 location 的请求出错时没有插件可问，使用 server 的页面。
