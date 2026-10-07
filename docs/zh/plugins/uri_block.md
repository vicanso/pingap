# uri_block

按请求的内容拦截请求：路径或查询串匹配规则列表中的某一条，或者请求方法不在允许的范围内。

它针对的是站点里没有任何部分会应答、而每个扫描器都会发的请求——`/.env`、`/.git/config`、`/wp-login.php`、查询串里带 `../`——否则这些请求会一路打到上游，或者得给每个路径单独配一个 location 加 [`mock`](mock.md) 插件。

- **步骤：** `request`（固定）
- **注册名：** `uri_block`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `uri_block`。 |
| `paths` | string[] | — | 正则表达式。路径匹配其中任意一条的请求被拦截。 |
| `queries` | string[] | — | 正则表达式。查询串匹配其中任意一条的请求被拦截。 |
| `methods` | string[] | — | 放行的请求方法，大小写不限（`GET`、`post`）。为空表示不限制方法。 |
| `status` | int | `403` | 拦截时的状态码，`400` 到 `599`。 |
| `message` | string | `Request is blocked` | 拦截时响应的正文。 |

`paths`、`queries`、`methods` 至少要配一项。编译不过的正则、不合法的方法名、范围之外的 `status` 都是配置错误，`pingap -t` 会报出来。

## 匹配的是什么

- **路径**匹配两次：一次按发送时的原样，一次按选择 location 时的方式——做一次百分号解码，消去 `.` 和 `..`，`//` 视为一个斜杠，`\` 视为 `/`，去掉每一段的 `;参数`。所以 `\.env$` 对 `/%2eenv`、`/public/../.env`、`//.env` 和对 `/.env` 一样生效，`^/admin` 既能拦住 `/public/../admin`，也能拦住 `/admin/..;/x`：同一个请求，有的上游按前一种形式理解，有的按后一种，两种形式有一种匹配就拦截。匹配的是 location 的 `rewrite` 之后的路径：配了 `rewrite = "^/app/(.*)$ /$1"` 时，`^/\.git/` 会拦住 `/app/.git/config`。
- **查询串**按发送时的原样匹配一次，再按解码后的样子匹配一次（`%2e%2e%2f` 即 `../`，`+` 即空格），一条规则两种写法都能覆盖。
- 规则不加 `^`、`$` 锚定时，匹配文本中的任意位置；区分大小写，除非开头加 `(?i)`。语法是 [`regex`](https://docs.rs/regex) crate 的。
- 同一个列表里的规则一次扫描全部比对，规则多了开销也增加不多。

## 示例

```toml
[plugins.blockScanners]
category = "uri_block"
paths = [
    '\.env$',
    '^/\.git/',
    '(?i)^/wp-(login|admin)',
    '\.(bak|sql|swp)$',
]
queries = ['\.\./', '(?i)union\s+select']
methods = ["GET", "HEAD", "POST"]
status = 404
message = "Not Found"

[locations.app]
upstream = "app"
plugins = ["blockScanners"]
```

用单引号可以避免 TOML 解释规则里的反斜杠。

## 响应

| Situation | Result |
| --- | --- |
| 方法不在 `methods` 中 | `status` 与 `message` |
| 路径匹配 `paths` 中的一条 | `status` 与 `message` |
| 查询串匹配 `queries` 中的一条 | `status` 与 `message` |
| 其他 | `Continue` |

拦截响应是 `text/plain`，并标记为 `no-store`。请求具体命中了哪一类规则会以 `debug` 级别记入日志。

## 使用说明

- 把它排在 location 插件列表的最前面：被拦截的请求不会再产生后面的任何开销，不查缓存，也不发认证子请求。
- 比起 `403`，返回 `404` 加一句普通的 `Not Found` 给扫描器的信息更少——`403` 等于告诉对方这里确实有东西。
- 它只是挡掉明显有问题的请求，不是 Web 应用防火墙：只看路径、查询串和方法，不看请求头和请求体。
- `methods` 是允许列表。只想在某些路径上拒绝某个方法时，给这些路径单独配一个 location。
