# uri_block

按请求的内容拦截请求：路径或查询串匹配规则列表中的某一条，或者请求方法不在允许的范围内。

它针对的是站点里没有任何部分会应答、而每个扫描器都会发的请求——`/.env`、`/.git/config`、`/wp-login.php`、查询串里带 `../`——否则这些请求会一路打到上游，或者得给每个路径单独配一个 location 加 [`mock`](mock.md) 插件。

- **步骤：** `request`（固定）
- **注册名：** `uri_block`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `uri_block`。 |
| `presets` | string[] | — | 内置安全规则预设包（`sensitive_files`、`scanners`、`path_traversal`、`sqli_xss`、`common`、`all`），会与自定义的 `paths`/`queries` 合并为单次扫描正则。见[内置预设包](#内置预设包)。 |
| `paths` | string[] | — | 正则表达式。路径匹配其中任意一条的请求被拦截。 |
| `queries` | string[] | — | 正则表达式。查询串匹配其中任意一条的请求被拦截。 |
| `methods` | string[] | — | 放行的请求方法，大小写不限（`GET`、`post`）。为空表示不限制方法。 |
| `status` | int | `403` | 拦截时的状态码，`400` 到 `599`。 |
| `message` | string | `Request is blocked` | 拦截时响应的正文。 |
| `dry_run` | bool | `false` | 本应拒绝的请求照常放行，改为记录一条警告日志：新规则可以先在真实流量上观察，再真正拦截。见[只记录不拦截](limit.md#只记录不拦截)。 |

`presets`、`paths`、`queries`、`methods` 至少要配一项。编译不过的正则、未知的预设名、不合法的方法名、范围之外的 `status` 都是配置错误，`pingap -t` 会报出来。

## 内置预设包

无需在每个 location 手写一长串正则，可直接选用内置轻量安全预设包，并建议先开启 `dry_run = true` 观察一段时间后再切换为拦截：

| Preset | Scope | 说明 |
| --- | --- | --- |
| `sensitive_files` | `paths` | `.env` / `.env.*`、`.git` / `.svn` / `.hg`、`.htaccess` / `.htpasswd`、`.npmrc` / `.netrc` / `.DS_Store`、`.aws` / `.ssh`、SSH 私钥（`id_rsa`、`id_ed25519`）、`wp-config.php`、`web.config` 以及常见备份/转储后缀（`.bak`、`.orig`、`.save`、`.swp`、`.swo`、`.sql`、`.dump`）。明确放行 `/.well-known/*`（ACME HTTP-01 / OIDC）。 |
| `scanners` | `paths` | WordPress 探测（`wp-login.php`、`wp-admin`、`xmlrpc.php`、`wlwmanifest.xml`）、phpMyAdmin / Adminer / `phpinfo.php`、`cgi-bin`、`vendor/phpunit`、路由器常见漏洞路径（`boaform/admin`、`HNAP1`）。 |
| `path_traversal` | `paths` + `queries` | `../` / `..\\` / `..;/`、百分号编码 `%2e%2e` 与双重编码 `%252e%252e`、空字节 `%00` 以及 `/etc/passwd`、`/etc/shadow`、`/proc/self/environ`、`windows/win.ini`。 |
| `sqli_xss` | `queries` | 高置信度 SQLi/XSS 查询载荷：`UNION [ALL] SELECT`、`' or 1=1`、`sleep()` / `benchmark()` / `pg_sleep()` / `waitfor delay`、`information_schema` / `load_file(` / `into outfile`、`<script`、`javascript:`、`onerror=` / `onload=` / `onclick=`。 |
| `common` | 组合包 | `sensitive_files` + `scanners` + `path_traversal` 的简写（低误报基础包）。 |
| `all` | 组合包 | `common` + `sqli_xss` 的简写。 |

## 匹配的是什么

- **路径**匹配两次：一次按发送时的原样，一次按选择 location 时的方式——做一次百分号解码，消去 `.` 和 `..`，`//` 视为一个斜杠，`\` 视为 `/`，去掉每一段的 `;参数`。所以 `\.env$` 对 `/%2eenv`、`/public/../.env`、`//.env` 和对 `/.env` 一样生效，`^/admin` 既能拦住 `/public/../admin`，也能拦住 `/admin/..;/x`：同一个请求，有的上游按前一种形式理解，有的按后一种，两种形式有一种匹配就拦截。匹配的是 location 的 `rewrite` 之后的路径：配了 `rewrite = "^/app/(.*)$ /$1"` 时，`^/\.git/` 会拦住 `/app/.git/config`。
- **查询串**按发送时的原样匹配一次，再按解码后的样子匹配一次（`%2e%2e%2f` 即 `../`，`+` 即空格），一条规则两种写法都能覆盖。
- 规则不加 `^`、`$` 锚定时，匹配文本中的任意位置；区分大小写，除非开头加 `(?i)`。语法是 [`regex`](https://docs.rs/regex) crate 的。
- 同一个列表里的规则一次扫描全部比对，规则多了开销也增加不多。

## 示例

```toml
[plugins.blockScanners]
category = "uri_block"
presets = ["common"]
paths = ['^/internal/']
queries = ['\bexec\s*\(']
methods = ["GET", "HEAD", "POST"]
status = 404
message = "Not Found"
dry_run = true

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
