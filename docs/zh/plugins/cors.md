# cors

跨域资源共享。直接应答预检 `OPTIONS`，并在真实响应上附加 CORS 头。

- **步骤：** 预检在 `request`，实际响应在 `response`
- **注册名：** `cors`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `cors`。 |
| `path` | string | — | 正则；仅匹配路径应用 CORS。未设置表示所有路径。 |
| `allow_origin` | string | `*` | `Access-Control-Allow-Origin` 的值。支持 `$http_origin` 镜像请求。 |
| `allow_methods` | string | `GET, POST, PUT, PATCH, DELETE, OPTIONS` | `Access-Control-Allow-Methods` 的值。 |
| `allow_headers` | string | — | `Access-Control-Allow-Headers` 的值。 |
| `allow_credentials` | bool | `false` | 发出 `Access-Control-Allow-Credentials: true`。 |
| `expose_headers` | string | — | `Access-Control-Expose-Headers` 的值。 |
| `max_age` | duration | `1h` | `Access-Control-Max-Age` 的值。`0` 省略该头。 |

## 示例

公开只读 API：

```toml
[plugins.cors]
category = "cors"
path = "^/api/"
allow_origin = "*"
allow_methods = "GET, OPTIONS"
allow_headers = "Content-Type"
max_age = "24h"
```

需凭证的跨源 SPA API：

```toml
[plugins.cors]
category = "cors"
path = "^/api/"
allow_origin = "$http_origin"
allow_methods = "GET, POST, PUT, DELETE, OPTIONS"
allow_headers = "Content-Type, Authorization, X-Requested-With"
expose_headers = "X-Request-Id, X-Total-Count"
allow_credentials = true
max_age = "1h"
```

检查：

```bash
curl -i -X OPTIONS http://127.0.0.1:6188/api/users \
  -H 'Origin: https://app.example.com' \
  -H 'Access-Control-Request-Method: POST'
# HTTP/1.1 204 No Content
# access-control-allow-origin: https://app.example.com
# access-control-allow-methods: GET, POST, PUT, DELETE, OPTIONS
# access-control-allow-credentials: true
# access-control-max-age: 3600
```

## 行为

| Request | Result |
| --- | --- |
| 匹配路径上的 `OPTIONS` | `204 No Content` 带全部 CORS 头；不调用上游 |
| 任意方法，请求有 `Origin` | 向响应追加 CORS 头 |
| 任意方法，无 `Origin` | 响应不变 |
| 路径不匹配 `path` | 两阶段均跳过插件 |

## 使用说明

- `allow_origin = "*"` 与 `allow_credentials = true` 会被浏览器拒绝。需要凭证时用 `$http_origin`——但 location 本身应有访问控制，因为它会把任意 Origin 原样反射回去。
- 匹配路径上的**任意** `OPTIONS` 都会被预检应答，无论是否带 `Origin` 与 `Access-Control-Request-Method`。若上游需要看到 `OPTIONS`（如 WebDAV），请收窄 `path`。
- `allow_origin` 仅支持单个值；实现 origin 允许列表请用 `$http_origin` 加上游/边缘检查。
- 预检完全绕过上游，成本很低。
