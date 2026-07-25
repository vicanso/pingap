# key_auth

API Key 认证。密钥从请求头**或**查询参数读取，并以常量时间与配置列表比较。

- **步骤：** `request`（固定）
- **注册名：** `key_auth`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `key_auth`。 |
| `header` | string | — | 携带密钥的头名，如 `X-API-Key`。 |
| `query` | string | — | 携带密钥的查询参数名，如 `api_key`。 |
| `keys` | string[] | — | **必填，非空。** 可接受的密钥，按字节比较。 |
| `delay` | duration | 无 | 失败应答前休眠时长。 |
| `hide_credentials` | bool | `false` | 转发前从请求中移除密钥。 |

`header` / `query` 至少设置其一。**若两者都设置，以 `query` 为准**，`header` 被忽略——插件只从一个位置读取，不会两者都读。

## 示例

基于请求头：

```toml
[plugins.apiKey]
category = "key_auth"
header = "X-API-Key"
keys = ["KOXQaw", "GKvXY2"]
hide_credentials = true
delay = "500ms"
```

```bash
curl -H 'X-API-Key: KOXQaw' http://127.0.0.1:6188/api/users
```

基于查询参数（适合无法设置头的 `<img>` / `<script>` URL）：

```toml
[plugins.apiKey]
category = "key_auth"
query = "api_key"
keys = ["KOXQaw"]
hide_credentials = true
```

```bash
curl 'http://127.0.0.1:6188/api/users?api_key=KOXQaw'
```

`hide_credentials = true` 时，上游收到的是去掉 `api_key` 参数后的 `/api/users`，密钥不会进入上游访问日志。

## 响应

| Situation | Status | Body |
| --- | --- | --- |
| 密钥缺失或为空 | 401 | `Key missing` |
| 密钥存在但未知 | 401（在 `delay` 之后） | `Key auth fail` |

## 使用说明

- 查询串中的密钥会出现在浏览器历史、`Referer` 以及中间代理日志中。能控制客户端时优先用 `header`。
- **不**遵循 `step`——无论配置如何，始终在 `request` 运行。
- 若需按密钥配额，在本插件之后挂 [`limit`](limit.md)，`tag = "header"`（或 `"query"`）并使用相同的密钥名。
