# referer_restriction

按 `Referer` 头中的主机做允许/拒绝列表。经典用途是图片与下载的防盗链。

- **步骤：** `request`（固定）
- **注册名：** `referer_restriction`

## 配置

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `category` | string | — | 必须为 `referer_restriction`。 |
| `referer_list` | string[] | `[]` | 要匹配的主机。以 `*` 开头的条目按后缀匹配。 |
| `type` | string | `allow` | `deny` 拦截列表中的主机；其他值仅允许列表中的主机。 |
| `message` | string | `Request is forbidden` | 403 响应正文。 |

条目与解析后的 `Referer` URL 的**主机**匹配，而非完整 URL。`*.example.com` 存为后缀 `.example.com`，匹配 `a.example.com` 但不匹配 `example.com` 本身——两者都需要时请都列出。

## 示例

防盗链：

```toml
[plugins.hotlink]
category = "referer_restriction"
type = "allow"
referer_list = ["example.com", "*.example.com"]
message = "Hotlinking is not allowed"

[locations.images]
path = "/images"
plugins = ["hotlink"]
```

拦截若干已知爬虫：

```toml
[plugins.blockReferers]
category = "referer_restriction"
type = "deny"
referer_list = ["spam.example", "*.scraper.example"]
```

## 行为

| `Referer` | `type = "allow"` | `type = "deny"` |
| --- | --- | --- |
| 主机在列表中 | 允许 | **403** |
| 主机不在列表中 | **403** | 允许 |
| 头缺失 | **403** | 允许 |
| 头无法解析为 URL | **403** | 允许 |

## 使用说明

- 允许模式下，**没有** `Referer` 的请求会被拦截。这会影响直接打开、书签与严格 `Referrer-Policy` 的客户端。防盗链通常应放行空 Referer——可用 deny 模式，或仅把插件挂到仅嵌入路径。
- `Referer` 由客户端控制，极易伪造；当作便利措施，而非安全控制。真正需要把守时请用 [`key_auth`](key_auth.md) 或签名 URL。
