# Pingap 插件

[Pingap](https://github.com/vicanso/pingap) 的内置插件。

插件是自包含的请求/响应逻辑单元，在代理生命周期的明确阶段执行。插件声明一次后可挂到任意多个 location，使路由配置不必夹杂认证、限流、缓存或头改写等横切逻辑。

## 如何配置插件

在 `[plugins.<name>]` 下声明插件。`<name>` 可任意取名，供 location 引用；`category` 决定实例化哪一种实现。

```toml
[plugins.pingPath]
category = "ping"
path = "/ping"

[locations.api]
upstream = "api"
path = "/api"
plugins = ["pingPath"]
```

同一插件可用不同配置声明多次；一个 location 可列出多个插件。插件按 `plugins` 列表中的顺序执行。

亦支持等价的 HCL / KDL 写法——见 [pingap-config](../crates/config.md)。

## 生命周期步骤

Pingap 将 `pingap-proxy/src/server.rs` 中的 pingora 回调映射为五个 `PluginStep`。每个插件实例在请求的**恰好一个**步骤运行：

| 步骤 | 运行时机 | 典型用途 |
| --- | --- | --- |
| `early_request` | 读完请求行与头之后、路由之前 | 协商压缩 / `Accept-Encoding` |
| `request` | 已匹配 location | 认证、限流、缓存、mock、静态文件 |
| `proxy_upstream` | location 已解析、尚未选后端 | 不应在缓存命中时执行的检查 |
| `upstream_response` | 上游响应头到达时 | 改写上游头、响应体变换 |
| `response` | 响应头即将发往下游时 | 添加响应头、正文替换 |

若 `step` 设为插件未实现的值，该插件静默跳过。只有 `directory`、`limit`、`request_id` 和 `stats` 会读取 `step`；其余插件固定自身步骤（见各插件文档）。

请求步骤插件的返回值：

- `Skipped` — 未生效，继续处理
- `Continue` — 已执行，可能修改了请求，继续处理
- `Respond(response)` — 终止请求并返回该响应

## 插件索引

### 认证与授权

| Category | 用途 | 文档 |
| --- | --- | --- |
| `basic_auth` | HTTP Basic 认证 | [basic_auth](./basic_auth.md) |
| `key_auth` | 请求头或查询参数中的 API Key | [key_auth](./key_auth.md) |
| `jwt` | JWT 校验（HMAC、公钥或远程 JWKS）与签发 | [jwt](./jwt.md) |
| `combined_auth` | app id + 时间戳 + HMAC 摘要，可选绑定 IP | [combined_auth](./combined_auth.md) |
| `forward_auth` | 将决策委托给外部 HTTP 服务 | [forward_auth](./forward_auth.md) |
| `csrf` | 双提交 Cookie CSRF 防护 | [csrf](./csrf.md) |

### 访问控制

| Category | 用途 | 文档 |
| --- | --- | --- |
| `ip_restriction` | 按 IP 或 CIDR 允许/拒绝 | [ip_restriction](./ip_restriction.md) |
| `referer_restriction` | 按 `Referer` 主机允许/拒绝 | [referer_restriction](./referer_restriction.md) |
| `ua_restriction` | 按 `User-Agent` 正则允许/拒绝 | [ua_restriction](./ua_restriction.md) |
| `geo_restriction` | 按 GeoIP 国家允许/拒绝（feature `geo`） | [geo_restriction](./geo_restriction.md) |

### 流量控制

| Category | 用途 | 文档 |
| --- | --- | --- |
| `limit` | 速率限制与并发限制 | [limit](./limit.md) |
| `traffic_splitting` | 将部分流量导向另一 upstream | [traffic_splitting](./traffic_splitting.md) |
| `cache` | HTTP 缓存，支持 `PURGE` | [cache](./cache.md) |

### 内容

| Category | 用途 | 文档 |
| --- | --- | --- |
| `compression` | gzip / brotli / zstd 响应压缩 | [compression](./compression.md) |
| `accept_encoding` | 规范化客户端 `Accept-Encoding` | [accept_encoding](./accept_encoding.md) |
| `directory` | 静态文件，支持 range 与 autoindex | [directory](./directory.md) |
| `sub_filter` | 响应体字面量 / 正则替换 | [sub_filter](./sub_filter.md) |
| `response_headers` | 添加 / 设置 / 删除 / 重命名响应头 | [response_headers](./response_headers.md) |
| `cors` | CORS 预检与响应头 | [cors](./cors.md) |
| `redirect` | HTTP↔HTTPS 重定向与路径前缀 | [redirect](./redirect.md) |
| `image_optim` | PNG/JPEG 重编码为 WebP/AVIF（feature `imageoptim`） | [image_optim](./image_optim.md) |

### 运维

| Category | 用途 | 文档 |
| --- | --- | --- |
| `ping` | 存活探测，返回 `pong` | [ping](./ping.md) |
| `mock` | 返回固定响应，可选延迟 | [mock](./mock.md) |
| `request_id` | 生成或透传请求 ID | [request_id](./request_id.md) |
| `stats` | JSON 进程与请求统计 | [stats](./stats.md) |
| `admin` | Web 管理界面与配置 API | [admin](./admin.md) |

`stats` 与 `admin` 位于 `pingap` 二进制（`src/plugin/`）而非本 crate，因为它们需要进程与配置管理器。`image_optim` 位于 `pingap-imageoptim`。它们都注册到同一工厂，配置方式完全一致。

## 编写插件

1. 实现 `pingap_core::Plugin`。只需覆盖需要的钩子——其余方法默认空操作。
2. 在 `TryFrom` 中解析 `&PluginConf`，使用 `src/plugin.rs` 中的 `get_*_conf` 辅助函数，在此拒绝非法组合，以便 `pingap -t` 在代理启动前发现错误。
3. 从 `config_key()` 返回 `get_hash_key(conf)`。Pingap 用它判断热更新是否真正改变了该插件实例。
4. 用 `register_plugin!` 宏注册 category，该宏展开为 pre-main 构造。

```rust
use async_trait::async_trait;
use pingap_core::{Ctx, Plugin, PluginStep, RequestPluginResult};
use pingora::proxy::Session;
use std::borrow::Cow;

pub struct MyPlugin {
    hash_value: String,
}

#[async_trait]
impl Plugin for MyPlugin {
    fn config_key(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.hash_value)
    }

    async fn handle_request(
        &self,
        step: PluginStep,
        _session: &mut Session,
        _ctx: &mut Ctx,
    ) -> pingora::Result<RequestPluginResult> {
        if step != PluginStep::Request {
            return Ok(RequestPluginResult::Skipped);
        }
        Ok(RequestPluginResult::Continue)
    }
}

register_plugin!("my_plugin", MyPlugin);
```

## Features

- `geo` — 启用 `geo_restriction` 插件（内嵌 Tor GeoIP 数据库）。

## 许可证

Apache-2.0.
