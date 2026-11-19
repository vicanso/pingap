# AI / LLM SSE Streaming Gateway

Configuration template tailored for OpenAI-compatible LLM APIs and MCP Server-Sent Events (SSE) streams.

## Highlights

- **Unbuffered SSE streaming** ([locations.toml](./locations.toml)): Response compression is intentionally omitted on `/v1/` so token chunks (`text/event-stream`) stream straight to clients without compressor buffering.
- **Generous streaming timeouts** ([upstreams.toml](./upstreams.toml)): `read_timeout = "5m"` and `idle_timeout = "120s"` prevent premature disconnects during slow reasoning phases, while `connection_timeout = "5s"` keeps connect failures fast.
- **TTFT observability** ([servers.toml](./servers.toml)): Access logs record `{:upstream_first_body_time}` (Time-To-First-Token / first body chunk latency in ms) alongside `{:upstream_response_time}` and `{:upstream_name}`.
- **429 / 5xx circuit breaking & fallback failover**: `openai_primary` enables backend stats (`backend_failure_status_code = "429,500,502,503,504"` and `circuit_break_max_consecutive_failures = 3` for `30s`). Once tripped, `ai_chat` routes requests to `fallback_upstream = "openai_fallback"`.
- **High-cardinality per-API-key rate limiting** ([plugins.toml](./plugins.toml)): `ai_rate_limit` uses `mode = "exact"` (`max_keys = 50000`, `tag = "header"`, `key = "x-api-key"`) to enforce per-key quotas without Count-Min Sketch hash collisions.

## Run

```bash
cargo run -- -c=examples/ai-gateway --admin=127.0.0.1:3018 --autoreload
```
