# Documents

- [acme chart](./acme_chart.md)
- [modules](./modules.md)
- **Chinese translations** — [zh/](./zh/) (home, plugins, crates, guide)
- **GitHub Pages** (bilingual) — built by
  [`scripts/build-website.sh`](../scripts/build-website.sh), deployed by
  [`.github/workflows/pages.yml`](../.github/workflows/pages.yml).

  | URL | Content |
  | --- | --- |
  | `https://vicanso.github.io/pingap/` | language picker |
  | `https://vicanso.github.io/pingap/en/` | English (from crate / plugin READMEs) |
  | `https://vicanso.github.io/pingap/zh/` | 中文 (from `docs/zh/`) |

  Local preview:

  ```bash
  ./scripts/build-website.sh
  python3 -m http.server -d website 8080
  ```

## Crate documentation

Each workspace crate has its own README describing what it owns, how it is
configured and where it sits in the dependency graph.

| Crate | What it does |
| --- | --- |
| [pingap-util](../pingap-util/README.md) | Crypto, IP rules, PEM/base64, path and formatting helpers |
| [pingap-core](../pingap-core/README.md) | `Ctx`, `HttpResponse`, the `Plugin` trait, background services, coarse clock |
| [pingap-config](../pingap-config/README.md) | Configuration model, storage backends, TOML/HCL/KDL |
| [pingap-discovery](../pingap-discovery/README.md) | Static / DNS / Docker / transparent backend discovery |
| [pingap-health](../pingap-health/README.md) | TCP, HTTP(S) and gRPC health checks |
| [pingap-upstream](../pingap-upstream/README.md) | Load balancing, circuit breaking, upstream connection options |
| [pingap-location](../pingap-location/README.md) | Host/path matching, rewriting, per-location limits |
| [pingap-certificate](../pingap-certificate/README.md) | SNI-based dynamic TLS certificate store |
| [pingap-acme](../pingap-acme/README.md) | Let's Encrypt HTTP-01 and DNS-01 automation |
| [pingap-cache](../pingap-cache/README.md) | Memory (TinyUFO) and file cache backends |
| [pingap-plugin](../pingap-plugin/README.md) | Built-in plugins — see the [plugin index](../pingap-plugin/README.md#plugin-index) |
| [pingap-imageoptim](../pingap-imageoptim/README.md) | PNG/JPEG → WebP/AVIF conversion |
| [pingap-logger](../pingap-logger/README.md) | Access logs, file/syslog writers, rotation and compression |
| [pingap-performance](../pingap-performance/README.md) | Prometheus metrics and process introspection |
| [pingap-otel](../pingap-otel/README.md) | OpenTelemetry distributed tracing |
| [pingap-sentry](../pingap-sentry/README.md) | Sentry error reporting |
| [pingap-pyroscope](../pingap-pyroscope/README.md) | Continuous CPU profiling |
| [pingap-webhook](../pingap-webhook/README.md) | Operational notifications to WeCom / DingTalk / HTTP |
| [pingap-proxy](../pingap-proxy/README.md) | The proxy engine: lifecycle, routing, server configuration |

## Plugin documentation

Every plugin has a page covering its configuration keys, worked examples and the
caveats worth knowing before you deploy it:
[pingap-plugin/docs](../pingap-plugin/README.md#plugin-index).
