# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Pingap is a Cloudflare-Pingora-based reverse proxy. The binary lives in `src/`; all reusable logic is split across `pingap-*` workspace crates. MSRV is `1.88.0` (Rust edition 2024). Pingora is pinned to `0.8.0` and only the `lb`/`openssl`/`cache` features are enabled.

## Common commands

```bash
# Bacon-driven dev loop (uses --autoreload + admin UI on :3018)
make dev                 # bacon run -- --features=full -- -c=... --admin=...

# Lint (CI gate — runs typos + clippy --features=full --all-targets -- -D warnings)
make lint

# Format
make fmt

# Full test suite (requires the `full` feature set)
make test                # cargo test --workspace --features=full

# One package / one test (use cargo directly, not make)
cargo test -p pingap-proxy
cargo test -p pingap-core util::tests::test_now_ms -- --nocapture

# Benchmarks (criterion)
make bench               # workspace-wide
make bench-all           # explicit list (pingap-core, pingap-logger, pingap-location)

# Release builds — see Makefile for the matrix
make release             # default features
make release-full        # tracing + imageoptim
make release-perf        # release-perf profile, includes pyroscope agent

# Web admin assets (rust-embed'd into the binary at build time)
make build-web           # cd web && npm install && npm run build, then cp dist ../

# Pre-commit hook (runs `make lint`)
make hooks               # cp hooks/* .git/hooks/
```

Bacon shortcuts: `bacon` (check), `bacon clippy-all`, `bacon test`, `bacon test -- some::path`, `bacon nextest`, `bacon doc-open`.

## Architecture

The dependency layering (see `docs/modules.md` for the full mermaid graph) is roughly:

```
util -> core -> {discovery, config, logger, location, cache, certificate, upstream, plugin, health}
                        |
                        v
              acme, performance, otel, sentry, pyroscope, imageoptim, webhook
                        |
                        v
                     proxy <- top binary (`src/main.rs`)
```

- `pingap-core` — `HttpResponse`, `Ctx`, plugin traits, coarse clock helpers (`now_sec`/`now_ms`/`real_now_ms`), `BackgroundTaskService`, `ClockUpdaterService`. Every other crate depends on it.
- `pingap-config` — `PingapConfig` model plus storage backends (`file_storage.rs`, `etcd_storage.rs`) chosen at runtime by URL prefix (`file://`, `etcd://`). Supports TOML, HCL (`hcl.rs`), and KDL (`kdl.rs`) input formats.
- `pingap-proxy` — implements pingora's `ProxyHttp`. The request lifecycle in `pingap-proxy/src/server.rs` calls (in order) `early_request_filter` -> `request_filter` -> `proxy_upstream_filter` -> `upstream_request_filter` -> `upstream_response_filter` -> `logging`. Each step matches the `PluginStep` enum in `pingap-core/src/plugin.rs` (`EarlyRequest`, `Request`, `ProxyUpstream`, `UpstreamResponse`, `Response`); a plugin runs at most one step per request.
- `pingap-plugin` — built-in plugins. Add new ones by implementing the `Plugin` trait from `pingap-core` and registering them via the plugin factory.
- `pingap-upstream` — pingora `Backends` + load-balancing wiring; gets its backend set from `pingap-discovery` (static / DNS / Docker labels / transparent) and `pingap-health` for active checks.
- `src/main.rs` — argument parsing, config bootstrap, daemonization, server assembly. The `src/process/` and `src/plugin/` modules handle hot reload + the admin plugin.
- `build.rs` — uses `vergen = "9.1.0"` + `vergen-git2 = "9.1.0"` to embed `VERGEN_GIT_SHA` into the binary's `--version`. **Both crates must stay on matching majors**; if you see `Add` trait-bound errors from `vergen_lib`, the lockfile has pulled mismatched versions — refresh it.
- `examples/` — working configs to copy from: `api-gateway`, `grpc-web`, `static-serve`, `transparent-proxy`, `web-socket`.

### Hot reload vs auto-restart

`src/main.rs` branches on `pingap_config::ConfigManager::support_observer()`. **etcd** returns `true` and pushes changes via a `WatchStream` (`pingap-config/src/etcd_storage.rs`) wired through `new_observer_service`. **File** storage returns `false` and is polled by `new_auto_restart_service` (`src/process/auto_restart.rs`) on a fixed interval. Both feed the same `reload_handle` — the difference is only the delivery mechanism. `--autoreload` keeps the process and swaps config in place; `--autorestart` performs a zero-downtime graceful restart for changes that need a fresh listener.

### Daemonization and the coarse clock

Pingora forks inside `Server::run_forever()` for daemon mode. **`fork()` only carries the calling thread**, so any `std::thread` (including coarsetime's background updater) started before the fork is gone in the child.

`pingap_core::ensure_clock_updater()` is pid-aware and idempotent — it detects a pid mismatch and re-spawns the coarsetime updater for the current process. `pingap_core::ClockUpdaterService` is a pingora `BackgroundService` that wraps that call so the updater is guaranteed to (re)start *inside* the post-fork process. The service is registered in `src/main.rs` right after `my_server.bootstrap()`; the `#[ctor]` in `pingap-core/src/util.rs` handles the non-daemon path. Anything time-sensitive that runs only on specific paths (e.g. admin auth in `src/plugin/admin.rs`) must not assume `now_sec()` is fresh without this safety net — otherwise it returns the last cached value and skews by hours.

### Plugin step contract

`PluginStep` is matched to the pingora callback by `pingap-proxy/src/server.rs`. Plugins return `RequestPluginResult` (`Skipped` / `Continue` / `Respond(HttpResponse)`) or `ResponsePluginResult`. Respect the configured `step` value — running a request plugin at `Response` is silently a no-op.

### Config formats

The same configuration can be expressed in TOML (canonical, see `conf/*.toml`), HCL (`conf/test.hcl`), or KDL (`conf/test.kdl`). `--to-hcl` and `--to-kdl` round-trip the loaded config. The `--sync <url>` flag pushes the loaded config to a different backend (e.g. file -> etcd). `--template` prints a starter TOML and exits.

## Features and feature gates

The top-level `[features]` block in `Cargo.toml`:

- `default` — none, lean build.
- `tracing` — turns on `pingap-otel` + `pingap-sentry`, and the `tracing` feature on `pingap-cache`, `pingap-core`, `pingap-performance`, `pingap-proxy`, and pingora's `sentry`. **`pingap-cache/tracing` also pulls in `prometheus`** — needed for any code touching cache metrics.
- `imageoptim` — `pingap-imageoptim` (png/jpeg/webp/avif).
- `full` = `tracing` + `imageoptim`. Required by `make test` and `make lint`.
- `pyro` — pyroscope agent.
- `perf` = `pyro` + `full`, paired with the `release-perf` profile (keeps debug info, no strip).

When adding a feature-gated module, mirror the wiring in both the workspace `Cargo.toml` and the consuming crate's `Cargo.toml`, and gate the `use`/registration with `#[cfg(feature = "...")]`.

## Configuration loading and env vars

`src/main.rs::parse_arguments()` overlays CLI args with `PINGAP_*` env vars. Anything not on the CLI falls back to env: `PINGAP_CONF`, `PINGAP_DAEMON`, `PINGAP_UPGRADE`, `PINGAP_LOG`, `PINGAP_ADMIN_ADDR`/`PINGAP_ADMIN_USER`/`PINGAP_ADMIN_PASSWORD` (these three combine into `--admin user:pass@addr` with base64-encoded creds). Other env vars used at runtime: `PINGAP_DISABLE_ACME`, `PINGAP_COARSE_CLOCK_INTERVAL` (in **milliseconds**, clamped 1–500), and `$ENV:...` interpolations inside HCL configs (e.g. `$ENV:PINGAP_DNS_SERVICE_URL`).

CLI flags worth knowing: `-c/--conf <url>`, `-d/--daemon`, `-u/--upgrade` (hot upgrade from a running instance), `-t/--test` (validate config and exit), `-a/--autorestart` (graceful restart on config change), `--autoreload` (hot reload only — preferred for containers), `--cp` (control-panel mode, admin only).

## Lint and code style notes

- `clippy.toml` denies unwrap outside tests, sets `cognitive-complexity-threshold = 10`, and pins `msrv = "1.88.0"`. The root `Cargo.toml` adds `unwrap_used = "deny"`.
- CI runs `cargo clippy --features=full --all-targets --all -- --deny=warnings` plus `typos`. Run `make lint` before pushing.
- The git pre-commit hook (installed via `make hooks`) just runs `make lint`.
- `typos.toml` excludes `*.md` and `*.toml` from the spell check — typos in those file types will not be caught by `make lint`.

## CI gates

`.github/workflows/test.yml` runs every gate listed below; any one of them failing breaks the build. Reproduce locally with the corresponding command:

| CI step | Local equivalent |
|---|---|
| `cargo fmt --all -- --check` | `make fmt` (auto-fixes) or run the check directly |
| `make lint` (typos + clippy `--features=full -D warnings`) | `make lint` |
| `cargo machete` | `cargo install cargo-machete@0.9.1 && cargo machete` — `Cargo.toml` whitelists `humantime-serde`, `include-flate`, `hcl-rs`, `kdl` in `[package.metadata.cargo-machete]` |
| `make test` (`cargo test --workspace --features=full`) | `make test` |
| `cargo msrv list` | `cargo install cargo-msrv --version 0.18.4 && cargo msrv list` |
| `cargo llvm-cov` | `make cov` |
| `make release-all` (builds both `pingap` and `pingap-full`) | `make release-all` |
| `make build-web` (web assets) | `make build-web` |

## Web admin

`web/` is a Vite/React app. After editing it, run `make build-web` so the compiled assets in `dist/` get embedded into the binary via `rust-embed` at compile time. `--admin user:pass@host:port[/prefix]` exposes the admin UI; in `make dev` it's on `127.0.0.1:3018`.
