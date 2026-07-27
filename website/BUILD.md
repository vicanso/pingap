# Building the documentation site

Bilingual documentation for Pingap, built with **[VitePress](https://vitepress.dev/)**
and deployed to GitHub Pages (custom domain <https://pingap.io/>).

## Languages

| URL | Language | Source of truth |
| --- | --- | --- |
| <https://pingap.io/> | English (default) | `pingap-*/README.md`, `pingap-plugin/docs/*`, `docs/`, `examples/` |
| <https://pingap.io/zh/> | 中文 | `docs/zh/**` |

## Layout

| Path | Role |
| --- | --- |
| `.vitepress/config.mts` | VitePress config (nav, sidebar, i18n, mermaid) |
| `.vitepress/theme/` | Brand colours and layout tweaks |
| `public/logo.png` | Site logo |
| `index.md`, `plugins/`, `crates/`, `guide/` | **Generated** English content |
| `zh/**` | **Generated** Chinese content |
| `package.json` | VitePress + mermaid deps |

Do **not** edit generated markdown under `plugins/`, `crates/`, `guide/` or
`zh/` by hand — re-run the build script.

## Local development

```bash
# 1. Assemble markdown from the monorepo
./scripts/build-website.sh

# 2. Install deps (once) and start the VitePress dev server
cd website
npm install
npm run docs:dev
# open the printed local URL (usually http://127.0.0.1:5173/)
```

Production build:

```bash
./scripts/build-website.sh
cd website
npm run docs:build
# output: website/.vitepress/dist
npm run docs:preview
```

If you deploy under a subpath (e.g. `username.github.io/pingap/` without a
custom domain):

```bash
DOCS_BASE=/pingap/ npm run docs:build
```

## Updating Chinese docs

Edit files under `docs/zh/` (not under `website/zh/`). Then re-run
`./scripts/build-website.sh`.

## CI

`.github/workflows/pages.yml`:

1. Runs `scripts/build-website.sh`
2. `npm ci && npm run docs:build` in `website/`
3. Uploads `website/.vitepress/dist` to GitHub Pages
