# Pingap Web Admin Design & Engineering System

This document captures the visual language, layout resilience rules, mobile-native platform contracts, motion discipline, and copy conventions for the Pingap Web Admin console (`web/`). Every rule names concrete tokens, classes, or files and states why it exists.

> Guardrails that can be verified mechanically are enforced by [`test_web_admin_design_guardrails`](pingap-config/src/unknown.rs) alongside [`test_admin_forms_have_an_item_for_every_key`](pingap-config/src/unknown.rs).

---

## Surfaces

- **Framed sheet over three luminance tiers, flat at rest.**
  The sidebar and top bar share one low-chroma frame (`--background`), every page sits on an inset sheet (`--canvas`, `lg:rounded-2xl lg:border` in `web/src/pages/Root.tsx`), and data groups lift onto cards (`--card`). *Inferred:* an operations console is scanned for hours; depth comes from one tone step and hairline borders rather than drop shadows or glass effects at rest.
  <!-- 2026-11-28: existing design comment in web/src/index.css + web/src/pages/Root.tsx -->

- **Inputs stay recessed until focused, never white-on-white at rest in dark mode.**
  Fields use `bg-input-surface` and `focus-visible:bg-card` (`web/src/components/ui/input.tsx`, `textarea.tsx`, `select.tsx`). *Inferred:* dense forms need clear field boundaries without thick outlines.
  <!-- 2026-11-28: existing comment in web/src/components/ui/input.tsx -->

- **Floating layers use `overscroll-contain`, never bleed scroll into the canvas.**
  Dialogs, sheets, command lists, popovers, dropdowns, select menus, code panels (`<pre>`), and non-`fill` `PageShell` scrollers always set `overscroll-contain` (`html, body` use `overscroll-behavior: none`).
  <!-- 2026-11-28: mobile-native pass across web/src/index.css, page-shell.tsx, ui/*.tsx -->

- **Never nest modal triggers (`<AlertDialog>` / `<Dialog>`) inside `<DropdownMenu>` / `<DropdownMenuItem>`.**
  Lift modal `open` state outside `<DropdownMenu>` and trigger it from `onSelect` (`web/src/components/header.tsx`) so Radix closes the menu cleanly before locking focus in the dialog, rather than keeping `DropdownMenuContent` mounted over the overlay. Enforced by `test_web_admin_design_guardrails`.
  <!-- 2026-11-28: overlay stacking fix in header.tsx + unknown.rs guardrail -->

- **Close active `Sheet` drawers before opening diff or confirmation dialogs.**
  `SheetContent` and `DialogContent`/`AlertDialogContent` share `z-50`; closing the drawer (`setOpen(false)`) before opening `ConfigDiffDialog` or confirmation `AlertDialog` prevents the sheet from sitting undimmed above the backdrop (`web/src/pages/History.tsx`).
  <!-- 2026-11-28: overlay stacking fix in History.tsx -->

---

## Color

- **Chrome stays neutral; color belongs to telemetry and health states.**
  Primary focus and charts use the teal accent (`--chart-1`, `--primary`), while operational health uses strictly separated tokens (`--ok` green, `--warn` amber, `--down` red) so chart series are never mistaken for health status (`web/src/index.css`).
  <!-- 2026-11-28: existing comment in web/src/index.css -->

- **Pre-paint `theme-color` and `background-color` stay synced with `--background`.**
  `web/index.html` and `web/src/components/theme-provider.tsx` maintain matching light (`#eceff4` / `hsl(212, 26%, 94%)`) and dark (`#0a0d12` / `hsl(222, 26%, 5.5%)`) values on both `<html>` and `<meta name="theme-color">`, including live updates when manual theme toggles override `system`. *Inferred:* browser chrome seams and first-paint flashes break the native app frame feel on mobile and desktop.
  <!-- 2026-11-28: mobile-native pass in web/index.html + theme-provider.tsx -->

---

## Typography

- **Three semantic roles: UI prose (`--font-sans`), aligned metrics (`.figure`), and copyable machine identifiers (`.machine`).**
  - Prose keeps `IBM Plex Sans` + explicit CJK fallbacks (`PingFang SC`, `Hiragino Sans GB`, `Microsoft YaHei`).
  - Numbers read or compared across rows use `.figure` (`font-variant-numeric: tabular-nums`).
  - Addresses, ports, routes, hashes, TOML/HCL/KDL, and entity badges use `.machine` (`IBM Plex Mono` + `tabular-nums`, `web/src/index.css`).
  <!-- 2026-11-28: existing tokens & utilities in web/src/index.css -->

- **Interactive touch inputs stay `>= 16px` (`text-base`) on coarse pointers and mobile widths.**
  `input:not([type="checkbox"]):not([type="radio"])`, `textarea`, and `select` floor at `max(16px, 1rem)` inside `@media (pointer: coarse)` (`web/src/index.css`), and inputs in `command.tsx`, `plugin-category-picker.tsx`, `Config.tsx`, and `Diagnostics.tsx` step down only at `sm:`/`md:`. Why: iOS Safari auto-zooms the viewport on any input smaller than `16px` and does not zoom back out on blur.
  <!-- 2026-11-28: mobile-native pass -->

---

## Spacing & layout

- **Every flex or grid child holding dynamic names, addresses, or URLs must set `min-w-0`.**
  Pairs of `<name>` + `<value>` in cards, headers, alerts, command palette rows, and forms constrain the name/value with `truncate` + `title={fullText}` (or `break-words`/`break-all` for non-link messages/hashes like `abnormal_exit`, `normalized_path`, and `snapshot.id`), and never leave an unbounded `shrink-0` string next to a flexing sibling. Why: 60+ character unbreakable upstream/server names pushed columns and chevrons off-screen at `320px`.
  <!-- 2026-11-28: break-ui pass across Home.tsx, ConfigEntityList, TrafficPanel, Root.tsx, Diagnostics.tsx -->

- **Truncated table cells and summary readouts always expose full text via `title`.**
  Never truncate with `truncate` / `text-overflow: ellipsis` on read-only values without a `title` (or detail route + full-text wrap) (`EntityText` in `config-entity-list.tsx`, `ConfigEntitySummary`, `TrafficPath`, `TrafficPanel`, `Home.tsx`, `ConfigEntityBadge`). *Inferred:* operators reading 64-char SHA hashes or long domain SAN lists need a zero-click way to inspect the full string.
  <!-- 2026-11-28: break-ui pass -->

- **Fixed-width micro-visualizations degrade before overflowing `320px` cells.**
  When `TrafficPath`'s `HealthStrip` exceeds 12 backends, render the compact ratio bar below `sm` and individual ticks on `sm+` (`<= 28` ticks total). *Inferred:* 13–28 fixed-width ticks (`> 100px`) overflow 2-column mobile stage cells (`~145px`).
  <!-- 2026-11-28: break-ui fix in web/src/components/traffic-path.tsx -->

- **Fixed app-shell wrappers use `h-dvh`, scrolling auth pages use `min-h-svh`, and chrome respects `env(safe-area-inset-*)`.**
  `SidebarProvider` and desktop `sidebar-container` use `h-dvh`; `Login.tsx` keeps `min-h-svh`; `MainHeader`, mobile `Sheet` sidebar, `PageShell`, sticky `ExForm` action bar, and `Sonner` `mobileOffset` pad against safe-area insets.
  <!-- 2026-11-28: mobile-native pass in sidebar.tsx, header.tsx, page-shell.tsx, sonner.tsx, Login.tsx -->

- **Header action toolbars and segmented filter strips always use `flex-wrap`.**
  Toolbars combining custom actions + primary CTAs (`ConfigEntityList` actions, `Diagnostics` filter groups) wrap cleanly at `320px` and `200%` zoom.
  <!-- 2026-11-28: break-ui pass in config-entity-list.tsx, Diagnostics.tsx -->

- **All entity URLs and API paths encode names with `encodeURIComponent(name)` — never raw `${name}` interpolation.**
  Entity names containing `&`, `+`, `#`, spaces, or CJK break query parsing unless encoded (`routers.tsx`, `Home.tsx`, `sidebar-nav.tsx`, `config-entity-list.tsx`, `traffic-panel.tsx`, `command-palette.tsx`, `states/config.ts`). Enforced by `test_web_admin_design_guardrails`.
  <!-- 2026-11-28: break-ui audit found raw ?name=${name} and /configs/${name} bugs -->

- **Stress fixtures stay strictly behind `import.meta.env.DEV` in `web/src/dev/`.**
  The `BreakUiBar` fixture toggle (`?data=worst|empty|one`) mounts only via `import.meta.env.DEV ? lazy(() => import("@/dev/break-ui-bar")) : null` in `Root.tsx` — passed inline into `MainHeader` `devSlot` as a compact dropdown rather than a `fixed` overlay so it never obscures page actions or sticky form bars — and production `make build-web` (`dist/`) ships zero mock data or debug chrome. Enforced by `test_web_admin_design_guardrails`.
  <!-- 2026-11-28: break-ui dev-only harness rule (moved inline via MainHeader devSlot) -->

- **Fold multi-column tables into 2-line mobile rows (`ConfigEntityList`, `TrafficPanel`) or stacked cards (`Diagnostics` `Recent Events`).**
  Keep desktop `<Table>` inside `hidden sm:block` / `hidden md:block` and render compact `sm:hidden` 2-line rows or `md:hidden` stacked cards on small viewports, align parallel desktop tables with `table-fixed` + shared `<colgroup>` widths (`traffic-panel.tsx`), right-align numeric columns (`.figure text-right`), and set `whitespace-normal break-words` on unwrapped log/error message cells (`Diagnostics.tsx`). Why: 6–8 column tables clipped mid-character at `320px`/`390px` (and `Streams` / `Recent Events` overflowed at `1440px`).
  <!-- 2026-11-28: responsive table pass in config-entity-list.tsx, traffic-panel.tsx, Diagnostics.tsx -->

- **`ExForm` sections sum cleanly to multiples of the 6-column desktop grid (`span` 2 / 3 / 6), without blank filler cells.**
  Balance field `span`s inside every form `section` to complete 6-column rows, and adapt trailing `col-span` in `ConfigEntitySummary` and `Home` runtime cards rather than rendering empty bordered filler cells, so sections never end with orphan half-rows.
  <!-- 2026-11-28: form & summary grid pass in ex-form.tsx, config-entity-summary.tsx, Home.tsx, pages/*.tsx, plugin-fields.ts -->

- **Single-choice `ExForm` fields with 4 or more options use `SELECT` rather than `RADIOS`.**
  Use controlled `ExFormItemCategory.SELECT` (`value={selectedOption}`, `disabled={item.readOnly || false}`) once options reach 4+ (`Certificates.tsx` `dns_provider`, `Upstreams.tsx` `alpn`/`h1_upgrade`, `plugin-fields.ts` `limit.tag`) so radio groups do not wrap awkwardly inside `span: 2` or `span: 3` cells.
  <!-- 2026-11-28: form control density pass in ex-form.tsx, Certificates.tsx, Upstreams.tsx, plugin-fields.ts -->

---

## Motion

- **Never use `transition-all` or `transition: all`.**
  Every transition names explicit properties (`transition-colors`, `transition-[color,background-color,border-color,box-shadow,transform]`) so layout properties (`width`, `height`, `padding`) cannot animate accidentally. Enforced by `test_web_admin_design_guardrails`.
  <!-- 2026-11-28: remove-animations + animation-performance pass across button.tsx, switch.tsx, tabs.tsx, sidebar.tsx -->

- **Keyboard-shortcut actions (`⌘K` Command Palette, `⌘B` Sidebar toggle) and layout geometry execute instantaneously (`0ms`).**
  `CommandDialog` renders with `animated={false}` (`ui/dialog.tsx`, `ui/command.tsx`), `Sidebar` omits `transition-[width]` / `transition-[left,right,width]` (`ui/sidebar.tsx`), and `MainHeader` omits height/width transitions (`header.tsx`). *Inferred:* animating keyboard-initiated navigation or re-laying out dashboard charts/tables on every frame adds sluggishness and frame drops with zero spatial benefit.
  <!-- 2026-11-28: remove-animations + animation-performance pass -->

- **No decorative transforms on high-frequency list or table row hover.**
  Table rows and navigation items transition background/text color only (`ConfigEntityList` removed `group-hover:translate-x-0.5` on chevrons). *Inferred:* shifting icons across 20+ rows on cursor sweep creates visual noise without aiding orientation.
  <!-- 2026-11-28: remove-animations pass in config-entity-list.tsx -->

- **Shared precision curves & asymmetric durations across interactive overlays.**
  `@theme` defines `--ease-out: cubic-bezier(0.23, 1, 0.32, 1)`, `--ease-in-out: cubic-bezier(0.77, 0, 0.175, 1)`, and `--ease-drawer: cubic-bezier(0.32, 0.72, 0, 1)` (`web/src/index.css`):
  - Popovers, dropdowns, selects, tooltips: `150ms` enter / `100ms` exit (`--ease-out`).
  - Modal dialogs & alert dialogs: `200ms` enter / `150ms` exit (`--ease-out`).
  - Sheets / mobile drawer: `300ms` enter / `200ms` exit (`--ease-drawer`).
  - Buttons (`variant !== "link"`): crisp tactile `active:scale-[0.98]` at `150ms` (`--ease-out`).
  <!-- 2026-11-28: improve-animations pass across index.css, ui/{button,sheet,dialog,alert-dialog,popover,dropdown-menu,select,tooltip}.tsx -->

- **`prefers-reduced-motion: reduce` removes spatial movement (`translate` / `scale`) without blinding opacity/state feedback.**
  Overlay spatial variables zero out (`--tw-enter-translate-*: 0`, `--tw-enter-scale: 1`), active button scale disables, and `.animate-spin` slows gently to `1.5s` rather than collapsing all durations to `0.01ms !important` (`web/src/index.css`). *Inferred:* smooth opacity cross-fades and gentle spinner progress remain essential state cues for vestibular-sensitive users.
  <!-- 2026-11-28: improve-animations pass in web/src/index.css -->

---

## Interaction

- **Never block pinch-zoom (`user-scalable=no` / `maximum-scale=1`) or global text selection on `body`.**
  `user-select: none` applies only to interactive controls (`button, summary, [role="button"], [role="tab"], [data-slot="tabs-trigger"]`); tables, logs, `.machine` values, and `<pre>` remain selectable. `touch-action: manipulation` removes 300ms double-tap delay on controls, and `-webkit-tap-highlight-color: transparent` removes default gray flash (`web/src/index.css`). Enforced by `test_web_admin_design_guardrails`.
  <!-- 2026-11-28: mobile-native pass in web/index.html + web/src/index.css -->

- **Machine/technical inputs disable iOS autocapitalize, autocorrect, and spellcheck.**
  Hosts, paths, queries, cookies, config textareas, filter/command inputs, and account login set `autoCapitalize="none" autoCorrect="off" spellCheck={false}` plus appropriate `enterKeyHint` (`search` / `next` / `go`).
  <!-- 2026-11-28: mobile-native pass in Login.tsx, command.tsx, sidebar-nav.tsx, config-entity-list.tsx, Config.tsx, Diagnostics.tsx -->

- **Sidebar tooltips allow a brief `150ms` intent delay (`delayDuration={150}`).**
  Prevents accidental tooltip flashing when sweeping across collapsed rail icons (`ui/sidebar.tsx`).
  <!-- 2026-11-28: remove-animations / polish pass in web/src/components/ui/sidebar.tsx -->

---

## Copy

- **Both English (`en.ts`) and Chinese (`zh.ts`) share identical i18n schemas and concise operational phrasing.**
  Every missing/unset scalar displays `—` (`EntityText`, `ConfigEntitySummary`, runtime grid), while numeric counters format with `toLocaleString()` so empty states, `1` item, and `100,000+` items read consistently without hardcoded grammar assumptions.
  <!-- 2026-11-28: existing AGENTS.md + web/src/i18n/ conventions + break-ui count formatting -->
