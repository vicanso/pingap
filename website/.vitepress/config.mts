import { defineConfig } from "vitepress";
import { withMermaid } from "vitepress-plugin-mermaid";

const github = "https://github.com/vicanso/pingap";

// Custom domain (pingap.io) serves at site root. Override for project pages:
//   DOCS_BASE=/pingap/ npm run docs:build
const base = process.env.DOCS_BASE || "/";

function pluginSidebar(prefix: string, labels: {
  overview: string;
  auth: string;
  access: string;
  traffic: string;
  content: string;
  ops: string;
}) {
  return [
    { text: labels.overview, link: `${prefix}/plugins/` },
    {
      text: labels.auth,
      collapsed: false,
      items: [
        { text: "basic_auth", link: `${prefix}/plugins/basic_auth` },
        { text: "key_auth", link: `${prefix}/plugins/key_auth` },
        { text: "jwt", link: `${prefix}/plugins/jwt` },
        { text: "combined_auth", link: `${prefix}/plugins/combined_auth` },
        { text: "forward_auth", link: `${prefix}/plugins/forward_auth` },
        { text: "csrf", link: `${prefix}/plugins/csrf` },
      ],
    },
    {
      text: labels.access,
      collapsed: false,
      items: [
        { text: "ip_restriction", link: `${prefix}/plugins/ip_restriction` },
        { text: "referer_restriction", link: `${prefix}/plugins/referer_restriction` },
        { text: "ua_restriction", link: `${prefix}/plugins/ua_restriction` },
        { text: "geo_restriction", link: `${prefix}/plugins/geo_restriction` },
      ],
    },
    {
      text: labels.traffic,
      collapsed: false,
      items: [
        { text: "limit", link: `${prefix}/plugins/limit` },
        { text: "traffic_splitting", link: `${prefix}/plugins/traffic_splitting` },
        { text: "cache", link: `${prefix}/plugins/cache` },
      ],
    },
    {
      text: labels.content,
      collapsed: false,
      items: [
        { text: "compression", link: `${prefix}/plugins/compression` },
        { text: "accept_encoding", link: `${prefix}/plugins/accept_encoding` },
        { text: "directory", link: `${prefix}/plugins/directory` },
        { text: "sub_filter", link: `${prefix}/plugins/sub_filter` },
        { text: "response_headers", link: `${prefix}/plugins/response_headers` },
        { text: "cors", link: `${prefix}/plugins/cors` },
        { text: "redirect", link: `${prefix}/plugins/redirect` },
        { text: "image_optim", link: `${prefix}/plugins/image_optim` },
      ],
    },
    {
      text: labels.ops,
      collapsed: false,
      items: [
        { text: "ping", link: `${prefix}/plugins/ping` },
        { text: "mock", link: `${prefix}/plugins/mock` },
        { text: "request_id", link: `${prefix}/plugins/request_id` },
        { text: "stats", link: `${prefix}/plugins/stats` },
        { text: "admin", link: `${prefix}/plugins/admin` },
      ],
    },
  ];
}

function crateSidebar(prefix: string, indexLabel: string) {
  const names = [
    "proxy",
    "core",
    "config",
    "plugin",
    "upstream",
    "location",
    "discovery",
    "health",
    "certificate",
    "acme",
    "cache",
    "logger",
    "performance",
    "otel",
    "webhook",
    "sentry",
    "pyroscope",
    "imageoptim",
    "util",
  ];
  return [
    { text: indexLabel, link: `${prefix}/crates/` },
    ...names.map((n) => ({ text: n, link: `${prefix}/crates/${n}` })),
  ];
}

function guideSidebar(prefix: string, labels: {
  modules: string;
  acme: string;
  examples: string;
}) {
  return [
    { text: labels.modules, link: `${prefix}/guide/modules` },
    { text: labels.acme, link: `${prefix}/guide/acme-flow` },
    { text: labels.examples, link: `${prefix}/guide/examples` },
  ];
}

export default withMermaid(
  defineConfig({
    base,
    title: "Pingap",
    description:
      "High-performance reverse proxy powered by Cloudflare Pingora",
    cleanUrls: true,
    lastUpdated: false,
    ignoreDeadLinks: true,
    // Repo notes / tooling files that live next to the docs content
    srcExclude: ["**/BUILD.md", "**/node_modules/**"],

    head: [
      ["link", { rel: "icon", href: `${base}logo.png` }],
      ["meta", { name: "theme-color", content: "#0b6e4f" }],
    ],

    mermaid: {
      theme: "neutral",
    },

    themeConfig: {
      logo: "/logo.png",
      socialLinks: [{ icon: "github", link: github }],
      search: {
        provider: "local",
      },
      outline: {
        level: [2, 3],
      },
    },

    locales: {
      root: {
        label: "English",
        lang: "en",
        title: "Pingap",
        description:
          "High-performance reverse proxy powered by Cloudflare Pingora",
        themeConfig: {
          nav: [
            { text: "Guide", link: "/guide/modules" },
            { text: "Plugins", link: "/plugins/" },
            { text: "Crates", link: "/crates/" },
            { text: "Examples", link: "/guide/examples" },
            {
              text: "vLatest",
              items: [
                { text: "GitHub", link: github },
                { text: "Releases", link: `${github}/releases` },
              ],
            },
          ],
          sidebar: {
            "/guide/": guideSidebar("", {
              modules: "Architecture",
              acme: "ACME flow",
              examples: "Examples",
            }),
            "/plugins/": pluginSidebar("", {
              overview: "Overview",
              auth: "Authentication",
              access: "Access control",
              traffic: "Traffic",
              content: "Content",
              ops: "Operations",
            }),
            "/crates/": crateSidebar("", "Index"),
          },
          footer: {
            message: "Released under the Apache-2.0 License.",
            copyright: "Copyright © Pingap contributors",
          },
          docFooter: {
            prev: "Previous page",
            next: "Next page",
          },
          returnToTopLabel: "Return to top",
          sidebarMenuLabel: "Menu",
          darkModeSwitchLabel: "Appearance",
          lightModeSwitchTitle: "Switch to light theme",
          darkModeSwitchTitle: "Switch to dark theme",
        },
      },
      zh: {
        label: "中文",
        lang: "zh-CN",
        title: "Pingap",
        description: "基于 Cloudflare Pingora 的高性能反向代理",
        link: "/zh/",
        themeConfig: {
          nav: [
            { text: "指南", link: "/zh/guide/modules" },
            { text: "插件", link: "/zh/plugins/" },
            { text: "组件", link: "/zh/crates/" },
            { text: "示例", link: "/zh/guide/examples" },
            {
              text: "更多",
              items: [
                { text: "GitHub", link: github },
                { text: "Releases", link: `${github}/releases` },
              ],
            },
          ],
          sidebar: {
            "/zh/guide/": guideSidebar("/zh", {
              modules: "架构",
              acme: "ACME 流程",
              examples: "示例",
            }),
            "/zh/plugins/": pluginSidebar("/zh", {
              overview: "概览",
              auth: "认证与授权",
              access: "访问控制",
              traffic: "流量",
              content: "内容",
              ops: "运维",
            }),
            "/zh/crates/": crateSidebar("/zh", "索引"),
          },
          footer: {
            message: "基于 Apache-2.0 许可发布。",
            copyright: "Copyright © Pingap contributors",
          },
          docFooter: {
            prev: "上一页",
            next: "下一页",
          },
          returnToTopLabel: "回到顶部",
          sidebarMenuLabel: "菜单",
          darkModeSwitchLabel: "外观",
          lightModeSwitchTitle: "切换到浅色主题",
          darkModeSwitchTitle: "切换到深色主题",
          outlineTitle: "本页目录",
        },
      },
    },
  }),
);
