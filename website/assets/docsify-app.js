/* Shared docsify bootstrap for /en/ and /zh/ */
(function () {
  var lang = document.documentElement.getAttribute("data-lang") || "en";
  var path = location.pathname;

  // Derive base path for this language root, e.g. /pingap/en/ or /en/
  function languageBase() {
    var marker = "/" + lang + "/";
    var idx = path.indexOf(marker);
    if (idx !== -1) {
      return path.substring(0, idx + marker.length);
    }
    // file opened as .../en/index.html
    var bare = "/" + lang;
    idx = path.indexOf(bare);
    if (idx !== -1) {
      return path.substring(0, idx + bare.length) + "/";
    }
    return "/" + lang + "/";
  }

  var base = languageBase();

  // Cross-language twin URL for the navbar switcher
  function otherLangUrl() {
    var other = lang === "zh" ? "en" : "zh";
    var hash = location.hash || "#/";
    // hash is like #/plugins/jwt — keep path, swap language root
    return base.replace("/" + lang + "/", "/" + other + "/") + hash;
  }

  window.__PINGAP_DOCS__ = {
    lang: lang,
    base: base,
    otherLangUrl: otherLangUrl,
  };

  var isZh = lang === "zh";

  // Logo sits next to the site title in the sidebar
  var logoSrc = base.replace(/\/?(en|zh)\/?$/, "/") + "assets/logo.png";
  // When base is /pingap/en/, replace gives /pingap/assets/logo.png
  if (logoSrc.indexOf("assets/logo.png") === -1) {
    logoSrc = "../assets/logo.png";
  }

  window.$docsify = {
    name:
      '<img src="' +
      logoSrc +
      '" alt="" class="app-logo" /> Pingap',
    nameLink: base,
    repo: "https://github.com/vicanso/pingap",
    loadSidebar: true,
    loadNavbar: true,
    subMaxLevel: 3,
    auto2top: true,
    maxLevel: 4,
    homepage: "README.md",
    basePath: base,
    relativePath: false,
    search: {
      maxAge: 86400000,
      paths: "auto",
      placeholder: isZh ? "搜索文档…" : "Search docs…",
      noData: isZh ? "无结果" : "No results",
      depth: 4,
    },
    alias: {
      "/.*/_sidebar.md": "/_sidebar.md",
      "/.*/_navbar.md": "/_navbar.md",
    },
    plugins: [
      function (hook) {
        hook.doneEach(function () {
          if (window.mermaid) {
            try {
              mermaid.run({ querySelector: ".mermaid" });
            } catch (e) {
              /* mermaid < 10 */
              if (mermaid.init) mermaid.init(undefined, ".mermaid");
            }
          }
        });
      },
    ],
    markdown: {
      renderer: {
        code: function (code, langName) {
          if (langName === "mermaid") {
            return '<div class="mermaid">' + code + "</div>";
          }
          return this.origin.code.apply(this, arguments);
        },
      },
    },
  };
})();
