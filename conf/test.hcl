server "test" {
  addr = "127.0.0.1:6118"

  location "github-api" {
    path = "/api"
    proxy_set_headers = ["Host:api.github.com"]
    rewrite = "^/api/(?<path>.+)$ /$1"

    upstream "api" {
      addrs     = ["api.github.com:443"]
      discovery = "dns"
      sni       = "api.github.com"
    }
  }

  location "static" {
    plugin "staticServe" {
      category = "directory"
      path     = "~/Downloads"
      step     = "request"
    }
  }
}

