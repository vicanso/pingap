// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Static translators converting common Nginx (`nginx.conf`) and Caddy
//! (`Caddyfile`) configurations into draft Pingap TOML configurations.
//!
//! Supported directives produce ready-to-validate `[servers.*]`,
//! `[locations.*]`, `[upstreams.*]`, `[certificates.*]`, and `[plugins.*]`
//! sections, while unrecognized directives are recorded in both structured
//! `warnings` and `# TODO(...)` header comments so operators know exactly
//! what requires manual review.

use crate::{
    CertificateConf, Error, LocationConf, PingapConfig, PingapTomlConfig,
    Result, ServerConf, UpstreamConf,
};
use bytesize::ByteSize;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use toml::Value;
use toml::map::Map;

/// Output of translating an Nginx or Caddy configuration to Pingap TOML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportResult {
    /// Generated Pingap TOML document (prefixed with `# TODO` comments when
    /// any directives could not be translated automatically).
    pub toml: String,
    /// Non-fatal warnings describing skipped or partially translated directives.
    pub warnings: Vec<String>,
    /// Number of generated server entries.
    pub servers: usize,
    /// Number of generated location entries.
    pub locations: usize,
    /// Number of generated upstream entries.
    pub upstreams: usize,
    /// Number of generated certificate entries.
    pub certificates: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NginxItem {
    Directive(Vec<String>),
    Block(Vec<String>, Vec<NginxItem>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NginxTok {
    Word(String),
    LBrace,
    RBrace,
    Semi,
}

fn read_quoted_word(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    quote: char,
    allow_escape: bool,
) -> (String, bool) {
    let mut word = String::new();
    let mut closed = false;
    let mut escaped = false;
    for c in chars.by_ref() {
        if escaped {
            word.push(c);
            escaped = false;
            continue;
        }
        if allow_escape && c == '\\' {
            escaped = true;
            continue;
        }
        if c == quote {
            closed = true;
            break;
        }
        word.push(c);
    }
    if escaped {
        word.push('\\');
    }
    (word, closed)
}

fn tokenize_nginx(input: &str) -> Result<Vec<NginxTok>> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&ch) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }
        if ch == '#' {
            for c in chars.by_ref() {
                if c == '\n' {
                    break;
                }
            }
            continue;
        }
        match ch {
            '{' => {
                chars.next();
                tokens.push(NginxTok::LBrace);
            },
            '}' => {
                chars.next();
                tokens.push(NginxTok::RBrace);
            },
            ';' => {
                chars.next();
                tokens.push(NginxTok::Semi);
            },
            '\'' | '"' => {
                let quote = chars.next().unwrap_or(ch);
                let (word, closed) = read_quoted_word(&mut chars, quote, true);
                if !closed {
                    return Err(Error::Invalid {
                        message: "unterminated quoted string in nginx config"
                            .to_string(),
                    });
                }
                tokens.push(NginxTok::Word(word));
            },
            _ => {
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() || matches!(c, '{' | '}' | ';' | '#') {
                        break;
                    }
                    word.push(c);
                    chars.next();
                }
                tokens.push(NginxTok::Word(word));
            },
        }
    }
    Ok(tokens)
}

fn parse_nginx_items(
    tokens: &[NginxTok],
    pos: &mut usize,
    stop_at_rbrace: bool,
) -> Result<Vec<NginxItem>> {
    let mut items = Vec::new();
    let mut current: Vec<String> = Vec::new();
    while *pos < tokens.len() {
        match &tokens[*pos] {
            NginxTok::Word(word) => {
                current.push(word.clone());
                *pos += 1;
            },
            NginxTok::Semi => {
                *pos += 1;
                if !current.is_empty() {
                    items.push(NginxItem::Directive(std::mem::take(
                        &mut current,
                    )));
                }
            },
            NginxTok::LBrace => {
                *pos += 1;
                let head = std::mem::take(&mut current);
                let body = parse_nginx_items(tokens, pos, true)?;
                items.push(NginxItem::Block(head, body));
            },
            NginxTok::RBrace => {
                if !stop_at_rbrace {
                    return Err(Error::Invalid {
                        message: "unexpected '}' in nginx config".to_string(),
                    });
                }
                if !current.is_empty() {
                    items.push(NginxItem::Directive(std::mem::take(
                        &mut current,
                    )));
                }
                *pos += 1;
                return Ok(items);
            },
        }
    }
    if stop_at_rbrace {
        return Err(Error::Invalid {
            message: "unclosed '{' block in nginx config".to_string(),
        });
    }
    if !current.is_empty() {
        items.push(NginxItem::Directive(current));
    }
    Ok(items)
}

fn sanitize_id(raw: &str, fallback: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-') {
            out.push(ch);
        } else if !out.ends_with('_') {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn unique_name(existing: &HashMap<String, impl Sized>, base: &str) -> String {
    if !existing.contains_key(base) {
        return base.to_string();
    }
    let mut idx = 2;
    loop {
        let candidate = format!("{base}_{idx}");
        if !existing.contains_key(&candidate) {
            return candidate;
        }
        idx += 1;
    }
}

fn insert_plugin(
    plugins: &mut HashMap<String, Map<String, Value>>,
    base_name: &str,
    entries: Vec<(&str, Value)>,
) -> String {
    let name = unique_name(plugins, base_name);
    let mut map = Map::new();
    for (k, v) in entries {
        map.insert(k.to_string(), v);
    }
    plugins.insert(name.clone(), map);
    name
}

fn parse_nginx_listen(args: &[String]) -> (String, bool, bool) {
    let raw = args.first().map(String::as_str).unwrap_or("80");
    let ssl = args.iter().any(|arg| arg == "ssl");
    let http2 = args.iter().any(|arg| arg == "http2");
    let addr = if raw.contains(':') {
        if raw.starts_with('[') || raw.matches(':').count() == 1 {
            raw.to_string()
        } else {
            format!("[{raw}]")
        }
    } else {
        format!("0.0.0.0:{raw}")
    };
    (addr, ssl, http2)
}

fn parse_nginx_upstream_server(args: &[String]) -> Option<String> {
    let addr = args.first()?.trim();
    if addr.is_empty() {
        return None;
    }
    let mut weight = None;
    for arg in args.iter().skip(1) {
        if let Some(w) = arg.strip_prefix("weight=") {
            weight = w.parse::<usize>().ok();
        }
    }
    let formatted = match weight {
        Some(w) if w != 1 => format!("{addr} {w}"),
        _ => addr.to_string(),
    };
    Some(formatted)
}

fn collect_nginx_upstream(
    head: &[String],
    body: &[NginxItem],
    config: &mut PingapConfig,
    warnings: &mut Vec<String>,
) {
    let raw_name = head.get(1).map(String::as_str).unwrap_or("upstream");
    let name = sanitize_id(raw_name, "upstream");
    let mut addrs = Vec::new();
    for item in body {
        match item {
            NginxItem::Directive(args) => {
                match args.first().map(String::as_str) {
                    Some("server") => {
                        if let Some(addr) =
                            parse_nginx_upstream_server(&args[1..])
                        {
                            addrs.push(addr);
                        }
                    },
                    Some("least_conn" | "ip_hash" | "keepalive") => {
                        warnings.push(format!(
                        "nginx upstream({name}): directive '{}' noted; review upstream algo/keepalive settings",
                        args.join(" ")
                    ));
                    },
                    _ => warnings.push(format!(
                        "nginx upstream({name}): skipped directive '{}'",
                        args.join(" ")
                    )),
                }
            },
            NginxItem::Block(sub_head, _) => warnings.push(format!(
                "nginx upstream({name}): skipped block '{}'",
                sub_head.join(" ")
            )),
        }
    }
    if !addrs.is_empty() {
        config.upstreams.insert(
            name,
            UpstreamConf {
                addrs,
                ..Default::default()
            },
        );
    }
}

fn parse_nginx_location_selector(head: &[String]) -> String {
    match (
        head.get(1).map(String::as_str),
        head.get(2).map(String::as_str),
    ) {
        (Some("="), Some(p)) => format!("={p}"),
        (Some("~" | "~*"), Some(p)) => format!("~{p}"),
        (Some("^~"), Some(p)) => p.to_string(),
        (Some(p), None) => p.to_string(),
        (Some(a), Some(b)) => format!("{a} {b}"),
        _ => "/".to_string(),
    }
}

fn parse_nginx_size(raw: &str) -> Option<ByteSize> {
    let trimmed = raw.trim();
    if let Some(v) = trimmed.strip_suffix(['k', 'K'])
        && let Ok(n) = v.parse::<u64>()
    {
        return Some(ByteSize::kib(n));
    }
    if let Some(v) = trimmed.strip_suffix(['m', 'M'])
        && let Ok(n) = v.parse::<u64>()
    {
        return Some(ByteSize::mib(n));
    }
    if let Some(v) = trimmed.strip_suffix(['g', 'G'])
        && let Ok(n) = v.parse::<u64>()
    {
        return Some(ByteSize::gib(n));
    }
    ByteSize::from_str(trimmed).ok()
}

fn ensure_proxy_upstream(
    target: &str,
    config: &mut PingapConfig,
) -> (String, bool) {
    let is_https = target.starts_with("https://");
    let stripped = target
        .strip_prefix("https://")
        .or_else(|| target.strip_prefix("http://"))
        .unwrap_or(target);
    let authority = stripped.split('/').next().unwrap_or(stripped);
    let sanitized = sanitize_id(authority, "backend");
    if config.upstreams.contains_key(authority) {
        return (authority.to_string(), is_https);
    }
    if config.upstreams.contains_key(&sanitized) {
        return (sanitized, is_https);
    }
    let addr = if authority.contains(':') {
        authority.to_string()
    } else if is_https {
        format!("{authority}:443")
    } else {
        format!("{authority}:80")
    };
    config.upstreams.insert(
        sanitized.clone(),
        UpstreamConf {
            addrs: vec![addr],
            sni: is_https.then(|| {
                authority.split(':').next().unwrap_or(authority).to_string()
            }),
            ..Default::default()
        },
    );
    (sanitized, is_https)
}

#[derive(Default)]
struct NginxLocationDraft {
    loc: LocationConf,
    add_headers: Vec<String>,
    redirect: Option<(u16, String)>,
}

fn apply_nginx_location_directive(
    args: &[String],
    loc_name: &str,
    draft: &mut NginxLocationDraft,
    config: &mut PingapConfig,
    warnings: &mut Vec<String>,
) {
    let key = args.first().map(String::as_str).unwrap_or_default();
    match key {
        "proxy_pass" => {
            if let Some(target) = args.get(1) {
                let (upstream_name, _) = ensure_proxy_upstream(target, config);
                draft.loc.upstream = Some(upstream_name);
            }
        },
        "proxy_set_header" => {
            if let (Some(h_name), Some(h_val)) = (args.get(1), args.get(2)) {
                let lower = h_name.to_ascii_lowercase();
                if matches!(
                    lower.as_str(),
                    "x-real-ip"
                        | "x-forwarded-for"
                        | "x-forwarded-proto"
                        | "x-forwarded-host"
                        | "x-forwarded-port"
                ) {
                    draft.loc.enable_reverse_proxy_headers = Some(true);
                } else if lower != "host" && lower != "connection" {
                    draft
                        .loc
                        .proxy_set_headers
                        .get_or_insert_with(Vec::new)
                        .push(format!("{h_name}: {h_val}"));
                }
            }
        },
        "add_header" => {
            if let (Some(h_name), Some(h_val)) = (args.get(1), args.get(2)) {
                draft.add_headers.push(format!("{h_name}: {h_val}"));
            }
        },
        "rewrite" => {
            if let (Some(pat), Some(rep)) = (args.get(1), args.get(2)) {
                draft.loc.rewrite = Some(format!("{pat} {rep}"));
            }
        },
        "return" => {
            if let (Some(code_str), Some(target)) = (args.get(1), args.get(2))
                && let Ok(code) = code_str.parse::<u16>()
                && (300..400).contains(&code)
            {
                draft.redirect = Some((code, target.clone()));
            } else {
                warnings.push(format!(
                    "nginx location({loc_name}): manual review needed for '{}'",
                    args.join(" ")
                ));
            }
        },
        "client_max_body_size" => {
            if let Some(sz) = args.get(1).and_then(|v| parse_nginx_size(v)) {
                draft.loc.client_max_body_size = Some(sz);
            }
        },
        "proxy_http_version" | "proxy_buffering" => {},
        _ => warnings.push(format!(
            "nginx location({loc_name}): skipped directive '{}'",
            args.join(" ")
        )),
    }
}

fn finalize_nginx_location(
    base_name: &str,
    mut draft: NginxLocationDraft,
    config: &mut PingapConfig,
) -> String {
    let loc_name = unique_name(&config.locations, base_name);
    let mut plugins = Vec::new();
    if !draft.add_headers.is_empty() {
        let plugin_name = insert_plugin(
            &mut config.plugins,
            &format!("{loc_name}_headers"),
            vec![
                ("category", Value::String("response_headers".to_string())),
                (
                    "set_headers",
                    Value::Array(
                        draft
                            .add_headers
                            .into_iter()
                            .map(Value::String)
                            .collect(),
                    ),
                ),
            ],
        );
        plugins.push(plugin_name);
    }
    if let Some((_status, target)) = draft.redirect {
        let http_to_https = target.starts_with("https://$host");
        let mut entries =
            vec![("category", Value::String("redirect".to_string()))];
        if http_to_https {
            entries.push(("http_to_https", Value::Boolean(true)));
        } else {
            entries.push(("prefix", Value::String(target)));
        }
        let plugin_name = insert_plugin(
            &mut config.plugins,
            &format!("{loc_name}_redirect"),
            entries,
        );
        plugins.push(plugin_name);
    }
    if !plugins.is_empty() {
        draft.loc.plugins = Some(plugins);
    }
    config.locations.insert(loc_name.clone(), draft.loc);
    loc_name
}

fn collect_nginx_server(
    body: &[NginxItem],
    server_idx: usize,
    config: &mut PingapConfig,
    warnings: &mut Vec<String>,
) {
    let mut addrs = Vec::new();
    let mut hosts = Vec::new();
    let mut ssl_cert = None;
    let mut ssl_key = None;
    let mut enable_ssl = false;
    let mut enable_h2 = false;
    let mut loc_blocks = Vec::new();
    let mut default_upstream: Option<String> = None;

    for item in body {
        match item {
            NginxItem::Directive(args) => {
                match args.first().map(String::as_str) {
                    Some("listen") => {
                        let (addr, ssl, h2) = parse_nginx_listen(&args[1..]);
                        enable_ssl |= ssl;
                        enable_h2 |= h2;
                        if !addrs.contains(&addr) {
                            addrs.push(addr);
                        }
                    },
                    Some("http2") => {
                        if args.get(1).is_some_and(|v| v == "on") {
                            enable_h2 = true;
                        }
                    },
                    Some("server_name") => {
                        for host in &args[1..] {
                            if host != "_" && !host.is_empty() {
                                hosts.push(host.clone());
                            }
                        }
                    },
                    Some("ssl_certificate") => ssl_cert = args.get(1).cloned(),
                    Some("ssl_certificate_key") => {
                        ssl_key = args.get(1).cloned()
                    },
                    Some("return") => {
                        let mut draft = NginxLocationDraft::default();
                        draft.loc.path = Some("/".to_string());
                        apply_nginx_location_directive(
                            args,
                            "root_return",
                            &mut draft,
                            config,
                            warnings,
                        );
                        if draft.redirect.is_some() {
                            loc_blocks.push((
                                vec!["location".to_string(), "/".to_string()],
                                vec![NginxItem::Directive(args.clone())],
                            ));
                        }
                    },
                    Some("proxy_pass") => {
                        if let Some(t) = args.get(1) {
                            default_upstream =
                                Some(ensure_proxy_upstream(t, config).0);
                        }
                    },
                    _ => warnings.push(format!(
                        "nginx server[{server_idx}]: skipped directive '{}'",
                        args.join(" ")
                    )),
                }
            },
            NginxItem::Block(head, sub)
                if head.first().map(String::as_str) == Some("location") =>
            {
                loc_blocks.push((head.clone(), sub.clone()));
            },
            NginxItem::Block(head, _) => warnings.push(format!(
                "nginx server[{server_idx}]: skipped block '{}'",
                head.join(" ")
            )),
        }
    }

    let base_server = hosts
        .first()
        .map(|h| sanitize_id(h, "server"))
        .unwrap_or_else(|| format!("server_{server_idx}"));
    let server_name = unique_name(&config.servers, &base_server);
    let host_filter = (!hosts.is_empty()).then(|| hosts.join(","));

    let mut has_tls = false;
    if let (Some(cert), Some(key)) = (ssl_cert, ssl_key) {
        let cert_name = unique_name(&config.certificates, &server_name);
        config.certificates.insert(
            cert_name,
            CertificateConf {
                domains: host_filter.clone(),
                tls_cert: Some(cert),
                tls_key: Some(key),
                ..Default::default()
            },
        );
        has_tls = true;
    } else if enable_ssl {
        warnings.push(format!(
            "nginx server({server_name}): `listen ... ssl` lacks ssl_certificate / ssl_certificate_key"
        ));
    }

    let mut server_locations = Vec::new();
    for (idx, (head, sub)) in loc_blocks.into_iter().enumerate() {
        let selector = parse_nginx_location_selector(&head);
        let mut draft = NginxLocationDraft::default();
        draft.loc.path = Some(selector.clone());
        draft.loc.host.clone_from(&host_filter);
        draft.loc.upstream.clone_from(&default_upstream);
        let candidate_name = format!(
            "{server_name}_{}",
            sanitize_id(&selector, &format!("loc_{idx}"))
        );
        for item in sub {
            match item {
                NginxItem::Directive(args) => apply_nginx_location_directive(
                    &args,
                    &candidate_name,
                    &mut draft,
                    config,
                    warnings,
                ),
                NginxItem::Block(sub_head, _) => warnings.push(format!(
                    "nginx location({candidate_name}): skipped block '{}'",
                    sub_head.join(" ")
                )),
            }
        }
        server_locations.push(finalize_nginx_location(
            &candidate_name,
            draft,
            config,
        ));
    }

    if server_locations.is_empty() && default_upstream.is_some() {
        let mut draft = NginxLocationDraft::default();
        draft.loc.path = Some("/".to_string());
        draft.loc.host = host_filter;
        draft.loc.upstream = default_upstream;
        server_locations.push(finalize_nginx_location(
            &format!("{server_name}_root"),
            draft,
            config,
        ));
    }

    let listen_addr = if addrs.is_empty() {
        if has_tls {
            "0.0.0.0:443".to_string()
        } else {
            "0.0.0.0:80".to_string()
        }
    } else {
        addrs.join(",")
    };
    config.servers.insert(
        server_name,
        ServerConf {
            addr: listen_addr,
            locations: (!server_locations.is_empty())
                .then_some(server_locations),
            global_certificates: has_tls.then_some(true),
            enabled_h2: enable_h2.then_some(true),
            ..Default::default()
        },
    );
}

fn format_import_result(
    config: PingapConfig,
    warnings: Vec<String>,
) -> Result<ImportResult> {
    let servers = config.servers.len();
    let locations = config.locations.len();
    let upstreams = config.upstreams.len();
    let certificates = config.certificates.len();

    let toml_value = PingapTomlConfig::from_pingap_config(&config)?;
    let mut toml = toml::to_string_pretty(&toml_value)
        .map_err(|source| Error::Ser { source })?;
    if !warnings.is_empty() {
        let header: String =
            warnings.iter().map(|w| format!("# TODO: {w}\n")).collect();
        toml = format!("{header}\n{toml}");
    }
    Ok(ImportResult {
        toml,
        warnings,
        servers,
        locations,
        upstreams,
        certificates,
    })
}

/// Translates an Nginx configuration (`nginx.conf` or `conf.d/*.conf`) into a
/// draft Pingap TOML configuration plus conversion warnings.
pub fn convert_nginx_to_toml(input: &str) -> Result<ImportResult> {
    let tokens = tokenize_nginx(input)?;
    let mut pos = 0;
    let ast = parse_nginx_items(&tokens, &mut pos, false)?;

    let mut top_items = Vec::new();
    let mut warnings = Vec::new();
    for item in ast {
        match item {
            NginxItem::Block(head, body)
                if head.first().map(String::as_str) == Some("http") =>
            {
                top_items.extend(body);
            },
            NginxItem::Block(head, _)
                if matches!(
                    head.first().map(String::as_str),
                    Some("events" | "stream")
                ) =>
            {
                warnings.push(format!(
                    "nginx top-level block '{}' skipped",
                    head.join(" ")
                ));
            },
            other => top_items.push(other),
        }
    }

    let mut config = PingapConfig::default();
    let mut server_blocks = Vec::new();
    for item in top_items {
        match item {
            NginxItem::Block(head, body)
                if head.first().map(String::as_str) == Some("upstream") =>
            {
                collect_nginx_upstream(
                    &head,
                    &body,
                    &mut config,
                    &mut warnings,
                );
            },
            NginxItem::Block(head, body)
                if head.first().map(String::as_str) == Some("server") =>
            {
                server_blocks.push(body);
            },
            NginxItem::Block(head, _) => warnings
                .push(format!("nginx block '{}' skipped", head.join(" "))),
            NginxItem::Directive(args) => warnings
                .push(format!("nginx directive '{}' skipped", args.join(" "))),
        }
    }

    for (idx, body) in server_blocks.iter().enumerate() {
        collect_nginx_server(body, idx + 1, &mut config, &mut warnings);
    }

    format_import_result(config, warnings)
}

#[derive(Debug, Clone)]
struct CaddyLine {
    tokens: Vec<String>,
    block: Option<Vec<CaddyLine>>,
}

fn split_caddy_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut chars = line.chars().peekable();
    while let Some(&ch) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }
        if ch == '#' {
            break;
        }
        if ch == '"' || ch == '\'' || ch == '`' {
            let quote = chars.next().unwrap_or(ch);
            let (val, _) = read_quoted_word(&mut chars, quote, quote != '`');
            words.push(val);
            continue;
        }
        if ch == '{' || ch == '}' {
            chars.next();
            words.push(ch.to_string());
            continue;
        }
        let mut word = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_whitespace() || c == '#' || c == '{' || c == '}' {
                break;
            }
            word.push(c);
            chars.next();
        }
        if !word.is_empty() {
            words.push(word);
        }
    }
    words
}

fn parse_caddy_block(
    lines: &[&str],
    idx: &mut usize,
    stop_at_rbrace: bool,
) -> Result<Vec<CaddyLine>> {
    let mut result = Vec::new();
    while *idx < lines.len() {
        let mut tokens = split_caddy_words(lines[*idx]);
        *idx += 1;
        if tokens.is_empty() {
            continue;
        }
        if tokens.first().map(String::as_str) == Some("}") {
            if stop_at_rbrace {
                return Ok(result);
            }
            return Err(Error::Invalid {
                message: "unexpected '}' in Caddyfile".to_string(),
            });
        }
        if tokens.last().map(String::as_str) == Some("{") {
            tokens.pop();
            let block = parse_caddy_block(lines, idx, true)?;
            result.push(CaddyLine {
                tokens,
                block: Some(block),
            });
        } else {
            result.push(CaddyLine {
                tokens,
                block: None,
            });
        }
    }
    if stop_at_rbrace {
        return Err(Error::Invalid {
            message: "unclosed '{' block in Caddyfile".to_string(),
        });
    }
    Ok(result)
}

fn parse_caddy_site_addr(site: &str) -> (Option<String>, Option<u16>, bool) {
    let trimmed = site.trim().trim_end_matches(',');
    let (scheme_tls, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        (Some(true), r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        (Some(false), r)
    } else {
        (None, trimmed)
    };
    let host_port = rest.split('/').next().unwrap_or(rest);
    if let Some(port_only) = host_port.strip_prefix(':') {
        return (None, port_only.parse().ok(), scheme_tls == Some(true));
    }
    if let Some((host, port)) = host_port.rsplit_once(':')
        && let Ok(p) = port.parse::<u16>()
    {
        let wants_tls = scheme_tls.unwrap_or(p != 80);
        return (Some(host.to_string()), Some(p), wants_tls);
    }
    let wants_tls = scheme_tls.unwrap_or(true);
    let host = (!host_port.is_empty()).then(|| host_port.to_string());
    (host, None, wants_tls)
}

#[derive(Default)]
struct CaddySiteDirectives {
    headers: Vec<String>,
    encode: bool,
    redirect: Option<String>,
    static_dir: Option<String>,
    tls_files: Option<(String, String)>,
    tls_off: bool,
    routes: Vec<(String, Option<String>, Vec<String>)>,
}

fn collect_caddy_directive(
    line: &CaddyLine,
    site_name: &str,
    draft: &mut CaddySiteDirectives,
    warnings: &mut Vec<String>,
) {
    let cmd = line.tokens.first().map(String::as_str).unwrap_or_default();
    match cmd {
        "reverse_proxy" => {
            let mut rest = &line.tokens[1..];
            let matcher = rest.first().filter(|t| t.starts_with('/')).cloned();
            if matcher.is_some() {
                rest = &rest[1..];
            }
            let upstreams: Vec<String> = rest
                .iter()
                .filter(|t| !t.starts_with('@'))
                .cloned()
                .collect();
            if !upstreams.is_empty() {
                draft.routes.push((
                    matcher.unwrap_or_else(|| "/".to_string()),
                    None,
                    upstreams,
                ));
            }
        },
        "handle" | "handle_path" => {
            let prefix = line
                .tokens
                .get(1)
                .map(|p| p.trim_end_matches('*').to_string())
                .unwrap_or_else(|| "/".to_string());
            let rewrite = (cmd == "handle_path" && prefix != "/").then(|| {
                let clean = prefix.trim_end_matches('/');
                format!("^{clean}(.*)$ $1")
            });
            if let Some(sub) = &line.block {
                for inner in sub {
                    if inner.tokens.first().map(String::as_str)
                        == Some("reverse_proxy")
                    {
                        let addrs: Vec<String> = inner.tokens[1..]
                            .iter()
                            .filter(|t| !t.starts_with('@'))
                            .cloned()
                            .collect();
                        if !addrs.is_empty() {
                            draft.routes.push((
                                prefix.clone(),
                                rewrite.clone(),
                                addrs,
                            ));
                        }
                    } else {
                        collect_caddy_directive(inner, site_name, draft, warnings);
                    }
                }
            }
        },
        "encode" => draft.encode = true,
        "header" => {
            let args: Vec<&str> = line
                .tokens
                .iter()
                .skip(1)
                .filter(|t| !t.starts_with('@'))
                .map(String::as_str)
                .collect();
            if args.len() >= 2 && !args[0].starts_with(['+', '-']) {
                draft.headers.push(format!("{}: {}", args[0], args[1]));
            } else {
                warnings.push(format!(
                    "caddy site({site_name}): review header '{}'",
                    line.tokens.join(" ")
                ));
            }
        },
        "redir" => {
            if let Some(target) = line.tokens.iter().skip(1).find(|t| !t.starts_with('@')) {
                draft.redirect = Some(target.clone());
            }
        },
        "root" => {
            if let Some(dir) = line.tokens.last() {
                draft.static_dir = Some(dir.clone());
            }
        },
        "file_server" => {},
        "tls" => match (line.tokens.get(1).map(String::as_str), line.tokens.get(2).map(String::as_str)) {
            (Some("off"), _) => draft.tls_off = true,
            (Some("internal"), _) => warnings.push(format!(
                "caddy site({site_name}): `tls internal` skipped (configure custom cert or CA)"
            )),
            (Some(cert), Some(key)) => {
                draft.tls_files = Some((cert.to_string(), key.to_string()));
            },
            _ => {},
        },
        other => warnings.push(format!(
            "caddy site({site_name}): skipped directive '{other}'"
        )),
    }
}

fn build_caddy_site(
    site: &CaddyLine,
    idx: usize,
    config: &mut PingapConfig,
    warnings: &mut Vec<String>,
) {
    let mut hosts = Vec::new();
    let mut port = None;
    let mut wants_tls = false;
    for tok in &site.tokens {
        for part in tok.split(',').filter(|p| !p.trim().is_empty()) {
            let (host, p, tls) = parse_caddy_site_addr(part);
            if let Some(h) = host {
                hosts.push(h);
            }
            if port.is_none() {
                port = p;
            }
            wants_tls |= tls;
        }
    }

    let mut draft = CaddySiteDirectives::default();
    if let Some(block) = &site.block {
        for inner in block {
            collect_caddy_directive(
                inner,
                hosts.first().map(String::as_str).unwrap_or("site"),
                &mut draft,
                warnings,
            );
        }
    }

    let base_name = hosts
        .first()
        .map(|h| sanitize_id(h, "site"))
        .unwrap_or_else(|| format!("site_{}", idx + 1));
    let server_name = unique_name(&config.servers, &base_name);
    let host_filter = (!hosts.is_empty()).then(|| hosts.join(","));

    let has_tls = if let Some((cert, key)) = draft.tls_files {
        let cert_name = unique_name(&config.certificates, &server_name);
        config.certificates.insert(
            cert_name,
            CertificateConf {
                domains: host_filter.clone(),
                tls_cert: Some(cert),
                tls_key: Some(key),
                ..Default::default()
            },
        );
        true
    } else if wants_tls && !draft.tls_off && host_filter.is_some() {
        let cert_name = unique_name(&config.certificates, &server_name);
        config.certificates.insert(
            cert_name,
            CertificateConf {
                domains: host_filter.clone(),
                acme: Some("lets_encrypt".to_string()),
                ..Default::default()
            },
        );
        true
    } else {
        false
    };

    let mut shared_plugins = Vec::new();
    if draft.encode {
        shared_plugins.push(insert_plugin(
            &mut config.plugins,
            &format!("{server_name}_compression"),
            vec![
                ("category", Value::String("compression".to_string())),
                ("gzip_level", Value::Integer(6)),
                ("br_level", Value::Integer(6)),
                ("zstd_level", Value::Integer(3)),
            ],
        ));
    }
    if !draft.headers.is_empty() {
        shared_plugins.push(insert_plugin(
            &mut config.plugins,
            &format!("{server_name}_headers"),
            vec![
                ("category", Value::String("response_headers".to_string())),
                (
                    "set_headers",
                    Value::Array(
                        draft.headers.into_iter().map(Value::String).collect(),
                    ),
                ),
            ],
        ));
    }
    if let Some(target) = draft.redirect {
        let mut entries =
            vec![("category", Value::String("redirect".to_string()))];
        if target.starts_with("https://") {
            entries.push(("http_to_https", Value::Boolean(true)));
        } else {
            entries.push(("prefix", Value::String(target)));
        }
        shared_plugins.push(insert_plugin(
            &mut config.plugins,
            &format!("{server_name}_redirect"),
            entries,
        ));
    }

    let mut server_locations = Vec::new();
    for (r_idx, (path, rewrite, addrs)) in draft.routes.into_iter().enumerate()
    {
        let up_name =
            unique_name(&config.upstreams, &format!("{server_name}_{r_idx}"));
        let formatted_addrs: Vec<String> = addrs
            .into_iter()
            .map(|a| {
                a.strip_prefix("http://")
                    .or_else(|| a.strip_prefix("https://"))
                    .unwrap_or(&a)
                    .to_string()
            })
            .collect();
        config.upstreams.insert(
            up_name.clone(),
            UpstreamConf {
                addrs: formatted_addrs,
                ..Default::default()
            },
        );
        let loc_name = unique_name(
            &config.locations,
            &format!("{server_name}_{}", sanitize_id(&path, "loc")),
        );
        config.locations.insert(
            loc_name.clone(),
            LocationConf {
                path: Some(path),
                host: host_filter.clone(),
                upstream: Some(up_name),
                rewrite,
                enable_reverse_proxy_headers: Some(true),
                plugins: (!shared_plugins.is_empty())
                    .then(|| shared_plugins.clone()),
                ..Default::default()
            },
        );
        server_locations.push(loc_name);
    }

    if server_locations.is_empty()
        && (!shared_plugins.is_empty() || draft.static_dir.is_some())
    {
        if let Some(dir) = draft.static_dir {
            shared_plugins.push(insert_plugin(
                &mut config.plugins,
                &format!("{server_name}_static"),
                vec![
                    ("category", Value::String("directory".to_string())),
                    ("path", Value::String(dir)),
                ],
            ));
        }
        let loc_name = unique_name(&config.locations, &server_name);
        config.locations.insert(
            loc_name.clone(),
            LocationConf {
                path: Some("/".to_string()),
                host: host_filter,
                plugins: Some(shared_plugins),
                ..Default::default()
            },
        );
        server_locations.push(loc_name);
    }

    let listen_port = port.unwrap_or(if has_tls { 443 } else { 80 });
    let grouped = BTreeMap::from([(server_name, server_locations)]);
    for (name, locs) in grouped {
        config.servers.insert(
            name,
            ServerConf {
                addr: format!("0.0.0.0:{listen_port}"),
                locations: (!locs.is_empty()).then_some(locs),
                global_certificates: has_tls.then_some(true),
                enabled_h2: has_tls.then_some(true),
                ..Default::default()
            },
        );
    }
}

/// Translates a `Caddyfile` into a draft Pingap TOML configuration plus
/// conversion warnings.
pub fn convert_caddy_to_toml(input: &str) -> Result<ImportResult> {
    let lines: Vec<&str> = input.lines().collect();
    let mut idx = 0;
    let items = parse_caddy_block(&lines, &mut idx, false)?;

    let mut config = PingapConfig::default();
    let mut warnings = Vec::new();
    for (site_idx, item) in items.iter().enumerate() {
        if item.tokens.is_empty() {
            warnings.push(
                "caddy global options block `{ ... }` skipped".to_string(),
            );
            continue;
        }
        build_caddy_site(item, site_idx, &mut config, &mut warnings);
    }

    format_import_result(config, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_convert_nginx_multi_server_and_warnings() {
        let nginx_conf = r#"
        events { worker_connections 1024; }
        http {
            upstream app_pool {
                server 10.0.0.1:8080 weight=3;
                server 10.0.0.2:8080;
                keepalive 64;
            }
            server {
                listen 443 ssl http2;
                server_name api.example.com www.example.com;
                ssl_certificate /etc/ssl/fullchain.pem;
                ssl_certificate_key /etc/ssl/privkey.pem;

                location = /healthz {
                    proxy_pass http://app_pool;
                    proxy_set_header X-Real-IP $remote_addr;
                    add_header X-Env prod;
                }
                location ^~ /static/ {
                    try_files $uri =404;
                    proxy_pass http://127.0.0.1:9000;
                    client_max_body_size 16m;
                }
            }
        }
        "#;

        let res = convert_nginx_to_toml(nginx_conf).unwrap();
        assert_eq!(1, res.servers);
        assert_eq!(2, res.locations);
        assert_eq!(2, res.upstreams);
        assert_eq!(1, res.certificates);
        assert!(res.warnings.iter().any(|w| w.contains("try_files")));
        assert!(res.toml.contains("# TODO:"));

        let parsed: PingapTomlConfig = toml::from_str(&res.toml).unwrap();
        let cfg = parsed.to_pingap_config(false).unwrap();
        assert_eq!(
            vec!["10.0.0.1:8080 3".to_string(), "10.0.0.2:8080".to_string()],
            cfg.upstreams["app_pool"].addrs
        );
        let srv = cfg.servers.values().next().unwrap();
        assert_eq!("0.0.0.0:443", srv.addr);
        assert_eq!(Some(true), srv.enabled_h2);
        assert_eq!(Some(true), srv.global_certificates);
    }

    #[test]
    fn test_convert_caddy_site_blocks_and_warnings() {
        let caddy = r#"
        {
            email ops@example.com
        }
        app.example.com, www.example.com {
            encode gzip zstd
            header Strict-Transport-Security "max-age=31536000"
            handle_path /api* {
                reverse_proxy 127.0.0.1:3000 127.0.0.1:3001
            }
            handle /web {
                reverse_proxy http://127.0.0.1:4000
            }
            log
        }
        http://legacy.example.com {
            redir https://{host}{uri} permanent
        }
        "#;

        let res = convert_caddy_to_toml(caddy).unwrap();
        assert_eq!(2, res.servers);
        assert_eq!(3, res.locations);
        assert_eq!(2, res.upstreams);
        assert_eq!(1, res.certificates);
        assert!(res.warnings.iter().any(|w| w.contains("global options")));
        assert!(res.warnings.iter().any(|w| w.contains("log")));

        let parsed: PingapTomlConfig = toml::from_str(&res.toml).unwrap();
        let cfg = parsed.to_pingap_config(false).unwrap();
        assert_eq!(
            Some("lets_encrypt".to_string()),
            cfg.certificates.values().next().unwrap().acme
        );
        assert!(
            cfg.locations
                .values()
                .any(|l| { l.rewrite.as_deref() == Some("^/api(.*)$ $1") })
        );
    }
}
