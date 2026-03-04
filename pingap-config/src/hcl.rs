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

use crate::{Error, Result};
use serde_json::Value as JsonValue;
use toml::Value as TomlValue;
use toml::map::Map as TomlMap;

/// Convert a serde_json::Value to a toml::Value.
fn json_to_toml(value: JsonValue) -> Result<TomlValue> {
    match value {
        JsonValue::Null => Ok(TomlValue::String(String::new())),
        JsonValue::Bool(b) => Ok(TomlValue::Boolean(b)),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(TomlValue::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Ok(TomlValue::Float(f))
            } else {
                Err(Error::Invalid {
                    message: format!("unsupported number value: {n}"),
                })
            }
        },
        JsonValue::String(s) => Ok(TomlValue::String(s)),
        JsonValue::Array(arr) => {
            let items: Result<Vec<TomlValue>> =
                arr.into_iter().map(json_to_toml).collect();
            Ok(TomlValue::Array(items?))
        },
        JsonValue::Object(obj) => {
            let mut map = TomlMap::new();
            for (k, v) in obj {
                map.insert(k, json_to_toml(v)?);
            }
            Ok(TomlValue::Table(map))
        },
    }
}

/// Extract only attributes from a body (ignoring nested blocks)
/// and convert to a TOML table via serde_json intermediate.
fn body_attrs_to_toml(body: hcl::Body) -> Result<TomlMap<String, TomlValue>> {
    let attr_body: hcl::Body = body
        .into_iter()
        .filter(|s| matches!(s, hcl::Structure::Attribute(_)))
        .collect();
    let json: JsonValue =
        hcl::from_body(attr_body).map_err(|e| Error::Invalid {
            message: format!("HCL body conversion error: {e}"),
        })?;
    match json_to_toml(json)? {
        TomlValue::Table(t) => Ok(t),
        _ => Ok(TomlMap::new()),
    }
}

/// Insert a named entry into a section table in root.
fn insert_into_section(
    root: &mut TomlMap<String, TomlValue>,
    section_key: &str,
    name: String,
    value: TomlValue,
) {
    let section = root
        .entry(section_key.to_string())
        .or_insert_with(|| TomlValue::Table(TomlMap::new()));
    if let TomlValue::Table(t) = section {
        t.insert(name, value);
    }
}

/// Process a location block body, extracting nested upstream blocks.
///
/// ```hcl
/// location "api" {
///     path = "/api"
///     plugins = ["rate-limit"]
///     upstream "backend" {
///         addrs = ["127.0.0.1:8080"]
///     }
/// }
/// ```
///
/// The nested upstream is extracted to top-level upstreams.
/// If no explicit `upstream = "..."` attribute exists, it is
/// auto-set to the first nested upstream's name.
/// Nested plugin blocks are extracted to top-level plugins,
/// and their names are auto-added to the location's `plugins` list.
struct ParsedLocationBlock {
    location: TomlMap<String, TomlValue>,
    upstreams: TomlMap<String, TomlValue>,
    plugins: TomlMap<String, TomlValue>,
}
fn process_location_block(body: hcl::Body) -> Result<ParsedLocationBlock> {
    let mut upstreams = TomlMap::new();
    let mut plugins = TomlMap::new();
    let mut first_upstream_name: Option<String> = None;
    let mut plugin_names = Vec::new();
    let mut attr_structs = Vec::new();

    for s in body.into_iter() {
        match s {
            hcl::Structure::Block(block) => {
                let ident = block.identifier.as_str();
                match ident {
                    "upstream" | "upstreams" => {
                        if let Some(label) = block.labels.first() {
                            let name = label.as_str().to_string();
                            if first_upstream_name.is_none() {
                                first_upstream_name = Some(name.clone());
                            }
                            let table = body_attrs_to_toml(block.body)?;
                            upstreams.insert(name, TomlValue::Table(table));
                        }
                    },
                    "plugin" | "plugins" => {
                        if let Some(label) = block.labels.first() {
                            let name = label.as_str().to_string();
                            plugin_names.push(name.clone());
                            let table = body_attrs_to_toml(block.body)?;
                            plugins.insert(name, TomlValue::Table(table));
                        }
                    },
                    _ => {},
                }
            },
            attr @ hcl::Structure::Attribute(_) => {
                attr_structs.push(attr);
            },
        }
    }

    let attr_body: hcl::Body = attr_structs.into_iter().collect();
    let json: JsonValue =
        hcl::from_body(attr_body).map_err(|e| Error::Invalid {
            message: format!("HCL location body conversion error: {e}"),
        })?;
    let mut loc_table = match json_to_toml(json)? {
        TomlValue::Table(t) => t,
        _ => TomlMap::new(),
    };

    // Auto-set upstream reference from nested block
    if let Some(name) = first_upstream_name {
        if !loc_table.contains_key("upstream") {
            loc_table.insert("upstream".to_string(), TomlValue::String(name));
        }
    }

    // Auto-populate plugins list from nested plugin blocks
    if !plugin_names.is_empty() {
        let mut all: Vec<String> = loc_table
            .get("plugins")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        for name in plugin_names {
            if !all.contains(&name) {
                all.push(name);
            }
        }
        loc_table.insert(
            "plugins".to_string(),
            TomlValue::Array(all.into_iter().map(TomlValue::String).collect()),
        );
    }

    Ok(ParsedLocationBlock {
        location: loc_table,
        upstreams,
        plugins,
    })
}

/// Process a server block body, extracting nested location blocks
/// (which may themselves contain nested upstream blocks).
///
/// ```hcl
/// server "web" {
///     addr = "0.0.0.0:443"
///     location "api" {
///         path = "/api"
///         upstream "backend" {
///             addrs = ["127.0.0.1:8080"]
///         }
///     }
/// }
/// ```
///
/// Nested locations are extracted to top-level locations.
/// Their names are auto-added to the server's `locations` list.
struct ParsedServerBlock {
    server: TomlMap<String, TomlValue>,
    locations: TomlMap<String, TomlValue>,
    upstreams: TomlMap<String, TomlValue>,
    plugins: TomlMap<String, TomlValue>,
    certificates: TomlMap<String, TomlValue>,
}
fn process_server_block(body: hcl::Body) -> Result<ParsedServerBlock> {
    let mut locations = TomlMap::new();
    let mut upstreams = TomlMap::new();
    let mut plugins = TomlMap::new();
    let mut certificates = TomlMap::new();
    let mut location_names = Vec::new();
    let mut attr_structs = Vec::new();

    for s in body.into_iter() {
        match s {
            hcl::Structure::Block(block) => {
                let ident = block.identifier.as_str();
                match ident {
                    "location" | "locations" => {
                        if let Some(label) = block.labels.first() {
                            let name = label.as_str().to_string();
                            location_names.push(name.clone());
                            let parsed = process_location_block(block.body)?;
                            locations.insert(
                                name,
                                TomlValue::Table(parsed.location),
                            );
                            upstreams.extend(parsed.upstreams);
                            plugins.extend(parsed.plugins);
                        }
                    },
                    "plugin" | "plugins" => {
                        if let Some(label) = block.labels.first() {
                            let name = label.as_str().to_string();
                            let table = body_attrs_to_toml(block.body)?;
                            plugins.insert(name, TomlValue::Table(table));
                        }
                    },
                    "certificate" | "certificates" => {
                        if let Some(label) = block.labels.first() {
                            let name = label.as_str().to_string();
                            let table = body_attrs_to_toml(block.body)?;
                            certificates.insert(name, TomlValue::Table(table));
                        }
                    },
                    _ => {},
                }
            },
            attr @ hcl::Structure::Attribute(_) => {
                attr_structs.push(attr);
            },
        }
    }

    let attr_body: hcl::Body = attr_structs.into_iter().collect();
    let json: JsonValue =
        hcl::from_body(attr_body).map_err(|e| Error::Invalid {
            message: format!("HCL server body conversion error: {e}"),
        })?;
    let mut server = match json_to_toml(json)? {
        TomlValue::Table(t) => t,
        _ => TomlMap::new(),
    };

    // Auto-populate locations list from nested location blocks
    if !location_names.is_empty() {
        let mut all: Vec<String> = server
            .get("locations")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        for name in location_names {
            if !all.contains(&name) {
                all.push(name);
            }
        }
        server.insert(
            "locations".to_string(),
            TomlValue::Array(all.into_iter().map(TomlValue::String).collect()),
        );
    }

    Ok(ParsedServerBlock {
        server,
        locations,
        upstreams,
        plugins,
        certificates,
    })
}

/// Convert HCL configuration text to TOML format string.
///
/// Supports both flat and nested block styles:
///
/// Flat style (same as TOML relationships via string references):
/// ```hcl
/// server "web" {
///     addr = "0.0.0.0:443"
///     locations = ["api"]
/// }
/// upstream "backend" {
///     addrs = ["127.0.0.1:8080"]
/// }
/// location "api" {
///     upstream = "backend"
///     path = "/api"
/// }
/// ```
///
/// Nested style (structural relationships via nesting):
/// ```hcl
/// server "web" {
///     addr = "0.0.0.0:443"
///     location "api" {
///         path = "/api"
///         upstream "backend" {
///             addrs = ["127.0.0.1:8080"]
///         }
///     }
/// }
/// ```
pub fn convert_hcl_to_toml(input: &str) -> Result<String> {
    let body = hcl::parse(input).map_err(|e| Error::Invalid {
        message: format!("HCL parse error: {e}"),
    })?;

    let mut root = TomlMap::new();
    let mut all_locations = TomlMap::new();
    let mut all_upstreams = TomlMap::new();
    let mut all_plugins = TomlMap::new();
    let mut all_certificates = TomlMap::new();

    for structure in body.into_iter() {
        let hcl::Structure::Block(block) = structure else {
            continue;
        };

        let ident = block.identifier.as_str();
        let label = block.labels.first().map(|l| l.as_str().to_string());

        match ident {
            "basic" => {
                let table = body_attrs_to_toml(block.body)?;
                root.insert("basic".to_string(), TomlValue::Table(table));
            },
            "server" | "servers" => {
                let name = label.ok_or_else(|| Error::Invalid {
                    message: "server block requires a name label".to_string(),
                })?;
                let ParsedServerBlock {
                    server,
                    locations,
                    upstreams,
                    plugins,
                    certificates,
                } = process_server_block(block.body)?;
                insert_into_section(
                    &mut root,
                    "servers",
                    name,
                    TomlValue::Table(server),
                );
                all_locations.extend(locations);
                all_upstreams.extend(upstreams);
                all_plugins.extend(plugins);
                all_certificates.extend(certificates);
            },
            "location" | "locations" => {
                let name = label.ok_or_else(|| Error::Invalid {
                    message: "location block requires a name label".to_string(),
                })?;
                let parsed = process_location_block(block.body)?;
                all_locations.insert(name, TomlValue::Table(parsed.location));
                all_upstreams.extend(parsed.upstreams);
                all_plugins.extend(parsed.plugins);
            },
            "upstream" | "upstreams" => {
                let name = label.ok_or_else(|| Error::Invalid {
                    message: "upstream block requires a name label".to_string(),
                })?;
                let table = body_attrs_to_toml(block.body)?;
                all_upstreams.insert(name, TomlValue::Table(table));
            },
            "plugin" | "plugins" => {
                let name = label.ok_or_else(|| Error::Invalid {
                    message: "plugin block requires a name label".to_string(),
                })?;
                let table = body_attrs_to_toml(block.body)?;
                insert_into_section(
                    &mut root,
                    "plugins",
                    name,
                    TomlValue::Table(table),
                );
            },
            "certificate" | "certificates" => {
                let name = label.ok_or_else(|| Error::Invalid {
                    message: "certificate block requires a name label"
                        .to_string(),
                })?;
                let table = body_attrs_to_toml(block.body)?;
                insert_into_section(
                    &mut root,
                    "certificates",
                    name,
                    TomlValue::Table(table),
                );
            },
            "storage" | "storages" => {
                let name = label.ok_or_else(|| Error::Invalid {
                    message: "storage block requires a name label".to_string(),
                })?;
                let table = body_attrs_to_toml(block.body)?;
                insert_into_section(
                    &mut root,
                    "storages",
                    name,
                    TomlValue::Table(table),
                );
            },
            _ => {
                return Err(Error::Invalid {
                    message: format!("unknown HCL block type: {ident}"),
                });
            },
        }
    }

    if !all_locations.is_empty() {
        root.insert("locations".to_string(), TomlValue::Table(all_locations));
    }
    if !all_upstreams.is_empty() {
        root.insert("upstreams".to_string(), TomlValue::Table(all_upstreams));
    }
    if !all_plugins.is_empty() {
        let section = root
            .entry("plugins".to_string())
            .or_insert_with(|| TomlValue::Table(TomlMap::new()));
        if let TomlValue::Table(t) = section {
            t.extend(all_plugins);
        }
    }
    if !all_certificates.is_empty() {
        let section = root
            .entry("certificates".to_string())
            .or_insert_with(|| TomlValue::Table(TomlMap::new()));
        if let TomlValue::Table(t) = section {
            t.extend(all_certificates);
        }
    }

    toml::to_string_pretty(&root).map_err(|e| Error::Ser { source: e })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::convert_pingap_config;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_flat_hcl() {
        let hcl_input = r#"
basic {
    name = "pingap"
    threads = 4
}

server "web" {
    addr = "0.0.0.0:6188"
    locations = ["api", "static"]
}

upstream "backend" {
    addrs = ["127.0.0.1:8080", "127.0.0.1:8081"]
    connection_timeout = "30s"
}

location "api" {
    upstream = "backend"
    path = "/api"
    plugins = ["rate-limit"]
}

location "static" {
    upstream = "backend"
    path = "/"
}

plugin "rate-limit" {
    category = "limit"
    step = "request"
}

certificate "default" {
    domains = "example.com"
}

storage "shared" {
    category = "kv"
    value = "test_data"
}
"#;

        let toml_str = convert_hcl_to_toml(hcl_input).unwrap();
        let config = convert_pingap_config(toml_str.as_bytes(), false).unwrap();

        assert_eq!("pingap", config.basic.name.unwrap());
        assert_eq!(4, config.basic.threads.unwrap());

        let server = config.servers.get("web").unwrap();
        assert_eq!("0.0.0.0:6188", server.addr);
        assert_eq!(
            vec!["api", "static"],
            server.locations.as_ref().unwrap().clone()
        );

        let upstream = config.upstreams.get("backend").unwrap();
        assert_eq!(vec!["127.0.0.1:8080", "127.0.0.1:8081"], upstream.addrs);
        assert_eq!(
            Some(std::time::Duration::from_secs(30)),
            upstream.connection_timeout
        );

        let loc = config.locations.get("api").unwrap();
        assert_eq!("backend", loc.upstream.as_ref().unwrap());
        assert_eq!("/api", loc.path.as_ref().unwrap());
        assert_eq!(vec!["rate-limit"], loc.plugins.as_ref().unwrap().clone());

        let plugin = config.plugins.get("rate-limit").unwrap();
        assert_eq!("limit", plugin.get("category").unwrap().as_str().unwrap());

        let cert = config.certificates.get("default").unwrap();
        assert_eq!("example.com", cert.domains.as_ref().unwrap());

        let storage = config.storages.get("shared").unwrap();
        assert_eq!("kv", storage.category);
    }

    #[test]
    fn test_nested_hcl() {
        let hcl_input = r#"
basic {
    name = "pingap"
}

server "web" {
    addr = "0.0.0.0:6188"

    location "api" {
        path = "/api"
        plugins = ["rate-limit"]

        upstream "backend" {
            addrs = ["127.0.0.1:8080"]
            connection_timeout = "30s"
        }
    }

    location "static" {
        path = "/"
        upstream = "backend"
    }
}

plugin "rate-limit" {
    category = "limit"
    step = "request"
}
"#;

        let toml_str = convert_hcl_to_toml(hcl_input).unwrap();
        let config = convert_pingap_config(toml_str.as_bytes(), false).unwrap();

        // server auto-populated locations from nested blocks
        let server = config.servers.get("web").unwrap();
        assert_eq!("0.0.0.0:6188", server.addr);
        let locations = server.locations.as_ref().unwrap();
        assert_eq!(true, locations.contains(&"api".to_string()));
        assert_eq!(true, locations.contains(&"static".to_string()));

        // location "api" auto-set upstream from nested block
        let loc_api = config.locations.get("api").unwrap();
        assert_eq!("backend", loc_api.upstream.as_ref().unwrap());
        assert_eq!("/api", loc_api.path.as_ref().unwrap());
        assert_eq!(
            vec!["rate-limit"],
            loc_api.plugins.as_ref().unwrap().clone()
        );

        // location "static" keeps explicit upstream attribute
        let loc_static = config.locations.get("static").unwrap();
        assert_eq!("backend", loc_static.upstream.as_ref().unwrap());

        // nested upstream extracted to top-level
        let upstream = config.upstreams.get("backend").unwrap();
        assert_eq!(vec!["127.0.0.1:8080"], upstream.addrs);
        assert_eq!(
            Some(std::time::Duration::from_secs(30)),
            upstream.connection_timeout
        );

        // top-level plugin still works
        let plugin = config.plugins.get("rate-limit").unwrap();
        assert_eq!("limit", plugin.get("category").unwrap().as_str().unwrap());
    }

    #[test]
    fn test_nested_with_explicit_upstream_attr() {
        // Both explicit upstream = "..." and nested upstream block
        let hcl_input = r#"
server "web" {
    addr = "0.0.0.0:6188"

    location "api" {
        path = "/api"
        upstream = "my-backend"

        upstream "my-backend" {
            addrs = ["127.0.0.1:8080"]
        }
    }
}
"#;

        let toml_str = convert_hcl_to_toml(hcl_input).unwrap();
        let config = convert_pingap_config(toml_str.as_bytes(), false).unwrap();

        let loc = config.locations.get("api").unwrap();
        assert_eq!("my-backend", loc.upstream.as_ref().unwrap());

        let upstream = config.upstreams.get("my-backend").unwrap();
        assert_eq!(vec!["127.0.0.1:8080"], upstream.addrs);
    }

    #[test]
    fn test_multiple_servers_nested() {
        let hcl_input = r#"
server "web" {
    addr = "0.0.0.0:443"
    location "api" {
        path = "/api"
        upstream "backend" {
            addrs = ["127.0.0.1:8080"]
        }
    }
}

server "admin" {
    addr = "0.0.0.0:8443"
    location "admin-panel" {
        path = "/admin"
        upstream "admin-backend" {
            addrs = ["127.0.0.1:9090"]
        }
    }
}
"#;

        let toml_str = convert_hcl_to_toml(hcl_input).unwrap();
        let config = convert_pingap_config(toml_str.as_bytes(), false).unwrap();

        assert_eq!(2, config.servers.len());
        assert_eq!(2, config.locations.len());
        assert_eq!(2, config.upstreams.len());

        let web = config.servers.get("web").unwrap();
        assert_eq!(vec!["api"], web.locations.as_ref().unwrap().clone());

        let admin = config.servers.get("admin").unwrap();
        assert_eq!(
            vec!["admin-panel"],
            admin.locations.as_ref().unwrap().clone()
        );

        assert_eq!(
            "backend",
            config
                .locations
                .get("api")
                .unwrap()
                .upstream
                .as_ref()
                .unwrap()
        );
        assert_eq!(
            "admin-backend",
            config
                .locations
                .get("admin-panel")
                .unwrap()
                .upstream
                .as_ref()
                .unwrap()
        );
    }

    #[test]
    fn test_nested_certificate_and_plugin() {
        let hcl_input = r#"
server "web" {
    addr = "0.0.0.0:443"

    location "api" {
        path = "/api"
        upstream "backend" {
            addrs = ["127.0.0.1:8080"]
        }
        plugin "rate-limit" {
            category = "limit"
            step = "request"
        }
    }

    certificate "default" {
        domains = "example.com"
        tls_cert = "cert.pem"
        tls_key = "key.pem"
    }

    plugin "server-auth" {
        category = "auth"
        step = "request"
    }
}

plugin "global-compress" {
    category = "compression"
    step = "response"
}
"#;

        let toml_str = convert_hcl_to_toml(hcl_input).unwrap();
        let config = convert_pingap_config(toml_str.as_bytes(), false).unwrap();

        // server has location auto-populated
        let server = config.servers.get("web").unwrap();
        assert_eq!(vec!["api"], server.locations.as_ref().unwrap().clone());

        // location's plugins list auto-populated from nested plugin block
        let loc = config.locations.get("api").unwrap();
        assert_eq!("backend", loc.upstream.as_ref().unwrap());
        assert_eq!(vec!["rate-limit"], loc.plugins.as_ref().unwrap().clone());

        // nested certificate extracted to top-level
        let cert = config.certificates.get("default").unwrap();
        assert_eq!("example.com", cert.domains.as_ref().unwrap());
        assert_eq!("cert.pem", cert.tls_cert.as_ref().unwrap());
        assert_eq!("key.pem", cert.tls_key.as_ref().unwrap());

        // nested plugin from location extracted to top-level
        let plugin = config.plugins.get("rate-limit").unwrap();
        assert_eq!("limit", plugin.get("category").unwrap().as_str().unwrap());

        // nested plugin from server extracted to top-level
        let server_plugin = config.plugins.get("server-auth").unwrap();
        assert_eq!(
            "auth",
            server_plugin.get("category").unwrap().as_str().unwrap()
        );

        // top-level plugin also works
        let global_plugin = config.plugins.get("global-compress").unwrap();
        assert_eq!(
            "compression",
            global_plugin.get("category").unwrap().as_str().unwrap()
        );

        // upstream extracted from nested location
        let upstream = config.upstreams.get("backend").unwrap();
        assert_eq!(vec!["127.0.0.1:8080"], upstream.addrs);
    }

    #[test]
    fn test_nested_plugin_in_location_only() {
        let hcl_input = r#"
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
"#;

        let toml_str = convert_hcl_to_toml(hcl_input).unwrap();
        let config = convert_pingap_config(toml_str.as_bytes(), false).unwrap();

        // server auto-populated locations
        let server = config.servers.get("test").unwrap();
        assert_eq!(
            vec!["github-api", "static"],
            server.locations.as_ref().unwrap().clone()
        );

        // location "github-api" auto-set upstream
        let loc_api = config.locations.get("github-api").unwrap();
        assert_eq!("api", loc_api.upstream.as_ref().unwrap());
        assert_eq!("/api", loc_api.path.as_ref().unwrap());

        // location "static" auto-populated plugins from nested plugin block
        let loc_static = config.locations.get("static").unwrap();
        assert_eq!(
            vec!["staticServe"],
            loc_static.plugins.as_ref().unwrap().clone()
        );

        // nested plugin extracted to top-level
        let plugin = config.plugins.get("staticServe").unwrap();
        assert_eq!(
            "directory",
            plugin.get("category").unwrap().as_str().unwrap()
        );
        assert_eq!(
            "~/Downloads",
            plugin.get("path").unwrap().as_str().unwrap()
        );
        assert_eq!("request", plugin.get("step").unwrap().as_str().unwrap());

        // nested upstream extracted to top-level
        let upstream = config.upstreams.get("api").unwrap();
        assert_eq!(vec!["api.github.com:443"], upstream.addrs);
    }

    #[test]
    fn test_unknown_block() {
        let hcl_input = r#"
unknown_block "test" {
    key = "value"
}
"#;
        let result = convert_hcl_to_toml(hcl_input);
        assert_eq!(true, result.is_err());
        assert_eq!(
            true,
            result
                .unwrap_err()
                .to_string()
                .contains("unknown HCL block type")
        );
    }

    #[test]
    fn test_json_to_toml() {
        let v = json_to_toml(JsonValue::String("hello".to_string())).unwrap();
        assert_eq!(TomlValue::String("hello".to_string()), v);

        let v = json_to_toml(JsonValue::Number(42.into())).unwrap();
        assert_eq!(TomlValue::Integer(42), v);

        let v = json_to_toml(JsonValue::Bool(true)).unwrap();
        assert_eq!(TomlValue::Boolean(true), v);

        let v = json_to_toml(JsonValue::Null).unwrap();
        assert_eq!(TomlValue::String(String::new()), v);

        let v = json_to_toml(serde_json::json!(["a", "b"])).unwrap();
        assert_eq!(
            TomlValue::Array(vec![
                TomlValue::String("a".to_string()),
                TomlValue::String("b".to_string()),
            ]),
            v
        );
    }
}
