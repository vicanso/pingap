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
use std::collections::HashSet;
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
    if let Some(name) = first_upstream_name
        && !loc_table.contains_key("upstream")
    {
        loc_table.insert("upstream".to_string(), TomlValue::String(name));
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

/// Convert a TOML value to its HCL attribute value representation.
fn toml_value_to_hcl(value: &TomlValue) -> String {
    match value {
        TomlValue::String(s) => {
            let escaped = s
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
                .replace('\r', "\\r")
                .replace('\t', "\\t");
            format!("\"{escaped}\"")
        },
        TomlValue::Integer(i) => i.to_string(),
        TomlValue::Float(f) => f.to_string(),
        TomlValue::Boolean(b) => b.to_string(),
        TomlValue::Datetime(dt) => format!("\"{dt}\""),
        TomlValue::Array(arr) => {
            let items: Vec<String> =
                arr.iter().map(toml_value_to_hcl).collect();
            format!("[{}]", items.join(", "))
        },
        TomlValue::Table(_) => "{}".to_string(),
    }
}

fn hcl_indent(indent: usize) -> String {
    "    ".repeat(indent)
}

/// Write an HCL attribute (key = value) at the given indentation level.
/// Multiline strings use heredoc (`<<-EOT ... EOT`) for readability.
fn write_hcl_attr(
    output: &mut String,
    key: &str,
    value: &TomlValue,
    indent: usize,
) {
    output.push_str(&hcl_indent(indent));
    output.push_str(key);
    output.push_str(" = ");

    if let TomlValue::String(s) = value
        && s.contains('\n')
    {
        let inner = hcl_indent(indent + 1);
        output.push_str("<<-EOT\n");
        for line in s.lines() {
            output.push_str(&inner);
            output.push_str(line);
            output.push('\n');
        }
        output.push_str(&inner);
        output.push_str("EOT\n");
        return;
    }

    output.push_str(&toml_value_to_hcl(value));
    output.push('\n');
}

/// Write a named HCL block containing only attributes (no nested blocks).
fn write_named_block(
    output: &mut String,
    block_type: &str,
    label: Option<&str>,
    table: &TomlMap<String, TomlValue>,
    indent: usize,
) {
    let prefix = hcl_indent(indent);
    match label {
        Some(l) => {
            output.push_str(&format!("{prefix}{block_type} \"{l}\" {{\n"))
        },
        None => output.push_str(&format!("{prefix}{block_type} {{\n")),
    }
    for (key, value) in table {
        write_hcl_attr(output, key, value, indent + 1);
    }
    output.push_str(&format!("{prefix}}}\n"));
}

struct EmbedContext<'a> {
    upstreams: &'a TomlMap<String, TomlValue>,
    plugins: &'a TomlMap<String, TomlValue>,
    embedded_upstreams: &'a mut HashSet<String>,
    embedded_plugins: &'a mut HashSet<String>,
}

/// Write a location block, embedding upstream and plugin blocks where
/// possible. Upstreams are embedded if not already claimed by another
/// location. Plugins use all-or-nothing embedding per location to
/// preserve ordering on round-trip.
fn write_location_hcl(
    output: &mut String,
    name: &str,
    loc_table: &TomlMap<String, TomlValue>,
    ctx: &mut EmbedContext,
    indent: usize,
) {
    let prefix = hcl_indent(indent);

    let mut skip_upstream = false;
    let mut upstream_block: Option<String> = None;
    if let Some(upstream_name) =
        loc_table.get("upstream").and_then(|v| v.as_str())
        && !ctx.embedded_upstreams.contains(upstream_name)
        && let Some(up_table) =
            ctx.upstreams.get(upstream_name).and_then(|v| v.as_table())
    {
        ctx.embedded_upstreams.insert(upstream_name.to_string());
        skip_upstream = true;
        let mut block = String::new();
        write_named_block(
            &mut block,
            "upstream",
            Some(upstream_name),
            up_table,
            indent + 1,
        );
        upstream_block = Some(block);
    }

    let mut plugin_blocks = Vec::new();
    let mut skip_plugins = false;
    if let Some(plugin_arr) =
        loc_table.get("plugins").and_then(|v| v.as_array())
    {
        let plugin_names: Vec<&str> =
            plugin_arr.iter().filter_map(|v| v.as_str()).collect();
        let can_embed_all = !plugin_names.is_empty()
            && plugin_names.iter().all(|item| {
                !ctx.embedded_plugins.contains(*item)
                    && ctx.plugins.contains_key(*item)
            });
        if can_embed_all {
            skip_plugins = true;
            for plugin_name in &plugin_names {
                ctx.embedded_plugins.insert(plugin_name.to_string());
                if let Some(p_table) =
                    ctx.plugins.get(*plugin_name).and_then(|v| v.as_table())
                {
                    let mut block = String::new();
                    write_named_block(
                        &mut block,
                        "plugin",
                        Some(plugin_name),
                        p_table,
                        indent + 1,
                    );
                    plugin_blocks.push(block);
                }
            }
        }
    }

    output.push_str(&format!("{prefix}location \"{name}\" {{\n"));

    for (key, value) in loc_table {
        if key == "upstream" && skip_upstream {
            continue;
        }
        if key == "plugins" && skip_plugins {
            continue;
        }
        write_hcl_attr(output, key, value, indent + 1);
    }

    if let Some(block) = upstream_block {
        output.push('\n');
        output.push_str(&block);
    }
    for block in plugin_blocks {
        output.push('\n');
        output.push_str(&block);
    }

    output.push_str(&format!("{prefix}}}\n"));
}

/// Convert TOML configuration text to HCL format with nested/embedded
/// blocks.
///
/// The output uses a nested block style where:
/// - Locations are embedded inside their server blocks
/// - Upstreams are embedded inside location blocks (first reference)
/// - Plugins are embedded inside location blocks (first reference)
/// - Certificates and storages remain at the top level
///
/// ```text
/// basic {
///     name = "pingap"
/// }
///
/// server "web" {
///     addr = "0.0.0.0:6188"
///
///     location "api" {
///         path = "/api"
///
///         upstream "backend" {
///             addrs = ["127.0.0.1:8080"]
///         }
///     }
/// }
/// ```
/// Parse a TOML string into a TomlValue table, falling back through
/// PingapConfig round-trip when the raw string contains syntax that
/// the generic Value deserializer cannot handle (e.g. multiline basic
/// strings, literal strings with quotes).
fn parse_toml_to_value(input: &str) -> Result<TomlValue> {
    toml::from_str::<TomlValue>(input).or_else(|_| {
        let config = crate::convert_pingap_config(input.as_bytes(), false)?;
        let json_value =
            serde_json::to_value(&config).map_err(|e| Error::Invalid {
                message: format!("JSON serialization error: {e}"),
            })?;
        json_to_toml(json_value)
    })
}

pub fn convert_toml_to_hcl(input: &str) -> Result<String> {
    let value = parse_toml_to_value(input)?;
    let empty_table = TomlMap::new();
    let root = value.as_table().unwrap_or(&empty_table);

    let mut output = String::new();
    let mut embedded_upstreams = HashSet::new();
    let mut embedded_plugins = HashSet::new();
    let mut embedded_locations = HashSet::new();

    let servers = root
        .get("servers")
        .and_then(|v| v.as_table())
        .unwrap_or(&empty_table);
    let locations_map = root
        .get("locations")
        .and_then(|v| v.as_table())
        .unwrap_or(&empty_table);
    let upstreams_map = root
        .get("upstreams")
        .and_then(|v| v.as_table())
        .unwrap_or(&empty_table);
    let plugins_map = root
        .get("plugins")
        .and_then(|v| v.as_table())
        .unwrap_or(&empty_table);
    let certificates = root
        .get("certificates")
        .and_then(|v| v.as_table())
        .unwrap_or(&empty_table);
    let storages = root
        .get("storages")
        .and_then(|v| v.as_table())
        .unwrap_or(&empty_table);

    // Basic block
    if let Some(basic) = root.get("basic").and_then(|v| v.as_table())
        && !basic.is_empty()
    {
        write_named_block(&mut output, "basic", None, basic, 0);
        output.push('\n');
    }

    // Server blocks with embedded locations
    for (server_name, server_value) in servers {
        if let Some(server_table) = server_value.as_table() {
            output.push_str(&format!("server \"{server_name}\" {{\n"));

            let location_names: Vec<String> = server_table
                .get("locations")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            for (key, value) in server_table {
                if key == "locations" {
                    continue;
                }
                write_hcl_attr(&mut output, key, value, 1);
            }

            for loc_name in &location_names {
                if let Some(loc_table) =
                    locations_map.get(loc_name).and_then(|v| v.as_table())
                {
                    embedded_locations.insert(loc_name.clone());
                    output.push('\n');
                    write_location_hcl(
                        &mut output,
                        loc_name,
                        loc_table,
                        &mut EmbedContext {
                            upstreams: upstreams_map,
                            plugins: plugins_map,
                            embedded_upstreams: &mut embedded_upstreams,
                            embedded_plugins: &mut embedded_plugins,
                        },
                        1,
                    );
                }
            }

            output.push_str("}\n\n");
        }
    }

    // Un-embedded locations
    for (loc_name, loc_value) in locations_map {
        if embedded_locations.contains(loc_name) {
            continue;
        }
        if let Some(loc_table) = loc_value.as_table() {
            write_location_hcl(
                &mut output,
                loc_name,
                loc_table,
                &mut EmbedContext {
                    upstreams: upstreams_map,
                    plugins: plugins_map,
                    embedded_upstreams: &mut embedded_upstreams,
                    embedded_plugins: &mut embedded_plugins,
                },
                0,
            );
            output.push('\n');
        }
    }

    // Un-embedded upstreams
    for (name, value) in upstreams_map {
        if embedded_upstreams.contains(name) {
            continue;
        }
        if let Some(table) = value.as_table() {
            write_named_block(&mut output, "upstream", Some(name), table, 0);
            output.push('\n');
        }
    }

    // Un-embedded plugins
    for (name, value) in plugins_map {
        if embedded_plugins.contains(name) {
            continue;
        }
        if let Some(table) = value.as_table() {
            write_named_block(&mut output, "plugin", Some(name), table, 0);
            output.push('\n');
        }
    }

    // Certificates
    for (name, value) in certificates {
        if let Some(table) = value.as_table() {
            write_named_block(&mut output, "certificate", Some(name), table, 0);
            output.push('\n');
        }
    }

    // Storages
    for (name, value) in storages {
        if let Some(table) = value.as_table() {
            write_named_block(&mut output, "storage", Some(name), table, 0);
            output.push('\n');
        }
    }

    Ok(output.trim_end().to_string() + "\n")
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

    #[test]
    fn test_toml_to_hcl_roundtrip() {
        let toml_input = r#"
[basic]
name = "pingap"
threads = 4

[servers.web]
addr = "0.0.0.0:6188"
locations = ["api", "static"]

[locations.api]
path = "/api"
plugins = ["rate-limit"]
upstream = "backend"

[locations.static]
path = "/"
upstream = "backend"

[upstreams.backend]
addrs = ["127.0.0.1:8080", "127.0.0.1:8081"]
connection_timeout = "30s"

[plugins.rate-limit]
category = "limit"
step = "request"

[certificates.default]
domains = "example.com"

[storages.shared]
category = "kv"
value = "test_data"
"#;

        let hcl_output = convert_toml_to_hcl(toml_input).unwrap();
        let toml_roundtrip = convert_hcl_to_toml(&hcl_output).unwrap();
        let config =
            convert_pingap_config(toml_roundtrip.as_bytes(), false).unwrap();

        assert_eq!("pingap", config.basic.name.unwrap());
        assert_eq!(4, config.basic.threads.unwrap());

        let server = config.servers.get("web").unwrap();
        assert_eq!("0.0.0.0:6188", server.addr);
        let locations = server.locations.as_ref().unwrap();
        assert_eq!(true, locations.contains(&"api".to_string()));
        assert_eq!(true, locations.contains(&"static".to_string()));

        let loc_api = config.locations.get("api").unwrap();
        assert_eq!("backend", loc_api.upstream.as_ref().unwrap());
        assert_eq!("/api", loc_api.path.as_ref().unwrap());
        assert_eq!(
            true,
            loc_api
                .plugins
                .as_ref()
                .unwrap()
                .contains(&"rate-limit".to_string())
        );

        let loc_static = config.locations.get("static").unwrap();
        assert_eq!("backend", loc_static.upstream.as_ref().unwrap());

        let upstream = config.upstreams.get("backend").unwrap();
        assert_eq!(vec!["127.0.0.1:8080", "127.0.0.1:8081"], upstream.addrs);
        assert_eq!(
            Some(std::time::Duration::from_secs(30)),
            upstream.connection_timeout
        );

        let plugin = config.plugins.get("rate-limit").unwrap();
        assert_eq!("limit", plugin.get("category").unwrap().as_str().unwrap());

        let cert = config.certificates.get("default").unwrap();
        assert_eq!("example.com", cert.domains.as_ref().unwrap());

        let storage = config.storages.get("shared").unwrap();
        assert_eq!("kv", storage.category);
    }

    #[test]
    fn test_toml_to_hcl_multiple_servers() {
        let toml_input = r#"
[servers.web]
addr = "0.0.0.0:443"
locations = ["api"]

[servers.admin]
addr = "0.0.0.0:8443"
locations = ["admin-panel"]

[locations.api]
path = "/api"
upstream = "backend"

[locations.admin-panel]
path = "/admin"
upstream = "admin-backend"

[upstreams.backend]
addrs = ["127.0.0.1:8080"]

[upstreams.admin-backend]
addrs = ["127.0.0.1:9090"]
"#;

        let hcl_output = convert_toml_to_hcl(toml_input).unwrap();
        let toml_roundtrip = convert_hcl_to_toml(&hcl_output).unwrap();
        let config =
            convert_pingap_config(toml_roundtrip.as_bytes(), false).unwrap();

        assert_eq!(2, config.servers.len());
        assert_eq!(2, config.locations.len());
        assert_eq!(2, config.upstreams.len());

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
    fn test_toml_to_hcl_embedded_plugins() {
        let toml_input = r#"
[servers.web]
addr = "0.0.0.0:443"
locations = ["api"]

[locations.api]
path = "/api"
plugins = ["rate-limit", "cache"]
upstream = "backend"

[upstreams.backend]
addrs = ["127.0.0.1:8080"]

[plugins.rate-limit]
category = "limit"
step = "request"

[plugins.cache]
category = "cache"
step = "request"
"#;

        let hcl_output = convert_toml_to_hcl(toml_input).unwrap();
        let toml_roundtrip = convert_hcl_to_toml(&hcl_output).unwrap();
        let config =
            convert_pingap_config(toml_roundtrip.as_bytes(), false).unwrap();

        let loc = config.locations.get("api").unwrap();
        let plugins = loc.plugins.as_ref().unwrap();
        assert_eq!(true, plugins.contains(&"rate-limit".to_string()));
        assert_eq!(true, plugins.contains(&"cache".to_string()));

        assert_eq!(true, config.plugins.contains_key("rate-limit"));
        assert_eq!(true, config.plugins.contains_key("cache"));
    }

    #[test]
    fn test_toml_to_hcl_shared_upstream() {
        let toml_input = r#"
[servers.web]
addr = "0.0.0.0:443"
locations = ["api", "static"]

[locations.api]
path = "/api"
upstream = "backend"

[locations.static]
path = "/"
upstream = "backend"

[upstreams.backend]
addrs = ["127.0.0.1:8080"]
"#;

        let hcl_output = convert_toml_to_hcl(toml_input).unwrap();

        // "backend" is embedded in "api" (first reference),
        // "static" keeps `upstream = "backend"` as attribute
        assert_eq!(true, hcl_output.contains("upstream \"backend\""));
        assert_eq!(true, hcl_output.contains("upstream = \"backend\""));

        let toml_roundtrip = convert_hcl_to_toml(&hcl_output).unwrap();
        let config =
            convert_pingap_config(toml_roundtrip.as_bytes(), false).unwrap();

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
            "backend",
            config
                .locations
                .get("static")
                .unwrap()
                .upstream
                .as_ref()
                .unwrap()
        );
        assert_eq!(1, config.upstreams.len());
    }

    #[test]
    fn test_toml_to_hcl_value_types() {
        assert_eq!(
            "\"hello\"",
            toml_value_to_hcl(&TomlValue::String("hello".to_string()))
        );
        assert_eq!("42", toml_value_to_hcl(&TomlValue::Integer(42)));
        assert_eq!("true", toml_value_to_hcl(&TomlValue::Boolean(true)));
        assert_eq!(
            "[\"a\", \"b\"]",
            toml_value_to_hcl(&TomlValue::Array(vec![
                TomlValue::String("a".to_string()),
                TomlValue::String("b".to_string()),
            ]))
        );
        assert_eq!(
            "\"line1\\nline2\"",
            toml_value_to_hcl(&TomlValue::String("line1\nline2".to_string()))
        );
        assert_eq!(
            "\"say \\\"hi\\\"\"",
            toml_value_to_hcl(&TomlValue::String("say \"hi\"".to_string()))
        );
    }

    #[test]
    fn test_toml_to_hcl_real_config() {
        let toml_input = r##"[basic]
auto_restart_check_interval = "2m"
error_template = ""
grace_period = "1m"
graceful_shutdown_timeout = "20s"
log_buffered_size = "4.0 KiB"
log_compress_algorithm = "zstd"
log_compress_days_ago = 3
log_compress_level = 15
log_compress_time_point_hour = 2
log_level = "INFO"
name = "charts"
upstream_keepalive_pool_size = 16
webhook = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=6f2aaf3c-6642-49c1-a1c9-616fb60ad0f3"
webhook_notifications = [
    "upstream_status",
    "lets_encrypt",
    "reload_config",
    "reload_config_fail",
    "parse_certificate_fail",
    "tls_validity",
    "service_discover_fail",
]
webhook_type = "wecom"

[certificates.npmtrend]
acme = "lets_encrypt"
buffer_days = 10
dns_challenge = true
dns_provider = "ali"
dns_service_url = "$ENV:PINGAP_DNS_SERVICE_URL"
domains = "*.npmtrend.com,npmtrend.com"
is_default = true
tls_cert = """

"""
tls_key = """

"""

[locations.cybertect]
host = "cybertect.npmtrend.com"
path = ""
plugins = [
    "commonCache",
    "commonResponseHeaders",
]
rewrite = ""
upstream = "tibba-web"

[locations.cybertect-api]
enable_reverse_proxy_headers = true
host = "cybertect.npmtrend.com"
path = "/api/"
plugins = [
    "commonCache",
    "commonResponseHeaders",
    "pingap:acceptEncodingAdjustment",
]
rewrite = "^/api"
upstream = "tibba"

[locations.http2https]
plugins = ["http2https"]

[locations.npmtrend]
enable_reverse_proxy_headers = true
host = "~(?<upstream>.+).npmtrend.com"
max_retries = 1
max_retry_window = "1s"
path = "/"
plugins = [
    "pingap:stats",
    "customAdmin",
    "commonCache",
    "commonResponseHeaders",
]
upstream = "$upstream"

[plugins.commonCache]
category = "cache"
check_cache_control = true
directory = "/opt/pingap/cache?levels=2&inactive=7d"
eviction = false
headers = [
    "Host",
    "Accept-Encoding",
]
lock = "3s"
max_file_size = "1MB"
max_ttl = "7d"
predictor = true
remark = "通用缓存，缓存key添加了Host"

[plugins.commonResponseHeaders]
category = "response_headers"
remark = "通用的响应头"
set_headers = ["X-Server:$hostname"]

[plugins.customAdmin]
authorizations = ["dHJlZXhpZTpwd2Q0dHJlZXhpZQ=="]
category = "admin"
ip_fail_limit = 0
max_age = "30d"
path = "/pingap"
step = "request"

[plugins.http2https]
category = "redirect"
http_to_https = true
prefix = ""
remark = "将http重定向至https"
step = "request"

[servers.http80]
addr = "0.0.0.0:80"
locations = ["http2https"]

[servers.pingap]
access_log = '/opt/pingap/access_logs?flush_timeout=10s {when} {remote} "{method} {uri} {proto}" {status} {size_human} {latency_human} "{referer}" "{user_agent}" "tls:{:tls_version}-{:tls_cipher}-{:tls_handshake_time}" "{:connection_time} {:connection_reused}" {:upstream_addr}'
addr = "0.0.0.0:443"
enable_server_timing = true
enabled_h2 = true
global_certificates = true
locations = [
    "npmtrend",
    "cybertect",
    "cybertect-api",
]
otlp_exporter = "http://100.100.22.113:4317/?timeout=10s&max_queue_size=1000&scheduled_delay=10s&max_export_batch_size=100&max_export_timeout=10s&max_attributes=100&max_events=100"
prometheus_metrics = "http://n150:9091/metrics/job/pingap"
tcp_idle = "5m"
tcp_interval = "30s"
tcp_probe_count = 3
tcp_user_timeout = "30s"
tls_max_version = "tlsv1.3"
tls_min_version = "tlsv1.1"

[upstreams.charts]
addrs = [
    "tree:6107 10",
    "tx:6107 5",
]
discovery = "dns"
enable_backend_stats = true
enable_tracer = true
health_check = "http://charts/ping"
idle_timeout = "2m"
ipv4_only = true
update_frequency = "1m"

[upstreams.mermaid]
addrs = ["tx:6051"]
discovery = "dns"
ipv4_only = true
update_frequency = "1m"

[upstreams.tibba]
addrs = [
    "tx:6021",
    "tree:6021",
]
discovery = "dns"
enable_backend_stats = true
health_check = "http://n150:6021/ping"
ipv4_only = true
update_frequency = "1m"

[upstreams.tibba-web]
addrs = ["tx:6020"]
discovery = "dns"
enable_backend_stats = true
health_check = "http://tibba-web/health"
ipv4_only = true
update_frequency = "1m"
"##;

        let hcl_output = convert_toml_to_hcl(toml_input).unwrap();

        // Also test via PingapConfig serialization round-trip
        let config_orig =
            convert_pingap_config(toml_input.as_bytes(), false).unwrap();
        let pretty_toml = toml::to_string_pretty(&config_orig).unwrap();
        let hcl_from_pretty = convert_toml_to_hcl(&pretty_toml).unwrap();
        assert_eq!(false, hcl_from_pretty.is_empty());

        // Verify round-trip
        let toml_roundtrip = convert_hcl_to_toml(&hcl_output).unwrap();
        let config =
            convert_pingap_config(toml_roundtrip.as_bytes(), false).unwrap();

        assert_eq!("charts", config.basic.name.unwrap());
        assert_eq!(2, config.servers.len());
        assert_eq!(4, config.upstreams.len());
        assert_eq!(4, config.locations.len());

        let server_pingap = config.servers.get("pingap").unwrap();
        assert_eq!("0.0.0.0:443", server_pingap.addr);
        let locs = server_pingap.locations.as_ref().unwrap();
        assert_eq!(true, locs.contains(&"npmtrend".to_string()));
        assert_eq!(true, locs.contains(&"cybertect".to_string()));
        assert_eq!(true, locs.contains(&"cybertect-api".to_string()));

        let server_http = config.servers.get("http80").unwrap();
        assert_eq!("0.0.0.0:80", server_http.addr);

        let cert = config.certificates.get("npmtrend").unwrap();
        assert_eq!(
            "*.npmtrend.com,npmtrend.com",
            cert.domains.as_ref().unwrap()
        );

        let loc_cybertect = config.locations.get("cybertect").unwrap();
        assert_eq!("tibba-web", loc_cybertect.upstream.as_ref().unwrap());
        let loc_npmtrend = config.locations.get("npmtrend").unwrap();
        assert_eq!("$upstream", loc_npmtrend.upstream.as_ref().unwrap());

        assert_eq!(true, config.upstreams.contains_key("charts"));
        assert_eq!(true, config.upstreams.contains_key("mermaid"));
        assert_eq!(true, config.upstreams.contains_key("tibba"));
        assert_eq!(true, config.upstreams.contains_key("tibba-web"));

        assert_eq!(true, config.plugins.contains_key("commonCache"));
        assert_eq!(true, config.plugins.contains_key("http2https"));
        assert_eq!(true, config.plugins.contains_key("customAdmin"));
    }

    #[test]
    fn test_multiline_heredoc_roundtrip() {
        let tls_key = "-----BEGIN EC PRIVATE KEY-----\nAAAAAAAAAABBBBBBBBBBBBBBBCCCCCCCCCCCCCCCDDDDDDDDDD\nEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFGGGGGGGGGGGGGGGGHH\n-----END EC PRIVATE KEY-----\n";
        let tls_cert = "-----BEGIN CERTIFICATE-----\nAAAAAAAAAAAABBBBBBBBBBBBBBCCCCCCCCCCCCCCDDDDDDDDDD\n-----END CERTIFICATE-----\n";

        let toml_input = format!(
            r#"[certificates.test]
domains = "example.com"
tls_cert = {tls_cert:?}
tls_key = {tls_key:?}
"#
        );

        let hcl_output = convert_toml_to_hcl(&toml_input).unwrap();

        // Should use heredoc, not escaped \n
        assert_eq!(true, hcl_output.contains("<<-EOT"));
        assert_eq!(true, hcl_output.contains("-----BEGIN EC PRIVATE KEY-----"));
        assert_eq!(false, hcl_output.contains("\\n"));

        // Round-trip back to TOML and verify
        let toml_roundtrip = convert_hcl_to_toml(&hcl_output).unwrap();
        let config =
            convert_pingap_config(toml_roundtrip.as_bytes(), false).unwrap();

        let cert = config.certificates.get("test").unwrap();
        assert_eq!("example.com", cert.domains.as_ref().unwrap());
        assert_eq!(tls_key.trim(), cert.tls_key.as_ref().unwrap().trim());
        assert_eq!(tls_cert.trim(), cert.tls_cert.as_ref().unwrap().trim());
    }

    #[test]
    fn test_hcl_heredoc_parse() {
        let hcl_input = r#"
certificate "test" {
    domains = "example.com"
    tls_key = <<-EOT
        -----BEGIN EC PRIVATE KEY-----
        AAAAAAAAAAAABBBBBBBBBBBBBBCCCCCCCCCCCCCCDDDDDDDDDD
        -----END EC PRIVATE KEY-----
        EOT
}
"#;

        let toml_str = convert_hcl_to_toml(hcl_input).unwrap();
        let config = convert_pingap_config(toml_str.as_bytes(), false).unwrap();

        let cert = config.certificates.get("test").unwrap();
        assert_eq!("example.com", cert.domains.as_ref().unwrap());
        let key = cert.tls_key.as_ref().unwrap();
        assert_eq!(true, key.contains("-----BEGIN EC PRIVATE KEY-----"));
        assert_eq!(true, key.contains("-----END EC PRIVATE KEY-----"));
    }

    #[test]
    fn test_parse_toml_to_value_fallback() {
        let toml_input = r#"
[basic]
name = "test"

[servers.web]
addr = "0.0.0.0:80"
locations = ["home"]

[locations.home]
path = "/"
upstream = "backend"

[upstreams.backend]
addrs = ["127.0.0.1:3000"]
"#;
        // The direct path should work fine
        let val = parse_toml_to_value(toml_input).unwrap();
        assert_eq!(true, val.as_table().is_some());

        // Verify the full conversion works
        let hcl = convert_toml_to_hcl(toml_input).unwrap();
        let toml_back = convert_hcl_to_toml(&hcl).unwrap();
        let config =
            convert_pingap_config(toml_back.as_bytes(), false).unwrap();
        assert_eq!("test", config.basic.name.unwrap());
    }
}
