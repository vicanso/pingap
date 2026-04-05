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
use kdl::{KdlDocument, KdlNode, KdlValue};
use toml::Value as TomlValue;
use toml::map::Map as TomlMap;
use tracing::warn;

/// Fields that are always TOML arrays in pingap configs, even with a single value.
fn is_always_list(field: &str) -> bool {
    matches!(
        field,
        "addrs"
            | "locations"
            | "plugins"
            | "includes"
            | "modules"
            | "proxy_set_headers"
            | "proxy_add_headers"
            | "webhook_notifications"
    )
}

/// Collect all positional args of a node into a TOML array.
fn collect_args_as_array(node: &KdlNode) -> TomlValue {
    let items: Vec<TomlValue> = node
        .entries()
        .iter()
        .filter(|e| e.name().is_none())
        .map(|e| kdl_value_to_toml(e.value()))
        .collect();
    TomlValue::Array(items)
}

/// Insert `value` into `map` under `key`, with merge semantics:
///
/// - If the existing value is an Array, the new value (or its elements if
///   also an Array) are **appended** rather than overwriting. This supports
///   the common KDL pattern of multiple same-name nodes for a list:
///   ```kdl
///   addrs "127.0.0.1:8080"
///   addrs "127.0.0.1:8081"
///   ```
/// - Otherwise (existing scalar or no existing value) the new value wins.
fn map_insert_or_append(
    map: &mut TomlMap<String, TomlValue>,
    key: String,
    value: TomlValue,
) {
    if let Some(TomlValue::Array(existing)) = map.get_mut(&key) {
        match value {
            TomlValue::Array(new_items) => existing.extend(new_items),
            other => existing.push(other),
        }
    } else {
        map.insert(key, value);
    }
}

/// Convert a KdlValue to a TomlValue.
fn kdl_value_to_toml(value: &KdlValue) -> TomlValue {
    match value {
        KdlValue::String(s) => TomlValue::String(s.clone()),
        KdlValue::Integer(i) => TomlValue::Integer(*i as i64),
        KdlValue::Float(f) => TomlValue::Float(*f),
        KdlValue::Bool(b) => TomlValue::Boolean(*b),
        KdlValue::Null => TomlValue::String(String::new()),
    }
}

/// Get the first positional argument from a node as a String (used as item name).
fn get_node_name_arg(node: &KdlNode) -> Result<String> {
    node.entries()
        .iter()
        .find(|e| e.name().is_none())
        .map(|e| match e.value() {
            KdlValue::String(s) => s.clone(),
            KdlValue::Integer(i) => i.to_string(),
            KdlValue::Float(f) => f.to_string(),
            KdlValue::Bool(b) => b.to_string(),
            KdlValue::Null => String::new(),
        })
        .ok_or_else(|| Error::Invalid {
            message: format!(
                "'{}' node requires a name as first argument",
                node.name().value()
            ),
        })
}

/// Convert a child property node to a TOML value:
/// - No args/props/children → empty string
/// - Has children, all named `item` → Array of Tables (matches `write_kdl_property` output)
/// - Has children (mixed/other) → recursive table
/// - Single positional arg → scalar
/// - Multiple positional args → array
/// - Named props only → table
fn child_node_to_toml(node: &KdlNode) -> Result<TomlValue> {
    if let Some(children) = node.children() {
        let nodes = children.nodes();
        // All-`item` children → Array of Tables (produced by write_kdl_property for table arrays)
        if !nodes.is_empty() && nodes.iter().all(|n| n.name().value() == "item")
        {
            let arr: Result<Vec<TomlValue>> = nodes
                .iter()
                .map(|item_node| {
                    Ok(TomlValue::Table(node_to_toml_map(item_node)?))
                })
                .collect();
            return Ok(TomlValue::Array(arr?));
        }
        return Ok(TomlValue::Table(node_to_toml_map(node)?));
    }

    let positional: Vec<TomlValue> = node
        .entries()
        .iter()
        .filter(|e| e.name().is_none())
        .map(|e| kdl_value_to_toml(e.value()))
        .collect();

    let named: TomlMap<String, TomlValue> = node
        .entries()
        .iter()
        .filter_map(|e| {
            e.name()
                .map(|n| (n.value().to_string(), kdl_value_to_toml(e.value())))
        })
        .collect();

    if positional.is_empty() && named.is_empty() {
        return Ok(TomlValue::String(String::new()));
    }
    if positional.is_empty() {
        return Ok(TomlValue::Table(named));
    }
    if positional.len() == 1 {
        Ok(positional
            .into_iter()
            .next()
            .unwrap_or(TomlValue::String(String::new())))
    } else {
        Ok(TomlValue::Array(positional))
    }
}

/// Convert a node's inline named properties + child nodes to a TOML map.
/// Inline positional args (the item name) are ignored; named props are included.
///
/// Inline named properties work without a child block:
/// `upstream "backend" health_check="http://..." sni="api.example.com"`
///
/// Known list fields are wrapped in a TOML array even when specified inline:
/// `location "api" plugins="rate-limit"` → `plugins = ["rate-limit"]`
fn node_to_toml_map(node: &KdlNode) -> Result<TomlMap<String, TomlValue>> {
    let mut map = TomlMap::new();

    // Inline named properties (e.g., `upstream "name" health_check="http://..."`)
    // Known list fields are wrapped in a single-element array.
    for entry in node.entries() {
        if let Some(key) = entry.name() {
            let key_str = key.value().to_string();
            let val = if is_always_list(&key_str) {
                TomlValue::Array(vec![kdl_value_to_toml(entry.value())])
            } else {
                kdl_value_to_toml(entry.value())
            };
            map.insert(key_str, val);
        }
    }

    if let Some(children) = node.children() {
        for child in children.nodes() {
            let key = child.name().value().to_string();
            // Known array fields always produce a TOML array, even with one value.
            // map_insert_or_append handles same-name duplicate nodes by appending.
            let value = if is_always_list(&key) && child.children().is_none() {
                let discarded: Vec<&str> = child
                    .entries()
                    .iter()
                    .filter_map(|e| e.name().map(|n| n.value()))
                    .collect();
                if !discarded.is_empty() {
                    warn!(
                        field = key,
                        discarded = discarded.join(", "),
                        "KDL list field has named properties that will be ignored; \
                         only positional arguments are collected into the array"
                    );
                }
                collect_args_as_array(child)
            } else {
                child_node_to_toml(child)?
            };
            map_insert_or_append(&mut map, key, value);
        }
    }

    Ok(map)
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

struct ParsedLocationNode {
    location: TomlMap<String, TomlValue>,
    upstreams: TomlMap<String, TomlValue>,
    plugins: TomlMap<String, TomlValue>,
}

/// Process a location node, extracting nested upstream/plugin blocks.
///
/// ```kdl
/// location "api" {
///     path "/api"
///     plugins "rate-limit"
///     upstream "backend" {
///         addrs "127.0.0.1:8080"
///     }
/// }
/// ```
///
/// Nested upstreams are extracted to top-level upstreams.
/// If no explicit `upstream "..."` child exists, auto-set from nested block name.
/// Nested plugin blocks are extracted to top-level plugins.
fn process_location_node(node: &KdlNode) -> Result<ParsedLocationNode> {
    let mut upstreams = TomlMap::new();
    let mut plugins = TomlMap::new();
    let mut first_upstream_name: Option<String> = None;
    let mut plugin_names: Vec<String> = Vec::new();
    let mut loc_map = TomlMap::new();

    // Inline named properties (skip positional = item name)
    for entry in node.entries() {
        if let Some(key) = entry.name() {
            let key_str = key.value().to_string();
            let val = if is_always_list(&key_str) {
                TomlValue::Array(vec![kdl_value_to_toml(entry.value())])
            } else {
                kdl_value_to_toml(entry.value())
            };
            loc_map.insert(key_str, val);
        }
    }

    if let Some(children) = node.children() {
        for child in children.nodes() {
            let child_name = child.name().value();
            match child_name {
                "upstream" | "upstreams" => {
                    if child.children().is_some() {
                        // Nested upstream block with its own attrs
                        let up_name = get_node_name_arg(child)?;
                        if first_upstream_name.is_none() {
                            first_upstream_name = Some(up_name.clone());
                        }
                        upstreams.insert(
                            up_name,
                            TomlValue::Table(node_to_toml_map(child)?),
                        );
                    } else {
                        // Reference: `upstream "backend"`
                        loc_map.insert(
                            child_name.to_string(),
                            child_node_to_toml(child)?,
                        );
                    }
                },
                "plugin" | "plugins" => {
                    // A plugin *definition* has either a child block OR inline named
                    // properties (key=value). A plain reference list has only
                    // positional args: `plugins "rate-limit" "auth"`.
                    let is_definition = child.children().is_some()
                        || child.entries().iter().any(|e| e.name().is_some());
                    if is_definition {
                        let plug_name = get_node_name_arg(child)?;
                        plugin_names.push(plug_name.clone());
                        plugins.insert(
                            plug_name,
                            TomlValue::Table(node_to_toml_map(child)?),
                        );
                    } else {
                        // Plugin reference list: `plugins "rate-limit" "auth"`
                        loc_map.insert(
                            "plugins".to_string(),
                            collect_args_as_array(child),
                        );
                    }
                },
                _ => {
                    let key = child_name.to_string();
                    let value = if is_always_list(child_name)
                        && child.children().is_none()
                    {
                        collect_args_as_array(child)
                    } else {
                        child_node_to_toml(child)?
                    };
                    map_insert_or_append(&mut loc_map, key, value);
                },
            }
        }
    }

    // Auto-set upstream reference from nested block
    if let Some(up_name) = first_upstream_name
        && !loc_map.contains_key("upstream")
    {
        loc_map.insert("upstream".to_string(), TomlValue::String(up_name));
    }

    // Auto-populate plugins list from nested plugin blocks
    if !plugin_names.is_empty() {
        let mut all: Vec<String> = loc_map
            .get("plugins")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        for pname in plugin_names {
            if !all.contains(&pname) {
                all.push(pname);
            }
        }
        loc_map.insert(
            "plugins".to_string(),
            TomlValue::Array(all.into_iter().map(TomlValue::String).collect()),
        );
    }

    Ok(ParsedLocationNode {
        location: loc_map,
        upstreams,
        plugins,
    })
}

struct ParsedServerNode {
    server: TomlMap<String, TomlValue>,
    locations: TomlMap<String, TomlValue>,
    upstreams: TomlMap<String, TomlValue>,
    plugins: TomlMap<String, TomlValue>,
    certificates: TomlMap<String, TomlValue>,
}

/// Process a server node, extracting nested location/plugin/certificate blocks.
///
/// ```kdl
/// server "web" {
///     addr "0.0.0.0:443"
///     location "api" {
///         path "/api"
///         upstream "backend" {
///             addrs "127.0.0.1:8080"
///         }
///     }
/// }
/// ```
///
/// Nested locations are extracted to top-level and auto-added to `locations` list.
fn process_server_node(node: &KdlNode) -> Result<ParsedServerNode> {
    let mut locations = TomlMap::new();
    let mut upstreams = TomlMap::new();
    let mut plugins = TomlMap::new();
    let mut certificates = TomlMap::new();
    let mut location_names: Vec<String> = Vec::new();
    let mut server_map = TomlMap::new();

    // Inline named properties
    for entry in node.entries() {
        if let Some(key) = entry.name() {
            let key_str = key.value().to_string();
            let val = if is_always_list(&key_str) {
                TomlValue::Array(vec![kdl_value_to_toml(entry.value())])
            } else {
                kdl_value_to_toml(entry.value())
            };
            server_map.insert(key_str, val);
        }
    }

    if let Some(children) = node.children() {
        for child in children.nodes() {
            let child_name = child.name().value();
            match child_name {
                "location" | "locations" => {
                    if child.children().is_some() {
                        let loc_name = get_node_name_arg(child)?;
                        location_names.push(loc_name.clone());
                        let parsed = process_location_node(child)?;
                        locations.insert(
                            loc_name,
                            TomlValue::Table(parsed.location),
                        );
                        upstreams.extend(parsed.upstreams);
                        plugins.extend(parsed.plugins);
                    } else {
                        // Locations reference list: `locations "api" "static"` → always array
                        server_map.insert(
                            "locations".to_string(),
                            collect_args_as_array(child),
                        );
                    }
                },
                "plugin" | "plugins" => {
                    let is_definition = child.children().is_some()
                        || child.entries().iter().any(|e| e.name().is_some());
                    if is_definition {
                        let plug_name = get_node_name_arg(child)?;
                        plugins.insert(
                            plug_name,
                            TomlValue::Table(node_to_toml_map(child)?),
                        );
                    } else {
                        server_map.insert(
                            "plugins".to_string(),
                            collect_args_as_array(child),
                        );
                    }
                },
                "certificate" | "certificates" => {
                    if child.children().is_some() {
                        let cert_name = get_node_name_arg(child)?;
                        certificates.insert(
                            cert_name,
                            TomlValue::Table(node_to_toml_map(child)?),
                        );
                    } else {
                        server_map.insert(
                            child_name.to_string(),
                            child_node_to_toml(child)?,
                        );
                    }
                },
                _ => {
                    let key = child_name.to_string();
                    let value = if is_always_list(child_name)
                        && child.children().is_none()
                    {
                        collect_args_as_array(child)
                    } else {
                        child_node_to_toml(child)?
                    };
                    map_insert_or_append(&mut server_map, key, value);
                },
            }
        }
    }

    // Auto-populate locations list from nested location blocks
    if !location_names.is_empty() {
        let mut all: Vec<String> = server_map
            .get("locations")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        for lname in location_names {
            if !all.contains(&lname) {
                all.push(lname);
            }
        }
        server_map.insert(
            "locations".to_string(),
            TomlValue::Array(all.into_iter().map(TomlValue::String).collect()),
        );
    }

    Ok(ParsedServerNode {
        server: server_map,
        locations,
        upstreams,
        plugins,
        certificates,
    })
}

/// Convert KDL configuration text to TOML format string.
///
/// Supports both flat and nested block styles:
///
/// Flat style:
/// ```kdl
/// server "web" {
///     addr "0.0.0.0:443"
///     locations "api"
/// }
/// upstream "backend" {
///     addrs "127.0.0.1:8080" "127.0.0.1:8081"
/// }
/// location "api" {
///     upstream "backend"
///     path "/api"
/// }
/// ```
///
/// Nested style:
/// ```kdl
/// server "web" {
///     addr "0.0.0.0:443"
///     location "api" {
///         path "/api"
///         upstream "backend" {
///             addrs "127.0.0.1:8080"
///         }
///     }
/// }
/// ```
pub fn convert_kdl_to_toml(input: &str) -> Result<String> {
    let doc: KdlDocument = input.parse().map_err(|e| Error::Invalid {
        message: format!("KDL parse error: {e}"),
    })?;

    let mut root = TomlMap::new();
    let mut all_locations = TomlMap::new();
    let mut all_upstreams = TomlMap::new();
    let mut all_plugins = TomlMap::new();
    let mut all_certificates = TomlMap::new();

    for node in doc.nodes() {
        let node_type = node.name().value();

        match node_type {
            "basic" => {
                let table = node_to_toml_map(node)?;
                root.insert("basic".to_string(), TomlValue::Table(table));
            },
            "server" | "servers" => {
                let name = get_node_name_arg(node)?;
                let ParsedServerNode {
                    server,
                    locations,
                    upstreams,
                    plugins,
                    certificates,
                } = process_server_node(node)?;
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
                let name = get_node_name_arg(node)?;
                let parsed = process_location_node(node)?;
                all_locations.insert(name, TomlValue::Table(parsed.location));
                all_upstreams.extend(parsed.upstreams);
                all_plugins.extend(parsed.plugins);
            },
            "upstream" | "upstreams" => {
                let name = get_node_name_arg(node)?;
                let table = node_to_toml_map(node)?;
                all_upstreams.insert(name, TomlValue::Table(table));
            },
            "plugin" | "plugins" => {
                let name = get_node_name_arg(node)?;
                let table = node_to_toml_map(node)?;
                insert_into_section(
                    &mut root,
                    "plugins",
                    name,
                    TomlValue::Table(table),
                );
            },
            "certificate" | "certificates" => {
                let name = get_node_name_arg(node)?;
                let table = node_to_toml_map(node)?;
                insert_into_section(
                    &mut root,
                    "certificates",
                    name,
                    TomlValue::Table(table),
                );
            },
            "storage" | "storages" => {
                let name = get_node_name_arg(node)?;
                let table = node_to_toml_map(node)?;
                insert_into_section(
                    &mut root,
                    "storages",
                    name,
                    TomlValue::Table(table),
                );
            },
            _ => {
                return Err(Error::Invalid {
                    message: format!("unknown KDL node type: {node_type}"),
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

// ── TOML → KDL ──────────────────────────────────────────────────────────────

fn kdl_escape_string(s: &str) -> String {
    let escaped = s
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t");
    format!("\"{escaped}\"")
}

/// Render a single TOML value as a KDL argument token.
/// Arrays are rendered as space-separated tokens (for child nodes).
fn toml_value_to_kdl_arg(value: &TomlValue) -> String {
    match value {
        TomlValue::String(s) => kdl_escape_string(s),
        TomlValue::Integer(i) => i.to_string(),
        TomlValue::Float(f) => f.to_string(),
        TomlValue::Boolean(b) => format!("#{b}"), // KDL v2: #true / #false
        TomlValue::Datetime(dt) => kdl_escape_string(&dt.to_string()),
        TomlValue::Array(arr) => arr
            .iter()
            .map(toml_value_to_kdl_arg)
            .collect::<Vec<_>>()
            .join(" "),
        // Tables must be handled by write_kdl_property, never rendered inline.
        // Reaching here means a table appeared inside a scalar-only context
        // (e.g., a mixed array), which is a caller bug.
        TomlValue::Table(_) => {
            unreachable!(
                "TomlValue::Table should never be passed to toml_value_to_kdl_arg; \
                 use write_kdl_property for table values"
            )
        },
    }
}

fn kdl_indent(n: usize) -> String {
    "    ".repeat(n)
}

/// Write one TOML key-value pair as a KDL child node at the given indent.
fn write_kdl_property(
    out: &mut String,
    key: &str,
    value: &TomlValue,
    indent: usize,
) {
    let pad = kdl_indent(indent);
    match value {
        TomlValue::Table(t) => {
            out.push_str(&format!("{pad}{key} {{\n"));
            for (k, v) in t {
                write_kdl_property(out, k, v, indent + 1);
            }
            out.push_str(&format!("{pad}}}\n"));
        },
        TomlValue::Array(arr) => {
            if arr.iter().any(|v| matches!(v, TomlValue::Table(_))) {
                // Array of inline tables → each Table becomes an `item { }` child block.
                // This preserves all data without silently dropping nested structure.
                // KDL syntax: `key { item { k1 v1; k2 v2 }  item { ... } }`
                out.push_str(&format!("{pad}{key} {{\n"));
                for elem in arr {
                    match elem {
                        TomlValue::Table(t) => {
                            out.push_str(&format!(
                                "{}item {{\n",
                                kdl_indent(indent + 1)
                            ));
                            for (k, v) in t {
                                write_kdl_property(out, k, v, indent + 2);
                            }
                            out.push_str(&format!(
                                "{}}}\n",
                                kdl_indent(indent + 1)
                            ));
                        },
                        other => {
                            // Scalar mixed into a table array (unusual in TOML, but valid)
                            out.push_str(&format!(
                                "{}item {}\n",
                                kdl_indent(indent + 1),
                                toml_value_to_kdl_arg(other)
                            ));
                        },
                    }
                }
                out.push_str(&format!("{pad}}}\n"));
            } else {
                // Homogeneous scalar array → space-separated args on one line
                let items: Vec<String> =
                    arr.iter().map(toml_value_to_kdl_arg).collect();
                out.push_str(&format!("{pad}{key} {}\n", items.join(" ")));
            }
        },
        _ => {
            out.push_str(&format!(
                "{pad}{key} {}\n",
                toml_value_to_kdl_arg(value)
            ));
        },
    }
}

/// Write a named section entry (e.g., `upstream "backend" { ... }`) to `out`.
fn write_kdl_section(
    out: &mut String,
    node_type: &str,
    name: &str,
    value: &TomlValue,
) {
    out.push_str(&format!("{node_type} {} {{\n", kdl_escape_string(name)));
    if let TomlValue::Table(t) = value {
        for (k, v) in t {
            write_kdl_property(out, k, v, 1);
        }
    }
    out.push_str("}\n\n");
}

/// Convert a TOML configuration string to KDL format.
///
/// The output uses a flat per-item style:
/// ```kdl
/// upstream "backend" {
///     addrs "127.0.0.1:8080" "127.0.0.1:8081"
///     health_check "http://backend/health"
/// }
/// ```
pub fn convert_toml_to_kdl(input: &str) -> Result<String> {
    let value: TomlValue =
        toml::from_str(input).map_err(|e| Error::De { source: e })?;
    let TomlValue::Table(root) = value else {
        return Err(Error::Invalid {
            message: "expected TOML root table".to_string(),
        });
    };

    let mut out = String::new();

    // basic
    if let Some(TomlValue::Table(basic)) = root.get("basic") {
        out.push_str("basic {\n");
        for (k, v) in basic {
            write_kdl_property(&mut out, k, v, 1);
        }
        out.push_str("}\n\n");
    }

    for (section, node_type) in [
        ("upstreams", "upstream"),
        ("locations", "location"),
        ("servers", "server"),
        ("plugins", "plugin"),
        ("certificates", "certificate"),
        ("storages", "storage"),
    ] {
        if let Some(TomlValue::Table(items)) = root.get(section) {
            for (name, value) in items {
                write_kdl_section(&mut out, node_type, name, value);
            }
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_basic_flat_kdl_to_toml() {
        let kdl_input = r#"
upstream "backend" {
    addrs "127.0.0.1:8080" "127.0.0.1:8081"
    health_check "http://backend/health?connection_timeout=3s"
}

location "api" {
    upstream "backend"
    path "/api"
}

server "web" {
    addr "0.0.0.0:3000"
    locations "api"
}
"#;
        let toml_str = convert_kdl_to_toml(kdl_input).unwrap();
        let value: toml::Value = toml::from_str(&toml_str).unwrap();
        let root = value.as_table().unwrap();

        let upstream = &root["upstreams"]["backend"];
        let addrs = upstream["addrs"].as_array().unwrap();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0].as_str().unwrap(), "127.0.0.1:8080");

        let location = &root["locations"]["api"];
        assert_eq!(location["upstream"].as_str().unwrap(), "backend");
        assert_eq!(location["path"].as_str().unwrap(), "/api");

        let server = &root["servers"]["web"];
        assert_eq!(server["addr"].as_str().unwrap(), "0.0.0.0:3000");
        let locs = server["locations"].as_array().unwrap();
        assert_eq!(locs[0].as_str().unwrap(), "api");
    }

    #[test]
    fn test_basic_section_kdl_to_toml() {
        let kdl_input = r#"
basic {
    worker_threads 4
    daemon #true
    grace_period "10s"
}
"#;
        let toml_str = convert_kdl_to_toml(kdl_input).unwrap();
        let value: toml::Value = toml::from_str(&toml_str).unwrap();
        let basic = &value["basic"];
        assert_eq!(basic["worker_threads"].as_integer().unwrap(), 4);
        assert_eq!(basic["daemon"].as_bool().unwrap(), true);
        assert_eq!(basic["grace_period"].as_str().unwrap(), "10s");
    }

    #[test]
    fn test_nested_server_location_upstream() {
        let kdl_input = r#"
server "web" {
    addr "0.0.0.0:3000"
    location "api" {
        path "/api"
        upstream "backend" {
            addrs "127.0.0.1:8080"
        }
    }
}
"#;
        let toml_str = convert_kdl_to_toml(kdl_input).unwrap();
        let value: toml::Value = toml::from_str(&toml_str).unwrap();
        let root = value.as_table().unwrap();

        // Server has locations list
        let server = &root["servers"]["web"];
        let locs = server["locations"].as_array().unwrap();
        assert_eq!(locs[0].as_str().unwrap(), "api");

        // Location has auto-set upstream ref
        let loc = &root["locations"]["api"];
        assert_eq!(loc["upstream"].as_str().unwrap(), "backend");

        // Upstream was extracted to top-level
        let up = &root["upstreams"]["backend"];
        let addrs = up["addrs"].as_array().unwrap();
        assert_eq!(addrs[0].as_str().unwrap(), "127.0.0.1:8080");
    }

    #[test]
    fn test_inline_properties() {
        let kdl_input = r#"
upstream "backend" health_check="http://backend/health" {
    addrs "127.0.0.1:8080"
}
"#;
        let toml_str = convert_kdl_to_toml(kdl_input).unwrap();
        let value: toml::Value = toml::from_str(&toml_str).unwrap();
        let up = &value["upstreams"]["backend"];
        assert_eq!(
            up["health_check"].as_str().unwrap(),
            "http://backend/health"
        );
        assert_eq!(
            up["addrs"].as_array().unwrap()[0].as_str().unwrap(),
            "127.0.0.1:8080"
        );
    }

    #[test]
    fn test_duplicate_same_name_nodes_appended() {
        // Multiple same-name nodes should be merged into one array, not overwritten
        let kdl_input = r#"
upstream "backend" {
    addrs "127.0.0.1:8080"
    addrs "127.0.0.1:8081"
    addrs "127.0.0.1:8082"
}
"#;
        let toml_str = convert_kdl_to_toml(kdl_input).unwrap();
        let value: toml::Value = toml::from_str(&toml_str).unwrap();
        let addrs = value["upstreams"]["backend"]["addrs"].as_array().unwrap();
        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[0].as_str().unwrap(), "127.0.0.1:8080");
        assert_eq!(addrs[1].as_str().unwrap(), "127.0.0.1:8081");
        assert_eq!(addrs[2].as_str().unwrap(), "127.0.0.1:8082");
    }

    #[test]
    fn test_mixed_bulk_and_single_addrs() {
        // Mix of multi-value and single-value addrs nodes
        let kdl_input = r#"
upstream "backend" {
    addrs "127.0.0.1:8080" "127.0.0.1:8081"
    addrs "127.0.0.1:8082"
}
"#;
        let toml_str = convert_kdl_to_toml(kdl_input).unwrap();
        let value: toml::Value = toml::from_str(&toml_str).unwrap();
        let addrs = value["upstreams"]["backend"]["addrs"].as_array().unwrap();
        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[2].as_str().unwrap(), "127.0.0.1:8082");
    }

    #[test]
    fn test_inline_plugin_definition() {
        // Plugin defined fully inline (no {} block) inside a location
        let kdl_input = r#"
location "static" {
    plugin "staticServe" category="directory" path="~/Downloads" step="request"
}
"#;
        let toml_str = convert_kdl_to_toml(kdl_input).unwrap();
        let value: toml::Value = toml::from_str(&toml_str).unwrap();
        let root = value.as_table().unwrap();

        // Plugin should appear in top-level plugins
        let plugin = &root["plugins"]["staticServe"];
        assert_eq!(plugin["category"].as_str().unwrap(), "directory");
        assert_eq!(plugin["path"].as_str().unwrap(), "~/Downloads");
        assert_eq!(plugin["step"].as_str().unwrap(), "request");

        // Location's plugins list should reference the plugin
        let loc = &root["locations"]["static"];
        let plugin_list = loc["plugins"].as_array().unwrap();
        assert_eq!(plugin_list[0].as_str().unwrap(), "staticServe");
    }

    #[test]
    fn test_fully_inline_no_block() {
        // All scalar properties on one line, no child block needed
        let kdl_input = r#"
upstream "backend" health_check="http://backend/health" sni="backend.com" discovery="dns"

location "api" path="/api" upstream="backend"

server "web" addr="0.0.0.0:3000" locations="api"
"#;
        let toml_str = convert_kdl_to_toml(kdl_input).unwrap();
        let value: toml::Value = toml::from_str(&toml_str).unwrap();
        let root = value.as_table().unwrap();

        let up = &root["upstreams"]["backend"];
        assert_eq!(
            up["health_check"].as_str().unwrap(),
            "http://backend/health"
        );
        assert_eq!(up["sni"].as_str().unwrap(), "backend.com");

        let loc = &root["locations"]["api"];
        assert_eq!(loc["path"].as_str().unwrap(), "/api");
        assert_eq!(loc["upstream"].as_str().unwrap(), "backend");

        // Single-element list fields are wrapped into arrays
        let server = &root["servers"]["web"];
        assert_eq!(server["addr"].as_str().unwrap(), "0.0.0.0:3000");
        let locs = server["locations"].as_array().unwrap();
        assert_eq!(locs[0].as_str().unwrap(), "api");
    }

    #[test]
    fn test_mixed_inline_and_block() {
        // Mix: some props inline, some in child block
        let kdl_input = r#"
upstream "backend" sni="api.github.com" discovery="dns" {
    addrs "api.github.com:443"
    health_check "http://api.github.com/health"
}

location "github-api" path="/api" upstream="backend" {
    proxy_set_headers "Host:api.github.com"
    rewrite "^/api/(?<path>.+)$ /$1"
}

server "web" addr="0.0.0.0:3000" {
    locations "github-api"
}
"#;
        let toml_str = convert_kdl_to_toml(kdl_input).unwrap();
        let value: toml::Value = toml::from_str(&toml_str).unwrap();
        let root = value.as_table().unwrap();

        let up = &root["upstreams"]["backend"];
        assert_eq!(up["sni"].as_str().unwrap(), "api.github.com");
        assert_eq!(
            up["addrs"].as_array().unwrap()[0].as_str().unwrap(),
            "api.github.com:443"
        );

        let loc = &root["locations"]["github-api"];
        assert_eq!(loc["path"].as_str().unwrap(), "/api");
        assert_eq!(loc["upstream"].as_str().unwrap(), "backend");
        assert_eq!(
            loc["proxy_set_headers"].as_array().unwrap()[0]
                .as_str()
                .unwrap(),
            "Host:api.github.com"
        );
    }

    #[test]
    fn test_array_of_tables_roundtrip() {
        // Array of inline tables: TOML → KDL → TOML must preserve all data.
        // This tests the fix for the silent data-loss bug where Table elements
        // inside an array were previously rendered as empty strings.
        let toml_simple = "[basic]\nrules = [{path = \"/a\", weight = 1}, {path = \"/b\", weight = 2}]\n";

        let kdl_str = convert_toml_to_kdl(toml_simple).unwrap();

        // KDL output must NOT contain empty strings for table elements
        // (old bug: tables were silently dropped → output would be `rules \n`)
        assert!(
            !kdl_str.contains("rules \n") && !kdl_str.contains("rules\n"),
            "Table array elements must not be silently dropped; got:\n{kdl_str}"
        );
        // Must contain `item {` blocks
        assert!(
            kdl_str.contains("item {"),
            "Expected item blocks in: {kdl_str}"
        );

        // Round-trip: KDL → TOML → compare
        let toml_rt = convert_kdl_to_toml(&kdl_str).unwrap();
        let orig: toml::Value = toml::from_str(toml_simple).unwrap();
        let rt: toml::Value = toml::from_str(&toml_rt).unwrap();
        assert_eq!(orig["basic"]["rules"], rt["basic"]["rules"]);
    }

    #[test]
    fn test_boolean_roundtrip() {
        // KDL v2 (kdl crate 6.x) uses #true / #false as boolean literals.
        // Plain `true`/`false` are identifiers in v2, not booleans.
        // This test guards against accidentally switching to v1 syntax.

        // TOML → KDL: booleans must render as #true / #false
        let toml_input = "[basic]\ndaemon = true\nlog_format_json = false\n";
        let kdl_str = convert_toml_to_kdl(toml_input).unwrap();
        assert!(
            kdl_str.contains("#true"),
            "expected #true in KDL output, got: {kdl_str}"
        );
        assert!(
            kdl_str.contains("#false"),
            "expected #false in KDL output, got: {kdl_str}"
        );

        // KDL → TOML: #true / #false must parse back to booleans
        let kdl_input =
            "basic {\n    daemon #true\n    log_format_json #false\n}\n";
        let toml_str = convert_kdl_to_toml(kdl_input).unwrap();
        let value: toml::Value = toml::from_str(&toml_str).unwrap();
        assert_eq!(value["basic"]["daemon"].as_bool().unwrap(), true);
        assert_eq!(value["basic"]["log_format_json"].as_bool().unwrap(), false);

        // Full roundtrip preserves boolean values
        let orig: toml::Value = toml::from_str(toml_input).unwrap();
        let rt: toml::Value =
            toml::from_str(&convert_kdl_to_toml(&kdl_str).unwrap()).unwrap();
        assert_eq!(orig, rt);
    }

    #[test]
    fn test_roundtrip_toml_kdl_toml() {
        let toml_input = r#"
[basic]
worker_threads = 4
daemon = false

[upstreams.backend]
addrs = ["127.0.0.1:8080", "127.0.0.1:8081"]
health_check = "http://backend/health"

[locations.api]
upstream = "backend"
path = "/api"

[servers.web]
addr = "0.0.0.0:3000"
locations = ["api"]
"#;
        let kdl_str = convert_toml_to_kdl(toml_input).unwrap();
        let toml_roundtrip = convert_kdl_to_toml(&kdl_str).unwrap();

        let orig: toml::Value = toml::from_str(toml_input).unwrap();
        let rt: toml::Value = toml::from_str(&toml_roundtrip).unwrap();
        assert_eq!(orig, rt);
    }
}
