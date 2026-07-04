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

//! Shared TOML assembly for the HCL and KDL config front-ends.
//!
//! Both the `hcl` and `kdl` modules parse their own syntax into the same set
//! of [`ConfigBlock`]s, then hand them to [`assemble_toml`], which applies the
//! common section-merging rules (nested upstreams/plugins/locations/
//! certificates are lifted to the top level). Keeping that logic here means
//! the two parsers only differ in how they read their respective AST.

use crate::{Error, Result};
use toml::Value as TomlValue;
use toml::map::Map as TomlMap;

/// A location block after format-specific parsing: the location's own
/// attributes plus any upstreams/plugins lifted from nested blocks.
pub(crate) struct ParsedLocation {
    pub location: TomlMap<String, TomlValue>,
    pub upstreams: TomlMap<String, TomlValue>,
    pub plugins: TomlMap<String, TomlValue>,
}

/// A server block after format-specific parsing, with nested locations,
/// upstreams, plugins, and certificates lifted to the top level.
pub(crate) struct ParsedServer {
    pub server: TomlMap<String, TomlValue>,
    pub locations: TomlMap<String, TomlValue>,
    pub upstreams: TomlMap<String, TomlValue>,
    pub plugins: TomlMap<String, TomlValue>,
    pub certificates: TomlMap<String, TomlValue>,
}

/// A top-level configuration block produced by a format front-end and
/// consumed by [`assemble_toml`].
pub(crate) enum ConfigBlock {
    Basic(TomlMap<String, TomlValue>),
    Server(String, ParsedServer),
    Location(String, ParsedLocation),
    Upstream(String, TomlMap<String, TomlValue>),
    Plugin(String, TomlMap<String, TomlValue>),
    Certificate(String, TomlMap<String, TomlValue>),
    Storage(String, TomlMap<String, TomlValue>),
}

/// Insert `name`→`value` into `dst`, erroring if `name` is already present so
/// that two blocks sharing a name are reported instead of silently
/// overwriting each other.
fn insert_unique(
    dst: &mut TomlMap<String, TomlValue>,
    name: String,
    value: TomlValue,
    section: &str,
) -> Result<()> {
    if dst.contains_key(&name) {
        return Err(Error::Invalid {
            message: format!("duplicate \"{name}\" in {section}"),
        });
    }
    dst.insert(name, value);
    Ok(())
}

/// Merge `src` into `dst`, erroring on the first duplicate name.
fn merge_unique(
    dst: &mut TomlMap<String, TomlValue>,
    src: TomlMap<String, TomlValue>,
    section: &str,
) -> Result<()> {
    for (name, value) in src {
        insert_unique(dst, name, value, section)?;
    }
    Ok(())
}

/// Insert `value` at `root[section_key][name]`, creating the section table
/// when it does not yet exist. Errors on a duplicate name.
pub(crate) fn insert_into_section(
    root: &mut TomlMap<String, TomlValue>,
    section_key: &str,
    name: String,
    value: TomlValue,
) -> Result<()> {
    let section = root
        .entry(section_key.to_string())
        .or_insert_with(|| TomlValue::Table(TomlMap::new()));
    if let TomlValue::Table(t) = section {
        insert_unique(t, name, value, section_key)?;
    }
    Ok(())
}

/// Merge `values` into `root[section_key]`, creating the section table when
/// needed. Used for sections that may also receive standalone top-level
/// entries (plugins, certificates). Errors on any name collision.
fn extend_section(
    root: &mut TomlMap<String, TomlValue>,
    section_key: &str,
    values: TomlMap<String, TomlValue>,
) -> Result<()> {
    if values.is_empty() {
        return Ok(());
    }
    let section = root
        .entry(section_key.to_string())
        .or_insert_with(|| TomlValue::Table(TomlMap::new()));
    if let TomlValue::Table(t) = section {
        merge_unique(t, values, section_key)?;
    }
    Ok(())
}

/// Assemble parsed config blocks into a pretty-printed TOML document,
/// lifting nested upstreams/plugins/locations/certificates to top-level
/// sections. Shared by the HCL and KDL front-ends so the merge rules live
/// in one place.
pub(crate) fn assemble_toml(blocks: Vec<ConfigBlock>) -> Result<String> {
    let mut root = TomlMap::new();
    let mut all_locations = TomlMap::new();
    let mut all_upstreams = TomlMap::new();
    let mut all_plugins = TomlMap::new();
    let mut all_certificates = TomlMap::new();

    for block in blocks {
        match block {
            ConfigBlock::Basic(table) => {
                insert_unique(
                    &mut root,
                    "basic".to_string(),
                    TomlValue::Table(table),
                    "basic",
                )?;
            },
            ConfigBlock::Server(name, parsed) => {
                let ParsedServer {
                    server,
                    locations,
                    upstreams,
                    plugins,
                    certificates,
                } = parsed;
                insert_into_section(
                    &mut root,
                    "servers",
                    name,
                    TomlValue::Table(server),
                )?;
                merge_unique(&mut all_locations, locations, "locations")?;
                merge_unique(&mut all_upstreams, upstreams, "upstreams")?;
                merge_unique(&mut all_plugins, plugins, "plugins")?;
                merge_unique(
                    &mut all_certificates,
                    certificates,
                    "certificates",
                )?;
            },
            ConfigBlock::Location(name, parsed) => {
                insert_unique(
                    &mut all_locations,
                    name,
                    TomlValue::Table(parsed.location),
                    "locations",
                )?;
                merge_unique(
                    &mut all_upstreams,
                    parsed.upstreams,
                    "upstreams",
                )?;
                merge_unique(&mut all_plugins, parsed.plugins, "plugins")?;
            },
            ConfigBlock::Upstream(name, table) => {
                insert_unique(
                    &mut all_upstreams,
                    name,
                    TomlValue::Table(table),
                    "upstreams",
                )?;
            },
            ConfigBlock::Plugin(name, table) => {
                insert_into_section(
                    &mut root,
                    "plugins",
                    name,
                    TomlValue::Table(table),
                )?;
            },
            ConfigBlock::Certificate(name, table) => {
                insert_into_section(
                    &mut root,
                    "certificates",
                    name,
                    TomlValue::Table(table),
                )?;
            },
            ConfigBlock::Storage(name, table) => {
                insert_into_section(
                    &mut root,
                    "storages",
                    name,
                    TomlValue::Table(table),
                )?;
            },
        }
    }

    if !all_locations.is_empty() {
        root.insert("locations".to_string(), TomlValue::Table(all_locations));
    }
    if !all_upstreams.is_empty() {
        root.insert("upstreams".to_string(), TomlValue::Table(all_upstreams));
    }
    extend_section(&mut root, "plugins", all_plugins)?;
    extend_section(&mut root, "certificates", all_certificates)?;

    toml::to_string_pretty(&root).map_err(|e| Error::Ser { source: e })
}
