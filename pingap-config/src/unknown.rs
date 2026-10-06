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

//! Finds what a configuration document has that pingap does not read.
//!
//! A key or a table pingap does not know is left out when the document is
//! read, and nothing said so: `[server.web]` for `[servers.web]` was no
//! server at all, `trusted_proxy` under `[basic]` no trusted proxy, and
//! `client_max_body_sizes` on a location no limit - each of them a config
//! that passed `--test` and did less than it says.

use crate::common::expand_includes;
use crate::{
    BasicConf, CertificateConf, LocationConf, PingapTomlConfig, ServerConf,
    StorageConf, UpstreamConf,
};
use serde::Serialize;
use std::collections::HashMap;
use toml::{Value, map::Map};

/// The sections of a document, with the name each has in HCL and KDL -
/// which is the name it is most often given in TOML by mistake.
const SECTIONS: [(&str, &str); 7] = [
    ("basic", "basic"),
    ("servers", "server"),
    ("locations", "location"),
    ("upstreams", "upstream"),
    ("plugins", "plugin"),
    ("certificates", "certificate"),
    ("storages", "storage"),
];

/// The keys an entry of type `T` has: those of its default value, which
/// serializes every field.
fn known_keys<T: Default + Serialize>() -> Vec<String> {
    match serde_json::to_value(T::default()) {
        Ok(serde_json::Value::Object(fields)) => {
            fields.keys().cloned().collect()
        },
        _ => vec![],
    }
}

/// The number of single character edits between two keys, as far as it is
/// below `limit`.
fn edit_distance(a: &str, b: &str, limit: usize) -> Option<usize> {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len().abs_diff(b.len()) > limit {
        return None;
    }
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, x) in a.iter().enumerate() {
        let mut previous = row[0];
        row[0] = i + 1;
        for (j, y) in b.iter().enumerate() {
            let cost = previous + usize::from(x != y);
            previous = row[j + 1];
            row[j + 1] = cost.min(previous + 1).min(row[j] + 1);
        }
    }
    Some(row[b.len()]).filter(|distance| *distance <= limit)
}

/// The known key `key` was most likely meant to be: the closest one
/// within two edits, or three for a long key (`trusted_proxy` is three
/// away from `trusted_proxies`).
fn closest<'a>(key: &str, known: &'a [String]) -> Option<&'a str> {
    let limit = if key.len() >= 10 { 3 } else { 2 };
    known
        .iter()
        .filter_map(|item| {
            Some((edit_distance(key, item, limit)?, item.as_str()))
        })
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, item)| item)
}

fn hint(suggestion: Option<&str>) -> String {
    suggestion
        .map_or_else(String::new, |name| format!(", did you mean \"{name}\"?"))
}

/// The keys of `entry` that `T` does not have.
fn unknown_entry_keys<T: Default + Serialize>(
    kind: &str,
    name: &str,
    entry: &Value,
    found: &mut Vec<String>,
) {
    let known = known_keys::<T>();
    let Some(table) = entry.as_table() else {
        return;
    };
    // Nothing to go by: say nothing rather than call every key unknown.
    if known.is_empty() {
        return;
    }
    let owner = if name.is_empty() {
        kind.to_string()
    } else {
        format!("{kind}({name})")
    };
    for key in table.keys() {
        if known.iter().any(|item| item == key) {
            continue;
        }
        found.push(format!(
            "{owner}: unknown key \"{key}\"{}",
            hint(closest(key, &known))
        ));
    }
}

impl PingapTomlConfig {
    /// What the document has that pingap does not read: sections under a
    /// name it does not know, and keys an entry of its kind does not have.
    /// Each is a line for the operator, with the name it was probably
    /// meant to be where there is an obvious one.
    ///
    /// The includes of an entry are put in first, so a key that comes
    /// from a storage is checked as part of the entry it ends up in.
    /// Plugins are left out: what a plugin takes is for the plugin to say.
    pub fn unknown_keys(&self) -> Vec<String> {
        let mut found = vec![];
        for key in self.unknown.keys() {
            let section = SECTIONS
                .iter()
                .find(|(_, single)| key == single)
                .map(|(section, _)| *section);
            found.push(format!(
                "unknown section [{key}]{}",
                section.map_or_else(String::new, |name| {
                    format!(", did you mean [{name}]?")
                })
            ));
        }
        if let Some(basic) = &self.basic {
            unknown_entry_keys::<BasicConf>("basic", "", basic, &mut found);
        }
        // A storage that does not read is reported when the config is
        // loaded; here it only means its includes cannot be put in.
        let storages: HashMap<String, StorageConf> = self
            .storages
            .iter()
            .flatten()
            .filter_map(|(name, value)| {
                Some((name.clone(), value.clone().try_into().ok()?))
            })
            .collect();
        fn entries<T: Default + Serialize>(
            kind: &str,
            section: &Option<Map<String, Value>>,
            storages: Option<&HashMap<String, StorageConf>>,
            found: &mut Vec<String>,
        ) {
            for (name, value) in section.iter().flatten() {
                let mut value = value.clone();
                if let Some(storages) = storages {
                    let _ = expand_includes(storages, kind, name, &mut value);
                }
                unknown_entry_keys::<T>(kind, name, &value, found);
            }
        }
        let with = Some(&storages);
        entries::<ServerConf>("server", &self.servers, with, &mut found);
        entries::<LocationConf>("location", &self.locations, with, &mut found);
        entries::<UpstreamConf>("upstream", &self.upstreams, with, &mut found);
        entries::<CertificateConf>(
            "certificate",
            &self.certificates,
            None,
            &mut found,
        );
        entries::<StorageConf>("storage", &self.storages, None, &mut found);
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// Regression: all of these loaded without a word.
    #[test]
    fn test_unknown_keys() {
        // The misspellings are the point of this test.
        // spellchecker:off
        let config = PingapTomlConfig::from_toml(
            r#"
[basic]
name = "pingap"
trusted_proxy = ["10.0.0.1"]

[server.web]
addr = "127.0.0.1:80"

[servers.api]
addr = "127.0.0.1:81"
thread = 2

[upstreams.u1]
addrs = ["127.0.0.1:9000"]
includes = ["shared"]

[locations.l1]
upstream = "u1"
client_max_body_sizes = "1kb"

[plugins.any]
category = "mock"
whatever = 1

[certificates.c1]
domain = "a.test"

[storages.shared]
category = "config"
value = 'read_timout = "7s"'

[something]
else = 1
"#,
        )
        .unwrap();
        let mut found = config.unknown_keys();
        found.sort();
        assert_eq!(
            vec![
                r#"basic: unknown key "trusted_proxy", did you mean "trusted_proxies"?"#,
                r#"certificate(c1): unknown key "domain", did you mean "domains"?"#,
                r#"location(l1): unknown key "client_max_body_sizes", did you mean "client_max_body_size"?"#,
                r#"server(api): unknown key "thread", did you mean "threads"?"#,
                "unknown section [server], did you mean [servers]?",
                "unknown section [something]",
                // from the storage it includes
                r#"upstream(u1): unknown key "read_timout", did you mean "read_timeout"?"#,
            ],
            found
        );
        // spellchecker:on
    }

    /// Every key the samples document is one pingap knows: a field that
    /// stops being listed (it is skipped when it serializes, say) would
    /// show here as unknown.
    #[test]
    fn test_sample_configs_have_no_unknown_keys() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../conf");
        let mut checked = 0;
        for name in [
            "basic.toml",
            "servers.toml",
            "locations.toml",
            "upstreams.toml",
            "certificates.toml",
        ] {
            let Ok(text) = std::fs::read_to_string(dir.join(name)) else {
                continue;
            };
            // The samples document their keys as comments: `# key = value`,
            // and now and then the header of an entry too.
            let is_key = |key: &str| {
                !key.is_empty()
                    && key.chars().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'
                    })
            };
            // A key documented twice (two ways to write it) is taken once.
            let mut seen = std::collections::HashSet::new();
            let uncommented: String = text
                .lines()
                .map(|line| {
                    let rest = line.strip_prefix("# ").unwrap_or(line);
                    let is_header = rest.starts_with('[')
                        && rest.ends_with(']')
                        && !rest.contains(' ');
                    if is_header {
                        seen.clear();
                        return format!("{rest}\n");
                    }
                    let key = rest
                        .split_once(" = ")
                        .map(|(key, _)| key)
                        .filter(|key| is_key(key));
                    match key {
                        Some(key) if seen.insert(key.to_string()) => {
                            format!("{rest}\n")
                        },
                        // a second mention of a key, or its value going on
                        _ if line.starts_with('#') => "\n".to_string(),
                        _ => format!("{line}\n"),
                    }
                })
                .collect();
            let config = PingapTomlConfig::from_toml(&uncommented)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(Vec::<String>::new(), config.unknown_keys(), "{name}");
            checked += 1;
        }
        assert_eq!(5, checked, "a sample config is missing");
    }

    /// The check goes by the fields each kind of entry has. With none to
    /// go by it says nothing, so that a kind that stops listing its fields
    /// would pass every other test here without checking anything.
    #[test]
    fn test_known_keys_are_listed() {
        for (kind, keys, expected) in [
            ("basic", known_keys::<BasicConf>(), "trusted_proxies"),
            ("server", known_keys::<ServerConf>(), "addr"),
            ("location", known_keys::<LocationConf>(), "upstream"),
            ("upstream", known_keys::<UpstreamConf>(), "addrs"),
            ("certificate", known_keys::<CertificateConf>(), "tls_key"),
            ("storage", known_keys::<StorageConf>(), "value"),
        ] {
            assert_eq!(
                true,
                keys.iter().any(|key| key == expected),
                "{kind}: {keys:?}"
            );
        }
    }

    #[test]
    fn test_edit_distance() {
        assert_eq!(Some(0), edit_distance("addrs", "addrs", 2));
        assert_eq!(Some(1), edit_distance("addr", "addrs", 2));
        assert_eq!(
            Some(2),
            edit_distance("trusted_proxy", "trusted_proxie", 2)
        );
        assert_eq!(None, edit_distance("name", "threads", 2));
    }
}
