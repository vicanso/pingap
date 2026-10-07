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

//! Values that are not in the configuration itself: `$ENV:NAME` is read
//! from the environment and `$FILE:/path` from a file.
//!
//! A container gets its credentials through the environment or as mounted
//! files, and without this they had to be written into the configuration
//! as they are. A reference is the whole of a string value, wherever in an
//! entry that string is; it is replaced in the configuration a process
//! runs with ([`crate::PingapTomlConfig::to_running_config`]) and nowhere
//! else: what the admin shows and saves, what `--sync` copies and what
//! `--to-hcl` prints is the reference as it is written.

use std::collections::HashSet;
use std::io::Read;
use std::path::Path;
use toml::Value;

const ENV_PREFIX: &str = "$ENV:";
/// What a reference to a file starts with.
pub const FILE_PREFIX: &str = "$FILE:";

/// The most a referenced file may hold. A certificate chain is a few
/// kilobytes; anything near this is a path that was not meant.
const MAX_FILE_SIZE: u64 = 1024 * 1024;

/// What to do with a reference that names nothing on this machine: a
/// variable that is not set, a file that is not there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingReference {
    /// It is an error. For a configuration that is to run here: taken as
    /// the text it is, `secret = "$ENV:JWT_SECRET"` is a secret anyone can
    /// read in the documentation.
    Refuse,
    /// It stays as it is written. For a control panel node, which stores
    /// a configuration that other machines run with their environment.
    Keep,
}

/// Whether `value` is written as a reference.
pub fn is_reference(value: &str) -> bool {
    value.starts_with(ENV_PREFIX) || value.starts_with(FILE_PREFIX)
}

/// What a reference names.
enum Lookup {
    Found(String),
    /// Nothing on this machine, with what to say about it.
    Missing(String),
}

fn read_env(name: &str) -> Result<Lookup, String> {
    let mut chars = name.chars();
    let valid = chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    // Not left as text: a name with a slip in it would make the reference
    // itself the value.
    if !valid {
        return Err(format!(
            "{ENV_PREFIX}{name} does not name an environment variable"
        ));
    }
    Ok(match std::env::var(name) {
        // Set to nothing is what an environment gets from
        // `NAME: ${NAME}` of a compose file when the host has no such
        // variable. Taken as the value, a credential that is empty is
        // one that some of what checks credentials accepts.
        Ok(value) if value.is_empty() => {
            Lookup::Missing(format!("environment variable {name} is empty"))
        },
        Ok(value) => Lookup::Found(value),
        Err(std::env::VarError::NotPresent) => {
            Lookup::Missing(format!("environment variable {name} is not set"))
        },
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(format!("environment variable {name} is not utf-8"));
        },
    })
}

fn read_file(path: &str) -> Result<Lookup, String> {
    let resolved = if path == "~" || path.starts_with("~/") {
        pingap_util::resolve_path(path)
    } else {
        path.to_string()
    };
    // A daemon runs in `/`, and a path relative to where the process was
    // started names another file once it has moved there.
    if !Path::new(&resolved).is_absolute() {
        return Err(format!("{FILE_PREFIX}{path} has to be an absolute path"));
    }
    let missing = |e: std::io::Error| {
        Ok(Lookup::Missing(format!("file {path} can not be read: {e}")))
    };
    let meta = match std::fs::metadata(&resolved) {
        Ok(meta) => meta,
        Err(e) => return missing(e),
    };
    // A pipe or a device has no end to read up to.
    if !meta.is_file() {
        return Err(format!("file {path} is not a regular file"));
    }
    let too_large =
        || format!("file {path} is larger than {} kb", MAX_FILE_SIZE / 1024);
    if meta.len() > MAX_FILE_SIZE {
        return Err(too_large());
    }
    let file = match std::fs::File::open(&resolved) {
        Ok(file) => file,
        Err(e) => return missing(e),
    };
    // Bounded on its own: the file may have grown since it was looked at.
    let mut data = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_FILE_SIZE + 1)
        .read_to_end(&mut data)
        .map_err(|e| format!("file {path} can not be read: {e}"))?;
    if data.len() as u64 > MAX_FILE_SIZE {
        return Err(too_large());
    }
    let text = String::from_utf8(data)
        .map_err(|_| format!("file {path} is not utf-8 text"))?;
    // The line end an editor or `echo` leaves is not a part of the value,
    // as in the `$(< file)` of a shell.
    let text = text.trim_end_matches(['\r', '\n']);
    // As for a variable that is set to nothing.
    if text.is_empty() {
        return Ok(Lookup::Missing(format!("file {path} is empty")));
    }
    Ok(Lookup::Found(text.to_string()))
}

/// What `value` names when it is a reference, `None` when it is not one.
fn lookup(value: &str) -> Option<Result<Lookup, String>> {
    if let Some(name) = value.strip_prefix(ENV_PREFIX) {
        return Some(read_env(name));
    }
    value.strip_prefix(FILE_PREFIX).map(read_file)
}

/// Whether any value of `entry` is written as a reference.
pub fn entry_has_reference<T: serde::Serialize>(entry: &T) -> bool {
    Value::try_from(entry).is_ok_and(|value| has_reference(&value))
}

/// Whether any string of `value` is written as a reference.
pub(crate) fn has_reference(value: &Value) -> bool {
    match value {
        Value::String(text) => is_reference(text),
        Value::Array(items) => items.iter().any(has_reference),
        Value::Table(table) => table.values().any(has_reference),
        _ => false,
    }
}

/// Adds the path of every `$FILE:` reference in `value` to `paths`.
fn collect_files(value: &Value, paths: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            if let Some(path) = text.strip_prefix(FILE_PREFIX) {
                paths.push(path.to_string());
            }
        },
        Value::Array(items) => {
            for item in items {
                collect_files(item, paths);
            }
        },
        Value::Table(table) => {
            for item in table.values() {
                collect_files(item, paths);
            }
        },
        _ => {},
    }
}

/// A hash of what the files that `values` refer to hold now, `0` when
/// they refer to none.
///
/// The document a reload looks at does not change when one of these files
/// does (a secret that is rotated in place, a certificate that is
/// renewed), so the reload goes by this as well. A file that can not be
/// read is a state like any other: the hash changes when it appears.
pub(crate) fn files_hash<'a>(values: impl Iterator<Item = &'a Value>) -> u64 {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut paths = vec![];
    for value in values {
        collect_files(value, &mut paths);
    }
    if paths.is_empty() {
        return 0;
    }
    paths.sort();
    paths.dedup();
    let mut hasher = DefaultHasher::new();
    for path in paths {
        path.hash(&mut hasher);
        match read_file(&path) {
            Ok(Lookup::Found(content)) => (0u8, content).hash(&mut hasher),
            Ok(Lookup::Missing(_)) => 1u8.hash(&mut hasher),
            Err(message) => (2u8, message).hash(&mut hasher),
        }
    }
    // Never the `0` of a document without such references.
    hasher.finish().max(1)
}

struct Resolver<'a> {
    missing: MissingReference,
    /// What the references stood for, see [`resolve_entry`].
    resolved: &'a mut HashSet<String>,
    /// Where in the entry the walk is, for the error: `rules[1].secret`.
    path: String,
}

impl Resolver<'_> {
    fn walk(&mut self, value: &mut Value) -> Result<(), String> {
        match value {
            Value::String(text) => {
                let Some(found) = lookup(text) else {
                    return Ok(());
                };
                let found = found.map_err(|message| self.located(&message))?;
                match found {
                    Lookup::Found(content) => {
                        self.resolved.insert(content.clone());
                        *text = content;
                    },
                    Lookup::Missing(message) => {
                        if self.missing == MissingReference::Refuse {
                            return Err(self.located(&message));
                        }
                    },
                }
            },
            Value::Array(items) => {
                let len = self.path.len();
                for (index, item) in items.iter_mut().enumerate() {
                    self.path.push_str(&format!("[{index}]"));
                    self.walk(item)?;
                    self.path.truncate(len);
                }
            },
            Value::Table(table) => {
                let len = self.path.len();
                for (key, item) in table.iter_mut() {
                    if len > 0 {
                        self.path.push('.');
                    }
                    self.path.push_str(key);
                    self.walk(item)?;
                    self.path.truncate(len);
                }
            },
            _ => {},
        }
        Ok(())
    }
    fn located(&self, message: &str) -> String {
        format!("{}: {message}", self.path)
    }
}

/// Replaces each string of `entry` that is a reference by what it names.
///
/// What they stood for is added to `resolved`, so that it can be kept out
/// of what is printed about the configuration: a value that was put into
/// the environment or a file to keep it out of the configuration does not
/// belong in the difference a reload writes to the log either, whatever
/// its key is called.
///
/// The error says where in the entry the reference is, and never what
/// another reference stood for.
pub(crate) fn resolve_entry(
    entry: &mut Value,
    missing: MissingReference,
    resolved: &mut HashSet<String>,
) -> Result<(), String> {
    Resolver {
        missing,
        resolved,
        path: String::new(),
    }
    .walk(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PingapTomlConfig;
    use pretty_assertions::assert_eq;
    use std::io::Write;

    fn resolve(
        data: &str,
        missing: MissingReference,
    ) -> Result<(toml::Table, HashSet<String>), String> {
        let mut value = Value::Table(toml::from_str(data).unwrap());
        let mut resolved = HashSet::new();
        resolve_entry(&mut value, missing, &mut resolved)?;
        let Value::Table(table) = value else {
            unreachable!("a table stays one");
        };
        Ok((table, resolved))
    }

    #[test]
    fn test_is_reference() {
        assert_eq!(true, is_reference("$ENV:HOME"));
        assert_eq!(true, is_reference("$FILE:/etc/hosts"));
        // The whole of the value, from its first character.
        assert_eq!(false, is_reference("https://a.com?token=$ENV:TOKEN"));
        assert_eq!(false, is_reference(" $ENV:HOME"));
        assert_eq!(false, is_reference("$env:HOME"));
        assert_eq!(false, is_reference("$HOME"));
        assert_eq!(false, is_reference(""));

        let entry = |data: &str| Value::Table(toml::from_str(data).unwrap());
        assert_eq!(false, has_reference(&entry("a = \"b\"\nc = 1")));
        assert_eq!(true, has_reference(&entry("a = [\"b\", \"$ENV:C\"]")));
        assert_eq!(true, has_reference(&entry("[a.b]\nc = \"$FILE:/d\"")));
    }

    #[test]
    fn test_resolve_entry() {
        // The one variable every environment has.
        let path = std::env::var("PATH").unwrap();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"s3cret line\nsecond line\r\n\n").unwrap();
        let file_path = file.path().to_string_lossy().to_string();

        let (value, resolved) = resolve(
            &format!(
                r#"
plain = "$PATH"
whole = "$ENV:PATH"
inside = "a $ENV:PATH"
number = 1
list = ["a", "$ENV:PATH", "$FILE:{file_path}"]

[nested]
key = "$FILE:{file_path}"
"#
            ),
            MissingReference::Refuse,
        )
        .unwrap();
        assert_eq!(Some("$PATH"), value["plain"].as_str());
        assert_eq!(Some(path.as_str()), value["whole"].as_str());
        // Only the whole of a value is a reference.
        assert_eq!(Some("a $ENV:PATH"), value["inside"].as_str());
        assert_eq!(Some(1), value["number"].as_integer());
        assert_eq!(Some(path.as_str()), value["list"][1].as_str());
        // The line ends at its end are not a part of the value, the ones
        // inside it are.
        let content = "s3cret line\nsecond line";
        assert_eq!(Some(content), value["list"][2].as_str());
        assert_eq!(Some(content), value["nested"]["key"].as_str());
        assert_eq!(
            HashSet::from([path.clone(), content.to_string()]),
            resolved
        );
    }

    #[test]
    fn test_resolve_entry_errors() {
        let error =
            |data: &str| resolve(data, MissingReference::Refuse).unwrap_err();
        // Named by where it is in the entry.
        assert_eq!(
            "secret: environment variable PINGAP_NOT_SET_FOR_SURE is not set",
            error("secret = \"$ENV:PINGAP_NOT_SET_FOR_SURE\"")
        );
        assert_eq!(
            "keys[1]: environment variable PINGAP_NOT_SET_FOR_SURE is not set",
            error("keys = [\"a\", \"$ENV:PINGAP_NOT_SET_FOR_SURE\"]")
        );
        assert_eq!(
            "rules[0].auth.secret: environment variable PINGAP_NOT_SET_FOR_SURE is not set",
            error(
                "[[rules]]\n[rules.auth]\nsecret = \"$ENV:PINGAP_NOT_SET_FOR_SURE\""
            )
        );
        let message = error("tls_key = \"$FILE:/pingap/not/there.pem\"");
        assert_eq!(
            true,
            message.starts_with(
                "tls_key: file /pingap/not/there.pem can not be read: "
            ),
            "{message}"
        );

        // What is no reference at all is an error whatever is to be done
        // with a missing one: nothing about it depends on the machine.
        for missing in [MissingReference::Refuse, MissingReference::Keep] {
            for (data, expected) in [
                (
                    "a = \"$ENV:MY-SECRET\"",
                    "a: $ENV:MY-SECRET does not name an environment variable",
                ),
                (
                    "a = \"$ENV:\"",
                    "a: $ENV: does not name an environment variable",
                ),
                (
                    "a = \"$ENV:1ST\"",
                    "a: $ENV:1ST does not name an environment variable",
                ),
                (
                    "a = \"$FILE:conf/key.pem\"",
                    "a: $FILE:conf/key.pem has to be an absolute path",
                ),
                ("a = \"$FILE:\"", "a: $FILE: has to be an absolute path"),
                ("a = \"$FILE:/\"", "a: file / is not a regular file"),
            ] {
                assert_eq!(
                    expected,
                    resolve(data, missing).unwrap_err(),
                    "{data}"
                );
            }
        }

        // Nothing in it is no value: an empty credential is not one to
        // go on with.
        let mut empty = tempfile::NamedTempFile::new().unwrap();
        empty.write_all(b"\n").unwrap();
        let message = error(&format!(
            "secret = \"$FILE:{}\"",
            empty.path().to_string_lossy()
        ));
        assert_eq!(true, message.starts_with("secret: file "), "{message}");
        assert_eq!(true, message.ends_with(" is empty"), "{message}");

        // Too much for a value.
        let mut large = tempfile::NamedTempFile::new().unwrap();
        large
            .write_all(&vec![b'a'; MAX_FILE_SIZE as usize + 1])
            .unwrap();
        let message =
            error(&format!("a = \"$FILE:{}\"", large.path().to_string_lossy()));
        assert_eq!(true, message.ends_with("is larger than 1024 kb"));
        let mut binary = tempfile::NamedTempFile::new().unwrap();
        binary.write_all(&[0xff, 0xfe, 0x00]).unwrap();
        let message = error(&format!(
            "a = \"$FILE:{}\"",
            binary.path().to_string_lossy()
        ));
        assert_eq!(true, message.ends_with("is not utf-8 text"));
    }

    /// A node that only stores the configuration keeps what it can not
    /// look up, and still replaces what it can.
    #[test]
    fn test_resolve_entry_keeps_what_is_missing() {
        let path = std::env::var("PATH").unwrap();
        let (value, resolved) = resolve(
            "a = \"$ENV:PINGAP_NOT_SET_FOR_SURE\"\nb = \"$FILE:/pingap/not/there\"\nc = \"$ENV:PATH\"",
            MissingReference::Keep,
        )
        .unwrap();
        assert_eq!(Some("$ENV:PINGAP_NOT_SET_FOR_SURE"), value["a"].as_str());
        assert_eq!(Some("$FILE:/pingap/not/there"), value["b"].as_str());
        assert_eq!(Some(path.as_str()), value["c"].as_str());
        assert_eq!(HashSet::from([path]), resolved);
    }

    /// A file holding `content`, and the reference to it.
    fn file_reference(content: &str) -> (tempfile::NamedTempFile, String) {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        let reference = format!("$FILE:{}", file.path().to_string_lossy());
        (file, reference)
    }

    /// The configuration to run with has every reference replaced, in
    /// each kind of entry and in what an entry includes; the one that is
    /// shown and stored has none replaced.
    #[test]
    fn test_running_config_replaces_references() {
        let (_addr_file, addr) = file_reference("127.0.0.1:5001\n");
        let (_secret_file, secret) = file_reference("s3cret-value");
        let (_hook_file, hook) = file_reference("https://hook.test/a/key");
        let (_host_file, host) = file_reference("api.test");
        let (_listen_file, listen) = file_reference("127.0.0.1:6188");
        let (_domain_file, domain) = file_reference("pingap.test");
        let document = PingapTomlConfig::from_toml(&format!(
            r#"
[basic]
webhook = "{hook}"

[upstreams.api]
addrs = ["{addr}", "127.0.0.1:5002"]
includes = ["shared"]

[locations.api]
upstream = "api"
host = "{host}"

[servers.web]
addr = "{listen}"
locations = ["api"]

[plugins.auth]
category = "key_auth"
header = "X-Api-Key"
keys = ["{secret}"]

[certificates.site]
domains = "{domain}"

[storages.shared]
category = "config"
value = 'sni = "{host}"'
"#
        ))
        .unwrap();

        let running = document
            .to_running_config(MissingReference::Refuse)
            .unwrap();
        assert_eq!(
            Some("https://hook.test/a/key".to_string()),
            running.basic.webhook
        );
        assert_eq!(
            vec!["127.0.0.1:5001".to_string(), "127.0.0.1:5002".to_string()],
            running.upstreams["api"].addrs
        );
        // What came in through an include is replaced where it ends up.
        assert_eq!(Some("api.test".to_string()), running.upstreams["api"].sni);
        assert_eq!(Some("api.test".to_string()), running.locations["api"].host);
        assert_eq!("127.0.0.1:6188", running.servers["web"].addr);
        assert_eq!(
            Some("s3cret-value"),
            running.plugins["auth"]["keys"][0].as_str()
        );
        assert_eq!(
            Some("pingap.test".to_string()),
            running.certificates["site"].domains
        );
        // The storage itself is as it is written.
        assert_eq!(
            format!("sni = \"{host}\""),
            running.storages["shared"].value
        );
        assert_eq!(
            HashSet::from(
                [
                    "https://hook.test/a/key",
                    "127.0.0.1:5001",
                    "api.test",
                    "127.0.0.1:6188",
                    "s3cret-value",
                    "pingap.test"
                ]
                .map(str::to_string)
            ),
            running.referenced
        );
        // And it is a configuration that passes.
        running.validate().unwrap();

        // As written, with the includes replaced or not: the admin shows
        // and stores this, `--sync` and `--to-hcl` copy it.
        for replace_include in [true, false] {
            let written = document.to_pingap_config(replace_include).unwrap();
            assert_eq!(Some(hook.clone()), written.basic.webhook);
            assert_eq!(addr, written.upstreams["api"].addrs[0]);
            assert_eq!(Some(host.clone()), written.locations["api"].host);
            assert_eq!(listen, written.servers["web"].addr);
            assert_eq!(
                Some(secret.as_str()),
                written.plugins["auth"]["keys"][0].as_str()
            );
            assert_eq!(true, written.referenced.is_empty());
        }
        assert_eq!(
            Some(host),
            document.to_pingap_config(true).unwrap().upstreams["api"].sni
        );
    }

    /// What a reference stood for is not in the difference of two
    /// configurations, under whatever key it is, and a change of it still
    /// shows as one.
    #[test]
    fn test_referenced_values_stay_out_of_the_diff() {
        let config = |addr: &str, data: &str| {
            let (_addr_file, addr) = file_reference(addr);
            let (_data_file, data) = file_reference(data);
            PingapTomlConfig::from_toml(&format!(
                r#"
[upstreams.api]
addrs = ["{addr}"]

[plugins.page]
category = "mock"
data = "{data}"
"#
            ))
            .unwrap()
            .to_running_config(MissingReference::Refuse)
            .unwrap()
        };
        let before = config("10.1.1.1:5001", "first-private-text");
        let after = config("10.1.1.2:5001", "second-private-text");
        assert_eq!("10.1.1.1:5001", before.upstreams["api"].addrs[0]);

        let (mut categories, lines) = before.diff(&after);
        categories.sort();
        assert_eq!(vec!["plugin", "upstream"], categories);
        let text = lines.join("\n");
        for hidden in [
            "10.1.1.1",
            "10.1.1.2",
            "first-private-text",
            "second-private-text",
        ] {
            assert_eq!(false, text.contains(hidden), "{hidden} in {text}");
        }
        assert_eq!(true, text.contains("[MODIFIED] upstream:api"), "{text}");
        assert_eq!(true, text.contains("crc32:"), "{text}");
        // The same values again are no difference, and the hash follows.
        let same = config("10.1.1.1:5001", "first-private-text");
        assert_eq!(true, before.diff(&same).1.is_empty());
        assert_eq!(before.hash().unwrap(), same.hash().unwrap());
        assert_eq!(false, before.hash().unwrap() == after.hash().unwrap());
    }

    /// Regression: a reload makes the running configuration out of the
    /// one before and the entries of the new one. With the set of the old
    /// one kept, what the new references stood for was in the next
    /// difference as it is.
    #[test]
    fn test_referenced_values_follow_a_reload() {
        let config = |data: &str, addr: &str| {
            let (_data_file, data) = file_reference(data);
            let (_addr_file, addr) = file_reference(addr);
            PingapTomlConfig::from_toml(&format!(
                r#"
[upstreams.api]
addrs = ["{addr}"]

[plugins.page]
category = "mock"
data = "{data}"
"#
            ))
            .unwrap()
            .to_running_config(MissingReference::Refuse)
            .unwrap()
        };
        let first = config("first-private-text", "10.1.1.1:5001");
        let second = config("second-private-text", "10.1.1.1:5001");
        let third = config("third-private-text", "10.1.1.1:5001");

        // What a hot reload does with the plugins of `second`.
        let mut running = first.clone();
        running.referenced.extend(second.referenced.iter().cloned());
        running.plugins = second.plugins.clone();
        running.prune_referenced();
        // The value that is gone is gone from the set, the ones that are
        // there are in it.
        assert_eq!(
            HashSet::from(
                ["second-private-text", "10.1.1.1:5001"].map(str::to_string)
            ),
            running.referenced
        );
        let text = running.diff(&third).1.join("\n");
        assert_eq!(true, text.contains("[MODIFIED] plugin:page"), "{text}");
        for hidden in ["second-private-text", "third-private-text"] {
            assert_eq!(false, text.contains(hidden), "{hidden} in {text}");
        }

        // Without the set of the new configuration it is in there.
        let mut stale = first.clone();
        stale.plugins = second.plugins.clone();
        let text = stale.diff(&third).1.join("\n");
        assert_eq!(true, text.contains("second-private-text"), "{text}");
    }

    /// A node that stores a configuration for others keeps the
    /// references it can not look up, and does not judge the form of an
    /// entry by them: the address of a server written as a reference was
    /// refused as no address, on the node the variable is not meant for.
    #[test]
    fn test_kept_references_are_not_validated() {
        let document = PingapTomlConfig::from_toml(
            r#"
[upstreams.api]
addrs = ["$ENV:PINGAP_NOT_SET_FOR_SURE"]
discovery = "static"

[locations.api]
upstream = "api"

[servers.web]
addr = "$ENV:PINGAP_NOT_SET_FOR_SURE"
locations = ["api"]

[certificates.site]
tls_cert = "$FILE:/pingap/not/there.pem"
tls_key = "$FILE:/pingap/not/there.key"
"#,
        )
        .unwrap();
        let kept = document.to_running_config(MissingReference::Keep).unwrap();
        assert_eq!("$ENV:PINGAP_NOT_SET_FOR_SURE", kept.servers["web"].addr);
        kept.validate().unwrap();
        // What the other entries say of each other is still checked.
        let mut lost = kept.clone();
        lost.locations.get_mut("api").unwrap().upstream =
            Some("gone".to_string());
        assert_eq!(true, lost.validate().is_err());
        // Where it is to run, the same document does not get this far.
        assert_eq!(
            true,
            document
                .to_running_config(MissingReference::Refuse)
                .is_err()
        );
    }

    #[test]
    fn test_running_config_reference_errors() {
        let error = |data: &str, missing: MissingReference| {
            PingapTomlConfig::from_toml(data)
                .unwrap()
                .to_running_config(missing)
                .unwrap_err()
                .to_string()
        };
        // Which entry, and which of its keys.
        assert_eq!(
            "Invalid error plugin(auth): keys[1]: environment variable PINGAP_NOT_SET_FOR_SURE is not set",
            error(
                "[plugins.auth]\ncategory = \"key_auth\"\nkeys = [\"a\", \"$ENV:PINGAP_NOT_SET_FOR_SURE\"]",
                MissingReference::Refuse
            )
        );
        assert_eq!(
            "Invalid error basic: webhook: environment variable PINGAP_NOT_SET_FOR_SURE is not set",
            error(
                "[basic]\nwebhook = \"$ENV:PINGAP_NOT_SET_FOR_SURE\"",
                MissingReference::Refuse
            )
        );

        // A duration is not text: the entry has to read as it is written,
        // which is how the admin shows it. Said of the reference, and
        // without what it stands for.
        let (_file, reference) = file_reference("private-10s");
        let data = format!(
            "[upstreams.api]\naddrs = [\"127.0.0.1:5001\"]\nread_timeout = \"{reference}\""
        );
        for missing in [MissingReference::Refuse, MissingReference::Keep] {
            let message = error(&data, missing);
            assert_eq!(
                true,
                message.starts_with("Invalid error upstream(api): "),
                "{message}"
            );
            assert_eq!(
                true,
                message.ends_with(
                    "(a $ENV: or $FILE: reference is only read where the value is text)"
                ),
                "{message}"
            );
            assert_eq!(false, message.contains("private-10s"), "{message}");
        }

        // A node that only stores the configuration keeps what it can not
        // look up.
        let kept = PingapTomlConfig::from_toml(
            "[plugins.auth]\ncategory = \"key_auth\"\nkeys = [\"$ENV:PINGAP_NOT_SET_FOR_SURE\"]",
        )
        .unwrap()
        .to_running_config(MissingReference::Keep)
        .unwrap();
        assert_eq!(
            Some("$ENV:PINGAP_NOT_SET_FOR_SURE"),
            kept.plugins["auth"]["keys"][0].as_str()
        );
        assert_eq!(true, kept.referenced.is_empty());
    }

    /// The files a document refers to are a part of its state: their
    /// hash moves when one of them changes, appears or goes.
    #[test]
    fn test_referenced_files_hash() {
        let (mut file, reference) = file_reference("first");
        let document = |data: &str| PingapTomlConfig::from_toml(data).unwrap();
        // No file is referred to.
        assert_eq!(
            0,
            document(
                "[upstreams.api]\naddrs = [\"$ENV:PATH\", \"127.0.0.1:1\"]"
            )
            .referenced_files_hash()
        );
        assert_eq!(0, document("").referenced_files_hash());

        let plugin = document(&format!(
            "[plugins.auth]\ncategory = \"key_auth\"\nkeys = [\"{reference}\"]"
        ));
        let first = plugin.referenced_files_hash();
        assert_eq!(false, first == 0);
        assert_eq!(first, plugin.referenced_files_hash());
        file.write_all(b" and more").unwrap();
        file.flush().unwrap();
        let second = plugin.referenced_files_hash();
        assert_eq!(false, first == second);

        // In what a storage holds for the entries that include it.
        let fragment = document(&format!(
            "[storages.shared]\ncategory = \"config\"\nvalue = 'sni = \"{reference}\"'"
        ));
        assert_eq!(false, fragment.referenced_files_hash() == 0);
        // In `basic`, and for a file that is not there: its appearing is
        // a change.
        let path = file.path().with_extension("later");
        let basic = document(&format!(
            "[basic]\nwebhook = \"$FILE:{}\"",
            path.to_string_lossy()
        ));
        let missing = basic.referenced_files_hash();
        assert_eq!(false, missing == 0);
        std::fs::write(&path, "https://hook.test").unwrap();
        let there = basic.referenced_files_hash();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(false, missing == there);
        assert_eq!(missing, basic.referenced_files_hash());
    }

    /// What a reference gives is the value: it is not looked at again.
    #[test]
    fn test_resolved_value_is_not_resolved_again() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"$ENV:PATH").unwrap();
        let (value, _) = resolve(
            &format!("a = \"$FILE:{}\"", file.path().to_string_lossy()),
            MissingReference::Refuse,
        )
        .unwrap();
        assert_eq!(Some("$ENV:PATH"), value["a"].as_str());
    }
}
