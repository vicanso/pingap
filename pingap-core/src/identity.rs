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

//! Who a process is, for what it says about itself.
//!
//! With one deployment the hostname says it. With several - a cluster per
//! region, production next to staging - a notification from `pingap` on
//! `pingap-7d9f5c6b8-x2k4q` says nothing about which of them it is from.
//! The name (`basic.name`) and the labels (`basic.labels`) of a deployment
//! are what tells: they go into notifications, into the access log where
//! its format asks for them, and into the traces.

use std::sync::{LazyLock, OnceLock};

/// What a deployment is called when its configuration does not say.
pub const DEFAULT_IDENTITY_NAME: &str = "pingap";

/// The most labels a deployment has. They go into every notification.
const MAX_LABELS: usize = 16;
const MAX_LABEL_KEY: usize = 32;
const MAX_LABEL_VALUE: usize = 128;
const MAX_NAME: usize = 64;

#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    /// What the deployment is called (`basic.name`).
    pub name: String,
    /// Its labels (`basic.labels`), in the order they are written:
    /// `cluster` and `sh-prod`, `env` and `prod`.
    pub labels: Vec<(String, String)>,
}

impl Default for Identity {
    fn default() -> Self {
        Self {
            name: DEFAULT_IDENTITY_NAME.to_string(),
            labels: vec![],
        }
    }
}

impl Identity {
    /// The identity of a deployment with `name` and `labels`. No name, or
    /// one that is empty, is the default one.
    pub fn new(name: Option<&str>, labels: Vec<(String, String)>) -> Self {
        let name = name
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or(DEFAULT_IDENTITY_NAME);
        Self {
            name: name.to_string(),
            labels,
        }
    }
    /// Whether the deployment was given a name of its own.
    pub fn is_named(&self) -> bool {
        self.name != DEFAULT_IDENTITY_NAME
    }
    /// The value of the label `key`.
    pub fn label(&self, key: &str) -> Option<&str> {
        self.labels
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }
}

/// What a deployment may be called (`basic.name`): one line of at most
/// 64 bytes. It is put ahead of the title of a message and into the lines
/// of an access log.
pub fn parse_identity_name(name: Option<&str>) -> Result<(), String> {
    let name = name.unwrap_or_default().trim();
    if name.len() > MAX_NAME || name.chars().any(char::is_control) {
        return Err(format!(
            "name should be one line of at most {MAX_NAME} bytes"
        ));
    }
    Ok(())
}

static IDENTITY: OnceLock<Identity> = OnceLock::new();
static DEFAULT_IDENTITY: LazyLock<Identity> = LazyLock::new(Identity::default);

/// Notes who this process is. Once, when it starts: what is told with it
/// is put together from then on, and a second call changes nothing.
pub fn set_identity(identity: Identity) {
    IDENTITY.get_or_init(|| identity);
}

/// Who this process is: what [`set_identity`] was given, `pingap` without
/// labels before that.
pub fn get_identity() -> &'static Identity {
    IDENTITY.get().unwrap_or(&DEFAULT_IDENTITY)
}

/// The labels of a deployment, as the configuration has them
/// (`basic.labels`): each `key:value`. The key is made of letters, digits,
/// `_` and `-`, which is what every place that names one can write: a
/// template, a placeholder of the access log, a tag.
pub fn parse_labels(
    entries: &[String],
) -> Result<Vec<(String, String)>, String> {
    if entries.len() > MAX_LABELS {
        return Err(format!(
            "labels: {} of them, the most is {MAX_LABELS}",
            entries.len()
        ));
    }
    let mut labels: Vec<(String, String)> = Vec::with_capacity(entries.len());
    for item in entries {
        let invalid = |what: &str| {
            let key = item.split(':').next().unwrap_or_default().trim();
            format!("labels: {key:?} {what}")
        };
        let (key, value) = item
            .split_once(':')
            .ok_or_else(|| invalid("should be `key:value`"))?;
        let (key, value) = (key.trim(), value.trim());
        let named = !key.is_empty()
            && key.len() <= MAX_LABEL_KEY
            && key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !named {
            return Err(invalid(
                "should be a key of letters, digits, _ and -, at most 32",
            ));
        }
        if value.is_empty() {
            return Err(invalid("has no value"));
        }
        // `$ENV:NAME` has been replaced by now. What is left with a `$`
        // in front was meant to be read from somewhere and is not: a
        // `$FILE:`, a `$NAME`.
        if value.starts_with('$') {
            return Err(invalid(
                "has a value that starts with $, which is read as nothing: the value of a label comes from the environment as $ENV:NAME",
            ));
        }
        if value.len() > MAX_LABEL_VALUE || value.chars().any(char::is_control)
        {
            return Err(invalid(
                "has a value that is longer than 128 bytes, or not one line of text",
            ));
        }
        if labels.iter().any(|(name, _)| name == key) {
            return Err(invalid("is there twice"));
        }
        labels.push((key.to_string(), value.to_string()));
    }
    Ok(labels)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_identity() {
        let identity = Identity::default();
        assert_eq!("pingap", identity.name);
        assert_eq!(false, identity.is_named());
        assert_eq!(None, identity.label("cluster"));
        // No name, or none to speak of, is the default one.
        assert_eq!("pingap", Identity::new(None, vec![]).name);
        assert_eq!("pingap", Identity::new(Some("  "), vec![]).name);

        let labels = parse_labels(&[
            "cluster:sh-prod".to_string(),
            " env : prod ".to_string(),
        ])
        .unwrap();
        let identity = Identity::new(Some(" edge-sh "), labels);
        assert_eq!("edge-sh", identity.name);
        assert_eq!(true, identity.is_named());
        assert_eq!(Some("sh-prod"), identity.label("cluster"));
        assert_eq!(Some("prod"), identity.label("env"));
        assert_eq!(None, identity.label("region"));

        assert_eq!(Ok(()), parse_identity_name(None));
        assert_eq!(Ok(()), parse_identity_name(Some("edge-sh 上海")));
        assert_eq!(true, parse_identity_name(Some("a\nb")).is_err());
        assert_eq!(true, parse_identity_name(Some(&"n".repeat(65))).is_err());
        // Before anything is noted: the default.
        assert_eq!("pingap", get_identity().name);
    }

    #[test]
    fn test_parse_labels() {
        let parse = |entries: &[&str]| {
            let entries: Vec<String> =
                entries.iter().map(|item| item.to_string()).collect();
            parse_labels(&entries)
        };
        assert_eq!(Ok(vec![]), parse(&[]));
        // A value may have a colon of its own.
        assert_eq!(
            Ok(vec![("zone".to_string(), "cn-east:a".to_string())]),
            parse(&["zone:cn-east:a"])
        );
        for (entries, reason) in [
            (vec!["cluster"], "\"cluster\" should be `key:value`"),
            (vec![":sh"], "\"\" should be a key of"),
            (vec!["k8s.cluster:sh"], "\"k8s.cluster\" should be a key of"),
            (vec!["my cluster:sh"], "should be a key of"),
            (vec!["cluster:"], "\"cluster\" has no value"),
            (vec!["cluster: "], "\"cluster\" has no value"),
            (vec!["cluster:a\nb"], "not one line of text"),
            (vec!["cluster:$FILE:/etc/cluster"], "starts with $"),
            (vec!["cluster:$CLUSTER"], "starts with $"),
            (vec!["cluster:a", "cluster:b"], "\"cluster\" is there twice"),
        ] {
            let error = parse(&entries).unwrap_err();
            assert_eq!(true, error.contains(reason), "{entries:?}: {error}");
        }
        let long = format!("cluster:{}", "a".repeat(129));
        assert_eq!(true, parse(&[&long]).is_err());
        let key = format!("{}:a", "k".repeat(33));
        assert_eq!(true, parse(&[&key]).is_err());
        let many: Vec<String> = (0..17).map(|i| format!("k{i}:v")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(true, parse(&many).unwrap_err().contains("the most is 16"));
    }
}
