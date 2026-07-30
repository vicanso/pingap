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

//! Host-bucket index for location routing.
//!
//! Locations on a server are still ordered by weight. The index only shrinks
//! the candidate set for a given `Host` header so we do not run path/condition
//! matching on every location when hosts are diverse.
//!
//! Buckets (a location may appear in several):
//! 1. exact host map
//! 2. suffix / `*.domain` list
//! 3. regex host list
//! 4. "any host" list
//!
//! Candidates are merged and sorted by their original weight index so the
//! first full match is identical to a linear scan of the ordered list.

use super::location::{HostIndexEntry, Location, host_matches_suffix};
use ahash::AHashMap;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Precomputed host buckets for a weight-ordered location list.
#[derive(Debug, Clone, Default)]
pub struct LocationHostIndex {
    /// Weight-descending location names (same order as the server's list).
    ordered: Vec<String>,
    /// Exact host → indices into `ordered`.
    exact: AHashMap<String, Vec<u16>>,
    /// `(domain, indices)` for `*.domain` patterns.
    suffixes: Vec<(String, Vec<u16>)>,
    /// Locations with at least one regex host pattern.
    regex: Vec<u16>,
    /// Locations with no host restriction.
    any: Vec<u16>,
}

impl LocationHostIndex {
    /// Build an index from a weight-ordered name list.
    ///
    /// `resolve` must return the live [`Location`] for each name; missing names
    /// are skipped (they cannot match at runtime either).
    pub fn build(
        ordered_names: &[String],
        mut resolve: impl FnMut(&str) -> Option<Arc<Location>>,
    ) -> Self {
        let mut exact: AHashMap<String, Vec<u16>> = AHashMap::new();
        let mut suffix_map: AHashMap<String, Vec<u16>> = AHashMap::new();
        let mut regex = Vec::new();
        let mut any = Vec::new();

        for (i, name) in ordered_names.iter().enumerate() {
            let Some(location) = resolve(name.as_str()) else {
                continue;
            };
            let idx = i as u16;
            for entry in location.host_index_entries() {
                match entry {
                    HostIndexEntry::Exact(host) => {
                        exact.entry(host).or_default().push(idx);
                    },
                    HostIndexEntry::Suffix(domain) => {
                        suffix_map.entry(domain).or_default().push(idx);
                    },
                    HostIndexEntry::Regex => {
                        if !regex.contains(&idx) {
                            regex.push(idx);
                        }
                    },
                    HostIndexEntry::Any => {
                        if !any.contains(&idx) {
                            any.push(idx);
                        }
                    },
                }
            }
        }

        let mut suffixes: Vec<(String, Vec<u16>)> =
            suffix_map.into_iter().collect();
        // Longer suffixes first so more specific wildcards are easy to reason
        // about when debugging (order among suffixes does not affect correctness
        // because we re-sort candidate indices by weight).
        suffixes.sort_by_key(|b| std::cmp::Reverse(b.0.len()));

        Self {
            ordered: ordered_names.to_vec(),
            exact,
            suffixes,
            regex,
            any,
        }
    }

    /// Weight-ordered location names.
    #[inline]
    pub fn ordered(&self) -> &[String] {
        &self.ordered
    }

    /// Indices into [`Self::ordered`] that may match `host`, in weight order.
    ///
    /// Always includes regex-host and any-host locations. Exact and suffix
    /// buckets contribute only when the request host matches.
    pub fn candidate_indices(&self, host: &str) -> Vec<usize> {
        let host_lower = host.to_ascii_lowercase();
        // BTreeSet keeps indices sorted → weight order of `ordered`.
        let mut set = BTreeSet::new();

        if let Some(idxs) = self.exact.get(&host_lower) {
            set.extend(idxs.iter().map(|&i| i as usize));
        }
        for (domain, idxs) in &self.suffixes {
            if host_matches_suffix(&host_lower, domain) {
                set.extend(idxs.iter().map(|&i| i as usize));
            }
        }
        set.extend(self.regex.iter().map(|&i| i as usize));
        set.extend(self.any.iter().map(|&i| i as usize));

        set.into_iter().collect()
    }

    /// Convenience: candidate location names in weight order.
    pub fn candidate_names(&self, host: &str) -> Vec<&str> {
        self.candidate_indices(host)
            .into_iter()
            .filter_map(|i| self.ordered.get(i).map(String::as_str))
            .collect()
    }
}

/// A server's weight-ordered locations plus the host index used for routing.
#[derive(Debug, Clone)]
pub struct ServerLocationRoute {
    pub ordered: Arc<Vec<String>>,
    pub host_index: Arc<LocationHostIndex>,
}

impl ServerLocationRoute {
    pub fn new(ordered: Vec<String>, host_index: LocationHostIndex) -> Self {
        Self {
            ordered: Arc::new(ordered),
            host_index: Arc::new(host_index),
        }
    }

    /// Build from weight-ordered names, resolving each location for host buckets.
    pub fn build(
        ordered: Vec<String>,
        resolve: impl FnMut(&str) -> Option<Arc<Location>>,
    ) -> Self {
        let host_index = LocationHostIndex::build(&ordered, resolve);
        Self::new(ordered, host_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pingap_config::LocationConf;
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;

    fn loc(
        name: &str,
        host: Option<&str>,
        path: Option<&str>,
    ) -> Arc<Location> {
        Arc::new(
            Location::new(
                name,
                &LocationConf {
                    host: host.map(str::to_string),
                    path: path.map(str::to_string),
                    upstream: Some("up".to_string()),
                    ..Default::default()
                },
            )
            .unwrap(),
        )
    }

    #[test]
    fn test_host_index_buckets_and_weight_order() {
        // Weight order is the order of `ordered` (already sorted by caller).
        // high weight first:
        // 0: any host, path /api  — would match everything under /api
        // 1: exact api.example.com
        // 2: suffix *.example.com
        // 3: regex ~^foo
        let map: HashMap<&str, Arc<Location>> = [
            ("any_api", loc("any_api", None, Some("/api"))),
            ("exact", loc("exact", Some("api.example.com"), Some("/"))),
            ("wild", loc("wild", Some("*.example.com"), Some("/"))),
            ("re", loc("re", Some("~^foo"), Some("/"))),
        ]
        .into_iter()
        .collect();

        let ordered = vec![
            "any_api".to_string(),
            "exact".to_string(),
            "wild".to_string(),
            "re".to_string(),
        ];
        let index = LocationHostIndex::build(&ordered, |n| map.get(n).cloned());

        // api.example.com: exact + suffix (subdomain of example.com) + any + regex
        let names = index.candidate_names("api.example.com");
        assert_eq!(names, vec!["any_api", "exact", "wild", "re"]);

        // other.example.com: suffix + any + regex (no exact)
        let names = index.candidate_names("other.example.com");
        assert_eq!(names, vec!["any_api", "wild", "re"]);

        // host matching the regex pattern: any + regex
        let names = index.candidate_names("foo.bar");
        assert_eq!(names, vec!["any_api", "re"]);

        // unrelated host: still any + regex (regex hosts cannot be excluded by index)
        let names = index.candidate_names("zzz");
        assert_eq!(names, vec!["any_api", "re"]);
    }

    #[test]
    fn test_candidate_order_matches_weight_not_bucket_order() {
        // exact is later in weight order than any — any must still come first
        // so the first full path match can prefer the higher-weight any rule.
        let map: HashMap<&str, Arc<Location>> = [
            ("any", loc("any", None, Some("/"))),
            ("exact", loc("exact", Some("h.com"), Some("/"))),
        ]
        .into_iter()
        .collect();
        let ordered = vec!["any".to_string(), "exact".to_string()];
        let index = LocationHostIndex::build(&ordered, |n| map.get(n).cloned());
        assert_eq!(index.candidate_names("h.com"), vec!["any", "exact"]);
    }

    #[test]
    fn test_suffix_does_not_match_apex() {
        let map: HashMap<&str, Arc<Location>> =
            [("wild", loc("wild", Some("*.example.com"), Some("/")))]
                .into_iter()
                .collect();
        let ordered = vec!["wild".to_string()];
        let index = LocationHostIndex::build(&ordered, |n| map.get(n).cloned());
        assert!(index.candidate_names("example.com").is_empty());
        assert_eq!(index.candidate_names("a.example.com"), vec!["wild"]);
    }
}
