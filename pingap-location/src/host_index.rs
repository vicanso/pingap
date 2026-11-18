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
use smallvec::SmallVec;
use std::ops::Deref;
use std::sync::Arc;

/// Weight-ordered location indices returned by [`LocationHostIndex::candidate_indices`].
///
/// Borrows a precomputed slice in the common cases (no host buckets, an exact
/// host hit, or at most one matching wildcard suffix) and falls back to a
/// stack-backed [`SmallVec`] only when two or more wildcard suffixes match
/// the same non-exact host.
#[derive(Debug, Clone)]
pub enum CandidateIndices<'a> {
    Borrowed(&'a [usize]),
    Inline(SmallVec<[usize; 16]>),
}

impl CandidateIndices<'_> {
    #[inline]
    pub fn as_slice(&self) -> &[usize] {
        match self {
            Self::Borrowed(slice) => slice,
            Self::Inline(vec) => vec.as_slice(),
        }
    }
}

impl Deref for CandidateIndices<'_> {
    type Target = [usize];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl PartialEq for CandidateIndices<'_> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for CandidateIndices<'_> {}

impl PartialEq<[usize]> for CandidateIndices<'_> {
    #[inline]
    fn eq(&self, other: &[usize]) -> bool {
        self.as_slice() == other
    }
}

impl PartialEq<&[usize]> for CandidateIndices<'_> {
    #[inline]
    fn eq(&self, other: &&[usize]) -> bool {
        self.as_slice() == *other
    }
}

impl PartialEq<Vec<usize>> for CandidateIndices<'_> {
    #[inline]
    fn eq(&self, other: &Vec<usize>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl PartialEq<CandidateIndices<'_>> for Vec<usize> {
    #[inline]
    fn eq(&self, other: &CandidateIndices<'_>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

/// Iterator over [`CandidateIndices`], yielding `usize` indices in weight order.
pub enum CandidateIndicesIter<'a> {
    Borrowed(std::slice::Iter<'a, usize>),
    Inline(smallvec::IntoIter<[usize; 16]>),
}

impl Iterator for CandidateIndicesIter<'_> {
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Borrowed(iter) => iter.next().copied(),
            Self::Inline(iter) => iter.next(),
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Borrowed(iter) => iter.size_hint(),
            Self::Inline(iter) => iter.size_hint(),
        }
    }
}

impl ExactSizeIterator for CandidateIndicesIter<'_> {}

impl<'a> IntoIterator for CandidateIndices<'a> {
    type Item = usize;
    type IntoIter = CandidateIndicesIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::Borrowed(slice) => {
                CandidateIndicesIter::Borrowed(slice.iter())
            },
            Self::Inline(vec) => CandidateIndicesIter::Inline(vec.into_iter()),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct SuffixBucket {
    domain: String,
    raw: Vec<usize>,
    with_always: Vec<usize>,
}

#[derive(Default)]
struct RawBuckets {
    exact: AHashMap<String, Vec<usize>>,
    suffix: AHashMap<String, Vec<usize>>,
    always: Vec<usize>,
}

fn collect_raw_buckets(
    ordered_names: &[String],
    mut resolve: impl FnMut(&str) -> Option<Arc<Location>>,
) -> RawBuckets {
    let mut raw = RawBuckets::default();
    for (idx, name) in ordered_names.iter().enumerate() {
        let Some(location) = resolve(name.as_str()) else {
            continue;
        };
        for entry in location.host_index_entries() {
            match entry {
                HostIndexEntry::Exact(host) => {
                    raw.exact.entry(host).or_default().push(idx);
                },
                HostIndexEntry::Suffix(domain) => {
                    raw.suffix.entry(domain).or_default().push(idx);
                },
                HostIndexEntry::Regex | HostIndexEntry::Any => {
                    if raw.always.last().copied() != Some(idx) {
                        raw.always.push(idx);
                    }
                },
            }
        }
    }
    raw.always.sort_unstable();
    raw.always.dedup();
    raw
}

fn merge_with_always(base: &[usize], always: &[usize]) -> Vec<usize> {
    let mut merged = Vec::with_capacity(base.len() + always.len());
    merged.extend_from_slice(base);
    merged.extend_from_slice(always);
    merged.sort_unstable();
    merged.dedup();
    merged
}

/// Precomputed host buckets for a weight-ordered location list.
#[derive(Debug, Clone, Default)]
pub struct LocationHostIndex {
    /// Weight-descending location names (same order as the server's list),
    /// shared with the [`ServerLocationRoute`] built from it.
    ordered: Arc<Vec<String>>,
    /// Exact host (lowercased) → pre-merged indices into `ordered`.
    exact: AHashMap<String, Vec<usize>>,
    /// `(domain, bucket)` for `*.domain` patterns, longer domains first.
    suffixes: Vec<SuffixBucket>,
    /// Sorted, deduplicated indices for regex-host and any-host locations.
    always: Vec<usize>,
}

impl LocationHostIndex {
    /// Build an index from a weight-ordered name list.
    ///
    /// `resolve` must return the live [`Location`] for each name; missing names
    /// are skipped (they cannot match at runtime either).
    pub fn build(
        ordered_names: &[String],
        resolve: impl FnMut(&str) -> Option<Arc<Location>>,
    ) -> Self {
        let raw = collect_raw_buckets(ordered_names, resolve);
        let mut suffix_pairs: Vec<(String, Vec<usize>)> =
            raw.suffix.into_iter().collect();
        // Longer suffixes first so more specific wildcards are easy to reason
        // about when debugging (order among suffixes does not affect correctness
        // because indices are kept in weight order).
        suffix_pairs.sort_by_key(|b| std::cmp::Reverse(b.0.len()));

        let suffixes: Vec<SuffixBucket> = suffix_pairs
            .into_iter()
            .map(|(domain, mut indices)| {
                indices.sort_unstable();
                indices.dedup();
                let with_always = merge_with_always(&indices, &raw.always);
                SuffixBucket {
                    domain,
                    raw: indices,
                    with_always,
                }
            })
            .collect();

        let exact = raw
            .exact
            .into_iter()
            .map(|(host, mut indices)| {
                for bucket in &suffixes {
                    if host_matches_suffix(&host, &bucket.domain) {
                        indices.extend_from_slice(&bucket.raw);
                    }
                }
                indices.extend_from_slice(&raw.always);
                indices.sort_unstable();
                indices.dedup();
                (host, indices)
            })
            .collect();

        Self {
            ordered: Arc::new(ordered_names.to_vec()),
            exact,
            suffixes,
            always: raw.always,
        }
    }

    /// Weight-ordered location names.
    #[inline]
    pub fn ordered(&self) -> &[String] {
        &self.ordered
    }

    #[inline]
    fn lookup_exact(&self, host: &str) -> Option<&[usize]> {
        if self.exact.is_empty() {
            return None;
        }
        if !host.bytes().any(|b| b.is_ascii_uppercase()) {
            return self.exact.get(host).map(Vec::as_slice);
        }
        if host.len() <= 256 {
            let mut buf = [0u8; 256];
            for (dst, src) in buf.iter_mut().zip(host.as_bytes()) {
                *dst = src.to_ascii_lowercase();
            }
            let lower = std::str::from_utf8(&buf[..host.len()]).ok()?;
            return self.exact.get(lower).map(Vec::as_slice);
        }
        let lower = host.to_ascii_lowercase();
        self.exact.get(lower.as_str()).map(Vec::as_slice)
    }

    #[inline]
    fn lookup_suffixes(&self, host: &str) -> CandidateIndices<'_> {
        let mut first: Option<&SuffixBucket> = None;
        let mut merged: Option<SmallVec<[usize; 16]>> = None;
        for bucket in &self.suffixes {
            if !host_matches_suffix(host, &bucket.domain) {
                continue;
            }
            if let Some(buf) = merged.as_mut() {
                buf.extend_from_slice(&bucket.raw);
            } else if let Some(prev) = first.take() {
                let mut buf = SmallVec::with_capacity(
                    prev.with_always.len() + bucket.raw.len(),
                );
                buf.extend_from_slice(&prev.with_always);
                buf.extend_from_slice(&bucket.raw);
                merged = Some(buf);
            } else {
                first = Some(bucket);
            }
        }
        if let Some(mut buf) = merged {
            buf.sort_unstable();
            buf.dedup();
            return CandidateIndices::Inline(buf);
        }
        if let Some(bucket) = first {
            return CandidateIndices::Borrowed(&bucket.with_always);
        }
        CandidateIndices::Borrowed(&self.always)
    }

    /// Indices into [`Self::ordered`] that may match `host`, in weight order.
    ///
    /// Always includes regex-host and any-host locations. Exact and suffix
    /// buckets contribute only when the request host matches. Common lookups
    /// borrow a pre-merged slice with zero heap allocation; only a non-exact
    /// host matching two or more wildcard suffixes merges into an inline
    /// `SmallVec`.
    #[inline]
    pub fn candidate_indices(&self, host: &str) -> CandidateIndices<'_> {
        if self.exact.is_empty() && self.suffixes.is_empty() {
            return CandidateIndices::Borrowed(&self.always);
        }
        if let Some(merged) = self.lookup_exact(host) {
            return CandidateIndices::Borrowed(merged);
        }
        self.lookup_suffixes(host)
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
    /// The location of each name in `ordered`, as it was when the route was
    /// built; `None` for a name that named none. Empty for a route made
    /// with [`ServerLocationRoute::new`].
    locations: Arc<Vec<Option<Arc<Location>>>>,
}

impl ServerLocationRoute {
    pub fn new(ordered: Vec<String>, host_index: LocationHostIndex) -> Self {
        Self {
            ordered: Arc::new(ordered),
            host_index: Arc::new(host_index),
            locations: Arc::new(vec![]),
        }
    }

    /// Build from weight-ordered names, resolving each location for host
    /// buckets. The route and its index share one copy of the names.
    ///
    /// The locations are kept. Matching a request used to look each
    /// candidate up by name again - a hash of the name and a reference
    /// count taken and given back, per candidate, on counters every worker
    /// thread shares. The route is rebuilt whenever a location changes, so
    /// what it holds is what the names stand for.
    pub fn build(
        ordered: Vec<String>,
        mut resolve: impl FnMut(&str) -> Option<Arc<Location>>,
    ) -> Self {
        let locations: Vec<Option<Arc<Location>>> =
            ordered.iter().map(|name| resolve(name)).collect();
        let by_name: AHashMap<&str, &Arc<Location>> = ordered
            .iter()
            .zip(locations.iter())
            .filter_map(|(name, location)| {
                Some((name.as_str(), location.as_ref()?))
            })
            .collect();
        let host_index = LocationHostIndex::build(&ordered, |name| {
            by_name.get(name).cloned().cloned()
        });
        Self {
            ordered: host_index.ordered.clone(),
            host_index: Arc::new(host_index),
            locations: Arc::new(locations),
        }
    }

    /// The location at `index` of `ordered`, if the route holds it.
    #[inline]
    pub fn location(&self, index: usize) -> Option<&Arc<Location>> {
        self.locations.get(index)?.as_ref()
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
    fn test_route_holds_its_locations() {
        let api = loc("api", Some("api.example.com"), Some("/"));
        let web = loc("web", None, Some("/"));
        let all: HashMap<&str, Arc<Location>> =
            HashMap::from([("api", api.clone()), ("web", web.clone())]);
        let route = ServerLocationRoute::build(
            vec!["api".to_string(), "gone".to_string(), "web".to_string()],
            |name| all.get(name).cloned(),
        );
        // The very instances that were resolved, by the index of the name.
        assert_eq!(true, Arc::ptr_eq(&api, route.location(0).unwrap()));
        assert_eq!(true, route.location(1).is_none());
        assert_eq!(true, Arc::ptr_eq(&web, route.location(2).unwrap()));
        assert_eq!(true, route.location(3).is_none());
        assert_eq!(
            vec![0, 2],
            route.host_index.candidate_indices("api.example.com")
        );

        // Made from names alone: nothing is held.
        let route = ServerLocationRoute::new(
            vec!["api".to_string()],
            LocationHostIndex::default(),
        );
        assert_eq!(true, route.location(0).is_none());
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

    /// Case differences in the request host reach the same buckets.
    #[test]
    fn test_candidates_ignore_host_case() {
        let map: HashMap<&str, Arc<Location>> = [
            ("exact", loc("exact", Some("API.Example.com"), Some("/"))),
            ("wild", loc("wild", Some("*.Example.com"), Some("/"))),
        ]
        .into_iter()
        .collect();
        let ordered = vec!["exact".to_string(), "wild".to_string()];
        let index = LocationHostIndex::build(&ordered, |n| map.get(n).cloned());
        assert_eq!(
            index.candidate_names("api.example.com"),
            vec!["exact", "wild"]
        );
        assert_eq!(
            index.candidate_names("Api.EXAMPLE.com"),
            vec!["exact", "wild"]
        );
        assert_eq!(index.candidate_names("other.example.COM"), vec!["wild"]);
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

    #[test]
    fn test_candidate_indices_borrowed_vs_multi_suffix_inline() {
        let map: HashMap<&str, Arc<Location>> = [
            (
                "sub_wild",
                loc("sub_wild", Some("*.sub.example.com"), Some("/")),
            ),
            (
                "exact",
                loc("exact", Some("api.sub.example.com"), Some("/")),
            ),
            (
                "top_wild",
                loc("top_wild", Some("*.example.com"), Some("/")),
            ),
            ("any", loc("any", None, Some("/"))),
        ]
        .into_iter()
        .collect();
        let ordered = vec![
            "sub_wild".to_string(),
            "exact".to_string(),
            "top_wild".to_string(),
            "any".to_string(),
        ];
        let index = LocationHostIndex::build(&ordered, |n| map.get(n).cloned());

        // Exact host also matching two wildcards and `any`: pre-merged, borrowed.
        let exact = index.candidate_indices("API.sub.example.com");
        assert_eq!(true, matches!(exact, CandidateIndices::Borrowed(_)));
        assert_eq!(vec![0, 1, 2, 3], exact);

        // Non-exact host matching two wildcards: inline SmallVec merge.
        let multi = index.candidate_indices("other.sub.example.com");
        assert_eq!(true, matches!(multi, CandidateIndices::Inline(_)));
        assert_eq!(vec![0, 2, 3], multi);

        // Single wildcard match: pre-merged, borrowed.
        let single = index.candidate_indices("other.example.com");
        assert_eq!(true, matches!(single, CandidateIndices::Borrowed(_)));
        assert_eq!(vec![2, 3], single);

        // Zero wildcard/exact match: borrows `always`.
        let none = index.candidate_indices("unrelated.org");
        assert_eq!(true, matches!(none, CandidateIndices::Borrowed(_)));
        assert_eq!(vec![3], none);

        // Pure any-host index: fast path borrows `always` directly.
        let any_only = LocationHostIndex::build(&["any".to_string()], |n| {
            map.get(n).cloned()
        });
        let res = any_only.candidate_indices("anything.test");
        assert_eq!(true, matches!(res, CandidateIndices::Borrowed(_)));
        assert_eq!(vec![0], res);
    }
}
