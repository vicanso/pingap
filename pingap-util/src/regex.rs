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

use regex::Regex;

/// RegexCapture provides a way to extract named captures from regex matches
///
/// # Example
/// ```
/// use pingap::pingap_util::RegexCapture;
/// let re = RegexCapture::new(r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})").unwrap();
/// let (matched, captures) = re.captures("2024-03-14");
/// assert_eq!(true, matched);
/// assert_eq!(Some(vec![("year".to_string(), "2024".to_string()), ("month".to_string(), "03".to_string()), ("day".to_string(), "14".to_string())]), captures);
/// ```
#[derive(Debug, Clone)]
pub struct RegexCapture {
    // The compiled regular expression
    re: Regex,
    // Vector storing the names of capture groups in order
    keys: Vec<String>,
}

impl RegexCapture {
    /// Creates a new RegexCapture instance from a regex pattern string
    /// Returns Result<RegexCapture, regex::Error> where Error occurs if the pattern is invalid
    pub fn new(value: &str) -> Result<Self, regex::Error> {
        // Compile the regex pattern
        let re = Regex::new(value)?;
        let mut keys = vec![];
        // Extract all named capture groups from the regex
        for name in re.capture_names() {
            keys.push(name.unwrap_or_default().to_string());
        }
        Ok(RegexCapture { re, keys })
    }

    /// Attempts to match the regex pattern against a string and extract named captures
    /// Returns a tuple containing:
    /// - bool: whether the pattern matched at all
    /// - Option<Vec<(String, String)>>: if matched, returns vector of (capture_name, captured_value) pairs
    pub fn captures(
        &self,
        value: &str,
    ) -> (bool, Option<Vec<(String, String)>>) {
        let re = &self.re;
        // Check if the pattern matches at all
        if !re.is_match(value) {
            return (false, None);
        }

        let mut arr = vec![];
        // Try to get the actual captures
        let Some(cap) = re.captures(value) else {
            return (true, Some(arr));
        };

        let keys = &self.keys;
        // Iterate through all captures
        for (index, value) in cap.iter().enumerate() {
            // Skip if we've run out of named captures
            if index >= keys.len() {
                continue;
            }
            let key = &keys[index];
            // Skip unnamed captures (index 0 is always the full match)
            if key.is_empty() {
                continue;
            }
            // Skip None values (unmatched optional groups)
            let Some(value) = value else {
                continue;
            };
            // Add the (capture_name, captured_value) pair to results
            arr.push((key.to_string(), value.as_str().to_string()));
        }
        (true, Some(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_regex_capture() {
        let re = RegexCapture::new(
            r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})",
        )
        .unwrap();
        let (matched, captures) = re.captures("2024-03-14");
        assert_eq!(true, matched);
        assert_eq!(
            Some(vec![
                ("year".to_string(), "2024".to_string()),
                ("month".to_string(), "03".to_string()),
                ("day".to_string(), "14".to_string()),
            ]),
            captures
        );
    }
}
