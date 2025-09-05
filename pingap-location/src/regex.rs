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

use ahash::AHashMap;
use regex::Regex;

/// RegexCapture provides a way to extract named captures from regex matches
#[derive(Debug, Clone)]
pub struct RegexCapture {
    // The compiled regular expression
    re: Regex,
}

impl RegexCapture {
    /// Creates a new RegexCapture instance from a regex pattern string
    /// Returns Result<RegexCapture, regex::Error> where Error occurs if the pattern is invalid
    pub fn new(value: &str) -> Result<Self, regex::Error> {
        // Compile the regex pattern
        let re = Regex::new(value)?;
        Ok(RegexCapture { re })
    }

    /// Attempts to match the regex pattern against a string and extract named captures
    /// Returns a tuple containing:
    /// - bool: whether the pattern matched at all
    #[inline]
    pub fn captures(
        &self,
        value: &str,
    ) -> (bool, Option<AHashMap<String, String>>) {
        // get captures, if not matched, return false
        let Some(captures) = self.re.captures(value) else {
            return (false, None);
        };

        let mut capture_variables = None;

        // iterate all named capture groups
        for name in self.re.capture_names().flatten() {
            if let Some(match_value) = captures.name(name) {
                let values =
                    capture_variables.get_or_insert_with(AHashMap::new);
                values
                    .insert(name.to_string(), match_value.as_str().to_string());
            }
        }

        // return true if matched
        (true, capture_variables)
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
        let (matched, capture_variables) = re.captures("2024-03-14");
        assert_eq!(true, matched);
        let capture_variables = capture_variables.unwrap();
        assert_eq!("2024", capture_variables.get("year").unwrap());
        assert_eq!("03", capture_variables.get("month").unwrap());
        assert_eq!("14", capture_variables.get("day").unwrap());
        assert_eq!(3, capture_variables.len());
    }
}
