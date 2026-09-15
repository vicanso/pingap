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

//! The error page template, split into literal text and placeholders once
//! when the server is built. Rendering an error used to run three
//! `str::replace` passes over the whole template, each producing a copy;
//! every unmatched route (a 404) paid for that.

/// One piece of the template.
#[derive(Debug, Clone, PartialEq)]
enum Segment {
    Literal(String),
    Version,
    Content,
    ErrorType,
}

/// A pre-parsed error page template with `{{version}}`, `{{content}}` and
/// `{{error_type}}` placeholders.
#[derive(Debug, Clone)]
pub struct ErrorTemplate {
    segments: Vec<Segment>,
    /// Length of the literal text, the floor of a rendered page.
    literal_len: usize,
    /// The page starts with `{`, so it is served as JSON.
    json: bool,
}

impl ErrorTemplate {
    pub fn new(template: &str) -> Self {
        let mut segments = vec![];
        let mut literal_len = 0;
        let mut rest = template;
        while let Some(start) = rest.find("{{") {
            let Some(len) = rest[start + 2..].find("}}") else {
                break;
            };
            let name = &rest[start + 2..start + 2 + len];
            let placeholder = match name.trim() {
                "version" => Segment::Version,
                "content" => Segment::Content,
                "error_type" => Segment::ErrorType,
                // Not a placeholder: keep the text and look past it.
                _ => {
                    let end = start + 2 + len + 2;
                    Self::push_literal(
                        &mut segments,
                        &mut literal_len,
                        &rest[..end],
                    );
                    rest = &rest[end..];
                    continue;
                },
            };
            Self::push_literal(&mut segments, &mut literal_len, &rest[..start]);
            segments.push(placeholder);
            rest = &rest[start + 2 + len + 2..];
        }
        Self::push_literal(&mut segments, &mut literal_len, rest);
        Self {
            segments,
            literal_len,
            json: template.trim_start().starts_with('{'),
        }
    }

    fn push_literal(
        segments: &mut Vec<Segment>,
        literal_len: &mut usize,
        text: &str,
    ) {
        if text.is_empty() {
            return;
        }
        *literal_len += text.len();
        if let Some(Segment::Literal(last)) = segments.last_mut() {
            last.push_str(text);
        } else {
            segments.push(Segment::Literal(text.to_string()));
        }
    }

    /// Whether the rendered page is JSON rather than HTML.
    pub fn is_json(&self) -> bool {
        self.json
    }

    /// The page for one error, built in a single pass into a buffer of the
    /// right size.
    pub fn render(
        &self,
        version: &str,
        content: &str,
        error_type: &str,
    ) -> String {
        let mut out = String::with_capacity(
            self.literal_len + version.len() + content.len() + error_type.len(),
        );
        for segment in &self.segments {
            out.push_str(match segment {
                Segment::Literal(text) => text,
                Segment::Version => version,
                Segment::Content => content,
                Segment::ErrorType => error_type,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::ErrorTemplate;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_render_matches_replace() {
        let template = include_str!("error.html");
        let expected = template
            .replace("{{version}}", "1.2.3")
            .replace("{{content}}", "boom")
            .replace("{{error_type}}", "InternalError");
        let parsed = ErrorTemplate::new(template);
        assert_eq!(expected, parsed.render("1.2.3", "boom", "InternalError"));
        assert_eq!(false, parsed.is_json());
    }

    #[test]
    fn test_placeholders_and_literals() {
        let parsed = ErrorTemplate::new(
            r#"{"v":"{{version}}","e":"{{ error_type }}","m":"{{content}}","x":"{{other}}","y":"{{"}"#,
        );
        assert_eq!(true, parsed.is_json());
        assert_eq!(
            r#"{"v":"1","e":"T","m":"c","x":"{{other}}","y":"{{"}"#,
            parsed.render("1", "c", "T")
        );
        // A placeholder can appear more than once, and text without any is
        // returned as it is.
        assert_eq!(
            "a-a",
            ErrorTemplate::new("{{content}}-{{content}}").render("v", "a", "t")
        );
        assert_eq!("plain", ErrorTemplate::new("plain").render("v", "c", "t"));
        assert_eq!("", ErrorTemplate::new("").render("v", "c", "t"));
    }
}
