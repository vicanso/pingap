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

use std::fmt::Write;

/// A powerful macro to format a value with units, handling integer and fractional parts.
///
/// It takes a writer, a value, and a series of thresholds with their corresponding units and divisors.
macro_rules! format_with_units {
    (
        $writer:expr,
        $value:expr,
        $base_unit:expr,
        $( ($threshold:expr, $unit:expr, $divisor:expr) ),*
    ) => {
        let value_f = $value as f64;
        let mut handled = false;

        // Use a temporary variable to handle string-specific logic before writing.
        #[allow(unused_variables)]
        let temp_writer = "";

        // Iterate through the thresholds in reverse order (largest unit first).
        $(
            if !handled && value_f >= $threshold as f64 {
                let divisor_f = $divisor as f64;

                // 1. Format the number with one decimal place into a temporary String.
                let num_str = format!("{:.1}", value_f / divisor_f);

                // 2. Trim the ".0" suffix from the temporary string if it exists.
                let final_num_str = num_str.strip_suffix(".0").unwrap_or(&num_str);

                // 3. Write the final, trimmed number and the unit to the writer.
                let _ = write!($writer, "{}{}", final_num_str, $unit);

                handled = true;
            }
        )*

        // If no threshold was met, use the base unit.
        if !handled {
            let _ = write!($writer, "{}{}", $value, $base_unit);
        }
    };
}

/// Formats a duration in milliseconds into a human-readable string (ms, s).
pub fn format_duration(buf: &mut impl Write, ms: u64) {
    const SEC: u64 = 1_000;
    format_with_units!(buf, ms, "ms", (SEC, "s", SEC));
}

/// Formats a byte size into a human-readable string (B, KB, MB, GB).
pub fn format_byte_size(buf: &mut impl Write, size: usize) {
    const KB: usize = 1_000;
    const MB: usize = 1_000 * KB;
    const GB: usize = 1_000 * MB;
    format_with_units!(
        buf,
        size,
        "B",
        (GB, "GB", GB),
        (MB, "MB", MB),
        (KB, "KB", KB)
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    // ... (tests remain exactly the same and will pass) ...
    fn formatted_duration(ms: u64) -> String {
        let mut s = String::new();
        format_duration(&mut s, ms);
        s
    }

    fn formatted_byte_size(size: usize) -> String {
        let mut s = String::new();
        format_byte_size(&mut s, size);
        s
    }

    #[test]
    fn test_format_byte_size() {
        assert_eq!(formatted_byte_size(512), "512B");
        assert_eq!(formatted_byte_size(999), "999B");
        assert_eq!(formatted_byte_size(1000), "1KB");
        assert_eq!(formatted_byte_size(1024), "1KB");
        assert_eq!(formatted_byte_size(1124), "1.1KB");
        assert_eq!(formatted_byte_size(1220 * 1000), "1.2MB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(formatted_duration(100), "100ms");
        assert_eq!(formatted_duration(999), "999ms");
        assert_eq!(formatted_duration(1000), "1s");
        assert_eq!(formatted_duration(12400), "12.4s");
    }
}
