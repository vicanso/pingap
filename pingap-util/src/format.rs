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

/// Writes an integer without going through `fmt::Display`: this runs for
/// every access log line, and `itoa` is a table lookup where `write!` is
/// the formatting machinery.
#[inline]
fn write_number(writer: &mut impl Write, value: usize) {
    let _ = writer.write_str(itoa::Buffer::new().format(value));
}

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
        let value = $value; // Use the value as an integer.
        let mut handled = false;

        // Iterate through thresholds, largest unit first.
        $(
            if !handled && value >= $threshold {
                // 1. Calculate the whole and fractional parts using integer math.
                let whole_part = value / $divisor;
                let remainder = value % $divisor;

                // 2. Calculate the first decimal digit.
                // We multiply by 10 before dividing to get the digit.
                // E.g., for 1234 bytes -> 1234 % 1024 = 210. (210 * 10) / 1024 = 2.
                let decimal_digit = (remainder * 10) / $divisor;

                // 3. Write directly to the writer, avoiding intermediate strings.
                write_number($writer, whole_part);
                if decimal_digit > 0 {
                    // Only write the decimal part if it's not zero.
                    // This naturally handles the "strip .0" logic.
                    let _ = $writer.write_char('.');
                    write_number($writer, decimal_digit);
                }
                let _ = $writer.write_str($unit);

                handled = true;
            }
        )*

        // Fallback for the base unit.
        if !handled {
            write_number($writer, value);
            let _ = $writer.write_str($base_unit);
        }
    };
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
        assert_eq!(formatted_byte_size(0), "0B");
        assert_eq!(formatted_byte_size(999_999), "999.9KB");
        assert_eq!(formatted_byte_size(5 * 1_000_000_000), "5GB");

        // Any `fmt::Write` sink works, the access log writes into BytesMut.
        let mut bytes = bytes::BytesMut::new();
        format_byte_size(&mut bytes, 1500);
        assert_eq!(b"1.5KB", bytes.as_ref());
    }
}
