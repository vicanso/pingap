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

use bytes::BytesMut;

const SEC: u64 = 1_000;

/// Formats a duration in milliseconds into a human readable string
/// For durations < 1000ms, formats as milliseconds
/// For durations >= 1000ms, formats as seconds with up to one decimal place
///
/// # Arguments
/// * `buf` - BytesMut buffer to write the formatted string into
/// * `ms` - Duration in milliseconds to format
///
/// # Returns
/// BytesMut buffer containing the formatted string
#[inline]
pub fn format_duration(mut buf: BytesMut, ms: u64) -> BytesMut {
    if ms < 1000 {
        buf.extend(itoa::Buffer::new().format(ms).as_bytes());
        buf.extend(b"ms");
    } else {
        buf.extend(itoa::Buffer::new().format(ms / SEC).as_bytes());
        let value = (ms % SEC) / 100;
        if value != 0 {
            buf.extend(b".");
            buf.extend(itoa::Buffer::new().format(value).as_bytes());
        }
        buf.extend(b"s");
    }
    buf
}

const B_100: usize = 100;
const KB: usize = 1_000;
const KB_100: usize = 100 * KB;
const MB: usize = 1_000_000;
const MB_100: usize = 100 * MB;
const GB: usize = 1_000_000_000;

/// Formats a byte size into a human readable string with appropriate units (B, KB, MB, GB)
/// The function will add decimal points for values between units (e.g., 1.5KB)
///
/// # Arguments
/// * `buf` - BytesMut buffer to write the formatted string into
/// * `size` - Size in bytes to format
///
/// # Returns
/// BytesMut buffer containing the formatted string
#[inline]
pub fn format_byte_size(mut buf: BytesMut, size: usize) -> BytesMut {
    if size < KB {
        buf.extend(itoa::Buffer::new().format(size).as_bytes());
        buf.extend(b"B");
    } else if size < MB {
        buf.extend(itoa::Buffer::new().format(size / KB).as_bytes());
        let value = (size % KB) / B_100;
        if value != 0 {
            buf.extend(b".");
            buf.extend(itoa::Buffer::new().format(value).as_bytes());
        }
        buf.extend(b"KB");
    } else if size < GB {
        buf.extend(itoa::Buffer::new().format(size / MB).as_bytes());
        let value = (size % MB) / KB_100;
        if value != 0 {
            buf.extend(b".");
            buf.extend(itoa::Buffer::new().format(value).as_bytes());
        }
        buf.extend(b"MB");
    } else {
        buf.extend(itoa::Buffer::new().format(size / GB).as_bytes());
        let value = (size % GB) / MB_100;
        if value != 0 {
            buf.extend(b".");
            buf.extend(itoa::Buffer::new().format(value).as_bytes());
        }
        buf.extend(b"GB");
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_byte_size() {
        let mut buf = BytesMut::with_capacity(1024);
        buf = format_byte_size(buf, 512);
        assert_eq!(
            "512B",
            std::string::String::from_utf8_lossy(&buf).to_string()
        );

        buf.clear();
        buf = format_byte_size(buf, 1024);
        assert_eq!(
            "1KB",
            std::string::String::from_utf8_lossy(&buf).to_string()
        );

        buf.clear();
        buf = format_byte_size(buf, 1124);
        assert_eq!(
            "1.1KB",
            std::string::String::from_utf8_lossy(&buf).to_string()
        );

        buf.clear();
        buf = format_byte_size(buf, 1020 * 1000);
        assert_eq!(
            "1MB",
            std::string::String::from_utf8_lossy(&buf).to_string()
        );

        buf.clear();
        buf = format_byte_size(buf, 1220 * 1000);
        assert_eq!(
            "1.2MB",
            std::string::String::from_utf8_lossy(&buf).to_string()
        );

        buf.clear();
        buf = format_byte_size(buf, 122220 * 1000);
        assert_eq!(
            "122.2MB",
            std::string::String::from_utf8_lossy(&buf).to_string()
        );

        buf.clear();
        buf = format_byte_size(buf, 1000 * 1000 * 1000 + 500 * 1000 * 1000);
        assert_eq!(
            "1.5GB",
            std::string::String::from_utf8_lossy(&buf).to_string()
        );
    }

    #[test]
    fn test_format_duration() {
        let mut buf = BytesMut::with_capacity(1024);
        buf = format_duration(buf, 100);
        assert_eq!(
            "100ms",
            std::string::String::from_utf8_lossy(&buf).to_string()
        );

        buf.clear();
        buf = format_duration(buf, 12400);
        assert_eq!(
            "12.4s",
            std::string::String::from_utf8_lossy(&buf).to_string()
        );
    }
}
