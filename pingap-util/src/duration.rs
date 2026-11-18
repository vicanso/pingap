// Copyright 2024-2026 Tree xie.
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

use std::fmt;
use std::str::{Chars, FromStr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SECONDS_PER_YEAR: u64 = 31_557_600; // 365.25 days
const SECONDS_PER_MONTH: u64 = 2_630_016; // 30.44 days
const SECONDS_PER_WEEK: u64 = 604_800;
const SECONDS_PER_DAY: u64 = 86_400;
const SECONDS_PER_HOUR: u64 = 3_600;
const SECONDS_PER_MINUTE: u64 = 60;
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// Error returned when parsing a human-readable duration string fails.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DurationError {
    /// Unexpected character at the given byte offset.
    InvalidCharacter(usize),
    /// Expected a leading digit at the given byte offset.
    NumberExpected(usize),
    /// Unrecognized or missing time unit.
    UnknownUnit {
        start: usize,
        end: usize,
        unit: String,
        value: u64,
    },
    /// Value exceeds `Duration` bounds or uses sub-nanosecond precision.
    NumberOverflow,
    /// Input was empty or whitespace-only.
    Empty,
}

impl std::error::Error for DurationError {}

impl fmt::Display for DurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCharacter(offset) => {
                write!(f, "invalid character at {offset}")
            },
            Self::NumberExpected(offset) => {
                write!(f, "expected number at {offset}")
            },
            Self::UnknownUnit { unit, value, .. } if unit.is_empty() => {
                write!(f, "time unit needed, for example {value}sec or {value}ms")
            },
            Self::UnknownUnit { unit, .. } => {
                write!(
                    f,
                    "unknown time unit {unit:?}, supported units: ns, us/µs, ms, sec, min, hours, days, weeks, months, years (and few variations)"
                )
            },
            Self::NumberOverflow => f.write_str(
                "number is too large or cannot be represented without a lack of precision (values below 1ns are not supported)",
            ),
            Self::Empty => f.write_str("value was empty"),
        }
    }
}

fn checked_mul(lhs: u64, rhs: u64) -> Result<u64, DurationError> {
    lhs.checked_mul(rhs).ok_or(DurationError::NumberOverflow)
}

fn checked_add(lhs: u64, rhs: u64) -> Result<u64, DurationError> {
    lhs.checked_add(rhs).ok_or(DurationError::NumberOverflow)
}

fn checked_exact_div(lhs: u64, rhs: u64) -> Result<u64, DurationError> {
    if lhs.is_multiple_of(rhs) {
        Ok(lhs / rhs)
    } else {
        Err(DurationError::NumberOverflow)
    }
}

#[derive(Debug, Clone, Copy)]
struct Fraction {
    numerator: u64,
    denominator: u64,
}

#[derive(Clone, Copy)]
enum Unit {
    Nanosecond,
    Microsecond,
    Millisecond,
    Second,
    Minute,
    Hour,
    Day,
    Week,
    Month,
    Year,
}

impl FromStr for Unit {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "nanos" | "nsec" | "ns" => Ok(Self::Nanosecond),
            "usec" | "us" | "µs" => Ok(Self::Microsecond),
            "millis" | "msec" | "ms" => Ok(Self::Millisecond),
            "seconds" | "second" | "secs" | "sec" | "s" => Ok(Self::Second),
            "minutes" | "minute" | "min" | "mins" | "m" => Ok(Self::Minute),
            "hours" | "hour" | "hr" | "hrs" | "h" => Ok(Self::Hour),
            "days" | "day" | "d" => Ok(Self::Day),
            "weeks" | "week" | "wk" | "wks" | "w" => Ok(Self::Week),
            "months" | "month" | "M" => Ok(Self::Month),
            "years" | "year" | "yr" | "yrs" | "y" => Ok(Self::Year),
            _ => Err(()),
        }
    }
}

impl Unit {
    fn whole_parts(self, value: u64) -> Result<(u64, u64), DurationError> {
        match self {
            Self::Nanosecond => Ok((0, value)),
            Self::Microsecond => Ok((0, checked_mul(value, 1_000)?)),
            Self::Millisecond => Ok((0, checked_mul(value, 1_000_000)?)),
            Self::Second => Ok((value, 0)),
            Self::Minute => Ok((checked_mul(value, SECONDS_PER_MINUTE)?, 0)),
            Self::Hour => Ok((checked_mul(value, SECONDS_PER_HOUR)?, 0)),
            Self::Day => Ok((checked_mul(value, SECONDS_PER_DAY)?, 0)),
            Self::Week => Ok((checked_mul(value, SECONDS_PER_WEEK)?, 0)),
            Self::Month => Ok((checked_mul(value, SECONDS_PER_MONTH)?, 0)),
            Self::Year => Ok((checked_mul(value, SECONDS_PER_YEAR)?, 0)),
        }
    }

    fn fraction_parts(
        self,
        frac: Fraction,
    ) -> Result<(u64, u64), DurationError> {
        let n = frac.numerator;
        let d = frac.denominator;
        match self {
            Self::Nanosecond => Err(DurationError::NumberOverflow),
            Self::Microsecond => {
                Ok((0, checked_exact_div(checked_mul(n, 1_000)?, d)?))
            },
            Self::Millisecond => {
                Ok((0, checked_exact_div(checked_mul(n, 1_000_000)?, d)?))
            },
            Self::Second => {
                Ok((0, checked_exact_div(checked_mul(n, NANOS_PER_SEC)?, d)?))
            },
            Self::Minute => {
                Ok((0, checked_exact_div(checked_mul(n, 60_000_000_000)?, d)?))
            },
            Self::Hour => Ok((
                checked_exact_div(checked_mul(n, SECONDS_PER_HOUR)?, d)?,
                0,
            )),
            Self::Day => {
                Ok((checked_exact_div(checked_mul(n, SECONDS_PER_DAY)?, d)?, 0))
            },
            Self::Week => Ok((
                checked_exact_div(checked_mul(n, SECONDS_PER_WEEK)?, d)?,
                0,
            )),
            Self::Month => Ok((
                checked_exact_div(checked_mul(n, SECONDS_PER_MONTH)?, d)?,
                0,
            )),
            Self::Year => Ok((
                checked_exact_div(checked_mul(n, SECONDS_PER_YEAR)?, d)?,
                0,
            )),
        }
    }
}

fn is_unit_char(ch: char) -> bool {
    ch.is_ascii_alphabetic() || ch == 'µ'
}

fn add_span(
    mut sec: u64,
    nsec: u64,
    out: &mut Duration,
) -> Result<(), DurationError> {
    let mut total_nsec = checked_add(u64::from(out.subsec_nanos()), nsec)?;
    if total_nsec >= NANOS_PER_SEC {
        sec = checked_add(sec, total_nsec / NANOS_PER_SEC)?;
        total_nsec %= NANOS_PER_SEC;
    }
    let total_sec = checked_add(out.as_secs(), sec)?;
    *out = Duration::new(total_sec, total_nsec as u32);
    Ok(())
}

struct Parser<'a> {
    iter: Chars<'a>,
    src: &'a str,
}

impl<'a> Parser<'a> {
    fn off(&self) -> usize {
        self.src.len() - self.iter.as_str().len()
    }

    fn parse(mut self) -> Result<Duration, DurationError> {
        let mut n = self.parse_first_char()?.ok_or(DurationError::Empty)?;
        let mut out = Duration::ZERO;
        loop {
            let (frac, unit_start) = self.read_number_and_fraction(&mut n)?;
            let (unit_end, next_digit) = self.read_unit_end()?;
            self.apply_unit(n, frac, unit_start, unit_end, &mut out)?;
            if let Some(digit) = next_digit {
                n = digit;
                continue;
            }
            match self.parse_first_char()? {
                Some(next) => n = next,
                None => return Ok(out),
            }
        }
    }

    fn parse_first_char(&mut self) -> Result<Option<u64>, DurationError> {
        let mut off = self.off();
        while let Some(ch) = self.iter.next() {
            if let Some(digit) = ch.to_digit(10) {
                return Ok(Some(u64::from(digit)));
            }
            if !ch.is_whitespace() {
                return Err(DurationError::NumberExpected(off));
            }
            off = self.off();
        }
        Ok(None)
    }

    fn read_number_and_fraction(
        &mut self,
        n: &mut u64,
    ) -> Result<(Option<Fraction>, usize), DurationError> {
        let mut off = self.off();
        while let Some(ch) = self.iter.next() {
            if let Some(digit) = ch.to_digit(10) {
                *n = checked_mul(*n, 10)
                    .and_then(|v| checked_add(v, u64::from(digit)))?;
            } else if ch == '.' {
                let frac = self.parse_fractional_part(&mut off)?;
                return Ok((Some(frac), off));
            } else if is_unit_char(ch) {
                return Ok((None, off));
            } else if !ch.is_whitespace() {
                return Err(DurationError::InvalidCharacter(off));
            }
            off = self.off();
        }
        Ok((None, off))
    }

    fn parse_fractional_part(
        &mut self,
        off: &mut usize,
    ) -> Result<Fraction, DurationError> {
        let mut numerator = 0u64;
        let mut denominator = 1u64;
        let mut leading_zeros = true;
        *off = self.off();
        while let Some(ch) = self.iter.next() {
            if ch == '0' {
                denominator = checked_mul(denominator, 10)?;
                if !leading_zeros {
                    numerator = checked_mul(numerator, 10)?;
                }
            } else if let Some(digit) = ch.to_digit(10) {
                leading_zeros = false;
                denominator = checked_mul(denominator, 10)?;
                numerator = checked_mul(numerator, 10)
                    .and_then(|v| checked_add(v, u64::from(digit)))?;
            } else if is_unit_char(ch) {
                break;
            } else if !ch.is_whitespace() {
                return Err(DurationError::InvalidCharacter(*off));
            }
            *off = self.off();
        }
        if denominator == 1 {
            return Err(DurationError::InvalidCharacter(*off));
        }
        Ok(Fraction {
            numerator,
            denominator,
        })
    }

    fn read_unit_end(&mut self) -> Result<(usize, Option<u64>), DurationError> {
        let mut off = self.off();
        while let Some(ch) = self.iter.next() {
            if let Some(digit) = ch.to_digit(10) {
                return Ok((off, Some(u64::from(digit))));
            }
            if ch.is_whitespace() {
                return Ok((off, None));
            }
            if !is_unit_char(ch) {
                return Err(DurationError::InvalidCharacter(off));
            }
            off = self.off();
        }
        Ok((off, None))
    }

    fn apply_unit(
        &self,
        n: u64,
        frac: Option<Fraction>,
        start: usize,
        end: usize,
        out: &mut Duration,
    ) -> Result<(), DurationError> {
        let raw_unit = &self.src[start..end];
        let unit = Unit::from_str(raw_unit).map_err(|()| {
            DurationError::UnknownUnit {
                start,
                end,
                unit: raw_unit.to_owned(),
                value: n,
            }
        })?;
        let (sec, nsec) = unit.whole_parts(n)?;
        add_span(sec, nsec, out)?;
        if let Some(frac) = frac {
            let (fsec, fnsec) = unit.fraction_parts(frac)?;
            add_span(fsec, fnsec, out)?;
        }
        Ok(())
    }
}

/// Parses a human-friendly duration string such as `"10s"`, `"2h 30m"`, or `"1.5s"`.
pub fn parse_duration(s: &str) -> Result<Duration, DurationError> {
    if s == "0" {
        return Ok(Duration::ZERO);
    }
    Parser {
        iter: s.chars(),
        src: s,
    }
    .parse()
}

/// Display wrapper for formatting a [`Duration`] in human-readable form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormattedDuration(Duration);

impl FormattedDuration {
    /// Returns a reference to the wrapped [`Duration`].
    pub fn get_ref(&self) -> &Duration {
        &self.0
    }
}

impl From<Duration> for FormattedDuration {
    fn from(value: Duration) -> Self {
        Self(value)
    }
}

/// Formats a [`Duration`] into a human-readable wrapper implementing [`fmt::Display`].
pub fn format_duration(val: Duration) -> FormattedDuration {
    FormattedDuration(val)
}

fn write_plural_item(
    f: &mut fmt::Formatter<'_>,
    started: &mut bool,
    name: &str,
    value: u64,
) -> fmt::Result {
    if value > 0 {
        if *started {
            f.write_str(" ")?;
        }
        write!(f, "{value}{name}")?;
        if value > 1 {
            f.write_str("s")?;
        }
        *started = true;
    }
    Ok(())
}

fn write_unit_item(
    f: &mut fmt::Formatter<'_>,
    started: &mut bool,
    name: &str,
    value: u32,
) -> fmt::Result {
    if value > 0 {
        if *started {
            f.write_str(" ")?;
        }
        write!(f, "{value}{name}")?;
        *started = true;
    }
    Ok(())
}

impl fmt::Display for FormattedDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0.as_secs();
        let nanos = self.0.subsec_nanos();
        if secs == 0 && nanos == 0 {
            return f.write_str("0s");
        }

        let years = secs / SECONDS_PER_YEAR;
        let ydays = secs % SECONDS_PER_YEAR;
        let months = ydays / SECONDS_PER_MONTH;
        let mdays = ydays % SECONDS_PER_MONTH;
        let days = mdays / SECONDS_PER_DAY;
        let day_secs = mdays % SECONDS_PER_DAY;
        let hours = (day_secs / SECONDS_PER_HOUR) as u32;
        let minutes =
            ((day_secs % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE) as u32;
        let seconds = (day_secs % SECONDS_PER_MINUTE) as u32;

        let millis = nanos / 1_000_000;
        let micros = (nanos / 1_000) % 1_000;
        let nanosec = nanos % 1_000;

        let started = &mut false;
        write_plural_item(f, started, "year", years)?;
        write_plural_item(f, started, "month", months)?;
        write_plural_item(f, started, "day", days)?;
        write_unit_item(f, started, "h", hours)?;
        write_unit_item(f, started, "m", minutes)?;
        write_unit_item(f, started, "s", seconds)?;
        write_unit_item(f, started, "ms", millis)?;
        write_unit_item(f, started, "us", micros)?;
        write_unit_item(f, started, "ns", nanosec)?;
        Ok(())
    }
}

/// Serde helper (`#[serde(with = "pingap_util::duration_serde")]`) for
/// `Duration` and `Option<Duration>` fields.
pub mod duration_serde {
    use super::{format_duration, parse_duration};
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
    use std::fmt;
    use std::time::Duration;

    /// Wrapper supporting serde serialization/deserialization for `Duration`
    /// and `Option<Duration>`.
    #[derive(Copy, Clone, Eq, Hash, PartialEq)]
    pub struct DurationSerde<T>(T);

    impl<T> DurationSerde<T> {
        /// Unwraps the inner value.
        pub fn into_inner(self) -> T {
            self.0
        }
    }

    impl<T> From<T> for DurationSerde<T> {
        fn from(val: T) -> Self {
            Self(val)
        }
    }

    impl<'de> Deserialize<'de> for DurationSerde<Duration> {
        fn deserialize<D>(d: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            struct Visitor;
            impl de::Visitor<'_> for Visitor {
                type Value = Duration;

                fn expecting(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                    fmt.write_str("a duration")
                }

                fn visit_str<E>(self, v: &str) -> Result<Duration, E>
                where
                    E: de::Error,
                {
                    parse_duration(v).map_err(|_| {
                        E::invalid_value(de::Unexpected::Str(v), &self)
                    })
                }
            }
            d.deserialize_str(Visitor).map(DurationSerde)
        }
    }

    impl<'de> Deserialize<'de> for DurationSerde<Option<Duration>> {
        fn deserialize<D>(d: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            match Option::<DurationSerde<Duration>>::deserialize(d)? {
                Some(DurationSerde(dur)) => Ok(DurationSerde(Some(dur))),
                None => Ok(DurationSerde(None)),
            }
        }
    }

    impl Serialize for DurationSerde<&Duration> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            format_duration(*self.0).to_string().serialize(serializer)
        }
    }

    impl Serialize for DurationSerde<Duration> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            format_duration(self.0).to_string().serialize(serializer)
        }
    }

    impl Serialize for DurationSerde<&Option<Duration>> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match *self.0 {
                Some(dur) => serializer.serialize_some(&DurationSerde(dur)),
                None => serializer.serialize_none(),
            }
        }
    }

    impl Serialize for DurationSerde<Option<Duration>> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            DurationSerde(&self.0).serialize(serializer)
        }
    }

    /// Deserializes a `Duration` or `Option<Duration>` from a human-readable string.
    pub fn deserialize<'de, T, D>(d: D) -> Result<T, D::Error>
    where
        DurationSerde<T>: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        DurationSerde::deserialize(d).map(DurationSerde::into_inner)
    }

    /// Serializes a `Duration` or `Option<Duration>` to a human-readable string.
    pub fn serialize<T, S>(d: &T, s: S) -> Result<S::Ok, S::Error>
    where
        for<'a> DurationSerde<&'a T>: Serialize,
        S: Serializer,
    {
        DurationSerde::from(d).serialize(s)
    }
}

/// Formats a [`SystemTime`] in UTC as RFC 3339 with whole-second precision
/// (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn format_rfc3339_seconds(time: SystemTime) -> String {
    let total_secs = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (total_secs / SECONDS_PER_DAY) as i64;
    let day_secs = total_secs % SECONDS_PER_DAY;
    let hour = day_secs / SECONDS_PER_HOUR;
    let minute = (day_secs % SECONDS_PER_HOUR) / SECONDS_PER_MINUTE;
    let second = day_secs % SECONDS_PER_MINUTE;

    // Howard Hinnant's civil-from-days algorithm (epoch 1970-01-01 = day 0).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(month <= 2);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde::{Deserialize, Serialize};

    #[test]
    fn test_parse_duration_units_and_compounds() {
        assert_eq!(Ok(Duration::ZERO), parse_duration("0"));
        assert_eq!(Ok(Duration::ZERO), parse_duration("0s"));
        assert_eq!(Ok(Duration::from_nanos(17)), parse_duration("17nsec"));
        assert_eq!(Ok(Duration::from_nanos(33)), parse_duration("33ns"));
        assert_eq!(Ok(Duration::from_micros(3)), parse_duration("3usec"));
        assert_eq!(Ok(Duration::from_micros(78)), parse_duration("78us"));
        assert_eq!(Ok(Duration::from_micros(163)), parse_duration("163µs"));
        assert_eq!(Ok(Duration::from_millis(31)), parse_duration("31millis"));
        assert_eq!(Ok(Duration::from_millis(6)), parse_duration("6ms"));
        assert_eq!(Ok(Duration::from_secs(50)), parse_duration("50seconds"));
        assert_eq!(Ok(Duration::from_secs(720)), parse_duration("12min"));
        assert_eq!(Ok(Duration::from_secs(7_200)), parse_duration("2h"));
        assert_eq!(Ok(Duration::from_secs(172_800)), parse_duration("2days"));
        assert_eq!(Ok(Duration::from_secs(604_800)), parse_duration("1week"));
        assert_eq!(
            Ok(Duration::from_secs(2_630_016)),
            parse_duration("1month")
        );
        assert_eq!(
            Ok(Duration::from_secs(31_557_600)),
            parse_duration("1year")
        );
        assert_eq!(Ok(Duration::new(9_420, 0)), parse_duration("2h 37min"));
        assert_eq!(
            Ok(Duration::new(3_600 + 120 + 5, 0)),
            parse_duration("1h2m5s")
        );
        assert_eq!(
            Ok(Duration::new(90, 500_000_000)),
            parse_duration(" 1m 30s 500ms ")
        );
    }

    #[test]
    fn test_parse_duration_fractions() {
        assert_eq!(Ok(Duration::new(4, 200_000_000)), parse_duration("4.2s"));
        assert_eq!(Ok(Duration::from_nanos(3_001)), parse_duration("3.001us"));
        assert_eq!(Ok(Duration::from_micros(3_001)), parse_duration("3.001ms"));
        assert_eq!(
            Ok(Duration::from_nanos(31_000_001)),
            parse_duration("31.000001ms")
        );
        assert_eq!(Ok(Duration::from_secs(90)), parse_duration("1.5m"));
        assert_eq!(Ok(Duration::from_secs(5_400)), parse_duration("1.5h"));
        assert_eq!(
            Err(DurationError::NumberOverflow),
            parse_duration("17.5ns")
        );
        assert_eq!(
            Err(DurationError::NumberOverflow),
            parse_duration("0.000123456789s")
        );
    }

    #[test]
    fn test_parse_duration_errors() {
        assert_eq!(Err(DurationError::Empty), parse_duration(""));
        assert_eq!(Err(DurationError::Empty), parse_duration("   "));
        assert_eq!(
            Err(DurationError::NumberExpected(0)),
            parse_duration(".1s")
        );
        assert_eq!(
            Err(DurationError::NumberExpected(2)),
            parse_duration("  abc")
        );
        assert!(matches!(
            parse_duration("1.s"),
            Err(DurationError::InvalidCharacter(_))
        ));
        assert!(matches!(
            parse_duration("-1s"),
            Err(DurationError::NumberExpected(0))
        ));

        let missing_unit = parse_duration("123").unwrap_err();
        assert_eq!(
            "time unit needed, for example 123sec or 123ms",
            missing_unit.to_string()
        );

        let unknown = parse_duration("1a").unwrap_err();
        assert_eq!(
            r#"unknown time unit "a", supported units: ns, us/µs, ms, sec, min, hours, days, weeks, months, years (and few variations)"#,
            unknown.to_string()
        );
    }

    #[test]
    fn test_format_duration_and_roundtrip() {
        assert_eq!("0s", format_duration(Duration::ZERO).to_string());
        assert_eq!(
            "2h 37m",
            format_duration(Duration::from_secs(9_420)).to_string()
        );
        assert_eq!(
            "32ms",
            format_duration(Duration::from_millis(32)).to_string()
        );
        assert_eq!(
            "2years 1month 3days 4h 5m 6s 7ms 8us 9ns",
            format_duration(Duration::new(
                2 * SECONDS_PER_YEAR
                    + SECONDS_PER_MONTH
                    + 3 * SECONDS_PER_DAY
                    + 4 * SECONDS_PER_HOUR
                    + 5 * SECONDS_PER_MINUTE
                    + 6,
                7_008_009,
            ))
            .to_string()
        );
        for d in [
            Duration::ZERO,
            Duration::from_nanos(1),
            Duration::from_micros(45),
            Duration::from_millis(1_234),
            Duration::from_secs(3600 * 25 + 61),
            Duration::from_secs(SECONDS_PER_YEAR * 3 + 90_000),
        ] {
            let text = format_duration(d).to_string();
            assert_eq!(Ok(d), parse_duration(&text), "{text}");
        }
    }

    #[test]
    fn test_duration_serde() {
        #[derive(Debug, PartialEq, Serialize, Deserialize)]
        struct Config {
            #[serde(with = "duration_serde")]
            timeout: Duration,
            #[serde(default, with = "duration_serde")]
            opt: Option<Duration>,
            #[serde(default, with = "duration_serde")]
            unset: Option<Duration>,
        }

        let cfg: Config = serde_json::from_str(
            r#"{"timeout":"15 seconds","opt":"2m 30s","unset":null}"#,
        )
        .unwrap();
        assert_eq!(Duration::from_secs(15), cfg.timeout);
        assert_eq!(Some(Duration::from_secs(150)), cfg.opt);
        assert_eq!(None, cfg.unset);

        let serialized = serde_json::to_string(&cfg).unwrap();
        assert_eq!(
            r#"{"timeout":"15s","opt":"2m 30s","unset":null}"#,
            serialized
        );

        let missing_opt: Config =
            serde_json::from_str(r#"{"timeout":"500ms"}"#).unwrap();
        assert_eq!(Duration::from_millis(500), missing_opt.timeout);
        assert_eq!(None, missing_opt.opt);
    }

    #[test]
    fn test_format_rfc3339_seconds() {
        assert_eq!("1970-01-01T00:00:00Z", format_rfc3339_seconds(UNIX_EPOCH));
        // Leap day: 2024-02-29T23:59:59Z = 1709251199
        assert_eq!(
            "2024-02-29T23:59:59Z",
            format_rfc3339_seconds(
                UNIX_EPOCH + Duration::from_secs(1_709_251_199)
            )
        );
        // Matches src/process/exit_mark.rs::tests::test_describe
        assert_eq!(
            "2025-10-09T08:53:20Z",
            format_rfc3339_seconds(
                UNIX_EPOCH + Duration::from_secs(1_760_000_000)
            )
        );
    }
}
