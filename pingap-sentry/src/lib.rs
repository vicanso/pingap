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

use sentry_core::ClientOptions;
use sentry_core::types::{Dsn, ParseDsnError};
use std::str::FromStr;

pub fn new_sentry_options(dsn: &str) -> Result<ClientOptions, ParseDsnError> {
    let dsn = Dsn::from_str(dsn)?;
    Ok(ClientOptions {
        dsn: Some(dsn),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::new_sentry_options;
    use sentry_core::ClientOptions;
    use sentry_core::types::Dsn;
    use std::str::FromStr;

    #[test]
    fn test_dsn_is_the_only_option_that_is_set() {
        let dsn = "https://public@o0.ingest.sentry.io/1";
        let options = match new_sentry_options(dsn) {
            Ok(options) => options,
            Err(err) => panic!("dsn was refused: {err}"),
        };
        let expected = match Dsn::from_str(dsn) {
            Ok(dsn) => dsn.to_string(),
            Err(err) => panic!("dsn was refused: {err}"),
        };
        let parsed = options.dsn.as_ref().map(|dsn| dsn.to_string());
        assert_eq!(Some(expected), parsed);
        let defaults = ClientOptions::default();
        assert_eq!(defaults.sample_rate, options.sample_rate);
        assert_eq!(defaults.traces_sample_rate, options.traces_sample_rate);
        assert_eq!(defaults.environment, options.environment);
        assert_eq!(defaults.release, options.release);

        for dsn in ["", "not a dsn", "https://o0.ingest.sentry.io/1"] {
            match new_sentry_options(dsn) {
                Err(_) => {},
                Ok(_) => panic!("{dsn} was accepted"),
            }
        }
    }
}
