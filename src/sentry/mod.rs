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

use sentry::types::{Dsn, ParseDsnError};
use sentry::ClientOptions;
use std::str::FromStr;

pub fn new_sentry_options(dsn: &str) -> Result<ClientOptions, ParseDsnError> {
    let dsn = Dsn::from_str(dsn)?;
    Ok(ClientOptions {
        dsn: Some(dsn),
        ..Default::default()
    })
}
