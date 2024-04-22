// Copyright 2024 Tree xie.
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

use serde::{Deserialize, Serialize};
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Instant error {source}"))]
    Instant { source: instant_acme::Error },
    #[snafu(display("Rcgen error {source}"))]
    Rcgen { source: rcgen::Error },
    #[snafu(display("Challenge not found error, {message}"))]
    NotFound { message: String },
    #[snafu(display("Lets encrypt fail, {message}"))]
    Fail { message: String },
    #[snafu(display("Io error {source}"))]
    Io { source: std::io::Error },
    #[snafu(display("Serde json error {source}"))]
    SerdeJson { source: serde_json::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Deserialize, Serialize)]
pub struct CertInfo {
    pub not_after: i64,
    pub not_before: i64,
    pub pem: String,
    pub key: String,
}

mod lets_encrypt;

pub use lets_encrypt::{handle_lets_encrypt, LetsEncryptService};
