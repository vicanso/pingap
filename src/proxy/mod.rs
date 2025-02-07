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

mod dynamic_certificate;
mod logger;
mod server;
mod server_conf;
mod validity_checker;

pub static LOG_CATEGORY: &str = "proxy";

pub use dynamic_certificate::{
    get_certificate_info_list, try_update_certificates,
};
// TODO remove this
#[allow(unused_imports)]
pub use logger::Parser;
pub use server::*;
pub use server_conf::{parse_from_conf, ServerConf};
pub use validity_checker::new_certificate_validity_service;
