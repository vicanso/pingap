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
mod location;
mod logger;
mod server;
mod server_conf;
mod upstream;

// for bench
#[allow(unused_imports)]
pub use location::Location;

pub use dynamic_certificate::{
    get_certificate_info_list, try_update_certificates,
};
pub use location::{get_locations_processing, try_init_locations};
pub use logger::Parser;
pub use server::*;
pub use server_conf::ServerConf;
pub use upstream::{
    get_upstreams_processing_connected, new_upstream_health_check_task,
    try_init_upstreams, try_update_upstreams, Upstream,
};
