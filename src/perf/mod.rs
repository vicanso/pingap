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
use async_trait::async_trait;
use pingora::{server::ShutdownWatch, services::background::BackgroundService};

pub struct DhatService {}

#[async_trait]
impl BackgroundService for DhatService {
    /// The lets encrypt servier checks the cert, it will get news cert if current is invalid.
    async fn start(&self, mut shutdown: ShutdownWatch) {
        // can not get the heap profile
        // because pingora exit the process
        let _profiler = dhat::Profiler::new_heap();
        let _ = shutdown.changed().await;
    }
}
