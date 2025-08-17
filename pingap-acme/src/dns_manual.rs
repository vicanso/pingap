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

use super::{AcmeDnsTask, Error, LOG_CATEGORY};
use async_trait::async_trait;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::Resolver;
use std::time::Duration;
use tracing::info;

type Result<T, E = Error> = std::result::Result<T, E>;

pub(crate) struct ManualDnsTask {}

impl ManualDnsTask {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl AcmeDnsTask for ManualDnsTask {
    async fn add_txt_record(&self, domain: &str, value: &str) -> Result<()> {
        info!(
            category = LOG_CATEGORY,
            "set the DNS record {domain} IN TXT {value}",
        );
        let resolver = Resolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .build();
        // dns txt record may take a while to propagate, so we need to retry
        for i in 0..10 {
            tokio::time::sleep(Duration::from_secs(10)).await;
            info!(
                category = LOG_CATEGORY,
                "lookup dns txt record of {domain}, times:{i}"
            );
            if let Ok(response) = resolver.lookup(domain, RecordType::TXT).await
            {
                let txt_records: Vec<String> = response
                    .record_iter()
                    .filter_map(|record| {
                        record.data().as_txt().map(|data| data.to_string())
                    })
                    .collect();
                let matched = txt_records.contains(&value.to_string());
                info!(
                    category = LOG_CATEGORY,
                    "get dns txt records: {:?}, matched: {matched}",
                    txt_records
                );
                if matched {
                    break;
                }
            }
        }
        Ok(())
    }

    async fn done(&self) -> Result<()> {
        Ok(())
    }
}
