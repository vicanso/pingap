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
use futures::future::BoxFuture;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};
use tokio::time::interval;
use tracing::{error, info};

pub static LOG_CATEGORY: &str = "service";

pub type SimpleServiceTaskFuture =
    Box<dyn Fn(u32) -> BoxFuture<'static, Result<bool, String>> + Sync + Send>;

pub struct SimpleServiceTask {
    name: String,
    count: AtomicU32,
    tasks: Vec<(String, SimpleServiceTaskFuture)>,
    interval: Duration,
}

pub fn new_simple_service_task(
    name: &str,
    interval: Duration,
    tasks: Vec<(String, SimpleServiceTaskFuture)>,
) -> SimpleServiceTask {
    SimpleServiceTask {
        name: name.to_string(),
        count: AtomicU32::new(0),
        tasks,
        interval,
    }
}

#[async_trait]
impl BackgroundService for SimpleServiceTask {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let period_human: humantime::Duration = self.interval.into();
        let task_names: Vec<String> =
            self.tasks.iter().map(|item| item.0.clone()).collect();
        info!(
            category = LOG_CATEGORY,
            name = self.name,
            tasks = task_names.join(","),
            interval = period_human.to_string(),
            "background service is running",
        );

        let mut period = interval(self.interval);
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    break;
                }
                _ = period.tick() => {
                    let now = SystemTime::now();
                    let count = self.count.fetch_add(1, Ordering::Relaxed);
                    let mut success_tasks = vec![];
                    let mut fail_tasks = vec![];
                    for (task_name, task) in self.tasks.iter() {
                        let task_start = SystemTime::now();
                        match task(count).await {
                           Err(e)  => {
                               fail_tasks.push(task_name.to_string());
                               error!(
                                   category = LOG_CATEGORY,
                                   name = self.name,
                                   task = task_name,
                                   e,
                               );
                           }
                           Ok(executed) => {
                               if executed {
                                   success_tasks.push(task_name.to_string());
                                   info!(
                                       category = LOG_CATEGORY,
                                       name = self.name,
                                       task = task_name,
                                       elapsed = format!(
                                           "{}ms",
                                           task_start.elapsed().unwrap_or_default().as_millis()
                                       ),
                                   );
                               }
                           }
                        };
                    }
                    info!(
                        category = LOG_CATEGORY,
                        name = self.name,
                        success_tasks = success_tasks.join(","),
                        fails = fail_tasks.len(),
                        fail_tasks = fail_tasks.join(","),
                        elapsed = format!(
                            "{}ms",
                            now.elapsed().unwrap_or_default().as_millis()
                        ),
                    );
                }
            }
        }
    }
}

#[async_trait]
pub trait ServiceTask: Sync + Send {
    async fn run(&self) -> Option<bool>;
    fn description(&self) -> String {
        "unknown".to_string()
    }
}

pub struct CommonServiceTask {
    task: Box<dyn ServiceTask>,
    interval: Duration,
    name: String,
}

impl CommonServiceTask {
    pub fn new(interval: Duration, task: impl ServiceTask + 'static) -> Self {
        let name = task.description();
        Self {
            task: Box::new(task),
            interval,
            name,
        }
    }
}

#[async_trait]
impl BackgroundService for CommonServiceTask {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let period_human: humantime::Duration = self.interval.into();
        // if interval is less than 1s
        // the task should only run once
        let once = self.interval.as_millis() < 1000;

        info!(
            name = self.name,
            description = self.task.description(),
            interval = period_human.to_string(),
            "background service is running",
        );

        let mut period = interval(self.interval);
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    break;
                }
                _ = period.tick() => {
                    let now = SystemTime::now();
                    let done = self.task.run().await.unwrap_or_default();
                    let description = self.task.description();
                    info!(
                        name = self.name,
                        done,
                        elapsed = format!(
                            "{}ms",
                            now.elapsed().unwrap_or_default().as_millis()
                        ),
                        description,
                    );
                    if once || done {
                        break;
                    }
                }
            }
        }
    }
}

mod auto_restart;

pub use auto_restart::{new_auto_restart_service, new_observer_service};
