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

use super::{Error, LOG_TARGET};
use async_trait::async_trait;
use futures::future::join_all;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::time::interval;
use tracing::{error, info};

fn duration_to_string(duration: Duration) -> String {
    let secs = duration.as_secs_f64();
    if secs < 60.0 {
        format!("{secs:.1}s")
    } else if secs < 3600.0 {
        format!("{:.1}m", secs / 60.0)
    } else if secs < 86400.0 {
        format!("{:.1}h", secs / 3600.0)
    } else {
        format!("{:.1}d", secs / 86400.0)
    }
}

/// A unified trait for any task that can be run in the background.
#[async_trait]
pub trait BackgroundTask: Sync + Send {
    /// Executes a single iteration of the task.
    ///
    /// # Arguments
    /// * `count` - The current execution cycle number.
    ///
    /// # Returns
    /// * `Ok(true)` if the task performed meaningful work and should be logged as "success".
    /// * `Ok(false)` if the task was skipped or did no work.
    /// * `Err(Error)` if the task failed.
    async fn execute(&self, count: u32) -> Result<bool, Error>;
}

/// A unified background service runner that can handle one or more named tasks.
pub struct BackgroundTaskService {
    name: String,
    count: AtomicU32,
    tasks: Vec<(String, Box<dyn BackgroundTask>)>, // Holds named tasks
    interval: Duration,
    immediately: bool,
    initial_delay: Option<Duration>,
}

impl BackgroundTaskService {
    /// Creates a new service to run multiple background tasks.
    pub fn new(
        name: &str,
        interval: Duration,
        tasks: Vec<(String, Box<dyn BackgroundTask>)>,
    ) -> Self {
        Self {
            name: name.to_string(),
            count: AtomicU32::new(0),
            tasks,
            interval,
            immediately: false,
            initial_delay: None,
        }
    }
    /// A convenience constructor for creating a service with a single task.
    pub fn new_single(
        name: &str,
        interval: Duration,
        task_name: &str,
        task: Box<dyn BackgroundTask>,
    ) -> Self {
        Self::new(name, interval, vec![(task_name.to_string(), task)])
    }
    /// Set whether the service should run immediately or wait for the interval
    pub fn set_immediately(&mut self, immediately: bool) {
        self.immediately = immediately;
    }
    pub fn set_initial_delay(&mut self, initial_delay: Option<Duration>) {
        self.initial_delay = initial_delay;
    }
    /// Add a task to the service
    /// This is useful for adding tasks to the service after it has been created
    pub fn add_task(&mut self, task_name: &str, task: Box<dyn BackgroundTask>) {
        self.tasks.push((task_name.to_string(), task));
    }
    pub fn name(&self) -> String {
        self.name.clone()
    }
}

#[async_trait]
impl BackgroundService for BackgroundTaskService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let task_names: Vec<_> =
            self.tasks.iter().map(|(name, _)| name.as_str()).collect();
        info!(
            target: LOG_TARGET,
            name = self.name,
            tasks = task_names.join(", "),
            interval = duration_to_string(self.interval),
            "background service is running",
        );

        if let Some(initial_delay) = self.initial_delay {
            tokio::time::sleep(initial_delay).await;
        }
        let mut period = interval(self.interval);
        // The first tick fires immediately, which is often not desired. We skip it.
        if !self.immediately {
            period.tick().await;
        }

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    info!(
                        target: LOG_TARGET,
                        name = self.name,
                        "background service is shutting down"
                    );
                    break;
                }
                _ = period.tick() => {
                    let cycle_start = Instant::now();
                    let count = self.count.fetch_add(1, Ordering::Relaxed);

                    // Create a collection of futures to run all tasks concurrently.
                    let futures = self.tasks.iter().map(|(task_name, task)| async move {
                        let task_start = Instant::now();
                        let result = task.execute(count).await;
                        (task_name, result, task_start.elapsed())
                    });

                    // Await all tasks to complete in parallel.
                    let results = join_all(futures).await;

                    let mut success_tasks = Vec::new();
                    let mut failed_tasks = Vec::new();

                    // Process results for logging.
                    for (task_name, result, elapsed) in results {
                        match result {
                            Ok(true) => {
                                success_tasks.push(task_name.as_str());
                                info!(
                                    target: LOG_TARGET,
                                    name = self.name,
                                    task = task_name,
                                    elapsed = duration_to_string(elapsed),
                                    "background task executed successfully"
                                );
                            }
                            Ok(false) => {
                                // Task was skipped, do nothing.
                            }
                            Err(e) => {
                                failed_tasks.push(task_name.as_str());
                                error!(
                                    target: LOG_TARGET,
                                    name = self.name,
                                    task = task_name,
                                    error = %e,
                                    "background task failed"
                                );
                            }
                        }
                    }

                    if !success_tasks.is_empty() || !failed_tasks.is_empty() {
                         info!(
                            target: LOG_TARGET,
                            name = self.name,
                            cycle = count,
                            success_count = success_tasks.len(),
                            failed_count = failed_tasks.len(),
                            total_elapsed = duration_to_string(cycle_start.elapsed()),
                            "background service cycle completed",
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_duration_to_string() {
        assert_eq!(duration_to_string(Duration::from_secs(1)), "1.0s");
        assert_eq!(duration_to_string(Duration::from_secs(60)), "1.0m");
        assert_eq!(duration_to_string(Duration::from_secs(3600)), "1.0h");
        assert_eq!(duration_to_string(Duration::from_secs(86400)), "1.0d");
    }

    #[test]
    fn new_background_task_service() {
        struct TestTask {}
        #[async_trait]
        impl BackgroundTask for TestTask {
            async fn execute(&self, _count: u32) -> Result<bool, Error> {
                Ok(true)
            }
        }
        let mut service = BackgroundTaskService::new(
            "test",
            Duration::from_secs(1),
            vec![
                ("task1".to_string(), Box::new(TestTask {})),
                ("task2".to_string(), Box::new(TestTask {})),
            ],
        );
        service.add_task("task3", Box::new(TestTask {}));

        assert_eq!(service.name(), "test");
        assert_eq!(service.tasks.len(), 3);
        assert_eq!(service.tasks[0].0, "task1");
        assert_eq!(service.tasks[1].0, "task2");
        assert_eq!(service.tasks[2].0, "task3");
        assert_eq!(false, service.immediately);

        let mut service = BackgroundTaskService::new_single(
            "test",
            Duration::from_secs(1),
            "task1",
            Box::new(TestTask {}),
        );
        service.set_immediately(true);
        assert_eq!(service.name(), "test");
        assert_eq!(service.tasks.len(), 1);
        assert_eq!(true, service.immediately);
    }
}
