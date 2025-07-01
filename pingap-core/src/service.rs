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

use super::{Error, LOG_CATEGORY};
use async_trait::async_trait;
use futures::future::BoxFuture;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};
use tokio::time::interval;
use tracing::{error, info};

// Type alias for a boxed future that represents a background task
// Takes a u32 counter and returns Result<bool, Error>
pub type SimpleServiceTaskFuture =
    Box<dyn Fn(u32) -> BoxFuture<'static, Result<bool, Error>> + Sync + Send>;

// Represents a collection of background tasks that run periodically
pub struct SimpleServiceTask {
    name: String,     // Name identifier for the service
    count: AtomicU32, // Counter for tracking task executions
    tasks: Vec<(String, SimpleServiceTaskFuture)>, // List of named tasks to execute
    interval: Duration, // Time between task executions
}

/// Creates a new SimpleServiceTask with the specified name, interval, and collection of tasks.
/// This service manages multiple background tasks that run concurrently at fixed intervals.
///
/// # Arguments
/// * `name` - Identifier for this service instance, used in logging
/// * `interval` - Duration between task executions (e.g., Duration::from_secs(60) for minute intervals)
/// * `tasks` - Vector of named tasks to execute periodically, where each task is a tuple of (name, task_function)
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

fn duration_to_string(duration: Duration) -> String {
    let secs = duration.as_secs_f64();
    if secs < 60.0 {
        format!("{secs:.1}s")
    } else if secs < 3600.0 {
        format!("{secs:.1}m")
    } else if secs < 86400.0 {
        format!("{secs:.1}h")
    } else {
        format!("{secs:.1}d")
    }
}

#[async_trait]
impl BackgroundService for SimpleServiceTask {
    /// Starts the background service, executing all tasks at the specified interval
    /// until shutdown is signaled or tasks complete. Each task execution is logged
    /// with timing information and success/failure status.
    ///
    /// # Arguments
    /// * `shutdown` - Watch channel for shutdown coordination
    ///
    /// # Task Execution
    /// - Tasks are executed sequentially in the order they were added
    /// - Each task receives a counter value that increments with each interval
    /// - Failed tasks are logged with error details but don't stop the service
    /// - Task execution times are logged for monitoring purposes
    ///
    /// # Shutdown Behavior
    /// - Service stops gracefully when shutdown signal is received
    /// - Current task iteration completes before shutdown
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let period_human = duration_to_string(self.interval);
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
                // Handle shutdown signal
                _ = shutdown.changed() => {
                    break;
                }
                // Execute tasks on each interval tick
                _ = period.tick() => {
                    let now = SystemTime::now();
                    let count = self.count.fetch_add(1, Ordering::Relaxed);
                    let mut success_tasks = vec![];
                    let mut fail_tasks = vec![];
                    // Execute each task and track results
                    for (task_name, task) in self.tasks.iter() {
                        let task_start = SystemTime::now();
                        match task(count).await {
                           Err(e)  => {
                               fail_tasks.push(task_name.to_string());
                               error!(
                                   category = LOG_CATEGORY,
                                   name = self.name,
                                   task = task_name,
                                   error = %e,
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
                    if !success_tasks.is_empty() || !fail_tasks.is_empty() {
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
}

// Trait defining interface for individual service tasks
#[async_trait]
pub trait ServiceTask: Sync + Send {
    /// Executes a single iteration of the task. This method is called repeatedly
    /// at the specified interval until shutdown or task completion.
    ///
    /// # Returns
    /// * `None` or `Some(false)` - Task completed normally, continue running the service
    /// * `Some(true)` - Task completed and requests service shutdown
    async fn run(&self) -> Option<bool>;

    /// Returns a human-readable description of the task for logging and monitoring.
    /// Implementations should provide meaningful descriptions of their purpose.
    ///
    /// # Returns
    /// * String describing the task's purpose, default is "unknown"
    fn description(&self) -> String {
        "unknown".to_string()
    }
}

// Wrapper for individual ServiceTask implementations
pub struct CommonServiceTask {
    task: Box<dyn ServiceTask>, // The actual task to execute
    interval: Duration,         // Time between executions
}

impl CommonServiceTask {
    /// Creates a new CommonServiceTask that wraps a single task implementation.
    /// This is useful for simpler cases where only one recurring task is needed.
    ///
    /// # Arguments
    /// * `interval` - Duration between task executions
    /// * `task` - Implementation of ServiceTask to execute
    ///
    /// # Special Cases
    /// - If interval is less than 1 second, task runs only once
    /// - Task can signal completion via return value to stop service
    pub fn new(interval: Duration, task: impl ServiceTask + 'static) -> Self {
        Self {
            task: Box::new(task),
            interval,
        }
    }
}

#[async_trait]
impl BackgroundService for CommonServiceTask {
    /// Starts the background service, executing the wrapped task at the specified interval.
    /// The service runs until one of the following conditions is met:
    /// - Shutdown signal is received
    /// - Task returns Some(true) indicating completion
    /// - Interval is less than 1 second (runs once and stops)
    ///
    /// # Arguments
    /// * `shutdown` - Watch channel for shutdown coordination
    ///
    /// # Logging
    /// - Service start is logged with task description and interval
    /// - Each task execution is logged with elapsed time
    /// - Task completion status is logged
    ///
    /// # Performance Considerations
    /// - Task execution time is measured and logged
    /// - Long-running tasks may delay the next interval
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let period_human = duration_to_string(self.interval);
        // if interval is less than 1s
        // the task should only run once
        let once = self.interval.as_millis() < 1000;

        info!(
            category = LOG_CATEGORY,
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
                    info!(
                        category = LOG_CATEGORY,
                        done,
                        elapsed = format!(
                            "{}ms",
                            now.elapsed().unwrap_or_default().as_millis()
                        ),
                        description = self.task.description(),
                    );
                    if once || done {
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_simple_service_task() {
        let task =
            new_simple_service_task("test", Duration::from_secs(1), vec![]);

        assert_eq!(task.name, "test");
        assert_eq!(task.interval, Duration::from_secs(1));
        assert_eq!(task.tasks.len(), 0);
    }

    #[test]
    fn test_duration_to_string() {
        assert_eq!(duration_to_string(Duration::from_secs(1)), "1.0s");
        assert_eq!(duration_to_string(Duration::from_secs(60)), "1.0m");
        assert_eq!(duration_to_string(Duration::from_secs(3600)), "1.0h");
        assert_eq!(duration_to_string(Duration::from_secs(86400)), "1.0d");
    }
}
