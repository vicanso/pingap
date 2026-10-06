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
use futures::stream::{FuturesUnordered, StreamExt};
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::time::{MissedTickBehavior, interval};
use tracing::{debug, error, info, warn};

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
    pub fn name(&self) -> &str {
        &self.name
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
        // A tick that comes late must not be followed by a burst of
        // catch-up ticks; the next one is due one interval after it.
        period.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // The first tick fires immediately, which is often not desired. We skip it.
        if !self.immediately {
            period.tick().await;
        }

        // The tasks that are running, and since when each of them is.
        //
        // A round used to wait for every task before the next round could
        // start. One slow task - an ACME order, the hourly sweep of a
        // cache directory, a push to a gateway that does not answer - held
        // all the others up for as long as it took: the log was not
        // flushed, metrics were not pushed, and a task that acts on every
        // sixtieth round drifted off its hour. Each task now keeps its own
        // time: a round starts the ones that are free and leaves out the
        // one that is still at it.
        //
        // And its own count, of the times it ran. A task that acts on
        // every nth run still sees every number: left out of a round, it
        // is given that round's turn the next time, where one count for
        // all would have had it miss the number it was waiting for.
        let mut running = FuturesUnordered::new();
        let mut started: Vec<Option<Instant>> = vec![None; self.tasks.len()];
        let mut runs: Vec<u32> = vec![0; self.tasks.len()];

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
                    let cycle = self.count.fetch_add(1, Ordering::Relaxed);
                    let mut skipped = vec![];
                    for (index, (task_name, task)) in
                        self.tasks.iter().enumerate()
                    {
                        if let Some(since) = started[index] {
                            skipped.push(format!(
                                "{task_name}({})",
                                duration_to_string(since.elapsed())
                            ));
                            continue;
                        }
                        started[index] = Some(Instant::now());
                        let count = runs[index];
                        runs[index] = count.wrapping_add(1);
                        running.push(async move {
                            let task_start = Instant::now();
                            let result = task.execute(count).await;
                            (index, result, task_start.elapsed())
                        });
                    }
                    if !skipped.is_empty() {
                        warn!(
                            target: LOG_TARGET,
                            name = self.name,
                            tasks = skipped.join(", "),
                            cycle,
                            "background tasks still running, left out of this round"
                        );
                    }
                }
                Some((index, result, elapsed)) = running.next(),
                    if !running.is_empty() =>
                {
                    started[index] = None;
                    let task_name = self.tasks[index].0.as_str();
                    match result {
                        Ok(true) => {
                            debug!(
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
            }
        }
        // Nothing is cancelled: a task is not stopped halfway through its
        // work, as it was not when a round was waited for.
        while running.next().await.is_some() {}
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

    /// Regression: a round waited for every task, so one slow task held
    /// up all the others for as long as it took.
    #[tokio::test]
    async fn test_slow_task_does_not_hold_up_the_others() {
        use std::sync::Arc;

        use std::sync::Mutex;

        struct Counting {
            runs: Arc<AtomicU32>,
            counts: Arc<Mutex<Vec<u32>>>,
            takes: Duration,
        }
        #[async_trait]
        impl BackgroundTask for Counting {
            async fn execute(&self, count: u32) -> Result<bool, Error> {
                self.runs.fetch_add(1, Ordering::Relaxed);
                self.counts.lock().unwrap().push(count);
                tokio::time::sleep(self.takes).await;
                Ok(true)
            }
        }
        let quick = Arc::new(AtomicU32::new(0));
        let slow = Arc::new(AtomicU32::new(0));
        let quick_counts = Arc::new(Mutex::new(vec![]));
        let slow_counts = Arc::new(Mutex::new(vec![]));
        let service = BackgroundTaskService::new(
            "test",
            Duration::from_millis(50),
            vec![
                (
                    "quick".to_string(),
                    Box::new(Counting {
                        runs: quick.clone(),
                        counts: quick_counts.clone(),
                        takes: Duration::ZERO,
                    }),
                ),
                (
                    "slow".to_string(),
                    Box::new(Counting {
                        runs: slow.clone(),
                        counts: slow_counts.clone(),
                        takes: Duration::from_millis(400),
                    }),
                ),
            ],
        );
        let (stop, shutdown) = tokio::sync::watch::channel(false);
        let stopper = async {
            tokio::time::sleep(Duration::from_millis(620)).await;
            stop.send(true).unwrap();
        };
        tokio::join!(service.start(shutdown), stopper);

        // About twelve rounds went by. The slow task was started when it
        // was free, twice; the quick one in every round, where it used to
        // get the two that the slow one let through.
        let quick = quick.load(Ordering::Relaxed);
        let slow = slow.load(Ordering::Relaxed);
        assert_eq!(true, quick >= 8, "quick ran {quick} times");
        assert_eq!(true, (1..=3).contains(&slow), "slow ran {slow} times");

        // Each task is given the number of its own run, so one that acts
        // on every nth does not miss its number in a round it sat out.
        assert_eq!((0..slow).collect::<Vec<_>>(), *slow_counts.lock().unwrap());
        assert_eq!(
            (0..quick).collect::<Vec<_>>(),
            *quick_counts.lock().unwrap()
        );
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
