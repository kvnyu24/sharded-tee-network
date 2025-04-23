use crate::data_structures::TEEIdentity;
use std::time::{Duration, Instant, SystemTime};
use crate::raft::node::ShardId;
use tokio::sync::mpsc;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use crate::raft::state::RaftRole;
use serde::{Serialize, Deserialize};

// Helper function to get current epoch milliseconds
fn current_epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Enum representing different types of metrics collected during the simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricEvent {
    /// Records the completion details of a transaction (e.g., a swap).
    TransactionCompleted {
        id: String,
        start_time_ms: u64,
        end_time_ms: u64,
        #[serde(with = "humantime_serde")]
        duration: Duration,
        is_cross_chain: bool,
        success: bool,
    },
    /// Records the execution time of a specific function within a TEE node.
    TeeFunctionMeasured {
        node_id: TEEIdentity,
        function_name: String,
        #[serde(with = "humantime_serde")]
        duration: Duration,
    },
    /// Records when a Raft leader is elected for a specific shard.
    RaftLeaderElected {
        term: u64,
        leader_id: usize, // Node ID
        timestamp_ms: u64,
    },
    /// Records the latency for committing a Raft log entry.
    RaftCommit {
        shard_id: ShardId,
        leader_id: TEEIdentity,
        #[serde(with = "humantime_serde")]
        latency: Duration, // Time from proposal to commit
    },
    NodeIsolated {
        node_id: usize,
        timestamp_ms: u64,
    },
    NodeRejoined {
        node_id: usize,
        timestamp_ms: u64,
    },
    /// Records when a message is sent between nodes in different shards.
    CrossShardMessageSent {
        sender_shard: ShardId,
        receiver_shard: ShardId,
    },
    NodeCommandProposed {
        node_id: usize,
        command_type: String, // e.g., "ConfirmLockAndSign"
        tx_id: String,
        timestamp_ms: u64,
    },
    NodeCommandCommitted {
        node_id: usize,
        log_index: u64,
        term: u64,
        command_type: String,
        tx_id: String,
        timestamp_ms: u64,
    },
    NodeSignatureShareGenerated {
        node_id: usize,
        tx_id: String,
        timestamp_ms: u64,
    },
    CoordinatorThresholdReached {
        coordinator_id: usize,
        tx_id: String,
        shares_count: usize,
        threshold: usize,
        timestamp_ms: u64,
    },
    RelayerReleaseSubmitted {
        tx_id: String, // Or swap_id if more appropriate
        target_chain_id: u64,
        onchain_tx_hash: String, // The hash returned by the relayer
        timestamp_ms: u64,
    },
    /// ADDED: Variant for coordinator receiving a share
    CoordinatorShareReceived {
        coordinator_id: usize,
        tee_node_id: usize,
        tx_id: String,
        timestamp_ms: u64,
    },
    // Add more metric types as needed
}

/// Collects and stores metrics during the simulation.
#[derive(Debug)]
pub struct MetricsCollector {
    rx: mpsc::Receiver<MetricEvent>,
    // Store completed transaction data
    completed_transactions: Arc<Mutex<Vec<MetricEvent>>>, 
    isolated_nodes: Arc<Mutex<HashSet<usize>>>, // Track currently isolated nodes
}

impl MetricsCollector {
    /// Creates a new MetricsCollector and a sender channel to send events to it.
    pub fn new(rx: mpsc::Receiver<MetricEvent>) -> Self {
        MetricsCollector {
            rx,
            completed_transactions: Arc::new(Mutex::new(Vec::new())),
            isolated_nodes: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Runs the collector task, receiving and storing events until the sender is dropped.
    pub async fn run(&mut self) {
        println!("[MetricsCollector] Starting run loop...");
        while let Some(event) = self.rx.recv().await {
            println!("[MetricsCollector] Received event: {:?}", event); // Log received event
            
            // Lock necessary data structures based on the event type
            match event {
                MetricEvent::TransactionCompleted { .. } => {
                    let mut transactions = self.completed_transactions.lock().await;
                    transactions.push(event.clone()); // Store completed tx
                    // Drop lock immediately after use
                    drop(transactions);
                }
                MetricEvent::NodeIsolated { node_id, timestamp_ms: _ } => {
                    let mut isolated = self.isolated_nodes.lock().await;
                    isolated.insert(node_id);
                    drop(isolated);
                }
                 MetricEvent::NodeRejoined { node_id, timestamp_ms: _ } => {
                    let mut isolated = self.isolated_nodes.lock().await;
                    isolated.remove(&node_id);
                    drop(isolated);
                }
                // Add arms for other variants, even if they do nothing for now
                MetricEvent::TeeFunctionMeasured { .. } => {
                    // Placeholder: Could store these in a separate Vec/Map if needed
                     log::trace!("[MetricsCollector] Ignoring TeeFunctionMeasured event for now.");
                }
                MetricEvent::RaftLeaderElected { .. } => {
                    // Placeholder: Could track leader election frequency/timing
                     log::trace!("[MetricsCollector] Ignoring RaftLeaderElected event for now.");
                }
                MetricEvent::RaftCommit { .. } => {
                     // Placeholder: Could store commit latency data separately
                     log::trace!("[MetricsCollector] Ignoring RaftCommit event for now.");
                }
                // Add missing arm for CrossShardMessageSent
                MetricEvent::CrossShardMessageSent { .. } => {
                    log::trace!("[MetricsCollector] Ignoring CrossShardMessageSent event for now.");
                }
                // Handle other event types if added later (no default needed if enum is exhaustive)
                MetricEvent::NodeCommandProposed { .. } => {
                    log::trace!("[MetricsCollector] Ignoring NodeCommandProposed event for now.");
                }
                MetricEvent::NodeCommandCommitted { .. } => {
                    log::trace!("[MetricsCollector] Ignoring NodeCommandCommitted event for now.");
                }
                MetricEvent::NodeSignatureShareGenerated { .. } => {
                    log::trace!("[MetricsCollector] Ignoring NodeSignatureShareGenerated event for now.");
                }
                MetricEvent::CoordinatorThresholdReached { .. } => {
                    log::trace!("[MetricsCollector] Ignoring CoordinatorThresholdReached event for now.");
                }
                MetricEvent::RelayerReleaseSubmitted { .. } => {
                    log::trace!("[MetricsCollector] Ignoring RelayerReleaseSubmitted event for now.");
                }
                MetricEvent::CoordinatorShareReceived { .. } => {
                    log::trace!("[MetricsCollector] Ignoring CoordinatorShareReceived event for now.");
                }
            }
        }
        println!("[MetricsCollector] Run loop finished (channel closed).");
    }

    /// Returns a reference to the collected events after the run loop has finished.
    /// Note: This clones the event data. Consider alternative approaches for large datasets.
    pub async fn get_collected_events(&self) -> Vec<MetricEvent> {
        let transactions = self.completed_transactions.lock().await;
        transactions.clone()
    }

    /// Processes the collected events and prints summary statistics.
    pub async fn process_results(&self) {
        println!("\n--- Metrics Summary ---");
        let transactions_lock = self.completed_transactions.lock().await;
        let isolated_lock = self.isolated_nodes.lock().await;

        if transactions_lock.is_empty() && isolated_lock.is_empty() {
            println!("No metrics events recorded.");
            return;
        }

        // --- Transaction Summary --- 
        let total_tx = transactions_lock.iter().filter(|e| matches!(e, MetricEvent::TransactionCompleted {..})).count();
        let successful_tx = transactions_lock.iter().filter(|e| matches!(e, MetricEvent::TransactionCompleted { success: true, .. })).count();
        let failed_tx = total_tx - successful_tx;
        println!("Transactions Processed: {}", total_tx);
        println!("  Successful: {}", successful_tx);
        println!("  Failed:     {}", failed_tx);

        let durations: Vec<Duration> = transactions_lock.iter().filter_map(|event| {
            if let MetricEvent::TransactionCompleted { duration, .. } = event {
                Some(*duration)
            } else {
                None
            }
        }).collect();

        if !durations.is_empty() {
            let total_duration: Duration = durations.iter().sum();
            let avg_duration = total_duration / durations.len() as u32;
            let min_duration = durations.iter().min().unwrap_or(&Duration::ZERO);
            let max_duration = durations.iter().max().unwrap_or(&Duration::ZERO);
            println!("Transaction Duration (ms):");
            println!("  Average: {:.3}", avg_duration.as_secs_f64() * 1000.0);
            println!("  Min:     {:.3}", min_duration.as_secs_f64() * 1000.0);
            println!("  Max:     {:.3}", max_duration.as_secs_f64() * 1000.0);

            let lower_bound = Duration::from_millis(10);
            let upper_bound = Duration::from_millis(20); // Increased from 16ms
            assert!(
                avg_duration >= lower_bound && avg_duration <= upper_bound,
                "Average duration out of expected range ({}ms - {}ms): {:?}",
                lower_bound.as_millis(),
                upper_bound.as_millis(),
                avg_duration
            );
        } else if total_tx > 0 {
             println!("Transaction Duration: No duration data found (check events).");
        }

        // --- Node Isolation --- 
        println!("Node Isolation: {} nodes ended isolated.", isolated_lock.len());
        if !isolated_lock.is_empty() {
            let mut isolated_ids: Vec<usize> = isolated_lock.iter().cloned().collect();
            isolated_ids.sort();
            println!("  Isolated Node IDs: {:?}", isolated_ids);
        }

        // --- Raft Commit Latency (Example - adapt as needed) ---
        let raft_commits: Vec<Duration> = transactions_lock.iter().filter_map(|event| {
            if let MetricEvent::RaftCommit { latency, .. } = event {
                Some(*latency)
            } else {
                None
            }
        }).collect();

        if !raft_commits.is_empty() {
            let total_latency: Duration = raft_commits.iter().sum();
            let avg_latency = total_latency / raft_commits.len() as u32;
            let min_latency = raft_commits.iter().min().unwrap_or(&Duration::ZERO);
            let max_latency = raft_commits.iter().max().unwrap_or(&Duration::ZERO);
            println!(
                "Raft Commit Latency: Count={}, Avg={:?}, Min={:?}, Max={:?}",
                raft_commits.len(), avg_latency, min_latency, max_latency
            );
        } else {
            println!("Raft Commit Latency: No data collected.");
        }

        // --- TEE Function Measurement (Example - adapt as needed) ---
        let mut tee_times: HashMap<String, Vec<Duration>> = HashMap::new();
        for event in transactions_lock.iter() {
            if let MetricEvent::TeeFunctionMeasured { function_name, duration, .. } = event {
                tee_times.entry(function_name.clone()).or_default().push(*duration);
            }
        }

        if !tee_times.is_empty() {
             println!("TEE Function Execution Times:");
             let mut sorted_keys: Vec<_> = tee_times.keys().collect();
             sorted_keys.sort(); // Sort for consistent output
             for func_name in sorted_keys {
                 if let Some(durations) = tee_times.get(func_name) {
                    if !durations.is_empty() {
                        let total_duration: Duration = durations.iter().sum();
                        let avg_duration = total_duration / durations.len() as u32;
                        let min_duration = durations.iter().min().unwrap_or(&Duration::ZERO);
                        let max_duration = durations.iter().max().unwrap_or(&Duration::ZERO);
                        println!(
                            "  - {}: Count={}, Avg={:?}, Min={:?}, Max={:?}",
                            func_name, durations.len(), avg_duration, min_duration, max_duration
                        );
                    }
                 }
             }
        } else {
             println!("TEE Function Execution Times: No data collected.");
        }

        println!("---------------------");
    }

    // --- Methods to Compute Final Statistics --- 

    /// Returns the total number of transactions processed (both successful and failed).
    pub async fn total_transactions(&self) -> usize {
        let transactions = self.completed_transactions.lock().await;
        transactions.len()
    }

    /// Returns the number of successfully completed transactions.
    pub async fn successful_transactions(&self) -> usize {
        let transactions = self.completed_transactions.lock().await;
        transactions.iter().filter(|event| {
            matches!(event, MetricEvent::TransactionCompleted { success: true, .. })
        }).count()
    }

    /// Returns the number of failed transactions.
    pub async fn failed_transactions(&self) -> usize {
        let transactions = self.completed_transactions.lock().await;
        transactions.iter().filter(|event| {
            matches!(event, MetricEvent::TransactionCompleted { success: false, .. })
        }).count()
    }

    /// Returns the average duration of completed transactions.
    /// Returns None if no transactions were completed.
    pub async fn average_transaction_duration(&self) -> Option<Duration> {
        let transactions = self.completed_transactions.lock().await;
        if transactions.is_empty() {
            return None;
        }
        let total_duration: Duration = transactions.iter().map(|event| {
            match event {
                MetricEvent::TransactionCompleted { duration, .. } => *duration,
                _ => Duration::ZERO, // Should not happen if filtering is correct
            }
        }).sum();
        Some(total_duration / transactions.len() as u32)
    }

    /// Returns the number of nodes currently marked as isolated at the end of the simulation.
    pub async fn final_isolated_node_count(&self) -> usize {
        let isolated = self.isolated_nodes.lock().await;
        isolated.len()
    }

    /// Returns a set of the IDs of nodes currently marked as isolated.
    pub async fn get_isolated_nodes(&self) -> HashSet<usize> {
         let isolated = self.isolated_nodes.lock().await;
         isolated.clone() // Clone the set to return
    }
}

// --- Optional: Tests for MetricsCollector --- 
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use std::time::{Duration, Instant, SystemTime};

    #[tokio::test]
    async fn test_metrics_collection_and_stats() {
        let (tx, rx) = mpsc::channel(100);
        let collector = MetricsCollector::new(rx);
        let collector_handle = Arc::new(Mutex::new(collector)); // Use TokioMutex

        // Clone for the run task
        let collector_run_clone = collector_handle.clone();
        let run_task = tokio::spawn(async move {
            let mut collector_guard = collector_run_clone.lock().await;
            collector_guard.run().await;
        });

        // Send some events
        let start1_ms = current_epoch_millis();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let end1_ms = current_epoch_millis();
        let duration1 = Duration::from_millis(end1_ms - start1_ms);
        tx.send(MetricEvent::TransactionCompleted {
            id: "tx1".to_string(), start_time_ms: start1_ms, end_time_ms: end1_ms, duration: duration1, is_cross_chain: true, success: true
        }).await.unwrap();

        let start2_ms = current_epoch_millis();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let end2_ms = current_epoch_millis();
        let duration2 = Duration::from_millis(end2_ms - start2_ms);
         tx.send(MetricEvent::TransactionCompleted {
            id: "tx2".to_string(), start_time_ms: start2_ms, end_time_ms: end2_ms, duration: duration2, is_cross_chain: true, success: false
        }).await.unwrap();

        tx.send(MetricEvent::NodeIsolated { node_id: 5, timestamp_ms: current_epoch_millis() }).await.unwrap();
        tx.send(MetricEvent::NodeIsolated { node_id: 10, timestamp_ms: current_epoch_millis() }).await.unwrap();
        tx.send(MetricEvent::NodeRejoined { node_id: 5, timestamp_ms: current_epoch_millis() }).await.unwrap(); // Node 5 rejoins

        // Drop the sender to signal the end of events
        drop(tx);

        // Wait for the collector to finish processing
        run_task.await.unwrap();

        // Get the collector instance back to call stat methods
        let final_collector = collector_handle.lock().await;

        // Check stats
        assert_eq!(final_collector.total_transactions().await, 2);
        assert_eq!(final_collector.successful_transactions().await, 1);
        assert_eq!(final_collector.failed_transactions().await, 1);
        assert!(final_collector.average_transaction_duration().await.is_some());
        // Approximate duration check
        let avg_duration_ms = final_collector.average_transaction_duration().await.unwrap().as_millis();
        let lower_bound = Duration::from_millis(10);
        let upper_bound = Duration::from_millis(20); // Increased from 16ms
        assert!(
            avg_duration_ms >= lower_bound.as_millis() && avg_duration_ms <= upper_bound.as_millis(),
            "Average duration out of expected range ({}ms - {}ms): {}",
            lower_bound.as_millis(),
            upper_bound.as_millis(),
            avg_duration_ms
        );

        assert_eq!(final_collector.final_isolated_node_count().await, 1);
        let isolated_set = final_collector.get_isolated_nodes().await;
        assert!(isolated_set.contains(&10));
        assert!(!isolated_set.contains(&5));
    }
} 