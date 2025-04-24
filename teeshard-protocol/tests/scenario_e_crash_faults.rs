// teeshard-protocol/tests/scenario_e_crash_faults.rs

// Scenario E: Crash Fault Tolerance in Shards
// Goals:
// - Validate shard-level consensus continuity under partial node failures.
// - Measure re-election overhead and final throughput impact.
// Procedure:
// 1. k=5 shards, each with m=10 TEE nodes (can tolerate f=4 failures with Raft majority).
// 2. Inject random node crashes (1 per minute, offline 30s, auto-restart).
// 3. Submit 3,000 transactions at 100 TPS.
// 4. Track: leader election count, latency spikes, aborted vs. committed transactions.

use teeshard_protocol::{
    config::SystemConfig,
    data_structures::{AccountId, AssetId, LockInfo, TEEIdentity, Transaction, TxType},
    network::NetworkMessage,
    raft::{node::RaftEvent, state::Command},
    simulation::{
        config::SimulationConfig, coordinator::SimulatedCoordinator,
        node::{NodeProposalRequest, NodeQuery, NodeQueryRequest, NodeQueryResponse, SimulatedTeeNode},
        runtime::{SignatureShare, SimulationRuntime},
        metrics::MetricEvent,
    },
    tee_logic::crypto_sim::{self, SecretKey},
    onchain::interface::TransactionId,
    // Add necessary imports if Coordinator/Relayer interaction is needed for abort tracking
};
use std::collections::{HashMap, VecDeque, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch, Mutex}; // Added Mutex
use rand::{seq::SliceRandom, thread_rng, Rng, SeedableRng}; // Import SeedableRng

// Helper to create TEE Identity and SecretKey
fn create_test_tee(id: usize) -> (TEEIdentity, SecretKey) {
    let secret_bytes = [id as u8; 32];
    let secret_key = SecretKey::from_bytes(&secret_bytes);
    let public_key = secret_key.verifying_key();
    (TEEIdentity { id, public_key }, secret_key)
}

// Helper to generate transactions (can reuse from other scenarios or simplify)
fn generate_scenario_e_transactions(
    num_tx: usize,
    cross_chain_ratio: f64, // e.g., 30%
    num_chains: usize, // e.g., 2
    accounts_per_chain: usize,
) -> Vec<Transaction> {
    // Reusing transaction generation logic (similar to Scenario C)
    let mut transactions = Vec::new();
    let mut rng = thread_rng();

    let accounts: Vec<AccountId> = (0..num_chains)
        .flat_map(|chain_id| {
            (0..accounts_per_chain).map(move |acc_idx| AccountId {
                chain_id: chain_id as u64,
                address: format!("addr_sce_{}_{}", chain_id, acc_idx), // Unique addresses
            })
        })
        .collect();

    let assets: Vec<AssetId> = (0..num_chains)
        .map(|chain_id| AssetId {
            chain_id: chain_id as u64,
            token_symbol: format!("TOK_SCE_{}", chain_id),
            token_address: format!("0xTOKEN_SCE_{}", chain_id),
        })
        .collect();

    for i in 0..num_tx {
        let tx_id = format!("scenario_e_tx_{}", i);
        let timeout = Duration::from_secs(300);
        let amount = rng.gen_range(10..1000) as u64;

        if rng.gen_bool(cross_chain_ratio) && num_chains >= 2 {
            // Cross-chain swap
            let chain_a_idx = rng.gen_range(0..num_chains);
            let mut chain_b_idx = rng.gen_range(0..num_chains);
            while chain_a_idx == chain_b_idx {
                chain_b_idx = rng.gen_range(0..num_chains);
            }

            // Collect into Vec before choosing
            let accounts_a: Vec<&AccountId> = accounts.iter().filter(|a| a.chain_id == chain_a_idx as u64).collect();
            let accounts_b: Vec<&AccountId> = accounts.iter().filter(|a| a.chain_id == chain_b_idx as u64).collect();

            let acc_a1 = accounts_a.choose(&mut rng).unwrap().clone();
            let acc_b1 = accounts_b.choose(&mut rng).unwrap().clone();

            // No need to collect assets again if already collected
            let asset_a = assets.iter().find(|a| a.chain_id == chain_a_idx as u64).unwrap().clone();
            let asset_b = assets.iter().find(|a| a.chain_id == chain_b_idx as u64).unwrap().clone();

            let lock = LockInfo { account: acc_a1.clone(), asset: asset_a.clone(), amount };

            transactions.push(Transaction {
                tx_id,
                tx_type: TxType::CrossChainSwap,
                accounts: vec![acc_a1.clone(), acc_b1.clone()],
                amounts: vec![amount],
                required_locks: vec![lock],
                target_asset: Some(asset_b),
                timeout,
            });
        } else {
            // Single-chain transfer
            let chain_idx = rng.gen_range(0..num_chains);
            let chain_accounts: Vec<&AccountId> = accounts.iter().filter(|a| a.chain_id == chain_idx as u64).collect();
            if chain_accounts.len() < 2 { continue; }

            let from_acc = chain_accounts.choose(&mut rng).unwrap().clone();
            let mut to_acc = chain_accounts.choose(&mut rng).unwrap().clone();
            // Corrected comparison: Compare AccountId with AccountId
            while from_acc == to_acc {
                 to_acc = chain_accounts.choose(&mut rng).unwrap().clone();
            }
            let asset = assets.iter().find(|a| a.chain_id == chain_idx as u64).unwrap().clone();
             let lock = LockInfo { account: from_acc.clone(), asset: asset.clone(), amount };

            transactions.push(Transaction {
                tx_id,
                tx_type: TxType::SingleChainTransfer,
                accounts: vec![from_acc.clone(), to_acc.clone()], // Already cloned
                amounts: vec![amount],
                required_locks: vec![lock],
                target_asset: None,
                timeout,
            });
        }
    }
    transactions
}

// --- Helper function for percentile calculation (copied from test_utils.rs) ---
fn calculate_stats_micros(latencies: &[u128]) -> (f64, u128, u128) {
    if latencies.is_empty() { return (0.0, 0, 0); }
    let count = latencies.len();
    let avg = latencies.iter().sum::<u128>() as f64 / count as f64;
    // Ensure index calculation doesn't panic on empty or single-element slices
    let p95_idx = ((count as f64 * 0.95).floor() as usize).min(count.saturating_sub(1));
    let p99_idx = ((count as f64 * 0.99).floor() as usize).min(count.saturating_sub(1));
    // Use the last element as fallback if index calculation somehow fails (e.g., len=0 was missed)
    let p95 = *latencies.get(p95_idx).unwrap_or(latencies.last().unwrap_or(&0));
    let p99 = *latencies.get(p99_idx).unwrap_or(latencies.last().unwrap_or(&0));
    (avg, p95, p99)
}

#[tokio::test]
async fn test_scenario_e_crash_faults() -> Result<(), String> {
    println!("--- Starting Scenario E: Crash Fault Tolerance ---");
    let start_scenario = Instant::now();

    // --- Configuration ---
    let num_chains = 2; // Example: 2 chains
    let num_shards = 5;
    let nodes_per_shard = 10; // m=10 to tolerate f=4
    let num_nodes = num_shards * nodes_per_shard;
    let cross_chain_ratio = 0.30; // Example: 30%
    let total_transactions = 3000;
    let submission_rate_tps = 100.0;
    let submission_interval = Duration::from_secs_f64(1.0 / submission_rate_tps);
    let accounts_per_chain = 20;

    // Fault Injection Params
    let crash_interval = Duration::from_secs(60); // 1 crash per minute
    let crash_duration = Duration::from_secs(30); // Offline for 30s

    let config = SystemConfig {
        num_shards,
        nodes_per_shard,
        // Use potentially faster Raft timings if testing recovery speed
        raft_election_timeout_min_ms: 1000,
        raft_election_timeout_max_ms: 2000,
        raft_heartbeat_ms: 300,
        ..Default::default()
    };
    // Use default sim config, assuming fault injection is handled separately via runtime calls
    let sim_config = SimulationConfig::default();

    // --- ADD shared state for crash intervals ---
    let crash_intervals = Arc::new(Mutex::new(Vec::<(usize, u64, u64)>::new()));

    // --- Identities ---
    let identities: Vec<(TEEIdentity, SecretKey)> = (0..num_nodes).map(create_test_tee).collect();
    let node_identities: Vec<TEEIdentity> = identities.iter().map(|(id, _)| id.clone()).collect();

    // --- Assign Nodes to Shards (Simple Round Robin for fixed k) ---
    let mut shard_assignments: HashMap<usize, Vec<TEEIdentity>> = HashMap::new();
    for (i, identity) in node_identities.iter().enumerate() {
        let shard_id = i % num_shards;
        shard_assignments.entry(shard_id).or_default().push(identity.clone());
    }
    // Keep track of node IDs for fault injection
    let all_node_ids: Vec<usize> = node_identities.iter().map(|id| id.id).collect();


    // --- Simulation Runtime ---
    println!("[Setup] Initializing Simulation Runtime...");
    // --- CHALLENGE: Fault Injection Capability ---
    // Assuming SimulationRuntime has methods like `crash_node(node_id: usize, duration: Duration)`
    // or provides a way to signal crashes (e.g., via isolation_tx)
    let (runtime, mut result_rx, mut isolation_rx, metrics_handle) = SimulationRuntime::new(sim_config);
    let runtime_handle = Arc::new(runtime); // Use Arc for sharing runtime handle with fault injector
    // --- Get Metrics Sender --- 
    let metrics_tx = runtime_handle.get_metrics_sender();

    let mut node_query_senders = HashMap::new();
    let mut proposal_txs = HashMap::new();
    let mut nodes_to_spawn = Vec::new();

    // --- Create and Register Nodes ---
    println!("[Setup] Creating and registering {} nodes...", num_nodes);
    for (shard_id, nodes_in_shard) in &shard_assignments {
        runtime_handle.assign_nodes_to_shard(*shard_id, nodes_in_shard.clone()).await;
        for tee_identity in nodes_in_shard {
            let (_, secret_key) = identities.iter().find(|(id, _)| id == tee_identity).unwrap();
            let peers: Vec<TEEIdentity> = nodes_in_shard.iter().filter(|&p| p != tee_identity).cloned().collect();
            let (proposal_tx, proposal_rx) = mpsc::channel::<NodeProposalRequest>(200);
            let (query_tx, query_rx) = mpsc::channel::<NodeQuery>(10);

            let network_rx = runtime_handle.register_node(tee_identity.clone(), proposal_tx.clone()).await;
            node_query_senders.insert(tee_identity.id, query_tx.clone());
            proposal_txs.insert(tee_identity.id, proposal_tx.clone());

            let node = SimulatedTeeNode::new(
                tee_identity.clone(),
                secret_key.clone(),
                peers,
                config.clone(),
                (*runtime_handle).clone(), // Dereference Arc, then clone SimulationRuntime
                network_rx,
                proposal_tx,
                proposal_rx,
                query_tx,
                query_rx,
                *shard_id,
            );
            nodes_to_spawn.push(node);
        }
    }

    // --- Spawn Node Tasks ---
    println!("[Setup] Spawning node tasks...");
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    let mut node_handles = Vec::new();
    for node in nodes_to_spawn {
        let node_id = node.identity.id;
        let shutdown_rx_clone = shutdown_rx.clone();
        let handle = tokio::spawn(async move {
            node.run(shutdown_rx_clone).await;
        });
        node_handles.push((node_id, handle));
    }
    println!("[Setup] All nodes spawned.");

    // --- Generate Transactions ---
    println!("[Setup] Generating {} transactions...", total_transactions);
    let transactions = generate_scenario_e_transactions(total_transactions, cross_chain_ratio, num_chains, accounts_per_chain);
    let transactions_queue = Arc::new(Mutex::new(VecDeque::from(transactions)));

    // --- Transaction Submission Task ---
    println!("[Run] Starting transaction submission (Target: {} TPS)...", submission_rate_tps);
    let submission_shutdown_rx = shutdown_rx.clone(); // Separate shutdown for submitter
    let submission_task = tokio::spawn({
        let transactions_queue = transactions_queue.clone();
        let proposal_txs = proposal_txs.clone();
        let shard_assignments = shard_assignments.clone();
        let node_query_senders = node_query_senders.clone();
        async move {
            let mut leaders: HashMap<usize, Option<TEEIdentity>> = HashMap::new();
            let mut tx_submitted_count = 0;
            let mut interval = tokio::time::interval(submission_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
            let mut shutdown_signal = submission_shutdown_rx; // Use the cloned receiver

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let mut tx_opt = {
                            let mut queue = transactions_queue.lock().await;
                            queue.pop_front()
                        };

                        if let Some(tx) = tx_opt {
                            // Determine target shard (Simplified logic)
                            let primary_account = tx.accounts.first().cloned().or_else(|| tx.required_locks.first().map(|l| l.account.clone()));
                             let target_shard_id = if let Some(acc) = primary_account {
                                (acc.address.len() % num_shards)
                            } else {
                                rand::thread_rng().gen_range(0..num_shards)
                            };

                            // Find leader or fallback (Simplified logic)
                             let leader_proposal_tx = match leaders.get(&target_shard_id) {
                                Some(Some(leader_id)) => proposal_txs.get(&leader_id.id),
                                _ => {
                                    let nodes_in_shard = shard_assignments.get(&target_shard_id).cloned().unwrap_or_default();
                                    // Try to query only the first node for simplicity in this sketch
                                    let mut found_leader_id = None;
                                     if let Some(first_node_id) = nodes_in_shard.first().map(|n| n.id) {
                                         if let Some(query_sender) = node_query_senders.get(&first_node_id) {
                                              let (resp_tx, resp_rx) = oneshot::channel();
                                              if query_sender.send((NodeQueryRequest::GetRaftState, resp_tx)).await.is_ok() {
                                                 if let Ok(Ok(NodeQueryResponse::RaftState { role, .. })) = tokio::time::timeout(Duration::from_millis(50), resp_rx).await {
                                                      // We queried first node, but response tells us who leader is
                                                      if role == teeshard_protocol::raft::state::RaftRole::Leader {
                                                          // If the queried node is the leader, use its ID
                                                          found_leader_id = nodes_in_shard.first().cloned();
                                                      }
                                                 }
                                             }
                                         }
                                     }

                                    if let Some(leader) = found_leader_id {
                                        leaders.insert(target_shard_id, Some(leader.clone()));
                                        proposal_txs.get(&leader.id)
                                    } else {
                                        leaders.insert(target_shard_id, None);
                                        nodes_in_shard.first().and_then(|n| proposal_txs.get(&n.id)) // Fallback
                                    }
                                }
                             };

                            // Propose command (Simplified logic)
                            if let Some(proposer_tx) = leader_proposal_tx {
                                let lock_data = teeshard_protocol::tee_logic::types::LockProofData { // Specify full path
                                    shard_id: target_shard_id,
                                    tx_id: tx.tx_id.clone(),
                                    source_chain_id: tx.required_locks.first().map(|l| l.asset.chain_id).unwrap_or(0),
                                    target_chain_id: tx.target_asset.as_ref().map(|a| a.chain_id).unwrap_or(0),
                                    token_address: tx.required_locks.first().map(|l| l.asset.token_address.clone()).unwrap_or_default(),
                                    amount: tx.amounts.first().cloned().unwrap_or(0),
                                    recipient: tx.accounts.get(1).map(|a| a.address.clone()).unwrap_or_default(),
                                    start_time: Instant::now(),
                                };
                                let command = Command::ConfirmLockAndSign(lock_data);
                                let (ack_tx, _ack_rx) = oneshot::channel();

                                if proposer_tx.send((command, ack_tx)).await.is_ok() {
                                    tx_submitted_count += 1;
                                } else {
                                     println!("[Submitter] WARN: Failed to send proposal for tx {}", tx.tx_id);
                                }
                            } else {
                                 println!("[Submitter] WARN: No proposal channel for shard {}, skipping tx {}", target_shard_id, tx.tx_id);
                            }
                        } else {
                            // Queue empty, break the loop
                            break;
                        }
                    },
                    _ = shutdown_signal.changed() => {
                         println!("[Submitter] Shutdown signal received, stopping submission.");
                         break;
                    }
                }
            }
            println!("[Submitter] Submission finished. Submitted {} transactions.", tx_submitted_count);
            tx_submitted_count
        }
    });

    // --- Fault Injection Task ---
    println!("[Run] Starting Fault Injection Task (1 crash / {:?})...", crash_interval);
    let fault_shutdown_rx = shutdown_rx.clone();
    let mut rng = rand::rngs::SmallRng::from_rng(thread_rng()).map_err(|e| e.to_string())?;
    let fault_injection_task = tokio::spawn({
        // Clone handles needed for the task
        let metrics_tx = metrics_tx.clone(); // Clone sender
        let node_ids = all_node_ids.clone();
        let crash_intervals_clone = crash_intervals.clone(); // Clone Arc for task
        // Move the created RNG into the async block
        let mut rng = rng;
        async move {
            let mut interval = tokio::time::interval(crash_interval);
            let mut shutdown_signal = fault_shutdown_rx;
            // Track currently crashed nodes to avoid crashing them again immediately
            let crashed_nodes = Arc::new(Mutex::new(HashSet::<usize>::new()));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let mut available_nodes = node_ids.clone();
                        {
                            // Filter out nodes that are already crashed
                            let currently_crashed = crashed_nodes.lock().await;
                            available_nodes.retain(|id| !currently_crashed.contains(id));
                        }

                        if available_nodes.is_empty() {
                            println!("[FaultInjector] No available nodes to crash currently.");
                            continue;
                        }

                        if let Some(&node_to_crash) = available_nodes.choose(&mut rng) { // Dereference the chosen node ID
                            println!("[FaultInjector] Injecting crash for Node {} for {:?}...", node_to_crash, crash_duration);
                            // Mark as crashed immediately
                            crashed_nodes.lock().await.insert(node_to_crash);
                            let crash_start_time_ms = teeshard_protocol::simulation::metrics::current_epoch_millis(); // Get current time

                            // --- Send NodeIsolated Metric Event --- 
                            let isolated_event = MetricEvent::NodeIsolated {
                                node_id: node_to_crash,
                                timestamp_ms: crash_start_time_ms,
                            };
                            if let Err(e) = metrics_tx.send(isolated_event).await {
                                eprintln!("[FaultInjector] Error sending NodeIsolated event: {}", e);
                            }

                            // Spawn rejoin task
                            let rejoin_metrics_tx = metrics_tx.clone();
                            let rejoin_crashed_nodes = crashed_nodes.clone();
                            let rejoin_crash_intervals = crash_intervals_clone.clone(); // Clone Arc for rejoin task
                            tokio::spawn(async move {
                                tokio::time::sleep(crash_duration).await;
                                let rejoin_time_ms = teeshard_protocol::simulation::metrics::current_epoch_millis();
                                println!("[FaultInjector] Injecting rejoin for Node {}...", node_to_crash);

                                // --- Record crash interval BEFORE sending rejoin event ---
                                {
                                    let mut intervals = rejoin_crash_intervals.lock().await;
                                    intervals.push((node_to_crash, crash_start_time_ms, rejoin_time_ms));
                                }
                                
                                // --- Send NodeRejoined Metric Event --- 
                                let rejoined_event = MetricEvent::NodeRejoined {
                                    node_id: node_to_crash,
                                    timestamp_ms: rejoin_time_ms,
                                };
                                if let Err(e) = rejoin_metrics_tx.send(rejoined_event).await {
                                     eprintln!("[FaultInjector] Error sending NodeRejoined event: {}", e);
                                }
                                // Unmark as crashed after sending rejoin event
                                rejoin_crashed_nodes.lock().await.remove(&node_to_crash);
                            });
                        }
                    },
                     _ = shutdown_signal.changed() => {
                         println!("[FaultInjector] Shutdown signal received, stopping fault injection.");
                         break;
                     }
                }
            }
        }
    });


    // --- Let Simulation Run ---
    println!("[Run] Waiting for simulation, transaction processing, and fault injection...");
    // Wait for submission to potentially finish, but run long enough for crashes
    let simulation_duration = Duration::from_secs( (total_transactions as f64 / submission_rate_tps * 1.2) as u64 + 90 ); // Longer duration
    println!("[Run] Simulation will run for approximately {:?}", simulation_duration);
    tokio::time::sleep(simulation_duration).await;

    // --- Shutdown and Collect Results ---
    println!("[Cleanup] Sending shutdown signal...");
    let _ = shutdown_tx.send(()); // Signal all tasks

    // --- Drop runtime BEFORE awaiting tasks ---
    println!("[Cleanup] Dropping SimulationRuntime instance...");
    drop(runtime_handle); // Drop the Arc<SimulationRuntime>
    println!("[Cleanup] SimulationRuntime instance dropped.");
    // --- End Drop ---

    // Wait for tasks (with timeouts)
    println!("[Cleanup] Waiting for submission task...");
    if let Err(_) = tokio::time::timeout(Duration::from_secs(5), submission_task).await {
        eprintln!("[Cleanup] WARN: Submission task timed out during shutdown await.");
    }
    println!("[Cleanup] Waiting for fault injection task...");
     if let Err(_) = tokio::time::timeout(Duration::from_secs(5), fault_injection_task).await {
        eprintln!("[Cleanup] WARN: Fault injection task timed out during shutdown await.");
     }
     println!("[Cleanup] Waiting for node tasks...");
    for (id, handle) in node_handles {
        if let Err(_) = tokio::time::timeout(Duration::from_secs(5), handle).await {
             eprintln!("[Cleanup] WARN: Node {} task timed out during shutdown await.", id);
        }
        // No need for else print, keep output clean
    }
    println!("[Cleanup] All node tasks finished or timed out."); // Consolidated log

    // Collect metrics using the correct handle
    println!("[Cleanup] Awaiting metrics handle..."); // Added log
    let collected_metrics = metrics_handle.await.unwrap_or_default(); // Await the handle
    println!("[Metrics] Collected {} metric events.", collected_metrics.len());

    // --- Analyze Metrics ---
    let mut leader_elections_per_shard: HashMap<usize, usize> = HashMap::new();
    let mut commit_latencies: Vec<Duration> = Vec::new(); // Raw commit latencies
    let mut transaction_outcomes: HashMap<String, bool> = HashMap::new(); // String = TxId, bool = success
    let mut latencies_during_crash: Vec<u128> = Vec::new(); // Tx completion latencies (micros)
    let mut latencies_normal: Vec<u128> = Vec::new(); // Tx completion latencies (micros)

    // Create node_id -> shard_id lookup map
    let mut node_id_to_shard_id: HashMap<usize, usize> = HashMap::new();
    for (shard_id, nodes_in_shard) in &shard_assignments {
        for node_identity in nodes_in_shard {
            node_id_to_shard_id.insert(node_identity.id, *shard_id);
        }
    }

    // --- Get the recorded crash intervals ---
    let final_crash_intervals = crash_intervals.lock().await.clone(); // Clone the data

    println!("[Analysis] Analyzing {} metric events...", collected_metrics.len());
    for event in collected_metrics {
        match event {
            MetricEvent::RaftLeaderElected { leader_id, .. } => {
                if let Some(shard_id) = node_id_to_shard_id.get(&leader_id) {
                    *leader_elections_per_shard.entry(*shard_id).or_insert(0) += 1;
                } else {
                    println!("[Analysis] Warning: Could not find shard for leader election event (leader_id: {}).", leader_id);
                }
            }
            MetricEvent::RaftCommit { latency, .. } => {
                commit_latencies.push(latency);
            }
            MetricEvent::TransactionCompleted { id, success, duration, end_time_ms, .. } => {
                 transaction_outcomes.insert(id, success);
                 if success {
                    let latency_micros = duration.as_micros();
                    let mut is_during_crash = false;
                    // Check if tx completed during ANY crash interval
                    for (_node_id, start_ms, finish_ms) in &final_crash_intervals {
                        if end_time_ms >= *start_ms && end_time_ms <= *finish_ms {
                            is_during_crash = true;
                            break;
                        }
                    }
                    if is_during_crash {
                        latencies_during_crash.push(latency_micros);
                    } else {
                        latencies_normal.push(latency_micros);
                    }
                 }
            }
            // Added cases to prevent warnings, ignore others for now
            MetricEvent::NodeIsolated { .. } | MetricEvent::NodeRejoined { .. } | MetricEvent::TeeFunctionMeasured {..} | _ => {}
        }
    }

    println!("\n[Results] Leader Elections per Shard:");
    for shard_id in 0..num_shards {
        println!("  - Shard {}: {}", shard_id, leader_elections_per_shard.get(&shard_id).unwrap_or(&0));
    }

    // --- Latency Spike Analysis ---
    println!("\n[Results] Transaction Completion Latency Comparison:");
    if !latencies_normal.is_empty() {
        latencies_normal.sort_unstable();
        let (avg, p95, p99) = calculate_stats_micros(&latencies_normal);
        println!("  Normal Period ({} samples): Avg={:.3} ms, P95={:.3} ms, P99={:.3} ms",
                 latencies_normal.len(), avg / 1000.0, p95 as f64 / 1000.0, p99 as f64 / 1000.0);
    } else {
        println!("  Normal Period: No successful transactions recorded.");
    }
    if !latencies_during_crash.is_empty() {
        latencies_during_crash.sort_unstable();
        let (avg, p95, p99) = calculate_stats_micros(&latencies_during_crash);
        println!("  During Crash ({} samples): Avg={:.3} ms, P95={:.3} ms, P99={:.3} ms",
                 latencies_during_crash.len(), avg / 1000.0, p95 as f64 / 1000.0, p99 as f64 / 1000.0);
    } else {
        println!("  During Crash: No successful transactions completed during recorded crash intervals.");
    }

    // --- Abort Rate Analysis ---
    let total_tracked_tx = transaction_outcomes.len();
    let committed_tx = transaction_outcomes.values().filter(|&&committed| committed).count();
    let aborted_tx = total_tracked_tx - committed_tx;
    println!("\n[Results] Transaction Outcomes ({} tracked): Committed: {}, Aborted: {}",
             total_tracked_tx, committed_tx, aborted_tx);
    // Assert abort rate should be very low if Raft handles failures correctly.
    // Allow a small tolerance, e.g., 1% failure rate just in case
    assert!(aborted_tx <= (total_tracked_tx as f64 * 0.01).ceil() as usize, 
            "Abort rate too high! Aborted: {}, Total: {}", aborted_tx, total_tracked_tx);

    let scenario_duration = start_scenario.elapsed();
    println!("--- Scenario E Finished in {:?} ---", scenario_duration);
    Ok(())
}


