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


#[tokio::test]
#[ignore] // Ignore by default as it requires fault injection mechanism and specific analysis
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
        let runtime = runtime_handle.clone(); // Use runtime Arc
        let node_ids = all_node_ids.clone();
        // Move the created RNG into the async block
        let mut rng = rng;
        async move {
            let mut interval = tokio::time::interval(crash_interval);
            let mut shutdown_signal = fault_shutdown_rx;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Some(node_to_crash) = node_ids.choose(&mut rng) {
                            println!("[FaultInjector] Placeholder: Would crash Node {} for {:?}", node_to_crash, crash_duration);
                            // --- TODO: Implement actual crash injection call using SimulationRuntime API ---
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

    // Wait for tasks (with timeouts)
    println!("[Cleanup] Waiting for submission task...");
    let _ = tokio::time::timeout(Duration::from_secs(5), submission_task).await;
    println!("[Cleanup] Waiting for fault injection task...");
     let _ = tokio::time::timeout(Duration::from_secs(5), fault_injection_task).await;
     println!("[Cleanup] Waiting for node tasks...");
    for (id, handle) in node_handles {
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
        println!("[Cleanup] Node {} finished.", id);
    }

    // Collect metrics using the correct handle
    let collected_metrics = metrics_handle.await.unwrap_or_default(); // Await the handle
    println!("[Metrics] Collected {} metric events.", collected_metrics.len());

    // --- Analyze Metrics (Placeholder) ---
    let mut leader_elections_per_shard: HashMap<usize, usize> = HashMap::new();
    let mut commit_latencies: Vec<Duration> = Vec::new();
    let mut transaction_outcomes: HashMap<TransactionId, bool> = HashMap::new(); // true=committed, false=aborted (needs tracking)

    for event in collected_metrics {
        match event {
            // --- TODO: Find the correct MetricEvent variant for leader elections ---
            // MetricEvent::RaftLeaderElection { shard_id, .. } => {
            //     *leader_elections_per_shard.entry(shard_id).or_insert(0) += 1;
            // }
            MetricEvent::RaftCommit { latency, .. } => {
                commit_latencies.push(latency);
            }
            // --- CHALLENGE: Abort Tracking ---
            // Need a way to track aborted transactions, e.g., a new MetricEvent::TransactionAborted
            // Adjust matching based on actual MetricEvent::TransactionCompleted structure
            // --- TODO: Re-enable and adjust matching based on actual MetricEvent::TransactionCompleted fields ---
            // MetricEvent::TransactionCompleted { tx_id, success, .. } => {
            //      // Assuming 'success: bool' field exists
            //      transaction_outcomes.insert(tx_id, success);
            // }
            _ => {}
        }
    }

    println!("[Results] Leader Elections per Shard:");
    for shard_id in 0..num_shards {
        println!("  - Shard {}: {}", shard_id, leader_elections_per_shard.get(&shard_id).unwrap_or(&0));
    }

    // --- CHALLENGE: Latency Spike Analysis ---
    println!("[Results] Commit Latency ({} samples):", commit_latencies.len());
    // TODO: Analyze commit_latencies for spikes or changes during crash periods. Requires correlating timestamps.

    // --- CHALLENGE: Abort Rate Analysis ---
    let total_tracked_tx = transaction_outcomes.len();
    let committed_tx = transaction_outcomes.values().filter(|&&committed| committed).count();
    let aborted_tx = total_tracked_tx - committed_tx;
    println!("[Results] Transaction Outcomes ({} tracked): Committed: {}, Aborted: {}",
             total_tracked_tx, committed_tx, aborted_tx);
    // Assert abort rate should be very low if Raft handles failures correctly.
    // assert!(aborted_tx <= (total_tracked_tx as f64 * 0.01) as usize, "Abort rate too high!");


    let scenario_duration = start_scenario.elapsed();
    println!("--- Scenario E Finished in {:?} ---", scenario_duration);
    Ok(())
}


