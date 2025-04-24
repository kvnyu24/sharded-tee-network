// teeshard-protocol/tests/scenario_c_tee_overhead.rs

// Scenario C: TEE Overhead Profiling
// Goals:
// - Isolate the cost of each TEE operation.
// - Validate that overheads remain practical under real concurrency.
// Procedure:
// 1. Fix k=5, n=2 blockchains, rho=30%.
// 2. Instrument TEE function calls (GenerateLockProof, ThresholdSign, RemoteAttestation).
// 3. Run 5,000 transactions at 150 TPS.
// 4. Collect average, p95, p99 overhead times.
// 5. Compare to a non-TEE baseline (conventional signatures).

use teeshard_protocol::{
    config::SystemConfig,
    data_structures::{AccountId, AssetId, LockInfo, TEEIdentity, Transaction, TxType},
    network::NetworkMessage,
    raft::{node::RaftEvent, state::Command},
    simulation::{
        config::SimulationConfig, coordinator::SimulatedCoordinator, // Use SimulatedCoordinator
        node::{NodeProposalRequest, NodeQuery, NodeQueryRequest, NodeQueryResponse, SimulatedTeeNode},
        runtime::{SignatureShare, SimulationRuntime},
        metrics::MetricEvent, // Import MetricEvent
    },
    tee_logic::crypto_sim::{self, SecretKey},
    onchain::{evm_relayer::{ChainConfig, EvmRelayer, EvmRelayerConfig}, interface::TransactionId}, // Add imports
    liveness::aggregator::Aggregator, // Add Aggregator/Challenger if needed for realism
    liveness::challenger::Challenger,
    liveness::types::LivenessConfig,
    tee_logic::types::LockProofData,
    tee_logic::enclave_sim::TeeDelayConfig, // Add this import
};
use std::collections::{HashMap, VecDeque, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use rand::{seq::SliceRandom, thread_rng, Rng};

// Helper to create TEE Identity and SecretKey
fn create_test_tee(id: usize) -> (TEEIdentity, SecretKey) {
    let secret_bytes = [id as u8; 32];
    let secret_key = SecretKey::from_bytes(&secret_bytes);
    let public_key = secret_key.verifying_key();
    (TEEIdentity { id, public_key }, secret_key)
}

// Helper to generate transactions for the scenario
fn generate_scenario_c_transactions(
    num_tx: usize,
    cross_chain_ratio: f64, // rho = 0.30
    num_chains: usize, // n = 2
    accounts_per_chain: usize,
) -> Vec<Transaction> {
    let mut transactions = Vec::new();
    let mut rng = thread_rng();

    let accounts: Vec<AccountId> = (0..num_chains)
        .flat_map(|chain_id| {
            (0..accounts_per_chain).map(move |acc_idx| AccountId {
                chain_id: chain_id as u64,
                address: format!("addr_{}_{}", chain_id, acc_idx),
            })
        })
        .collect();

    let assets: Vec<AssetId> = (0..num_chains)
        .map(|chain_id| AssetId {
            chain_id: chain_id as u64,
            token_symbol: format!("TOK{}", chain_id),
            token_address: format!("0xTOKEN{}", chain_id),
        })
        .collect();

    for i in 0..num_tx {
        let tx_id = format!("scenario_c_tx_{}", i);
        let timeout = Duration::from_secs(300);
        let amount = rng.gen_range(10..1000) as u64;

        if rng.gen_bool(cross_chain_ratio) && num_chains >= 2 {
            // Cross-chain swap
            let chain_a_idx = rng.gen_range(0..num_chains);
            let mut chain_b_idx = rng.gen_range(0..num_chains);
            while chain_a_idx == chain_b_idx {
                chain_b_idx = rng.gen_range(0..num_chains);
            }

            // Collect filter results into Vec before choosing
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
                accounts: vec![acc_a1.clone(), acc_b1.clone()], // Clone to ensure owned values
                amounts: vec![amount],
                required_locks: vec![lock],
                target_asset: Some(asset_b),
                timeout,
            });
        } else {
            // Single-chain transfer
            let chain_idx = rng.gen_range(0..num_chains);
            let chain_accounts: Vec<&AccountId> = accounts.iter().filter(|a| a.chain_id == chain_idx as u64).collect();
            if chain_accounts.len() < 2 { continue; } // Need at least two accounts on the chain

            let from_acc = chain_accounts.choose(&mut rng).unwrap().clone();
            let mut to_acc = chain_accounts.choose(&mut rng).unwrap().clone();
            while from_acc == to_acc {
                 to_acc = chain_accounts.choose(&mut rng).unwrap().clone();
            }
            let asset = assets.iter().find(|a| a.chain_id == chain_idx as u64).unwrap().clone();
             let lock = LockInfo { account: from_acc.clone(), asset: asset.clone(), amount };

            transactions.push(Transaction {
                tx_id,
                tx_type: TxType::SingleChainTransfer, // Or TEE-abstracted single chain op
                accounts: vec![from_acc.clone(), to_acc.clone()],
                amounts: vec![amount],
                required_locks: vec![lock], // TEE might still use internal locking/sequencing
                target_asset: None,
                timeout,
            });
        }
    }
    transactions
}

// Helper function for percentile calculation
fn calculate_percentile(data: &mut [Duration], percentile: f64) -> Option<Duration> {
    if data.is_empty() {
        return None;
    }
    data.sort_unstable();
    // Calculate index (0-based)
    let index = ((percentile / 100.0 * data.len() as f64).ceil() as usize).saturating_sub(1);
    // Clamp index to bounds
    let clamped_index = std::cmp::min(index, data.len() - 1);
    Some(data[clamped_index])
}

#[tokio::test]
async fn test_scenario_c_tee_overhead() -> Result<(), String> {
    println!("--- Starting Scenario C: TEE Overhead Profiling ---");
    let start_scenario = Instant::now();

    // --- Configuration ---
    let num_chains = 2;
    let num_shards = 5;
    let nodes_per_shard = 7;
    let num_nodes = num_shards * nodes_per_shard;
    let cross_chain_ratio = 0.30; // rho = 30%
    let total_transactions = 5000;
    let submission_rate_tps = 150.0;
    let submission_interval = Duration::from_secs_f64(1.0 / submission_rate_tps);
    let accounts_per_chain = 20;
    // TEE threshold 't' isn't directly configured in Raft/SimulatedNode here, assumed implicitly by logic using shares

    let mut sim_config = SimulationConfig::default(); // Make mutable
    sim_config.tee_delays = TeeDelayConfig { 
        sign_min_ms: 5, 
        sign_max_ms: 10, 
        verify_min_ms: 1, 
        verify_max_ms: 2, 
        attest_min_ms: 20, 
        attest_max_ms: 30, 
    };
    sim_config.sync_system_config(); // Ensure SystemConfig within runtime gets updated delays

    // --- ALSO update the standalone 'config' used for node creation --- 
    let mut config = SystemConfig { // Make mutable
        num_shards,
        nodes_per_shard,
        raft_election_timeout_min_ms: 1500, 
        raft_election_timeout_max_ms: 3000,
        raft_heartbeat_ms: 500,
        ..Default::default()
    };
    config.tee_delays = sim_config.tee_delays.clone(); // <<< Copy delays here

    // --- Identities ---
    let identities: Vec<(TEEIdentity, SecretKey)> = (0..num_nodes).map(create_test_tee).collect();
    let node_identities: Vec<TEEIdentity> = identities.iter().map(|(id, _)| id.clone()).collect();

    // --- Assign Nodes to Shards (Simple Round Robin for fixed k) ---
    let mut shard_assignments: HashMap<usize, Vec<TEEIdentity>> = HashMap::new();
    for (i, identity) in node_identities.iter().enumerate() {
        let shard_id = i % num_shards;
        shard_assignments.entry(shard_id).or_default().push(identity.clone());
    }
    let shard_assignments_handle = Arc::new(tokio::sync::Mutex::new(shard_assignments.clone())); // For coordinator

    // --- Simulation Runtime ---
    println!("[Setup] Initializing Simulation Runtime...");
    let (runtime, mut result_rx, mut isolation_rx, metrics_handle) = SimulationRuntime::new(sim_config.clone());
    let mut node_query_senders = HashMap::new();
    let mut proposal_txs = HashMap::new();
    let mut nodes_to_spawn = Vec::new();

    // --- Create and Register Nodes ---
    println!("[Setup] Creating and registering {} nodes...", num_nodes);
    for (shard_id, nodes_in_shard) in &shard_assignments {
        runtime.assign_nodes_to_shard(*shard_id, nodes_in_shard.clone()).await;
        for tee_identity in nodes_in_shard {
            let (_, secret_key) = identities.iter().find(|(id, _)| id == tee_identity).unwrap();
            let peers: Vec<TEEIdentity> = nodes_in_shard.iter().filter(|&p| p != tee_identity).cloned().collect();
            let (proposal_tx, proposal_rx) = mpsc::channel::<NodeProposalRequest>(200); // Larger buffer maybe
            let (query_tx, query_rx) = mpsc::channel::<NodeQuery>(10);

            let network_rx = runtime.register_node(tee_identity.clone(), proposal_tx.clone()).await;
            node_query_senders.insert(tee_identity.id, query_tx.clone());
            proposal_txs.insert(tee_identity.id, proposal_tx.clone());

            let node = SimulatedTeeNode::new(
                tee_identity.clone(),
                secret_key.clone(),
                peers,
                config.clone(),
                runtime.clone(),
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
    let transactions = generate_scenario_c_transactions(total_transactions, cross_chain_ratio, num_chains, accounts_per_chain);
    let transactions_queue = Arc::new(Mutex::new(VecDeque::from(transactions)));

    // --- Transaction Submission Task ---
    println!("[Run] Starting transaction submission (Target: {} TPS)...", submission_rate_tps);
    let submission_task = tokio::spawn({
        let transactions_queue = transactions_queue.clone();
        let proposal_txs = proposal_txs.clone(); // Clone for the task
        let shard_assignments = shard_assignments.clone(); // Clone needed data
        let node_query_senders = node_query_senders.clone();
        async move {
            let mut leaders: HashMap<usize, Option<TEEIdentity>> = HashMap::new();
            let mut tx_submitted_count = 0;
            let mut interval = tokio::time::interval(submission_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst); // Try to catch up

            loop {
                interval.tick().await;
                let mut tx_opt = {
                    let mut queue = transactions_queue.lock().await;
                    queue.pop_front()
                };

                if let Some(tx) = tx_opt {
                    // Determine target shard (simplified: use first account)
                    let primary_account = tx.accounts.first().cloned().or_else(|| tx.required_locks.first().map(|l| l.account.clone()));
                    let target_shard_id = if let Some(acc) = primary_account {
                         // Simple modulo mapping for test, replace with ShardManager logic if needed
                         (acc.address.len() % num_shards) // Or use hash(acc.address) % num_shards
                    } else {
                        rand::thread_rng().gen_range(0..num_shards) // Fallback if no account info easily available
                    };


                    // Find leader for the shard (cache or query)
                    let leader_proposal_tx = match leaders.get(&target_shard_id) {
                        Some(Some(leader_id)) => proposal_txs.get(&leader_id.id),
                        _ => {
                            // Find leader dynamically (simplified query first node in shard)
                            let nodes_in_shard = shard_assignments.get(&target_shard_id).cloned().unwrap_or_default();
                            let mut found_leader = None;
                            for node_id in nodes_in_shard.iter() {
                                if let Some(query_sender) = node_query_senders.get(&node_id.id) {
                                    let (resp_tx, resp_rx) = oneshot::channel();
                                    if query_sender.send((NodeQueryRequest::GetRaftState, resp_tx)).await.is_ok() {
                                         if let Ok(Ok(NodeQueryResponse::RaftState { role, .. })) = tokio::time::timeout(Duration::from_millis(50), resp_rx).await {
                                             if role == teeshard_protocol::raft::state::RaftRole::Leader {
                                                 found_leader = Some(node_id.clone());
                                                 break;
                                             }
                                         }
                                    }
                                }
                            }
                            if let Some(leader) = found_leader {
                                 println!("[Submitter] Found leader {} for shard {}", leader.id, target_shard_id);
                                 leaders.insert(target_shard_id, Some(leader.clone()));
                                 proposal_txs.get(&leader.id)
                            } else {
                                println!("[Submitter] WARN: No leader found for shard {}, submitting to first node {} instead.", target_shard_id, nodes_in_shard.first().map(|n| n.id).unwrap_or(9999));
                                leaders.insert(target_shard_id, None); // Mark as unknown
                                // Fallback: submit to first node in shard
                                nodes_in_shard.first().and_then(|n| proposal_txs.get(&n.id))
                            }
                        }
                    };


                    // Propose command if leader/node found
                    if let Some(proposer_tx) = leader_proposal_tx {
                        let lock_data = LockProofData { // Create dummy/simplified LockProofData for command
                            shard_id: target_shard_id,
                            tx_id: tx.tx_id.clone(),
                            source_chain_id: tx.required_locks.first().map(|l| l.asset.chain_id).unwrap_or(0),
                            target_chain_id: tx.target_asset.as_ref().map(|a| a.chain_id).unwrap_or(0),
                            token_address: tx.required_locks.first().map(|l| l.asset.token_address.clone()).unwrap_or_default(),
                            amount: tx.amounts.first().cloned().unwrap_or(0),
                            recipient: tx.accounts.get(1).map(|a| a.address.clone()).unwrap_or_default(),
                             start_time: Instant::now(), // Track proposal time for latency calc?
                        };
                        let command = Command::ConfirmLockAndSign(lock_data); // Or potentially a different command type
                        let (ack_tx, _ack_rx) = oneshot::channel(); // Can ignore ack for high throughput test

                         if proposer_tx.send((command, ack_tx)).await.is_ok() {
                             tx_submitted_count += 1;
                         } else {
                             println!("[Submitter] Failed to send proposal for tx {}", tx.tx_id);
                              // Re-queue transaction?
                              // transactions_queue.lock().await.push_back(tx);
                         }
                    } else {
                         println!("[Submitter] No proposal channel found for shard {}, skipping tx {}", target_shard_id, tx.tx_id);
                         // Re-queue transaction?
                         // transactions_queue.lock().await.push_back(tx);
                    }
                } else {
                    // Queue is empty
                    break;
                }
            }
            println!("[Submitter] Submission finished. Submitted {} transactions.", tx_submitted_count);
            tx_submitted_count // Return count
        }
    });

    // --- Let Simulation Run ---
    println!("[Run] Waiting for simulation and transaction processing...");
    // Wait for submission to finish OR a timeout
    let submission_timeout = Duration::from_secs( (total_transactions as f64 / submission_rate_tps * 1.5) as u64 + 30 ); // Estimate run time + buffer
    let submission_result = tokio::time::timeout(submission_timeout, submission_task).await;

    let submitted_count = match submission_result {
        Ok(Ok(count)) => {
            println!("[Run] Submission task completed normally. Submitted: {}", count);
            count
        }
        Ok(Err(e)) => {
             eprintln!("[Run] Submission task failed: {:?}", e);
            return Err("Submission task failed".to_string());
        }
        Err(_) => {
            eprintln!("[Run] Submission task timed out after {:?}.", submission_timeout);
             return Err("Submission task timed out".to_string());
        }
    };

    // --- Collect Results ---
    println!("[Run] Collecting results and metrics...");
    tokio::time::sleep(Duration::from_secs(10)).await; // Extra time for processing

    // Shutdown nodes
    println!("[Cleanup] Sending shutdown signal...");
    let _ = shutdown_tx.send(());
    for (id, handle) in node_handles {
        // Allow slightly longer for cleanup in case of hangs
        if let Err(_) = tokio::time::timeout(Duration::from_secs(10), handle).await {
             eprintln!("[Cleanup] WARN: Node {} task timed out during shutdown await.", id);
             // Optionally, abort the handle if timeout occurs: handle.abort();
        } else {
            println!("[Cleanup] Node {} finished.", id);
        }
    }

    // --- Explicitly drop the runtime BEFORE awaiting metrics --- 
    println!("[Cleanup] Dropping SimulationRuntime instance...");
    drop(runtime);
    println!("[Cleanup] SimulationRuntime instance dropped.");
    // --- End Drop ---

    // Collect metrics from the handle by awaiting the JoinHandle
    let collected_metrics = match metrics_handle.await {
        Ok(metrics) => metrics,
        Err(e) => {
            eprintln!("[Error] Metrics collection task failed: {:?}", e);
            Vec::new() // Return empty Vec on error
        }
    };
    println!("[Metrics] Collected {} metric events.", collected_metrics.len());

    // --- Analyze Metrics (Improved) ---
    let mut tee_function_times: HashMap<String, Vec<Duration>> = HashMap::new();
    println!("[Debug Metrics] Analyzing {} collected events...", collected_metrics.len()); // Add count log
    for event in collected_metrics { // Use collected_metrics directly
        // ---- ADD DEBUG PRINT ----
        println!("[Debug Metrics] Event: {:?}", event); 
        // ---- END DEBUG PRINT ----
        if let MetricEvent::TeeFunctionMeasured { node_id: _, function_name, duration } = event {
            tee_function_times.entry(function_name).or_default().push(duration);
        }
        // TODO: Collect other relevant metrics if needed (RaftCommit latency, etc.)
    }

    println!("\n[Results] TEE Function Call Overheads:");
    let mut function_names: Vec<String> = tee_function_times.keys().cloned().collect();
    function_names.sort(); // Print in consistent order

    for name in function_names {
        if let Some(times) = tee_function_times.get_mut(&name) { // Get mutable slice for sorting
             println!("  - {}: {} calls", name, times.len());
            if !times.is_empty() {
                let total_duration: Duration = times.iter().sum();
                let avg_duration = total_duration / times.len() as u32;
                let p95_duration = calculate_percentile(times, 95.0);
                let p99_duration = calculate_percentile(times, 99.0); // times is already sorted by p95 calc
                
                println!("    - Avg: {:?}", avg_duration);
                if let Some(p95) = p95_duration {
                    println!("    - p95: {:?}", p95);
                }
                if let Some(p99) = p99_duration {
                    println!("    - p99: {:?}", p99);
                }
            } else {
                 println!("    - (No timing data collected)");
            }
        }
    }

    // --- CHALLENGE: Instrumentation & Baseline ---
    // TODO: Verify if the collected metrics (`TeeFunctionMeasured`) cover the required functions
    //       (GenerateLockProof, ThresholdSign, RemoteAttestation). May need adjustments in EnclaveSim/SimulatedTeeNode.
    // TODO: Implement the non-TEE baseline scenario for comparison.

    let scenario_duration = start_scenario.elapsed();
    println!("\n--- Scenario C Finished in {:?} ---", scenario_duration);
    Ok(())
}
 