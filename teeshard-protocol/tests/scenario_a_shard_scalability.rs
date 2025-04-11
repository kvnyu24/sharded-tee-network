use teeshard_protocol::{
    config::SystemConfig,
    data_structures::{TEEIdentity, Transaction, AccountId, AssetId, LockInfo, TxType},
    network::NetworkMessage,
    raft::{messages::{}, node::RaftEvent, state::{Command, RaftRole}},
    simulation::{
        node::NodeProposalRequest,
        runtime::SimulationRuntime,
        node::{SimulatedTeeNode, NodeQueryRequest, NodeQueryResponse, NodeQuery},
        config::SimulationConfig,
        mocks::MockBlockchainInterface,
        coordinator::SimulatedCoordinator,
        metrics::MetricEvent,
    },
    tee_logic::crypto_sim::{SecretKey, verify, generate_keypair},
    tee_logic::types::LockProofData,
    shard_manager::PartitionMapping,
};
use std::time::{Duration, Instant};
use std::collections::{HashMap, HashSet};
use tokio::sync::{mpsc, oneshot};
use std::sync::Arc;
use ed25519_dalek::SigningKey;
use hex;
use rand::Rng;
use log::warn;

// --- Helper Functions (Copied from simulation_tests.rs - TODO: Move to shared test utils module) ---

fn create_test_tee_signing(id: usize) -> (TEEIdentity, SigningKey) {
    // Simple deterministic key generation for testing reproducibility
    let seed = [(id % 256) as u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    (TEEIdentity { id, public_key: verifying_key }, signing_key)
}


fn generate_test_transaction(tx_id_num: usize, cross_chain: bool, num_chains: usize) -> (Transaction, [u8; 32]) {
    // Ensure num_chains > 0
    let num_chains = if num_chains == 0 { 1 } else { num_chains };
    let chain_id_a = (tx_id_num % num_chains) as u64; // Assign to a chain
    let chain_id_b = ((tx_id_num + 1) % num_chains) as u64; // Assign to potentially different chain

    let acc_a1 = AccountId { chain_id: chain_id_a, address: format!("user_a_{}", tx_id_num) };
    let acc_a2 = AccountId { chain_id: chain_id_a, address: format!("pool_{}", chain_id_a) };
    let asset_a = AssetId { chain_id: chain_id_a, token_symbol: format!("TKA{}", chain_id_a), token_address: format!("0xA{}", chain_id_a) };

    // Create a mock 32-byte ID (e.g., tx_id_num as bytes padded)
    let mut mock_swap_id = [0u8; 32];
    let num_bytes = (tx_id_num as u64).to_be_bytes();
    let start_index = mock_swap_id.len() - num_bytes.len();
    mock_swap_id[start_index..].copy_from_slice(&num_bytes);

    if cross_chain && chain_id_a != chain_id_b {
        let acc_b1 = AccountId { chain_id: chain_id_b, address: format!("user_b_{}", tx_id_num) };
        let acc_b2 = AccountId { chain_id: chain_id_b, address: format!("pool_{}", chain_id_b) };
        let asset_b = AssetId { chain_id: chain_id_b, token_symbol: format!("TKB{}", chain_id_b), token_address: format!("0xB{}", chain_id_b) };
        let tx = Transaction {
            tx_id: format!("cc-tx-{}", tx_id_num),
            tx_type: TxType::CrossChainSwap,
            accounts: vec![acc_a1.clone(), acc_a2, acc_b1.clone(), acc_b2],
            amounts: vec![100, 50], // Example amounts
            required_locks: vec![
                LockInfo { account: acc_a1, asset: asset_a.clone(), amount: 100 },
                LockInfo { account: acc_b1, asset: asset_b.clone(), amount: 50 },
            ],
            target_asset: Some(asset_b), // Target asset for the swap
            timeout: Duration::from_secs(60),
        };
        (tx, mock_swap_id)
    } else {
        // Treat as single chain even if originally cross_chain was true but chains matched
        let tx = Transaction {
            tx_id: format!("sc-tx-{}", tx_id_num),
            tx_type: TxType::SingleChainTransfer,
            accounts: vec![acc_a1.clone(), acc_a2],
            amounts: vec![100],
            required_locks: vec![LockInfo { account: acc_a1, asset: asset_a, amount: 100 }],
            target_asset: None,
            timeout: Duration::from_secs(60),
        };
        (tx, mock_swap_id)
    }
}

// --- Performance Analysis Function (Based on provided baseline) ---
fn analyze_perf_results(
    scenario_name: &str,
    scenario_params: &HashMap<String, String>,
    metrics: &[MetricEvent],
    submitted_count: usize,
    submission_duration: Duration,
) {
    let mut latencies = Vec::new();
    let mut completed_count = 0;
    let mut successful_count = 0;

    // Assuming MetricEvent::TransactionCompleted exists with these fields
    for event in metrics {
        if let MetricEvent::TransactionCompleted { start_time, end_time, success, .. } = event {
            completed_count += 1;
            if *success { 
                successful_count += 1;
                if *end_time >= *start_time {
                    latencies.push((*end_time - *start_time).as_micros());
                } else {
                    warn!("Completion time (end_time) before start time detected, skipping latency calc.");
                }
            }
        }
        // TODO: Add extraction for other relevant metrics based on scenario
        // e.g., Raft events, TEE operation timings if available in MetricEvent
    }

    latencies.sort_unstable();

    let avg_latency_us = if !latencies.is_empty() {
        latencies.iter().sum::<u128>() / latencies.len() as u128
    } else {
        0
    };
    // Calculate p95 and p99 only if there are enough successful transactions
    let p95_latency_us = if latencies.len() > 1 {
        let index = (latencies.len() as f64 * 0.95).floor() as usize;
        latencies[index.min(latencies.len() - 1)] // Ensure index is within bounds
    } else {
        avg_latency_us // Fallback to average if too few samples
    };
    let p99_latency_us = if latencies.len() > 1 {
        let index = (latencies.len() as f64 * 0.99).floor() as usize;
        latencies[index.min(latencies.len() - 1)] // Ensure index is within bounds
    } else {
        avg_latency_us // Fallback to average if too few samples
    };

    // Calculate throughput based on *completed* transactions over *submission* duration.
    // This is a reasonable approximation but might slightly overestimate if completion lags significantly.
    let throughput_cps = if submission_duration > Duration::ZERO {
        completed_count as f64 / submission_duration.as_secs_f64()
    } else {
        0.0 // Avoid division by zero
    };

    println!("\n--- {} Analysis (Params: {:?}) ---", scenario_name, scenario_params);
    println!("Submitted Transactions: {}", submitted_count);
    println!("Completed Transactions: {}", completed_count);
    println!("Successful Transactions: {}", successful_count); // Added successful count
    println!("Submission Duration: {:.2?}", submission_duration);
    println!("Calculated Throughput (Completed/SubmissionTime): {:.2} CPS", throughput_cps);
    if !latencies.is_empty() {
        println!("Latency (Successful TXs): [based on {} samples]", latencies.len());
        println!("  Average: {:.3} ms", avg_latency_us as f64 / 1000.0);
        println!("  P95:     {:.3} ms", p95_latency_us as f64 / 1000.0);
        println!("  P99:     {:.3} ms", p99_latency_us as f64 / 1000.0);
    } else {
        println!("Latency (Successful TXs): No successful transactions with valid timings recorded.");
    }
    println!("------------------------------------\n");
}

// --- Test Runner Function ---

async fn run_scenario_a_trial(
    num_shards: usize,
    nodes_per_shard: usize,
    num_transactions: usize,
    target_tps: u64,
    cross_chain_ratio: f64,
    num_coordinators: usize,
    coordinator_threshold: usize,
    num_blockchains: usize,
) -> (Vec<MetricEvent>, Duration) {
    println!("--- Starting Scenario A Trial (k={}, m={}, tx={}, tps={}, rho={}, coords={}, chains={}) ---",
             num_shards, nodes_per_shard, num_transactions, target_tps, cross_chain_ratio, num_coordinators, num_blockchains);

    // --- Configuration ---
    let mut sim_config = SimulationConfig::default();
    sim_config.system_config.num_shards = num_shards;
    sim_config.system_config.nodes_per_shard = nodes_per_shard;
    sim_config.system_config.num_coordinators = num_coordinators;
    sim_config.system_config.coordinator_threshold = coordinator_threshold;
    // TODO: Configure network delays if needed for specific trials
    sim_config.sync_system_config();

    let total_nodes = num_shards * nodes_per_shard;
    let coordinator_id_start = total_nodes;

    // --- Setup ---
    println!("[Scenario A] Setting up simulation...");
    let mut identities = Vec::new();
    let mut signing_keys = HashMap::new();
    for i in 0..(total_nodes + sim_config.system_config.num_coordinators) {
        let (identity, signing_key) = create_test_tee_signing(i);
        identities.push(identity.clone());
        signing_keys.insert(identity.id, signing_key);
    }

    // Assign coordinator identities to config
    let coordinator_identities: Vec<TEEIdentity> = identities[coordinator_id_start..].to_vec();
    sim_config.system_config.coordinator_identities = coordinator_identities.clone();

    // Runtime setup
    let (runtime, result_rx, _isolation_rx, metrics_handle) =
        SimulationRuntime::new(sim_config.clone());
    let mut opt_result_rx = Some(result_rx); // Wrap in Option

    // Dummy partition mapping (may need refinement based on actual partitioning logic)
    let partition_mapping: PartitionMapping = HashMap::new();

    // Setup Shard Nodes
    let mut nodes_to_spawn = Vec::new();
    for shard_id in 0..num_shards {
        let mut current_shard_nodes = Vec::new();
        let start_node_id = shard_id * nodes_per_shard;
        let end_node_id = start_node_id + nodes_per_shard;

        for node_id in start_node_id..end_node_id {
            let identity = identities[node_id].clone();
            let secret_key = signing_keys.get(&identity.id).unwrap().clone();
            current_shard_nodes.push(identity.clone());

            let (proposal_tx, proposal_rx) = mpsc::channel::<NodeProposalRequest>(100);
            let (query_tx, query_rx) = mpsc::channel::<NodeQuery>(10);

            let network_rx = runtime.register_node(identity.clone(), proposal_tx.clone()).await;

            let peers: Vec<TEEIdentity> = identities[start_node_id..end_node_id]
                .iter()
                .filter(|id| id.id != identity.id)
                .cloned()
                .collect();

            let node = SimulatedTeeNode::new(
                identity.clone(), secret_key, peers, sim_config.system_config.clone(),
                runtime.clone(), network_rx, proposal_tx, proposal_rx, query_tx, query_rx,
                shard_id,
            );
            nodes_to_spawn.push(node);
        }
        runtime.assign_nodes_to_shard(shard_id, current_shard_nodes).await;
    }
    println!("[Scenario A] Shard nodes created and registered.");

    // Setup Coordinator Nodes
    let blockchain_interface = Arc::new(MockBlockchainInterface::new());
    let mut coordinator_handles = Vec::new();
    // Channel for coordinator results (if multiple coordinators produce results)
    // let (coord_result_tx, mut coord_result_rx) = mpsc::channel(100);

    for i in 0..num_coordinators {
        println!("[Debug] Loop iteration i = {}", i);
        println!("[Debug][i={}] Accessing coordinator_identities[{}] (BEFORE CLONE)", i, i);
        let identity_ref = &coordinator_identities[i]; // Get reference first
        println!("[Debug][i={}] Cloning identity ID {}", i, identity_ref.id);
        let coord_identity = identity_ref.clone(); // Clone the reference
        println!("[Debug][i={}] Identity cloned successfully.", i);
        
        println!("[Debug][i={}] Getting signing key for ID {} (BEFORE GET)", i, coord_identity.id);
        let signing_key_option = signing_keys.get(&coord_identity.id); // Separate get
        println!("[Debug][i={}] Signing key get returned Option: is_some={}", i, signing_key_option.is_some());
        let signing_key_ref = signing_key_option.unwrap(); // Separate unwrap
        println!("[Debug][i={}] Cloning signing key", i);
        let coord_signing_key = signing_key_ref.clone(); // Separate clone
        println!("[Debug][i={}] Signing key cloned successfully.", i);

        println!("[Debug][i={}] Creating channel", i);
        let (coord_network_tx, _coord_network_rx) = mpsc::channel(100);
        println!("[Debug][i={}] PRE-AWAIT runtime.register_component for ID {}", i, coord_identity.id);
        runtime.register_component(coord_identity.clone(), coord_network_tx).await;
        println!("[Debug][i={}] POST-AWAIT runtime.register_component for ID {}", i, coord_identity.id);
        let coordinator_metrics_tx = runtime.get_metrics_sender();

        println!("[Debug][i={}] Calling SimulatedCoordinator::new for ID {}", i, coord_identity.id);
        let coordinator = SimulatedCoordinator::new(
            coord_identity.clone(),
            coord_signing_key,
            sim_config.system_config.clone(),
            runtime.clone(),
            blockchain_interface.clone(),
            partition_mapping.clone(), // This is currently an empty HashMap
            coordinator_metrics_tx.clone(),
        );
        println!("[Debug][i={}] SimulatedCoordinator::new finished", i);
        let coordinator_arc = Arc::new(coordinator);

        // Spawn listener for the first coordinator
        if i == 0 {
            println!("[Debug][i={}] In i == 0 block", i);
             if let Some(rx_to_move) = opt_result_rx.take() { // Take the receiver here
                 let listener_handle = {
                     let coordinator_clone = coordinator_arc.clone();
                     tokio::spawn(async move {
                         coordinator_clone.run_share_listener(rx_to_move).await;
                     })
                 };
                 coordinator_handles.push(listener_handle);
                 println!("[Scenario A] Spawned Share Listener for Coordinator {}.", coord_identity.id);
            } else {
                 eprintln!("[Scenario A] Error: Could not take result_rx for Coordinator 0 listener.");
             }
        } else {
             println!("[Debug][i={}] In else block for coordinator setup", i);
             println!("[Scenario A] TODO: Spawn other tasks for Coordinator {}.", coord_identity.id);
        }
         println!("[Debug][i={}] End of loop iteration", i);
    }

    // Spawn Shard Nodes
    let mut node_handles = Vec::new();
    for node in nodes_to_spawn {
        let handle = tokio::spawn(node.run());
        node_handles.push(handle);
    }
    println!("[Scenario A] Spawned {} shard nodes.", total_nodes);

    // --- Transaction Generation/Submission ---
    println!("[Scenario A] Starting transaction submission ({} tx, target {} TPS)...", num_transactions, target_tps);
    let submission_interval = Duration::from_secs_f64(1.0 / target_tps as f64);
    let start_of_submission = Instant::now();

    for i in 0..num_transactions {
        let is_cross_chain = rand::random::<f64>() < cross_chain_ratio;
        let (tx, _mock_swap_id_bytes) = generate_test_transaction(i, is_cross_chain, num_blockchains);

        // Target shard determination (simple round-robin)
        let target_shard_id = i % num_shards;

        // Command creation (assuming ConfirmLockAndSign is the entry point)
        // This needs verification - does the client interact directly or propose this command?
        // For perf test, assume this command triggers the TEE flow.
        let lock_proof_data = LockProofData {
            tx_id: tx.tx_id.clone(), // Use descriptive ID? Or bytes32 ID? Needs consistency.
            source_chain_id: tx.required_locks.first().map(|l| l.asset.chain_id).unwrap_or(0),
            target_chain_id: tx.target_asset.map(|a| a.chain_id).unwrap_or(0),
            token_address: tx.required_locks.first().map(|l| l.asset.token_address.clone()).unwrap_or_default(),
            amount: tx.amounts.first().copied().unwrap_or(0),
            recipient: tx.accounts.last().map(|a| a.address.clone()).unwrap_or_default(),
            start_time: Instant::now(), // Initialize the new field
        };
        let command = Command::ConfirmLockAndSign(lock_proof_data);

        runtime.send_command_to_shard(target_shard_id, command).await;

        tokio::time::sleep(submission_interval).await;
        if i % 100 == 0 && i > 0 { // Log every 100
            println!("[Scenario A] Submitted {} transactions...", i);
        }
    }
    let submission_duration = start_of_submission.elapsed();
    println!("[Scenario A] Finished submitting {} transactions in {:?}.", num_transactions, submission_duration);

    // --- Completion Wait ---
    // TODO: Implement robust completion check (e.g., wait for expected metric count or use channels)
    println!("[Scenario A] Waiting for transactions to complete (max 60s)... ");
    tokio::time::sleep(Duration::from_secs(60)).await; // Increased wait time

    // --- Cleanup & Metric Collection ---\n    println!(\"[Scenario A] Cleaning up nodes and collecting metrics...\");
    // Abort coordinator tasks first
    for handle in coordinator_handles { handle.abort(); }
    // Abort node tasks
    for handle in node_handles { handle.abort(); }

    let collected_metrics = match metrics_handle.await {
        Ok(metrics) => metrics,
        Err(e) => { eprintln!("[Scenario A] Error awaiting metrics handle: {}", e); Vec::new() }
    };
    println!("[Scenario A] Trial finished.");
    (collected_metrics, submission_duration)
}

// --- Main Test Function ---

#[tokio::test]
#[ignore] // Ignore by default, run explicitly
async fn test_scenario_a_shard_scalability() {
    println!("===== Running Scenario A: Shard Scalability Test =====");
    let shard_counts = [2, 4, 5, 8, 10]; // k values
    let nodes_per_shard = 7; // m value
    let num_coordinators = 5; // Assuming a coordinator committee size
    let coordinator_threshold = 4; // t value (Changed from 3 to 4)
    let num_transactions = 5000;
    let target_tps = 300; // Example target TPS
    let cross_chain_ratio = 0.30; // rho = 30%
    let num_blockchains = 2; // n=2
    let num_trials = 1; // TODO: Increase to 3 for averaging

    let mut all_results: HashMap<usize, Vec<MetricEvent>> = HashMap::new();
    let mut all_durations: HashMap<usize, Vec<Duration>> = HashMap::new();

    for k in shard_counts {
        println!("\n>>> Testing with k = {} shards <<<", k);
        let mut trial_metrics = Vec::new();
        let mut trial_durations = Vec::new();
        for trial in 0..num_trials {
            println!("    Trial {}/{}...", trial + 1, num_trials);
            let (metrics, duration) = run_scenario_a_trial(
                k,
                nodes_per_shard,
                num_transactions,
                target_tps,
                cross_chain_ratio,
                num_coordinators,
                coordinator_threshold,
                num_blockchains,
            ).await;
            trial_metrics.extend(metrics);
            trial_durations.push(duration);
        }
        all_results.insert(k, trial_metrics);
        all_durations.insert(k, trial_durations);
    }

    println!("\n===== Scenario A Analysis =====");
    for k in shard_counts {
        if let (Some(metrics), Some(durations)) = (all_results.get(&k), all_durations.get(&k)) {
            let avg_duration = durations.iter().sum::<Duration>() / num_trials as u32;
            let mut params = HashMap::new();
            params.insert("k".to_string(), k.to_string());
            params.insert("m".to_string(), nodes_per_shard.to_string());
            params.insert("t".to_string(), coordinator_threshold.to_string());
            // Aggregate metrics across trials if necessary before analyzing
            analyze_perf_results("Scenario A", &params, metrics, num_transactions * num_trials, avg_duration);
        }
    }
    println!("=======================================");
}
