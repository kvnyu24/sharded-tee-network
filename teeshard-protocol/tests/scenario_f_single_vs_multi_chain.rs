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

// --- Helper Functions (Copied from scenario_a_shard_scalability.rs) ---

fn create_test_tee_signing(id: usize) -> (TEEIdentity, SigningKey) {
    // Simple deterministic key generation for testing reproducibility
    let seed = [(id % 256) as u8; 32];
    let signing_key = SigningKey::from_bytes(&seed); // Removed .expect()
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

// --- Test Runner Function (Adapted for Scenario F parameters) ---

async fn run_scenario_f_trial(
    num_blockchains: usize, // Key variable: n=1 or n=4
    num_shards_per_chain: usize, // Used for n=4 case
    nodes_per_shard: usize,
    num_transactions: usize,
    target_tps: u64,
    cross_chain_ratio: f64, // Relevant for n=4 case
    num_coordinators: usize,
    coordinator_threshold: usize,
) -> (Vec<MetricEvent>, Duration) {
    let total_shards = if num_blockchains == 1 {
        // Determine shard structure for n=1. Maybe fixed k=5? Or num_shards_per_chain * 1?
        // Let's assume a fixed number of shards for n=1 for simplicity in this skeleton
        5 // Example: Use 5 shards for the single chain case
    } else {
        num_blockchains * num_shards_per_chain // k = n * shards_per_chain
    };

    println!("--- Starting Scenario F Trial (n={}, k={}, m={}, tx={}, tps={}, rho={}) ---",
             num_blockchains, total_shards, nodes_per_shard, num_transactions, target_tps, cross_chain_ratio);

    // --- Configuration ---
    let mut sim_config = SimulationConfig::default();
    sim_config.system_config.num_shards = total_shards;
    sim_config.system_config.nodes_per_shard = nodes_per_shard;
    sim_config.system_config.num_coordinators = num_coordinators;
    sim_config.system_config.coordinator_threshold = coordinator_threshold;
    sim_config.sync_system_config();

    let total_nodes = total_shards * nodes_per_shard;
    let coordinator_id_start = total_nodes;

    // --- Setup (Identical structure, total_shards determines loops) ---
    println!("[Scenario F] Setting up simulation...");
    let mut identities = Vec::new();
    let mut signing_keys = HashMap::new();
     for i in 0..(total_nodes + num_coordinators) { // Correct loop range
        let (identity, signing_key) = create_test_tee_signing(i); // Use helper
        identities.push(identity.clone());
        signing_keys.insert(identity.id, signing_key);
    }
    let coordinator_identities: Vec<TEEIdentity> = identities[coordinator_id_start..].to_vec();
    sim_config.system_config.coordinator_identities = coordinator_identities.clone();

    let (runtime, result_rx, _isolation_rx, metrics_handle) =
        SimulationRuntime::new(sim_config.clone());
    let mut opt_result_rx = Some(result_rx); // Wrap in Option

    let partition_mapping: PartitionMapping = HashMap::new();
    let mut nodes_to_spawn = Vec::new();
    // Shard Node Setup loop uses total_shards
     for shard_id in 0..total_shards {
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
            let peers: Vec<TEEIdentity> = identities[start_node_id..end_node_id].iter().filter(|id| id.id != identity.id).cloned().collect();
            let node = SimulatedTeeNode::new(identity.clone(), secret_key, peers, sim_config.system_config.clone(), runtime.clone(), network_rx, proposal_tx, proposal_rx, query_tx, query_rx, shard_id);
            nodes_to_spawn.push(node);
        }
        runtime.assign_nodes_to_shard(shard_id, current_shard_nodes).await;
    }

    // Coordinator Node Setup loop
     let blockchain_interface = Arc::new(MockBlockchainInterface::new());
    let mut coordinator_handles = Vec::new();
    for i in 0..num_coordinators {
        let coord_identity = coordinator_identities[i].clone();
        let coord_signing_key = signing_keys.get(&coord_identity.id).unwrap().clone();
        let (coord_network_tx, _coord_network_rx) = mpsc::channel(100);
        runtime.register_component(coord_identity.clone(), coord_network_tx).await;
        let coordinator_metrics_tx = runtime.get_metrics_sender();
        let coordinator = SimulatedCoordinator::new(coord_identity.clone(), coord_signing_key, sim_config.system_config.clone(), runtime.clone(), blockchain_interface.clone(), partition_mapping.clone(), coordinator_metrics_tx.clone());
        let coordinator_arc = Arc::new(coordinator);
        if i == 0 {
             if let Some(rx_to_move) = opt_result_rx.take() { // Take receiver
                 let listener_handle = {
                     let coordinator_clone = coordinator_arc.clone();
                     tokio::spawn(async move {
                         coordinator_clone.run_share_listener(rx_to_move).await; // Use taken receiver
                     })
                 };
                 coordinator_handles.push(listener_handle);
             } else {
                 eprintln!("[Scenario F] Error: Could not take result_rx for Coordinator 0 listener.");
             }
        } else { /* Spawn other coord tasks */ }
    }

    // Spawn Node Tasks
     let mut node_handles = Vec::new();
    for node in nodes_to_spawn { let handle = tokio::spawn(node.run()); node_handles.push(handle); }

    // --- Transaction Generation/Submission ---
    // Note: generate_test_transaction needs num_blockchains to create appropriate txs
    println!("[Scenario F] Starting transaction submission...");
    let submission_interval = Duration::from_secs_f64(1.0 / target_tps as f64);
    let start_of_submission = Instant::now();

    for i in 0..num_transactions {
        // For n=1, cross_chain should effectively be false or handled by generate_test_transaction
        let is_cross_chain = if num_blockchains > 1 {
            rand::random::<f64>() < cross_chain_ratio
        } else {
            false // No cross-chain if n=1
        };
        let (tx, _mock_swap_id_bytes) = generate_test_transaction(i, is_cross_chain, num_blockchains);
        let target_shard_id = i % total_shards; // Distribute across all available shards
        let lock_proof_data = LockProofData {
            tx_id: tx.tx_id.clone(),
            source_chain_id: tx.required_locks.first().map(|l| l.asset.chain_id).unwrap_or(0),
            target_chain_id: tx.target_asset.map(|a| a.chain_id).unwrap_or(0),
            token_address: tx.required_locks.first().map(|l| l.asset.token_address.clone()).unwrap_or_default(),
            amount: tx.amounts.first().copied().unwrap_or(0),
            recipient: tx.accounts.last().map(|a| a.address.clone()).unwrap_or_default(),
            start_time: Instant::now(),
        };
        let command = Command::ConfirmLockAndSign(lock_proof_data);
        runtime.send_command_to_shard(target_shard_id, command).await;
        tokio::time::sleep(submission_interval).await;
        // ... (Optional progress logging) ...
    }
    let submission_duration = start_of_submission.elapsed();
    println!("[Scenario F] Finished submitting {} transactions in {:?}.", num_transactions, submission_duration);

    // --- Completion Wait ---
    println!("[Scenario F] Waiting for transactions to complete (max 60s)... ");
    tokio::time::sleep(Duration::from_secs(60)).await;

    // --- Cleanup & Metric Collection ---
    println!("[Scenario F] Cleaning up nodes and collecting metrics...");
    for handle in coordinator_handles { handle.abort(); }
    for handle in node_handles { handle.abort(); }
    let collected_metrics = match metrics_handle.await {
        Ok(metrics) => metrics,
        Err(e) => { eprintln!("[Scenario F] Error awaiting metrics handle: {}", e); Vec::new() }
    };
    println!("[Scenario F] Trial finished.");
    (collected_metrics, submission_duration)
}

// --- Main Test Function ---

#[tokio::test]
#[ignore] // Ignore by default
async fn test_scenario_f_single_vs_multi_chain() {
    println!("===== Running Scenario F: Single vs Multi-Chain Test =====");
    let nodes_per_shard = 7; // m value
    let num_coordinators = 5;
    let coordinator_threshold = 3;
    let num_transactions = 5000; // Adjust as needed
    let target_tps = 200; // Adjust as needed
    let num_trials = 1; // TODO: Increase

    // Test configurations
    let test_configs = [
        // n=1 case (single chain)
        ("n=1", 1, 5, 0.0), // (name, num_blockchains, total_shards_override?, cross_chain_ratio) - Use 0 ratio for n=1
        // n=4 case (multi chain)
        ("n=4", 4, 2, 0.3), // (name, num_blockchains, shards_per_chain, cross_chain_ratio)
    ];

    let mut all_results: HashMap<String, Vec<MetricEvent>> = HashMap::new();
    let mut all_durations: HashMap<String, Vec<Duration>> = HashMap::new();

    for (config_name, n_blockchains, n_shards_param, cc_ratio) in test_configs {
        println!("\n>>> Testing Configuration: {} <<<", config_name);
        let mut trial_metrics = Vec::new();
        let mut trial_durations = Vec::new();

        // Determine shards_per_chain (only relevant if n > 1)
        let shards_per_chain = if n_blockchains > 1 { n_shards_param } else { 0 };

        for trial in 0..num_trials {
            println!("    Trial {}/{}...", trial + 1, num_trials);
            let (metrics, duration) = run_scenario_f_trial(
                n_blockchains,
                shards_per_chain, // Pass shards_per_chain logic
                nodes_per_shard,
                num_transactions,
                target_tps,
                cc_ratio,
                num_coordinators,
                coordinator_threshold,
            ).await;
            trial_metrics.extend(metrics);
            trial_durations.push(duration);
        }
        all_results.insert(config_name.to_string(), trial_metrics);
        all_durations.insert(config_name.to_string(), trial_durations);
    }

    println!("\n===== Scenario F Analysis =====");
    for (config_name, n_blockchains, n_shards_param, cc_ratio) in test_configs {
         if let (Some(metrics), Some(durations)) = (all_results.get(config_name), all_durations.get(config_name)) {
            let avg_duration = durations.iter().sum::<Duration>() / num_trials as u32;
            let mut params = HashMap::new();
            params.insert("config".to_string(), config_name.to_string());
            params.insert("n".to_string(), n_blockchains.to_string());
            // Calculate total shards again for reporting if needed
             let total_shards = if n_blockchains == 1 { 5 } else { n_blockchains * n_shards_param };
             params.insert("k_total".to_string(), total_shards.to_string());
            analyze_perf_results("Scenario F", &params, metrics, num_transactions * num_trials, avg_duration);
            // TODO: Extract and analyze specific metrics: latency, throughput, TEE overhead comparison
        }
    }
    println!("=======================================");
}

