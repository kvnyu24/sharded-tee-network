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
use tokio::sync::{mpsc, oneshot, Mutex as TokioMutex, watch};
use std::sync::Arc;
use ed25519_dalek::SigningKey;
use hex;
use rand::Rng;
use log::warn;


use teeshard_protocol::test_utils::*;


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

    // --- Create Shutdown Signal ---
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    // --- End Create ---

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
    // Local map to track shard assignments for the coordinator
    let shard_assignments: Arc<tokio::sync::Mutex<HashMap<usize, Vec<TEEIdentity>>>> = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

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
            // Keep track of identities for local map
            current_shard_nodes.push(identity.clone());
        }
        // Assign in runtime AND store locally
        runtime.assign_nodes_to_shard(shard_id, current_shard_nodes.clone()).await;
        shard_assignments.lock().await.insert(shard_id, current_shard_nodes);
    }

    // Coordinator Node Setup loop
     let blockchain_interface = Arc::new(MockBlockchainInterface::new());
    let mut coordinator_handles = Vec::new();
    for i in 0..num_coordinators {
        let coord_identity = coordinator_identities[i].clone();
        let coord_signing_key = signing_keys.get(&coord_identity.id).unwrap().clone();
        let coordinator_id_for_task = coord_identity.id; // Capture ID before move

        let (coord_network_tx, _coord_network_rx) = mpsc::channel(100);
        runtime.register_component(coord_identity.clone(), coord_network_tx).await;
        let coordinator_metrics_tx = runtime.get_metrics_sender();
        let coordinator = SimulatedCoordinator::new(
            coord_identity.clone(),
            coord_signing_key,
            sim_config.system_config.clone(),
            runtime.clone(),
            blockchain_interface.clone(),
            partition_mapping.clone(),
            coordinator_metrics_tx.clone(),
            shard_assignments.clone(), // Pass the local assignments map (Arg 8)
        );
        // Keep Arc if other tasks need it
        let coordinator_arc = Arc::new(coordinator);
        if i == 0 {
             if let Some(rx_to_move) = opt_result_rx.take() {
                 let listener_handle = {
                     // REMOVE: let coordinator_clone = coordinator_arc.clone();
                     let shutdown_rx_clone = shutdown_rx.clone(); // Clone receiver
                     tokio::spawn(async move { // Only move required items
                         // Call the associated function directly using :: syntax
                         SimulatedCoordinator::run_share_listener(
                            coordinator_id_for_task, // Pass captured ID
                            rx_to_move,
                            shutdown_rx_clone
                         ).await;
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
    for node in nodes_to_spawn {
        let shutdown_rx_clone = shutdown_rx.clone(); // Clone receiver
        let handle = tokio::spawn(async move {
            node.run(shutdown_rx_clone).await;
        });
        node_handles.push(handle);
    }

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
        let target_shard_id = i % total_shards; // Use total_shards here
        let lock_proof_data = LockProofData {
            tx_id: tx.tx_id.clone(),
            shard_id: target_shard_id, // ADDED: Use the calculated target shard ID
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

    // --- Cleanup & Metric Collection (Add graceful shutdown) ---
    println!("[Scenario F] Cleaning up nodes and collecting metrics...");
    // --- Send Shutdown Signal ---
    println!("[Scenario F] Sending shutdown signal...");
    if shutdown_tx.send(()).is_err() {
        eprintln!("[Scenario F] Warning: Shutdown channel already closed?");
    }
    println!("[Scenario F] Shutdown signal sent.");
    // --- End Send ---

    // --- Drop runtime BEFORE awaiting tasks ---
    println!("[Scenario F] Dropping SimulationRuntime instance...");
    drop(runtime); // Drop the SimulationRuntime instance
    println!("[Scenario F] SimulationRuntime instance dropped.");
    // --- End Drop ---

    // --- Await Handles Gracefully (with Timeouts) ---
    println!("[Scenario F] Awaiting coordinator tasks...");
    for handle in coordinator_handles {
        if let Err(_) = tokio::time::timeout(Duration::from_secs(10), handle).await {
            eprintln!("[Scenario F] WARN: Coordinator task timed out during shutdown await.");
        } // No else needed
    }
    println!("[Scenario F] Coordinator tasks finished (or timed out).");

    println!("[Scenario F] Awaiting node tasks...");
    for handle in node_handles {
         if let Err(_) = tokio::time::timeout(Duration::from_secs(10), handle).await {
             eprintln!("[Scenario F] WARN: Node task timed out during shutdown await.");
         } // No else needed
    }
     println!("[Scenario F] Node tasks finished (or timed out).");
    // --- End Await ---

    println!("[Scenario F] Awaiting metrics handle..."); // Added log
    let collected_metrics = match metrics_handle.await {
        Ok(metrics) => metrics,
        Err(e) => { eprintln!("[Scenario F] Error awaiting metrics handle: {}", e); Vec::new() }
    };
    println!("[Scenario F] Trial finished.");
    (collected_metrics, submission_duration)
}

// --- Main Test Function ---

#[tokio::test]
// #[ignore] // Ignore by default - REMOVED
async fn test_scenario_f_single_vs_multi_chain() {
    println!("===== Running Scenario F: Single vs Multi-Chain Test =====");
    let nodes_per_shard = 7; // m value
    let num_coordinators = 5;
    let coordinator_threshold = 3;
    let num_transactions = 5000; // Adjust as needed
    let target_tps = 200; // Adjust as needed
    let num_trials = 3; // Increased from 1

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

