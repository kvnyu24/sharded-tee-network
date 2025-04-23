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

// --- Test Runner Function (Adapted for Scenario D parameters) ---

async fn run_scenario_d_trial(
    num_shards: usize,
    nodes_per_shard: usize,
    num_transactions: usize,
    target_tps: u64,
    cross_chain_ratio: f64,
    num_coordinators: usize,
    coordinator_threshold: usize,
    num_blockchains: usize,
    network_min_delay_ms: u64, // Key variable
    network_max_delay_ms: u64, // Key variable
    // packet_drop_rate: f64, // TODO: Add in Phase 3
) -> (Vec<MetricEvent>, Duration) {
    println!("--- Starting Scenario D Trial (k={}, m={}, delay=[{},{}], tps={}, rho={}) ---",
             num_shards, nodes_per_shard, network_min_delay_ms, network_max_delay_ms, target_tps, cross_chain_ratio);

    // --- Configuration (Set network delays) ---
    let mut sim_config = SimulationConfig::default();
    sim_config.system_config.num_shards = num_shards;
    sim_config.system_config.nodes_per_shard = nodes_per_shard;
    sim_config.system_config.num_coordinators = num_coordinators;
    sim_config.system_config.coordinator_threshold = coordinator_threshold;
    sim_config.network_min_delay_ms = network_min_delay_ms; // Set delay
    sim_config.network_max_delay_ms = network_max_delay_ms; // Set delay
    // sim_config.packet_drop_rate = packet_drop_rate; // Set drop rate later
    // **Important**: Raft timeouts might need adjusting based on network delay
    sim_config.system_config.raft_election_timeout_min_ms = network_max_delay_ms * 5; // Example heuristic
    sim_config.system_config.raft_election_timeout_max_ms = network_max_delay_ms * 10;
    sim_config.system_config.raft_heartbeat_ms = network_max_delay_ms * 2;
    sim_config.sync_system_config();

    // --- Setup (Identical to Scenario A/B) ---
    let total_nodes = num_shards * nodes_per_shard;
    let coordinator_id_start = total_nodes;
    println!("[Scenario D] Setting up simulation...");
    let mut identities = Vec::new();
    let mut signing_keys = HashMap::new();
     for i in 0..(total_nodes + num_coordinators) { // Correct loop range
        let (identity, signing_key) = create_test_tee_signing(i); // Use helper
        identities.push(identity.clone());
        signing_keys.insert(identity.id, signing_key);
    }
    let coordinator_identities: Vec<TEEIdentity> = identities[coordinator_id_start..].to_vec();
    sim_config.system_config.coordinator_identities = coordinator_identities.clone();

    // --- Create Shutdown Signal ---
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    // --- End Create ---

    let (runtime, result_rx, _isolation_rx, metrics_handle) =
        SimulationRuntime::new(sim_config.clone());
    let mut opt_result_rx = Some(result_rx);

    let partition_mapping: PartitionMapping = HashMap::new();
    // Local map to track shard assignments for the coordinator
    let shard_assignments: Arc<tokio::sync::Mutex<HashMap<usize, Vec<TEEIdentity>>>> = Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let mut nodes_to_spawn = Vec::new();
    // ... (Shard Node Setup loop - identical to Scenario A) ...
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

    // ... (Coordinator Node Setup loop - identical to Scenario A) ...
     let blockchain_interface = Arc::new(MockBlockchainInterface::new());
    let mut coordinator_handles = Vec::new();
    for i in 0..num_coordinators {
        let coord_identity = coordinator_identities[i].clone();
        let coord_signing_key = signing_keys.get(&coord_identity.id).unwrap().clone();
        let (coord_network_tx, _coord_network_rx) = mpsc::channel(100);
        runtime.register_component(coord_identity.clone(), coord_network_tx).await;
        let coordinator_metrics_tx = runtime.get_metrics_sender();
        let coordinator = SimulatedCoordinator::new(coord_identity.clone(), coord_signing_key, sim_config.system_config.clone(), runtime.clone(), blockchain_interface.clone(), partition_mapping.clone(), coordinator_metrics_tx.clone(), shard_assignments.clone(), // Pass the local assignments map (Arg 8)
        );
        let coordinator_arc = Arc::new(coordinator);
        if i == 0 {
             if let Some(rx_to_move) = opt_result_rx.take() {
                 let listener_handle = {
                     let coordinator_clone = coordinator_arc.clone();
                     let shutdown_rx_clone = shutdown_rx.clone(); // Clone receiver
                     tokio::spawn(async move {
                         // Pass shutdown receiver
                         coordinator_clone.run_share_listener(rx_to_move, shutdown_rx_clone).await;
                     })
                 };
                 coordinator_handles.push(listener_handle);
             } else {
                 eprintln!("[Scenario D] Error: Could not take result_rx for Coordinator 0 listener.");
             }
        } else { /* Spawn other coord tasks if needed */ }
    }

    // ... (Spawn Node Tasks - identical to Scenario A) ...
     let mut node_handles = Vec::new();
    for node in nodes_to_spawn {
        let shutdown_rx_clone = shutdown_rx.clone(); // Clone receiver
        let handle = tokio::spawn(async move {
            node.run(shutdown_rx_clone).await; // Pass receiver
        });
        node_handles.push(handle);
    }

    // --- Transaction Generation/Submission (Identical to Scenario B) ---
    println!("[Scenario D] Starting transaction submission...");
    let submission_interval = Duration::from_secs_f64(1.0 / target_tps as f64);
    let start_of_submission = Instant::now();

    for i in 0..num_transactions {
         let is_cross_chain = rand::random::<f64>() < cross_chain_ratio;
        let (tx, _mock_swap_id_bytes) = generate_test_transaction(i, is_cross_chain, num_blockchains);
        let target_shard_id = i % num_shards;
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
    println!("[Scenario D] Finished submitting {} transactions in {:?}.", num_transactions, submission_duration);

    // --- Completion Wait (Maybe needs to be longer with high latency) ---
    let wait_secs = if network_max_delay_ms > 100 { 90 } else { 60 };
    println!("[Scenario D] Waiting for transactions to complete (max {}s)... ", wait_secs);
    tokio::time::sleep(Duration::from_secs(wait_secs)).await;

    // --- Cleanup & Metric Collection (Add graceful shutdown) ---
     println!("[Scenario D] Cleaning up nodes and collecting metrics...");
     // --- Send Shutdown Signal ---
     println!("[Scenario D] Sending shutdown signal...");
     if shutdown_tx.send(()).is_err() {
         eprintln!("[Scenario D] Warning: Shutdown channel already closed?");
     }
     println!("[Scenario D] Shutdown signal sent.");
     // --- End Send ---

     // --- Await Handles Gracefully ---
     println!("[Scenario D] Awaiting coordinator tasks...");
     for handle in coordinator_handles {
         if let Err(e) = handle.await {
             eprintln!("[Scenario D] Error awaiting coordinator handle: {}", e);
         }
     }
     println!("[Scenario D] Coordinator tasks finished.");

     println!("[Scenario D] Awaiting node tasks...");
     for handle in node_handles {
          if let Err(e) = handle.await {
              eprintln!("[Scenario D] Error awaiting node handle: {}", e);
          }
     }
      println!("[Scenario D] Node tasks finished.");
     // --- End Await ---

     // Drop runtime AFTER awaiting tasks
     drop(runtime);

    let collected_metrics = match metrics_handle.await {
        Ok(metrics) => metrics,
        Err(e) => { eprintln!("[Scenario D] Error awaiting metrics handle: {}", e); Vec::new() }
    };
    println!("[Scenario D] Trial finished.");
    (collected_metrics, submission_duration)
}

// --- Main Test Function ---

#[tokio::test]
#[ignore] // Ignore by default
async fn test_scenario_d_network_delay_variations() {
    println!("===== Running Scenario D: Network Delay Variations Test =====");
    let num_shards = 5; // k value
    let nodes_per_shard = 7; // m value
    let num_coordinators = 5;
    let coordinator_threshold = 3;
    let num_transactions = 5000;
    let target_tps = 200; // Fixed TPS
    let cross_chain_ratio = 0.30; // rho = 30%
    let num_blockchains = 2;
    let num_trials = 1; // TODO: Increase

    // Network Profiles (min_ms, max_ms, drop_rate - drop rate added later)
    let network_profiles = [
        ("Low", 10, 20, 0.01),
        ("Moderate", 30, 50, 0.01),
        ("High", 80, 120, 0.02),
    ];

    let mut all_results: HashMap<String, Vec<MetricEvent>> = HashMap::new();
    let mut all_durations: HashMap<String, Vec<Duration>> = HashMap::new();

    for (profile_name, min_delay, max_delay, _drop_rate) in network_profiles {
        println!("\n>>> Testing with Network Profile: {} (Delay: {}-{}ms) <<<", profile_name, min_delay, max_delay);
        let mut trial_metrics = Vec::new();
        let mut trial_durations = Vec::new();
        for trial in 0..num_trials {
            println!("    Trial {}/{}...", trial + 1, num_trials);
            let (metrics, duration) = run_scenario_d_trial(
                num_shards,
                nodes_per_shard,
                num_transactions,
                target_tps,
                cross_chain_ratio,
                num_coordinators,
                coordinator_threshold,
                num_blockchains,
                min_delay, // Pass delay param
                max_delay, // Pass delay param
                // drop_rate, // Pass drop rate later
            ).await;
            trial_metrics.extend(metrics);
            trial_durations.push(duration);
        }
        all_results.insert(profile_name.to_string(), trial_metrics);
        all_durations.insert(profile_name.to_string(), trial_durations);
    }

    println!("\n===== Scenario D Analysis =====");
    for (profile_name, min_delay, max_delay, _drop_rate) in network_profiles {
         if let (Some(metrics), Some(durations)) = (all_results.get(profile_name), all_durations.get(profile_name)) {
            let avg_duration = durations.iter().sum::<Duration>() / num_trials as u32;
            let mut params = HashMap::new();
            params.insert("profile".to_string(), profile_name.to_string());
            params.insert("min_delay".to_string(), min_delay.to_string());
            params.insert("max_delay".to_string(), max_delay.to_string());
            // params.insert("drop_rate".to_string(), drop_rate.to_string());
            analyze_perf_results("Scenario D", &params, metrics, num_transactions * num_trials, avg_duration);
            // TODO: Extract and analyze specific metrics: finality latency, Raft elections
        }
    }
    println!("=======================================");
}
