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

// Import shared test utilities
use teeshard_protocol::test_utils::*;

// --- Helper Functions Removed (Now in test_utils) ---

// --- Test Runner Function (Adapted for Scenario B parameters) ---

async fn run_scenario_b_trial(
    num_shards: usize,
    nodes_per_shard: usize,
    num_transactions: usize,
    target_tps: u64,
    cross_chain_ratio: f64, // Key variable for this scenario
    num_coordinators: usize,
    coordinator_threshold: usize,
    num_blockchains: usize,
) -> (Vec<MetricEvent>, Duration) {
    println!("--- Starting Scenario B Trial (k={}, m={}, tx={}, tps={}, rho={}) ---",
             num_shards, nodes_per_shard, num_transactions, target_tps, cross_chain_ratio);

    // --- Configuration ---
    let mut sim_config = SimulationConfig::default();
    sim_config.system_config.num_shards = num_shards;
    sim_config.system_config.nodes_per_shard = nodes_per_shard;
    sim_config.system_config.num_coordinators = num_coordinators;
    sim_config.system_config.coordinator_threshold = coordinator_threshold;
    sim_config.sync_system_config();

    let total_nodes = num_shards * nodes_per_shard;
    let coordinator_id_start = total_nodes;

    // --- Setup (Similar to Scenario A) ---
    println!("[Scenario B] Setting up simulation...");
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
    let mut opt_result_rx = Some(result_rx);

    // --- Create Shutdown Signal ---
    let (shutdown_tx, shutdown_rx) = watch::channel(()); // Create the channel here
    // --- End Create ---

    let partition_mapping: PartitionMapping = HashMap::new();
    let shard_assignments: Arc<TokioMutex<HashMap<usize, Vec<TEEIdentity>>>> = Arc::new(TokioMutex::new(HashMap::new()));

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
        let coordinator_id_for_task = coord_identity.id; // Capture ID before move

        let (coord_network_tx, _coord_network_rx) = mpsc::channel(100);
        runtime.register_component(coord_identity.clone(), coord_network_tx).await;
        let coordinator_metrics_tx = runtime.get_metrics_sender();

        let coordinator = SimulatedCoordinator::new(
            coord_identity.clone(), coord_signing_key, sim_config.system_config.clone(),
            runtime.clone(), blockchain_interface.clone(), partition_mapping.clone(),
            coordinator_metrics_tx.clone(),
            shard_assignments.clone(), // Pass the local assignments map (Arg 8)
        );
        // Keep Arc if other tasks need it, but don't use it for listener call
        let coordinator_arc = Arc::new(coordinator);
        if i == 0 {
             if let Some(rx_to_move) = opt_result_rx.take() {
                 let listener_handle = {
                     let shutdown_rx_clone = shutdown_rx.clone(); // Clone receiver here
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
                  eprintln!("[Scenario B] Error: Could not take result_rx for Coordinator 0 listener.");
             }
        } else { /* Spawn other coord tasks if needed */ }
    }


    // ... (Spawn Node Tasks - identical to Scenario A) ...
    let mut node_handles = Vec::new();
    for node in nodes_to_spawn {
        let shutdown_rx_clone = shutdown_rx.clone(); // Clone receiver for node task
        let handle = tokio::spawn(async move {
            node.run(shutdown_rx_clone).await; // Pass receiver to run
        });
        node_handles.push(handle);
    }

    // --- Transaction Generation/Submission (Uses cross_chain_ratio) ---
    println!("[Scenario B] Starting transaction submission (rho={})...", cross_chain_ratio);
    let submission_interval = Duration::from_secs_f64(1.0 / target_tps as f64);
    let start_of_submission = Instant::now();

    for i in 0..num_transactions {
        let is_cross_chain = rand::random::<f64>() < cross_chain_ratio; // Use parameter
        let (tx, _mock_swap_id_bytes) = generate_test_transaction(i, is_cross_chain, num_blockchains); // Use helper
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
    println!("[Scenario B] Finished submitting {} transactions in {:?}.", num_transactions, submission_duration);

    // --- Completion Wait (Similar to Scenario A) ---
    println!("[Scenario B] Waiting for transactions to complete (max 60s)... ");
    tokio::time::sleep(Duration::from_secs(60)).await;

    // --- Cleanup & Metric Collection (Add graceful shutdown) ---
     println!("[Scenario B] Cleaning up nodes and collecting metrics...");
     // --- Send Shutdown Signal ---
     println!("[Scenario B] Sending shutdown signal...");
     if shutdown_tx.send(()).is_err() {
         eprintln!("[Scenario B] Warning: Shutdown channel already closed?");
     }
     println!("[Scenario B] Shutdown signal sent.");
     // --- End Send ---

     // --- Await Handles Gracefully ---
     println!("[Scenario B] Awaiting coordinator tasks...");
     for (i, handle) in coordinator_handles.into_iter().enumerate() {
         println!("[Scenario B] Awaiting coordinator handle {}...", i);
         if let Err(e) = handle.await {
             eprintln!("[Scenario B] Error awaiting coordinator handle: {}", e);
         }
         println!("[Scenario B] Coordinator handle {} finished.", i);
     }
     println!("[Scenario B] Coordinator tasks finished.");

     println!("[Scenario B] Awaiting node tasks...");
     for (i, handle) in node_handles.into_iter().enumerate() {
         println!("[Scenario B] Awaiting node handle {}...", i);
          if let Err(e) = handle.await {
              eprintln!("[Scenario B] Error awaiting node handle: {}", e);
          }
          println!("[Scenario B] Node handle {} finished.", i);
     }
      println!("[Scenario B] Node tasks finished.");
     // --- End Await ---

    // --- Drop the runtime explicitly AFTER tasks complete ---
    println!("[Scenario B] Dropping SimulationRuntime instance...");
    drop(runtime);
    println!("[Scenario B] SimulationRuntime instance dropped.");
    // --- End Drop ---

    println!("[Scenario B] Awaiting metrics handle...");
    let collected_metrics = match metrics_handle.await {
        Ok(metrics) => {
             println!("[Scenario B] Metrics collected successfully ({} events).", metrics.len());
            metrics
        },
        Err(e) => { 
            eprintln!("[Scenario B] Error awaiting metrics handle: {}", e); 
            Vec::new() 
        }
    };
    println!("[Scenario B] Metrics handle finished.");
    println!("[Scenario B] Trial finished.");
    (collected_metrics, submission_duration)
}

// --- Main Test Function ---

#[tokio::test]
async fn test_scenario_b_cross_chain_ratio() {
    println!("===== Running Scenario B: Cross-Chain Ratio Sensitivity Test =====");
    let num_shards = 5; // k value
    let nodes_per_shard = 7; // m value
    let num_coordinators = 5;
    let coordinator_threshold = 3;
    let num_transactions = 5000;
    let target_tps = 200; // Fixed TPS
    let cross_chain_ratios = [0.0, 0.2, 0.4, 0.6]; // rho values
    let num_blockchains = 2; // Assuming n=2 for this scenario
    let num_trials = 1; // TODO: Increase to 3 for averaging

    let mut all_results: HashMap<String, Vec<MetricEvent>> = HashMap::new(); // Use String key for float ratio
    let mut all_durations: HashMap<String, Vec<Duration>> = HashMap::new();

    for rho in cross_chain_ratios {
        let rho_key = format!("{:.1}", rho); // Key for the map
        println!("\n>>> Testing with rho = {}% cross-chain <<<", rho * 100.0);
        let mut trial_metrics = Vec::new();
        let mut trial_durations = Vec::new();
        for trial in 0..num_trials {
            println!("    Trial {}/{}...", trial + 1, num_trials);
            let (metrics, duration) = run_scenario_b_trial(
                num_shards,
                nodes_per_shard,
                num_transactions,
                target_tps,
                rho, // Pass the current ratio
                num_coordinators,
                coordinator_threshold,
                num_blockchains,
            ).await;
            trial_metrics.extend(metrics);
            trial_durations.push(duration);
        }
        all_results.insert(rho_key.clone(), trial_metrics);
        all_durations.insert(rho_key, trial_durations);
    }

    println!("\n===== Scenario B Analysis =====");
    for rho in cross_chain_ratios {
         let rho_key = format!("{:.1}", rho);
         if let (Some(metrics), Some(durations)) = (all_results.get(&rho_key), all_durations.get(&rho_key)) {
            let avg_duration = durations.iter().sum::<Duration>() / num_trials as u32;
            let mut params = HashMap::new();
            params.insert("k".to_string(), num_shards.to_string());
            params.insert("m".to_string(), nodes_per_shard.to_string());
            params.insert("rho".to_string(), rho_key);
            analyze_perf_results("Scenario B", &params, metrics, num_transactions * num_trials, avg_duration);
            // TODO: Extract and analyze specific metrics: cross-chain latency, TEE load, Raft traffic
        }
    }
    println!("=======================================");
}
