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
use rand::{thread_rng, Rng};
use tracing::{info, warn};

// Import shared test utilities
use teeshard_protocol::test_utils::*;

// --- Helper Functions Removed (Now in test_utils) ---

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
    sim_config.system_config.coordinator_threshold = coordinator_threshold;
    sim_config.system_config.num_coordinators = num_coordinators;

    // Increase Raft timeouts to potentially avoid election loops
    sim_config.system_config.raft_election_timeout_min_ms = 1000;
    sim_config.system_config.raft_election_timeout_max_ms = 2000;
    sim_config.system_config.raft_heartbeat_ms = 200;

    let total_nodes = num_shards * nodes_per_shard;
    let coordinator_id_start = total_nodes;

    // --- Setup ---
    println!("[Scenario A] Setting up simulation...");
    let mut identities = Vec::new();
    let mut signing_keys = HashMap::new();
    for i in 0..(total_nodes + num_coordinators) {
        let (identity, signing_key) = create_test_tee_signing(i);
        identities.push(identity.clone());
        signing_keys.insert(identity.id, signing_key);
    }

    let coordinator_identities: Vec<TEEIdentity> = identities[coordinator_id_start..].to_vec();
    sim_config.system_config.coordinator_identities = coordinator_identities.clone();

    // Runtime setup
    println!("[Debug] >>> PRE SimulationRuntime::new <<<");
    let (runtime, result_rx, _isolation_rx, metrics_handle) =
        SimulationRuntime::new(sim_config.clone());
    println!("[Debug] >>> POST SimulationRuntime::new <<<");
    let mut opt_result_rx = Some(result_rx);

    let partition_mapping: PartitionMapping = HashMap::new();
    let shard_assignments: Arc<TokioMutex<HashMap<usize, Vec<TEEIdentity>>>> = Arc::new(TokioMutex::new(HashMap::new()));

    let blockchain_interface = Arc::new(MockBlockchainInterface::new());
    let mut coordinator_handles = Vec::new();
    let mut node_handles = Vec::new();

    // --- Create Shutdown Signal ---
    let (shutdown_tx, shutdown_rx) = watch::channel(());
    // --- End Create ---

    // --- RESTORE THE NORMAL SETUP LOOPS ---
    println!("[DEBUG] >>> Entering Shard Node PREPARATION Loop <<<"); // Added
    let mut nodes_to_spawn = Vec::new(); // Define nodes_to_spawn here
    for shard_id in 0..num_shards {
        println!("[Debug][Shard Prep {}] >>> Loop Start <<<", shard_id); // Added
        let mut current_shard_nodes = Vec::new();
        let start_node_id = shard_id * nodes_per_shard;
        let end_node_id = start_node_id + nodes_per_shard;

        for node_id in start_node_id..end_node_id {
            println!("[Debug][Shard Prep {}][Node {}] >>> Inner Loop Start <<<", shard_id, node_id); // Added
            let identity = identities[node_id].clone();
            let secret_key = signing_keys.get(&identity.id).unwrap().clone();
            // current_shard_nodes.push(identity.clone()); // Pushed later

            let (proposal_tx, proposal_rx) = mpsc::channel::<NodeProposalRequest>(10000);
            let (query_tx, query_rx) = mpsc::channel::<NodeQuery>(1000);

            println!("[Debug][Shard Prep {}][Node {}] PRE runtime.register_node <<<", shard_id, node_id); // Added
            let network_rx = runtime.register_node(identity.clone(), proposal_tx.clone()).await;
            println!("[Debug][Shard Prep {}][Node {}] POST runtime.register_node <<<", shard_id, node_id); // Added

            let peers: Vec<TEEIdentity> = identities[start_node_id..end_node_id]
                .iter()
                .filter(|id| id.id != identity.id)
                .cloned()
                .collect();

            let node = SimulatedTeeNode::new(
                identity.clone(), secret_key, peers, sim_config.system_config.clone(),
                runtime.clone(), network_rx, proposal_tx, proposal_rx, query_tx, query_rx,
                shard_id as usize,
            );
            nodes_to_spawn.push(node);
            current_shard_nodes.push(identity.clone()); // Add to list for assignment
        }
        runtime.assign_nodes_to_shard(shard_id, current_shard_nodes.clone()).await;
        shard_assignments.lock().await.insert(shard_id, current_shard_nodes);
    }
    println!("[Scenario A] Shard nodes created and registered.");

    println!("[Debug] >>> Entering Coordinator Setup Loop <<<");
    for i in 0..num_coordinators {
         println!("[Debug][Coord {}] >>> Loop Start <<<", i); // Added
         let coord_identity = coordinator_identities[i].clone();
         let coord_signing_key = signing_keys.get(&coord_identity.id).unwrap().clone();

         println!("[Debug][Coord {}] Creating channel", i); // Added
         let (coord_network_tx, _coord_network_rx) = mpsc::channel(100);
         println!("[Debug][Coord {}] PRE-AWAIT runtime.register_component for ID {}", i, coord_identity.id); // Added
         runtime.register_component(coord_identity.clone(), coord_network_tx).await;
         println!("[Debug][Coord {}] POST-AWAIT runtime.register_component for ID {}", i, coord_identity.id); // Added
         let coordinator_metrics_tx = runtime.get_metrics_sender();

         println!("[Debug][Coord {}] Calling SimulatedCoordinator::new for ID {}", i, coord_identity.id); // Added
         let coordinator = SimulatedCoordinator::new(
             coord_identity.clone(),
             coord_signing_key,
             sim_config.system_config.clone(),
             runtime.clone(),
             blockchain_interface.clone(),
             partition_mapping.clone(),
             coordinator_metrics_tx.clone(),
             shard_assignments.clone(),
         );
         println!("[Debug][Coord {}] SimulatedCoordinator::new finished", i); // Added
         let coordinator_arc = Arc::new(coordinator);
         let coordinator_id_for_task = coord_identity.id; // Capture ID before move

         if i == 0 {
             println!("[Debug][Coord {}] In i == 0 block, PRE-TAKE opt_result_rx", i); // Added
              if let Some(rx_to_move) = opt_result_rx.take() {
                  println!("[Debug][Coord 0 Listener] Spawning Task."); // Updated log
                  let listener_handle = {
                      // --- Pass Shutdown Receiver ---
                      let shutdown_rx_clone = shutdown_rx.clone();
                      // DO NOT CAPTURE coordinator_arc here
                      tokio::spawn(async move { // Only move necessary items
                          println!("[Debug][Coord {} Listener] Task started.", coordinator_id_for_task);
                          // Call the static-like function from the SimulatedCoordinator struct
                          SimulatedCoordinator::run_share_listener(
                              coordinator_id_for_task, // Pass the ID
                              rx_to_move,
                              shutdown_rx_clone
                          ).await;
                          println!("[Debug][Coord {} Listener] Task finished.", coordinator_id_for_task);
                      })
                      // --- End Pass ---
                  };
                  coordinator_handles.push(listener_handle);
                  println!("[Debug][Coord {}] POST-SPAWN Share Listener for Coordinator {}.", i, coord_identity.id); // Added
             } else {
                  eprintln!("[Scenario A] Error: Could not take result_rx for Coordinator 0 listener.");
              }
         } else {
              println!("[Debug][Coord {}] In else block for coordinator setup", i); // Added
              // TODO: If spawning other coordinator tasks (like command listener) that NEED self,
              // you would capture coordinator_arc for those tasks.
              // Example:
              // let cmd_listener_handle = {
              //     let coord_clone = coordinator_arc.clone();
              //     let (cmd_tx, cmd_rx) = mpsc::channel(10); // Need command channel setup
              //     // Store cmd_tx somewhere accessible
              //     tokio::spawn(async move {
              //         coord_clone.run_command_listener(cmd_rx).await;
              //     })
              // };
              // coordinator_handles.push(cmd_listener_handle);
              println!("[Scenario A] TODO: Spawn other tasks for Coordinator {}.", coord_identity.id);
         }
          println!("[Debug][Coord {}] >>> Loop End <<<", i); // Added
    }
    println!("[Debug] >>> Exited Coordinator Setup Loop <<<"); // Added

    println!("[Debug] >>> Entering Shard Node Spawning Loop <<<"); // Added
    // let mut node_handles = Vec::new(); // Already defined above
    for (idx, node) in nodes_to_spawn.into_iter().enumerate() {
        let node_id = node.identity.id;
        // Capture shard_id *before* moving node into the async block
        let node_shard_id = node.shard_id(); 
        println!("[Debug][Node Spawn {}] PRE-SPAWN for Node ID {}", idx, node_id); // Added
        let handle = {
            // --- Pass Shutdown Receiver ---
            let shutdown_rx_clone = shutdown_rx.clone();
            tokio::spawn(async move {
                println!("[Node {} Task Startup] Entered run method. Shard ID: {}", node_id, node_shard_id);
                node.run(shutdown_rx_clone).await;
                println!("[Node {} Task] Finished.", node_id); // Added inside task
            })
            // --- End Pass ---
        };
        node_handles.push(handle);
        println!("[Debug][Node Spawn {}] POST-SPAWN for Node ID {}", idx, node_id); // Added
    }
    println!("[Debug] >>> Exited Shard Node Spawning Loop <<<"); // Added
    println!("[Scenario A] Spawned {} shard nodes.", node_handles.len());
    // --- END RESTORE ---

    // ADDED: Debug print to confirm setup phase completion
    println!("[Debug] >>> Setup Phase Completed. Entering Transaction Submission <<< ");

    // --- Transaction Generation/Submission (Restore original target shard logic) ---
    println!("[Scenario A] Starting transaction submission ({} tx, target {} TPS)...", num_transactions, target_tps);
    let submission_interval = Duration::from_secs_f64(1.0 / target_tps as f64);
    let start_of_submission = Instant::now();

    println!("[Debug] >>> Entering submission FOR loop <<< ");
    for i in 0..num_transactions {
        let is_cross_chain = rand::random::<f64>() < cross_chain_ratio;
        let (tx, _mock_swap_id_bytes) = generate_test_transaction(i, is_cross_chain, num_blockchains);

        // --- RESTORE Original shard target ---
        let target_shard_id = i % num_shards;

        let lock_proof_data = LockProofData {
            tx_id: tx.tx_id.clone(),
            shard_id: target_shard_id, // Use original target shard ID
            source_chain_id: tx.required_locks.first().map(|l| l.asset.chain_id).unwrap_or(0),
            target_chain_id: tx.target_asset.map(|a| a.chain_id).unwrap_or(0),
            token_address: tx.required_locks.first().map(|l| l.asset.token_address.clone()).unwrap_or_default(),
            amount: tx.amounts.first().copied().unwrap_or(0),
            recipient: tx.accounts.last().map(|a| a.address.clone()).unwrap_or_default(),
            start_time: Instant::now(),
        };
        let command = Command::ConfirmLockAndSign(lock_proof_data);

        println!("[Debug] >>> Sending command for tx {} to shard {} <<< ", i, target_shard_id);
        runtime.send_command_to_shard(target_shard_id, command).await;
        println!("[Debug] >>> Command for tx {} sent <<< ", i);

        tokio::time::sleep(submission_interval).await;
        if i % 100 == 0 && i > 0 {
            println!("[Scenario A] Submitted {} transactions...", i);
        }
    }
    let submission_duration = start_of_submission.elapsed();
    println!("[Scenario A] Finished submitting {} transactions in {:?}.", num_transactions, submission_duration);

    // --- Completion Wait ---
    println!("[Scenario A] SUBMISSION COMPLETE. Entering 60s wait period...");
    println!("[Scenario A] Waiting for transactions to complete (max 60s)... ");
    tokio::time::sleep(Duration::from_secs(60)).await;

    // --- Cleanup & Metric Collection ---
    println!("[Scenario A] Cleaning up nodes and collecting metrics...");
    // REMOVED: Abort loops are replaced by graceful shutdown below
    // for handle in coordinator_handles { handle.abort(); }
    // for handle in node_handles { handle.abort(); }

    // --- Send Shutdown Signal ---
    println!("[Scenario A] Sending shutdown signal...");
    if shutdown_tx.send(()).is_err() {
        eprintln!("[Scenario A] Warning: Shutdown channel already closed?");
    }
    println!("[Scenario A] Shutdown signal sent.");
    // --- End Send ---

    // --- FIX: Drop the runtime BEFORE awaiting tasks ---
    println!("[Scenario A] Dropping SimulationRuntime instance...");
    drop(runtime);
    println!("[Scenario A] SimulationRuntime instance dropped.");
    // --- END FIX ---

    // --- Await Handles Gracefully ---
    println!("[Scenario A] Awaiting coordinator tasks...");
    for handle in coordinator_handles {
        if let Err(e) = handle.await {
            // Use Display formatting for JoinError
            eprintln!("[Scenario A] Error awaiting coordinator handle: {}", e);
        }
    }
    println!("[Scenario A] Coordinator tasks finished.");

    println!("[Scenario A] Awaiting node tasks...");
    for handle in node_handles {
         if let Err(e) = handle.await {
             // Use Display formatting for JoinError
             eprintln!("[Scenario A] Error awaiting node handle: {}", e); 
         }
    }
     println!("[Scenario A] Node tasks finished.");
    // --- End Await ---

    println!("[Scenario A] Awaiting metrics handle..."); // Added log
    let collected_metrics = match metrics_handle.await {
        Ok(metrics) => {
            println!("[Scenario A] Metrics collected successfully ({} events).", metrics.len()); // Added log
            metrics
        },
        Err(e) => {
            eprintln!("[Scenario A] Error awaiting metrics handle: {}", e);
            Vec::new()
        }
    };
    println!("[Scenario A] Trial finished.");
    (collected_metrics, submission_duration)
}

// --- Main Test Function ---

#[tokio::test(flavor = "multi_thread")]
async fn scenario_a_shard_scalability() {
    println!(">>> Entering scenario_a_shard_scalability test function <<<"); // Added: Very first line
    println!("===== Running Scenario A: Shard Scalability Test =====");
    let shard_counts = [2]; // k values - REDUCED TO 1 for faster testing
    let nodes_per_shard = 7; // m value
    let num_coordinators = 5; // Assuming a coordinator committee size
    let coordinator_threshold = 4; // t value (Changed from 3 to 4)
    let num_transactions = 5000; // Keep 5k for load
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
