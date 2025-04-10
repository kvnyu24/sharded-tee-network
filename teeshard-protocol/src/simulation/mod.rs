// teeshard-protocol/src/simulation/mod.rs

pub mod node;
pub mod runtime;
pub mod coordinator;
pub mod mocks;
pub mod config;
pub mod network;
pub mod metrics;

// Re-export key simulation components
pub use node::SimulatedTeeNode;
pub use runtime::SimulationRuntime;
pub use coordinator::CoordinatorCommand;
pub use config::SimulationConfig;

use crate::data_structures::TEEIdentity;
use crate::tee_logic::crypto_sim::generate_keypair;
use crate::liveness::{challenger::Challenger, aggregator::Aggregator};
use crate::liveness::types::LivenessConfig as LivenessSystemConfig;
 // Assuming this will be refactored
use crate::config::SystemConfig as NodeSystemConfig; // Rename to avoid clash
use crate::simulation::node::{NodeProposalRequest, NodeQuery};
// Correct imports for mocks
use crate::network::MockNetwork;
use crate::simulation::mocks::MockBlockchainInterface; // Use this mock
use crate::shard_manager::PartitionMapping;
use crate::simulation::coordinator::SimulatedCoordinator;
use crate::tee_logic::crypto_sim::SecretKey; // Corrected Import Path
use rand::rngs::OsRng;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Represents the overall simulation setup and execution environment.
pub struct Simulation {
    pub runtime: SimulationRuntime,
    // Add handles for spawned tasks if needed for management
    pub node_handles: Vec<JoinHandle<()>>,
    pub coordinator_handles: Vec<JoinHandle<()>>,
    pub liveness_handles: Vec<JoinHandle<()>>,
    // Add other simulation state if necessary
}

impl Simulation {
    /// Builds the simulation environment based on the provided configuration.
    pub async fn build(config: SimulationConfig) -> Self {
        // Create runtime first
        let (runtime, _result_rx, _isolation_rx_agg_to_runtime, _metrics_handle) = 
            SimulationRuntime::new(config.clone());
        let _config_arc = runtime.get_config(); // Prefix unused config_arc

        let mut node_handles = Vec::new();
        let mut coordinator_handles = Vec::new();
        let mut liveness_handles = Vec::new();

        // 1. Generate TEE Identities for all nodes and coordinators
        let mut all_tee_identities = Vec::new();
        let mut all_tee_keys = HashMap::new(); // Store keys mapped by ID for easy lookup
        let total_shard_nodes = config.num_shards * config.nodes_per_shard;
        let total_entities = total_shard_nodes + config.num_coordinators + 2; // +2 for Challenger/Aggregator
        log::info!("Generating {} TEE identities...", total_entities);
        for i in 0..total_entities {
            let keypair = generate_keypair();
            let identity = TEEIdentity { id: i, public_key: keypair.verifying_key() };
            all_tee_identities.push(identity.clone());
            all_tee_keys.insert(i, keypair); // Store associated secret key by ID
        }

        // Separate identities
        let node_identities: Vec<_> = all_tee_identities.iter().take(total_shard_nodes).cloned().collect();
        let coordinator_identities: Vec<_> = all_tee_identities.iter().skip(total_shard_nodes).take(config.num_coordinators).cloned().collect();
        let challenger_identity = all_tee_identities.get(total_shard_nodes + config.num_coordinators).cloned();
        let aggregator_identity = all_tee_identities.get(total_shard_nodes + config.num_coordinators + 1).cloned();
        log::info!("Generated {} node identities, {} coordinator identities", node_identities.len(), coordinator_identities.len());

        // 1.1 Create NodeSystemConfig from SimulationConfig
        let node_sys_config = NodeSystemConfig {
            num_shards: config.num_shards,
            nodes_per_shard: config.nodes_per_shard,
            // Map SimulationConfig network delays to Raft timeouts (example heuristic)
            raft_election_timeout_min_ms: config.network_max_delay_ms * 5, // e.g., 5x max network delay
            raft_election_timeout_max_ms: config.network_max_delay_ms * 10,
            raft_heartbeat_ms: config.network_max_delay_ms * 2, // e.g., 2x max network delay
            coordinator_threshold: config.coordinator_threshold,
            coordinator_identities: coordinator_identities.clone(),
            ..Default::default()
        };

        // 2. Assign nodes to shards (Map shard_id -> Vec<TEEIdentity>)
        let mut shard_assignments = HashMap::new();
        let mut node_id_counter = 0;
        for shard_id in 0..config.num_shards {
            let mut nodes_in_shard = Vec::new();
            for _ in 0..config.nodes_per_shard {
                if let Some(identity) = node_identities.get(node_id_counter) {
                    nodes_in_shard.push(identity.clone());
                    node_id_counter += 1;
                } else {
                    log::error!("Ran out of generated node identities while assigning to shards!");
                    break;
                }
            }
            runtime.assign_nodes_to_shard(shard_id, nodes_in_shard.clone()).await;
            shard_assignments.insert(shard_id, nodes_in_shard);
        }

        // 3. Instantiate and Spawn Node Tasks
        log::info!("Spawning {} SimulatedTeeNode tasks...", node_identities.len());
        for identity in &node_identities {
            let node_id = identity.id;
            let signing_key = all_tee_keys.get(&node_id).expect("Node key must exist").clone();

            // Determine shard_id and peers for this node
            let shard_id = shard_assignments.iter()
                .find_map(|(sid, nodes)| if nodes.contains(identity) { Some(*sid) } else { None })
                .expect("Node must belong to a shard");
            let peers = shard_assignments.get(&shard_id).unwrap().iter()
                .filter(|peer_id| peer_id.id != node_id)
                .cloned()
                .collect();

            // Create proposal/query channels for this node
            let (proposal_tx, proposal_rx) = mpsc::channel::<NodeProposalRequest>(10);
            let (query_tx, query_rx) = mpsc::channel::<NodeQuery>(10);

            // Register the node with the runtime
            let network_rx = runtime.register_node(identity.clone(), proposal_tx.clone()).await;

            // Now create the node, passing all channels AND shard_id
            let node = SimulatedTeeNode::new(
                identity.clone(), 
                signing_key, 
                peers, 
                node_sys_config.clone(), 
                runtime.clone(),
                network_rx, // Pass receiver from runtime
                proposal_tx, // Pass proposal sender
                proposal_rx, // Pass proposal receiver
                query_tx,    // Pass query sender
                query_rx,    // Pass query receiver
                shard_id,    // Pass the determined shard_id
            );

            // Spawn the node's main loop
            let handle = tokio::spawn(async move {
                node.run().await;
            });
            node_handles.push(handle);
        }
        log::info!("Spawned {} node tasks.", node_handles.len());

        // 4. Instantiate and Spawn Coordinator Tasks (Placeholder/Needs Refactor)
        log::info!("Spawning {} Coordinator tasks...", config.num_coordinators);
        for i in 0..config.num_coordinators {
            if let Some(identity) = coordinator_identities.get(i) {
                let secret_key = all_tee_keys.get(&identity.id).expect("Coordinator key must exist").clone();
                let coordinator_runtime = runtime.clone(); // Clone runtime for coordinator
                let metrics_tx_clone = runtime.get_metrics_sender(); // Get metrics sender

                // NOTE: This part uses MockNetwork and needs full refactor for EmulatedNetwork
                let mock_network = Arc::new(MockNetwork::new()); 
                let mock_relayer = Arc::new(MockBlockchainInterface::new()); // Replace with actual relayer later
                let partition_mapping = PartitionMapping::new(); // Example, needs real mapping

                let coordinator = SimulatedCoordinator::new(
                    identity.clone(),
                    secret_key,
                    node_sys_config.clone(), // Using the node config for now
                    coordinator_runtime,
                    mock_relayer, // Using mock relayer
                    partition_mapping,
                    metrics_tx_clone, // Pass the metrics sender
                );

                // Spawn coordinator task(s) - Placeholder, needs run methods
                let coord_handle = tokio::spawn(async move {
                    log::warn!("SimulatedCoordinator run loop not implemented!");
                    // coordinator.run_command_listener(...).await;
                    // coordinator.run_share_listener(...).await;
                });
                coordinator_handles.push(coord_handle);
            } else {
                log::error!("Could not get identity for coordinator index {}", i);
            }
        }
        // log::warn!("Coordinator task spawning is placeholder - requires refactoring CrossChainCoordinator and runtime interface implementations.");

        // 5. Instantiate and Spawn Liveness Tasks
        log::info!("Spawning Liveness Challenger and Aggregator tasks...");
        if let (Some(challenger_id), Some(_aggregator_id)) = (challenger_identity.clone(), aggregator_identity.clone()) {
            // 5.1 Create LivenessSystemConfig from SimulationConfig
            let liveness_config = LivenessSystemConfig {
                tee_delays: config.tee_delays.clone(),
                default_trust: 100.0, // Make configurable?
                trust_increment: 1.0, // Make configurable?
                trust_decrement: 10.0, // Make configurable?
                trust_threshold: 50.0, // Make configurable?
                high_trust_threshold: 150.0, // Make configurable?
                min_interval: Duration::from_millis(config.tee_delays.attest_max_ms * 5 + config.network_max_delay_ms * 2), // Heuristic
                max_interval: Duration::from_millis(config.tee_delays.attest_max_ms * 10 + config.network_max_delay_ms * 5),
                max_failures: 3, // Make configurable?
                challenge_window: Duration::from_millis(config.tee_delays.attest_max_ms + config.network_max_delay_ms * 2), // Window based on TEE + network
            };

            // --- Aggregator --- 
            let (challenge_tx_for_agg, challenge_rx_for_agg) = mpsc::channel(100); // Aggregator listens for challenges issued by Challenger
            // Aggregator::new takes 6 arguments now
            // It returns a tuple: (Aggregator, mpsc::Receiver<ChallengeNonce>)
            let metrics_tx_agg = runtime.get_metrics_sender(); // Get metrics sender
            let aggregator_id = aggregator_identity.clone().unwrap(); 
            let (aggregator, _challenge_rx_returned) = Aggregator::new(
                aggregator_id,           // 1st: identity
                liveness_config.clone(), // 2nd: config
                node_identities.clone(), // 3rd: initial nodes
                runtime.clone(),         // 4th: runtime
                Some(metrics_tx_agg),    // 5th: metrics sender
                challenge_rx_for_agg,    // 6th: challenge receiver
            );
            // We capture the returned receiver but might not need it immediately,
            // as run_challenge_listener takes the original 'challenge_rx_for_agg'.

            let aggregator_arc = Arc::new(aggregator); // Wrap the instance from the tuple
            // Aggregator needs the receiver for attestations FROM the runtime
            // TODO: Refactor Aggregator to receive attestations via EmulatedNetwork
            // Commenting out listener spawn for now as it uses the wrong channel type
            // let agg_attestation_listener_handle = tokio::spawn(Arc::clone(&aggregator_arc).run_attestation_listener(???)); 
            let agg_timeout_handle = tokio::spawn(Arc::clone(&aggregator_arc).run_timeout_checker());
            // Spawn challenge listener with the original receiver channel
            let agg_challenge_listener_handle = tokio::spawn(Arc::clone(&aggregator_arc).run_challenge_listener(_challenge_rx_returned)); // Use the returned rx here
            // liveness_handles.push(agg_attestation_listener_handle);
            liveness_handles.push(agg_timeout_handle);
            liveness_handles.push(agg_challenge_listener_handle);

            // --- Challenger --- 
            // Challenger::new takes 4 arguments
            let challenger = Challenger::new(
                challenger_id, // Pass challenger identity
                node_identities.clone(), // Nodes to challenge
                runtime.clone(), // Pass runtime for routing challenges TO nodes
                challenge_tx_for_agg, // Pass the sender for Aggregator's challenge info channel
            );
            let chal_handle = tokio::spawn(async move { challenger.run().await; });
            liveness_handles.push(chal_handle);
            log::info!("Spawned Liveness tasks.");

        } else {
             log::error!("Could not get identities for Challenger/Aggregator!");
        }

        Simulation {
            runtime,
            node_handles,
            coordinator_handles,
            liveness_handles,
        }
    }

    // Add method to run the simulation (e.g., inject workload, wait for completion)
    pub async fn run(&mut self) {
        log::info!("Starting simulation run...");
        // TODO: Implement workload injection based on config
        // TODO: Implement simulation duration or transaction count limits
        // TODO: Wait for tasks or manage shutdown

        // Example: Wait for node tasks (this will block indefinitely without shutdown logic)
        // for handle in self.node_handles.drain(..) {
        //     let _ = handle.await;
        // }
         log::warn!("Simulation run logic is placeholder.");
    }
} 