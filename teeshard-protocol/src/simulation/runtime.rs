// teeshard-protocol/src/simulation/runtime.rs
use crate::{
    data_structures::TEEIdentity,
    liveness::types::LivenessAttestation, // Removed ChallengeNonce, NonceChallenge will be imported separately or confirmed
    raft::{messages::RaftMessage, state::Command}, // Import Command
    tee_logic::types::{LockProofData, Signature},
    simulation::node::NodeProposalRequest, // Import NodeProposalRequest
    simulation::config::SimulationConfig, // Import the new SimulationConfig
    network::{NetworkInterface, NetworkMessage, Message}, // Import Message enum
    simulation::network::EmulatedNetwork, // Import EmulatedNetwork
    simulation::metrics::{MetricsCollector, MetricEvent},
};
use std::collections::{HashMap, HashSet}; // Added HashSet
use std::sync::{Arc}; // Remove std Mutex import
use tokio::sync::{mpsc, oneshot, Mutex as TokioMutex}; // Add TokioMutex
use log::{debug, warn, error, info}; // Import log macros and info
use crate::liveness::types::NonceChallenge; // Import specifically
 // Need this for Message::LivenessResponse
use std::time::Duration; // Add Duration import
use rand::Rng; // Import Rng for packet loss
 // Import std::sync::Mutex

// Type for results sent back from nodes (e.g., signature shares)
// Tuple: (Signer Identity, Data Signed (e.g., LockProofData), Signature)
pub type SignatureShare = (TEEIdentity, LockProofData, Signature); // Use Signature struct

/// Manages the simulated network and nodes.
/// Cloning this struct allows multiple components (nodes, coordinator) to interact with the runtime.
#[derive(Clone, Debug)]
pub struct SimulationRuntime {
    // Simulation Configuration
    config: Arc<SimulationConfig>,
    // Emulated Network Interface
    network: Arc<EmulatedNetwork>,

    // Map Node ID -> Full TEEIdentity (needed for constructing NetworkMessage)
    node_identities: Arc<TokioMutex<HashMap<usize, TEEIdentity>>>,
    // Identity of the registered Aggregator (if any)
    aggregator_identity: Arc<TokioMutex<Option<TEEIdentity>>>,

    // --- Channels for INTERNAL Runtime -> Node communication (e.g., command proposal) ---
    // These might not go through the EmulatedNetwork
    node_proposal_senders: Arc<TokioMutex<HashMap<usize, mpsc::Sender<NodeProposalRequest>>>>,

    // --- Channels for Component -> Runtime communication (results, reports) ---
    result_tx: mpsc::Sender<SignatureShare>,
    isolation_report_tx: mpsc::Sender<Vec<usize>>,
    metrics_tx: mpsc::Sender<MetricEvent>,

    // --- Component Registration State (managed by Runtime) ---
    shard_assignments: Arc<TokioMutex<HashMap<usize, Vec<TEEIdentity>>>>,

    // --- Crash Fault State ---
    crashed_nodes: Arc<TokioMutex<HashSet<usize>>>, // Added state for crashed nodes

    // --- OBSOLETE? Channels previously used for direct Runtime -> Component message sending ---
    // These will likely be replaced by sending via EmulatedNetwork
    // node_raft_senders: Arc<Mutex<HashMap<usize, mpsc::Sender<(TEEIdentity, RaftMessage)>>>>,
    // node_challenge_senders: Arc<Mutex<HashMap<usize, mpsc::Sender<ChallengeNonce>>>>,
    aggregator_attestation_tx: Arc<TokioMutex<Option<mpsc::Sender<LivenessAttestation>>>>,
}

impl SimulationRuntime {
    /// Creates a new simulation runtime and returns it along with receivers.
    pub fn new(config: SimulationConfig) -> (
        Self, 
        mpsc::Receiver<SignatureShare>, 
        mpsc::Receiver<Vec<usize>>, // Return Vec<usize> receiver
        tokio::task::JoinHandle<Vec<MetricEvent>>, // Return JoinHandle for metrics collector
    ) {
        let (result_tx, result_rx) = mpsc::channel(50000);
        let (isolation_tx, isolation_rx) = mpsc::channel(100); // For isolation reports (Vec<usize>)
        // Create channel for metrics
        let (metrics_tx, metrics_rx) = mpsc::channel(50000); // Increased from 1000 to 50000
        // Create MetricsCollector instance with the receiver
        let mut metrics_collector = MetricsCollector::new(metrics_rx);

        let config_arc = Arc::new(config);
        let network = Arc::new(EmulatedNetwork::new(Arc::clone(&config_arc)));

        let runtime = SimulationRuntime {
            config: config_arc,
            network, // Store the emulated network
            node_identities: Arc::new(TokioMutex::new(HashMap::new())), // Initialize map
            aggregator_identity: Arc::new(TokioMutex::new(None)), // Initialize aggregator identity

            // Keep internal command proposal channel map
            node_proposal_senders: Arc::new(TokioMutex::new(HashMap::new())),

            // Keep result/report channels
            result_tx,
            isolation_report_tx: isolation_tx,
            metrics_tx: metrics_tx.clone(), // Store the metrics sender

            // Keep shard assignments map
            shard_assignments: Arc::new(TokioMutex::new(HashMap::new())),

            // Initialize crashed nodes set
            crashed_nodes: Arc::new(TokioMutex::new(HashSet::new())), // Initialize empty set

            // Remove obsolete direct senders
            // node_raft_senders: Arc::new(Mutex::new(HashMap::new())),
            // node_challenge_senders: Arc::new(Mutex::new(HashMap::new()))
            aggregator_attestation_tx: Arc::new(TokioMutex::new(None)),
        };

        // Spawn the metrics collector task
        let metrics_handle = tokio::spawn(async move {
            metrics_collector.run().await;
            // Once the run loop finishes (sender dropped), return the collected events
            // Await the async function first, then clone the result
            metrics_collector.get_collected_events().await.clone() 
        });

        // Return runtime, receivers, and the metrics collector handle
        (runtime, result_rx, isolation_rx, metrics_handle)
    }

    /// Returns a clone of the simulation configuration.
    pub fn get_config(&self) -> Arc<SimulationConfig> {
        Arc::clone(&self.config)
    }

    /// Returns a clone of the sender channel for metric events.
    pub fn get_metrics_sender(&self) -> mpsc::Sender<MetricEvent> {
        self.metrics_tx.clone()
    }

    /// Registers a node's communication channels and returns the receiver for network messages.
    pub async fn register_node(
        &self, 
        identity: TEEIdentity, 
        proposal_sender: mpsc::Sender<NodeProposalRequest>,
        // challenge_sender: mpsc::Sender<ChallengeNonce> // Removed challenge sender - handled separately if needed
    ) -> mpsc::Receiver<NetworkMessage> { // Return the network receiver
        
        let node_id = identity.id;
        // Store node identity
        self.node_identities.lock().await.insert(node_id, identity.clone());

        // Create the channel for the node to receive NetworkMessages
        let (network_tx, network_rx) = mpsc::channel::<NetworkMessage>(100); // Use a reasonable buffer size

        // Register the sender side with the emulated network
        let network_interface = self.network.clone();
        let identity_clone = identity.clone();
        tokio::spawn(async move {
            network_interface.register_recipient(identity_clone, network_tx).await;
        });

        // Store other senders associated with the node
        let mut proposal_senders = self.node_proposal_senders.lock().await;
        proposal_senders.insert(identity.id, proposal_sender);
        // Removed challenge sender storage
        // let mut challenge_senders = self.node_challenge_senders.lock().unwrap();
        // challenge_senders.insert(identity.id, challenge_sender);

        debug!("[Runtime] Registered node {} channels.", identity.id);
        network_rx // Return the receiver end for the node
    }

    /// Registers an Aggregator's attestation channel.
    pub async fn register_aggregator(&self, attestation_sender: mpsc::Sender<LivenessAttestation>) {
        // Use .lock().await for Tokio Mutex
        *self.aggregator_attestation_tx.lock().await = Some(attestation_sender);
    }

    /// Registers a generic component (like Aggregator or Coordinator) with the network.
    pub async fn register_component(&self, identity: TEEIdentity, network_message_sender: mpsc::Sender<NetworkMessage>) {
        let id = identity.id;
        // Store identity if it's the aggregator (based on configuration or a dedicated field)
        // TODO: Determine how to reliably identify the aggregator identity
        // For now, assume any non-node registering might be the aggregator
        let is_aggregator = { // Example logic - needs refinement
            let nodes = self.node_identities.lock().await;
            !nodes.contains_key(&id)
        };
        if is_aggregator {
             info!("[Runtime] Storing identity for potential Aggregator: {}", id);
             *self.aggregator_identity.lock().await = Some(identity.clone());
        }
        // Register with the network
        self.network.register_recipient(identity, network_message_sender).await;
    }

    /// Simulates crashing a node, preventing it from sending/receiving messages.
    pub async fn crash_node(&self, node_id: usize) {
        info!("[Runtime] Crashing Node {}", node_id);
        let mut crashed = self.crashed_nodes.lock().await;
        if crashed.insert(node_id) {
            // Send metric only if node wasn't already marked as crashed
             let _ = self.metrics_tx.send(MetricEvent::NodeIsolated { node_id }).await;
        }
    }

    /// Simulates restarting a crashed node, allowing it to send/receive messages again.
    pub async fn restart_node(&self, node_id: usize) {
        info!("[Runtime] Restarting Node {}", node_id);
        let mut crashed = self.crashed_nodes.lock().await;
        if crashed.remove(&node_id) {
             // Send metric only if node was actually crashed
             let _ = self.metrics_tx.send(MetricEvent::NodeRejoined { node_id }).await;
        }
    }

    // Helper function to check if a node is currently crashed
    async fn is_node_crashed(&self, node_id: usize) -> bool {
        self.crashed_nodes.lock().await.contains(&node_id)
    }

    /// Routes a RaftMessage from a sender node to a specific target node via the EmulatedNetwork.
    pub async fn route_message(&self, sender_identity: TEEIdentity, target_node_id: usize, message: RaftMessage) {
        // --- Crash Check ---
        if self.is_node_crashed(target_node_id).await {
            debug!("[Runtime] Dropping message for crashed Node {}", target_node_id);
            return;
        }
        if self.is_node_crashed(sender_identity.id).await {
             debug!("[Runtime] Dropping message from crashed Node {}", sender_identity.id);
             return;
        }
        // --- End Crash Check ---

        // Get the full TEEIdentity of the target node
        let target_identity = {
            let identities = self.node_identities.lock().await;
            identities.get(&target_node_id).cloned()
        };

        if let Some(receiver_identity) = target_identity {
            let network_msg = NetworkMessage {
                sender: sender_identity,
                receiver: receiver_identity.clone(), // Clone receiver for potential logging below
                message: Message::from(message), // Correct field name: message
            };

            // --- Packet Loss Check ---
            let loss_prob = self.config.network_packet_loss_probability;
            if loss_prob > 0.0 && rand::thread_rng().gen::<f64>() < loss_prob {
                debug!("[Runtime] PACKET LOSS: Dropping message from {} to {} (Loss Rate: {})",
                       network_msg.sender.id, network_msg.receiver.id, loss_prob);
                return; // Simulate packet loss
            }
            // --- End Packet Loss Check ---

            debug!("[Runtime] Sending network message from {} to {}: {:?}", 
                   network_msg.sender.id, network_msg.receiver.id, network_msg.message);
            self.network.send_message(network_msg); // Send via emulated network
        } else {
            warn!("[Runtime] Warning: No identity found for target Node {}. Cannot route message.", target_node_id);
        }
    }

    /// Broadcasts a RaftMessage from a sender node to all other registered nodes via the EmulatedNetwork.
    pub async fn broadcast_message(&self, sender: TEEIdentity, message: RaftMessage) {
        // --- Crash Check (Sender) ---
        if self.is_node_crashed(sender.id).await {
            debug!("[Runtime] Dropping broadcast from crashed Node {}", sender.id);
            return;
        }
        // --- End Crash Check ---

        debug!("[Runtime] Broadcasting message from Node {}: {:?}", sender.id, message);
        let identities_lock = self.node_identities.lock().await; // Lock once before loop
        let target_identities: Vec<TEEIdentity> = identities_lock
            .values()
            .filter(|id| id.id != sender.id) // Don't send to self
            .cloned()
            .collect();

        // Drop lock before iterating and checking crashes
        drop(identities_lock);

        for target_identity in target_identities {
            // --- Crash Check (Receiver) ---
            if self.is_node_crashed(target_identity.id).await {
                 debug!("[Runtime] Skipping broadcast to crashed Node {}", target_identity.id);
                 continue; // Skip sending to this crashed node
            }
            // --- End Crash Check ---

            let msg_clone = message.clone(); // Clone message for each send
            let network_msg = NetworkMessage {
                sender: sender.clone(), // Clone sender identity
                receiver: target_identity.clone(),
                message: Message::from(msg_clone),
            };

            // --- Packet Loss Check ---
            let loss_prob = self.config.network_packet_loss_probability;
            if loss_prob > 0.0 && rand::thread_rng().gen::<f64>() < loss_prob {
                debug!("[Runtime] PACKET LOSS (Broadcast): Dropping message from {} to {} (Loss Rate: {})",
                       network_msg.sender.id, network_msg.receiver.id, loss_prob);
                continue; // Skip sending this specific message
            }
            // --- End Packet Loss Check ---

            self.network.send_message(network_msg); 
        }
    }

    /// Routes a Liveness Challenge to a specific target node via the EmulatedNetwork.
    pub async fn route_challenge(&self, target_node_id: usize, challenge: NonceChallenge) {
        // --- Crash Check ---
        if self.is_node_crashed(target_node_id).await {
            debug!("[Runtime] Dropping challenge for crashed Node {}", target_node_id);
            return;
        }
        // Note: We assume the challenger itself doesn't crash in this simulation,
        // or its crashing is handled elsewhere. If challenger needs crash check,
        // the sender identity would need to be passed in.
        // --- End Crash Check ---

        // Get the full TEEIdentity of the target node
        let target_identity = {
            let identities = self.node_identities.lock().await;
            identities.get(&target_node_id).cloned()
        };

        if let Some(receiver_identity) = target_identity {
             // Sender identity is needed for NetworkMessage. Let's assume a default/runtime sender or pass it in.
             // For now, creating a dummy sender for the NetworkMessage structure.
             // A better approach might be to get the actual challenger identity.
             let dummy_sender = TEEIdentity { id: usize::MAX, public_key: receiver_identity.public_key.clone() }; // Placeholder!

            let network_msg = NetworkMessage {
                sender: dummy_sender, // Placeholder - needs actual challenger identity if available
                receiver: receiver_identity,
                message: Message::LivenessChallenge(challenge), // Wrap in Message enum
            };

             // --- Packet Loss Check ---
             let loss_prob = self.config.network_packet_loss_probability;
             if loss_prob > 0.0 && rand::thread_rng().gen::<f64>() < loss_prob {
                 debug!("[Runtime] PACKET LOSS: Dropping LivenessChallenge for {} (Loss Rate: {})",
                        network_msg.receiver.id, loss_prob);
                 return; // Simulate packet loss
             }
             // --- End Packet Loss Check ---

             debug!("[Runtime] Sending LivenessChallenge to {}: {:?}", target_node_id, network_msg.message);
            self.network.send_message(network_msg);
        } else {
            warn!("[Runtime] Warning: No identity found for target Node {}. Cannot route challenge.", target_node_id);
        }
    }

    /// Forwards a LivenessAttestation from a node to the registered Aggregator.
    pub async fn forward_attestation_to_aggregator(&self, attestation: LivenessAttestation) {
        let sender_node_id = attestation.node_id;
         // --- Crash Check (Sender Node) ---
         if self.is_node_crashed(sender_node_id).await {
             debug!("[Runtime] Dropping attestation from crashed Node {}", sender_node_id);
             return;
         }
         // --- End Crash Check ---

        // Send directly via the aggregator's channel if registered
        // TODO: Consider routing via EmulatedNetwork for consistency?
        let maybe_tx = self.aggregator_attestation_tx.lock().await;
        if let Some(tx) = maybe_tx.as_ref() {
             // --- Crash Check (Aggregator) ---
             // Need aggregator ID to check if it's crashed. Let's assume aggregator doesn't crash for now.
             // If needed, get aggregator ID from self.aggregator_identity
             // --- End Crash Check ---

             // --- Packet Loss Check (Sending to Aggregator Channel) ---
             // Note: This applies loss even though it's not going through EmulatedNetwork.
             // Decide if this is desired behavior for aggregator communication.
             let loss_prob = self.config.network_packet_loss_probability;
             if loss_prob > 0.0 && rand::thread_rng().gen::<f64>() < loss_prob {
                 debug!("[Runtime] PACKET LOSS: Dropping attestation for Aggregator from Node {} (Loss Rate: {})",
                        sender_node_id, loss_prob);
                 return; // Simulate packet loss
             }
            // --- End Packet Loss Check ---

            if let Err(e) = tx.send(attestation).await {
                error!("[Runtime] Failed to forward attestation to aggregator: {}", e);
            } else {
                 debug!("[Runtime] Forwarded attestation from Node {} to aggregator.", sender_node_id);
            }
        } else {
            warn!("[Runtime] No aggregator registered to forward attestation to.");
        }
    }

    /// Submits a result (SignatureShare) from a node.
    pub async fn submit_result(&self, result: SignatureShare) {
        let sender_node_id = result.0.id; // Get ID from TEEIdentity in tuple
        // --- Crash Check ---
        if self.is_node_crashed(sender_node_id).await {
             debug!("[Runtime] Dropping result from crashed Node {}", sender_node_id);
             return;
        }
        // --- End Crash Check ---

         // --- Packet Loss Check ---
         // Applying loss here assumes results channel simulates network loss.
         let loss_prob = self.config.network_packet_loss_probability;
         if loss_prob > 0.0 && rand::thread_rng().gen::<f64>() < loss_prob {
             debug!("[Runtime] PACKET LOSS: Dropping result submission from Node {} (Loss Rate: {})",
                    sender_node_id, loss_prob);
             return; // Simulate packet loss
         }
        // --- End Packet Loss Check ---

        if let Err(e) = self.result_tx.send(result).await {
            error!("[Runtime] Failed to submit result: {}", e);
        }
    }

    /// Assigns a list of nodes to a specific shard ID.
    pub async fn assign_nodes_to_shard(&self, shard_id: usize, nodes: Vec<TEEIdentity>) {
        debug!("[Runtime] [assign_nodes_to_shard START] Assigning {} nodes to shard {}", nodes.len(), shard_id);
        debug!("[Runtime] [assign_nodes_to_shard] Acquiring shard_assignments lock..."); // Added log
        let mut assignments = self.shard_assignments.lock().await;
        debug!("[Runtime] [assign_nodes_to_shard] Acquired shard_assignments lock for shard {}.", shard_id); // Added log
        assignments.insert(shard_id, nodes);
        // Lock is implicitly released when `assignments` goes out of scope here
        debug!("[Runtime] [assign_nodes_to_shard] Releasing shard_assignments lock for shard {}.", shard_id); // Added log
        debug!("[Runtime] [assign_nodes_to_shard END] Shard {}", shard_id);
    }

    /// Sends a command to all nodes assigned to a specific shard.
    pub async fn send_command_to_shard(&self, shard_id: usize, command: Command) {
        let cmd_id_str = command.tx_id_str();

        debug!("[Runtime][Cmd {}] PRE-LOCK shard_assignments for shard {}", cmd_id_str, shard_id);
        let assignments = self.shard_assignments.lock().await; // Lock 1
        debug!("[Runtime][Cmd {}] POST-LOCK shard_assignments for shard {}", cmd_id_str, shard_id);

        let target_node_ids = match assignments.get(&shard_id) {
            Some(nodes) => nodes.clone(),
            None => {
                warn!("[Runtime] Shard {} not found for sending command {}", shard_id, cmd_id_str);
                debug!("[Runtime][Cmd {}] Dropping shard_assignments lock (shard not found)", cmd_id_str);
                drop(assignments); // Drop Lock 1 explicitly before returning
                return;
            }
        };
        debug!("[Runtime][Cmd {}] Dropping shard_assignments lock (found nodes)", cmd_id_str);
        drop(assignments); // Drop Lock 1

        if target_node_ids.is_empty() {
            warn!("[Runtime] No nodes assigned to Shard {} for sending command {}", shard_id, cmd_id_str);
            return;
        }

        debug!("[Runtime][Cmd {}] Attempting to send command to shard {}", cmd_id_str, shard_id);

        debug!("[Runtime][Cmd {}] PRE-LOCK node_proposal_senders for shard {}", cmd_id_str, shard_id);
        let node_proposal_senders = self.node_proposal_senders.lock().await; // Lock 2
        debug!("[Runtime][Cmd {}] POST-LOCK node_proposal_senders for shard {}", cmd_id_str, shard_id);

        debug!("[Runtime][Cmd {}] PRE-LOCK crashed_nodes for shard {}", cmd_id_str, shard_id);
        let crashed_nodes = self.crashed_nodes.lock().await;            // Lock 3
        debug!("[Runtime][Cmd {}] POST-LOCK crashed_nodes for shard {}", cmd_id_str, shard_id);

        let packet_loss_chance = self.config.network_packet_loss_probability;
        debug!("[Runtime][Cmd {}] Accessed config for packet loss chance: {}", cmd_id_str, packet_loss_chance);

        for node_identity in target_node_ids {
            let node_id = node_identity.id;

            if crashed_nodes.contains(&node_id) {
                debug!("[Runtime][Cmd {}] Skipping send to crashed Node {}", cmd_id_str, node_id);
                continue;
            }

            if rand::thread_rng().gen_bool(packet_loss_chance) {
                debug!("[Runtime][Cmd {}] Simulating packet loss for command to Node {}", cmd_id_str, node_id);
                continue;
            }

            if let Some(sender) = node_proposal_senders.get(&node_id) {
                let sender = sender.clone();
                let command_clone = command.clone();
                let (ack_tx, _ack_rx) = oneshot::channel(); // Ignore receiver for now
                let cmd_id_str_clone = cmd_id_str.clone();

                debug!(
                    "[Runtime] [Shard {}][Cmd {}] PRE-SEND command to Node {} via channel",
                    shard_id, &cmd_id_str_clone, node_id // Use clone for consistency
                );

                if let Err(e) = sender.send((command_clone, ack_tx)).await {
                    error!("[Runtime][Cmd {}] Failed to send command to Node {}: {}", cmd_id_str_clone, node_id, e);
                } else {
                    debug!(
                        "[Runtime] [Shard {}][Cmd {}] POST-SEND command to Node {} via channel",
                        shard_id, cmd_id_str_clone, node_id
                    );
                    // Optional: Wait for ACK (commented out)
                    // match _ack_rx.await { ... }
                }

            } else {
                warn!("[Runtime][Cmd {}] No proposal sender found for Node {}", cmd_id_str, node_id);
            }
        }

        debug!("[Runtime][Cmd {}] Dropping crashed_nodes lock", cmd_id_str);
        drop(crashed_nodes);         // Drop Lock 3
        debug!("[Runtime][Cmd {}] Dropping node_proposal_senders lock", cmd_id_str);
        drop(node_proposal_senders); // Drop Lock 2

        debug!("[Runtime][Cmd {}] Finished iterating send loop for shard {}", cmd_id_str, shard_id);
    }

    /// Reports a list of isolated node IDs (presumably from the Liveness Aggregator).
    pub async fn report_isolated_nodes(&self, isolated_node_ids: Vec<usize>) {
        if !isolated_node_ids.is_empty() {
            info!("[Runtime] Received report of isolated nodes: {:?}", isolated_node_ids);
            // Propagate this report to interested components (e.g., simulation coordinator)
             // --- Packet Loss Check ---
             // Decide if isolation reports are subject to loss.
             // Let's assume they are for now.
             let loss_prob = self.config.network_packet_loss_probability;
             if loss_prob > 0.0 && rand::thread_rng().gen::<f64>() < loss_prob {
                 debug!("[Runtime] PACKET LOSS: Dropping isolation report {:?} (Loss Rate: {})",
                        isolated_node_ids, loss_prob);
                 return; // Simulate packet loss
             }
            // --- End Packet Loss Check ---
            if let Err(e) = self.isolation_report_tx.send(isolated_node_ids).await {
                error!("[Runtime] Failed to send isolation report: {}", e);
            }
        }
    }

    /// Generic message sending using the EmulatedNetwork (useful for component-to-component).
    pub fn send_message(&self, msg: NetworkMessage) {
        // --- Crash Check ---
        // Need async context to check crash status, or make is_node_crashed synchronous (requires Arc<Mutex> not TokioMutex).
        // For simplicity in this sync function, we'll skip the crash check here.
        // Rely on checks in async functions like route_message, broadcast_message.
        // If direct component-to-component sending needs crash checks, this function should be async.
        // --- End Crash Check ---

         // --- Packet Loss Check ---
         let loss_prob = self.config.network_packet_loss_probability;
         if loss_prob > 0.0 && rand::thread_rng().gen::<f64>() < loss_prob {
             debug!("[Runtime] PACKET LOSS (Direct Send): Dropping message from {} to {} (Loss Rate: {})",
                    msg.sender.id, msg.receiver.id, loss_prob);
             return; // Simulate packet loss
         }
         // --- End Packet Loss Check ---

        self.network.send_message(msg);
    }
} 