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
use std::collections::HashMap;
use std::sync::{Arc}; // Remove std Mutex import
use tokio::sync::{mpsc, oneshot, Mutex as TokioMutex}; // Add TokioMutex
use log::{debug, warn, error}; // Import log macros
use std::collections::HashSet;
use crate::liveness::types::NonceChallenge; // Import specifically
 // Need this for Message::LivenessResponse
use std::time::Duration; // Add Duration import
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
        let (result_tx, result_rx) = mpsc::channel(100);
        let (isolation_tx, isolation_rx) = mpsc::channel(100); // For isolation reports (Vec<usize>)
        // Create channel for metrics
        let (metrics_tx, metrics_rx) = mpsc::channel(1000); // Buffer size 1000
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

            // Remove obsolete direct senders
            // node_raft_senders: Arc::new(Mutex::new(HashMap::new())),
            // node_challenge_senders: Arc::new(Mutex::new(HashMap::new())),
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
             println!("[Runtime] Storing identity for potential Aggregator: {}", id);
             *self.aggregator_identity.lock().await = Some(identity.clone());
        }
        // Register with the network
        self.network.register_recipient(identity, network_message_sender).await;
    }

    /// Routes a RaftMessage from a sender node to a specific target node via the EmulatedNetwork.
    pub async fn route_message(&self, sender_identity: TEEIdentity, target_node_id: usize, message: RaftMessage) {
        // Get the full TEEIdentity of the target node
        let target_identity = {
            let identities = self.node_identities.lock().await;
            identities.get(&target_node_id).cloned()
        };

        if let Some(receiver_identity) = target_identity {
            let network_msg = NetworkMessage {
                sender: sender_identity,
                receiver: receiver_identity,
                message: Message::from(message), // Correct field name: message
            };
            debug!("[Runtime] Sending network message from {} to {}: {:?}", 
                   network_msg.sender.id, network_msg.receiver.id, network_msg.message); // Log the message
            self.network.send_message(network_msg); // Send via emulated network
        } else {
            warn!("[Runtime] Warning: No identity found for target Node {}. Cannot route message.", target_node_id);
        }
    }

    /// Broadcasts a RaftMessage to all nodes *except* the sender.
    pub async fn broadcast_message(&self, sender: TEEIdentity, message: RaftMessage) {
        // Lock the node identities map once to get all potential recipients
        let identities_map = self.node_identities.lock().await; // Use unwrap() for std::sync::Mutex
        let all_recipient_identities: Vec<TEEIdentity> = identities_map.values().cloned().collect();
        // Drop the lock quickly
        drop(identities_map);

        let message_payload = Message::from(message); // Use From trait

        for recipient_identity in all_recipient_identities {
            // Don't send back to self
            if recipient_identity.id == sender.id { continue; }

            let network_msg = NetworkMessage {
                sender: sender.clone(),
                receiver: recipient_identity, 
                message: message_payload.clone(), // Correct field name: message
            };
            // Use the generic send_message which handles queuing/delay
            self.network.send_message(network_msg); 
        }
    }

    /// Routes a Liveness Challenge to a specific target node via the EmulatedNetwork.
    pub async fn route_challenge(&self, target_node_id: usize, challenge: NonceChallenge) {
        // Get sender identity (Should be the Liveness Aggregator)
        let sender_identity = {
            self.aggregator_identity.lock().await.clone() // Clone the Option<TEEIdentity>
        };

        // Ensure aggregator identity is set
        let actual_sender = match sender_identity {
            Some(id) => id,
            None => {
                warn!("[Runtime] Cannot route challenge: Liveness Aggregator identity not yet registered.");
                return; // Cannot send without sender
            }
        };

        // Get the full TEEIdentity of the target node
        let target_identity = {
            let identities = self.node_identities.lock().await;
            identities.get(&target_node_id).cloned()
        };

        if let Some(receiver_identity) = target_identity {
            let network_msg = NetworkMessage {
                sender: actual_sender, // Use the retrieved aggregator identity
                receiver: receiver_identity,
                message: Message::from(challenge), // Convert NonceChallenge to Message enum
            };
            debug!("[Runtime] Sending Liveness Challenge from Aggregator {} to Node {}: {:?}", 
                   network_msg.sender.id, network_msg.receiver.id, network_msg.message);
            self.network.send_message(network_msg); // Send via emulated network
        } else {
            warn!("[Runtime] Warning: No identity found for target Node {}. Cannot route challenge.", target_node_id);
        }
    }

    /// Forwards a liveness attestation directly to the registered aggregator's channel.
    pub async fn forward_attestation_to_aggregator(&self, attestation: LivenessAttestation) {
        // Lock the Tokio Mutex using .lock().await
        let maybe_sender_guard = self.aggregator_attestation_tx.lock().await;
        if let Some(sender) = maybe_sender_guard.as_ref() {
            // Sender is cloned within the guard, guard dropped before await
            let sender_clone = sender.clone();
            drop(maybe_sender_guard);
            if let Err(e) = sender_clone.send(attestation).await {
                error!("[Runtime] Failed to forward attestation to aggregator: {}", e);
            }
        } else {
            // Guard is dropped automatically here
            warn!("[Runtime] Aggregator attestation channel not registered. Cannot forward attestation.");
        }
    }

    /// Sends a signature share result back to the central collector (test/coordinator).
    pub async fn submit_result(&self, result: SignatureShare) {
        if let Err(e) = self.result_tx.send(result).await {
             eprintln!("[Runtime] Failed to submit result: {}. Receiver likely dropped.", e);
        }
    }

    /// Assigns a list of nodes to a specific shard ID.
    pub async fn assign_nodes_to_shard(&self, shard_id: usize, nodes: Vec<TEEIdentity>) {
        let mut assignments = self.shard_assignments.lock().await;
        println!("[Runtime] Assigning nodes {:?} to Shard {}", nodes.iter().map(|n| n.id).collect::<Vec<_>>(), shard_id);
        assignments.insert(shard_id, nodes);
    }

    /// Sends a command directly to the Raft leader of a specific shard.
    pub async fn send_command_to_shard(&self, shard_id: usize, command: Command) {
        let proposal_senders = self.node_proposal_senders.lock().await;
        let shard_nodes = self.shard_assignments.lock().await;

        if let Some(nodes_in_shard) = shard_nodes.get(&shard_id) {
            if let Some(leader_identity) = nodes_in_shard.get(0) { // Simple: assume first node is leader for now
                if let Some(leader_sender) = proposal_senders.get(&leader_identity.id) {
                    let (resp_tx, resp_rx) = oneshot::channel();
                    if leader_sender.send((command, resp_tx)).await.is_ok() {
                        debug!("[Runtime] Sent command to potential leader {} of shard {}.", leader_identity.id, shard_id);
                        // Optionally wait for response/ack from leader via resp_rx
                        match tokio::time::timeout(Duration::from_secs(1), resp_rx).await {
                            Ok(Ok(Ok(events))) => debug!("[Runtime] Leader {} acked proposal. Events: {:?}", leader_identity.id, events),
                            Ok(Ok(Err(e))) => warn!("[Runtime] Leader {} rejected proposal: {}", leader_identity.id, e),
                            Ok(Err(_)) => warn!("[Runtime] Leader {} proposal response channel closed.", leader_identity.id),
                            Err(_) => warn!("[Runtime] Timeout waiting for leader {} proposal ack.", leader_identity.id),
                        }
                    } else {
                        warn!("[Runtime] Failed to send command to potential leader {} channel (closed?).", leader_identity.id);
                    }
                } else {
                    warn!("[Runtime] Leader node {} for shard {} not found in proposal senders.", leader_identity.id, shard_id);
                }
            } else {
                 warn!("[Runtime] No nodes found for shard {}. Cannot send command.", shard_id);
            }
        } else {
            warn!("[Runtime] Shard ID {} not found in assignments. Cannot send command.", shard_id);
        }
    }

    /// Sends a report of isolated node IDs and removes them from runtime structures.
    pub async fn report_isolated_nodes(&self, isolated_node_ids: Vec<usize>) {
         println!("[Runtime] Received isolation report for nodes: {:?}. Removing from runtime...", isolated_node_ids);
         if isolated_node_ids.is_empty() {
            return; // Nothing to do
         }

         let isolated_set: HashSet<usize> = isolated_node_ids.iter().cloned().collect();

         // Remove internal proposal senders
         { 
             let mut proposal_senders = self.node_proposal_senders.lock().await; // Use unwrap()
             for node_id in &isolated_node_ids {
                if proposal_senders.remove(node_id).is_some() {
                     println!("[Runtime] Removed Proposal sender for isolated node {}", node_id);
                 }
            }
         } 

         // Update shard assignments (Use .lock().unwrap())
         {
             let mut assignments = self.shard_assignments.lock().await; // Use unwrap()
             for (_shard_id, nodes_in_shard) in assignments.iter_mut() {
                 nodes_in_shard.retain(|identity| !isolated_set.contains(&identity.id));
             }
             println!("[Runtime] Updated shard assignments after isolation: {:?}", assignments);
         } 

         // --- Send the report ---
         if let Err(e) = self.isolation_report_tx.send(isolated_node_ids.clone()).await { // Clone ids for logging
             eprintln!("[Runtime] Failed to send isolation report for {:?}: {}. Receiver likely dropped.", isolated_node_ids, e);
         } else {
             // --- ADD THIS LOG --- 
             println!("[Runtime] Successfully sent isolation report for {:?} via channel.", isolated_node_ids);
         }
    }

    // Renamed from route_message - now just uses the generic send_message interface
    pub fn send_message(&self, msg: NetworkMessage) {
        self.network.send_message(msg);
    }

    // TODO: Add methods for coordinator interaction, logging, etc.
} 