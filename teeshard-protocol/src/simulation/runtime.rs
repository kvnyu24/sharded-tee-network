// teeshard-protocol/src/simulation/runtime.rs
use crate::{
    data_structures::TEEIdentity,
    liveness::types::{ChallengeNonce, LivenessAttestation}, // Import liveness types
    raft::{messages::RaftMessage, state::Command}, // Import Command
    tee_logic::types::{LockProofData, Signature},
    simulation::node::NodeProposalRequest, // Import NodeProposalRequest
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot}; // Import oneshot
use futures;
use std::collections::HashSet;

// Type for results sent back from nodes (e.g., signature shares)
// Tuple: (Signer Identity, Data Signed (e.g., LockProofData), Signature)
pub type SignatureShare = (TEEIdentity, LockProofData, Signature); // Use Signature struct

/// Manages the simulated network and nodes.
/// Cloning this struct allows multiple components (nodes, coordinator) to interact with the runtime.
#[derive(Clone, Debug)]
pub struct SimulationRuntime {
    // Map Node ID -> Sender channel for RaftMessages
    node_raft_senders: Arc<Mutex<HashMap<usize, mpsc::Sender<(TEEIdentity, RaftMessage)>>>>,
    // NEW: Map Node ID -> Sender channel for Command Proposals
    node_proposal_senders: Arc<Mutex<HashMap<usize, mpsc::Sender<NodeProposalRequest>>>>,
    // Map Node ID -> Sender channel for Liveness Challenges
    node_challenge_senders: Arc<Mutex<HashMap<usize, mpsc::Sender<ChallengeNonce>>>>,
    // Map Shard ID -> List of Node Identities in that shard
    shard_assignments: Arc<Mutex<HashMap<usize, Vec<TEEIdentity>>>>,
    // Channel for nodes to send results (e.g., signature shares) back to the test/coordinator
    result_tx: mpsc::Sender<SignatureShare>,
    // Channel for Aggregator to receive Liveness Attestations
    aggregator_attestation_tx: Arc<Mutex<Option<mpsc::Sender<LivenessAttestation>>>>,
    // Channel for Aggregator to report isolated node IDs
    isolation_report_tx: mpsc::Sender<Vec<usize>>,
}

impl SimulationRuntime {
    /// Creates a new simulation runtime and returns it along with receivers.
    pub fn new() -> (
        Self, 
        mpsc::Receiver<SignatureShare>, 
        mpsc::Receiver<LivenessAttestation>, 
        mpsc::Receiver<Vec<usize>>, // Return Vec<usize> receiver
    ) {
        let (result_tx, result_rx) = mpsc::channel(100);
        let (attestation_tx, attestation_rx) = mpsc::channel(100);
        // Create channel for isolation reports (Vec<usize>)
        let (isolation_tx, isolation_rx): (mpsc::Sender<Vec<usize>>, mpsc::Receiver<Vec<usize>>) = mpsc::channel(10); 

        let runtime = SimulationRuntime {
            node_raft_senders: Arc::new(Mutex::new(HashMap::new())),
            node_proposal_senders: Arc::new(Mutex::new(HashMap::new())),
            node_challenge_senders: Arc::new(Mutex::new(HashMap::new())), // Initialize new map
            shard_assignments: Arc::new(Mutex::new(HashMap::new())),
            result_tx,
            // Store the sender end for attestations
            aggregator_attestation_tx: Arc::new(Mutex::new(Some(attestation_tx))),
            isolation_report_tx: isolation_tx, // Store Vec<usize> sender
        };

        // Return runtime and Vec<usize> receiver
        (runtime, result_rx, attestation_rx, isolation_rx)
    }

    /// Registers a node's communication channels.
    pub fn register_node(
        &self, 
        identity: TEEIdentity, 
        raft_sender: mpsc::Sender<(TEEIdentity, RaftMessage)>,
        proposal_sender: mpsc::Sender<NodeProposalRequest>,
        challenge_sender: mpsc::Sender<ChallengeNonce>, // Add challenge sender
    ) {
        let node_id = identity.id;
        self.node_raft_senders.lock().unwrap().insert(node_id, raft_sender);
        println!("[Runtime] Registered Raft sender for Node {}", node_id);
        self.node_proposal_senders.lock().unwrap().insert(node_id, proposal_sender);
        println!("[Runtime] Registered Proposal sender for Node {}", node_id);
        // Register challenge sender
        self.node_challenge_senders.lock().unwrap().insert(node_id, challenge_sender);
        println!("[Runtime] Registered Challenge sender for Node {}", node_id);
    }

    /// Registers the Aggregator's attestation receiving channel.
    pub fn register_aggregator(&self, attestation_sender: mpsc::Sender<LivenessAttestation>) {
        // This might overwrite if called multiple times, consider alternatives if needed.
        println!("[Runtime] Registering Aggregator attestation channel.");
        *self.aggregator_attestation_tx.lock().unwrap() = Some(attestation_sender);
    }

    // --- Add method to take the aggregator sender (for the aggregator task) --- 
    // This prevents the runtime from holding a sender that the aggregator needs to receive from.
    pub fn take_aggregator_attestation_sender(&self) -> Option<mpsc::Sender<LivenessAttestation>> {
        self.aggregator_attestation_tx.lock().unwrap().take()
    }

    /// Routes a RaftMessage from a sender to a specific target node.
    pub async fn route_message(&self, sender_identity: TEEIdentity, target_node_id: usize, message: RaftMessage) {
        let target_sender = {
            // Lock, clone the sender if found, and immediately drop the guard
            let senders = self.node_raft_senders.lock().unwrap();
            senders.get(&target_node_id).cloned()
            // guard is dropped here
        };

        if let Some(sender) = target_sender {
            // println!("[Runtime] Routing message from Node {} to Node {}: {:?}", sender_identity.id, target_node_id, message);
            if let Err(e) = sender.send((sender_identity, message)).await { // Await happens *after* lock is released
                eprintln!("[Runtime] Error sending message to Node {}: {}", target_node_id, e);
            }
        } else {
            println!("[Runtime] Warning: No Raft sender found for target Node {}. Message dropped.", target_node_id);
        }
    }

    /// Broadcasts a RaftMessage from a sender to all registered nodes (except sender).
    pub async fn broadcast_message(&self, sender_identity: TEEIdentity, message: RaftMessage) {
        let channels_to_send: Vec<(usize, mpsc::Sender<(TEEIdentity, RaftMessage)>)> = {
            // Lock, collect cloned senders, drop guard
            let senders = self.node_raft_senders.lock().unwrap();
            senders.iter()
                 .filter(|(node_id, _)| **node_id != sender_identity.id)
                 .map(|(node_id, tx)| (*node_id, tx.clone()))
                 .collect()
            // guard is dropped here
        };

        // println!("[Runtime] Broadcasting message from Node {}: {:?}", sender_identity.id, message);
        for (node_id, sender) in channels_to_send {
            // Clone message and sender_identity for each send task
            let msg_clone = message.clone();
            let sender_clone = sender_identity.clone();
            // Await happens after lock release, within the loop/spawned task if using spawn
            if let Err(e) = sender.send((sender_clone, msg_clone)).await {
                 eprintln!("[Runtime] Error broadcasting message to Node {}: {}", node_id, e);
            }
            // Original implementation used spawn, which is fine too, but direct await works
            // send_futures.push(tokio::spawn(async move { ... sender.send(...).await ... }));
        }
        // if using spawn: futures::future::join_all(send_futures).await;
    }

    /// Routes a Liveness Challenge to a specific target node.
    pub async fn route_challenge(&self, target_node_id: usize, challenge: ChallengeNonce) {
        let target_sender = {
            let senders = self.node_challenge_senders.lock().unwrap();
            senders.get(&target_node_id).cloned()
        };

        if let Some(sender) = target_sender {
            // println!("[Runtime] Routing challenge to Node {}: {:?}", target_node_id, challenge);
            if let Err(e) = sender.send(challenge).await { 
                eprintln!("[Runtime] Error sending challenge to Node {}: {}", target_node_id, e);
            }
        } else {
            println!("[Runtime] Warning: No challenge sender found for target Node {}. Challenge dropped.", target_node_id);
        }
    }

    /// Forwards a Liveness Attestation from a node to the registered Aggregator.
    pub async fn forward_attestation_to_aggregator(&self, attestation: LivenessAttestation) {
        let agg_sender_opt = {
            self.aggregator_attestation_tx.lock().unwrap().clone()
        };
        if let Some(sender) = agg_sender_opt {
             if let Err(e) = sender.send(attestation).await {
                 eprintln!("[Runtime] Failed to forward attestation to aggregator: {}. Receiver likely dropped.", e);
            }
        } else {
             println!("[Runtime] Warning: No aggregator attestation channel registered. Attestation dropped.");
        }
    }

    /// Sends a signature share result back to the central collector (test/coordinator).
    pub async fn submit_result(&self, result: SignatureShare) {
        if let Err(e) = self.result_tx.send(result).await {
             eprintln!("[Runtime] Failed to submit result: {}. Receiver likely dropped.", e);
        }
    }

    /// Assigns a list of nodes to a specific shard ID.
    pub fn assign_nodes_to_shard(&self, shard_id: usize, nodes: Vec<TEEIdentity>) {
        let mut assignments = self.shard_assignments.lock().unwrap();
        println!("[Runtime] Assigning nodes {:?} to Shard {}", nodes.iter().map(|n| n.id).collect::<Vec<_>>(), shard_id);
        assignments.insert(shard_id, nodes);
    }

    /// Sends a command proposal to all nodes within a specific shard.
    pub async fn send_command_to_shard(&self, shard_id: usize, command: Command) {
        let node_identities_in_shard = {
            let assignments = self.shard_assignments.lock().unwrap();
            match assignments.get(&shard_id) {
                Some(nodes) => nodes.clone(),
                None => {
                    eprintln!("[Runtime] Error: Cannot send command to non-existent Shard {}", shard_id);
                    return;
                }
            }
            // guard dropped here
        };

        let senders_to_use: Vec<(usize, mpsc::Sender<NodeProposalRequest>)> = {
            // Lock, collect cloned senders, drop guard
            let senders_map = self.node_proposal_senders.lock().unwrap();
            node_identities_in_shard.iter()
                .filter_map(|identity| 
                    senders_map.get(&identity.id).map(|sender| (identity.id, sender.clone()))
                )
                .collect()
             // guard dropped here
        };

        println!("[Runtime] Sending command proposal {:?} to Shard {} (Nodes: {:?})", 
                 command, shard_id, senders_to_use.iter().map(|(id,_)| id).collect::<Vec<_>>());

        for (identity_id, sender) in senders_to_use {
            let (ack_tx, _ack_rx) = oneshot::channel();
            let proposal: NodeProposalRequest = (command.clone(), ack_tx);
            // Await happens after lock release
            if let Err(e) = sender.send(proposal).await { 
                eprintln!("[Runtime] Error sending command proposal to Node {}: {}", identity_id, e);
            }
            // Removed warning about missing sender here, handled by filter_map above
        }
    }

    /// Sends a report of isolated node IDs and removes them from runtime structures.
    pub async fn report_isolated_nodes(&self, isolated_node_ids: Vec<usize>) {
         println!("[Runtime] Received isolation report for nodes: {:?}. Removing from runtime...", isolated_node_ids);
         if isolated_node_ids.is_empty() {
            return; // Nothing to do
         }

         let isolated_set: HashSet<usize> = isolated_node_ids.iter().cloned().collect();

         // Remove senders (Use .lock().unwrap() for std::sync::Mutex)
         {
            let mut raft_senders = self.node_raft_senders.lock().unwrap(); // Use unwrap()
            for node_id in &isolated_node_ids {
                if raft_senders.remove(node_id).is_some() {
                    println!("[Runtime] Removed Raft sender for isolated node {}", node_id);
                }
            }
         } 
         {
            let mut proposal_senders = self.node_proposal_senders.lock().unwrap(); // Use unwrap()
             for node_id in &isolated_node_ids {
                if proposal_senders.remove(node_id).is_some() {
                     println!("[Runtime] Removed Proposal sender for isolated node {}", node_id);
                 }
            }
         } 
          {
            let mut challenge_senders = self.node_challenge_senders.lock().unwrap(); // Use unwrap()
             for node_id in &isolated_node_ids {
                 if challenge_senders.remove(node_id).is_some() {
                     println!("[Runtime] Removed Challenge sender for isolated node {}", node_id);
                 }
            }
         } 

         // Update shard assignments (Use .lock().unwrap())
         {
             let mut assignments = self.shard_assignments.lock().unwrap(); // Use unwrap()
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

    // TODO: Add methods for coordinator interaction, logging, etc.
} 