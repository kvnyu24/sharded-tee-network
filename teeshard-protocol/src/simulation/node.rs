// teeshard-protocol/src/simulation/node.rs

use crate::{
    config::SystemConfig,
    data_structures::TEEIdentity,
    liveness::types::LivenessAttestation, // Import liveness types
    raft::{
        messages::RaftMessage,
        node::{RaftNode, RaftEvent, ShardId},
        state::{Command, RaftRole}, // Import Command and RaftRole enum
        storage::InMemoryStorage, // Using InMemoryStorage for simulation
    },
    tee_logic::types::Signature,
};
// Use crate::simulation::runtime::SimulationRuntime;
// Corrected import path assumption
use crate::simulation::runtime::SimulationRuntime;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::time::{interval, Duration};
use bincode; // Add bincode import
use bincode::config::standard; // Import standard config
use std::collections::HashSet; // Import HashSet
use ed25519_dalek::SigningKey; // Import SigningKey
use ed25519_dalek::Signer; // Add Signer trait
use crate::network::{NetworkMessage, Message}; // Add NetworkMessage, Message
use log::warn; // Add warn import
use ethers::utils::keccak256; // Import keccak256
use crate::simulation::metrics::MetricEvent;
use hex; // Add hex import
use crate::tee_logic::enclave_sim::EnclaveSim; // Corrected Import Path

// Type for proposal requests received by the node's run loop
pub type NodeProposalRequest = (Command, oneshot::Sender<Result<Vec<RaftEvent>, String>>);

// NEW: Types for querying node state
#[derive(Debug)]
pub enum NodeQueryRequest {
    GetRaftState,
}

#[derive(Debug)]
pub enum NodeQueryResponse {
    RaftState {
        last_log_index: u64,
        commit_index: u64,
        role: RaftRole, // Also return the role for leader confirmation
    },
}

pub type NodeQuery = (NodeQueryRequest, oneshot::Sender<NodeQueryResponse>);

/// Represents a single TEE node within the simulation.
pub struct SimulatedTeeNode {
    pub identity: TEEIdentity,
    signing_key: SigningKey,
    raft_node: RaftNode,
    shard_id: ShardId,
    processed_commands: HashSet<String>,
    runtime: SimulationRuntime,
    network_rx: mpsc::Receiver<NetworkMessage>,
    proposal_rx: mpsc::Receiver<NodeProposalRequest>,
    proposal_tx: mpsc::Sender<NodeProposalRequest>,
    query_rx: mpsc::Receiver<NodeQuery>,
    query_tx: mpsc::Sender<NodeQuery>,
    metrics_tx: mpsc::Sender<MetricEvent>,
}

impl SimulatedTeeNode {
    /// Creates a new SimulatedTeeNode instance.
    pub fn new(
        identity: TEEIdentity,
        signing_key: SigningKey,
        peers: Vec<TEEIdentity>,
        config: SystemConfig,
        runtime: SimulationRuntime,
        network_rx: mpsc::Receiver<NetworkMessage>,
        proposal_tx: mpsc::Sender<NodeProposalRequest>,
        proposal_rx: mpsc::Receiver<NodeProposalRequest>,
        query_tx: mpsc::Sender<NodeQuery>,
        query_rx: mpsc::Receiver<NodeQuery>,
        shard_id: ShardId,
    ) -> Self {
        let storage = Box::new(InMemoryStorage::new());
        let sim_config = runtime.get_config();
        let tee_delay_config = Arc::new(sim_config.tee_delays.clone()); // Clone for Arc
        let metrics_tx_clone = runtime.get_metrics_sender(); // Clone for enclave and raft
        
        // Remove enclave creation here, it happens inside RaftNode::new - REVERTING THIS
        let enclave = Arc::new(EnclaveSim::new(
            identity.clone(), // Pass the full identity
            signing_key.clone(), // Pass the key directly (cloned for Arc)
            tee_delay_config.clone(), // Clone the Arc *before* moving it to EnclaveSim
            Some(metrics_tx_clone.clone())
        ));
        
        // Update RaftNode::new call signature: re-add enclave, pass metrics_tx
        let raft_node = RaftNode::new(
            identity.clone(),
            peers, // peers comes before config
            config, 
            storage,
            signing_key.clone(), // signing_key comes after storage
            shard_id, // shard_id comes after signing_key
            tee_delay_config, // Pass the original Arc here (ownership transfer)
            Some(metrics_tx_clone.clone()), // Pass metrics sender
        );

        SimulatedTeeNode {
            identity,
            signing_key,
            raft_node,
            shard_id,
            processed_commands: HashSet::new(),
            runtime,
            network_rx,
            proposal_rx,
            proposal_tx,
            query_rx,
            query_tx,
            metrics_tx: metrics_tx_clone, // Store the original sender
        }
    }

    /// Returns the sender channel for command proposals.
    pub fn get_proposal_sender(&self) -> mpsc::Sender<NodeProposalRequest> {
        self.proposal_tx.clone()
    }

    /// Returns the sender channel for state queries.
    pub fn get_query_sender(&self) -> mpsc::Sender<NodeQuery> {
        self.query_tx.clone()
    }

    /// Starts the node's main event loop in a separate Tokio task.
    pub async fn run(mut self) {
        println!("[Node {}] Starting run loop...", self.identity.id);
        let tick_duration = Duration::from_millis(50);
        let mut tick_timer = interval(tick_duration);

        loop {
            tokio::select! {
                _ = tick_timer.tick() => {
                    let events = self.raft_node.tick();
                    self.handle_raft_events(events).await;
                }
                Some(network_msg) = self.network_rx.recv() => {
                    println!("[Node {}] Received network message from {}: {:?}", 
                        self.identity.id, network_msg.sender.id, network_msg.message);
                    match network_msg.message {
                        Message::RaftAppendEntries(args) => {
                            let events = self.raft_node.handle_message(network_msg.sender, RaftMessage::AppendEntries(args));
                            self.handle_raft_events(events).await;
                        }
                        Message::RaftAppendEntriesReply(reply) => {
                            let events = self.raft_node.handle_message(network_msg.sender, RaftMessage::AppendEntriesReply(reply));
                            self.handle_raft_events(events).await;
                        }
                        Message::RaftRequestVote(args) => {
                            let events = self.raft_node.handle_message(network_msg.sender, RaftMessage::RequestVote(args));
                            self.handle_raft_events(events).await;
                        }
                        Message::RaftRequestVoteReply(reply) => {
                            let events = self.raft_node.handle_message(network_msg.sender, RaftMessage::RequestVoteReply(reply));
                            self.handle_raft_events(events).await;
                        }
                        Message::LivenessChallenge(challenge_struct) => {
                            println!("[Node {}] Received liveness challenge: Nonce={:?}", self.identity.id, challenge_struct.nonce);
                            // Pass the u64 nonce to the handler
                            self.handle_liveness_challenge(challenge_struct.nonce).await; // Pass u64
                        }
                        _ => {
                            warn!("[Node {}] Received unhandled message type: {:?}", self.identity.id, network_msg.message);
                        }
                    }
                }
                Some((command, result_sender)) = self.proposal_rx.recv() => {
                    println!("[Node {}] Received external command proposal: {:?}", self.identity.id, command);
                    let result = self.raft_node.propose_command(command);
                    if result_sender.send(Ok(result.clone())).is_err() {
                        eprintln!("[Node {}] Failed to send proposal result back.", self.identity.id);
                    }
                    self.handle_raft_events(result).await;
                }
                Some((query, response_sender)) = self.query_rx.recv() => {
                    self.handle_query(query, response_sender).await;
                }
                else => {
                    println!("[Node {}] Message/Query channel closed or select! completed. Stopping run loop.", self.identity.id);
                    break;
                }
            }
        }
    }

    /// Handles received state queries
    async fn handle_query(&self, query: NodeQueryRequest, response_sender: oneshot::Sender<NodeQueryResponse>) {
         match query {
            NodeQueryRequest::GetRaftState => {
                let state = &self.raft_node.state;
                let response = NodeQueryResponse::RaftState {
                    last_log_index: state.last_log_index(),
                    commit_index: state.commit_index,
                    role: state.role.clone(),
                };
                if response_sender.send(response).is_err() {
                    eprintln!("[Node {}] Failed to send query response back.", self.identity.id);
                }
            }
        }
    }

    /// Handles a received liveness challenge by generating and sending an attestation
    async fn handle_liveness_challenge(&self, nonce: u64) {
        // Construct the message to sign: (node_id || nonce || timestamp)
        // NOTE: Timestamp is missing here! Liveness challenge logic needs revision.
        // Using a placeholder timestamp for now.
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(); // Use millis as u128

        // Convert u64 nonce to [u8; 32] by hashing
        let nonce_bytes = nonce.to_ne_bytes();
        let nonce_hash: [u8; 32] = keccak256(&nonce_bytes); 

        let mut message = Vec::new();
        message.extend_from_slice(&self.identity.id.to_ne_bytes());
        message.extend_from_slice(&nonce_hash); // Use the 32-byte hash for signing
        message.extend_from_slice(&(timestamp as u64).to_ne_bytes()); 

        // Sign the message using the node's signing key
        let signature = self.signing_key.sign(&message);

        // Create the attestation response
        let attestation = LivenessAttestation {
            node_id: self.identity.id,
            nonce: nonce_hash, // Use the 32-byte hash
            timestamp: timestamp as u64, // Cast timestamp to u64
            signature,
        };

        // Send the attestation response via the Runtime to the Aggregator
        self.runtime.forward_attestation_to_aggregator(attestation).await;
    }

    /// Processes events generated by the RaftNode.
    async fn handle_raft_events(&mut self, events: Vec<RaftEvent>) {
        for event in events {
            match event {
                RaftEvent::SendMessage(target_identity, message) => {
                    let network_msg = NetworkMessage {
                        sender: self.identity.clone(),
                        receiver: target_identity,
                        message: Message::from(message),
                    };
                    self.runtime.send_message(network_msg);
                }
                RaftEvent::BroadcastMessage(message) => {
                    println!("[Node {}] Broadcasting message: {:?}", self.identity.id, message);
                    self.runtime.broadcast_message(self.identity.clone(), message).await;
                }
                RaftEvent::ApplyToStateMachine(commands) => {
                     println!("[Node {}] Applying commands: {:?}", self.identity.id, commands);
                    self.process_state_machine_commands(commands).await;
                }
                RaftEvent::Noop => {}
            }
        }
    }

    /// Processes commands applied to the state machine via Raft consensus.
    async fn process_state_machine_commands(&mut self, commands: Vec<Command>) {
        for command in commands {
            println!("[Node {}][StateMachine] Processing command: {:?}", self.identity.id, command);
            match command {
                Command::ConfirmLockAndSign(lock_data) => {
                    // Check if this lock proof has already been processed
                    if self.processed_commands.contains(&lock_data.tx_id) {
                        println!("[Node {}][StateMachine] Command for tx_id {} already processed. Skipping.", self.identity.id, lock_data.tx_id);
                        continue; // Skip processing this command
                    }

                    match bincode::encode_to_vec(&lock_data, standard()) {
                        Ok(data_to_sign) => {
                            // DEBUG: Print data and key before signing
                            println!("[Node {}][SignDebug] Signing data hex: {}", self.identity.id, hex::encode(&data_to_sign));
                            println!("[Node {}][SignDebug] Node PubKey: {:?}", self.identity.id, self.identity.public_key);
                            
                            println!("[Node {}][StateMachine] Signing data for tx_id: {}", self.identity.id, lock_data.tx_id);
                            let signature: Signature = self.raft_node.enclave.sign(&data_to_sign).await;
                            let share = (self.identity.clone(), lock_data.clone(), signature);
                            println!("[Node {}][StateMachine] Submitting signature share for tx_id: {}", self.identity.id, lock_data.tx_id);
                            self.runtime.submit_result(share).await;

                            // Mark this command (by tx_id) as processed
                            self.processed_commands.insert(lock_data.tx_id.clone());
                        }
                        Err(e) => {
                            eprintln!("[Node {}][StateMachine] Error serializing LockProofData for signing: {}", self.identity.id, e);
                        }
                    }
                }
                Command::Noop => {
                    println!("[Node {}][StateMachine] Processing Noop command.", self.identity.id);
                }
                // Add case for Dummy command (required because of cfg(test))
                #[cfg(test)]
                Command::Dummy => {
                     println!("Node {}: Applying Dummy command (test)", self.identity.id);
                     // No action needed for Dummy
                 }
                // Add other command handlers here if needed in the future
            }
        }
    }

    // Add methods for application-specific logic if needed
    // e.g., fn process_command(command: Command) -> Result<Option<SignatureShare>, Error>
}