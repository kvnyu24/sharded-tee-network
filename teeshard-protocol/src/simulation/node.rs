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
use log::{debug, error, info};

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

    /// Returns the shard ID this node belongs to.
    pub fn shard_id(&self) -> ShardId {
        self.shard_id
    }

    /// Starts the node's main event loop in a separate Tokio task.
    pub async fn run(mut self) {
        // ADD PRINTLN HERE
        println!("[Node {} Task Startup] Entered run method. Shard ID: {}", self.identity.id, self.shard_id);
        info!("[Node {} Task] Starting run loop. Shard ID: {}", self.identity.id, self.shard_id); // Use info! macro
        let raft_tick_duration = Duration::from_millis(50); // TODO: Make configurable?
        let mut raft_tick_timer = interval(raft_tick_duration);

        loop {
            // ADDED: Log at the start of each loop iteration
            debug!("[Node {} Task] Top of run loop iteration.", self.identity.id);

            let mut all_events: Vec<RaftEvent> = Vec::new();

            tokio::select! {
                // ADDED: Log when timer tick occurs
                _ = raft_tick_timer.tick() => {
                    debug!("[Node {} Task] Raft timer ticked.", self.identity.id);
                    let events = self.raft_node.tick();
                    all_events.extend(events);
                }
                // ADDED: Log when network message is received
                Some(network_msg) = self.network_rx.recv() => {
                    debug!("[Node {} Task] Received network message from Node {}: {:?}", self.identity.id, network_msg.sender.id, network_msg.message);
                    match network_msg.message {
                        Message::RaftAppendEntries(args) => {
                            let events = self.raft_node.handle_message(network_msg.sender, RaftMessage::AppendEntries(args));
                            all_events.extend(events);
                        }
                        Message::RaftAppendEntriesReply(reply) => {
                            let events = self.raft_node.handle_message(network_msg.sender, RaftMessage::AppendEntriesReply(reply));
                            all_events.extend(events);
                        }
                        Message::RaftRequestVote(args) => {
                            let events = self.raft_node.handle_message(network_msg.sender, RaftMessage::RequestVote(args));
                            all_events.extend(events);
                        }
                        Message::RaftRequestVoteReply(reply) => {
                            let events = self.raft_node.handle_message(network_msg.sender, RaftMessage::RequestVoteReply(reply));
                            all_events.extend(events);
                        }
                        Message::LivenessChallenge(challenge_struct) => {
                            info!("[Node {}] Received liveness challenge: Nonce={:?}", self.identity.id, challenge_struct.nonce);
                            self.handle_liveness_challenge(challenge_struct.nonce).await; // Nonce is u64
                        }
                        Message::LivenessResponse(_) => { // Added handling for LivenessResponse
                            warn!("[Node {}] Received LivenessResponse, but nodes typically send, not receive these.", self.identity.id);
                        }
                        // Add arms for the missing variants
                        Message::ShardLockRequest(req) => {
                            warn!("[Node {}] Received unexpected ShardLockRequest: {:?}", self.identity.id, req);
                        }
                        Message::CoordPartialSig { .. } => { // Use wildcard pattern for struct fields
                            warn!("[Node {}] Received unexpected CoordPartialSig.", self.identity.id);
                        }
                        Message::Placeholder(data) => {
                            warn!("[Node {}] Received Placeholder message: {:?}", self.identity.id, data);
                        }
                    }
                }
                // ADDED: Log when proposal message is received
                Some(proposal_request) = self.proposal_rx.recv() => {
                    debug!("[Node {} Task] Received proposal request.", self.identity.id);
                    let (command, ack_tx) = proposal_request;

                    info!("[Node {}] Received proposal request: {:?}", self.identity.id, command);
                    debug!("[Node {}] PRE raft_node.propose_command()", self.identity.id);
                    let raft_events = self.raft_node.propose_command(command);
                    debug!("[Node {}] POST raft_node.propose_command(), generated {} events", self.identity.id, raft_events.len());

                    all_events.extend(raft_events.clone()); // Clone events before sending

                    if let Err(_) = ack_tx.send(Ok(raft_events)) { // Send the cloned events
                        error!("[Node {}] Failed to send proposal ACK back to runtime.", self.identity.id);
                    }
                }
                // ADDED: Log when query message is received
                Some((query, response_sender)) = self.query_rx.recv() => {
                    debug!("[Node {} Task] Received query request: {:?}", self.identity.id, query);
                    self.handle_query(query, response_sender).await;
                }
                // Handles the case where a channel closes or the select! exits unexpectedly
                else => {
                    warn!("[Node {} Task] A channel closed or select! completed without matching. Breaking loop.", self.identity.id);
                    break; // Exit the loop if any channel closes or if select! terminates for other reasons
                }
            }

            if !all_events.is_empty() {
                 debug!("[Node {} Task] Handling {} Raft events.", self.identity.id, all_events.len());
                 self.handle_raft_events(all_events).await;
            }
        }
        info!("[Node {} Task] Run loop finished.", self.identity.id); // Use info!
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
            debug!("[Node {}] PRE apply_state_machine_command({:?}).await", self.identity.id, command);
            match self.apply_state_machine_command(command).await {
                Ok(_) => {
                     debug!("[Node {}] POST apply_state_machine_command().await - Success", self.identity.id);
                }
                Err(e) => {
                     error!("[Node {}] POST apply_state_machine_command().await - Error: {}", self.identity.id, e);
                }
            }
        }
        debug!("[Node {}] Finished processing ApplyToStateMachine event", self.identity.id);
    }
    
    async fn apply_state_machine_command(&mut self, command: Command) -> Result<(), String> {
        println!("[Node {}][StateMachine] Processing command: {:?}", self.identity.id, command);
        match command {
            Command::ConfirmLockAndSign(lock_data) => {
                if self.processed_commands.contains(&lock_data.tx_id) {
                    println!("[Node {}][StateMachine] Command for tx_id {} already processed. Skipping.", self.identity.id, lock_data.tx_id);
                    return Ok(());
                }

                let signable_data = (
                    &lock_data.tx_id, 
                    lock_data.source_chain_id, 
                    lock_data.target_chain_id, 
                    &lock_data.token_address, 
                    lock_data.amount, 
                    &lock_data.recipient
                );

                match bincode::encode_to_vec(&signable_data, standard()) {
                    Ok(data_to_sign) => {
                        println!("[Node {}][SignDebug] Signing data hex: {}", self.identity.id, hex::encode(&data_to_sign));
                        println!("[Node {}][SignDebug] Node PubKey: {:?}", self.identity.id, self.identity.public_key);
                        
                        println!("[Node {}][StateMachine] Signing data for tx_id: {}", self.identity.id, lock_data.tx_id);
                        let signature: Signature = self.raft_node.enclave.sign(&data_to_sign).await;
                        let share = (self.identity.clone(), lock_data.clone(), signature);

                        // --- Add PRE/POST logging for submit_result ---
                        let tx_id_for_log = lock_data.tx_id.clone(); // Clone tx_id for logging
                        println!("[Node {}][StateMachine] PRE runtime.submit_result for tx_id: {}", self.identity.id, tx_id_for_log);
                        self.runtime.submit_result(share).await;
                        println!("[Node {}][StateMachine] POST runtime.submit_result for tx_id: {}", self.identity.id, tx_id_for_log);
                        // --- End Add ---

                        self.processed_commands.insert(lock_data.tx_id.clone());
                        Ok(())
                    }
                    Err(e) => {
                        let err_msg = format!("Error serializing LockProofData for signing: {}", e);
                        eprintln!("[Node {}][StateMachine] {}", self.identity.id, err_msg);
                        Err(err_msg)
                    }
                }
            }
            Command::Noop => {
                println!("[Node {}][StateMachine] Processing Noop command.", self.identity.id);
                Ok(())
            }
            #[cfg(test)]
            Command::Dummy => {
                 println!("Node {}: Applying Dummy command (test)", self.identity.id);
                 Ok(())
             }
        }
    }

    // Add methods for application-specific logic if needed
    // e.g., fn process_command(command: Command) -> Result<Option<SignatureShare>, Error>
}