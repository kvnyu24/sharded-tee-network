// teeshard-protocol/src/simulation/node.rs

use crate::{
    config::SystemConfig,
    data_structures::TEEIdentity,
    liveness::types::{ChallengeNonce, LivenessAttestation}, // Import liveness types
    raft::{
        messages::RaftMessage,
        node::{RaftNode, RaftEvent},
        state::{Command, RaftRole}, // Import Command and RaftRole enum
        storage::InMemoryStorage, // Using InMemoryStorage for simulation
    },
    tee_logic::{crypto_sim::SecretKey, enclave_sim::EnclaveSim, types::{Signature, LockProofData}},
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
    // Use SigningKey from ed25519_dalek for consistency
    signing_key: SigningKey,
    raft_node: RaftNode,
    // Track processed command identifiers (e.g., tx_id for ConfirmLockAndSign)
    processed_commands: HashSet<String>,
    runtime: SimulationRuntime,                   // Handle to the runtime for sending messages
    // Channel now receives (sender_identity, message)
    message_rx: mpsc::Receiver<(TEEIdentity, RaftMessage)>,
    _message_tx: mpsc::Sender<(TEEIdentity, RaftMessage)>, // Keep sender to prevent channel closure
    // Channel specifically for receiving external command proposals
    proposal_rx: mpsc::Receiver<NodeProposalRequest>,
    proposal_tx: mpsc::Sender<NodeProposalRequest>, // Public sender for tests
    // NEW: Channel for state queries
    query_rx: mpsc::Receiver<NodeQuery>,
    query_tx: mpsc::Sender<NodeQuery>,
    // Channel for receiving liveness challenges
    challenge_rx: mpsc::Receiver<ChallengeNonce>,
    _challenge_tx: mpsc::Sender<ChallengeNonce>, // Keep sender for registration
}

impl SimulatedTeeNode {
    /// Creates a new simulated TEE node.
    pub fn new(
        identity: TEEIdentity,
        signing_key: SigningKey, // Accept SigningKey
        peers: Vec<TEEIdentity>, // Peers within the same shard
        config: SystemConfig,
        runtime: SimulationRuntime,
        // Accept liveness channel senders/receivers
        challenge_rx: mpsc::Receiver<ChallengeNonce>,
        _challenge_tx: mpsc::Sender<ChallengeNonce>,
    ) -> Self {
        let storage = Box::new(InMemoryStorage::new()); // Each node gets its own storage
        // EnclaveSim uses SecretKey which is an alias for SigningKey. Pass directly.
        // Remove redundant conversion via bytes:
        // let secret_key_bytes = signing_key.to_bytes();
        // let secret_key = SecretKey::from_bytes(&secret_key_bytes).expect("Should convert from signing key bytes");
        let enclave = EnclaveSim::new(identity.id, Some(signing_key.clone())); // Clone signing_key as EnclaveSim::new takes Option<SigningKey>
        let raft_node = RaftNode::new(identity.clone(), peers, config, storage, enclave);

        // Create a channel for this node to receive messages (now tuple)
        let (tx, rx): (mpsc::Sender<(TEEIdentity, RaftMessage)>, mpsc::Receiver<(TEEIdentity, RaftMessage)>) = mpsc::channel(100);
        let (prop_tx, prop_rx) = mpsc::channel(10); // Proposal channel
        let (query_tx, query_rx) = mpsc::channel(10); // Query channel

        SimulatedTeeNode {
            identity,
            signing_key,
            raft_node,
            processed_commands: HashSet::new(), // Initialize the set
            runtime,
            message_rx: rx,
            _message_tx: tx, // Store sender side
            proposal_rx: prop_rx,
            proposal_tx: prop_tx, // Store proposal sender
            query_rx, // Store query receiver
            query_tx, // Store query sender
            challenge_rx,
            _challenge_tx,
        }
    }

    /// Returns the sender channel for this node.
    pub fn get_message_sender(&self) -> mpsc::Sender<(TEEIdentity, RaftMessage)> {
        self._message_tx.clone()
    }

    /// Returns the sender channel for command proposals.
    pub fn get_proposal_sender(&self) -> mpsc::Sender<NodeProposalRequest> {
        self.proposal_tx.clone()
    }

    /// Returns the sender channel for state queries.
    pub fn get_query_sender(&self) -> mpsc::Sender<NodeQuery> {
        self.query_tx.clone()
    }

    /// Returns the sender channel for challenge sender (needed for runtime registration)
    pub fn get_challenge_sender(&self) -> mpsc::Sender<ChallengeNonce> {
        self._challenge_tx.clone()
    }

    /// Starts the node's main event loop in a separate Tokio task.
    pub async fn run(mut self) {
         println!("[Node {}] Starting run loop...", self.identity.id);
        // Example: Tick Raft periodically
        let tick_duration = Duration::from_millis(50); // Adjust as needed
        let mut tick_timer = interval(tick_duration);

        loop {
            tokio::select! {
                _ = tick_timer.tick() => {
                    // println!("[Node {}] Tick", self.identity.id);
                    let events = self.raft_node.tick();
                    self.handle_raft_events(events).await;
                }
                // Receive tuple (sender_identity, message)
                Some((sender_identity, message)) = self.message_rx.recv() => {
                     println!("[Node {}] Received message from {}: {:?}", self.identity.id, sender_identity.id, message);
                    // Pass both sender and message to handle_message
                    let events = self.raft_node.handle_message(sender_identity, message);
                     self.handle_raft_events(events).await;
                }
                // Handle incoming command proposals
                Some((command, result_sender)) = self.proposal_rx.recv() => {
                    println!("[Node {}] Received external command proposal: {:?}", self.identity.id, command);
                    // Directly call propose_command on the internal RaftNode
                    let result = self.raft_node.propose_command(command);
                    // Send the result back to the caller via the oneshot channel
                    if result_sender.send(Ok(result.clone())).is_err() {
                        eprintln!("[Node {}] Failed to send proposal result back.", self.identity.id);
                    }
                    // Also handle the events generated by the proposal itself
                    self.handle_raft_events(result).await;
                }
                // NEW: Handle state queries
                Some((query, response_sender)) = self.query_rx.recv() => {
                    self.handle_query(query, response_sender).await;
                }
                // Handle incoming liveness challenges
                Some(challenge) = self.challenge_rx.recv() => {
                    println!("[Node {}] Received liveness challenge: Nonce={:?}", self.identity.id, challenge.nonce);
                    self.handle_liveness_challenge(challenge).await;
                }
                else => {
                    // Channel closed or other condition, break the loop
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
    async fn handle_liveness_challenge(&self, challenge: ChallengeNonce) {
        // Construct the message to sign: (node_id || nonce || timestamp)
        let mut message = Vec::new();
        message.extend_from_slice(&self.identity.id.to_ne_bytes());
        message.extend_from_slice(&challenge.nonce);
        message.extend_from_slice(&challenge.timestamp.to_ne_bytes());

        // Sign the message using the node's signing key
        let signature = self.signing_key.sign(&message);

        // Create the attestation response
        let attestation = LivenessAttestation {
            node_id: self.identity.id,
            nonce: challenge.nonce,
            timestamp: challenge.timestamp,
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
                    self.runtime.route_message(self.identity.clone(), target_identity.id, message).await;
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
                            println!("[Node {}][StateMachine] Signing data for tx_id: {}", self.identity.id, lock_data.tx_id);
                            let signature: Signature = self.raft_node.enclave.sign_message(&data_to_sign);
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