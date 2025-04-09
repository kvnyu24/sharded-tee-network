// Network message types module

use crate::raft::messages::{AppendEntriesArgs, AppendEntriesReply, RequestVoteArgs, RequestVoteReply};
use crate::liveness::types::{NonceChallenge, AttestationResponse};
use crate::cross_chain::types::LockRequest;
use crate::tee_logic::threshold_sig::PartialSignature;
use crate::tee_logic::Signature;
use crate::data_structures::TEEIdentity;
use crate::tee_logic::crypto_sim::generate_keypair;
use std::sync::Mutex;

// Represents the types of messages that can be sent over the network
#[derive(Debug, Clone)] // Added Clone
pub enum Message {
    // Raft messages
    RaftAppendEntries(AppendEntriesArgs),
    RaftAppendEntriesReply(AppendEntriesReply),
    RaftRequestVote(RequestVoteArgs),
    RaftRequestVoteReply(RequestVoteReply),

    // Liveness messages
    LivenessChallenge(NonceChallenge),
    LivenessResponse(AttestationResponse),

    // Cross-Chain messages
    ShardLockRequest(LockRequest), // Coordinator -> Shard TEEs
    CoordPartialSig { // Coordinator -> Coordinator
        tx_id: String,
        commit: bool,
        signature: PartialSignature,
    },
    // TODO: Add LockProof message from Shard -> Coordinator
    // TODO: Add Release/Abort instruction message from Coordinator -> Shard

    // Placeholder for other message types like client requests, state updates etc.
    Placeholder(String),
}

// Represents a message in transit
// Useful for simulation frameworks
#[derive(Clone, Debug)]
pub struct NetworkMessage {
    pub sender: TEEIdentity,
    pub receiver: TEEIdentity,
    pub message: Message,
    // Add timestamp, sequence numbers etc. if needed for simulation
}

// Trait for abstracting network sending operations
pub trait NetworkInterface {
    fn send_message(&self, msg: NetworkMessage);
}

// Allow the trait object to be shared safely across threads
impl dyn NetworkInterface + Send + Sync {}


// Mock implementation for testing
#[derive(Default, Debug)] 
pub struct MockNetwork {
    pub sent_messages: Mutex<Vec<NetworkMessage>>,
}

#[async_trait::async_trait]
impl NetworkInterface for MockNetwork {
    fn send_message(&self, msg: NetworkMessage) {
        self.sent_messages.lock().unwrap().push(msg);
    }
}

impl MockNetwork {
    pub fn new() -> Self {
        MockNetwork { sent_messages: Mutex::new(Vec::new()) }
    }

    pub fn get_sent_messages(&self) -> Vec<NetworkMessage> {
        self.sent_messages.lock().unwrap().clone()
    }

    pub fn clear_sent_messages(&self) {
        self.sent_messages.lock().unwrap().clear();
    }

    pub fn retrieve_messages_for(&self, recipient_id: &TEEIdentity) -> Vec<NetworkMessage> {
        let mut messages = self.sent_messages.lock().unwrap();
        let mut recipient_messages = Vec::new();
        messages.retain(|msg| {
            if &msg.receiver == recipient_id {
                recipient_messages.push(msg.clone());
                false
            } else {
                true
            }
        });
        recipient_messages
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    // Import specific Raft message types needed for tests
    use crate::raft::messages::{RequestVoteArgs, RequestVoteReply};

     fn create_test_tee(id: usize) -> TEEIdentity {
        // Create TEEIdentity with usize ID and a real public key
        let keypair = generate_keypair();
        TEEIdentity { id, public_key: keypair.verifying_key() }
    }

    // Rename test to reflect it tests Message enum variants
    #[test]
    fn message_variant_creation() {
        // Create a Raft variant directly using Message enum
        let raft_req = Message::RaftRequestVote(RequestVoteArgs {
            term: 1,
            candidate_id: create_test_tee(1),
            last_log_index: 0,
            last_log_term: 0,
        });

        // Simple check that wrapping works
        match raft_req {
            Message::RaftRequestVote(args) => {
                assert_eq!(args.term, 1);
            }
            _ => panic!("Incorrect variant"),
        }

        // Example for cross-chain message (optional)
        // let lock_req = Message::ShardLockRequest(...);
        // assert!(matches!(lock_req, Message::ShardLockRequest(_)));
    }

    #[test]
    fn network_message_creation() {
         let sender_tee = create_test_tee(10);
         let receiver_tee = create_test_tee(20);
         // Create a Raft reply variant directly using Message enum
         let raft_reply = Message::RaftRequestVoteReply(RequestVoteReply {
             term: 1, vote_granted: true
         });

         let net_msg = NetworkMessage {
             sender: sender_tee.clone(),
             receiver: receiver_tee.clone(),
             message: raft_reply.clone(), // Use the Message variant
         };

         assert_eq!(net_msg.sender, sender_tee);
         assert_eq!(net_msg.receiver, receiver_tee);
         // Check inner type using the Message enum
         if let Message::RaftRequestVoteReply(reply) = net_msg.message {
             assert!(reply.vote_granted);
         } else {
             panic!("Incorrect inner message type");
         }
    }
} 