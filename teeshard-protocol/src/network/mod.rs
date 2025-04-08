// Network message types module

use crate::raft::messages::RaftMessage;
use crate::liveness::types::{NonceChallenge, AttestationResponse};
use crate::cross_chain::types::LockProof;
use crate::tee_logic::Signature;
use crate::data_structures::TEEIdentity;
use crate::tee_logic::crypto_sim::generate_keypair;
 // Import key generation

// Represents messages exchanged between TEE nodes or with external entities
#[derive(Clone, Debug)] // PartialEq might be tricky with all variants
pub enum ProtocolMessage {
    // Raft messages (within a shard)
    Raft(RaftMessage),

    // Liveness messages
    Challenge(NonceChallenge),
    Attestation(AttestationResponse),

    // Cross-Chain Swap Coordination messages
    RequestLock { // Sent from Coordinator to Shard
        tx_id: String,
        shard_id: usize, // Target shard
        // include lock details if needed
    },
    SubmitLockProof { // Sent from Shard to Coordinator
        proof: LockProof,
    },
    InstructRelease { // Sent from Coordinator to Shard
        tx_id: String,
        shard_id: usize,
        signature: Signature, // Threshold signature for release
    },
    InstructAbort { // Sent from Coordinator to Shard
        tx_id: String,
        shard_id: usize,
        signature: Signature, // Threshold signature for abort
    },

    // Placeholder for other messages like gossip, state sync, etc.
    Gossip(Vec<u8>),
}

// Simple struct to represent a network message with sender/receiver
// Useful for simulation frameworks
#[derive(Clone, Debug)]
pub struct NetworkMessage {
    pub sender: TEEIdentity,
    pub receiver: TEEIdentity,
    pub message: ProtocolMessage,
    // Add timestamp, sequence numbers etc. if needed for simulation
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::messages::RequestVoteArgs;

     fn create_test_tee(id: usize) -> TEEIdentity {
        // Create TEEIdentity with usize ID and a real public key
        let keypair = generate_keypair();
        TEEIdentity { id, public_key: keypair.verifying_key() }
    }

    #[test]
    fn protocol_message_creation() {
        let raft_msg = RaftMessage::RequestVote(RequestVoteArgs {
            term: 1,
            candidate_id: create_test_tee(1),
            last_log_index: 0,
            last_log_term: 0,
        });
        let proto_msg = ProtocolMessage::Raft(raft_msg);

        // Simple check that wrapping works
        match proto_msg {
            ProtocolMessage::Raft(RaftMessage::RequestVote(args)) => {
                assert_eq!(args.term, 1);
            }
            _ => panic!("Incorrect variant"),
        }
    }

    #[test]
    fn network_message_creation() {
         let sender_tee = create_test_tee(10);
         let receiver_tee = create_test_tee(20);
         let raft_msg = RaftMessage::RequestVoteReply(crate::raft::messages::RequestVoteReply {
             term: 1, vote_granted: true
         });
         let proto_msg = ProtocolMessage::Raft(raft_msg);

         let net_msg = NetworkMessage {
             sender: sender_tee.clone(),
             receiver: receiver_tee.clone(),
             message: proto_msg.clone(),
         };

         assert_eq!(net_msg.sender, sender_tee);
         assert_eq!(net_msg.receiver, receiver_tee);
         // Cannot directly compare ProtocolMessage easily, check inner type
         if let ProtocolMessage::Raft(RaftMessage::RequestVoteReply(reply)) = net_msg.message {
             assert!(reply.vote_granted);
         } else {
             panic!("Incorrect inner message");
         }
    }
} 