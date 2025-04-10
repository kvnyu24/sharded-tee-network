// Define Raft-specific state structures

use crate::{
    data_structures::TEEIdentity,
    tee_logic::types::LockProofData, // Import the type for data to be signed
};
use std::collections::HashMap;
use std::fmt::Debug;
use std::time::Instant; // Add Instant

/// Commands that can be applied to the state machine via Raft consensus.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, bincode::Encode, bincode::Decode)]
pub enum Command {
    // Example: Confirm a lock has been observed and generate signature share
    ConfirmLockAndSign(LockProofData),
    // Add other commands as needed (e.g., state updates, configuration changes)
    Noop, // Represents no operation, often used for leader heartbeats
    #[cfg(test)] // Only include Dummy variant during tests
    Dummy, // For testing purposes
}

/// Represents an entry in the Raft log.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub term: u64,
    pub command: Command, // The command for the state machine
    pub proposal_time: Instant, // Added proposal time
}

/// Represents the role of a node in the Raft cluster
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RaftRole {
    Follower,
    Candidate,
    Leader,
}

/// Represents the state of a Raft node. Combines persistent and volatile state.
#[derive(Debug)]
pub struct RaftNodeState {
    // Persistent state (must be saved before responding to RPCs)
    pub current_term: u64,
    pub voted_for: Option<TEEIdentity>,
    pub log: Vec<LogEntry>, // Log entries; each entry contains command for state machine, and term when entry was received by leader (first index is 1)

    // Volatile state on all servers
    pub commit_index: u64, // Index of highest log entry known to be committed (initialized to 0, increases monotonically)
    pub last_applied: u64, // Index of highest log entry applied to state machine (initialized to 0, increases monotonically)

    // Volatile state on leaders (reinitialized after election)
    pub next_index: HashMap<TEEIdentity, u64>, // For each server, index of the next log entry to send to that server (initialized to leader last log index + 1)
    pub match_index: HashMap<TEEIdentity, u64>, // For each server, index of highest log entry known to be replicated on server (initialized to 0, increases monotonically)

    // Node's current role and ID
    pub role: RaftRole,
    pub id: TEEIdentity,

    // Snapshot related fields (add these)
    pub last_snapshot_index: u64,
    pub last_snapshot_term: u64,
}

impl RaftNodeState {
    // Helper method to get the index of the last log entry
    pub fn last_log_index(&self) -> u64 {
        self.log.len() as u64 + self.last_snapshot_index
    }

    // Helper method to get the term of the last log entry
    pub fn last_log_term(&self) -> u64 {
        if let Some(last_entry) = self.log.last() {
            last_entry.term
        } else {
            self.last_snapshot_term
        }
    }

     // Helper method to get the term of the entry at a specific index
    pub fn get_term_at_index(&self, index: u64) -> Option<u64> {
        if index == 0 {
            Some(0) // Term 0 for index 0
        } else {
            self.log.get(index as usize - 1).map(|entry| entry.term)
        }
    }
}

// Remove the misplaced test function
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::tee_logic::crypto_sim::generate_keypair;
//
//     #[test]
//     fn test_log_entry_creation() {
//         let keypair = generate_keypair();
//         let identity = TEEIdentity { id: 1, public_key: keypair.verifying_key() };
//         let lock_data = LockProofData {
//             tx_id: "tx1".to_string(),
//             source_chain_id: 1,
//             target_chain_id: 2,
//             token_address: "0xtoken".to_string(),
//             amount: 100,
//             recipient: "0xrecipient".to_string(),
//         };
//         let cmd = Command::ConfirmLockAndSign(lock_data);
//         let entry = LogEntry { term: 1, command: cmd };
//         assert_eq!(entry.term, 1);
//         match entry.command {
//             Command::ConfirmLockAndSign(data) => assert_eq!(data.tx_id, "tx1"),
//             _ => panic!("Incorrect command type"),
//         }
//     }
// } 