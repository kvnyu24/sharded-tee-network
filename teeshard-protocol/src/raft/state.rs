// Define Raft-specific state structures

use crate::data_structures::TEEIdentity;
use std::collections::HashMap;
use crate::tee_logic::crypto_sim::generate_keypair; // Import key generation

// Represents the role of a Raft node
#[derive(Clone, Debug, PartialEq, Eq, Copy)] // Copy for simple state transitions
pub enum RaftRole {
    Follower,
    Candidate,
    Leader,
}

// Represents a command to be applied to the state machine
// For now, let's assume it's just a byte vector (serialized transaction or operation)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command(pub Vec<u8>);

// Represents an entry in the Raft log
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    pub term: u64,
    pub command: Command, // The command for the state machine
}

// Represents the persistent and volatile state of a Raft node
// Based on Figure 2 of the Raft paper
#[derive(Debug, Clone)] // Clone might be expensive if log is large
pub struct RaftNodeState {
    // Persistent state on all servers
    pub current_term: u64,
    pub voted_for: Option<TEEIdentity>, // CandidateId that received vote in current term
    pub log: Vec<LogEntry>,

    // Volatile state on all servers
    pub commit_index: u64, // Index of highest log entry known to be committed
    pub last_applied: u64, // Index of highest log entry applied to state machine

    // Volatile state on leaders (reinitialized after election)
    // TEEIdentity here assumes we use TEE IDs to identify followers
    pub next_index: HashMap<TEEIdentity, u64>,
    pub match_index: HashMap<TEEIdentity, u64>,

    // Current role of the node
    pub role: RaftRole,

    // Node's own identity
    pub id: TEEIdentity,
}

impl RaftNodeState {
    // Helper to get the term of the last log entry
    pub fn last_log_term(&self) -> u64 {
        self.log.last().map_or(0, |entry| entry.term)
    }

    // Helper to get the index of the last log entry
    pub fn last_log_index(&self) -> u64 {
        self.log.len() as u64 // Assuming 1-based indexing convention for raft indices
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_tee(id: usize) -> TEEIdentity {
        // Create TEEIdentity with usize ID and a real public key
        let keypair = generate_keypair();
        TEEIdentity { id, public_key: keypair.verifying_key() }
    }

    #[test]
    fn raft_role_equality() {
        assert_eq!(RaftRole::Follower, RaftRole::Follower);
        assert_ne!(RaftRole::Follower, RaftRole::Candidate);
    }

    #[test]
    fn log_entry_creation() {
        let entry = LogEntry {
            term: 1,
            command: Command(vec![10, 20]),
        };
        assert_eq!(entry.term, 1);
        assert_eq!(entry.command.0, vec![10, 20]);
    }

    #[test]
    fn raft_node_state_initial() {
        let tee_id = create_test_tee(1);
        let state = RaftNodeState {
            current_term: 0,
            voted_for: None,
            log: Vec::new(),
            commit_index: 0,
            last_applied: 0,
            next_index: HashMap::new(),
            match_index: HashMap::new(),
            role: RaftRole::Follower,
            id: tee_id.clone(),
        };

        assert_eq!(state.current_term, 0);
        assert_eq!(state.role, RaftRole::Follower);
        assert_eq!(state.id, tee_id);
        assert_eq!(state.last_log_index(), 0);
        assert_eq!(state.last_log_term(), 0);
    }

     #[test]
    fn raft_node_state_last_log_info() {
        let tee_id = create_test_tee(1);
        let log = vec![
            LogEntry { term: 1, command: Command(vec![1]) },
            LogEntry { term: 1, command: Command(vec![2]) },
            LogEntry { term: 2, command: Command(vec![3]) },
        ];

        let state = RaftNodeState {
            current_term: 2,
            voted_for: None,
            log: log.clone(),
            commit_index: 0,
            last_applied: 0,
            next_index: HashMap::new(),
            match_index: HashMap::new(),
            role: RaftRole::Follower,
            id: tee_id.clone(),
        };

        assert_eq!(state.last_log_index(), 3); // 1-based index
        assert_eq!(state.last_log_term(), 2);
    }
} 