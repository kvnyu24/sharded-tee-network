// Define Raft message structures

use crate::data_structures::TEEIdentity;
use crate::raft::state::LogEntry;
use serde::{Serialize, Deserialize};
use crate::tee_logic::crypto_sim::generate_keypair;
use std::time::{Duration, Instant, SystemTime};

// Sent by candidates to gather votes
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestVoteArgs {
    pub term: u64,
    pub candidate_id: TEEIdentity,
    pub last_log_index: u64,
    pub last_log_term: u64,
}

// Reply to RequestVoteArgs
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestVoteReply {
    pub term: u64,
    pub vote_granted: bool,
}

// Sent by leader to replicate log entries and as heartbeat
#[derive(Clone, Debug)]
pub struct AppendEntriesArgs {
    pub term: u64,
    pub leader_id: TEEIdentity,
    pub prev_log_index: u64,
    pub prev_log_term: u64,
    pub entries: Vec<LogEntry>, // Log entries to store (empty for heartbeat)
    pub leader_commit: u64,   // Leader's commitIndex
}

// Manual PartialEq implementation for AppendEntriesArgs
impl PartialEq for AppendEntriesArgs {
    fn eq(&self, other: &Self) -> bool {
        self.term == other.term &&
        self.leader_id == other.leader_id &&
        self.prev_log_index == other.prev_log_index &&
        self.prev_log_term == other.prev_log_term &&
        self.leader_commit == other.leader_commit &&
        self.entries.len() == other.entries.len() &&
        // Compare entries based on term and command only, ignore proposal_time
        self.entries.iter().zip(other.entries.iter()).all(|(a, b)| {
            a.term == b.term && a.command == b.command
        })
    }
}

// Add Eq implementation (safe because PartialEq is reflexive, symmetric, transitive)
impl Eq for AppendEntriesArgs {}

// Reply to AppendEntriesArgs
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendEntriesReply {
    pub term: u64,
    pub success: bool,
    // On success, contains the index of the last log entry known to be replicated on the follower.
    // On failure, this is None.
    pub match_index: Option<u64>,
    // On failure, can contain a hint for the leader's next attempt.
    // On success, this is None.
    pub mismatch_index: Option<u64>,
}

// Enum to wrap all possible Raft messages for network transport
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RaftMessage {
    RequestVote(RequestVoteArgs),
    RequestVoteReply(RequestVoteReply),
    AppendEntries(AppendEntriesArgs),
    AppendEntriesReply(AppendEntriesReply),
    // Potentially add other message types like InstallSnapshot later
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::state::Command;
    use crate::data_structures::TEEIdentity; // Ensure TEEIdentity is in scope

    fn create_test_tee(id: usize) -> TEEIdentity {
        let keypair = generate_keypair();
        TEEIdentity { id, public_key: keypair.verifying_key() }
    }

    #[test]
    fn request_vote_args_creation() {
        let args = RequestVoteArgs {
            term: 2,
            candidate_id: create_test_tee(1),
            last_log_index: 5,
            last_log_term: 1,
        };
        assert_eq!(args.term, 2);
        assert_eq!(args.candidate_id.id, 1);
    }

    #[test]
    fn request_vote_reply_creation() {
        let reply_granted = RequestVoteReply { term: 2, vote_granted: true };
        let reply_denied = RequestVoteReply { term: 2, vote_granted: false };
        assert!(reply_granted.vote_granted);
        assert!(!reply_denied.vote_granted);
    }

    #[test]
    fn append_entries_args_creation() {
        // Calculate Duration since epoch for the test entries using SystemTime
        let time_now_sys = SystemTime::now();
        let epoch_start = SystemTime::UNIX_EPOCH;
        // Calculate duration since epoch, handling potential error if time is before epoch
        let duration_since_epoch = time_now_sys.duration_since(epoch_start)
            .unwrap_or_else(|e| {
                eprintln!("Warning: System time is before epoch? Error: {}", e);
                Duration::ZERO // Default to zero duration if time is before epoch
            });

        let entries = vec![
            // Use the correct field name 'proposal_time_since_epoch' and provide a Duration
            LogEntry { term: 1, command: Command::Dummy, proposal_time_since_epoch: duration_since_epoch },
            LogEntry { term: 2, command: Command::Dummy, proposal_time_since_epoch: duration_since_epoch }
        ];
        let args = AppendEntriesArgs {
            term: 2,
            leader_id: create_test_tee(0),
            prev_log_index: 3,
            prev_log_term: 1,
            entries: entries.clone(),
            leader_commit: 3,
        };
        assert_eq!(args.term, 2);
        assert_eq!(args.leader_id.id, 0);
        assert_eq!(args.entries.len(), 2);
        assert_eq!(args.leader_commit, 3);
    }

    #[test]
    fn append_entries_reply_creation() {
        let reply_success = AppendEntriesReply { term: 2, success: true, match_index: Some(5), mismatch_index: None };
        let reply_fail = AppendEntriesReply { term: 2, success: false, match_index: None, mismatch_index: Some(2) };
        assert!(reply_success.success);
        assert!(reply_success.match_index.is_some());
        assert_eq!(reply_success.match_index.unwrap(), 5);
        assert!(reply_success.mismatch_index.is_none());

        assert!(!reply_fail.success);
        assert!(reply_fail.match_index.is_none());
        assert!(reply_fail.mismatch_index.is_some());
        assert_eq!(reply_fail.mismatch_index.unwrap(), 2);
    }

    #[test]
    fn raft_message_enum() {
        let args = RequestVoteArgs { term: 1, candidate_id: create_test_tee(1), last_log_index: 0, last_log_term: 0 };
        let msg = RaftMessage::RequestVote(args.clone());

        match msg {
            RaftMessage::RequestVote(inner_args) => assert_eq!(inner_args, args),
            _ => panic!("Incorrect message type"),
        }
    }
} 