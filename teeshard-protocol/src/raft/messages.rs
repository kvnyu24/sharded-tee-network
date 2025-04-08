// Define Raft message structures

use crate::data_structures::TEEIdentity;
use crate::raft::state::LogEntry;

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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendEntriesArgs {
    pub term: u64,
    pub leader_id: TEEIdentity,
    pub prev_log_index: u64,
    pub prev_log_term: u64,
    pub entries: Vec<LogEntry>, // Log entries to store (empty for heartbeat)
    pub leader_commit: u64,   // Leader's commitIndex
}

// Reply to AppendEntriesArgs
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendEntriesReply {
    pub term: u64,
    pub success: bool,
    // Optional: Used for fast log backtracking if success is false
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

    fn create_test_tee(id: usize) -> TEEIdentity {
        TEEIdentity { id, public_key: vec![id as u8] }
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
        let entries = vec![LogEntry { term: 2, command: Command(vec![0]) }];
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
        assert_eq!(args.entries.len(), 1);
        assert_eq!(args.leader_commit, 3);
    }

    #[test]
    fn append_entries_reply_creation() {
        let reply_success = AppendEntriesReply { term: 2, success: true, mismatch_index: None };
        let reply_fail = AppendEntriesReply { term: 2, success: false, mismatch_index: Some(2) };
        assert!(reply_success.success);
        assert!(!reply_fail.success);
        assert_eq!(reply_fail.mismatch_index, Some(2));
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