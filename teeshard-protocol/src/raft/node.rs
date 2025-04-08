// Main RaftNode implementation (Algorithm 3)
// for handling timers, messages, and state transitions.

use crate::raft::messages::*;
use crate::raft::state::{Command, LogEntry, RaftNodeState, RaftRole};
use crate::data_structures::TEEIdentity;
use crate::config::SystemConfig;
use crate::raft::storage::{RaftStorage, InMemoryStorage}; // Add InMemoryStorage for test
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use rand::Rng;
use std::fmt;

// Represents a Raft node participating in consensus within a shard
// #[derive(Debug)] // Cannot derive because of Box<dyn RaftStorage>
pub struct RaftNode {
    pub state: RaftNodeState,
    // Peers in the same shard (excluding self)
    peers: Vec<TEEIdentity>,
    // System configuration
    config: SystemConfig,
    // Persistent Storage Interface
    // Use Box<dyn Trait> for dynamic dispatch
    storage: Box<dyn RaftStorage>,
    // Timers
    election_timeout: Duration,
    last_activity: Instant, // Time of last heartbeat/vote received or granted vote
    heartbeat_interval: Duration,
    last_heartbeat_sent: Instant, // Only relevant for leader
    // Votes received in the current term (for candidates)
    votes_received: HashSet<TEEIdentity>,
    // TODO: Add interface for network communication (sending messages)
    // TODO: Add interface for applying committed entries to state machine
}

// Manual Debug implementation
impl fmt::Debug for RaftNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RaftNode")
         .field("state", &self.state)
         .field("peers", &self.peers)
         .field("config", &self.config)
         // Skip storage field for Debug formatting
         .field("election_timeout", &self.election_timeout)
         .field("last_activity", &self.last_activity)
         .field("heartbeat_interval", &self.heartbeat_interval)
         .field("last_heartbeat_sent", &self.last_heartbeat_sent)
         .field("votes_received", &self.votes_received)
         .finish()
    }
}

// Output of a Raft node tick/message handling
#[derive(Debug)]
pub enum RaftEvent {
    SendMessage(TEEIdentity, RaftMessage),
    BroadcastMessage(RaftMessage),
    ApplyToStateMachine(Vec<Command>), // Commands to apply
    Noop,
}

impl RaftNode {
    pub fn new(id: TEEIdentity, peers: Vec<TEEIdentity>, config: SystemConfig, storage: Box<dyn RaftStorage>) -> Self {
        // Load persistent state using new storage methods
        let current_term = storage.get_term();
        let voted_for = storage.get_voted_for();
        // Eagerly load the entire log for simplicity in this implementation
        // A production system might load entries on demand
        let log = storage.get_log_entries_from(1);

        let initial_state = RaftNodeState {
            current_term,
            voted_for,
            log,
            commit_index: 0, // Volatile state, initialized to 0
            last_applied: 0, // Volatile state, initialized to 0
            // Volatile leader state, reinitialized after election
            next_index: HashMap::new(),
            match_index: HashMap::new(),
            role: RaftRole::Follower,
            id: id.clone(),
        };

        let mut node = RaftNode {
            state: initial_state,
            peers,
            config: config.clone(),
            storage, // Store the storage interface
            election_timeout: Duration::from_millis(0), // Will be randomized
            last_activity: Instant::now(),
            heartbeat_interval: Duration::from_millis(config.raft_heartbeat_ms),
            last_heartbeat_sent: Instant::now(), // Reset for followers/candidates
            votes_received: HashSet::new(),
        };
        node.randomize_election_timeout();
        node
    }

    fn randomize_election_timeout(&mut self) {
        let min = self.config.raft_election_timeout_min_ms;
        let max = self.config.raft_election_timeout_max_ms;
        let timeout_ms = rand::thread_rng().gen_range(min..=max);
        self.election_timeout = Duration::from_millis(timeout_ms);
        // println!("Node {}: Randomized election timeout to {}ms", self.state.id.id, timeout_ms);
    }

    fn reset_election_timer(&mut self) {
        self.last_activity = Instant::now();
        self.randomize_election_timeout();
    }

    // Called periodically to drive state machine (timers, etc.)
    // Returns a list of events/actions to be performed
    pub fn tick(&mut self) -> Vec<RaftEvent> {
        let mut events = Vec::new();
        match self.state.role {
            RaftRole::Follower | RaftRole::Candidate => {
                if self.last_activity.elapsed() >= self.election_timeout {
                    println!("Node {}: Election timeout! Becoming candidate for term {}.", self.state.id.id, self.state.current_term + 1);
                    events.extend(self.become_candidate());
                }
            }
            RaftRole::Leader => {
                if self.last_heartbeat_sent.elapsed() >= self.heartbeat_interval {
                    // println!("Node {}: Sending heartbeats (Term {}).", self.state.id.id, self.state.current_term);
                    events.extend(self.send_heartbeats());
                    self.last_heartbeat_sent = Instant::now();
                }
            }
        }

        // Apply newly committed entries
        if self.state.commit_index > self.state.last_applied {
            events.push(self.apply_committed_entries());
        }

        events
    }

    // Convert to follower state
    fn become_follower(&mut self, term: u64) {
        println!("Node {}: Becoming follower for term {}. Current role: {:?}", self.state.id.id, term, self.state.role);
        let old_term = self.state.current_term;
        self.state.role = RaftRole::Follower;
        self.state.current_term = term;
        self.state.voted_for = None;
        self.votes_received.clear();
        self.reset_election_timer();
        // Persist state changes if term increased
        if term > old_term {
             self.storage.save_term(term);
             self.storage.save_voted_for(None);
        }
    }

    // Transition to candidate state and request votes
    fn become_candidate(&mut self) -> Vec<RaftEvent> {
        let new_term = self.state.current_term + 1;
        self.state.current_term = new_term;
        println!("Node {}: Transitioning to Candidate for term {}", self.state.id.id, self.state.current_term);
        self.state.role = RaftRole::Candidate;
        let self_id = self.state.id.clone();
        self.state.voted_for = Some(self_id.clone());
        self.votes_received.clear();
        self.votes_received.insert(self_id.clone());
        self.reset_election_timer();

        // Persist state changes (term, voted_for)
        self.storage.save_term(new_term);
        self.storage.save_voted_for(Some(&self_id));

        let args = RequestVoteArgs {
            term: self.state.current_term,
            candidate_id: self.state.id.clone(),
            last_log_index: self.state.last_log_index(),
            last_log_term: self.state.last_log_term(),
        };

        vec![RaftEvent::BroadcastMessage(RaftMessage::RequestVote(args))]
    }

    // Transition to leader state
    fn become_leader(&mut self) -> Vec<RaftEvent> {
        if self.state.role != RaftRole::Candidate {
            println!("Node {}: Non-candidate {:?} tried to become leader. Ignoring.", self.state.id.id, self.state.role);
            return vec![]; // Only candidates can become leaders
        }
        println!("Node {}: Becoming Leader for term {}!", self.state.id.id, self.state.current_term);
        self.state.role = RaftRole::Leader;
        self.state.next_index.clear();
        self.state.match_index.clear();
        let last_log_idx = self.state.last_log_index();
        for peer in &self.peers {
            self.state.next_index.insert(peer.clone(), last_log_idx + 1);
            self.state.match_index.insert(peer.clone(), 0);
        }
        self.last_heartbeat_sent = Instant::now(); // Send initial heartbeats immediately
        self.send_heartbeats() // Return initial heartbeat events
    }

    // Send AppendEntries (heartbeats or with entries) to peers
    fn send_heartbeats(&mut self) -> Vec<RaftEvent> {
        let mut events = Vec::new();
        for peer in &self.peers {
             // For heartbeats, send empty entries
             // TODO: Proper log matching - this is simplified for heartbeats
             let prev_log_index = self.state.next_index.get(peer).map_or(0, |&idx| idx - 1);
             let prev_log_term = if prev_log_index > 0 {
                 self.state.log.get(prev_log_index as usize - 1).map_or(0, |e| e.term)
             } else {
                 0
             };

            let args = AppendEntriesArgs {
                term: self.state.current_term,
                leader_id: self.state.id.clone(),
                prev_log_index,
                prev_log_term,
                entries: vec![], // Empty for heartbeat
                leader_commit: self.state.commit_index,
            };
            events.push(RaftEvent::SendMessage(peer.clone(), RaftMessage::AppendEntries(args)));
        }
        events
    }

    // Handle incoming Raft messages
    pub fn handle_message(&mut self, sender: TEEIdentity, message: RaftMessage) -> Vec<RaftEvent> {
        match message {
            RaftMessage::RequestVote(args) => self.handle_request_vote(sender, args),
            RaftMessage::RequestVoteReply(reply) => self.handle_request_vote_reply(sender, reply),
            RaftMessage::AppendEntries(args) => self.handle_append_entries(sender, args),
            RaftMessage::AppendEntriesReply(reply) => self.handle_append_entries_reply(sender, reply),
        }
    }

    // Algorithm 3, HandleRequestVote RPC
    fn handle_request_vote(&mut self, candidate_id: TEEIdentity, args: RequestVoteArgs) -> Vec<RaftEvent> {
        let mut vote_granted = false;
        let mut persist_term = false;
        let mut persist_vote = false;

        if args.term < self.state.current_term {
             println!("Node {}: Denying vote to {} (Term {} < Current Term {})", self.state.id.id, candidate_id.id, args.term, self.state.current_term);
        } else {
            if args.term > self.state.current_term {
                println!("Node {}: Received RequestVote from {} with higher term ({} > {}). Becoming follower.", self.state.id.id, candidate_id.id, args.term, self.state.current_term);
                let old_term = self.state.current_term;
                self.become_follower(args.term);
                // Persist needed only if term actually changed (handled in become_follower)
                // persist_term = term > old_term;
            }
            let can_vote = self.state.voted_for.is_none() || self.state.voted_for == Some(candidate_id.clone());
            let log_ok = args.last_log_term > self.state.last_log_term() ||
                         (args.last_log_term == self.state.last_log_term() && args.last_log_index >= self.state.last_log_index());

            if can_vote && log_ok {
                // Grant vote only if term matches current term (after potential update)
                if args.term == self.state.current_term {
                    println!("Node {}: Granting vote to {} for term {}. Log ok: {}. Can vote: {}",
                             self.state.id.id, candidate_id.id, args.term, log_ok, can_vote);
                    vote_granted = true;
                    self.state.voted_for = Some(candidate_id.clone());
                    persist_vote = true; // Persist the vote we just granted
                    self.reset_election_timer();
                } else {
                    println!("Node {}: Denying vote to {} due to term mismatch after update (ReqTerm: {}, CurTerm: {})",
                             self.state.id.id, candidate_id.id, args.term, self.state.current_term);
                }
            } else {
                 println!("Node {}: Denying vote to {} for term {}. Log ok: {}. Can vote: {} (Voted for: {:?})",
                          self.state.id.id, candidate_id.id, args.term, log_ok, can_vote, self.state.voted_for);
            }
        }

        // Persist votedFor change if we granted a vote in the current term
        if persist_vote {
            self.storage.save_voted_for(self.state.voted_for.as_ref());
        }

        let reply = RequestVoteReply {
            term: self.state.current_term,
            vote_granted,
        };
        vec![RaftEvent::SendMessage(candidate_id, RaftMessage::RequestVoteReply(reply))]
    }

    // Handle reply to our vote request (when we are a candidate)
    fn handle_request_vote_reply(&mut self, voter_id: TEEIdentity, reply: RequestVoteReply) -> Vec<RaftEvent> {
        if self.state.role != RaftRole::Candidate {
             // println!("Node {}: Received vote reply from {}, but not a candidate. Ignoring.", self.state.id.id, voter_id.id);
            return vec![RaftEvent::Noop];
        }
         if reply.term > self.state.current_term {
             println!("Node {}: Received vote reply from {} with higher term ({} > {}). Becoming follower.", self.state.id.id, voter_id.id, reply.term, self.state.current_term);
            self.become_follower(reply.term);
            return vec![RaftEvent::Noop];
        }
        if reply.term < self.state.current_term {
             // println!("Node {}: Received stale vote reply from {} for term {}. Ignoring.", self.state.id.id, voter_id.id, reply.term);
             return vec![RaftEvent::Noop];
        }

        if reply.vote_granted {
            println!("Node {}: Received vote granted from {} for term {}", self.state.id.id, voter_id.id, self.state.current_term);
            self.votes_received.insert(voter_id);
            let cluster_size = self.peers.len() + 1;
            let majority = (cluster_size / 2) + 1;
            if self.votes_received.len() >= majority {
                println!("Node {}: Achieved majority ({}/{})! Becoming Leader.", self.state.id.id, self.votes_received.len(), majority);
                return self.become_leader();
            }
        } else {
             // println!("Node {}: Received vote denied from {} for term {}", self.state.id.id, voter_id.id, self.state.current_term);
        }
        vec![RaftEvent::Noop]
    }

    // Algorithm 3, HandleAppendEntries RPC
    fn handle_append_entries(&mut self, leader_id: TEEIdentity, args: AppendEntriesArgs) -> Vec<RaftEvent> {
        let mut success = false;
        let mut mismatch_index: Option<u64> = None;
        let mut events = Vec::new();

        if args.term < self.state.current_term {
            println!("Node {}: Rejecting AppendEntries from {} (Term {} < Current Term {})", self.state.id.id, leader_id.id, args.term, self.state.current_term);
        } else {
            let term_changed = args.term > self.state.current_term;
            self.reset_election_timer();
            if term_changed {
                 println!("Node {}: Received AppendEntries from {} with higher term ({} >= {}). Becoming follower.", self.state.id.id, leader_id.id, args.term, self.state.current_term);
                 self.become_follower(args.term); // This handles persistence if term > old_term
            } else if self.state.role == RaftRole::Candidate {
                 println!("Node {}: Candidate received AppendEntries from current leader {}. Becoming follower.", self.state.id.id, leader_id.id);
                 self.become_follower(args.term);
            }

            let prev_log_index_usize = args.prev_log_index as usize;
            let log_check_ok = if args.prev_log_index == 0 {
                true
            } else if prev_log_index_usize > self.state.log.len() {
                println!("Node {}: Log check fail: prevLogIndex {} out of bounds ({})", self.state.id.id, args.prev_log_index, self.state.log.len());
                mismatch_index = Some(self.state.last_log_index() + 1);
                false
            } else {
                if self.state.log[prev_log_index_usize - 1].term == args.prev_log_term {
                    true
                } else {
                    println!("Node {}: Log check fail: Term mismatch at index {}. Expected {}, found {}.",
                            self.state.id.id, args.prev_log_index, args.prev_log_term, self.state.log[prev_log_index_usize - 1].term);
                    mismatch_index = Some(args.prev_log_index);
                    false
                }
            };

            if log_check_ok {
                success = true;
                let mut next_leader_idx = 0usize;
                let mut changed_log = false;
                let mut first_new_entry_idx = self.state.log.len(); // Track where new entries start

                // Find first conflicting entry or end of existing log
                for (log_idx_offset, entry) in args.entries.iter().enumerate() {
                    let current_log_idx = (args.prev_log_index as usize) + log_idx_offset;
                    if current_log_idx >= self.state.log.len() {
                        // Leader's log is longer or same length, start appending from here
                        next_leader_idx = log_idx_offset;
                        changed_log = !args.entries[next_leader_idx..].is_empty();
                        first_new_entry_idx = current_log_idx;
                        break;
                    }
                    if self.state.log[current_log_idx].term != entry.term {
                        // Conflict detected, truncate our log
                        println!("Node {}: Conflict detected at index {}. Truncating log.", self.state.id.id, current_log_idx + 1);
                        self.state.log.truncate(current_log_idx);
                        self.storage.truncate_log(current_log_idx as u64 + 1); // Persist truncation
                        changed_log = true;
                        next_leader_idx = log_idx_offset;
                        first_new_entry_idx = current_log_idx;
                        break;
                    }
                    // Entries match, continue checking
                     next_leader_idx = log_idx_offset + 1;
                }

                // Append new entries if any exist after conflict/end point
                if next_leader_idx < args.entries.len() {
                     let entries_to_append = &args.entries[next_leader_idx..];
                     if !entries_to_append.is_empty() {
                        println!("Node {}: Appending {} new entries starting from log index {}",
                                self.state.id.id, entries_to_append.len(), first_new_entry_idx + 1);
                        self.state.log.extend_from_slice(entries_to_append);
                        self.storage.append_log_entries(entries_to_append); // Persist appended entries
                        changed_log = true;
                     }
                }

                // Update commit index
                if args.leader_commit > self.state.commit_index {
                    let old_commit_index = self.state.commit_index;
                    // Raft rule: commitIndex is min(leaderCommit, index of last NEW entry added in THIS RPC)
                    // If no new entries were added, last_log_index is based on previous state.
                    // If new entries were added, use the index of the last one.
                    let last_new_entry_index = if changed_log {
                        self.state.last_log_index()
                    } else {
                        // If log didn't change (e.g. duplicate AE), use leaderCommit based on existing log
                        args.prev_log_index + args.entries.len() as u64
                    };
                    self.state.commit_index = std::cmp::min(args.leader_commit, last_new_entry_index);
                    if self.state.commit_index > old_commit_index {
                        println!("Node {}: Updated commitIndex from {} to {}", self.state.id.id, old_commit_index, self.state.commit_index);
                        // Trigger application check in the next tick()
                        // events.push(self.apply_committed_entries()); // Don't do this here, let tick handle it
                    }
                }
            }
        }

        let reply = AppendEntriesReply {
            term: self.state.current_term,
            success,
            mismatch_index,
        };
        events.push(RaftEvent::SendMessage(leader_id, RaftMessage::AppendEntriesReply(reply)));
        events
    }

    // Handle reply to our AppendEntries (when we are leader)
    fn handle_append_entries_reply(&mut self, follower_id: TEEIdentity, reply: AppendEntriesReply) -> Vec<RaftEvent> {
        if self.state.role != RaftRole::Leader {
             return vec![RaftEvent::Noop];
        }
         if reply.term > self.state.current_term {
             println!("Node {}: AppendEntries reply from {} has higher term ({} > {}). Becoming follower.", self.state.id.id, follower_id.id, reply.term, self.state.current_term);
            self.become_follower(reply.term);
            return vec![RaftEvent::Noop];
        }
        if reply.term < self.state.current_term {
             return vec![RaftEvent::Noop];
        }

        // Get the assumed state when the corresponding AE was sent
        // NOTE: This is a simplification. A real implementation needs to track inflight AEs.
        let assumed_next_idx = self.state.next_index.get(&follower_id).copied().unwrap_or(1);
        let assumed_prev_log_idx = assumed_next_idx - 1;
        // TODO: Need to know how many entries were sent in the original AE
        let assumed_num_entries_sent = 0; // Placeholder - crucial for correct update

        if reply.success {
            // Update based on the indices assumed to be replicated by this successful reply
            let new_match_index = assumed_prev_log_idx + assumed_num_entries_sent;
            let new_next_index = new_match_index + 1;

            // Only update if it increases (monotonicity)
            let current_match = self.state.match_index.get(&follower_id).copied().unwrap_or(0);
            if new_match_index > current_match {
                self.state.match_index.insert(follower_id.clone(), new_match_index);
                self.state.next_index.insert(follower_id.clone(), new_next_index);
                println!("Node {}: AppendEntries success from {}. Updated matchIndex={}, nextIndex={}.",
                         self.state.id.id, follower_id.id, new_match_index, new_next_index);
                 // Potentially update commit index now that matchIndex has advanced
                 self.update_commit_index();
            } else {
                 println!("Node {}: AppendEntries success from {} but new_match_index ({}) <= current ({}), no update.",
                          self.state.id.id, follower_id.id, new_match_index, current_match);
            }
        } else {
             // Use hint if available, otherwise just decrement
             let new_next_index = reply.mismatch_index.unwrap_or_else(|| std::cmp::max(1, assumed_next_idx.saturating_sub(1)));
             self.state.next_index.insert(follower_id.clone(), new_next_index);
             println!("Node {}: AppendEntries failed from {}. Decrementing nextIndex to {}. Will retry.",
                      self.state.id.id, follower_id.id, new_next_index);
            // TODO: Resend AppendEntries immediately?
        }

        vec![RaftEvent::Noop]
    }

    // Update commit index based on majority matchIndex (Leader only)
    fn update_commit_index(&mut self) {
        if self.state.role != RaftRole::Leader {
            return;
        }
        let cluster_size = self.peers.len() + 1;
        let majority = (cluster_size / 2) + 1;

        let mut potential_commit_indices: Vec<u64> = self.state.match_index.values().cloned().collect();
        potential_commit_indices.push(self.state.last_log_index());
        potential_commit_indices.sort_unstable();
        potential_commit_indices.reverse();

        let majority_threshold_idx = majority.saturating_sub(1);
        if majority_threshold_idx < potential_commit_indices.len() {
            let n = potential_commit_indices[majority_threshold_idx];
            if n > self.state.commit_index {
                if let Some(entry) = self.state.log.get(n as usize - 1) { // 1-based index N
                    if entry.term == self.state.current_term {
                        println!("Node {}: Updating commitIndex to {} based on majority match.", self.state.id.id, n);
                        self.state.commit_index = n;
                         // TODO: Trigger application of newly committed entries
                    } else {
                        println!("Node {}: Cannot update commitIndex to {} because log term is different ({})", self.state.id.id, n, entry.term);
                    }
                }
            }
        }
    }

    // Apply entries from last_applied up to commit_index
    fn apply_committed_entries(&mut self) -> RaftEvent {
        let mut commands_to_apply = Vec::new();
        // Note: commit_index and last_applied are 1-based
        while self.state.last_applied < self.state.commit_index {
            let apply_idx = (self.state.last_applied + 1) as usize;
            if apply_idx > self.state.log.len() {
                 eprintln!("Error: Trying to apply log index {} but log length is {}", apply_idx, self.state.log.len());
                 // This indicates a bug, maybe stop processing further applications?
                 break;
            }
            let entry_to_apply = &self.state.log[apply_idx - 1];
            println!("Node {}: Applying log entry {} (Term {}) to state machine.", self.state.id.id, apply_idx, entry_to_apply.term);
            commands_to_apply.push(entry_to_apply.command.clone());
            self.state.last_applied += 1;
        }

        if !commands_to_apply.is_empty() {
            RaftEvent::ApplyToStateMachine(commands_to_apply)
        } else {
            RaftEvent::Noop
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SystemConfig;
    use crate::data_structures::TEEIdentity;
    // Try absolute path from crate root
    use crate::raft::storage::InMemoryStorage;
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    // Helper function to create a TEEIdentity
    fn create_identity(id: u64) -> TEEIdentity {
        // Create TEEIdentity with usize ID and empty public key
        TEEIdentity { id: id as usize, public_key: vec![] }
    }

    // Helper function to deliver messages between nodes
    // Use TEEIdentity
    fn deliver_messages(
        nodes: &mut HashMap<TEEIdentity, Arc<Mutex<RaftNode>>>, // Use TEEIdentity
        messages: Vec<(TEEIdentity, TEEIdentity, RaftMessage)>, // (sender, recipient, message)
        network: &mut HashMap<TEEIdentity, VecDeque<(TEEIdentity, RaftMessage)>>, // Queue stores (sender, message)
    ) {
        for (sender_id, recipient_id, msg) in messages {
            if let Some(queue) = network.get_mut(&recipient_id) {
                // Queue the sender ID along with the message
                queue.push_back((sender_id, msg));
            } else {
                // Use recipient_id.id which is usize
                println!("Warning: Node {} not found for message delivery.", recipient_id.id);
            }
        }
    }

    // Helper to process queued messages for a node
    // Use TEEIdentity
    fn process_network_queue(
        node_id: &TEEIdentity, // Use TEEIdentity
        nodes: &mut HashMap<TEEIdentity, Arc<Mutex<RaftNode>>>, // Use TEEIdentity
        network: &mut HashMap<TEEIdentity, VecDeque<(TEEIdentity, RaftMessage)>>,
    ) -> Vec<(TEEIdentity, TEEIdentity, RaftMessage)> { // Returns (sender, recipient, message)
        let mut outgoing_messages = Vec::new();
        if let Some(queue) = network.get_mut(node_id) {
            while let Some((sender_id, msg)) = queue.pop_front() {
                if let Some(node_arc) = nodes.get(node_id) {
                    let mut node = node_arc.lock().unwrap();
                    // handle_message expects TEEIdentity, sender_id is now TEEIdentity
                    let events = node.handle_message(sender_id, msg);
                    for event in events {
                        match event {
                            RaftEvent::SendMessage(recipient, message) => {
                                // Sender is the current node processing the queue
                                outgoing_messages.push((node_id.clone(), recipient, message));
                            }
                            RaftEvent::BroadcastMessage(message) => {
                                for peer_id in node.peers.iter().cloned() {
                                    if &peer_id != node_id { // Compare TEEIdentity directly
                                        // Sender is the current node
                                        outgoing_messages.push((node_id.clone(), peer_id, message.clone()));
                                    }
                                }
                            }
                            RaftEvent::ApplyToStateMachine(commands) => {
                                // Use node_id.id which is usize
                                println!("Node {}: Applying {} commands", node_id.id, commands.len());
                            }
                            RaftEvent::Noop => {}
                        }
                    }
                }
            }
        }
        outgoing_messages
    }

    #[test]
    fn test_leader_election_basic() {
        // Use TEEIdentity
        let node_ids: Vec<TEEIdentity> = (1..=3).map(create_identity).collect();
        let mut nodes: HashMap<TEEIdentity, Arc<Mutex<RaftNode>>> = HashMap::new();
        let mut network: HashMap<TEEIdentity, VecDeque<(TEEIdentity, RaftMessage)>> = HashMap::new();
        let config = SystemConfig::default();

        for id in &node_ids {
            // Use TEEIdentity
            let peers: Vec<TEEIdentity> = node_ids.iter().filter(|&p| p != id).cloned().collect();
            let storage = Box::new(InMemoryStorage::new());
            let node = RaftNode::new(id.clone(), peers, config.clone(), storage);
            nodes.insert(id.clone(), Arc::new(Mutex::new(node)));
            network.insert(id.clone(), VecDeque::new());
        }

        println!("Simulating Raft ticks and message passing...");

        // Use TEEIdentity
        let mut outgoing_messages: Vec<(TEEIdentity, TEEIdentity, RaftMessage)> = Vec::new();

        for _ in 0..20 { 
            let mut current_tick_outgoing = Vec::new();
            deliver_messages(&mut nodes, outgoing_messages.drain(..).collect(), &mut network);

            for id in &node_ids {
                current_tick_outgoing.extend(process_network_queue(id, &mut nodes, &mut network));
            }

            for id in &node_ids {
                if let Some(node_arc) = nodes.get(id) {
                    let mut node = node_arc.lock().unwrap();
                    let events = node.tick();
                    for event in events {
                        match event {
                            RaftEvent::SendMessage(recipient, message) => {
                                current_tick_outgoing.push((id.clone(), recipient, message));
                            }
                            RaftEvent::BroadcastMessage(message) => {
                                for peer_id in node.peers.iter().cloned() {
                                    if &peer_id != id { // Compare TEEIdentity directly
                                        current_tick_outgoing.push((id.clone(), peer_id, message.clone()));
                                    }
                                }
                            }
                            RaftEvent::ApplyToStateMachine(commands) => {
                                // Use id.id which is usize
                                println!("Node {}: Applying {} commands during tick", id.id, commands.len());
                            }
                            RaftEvent::Noop => {}
                        }
                    }
                }
            }

            outgoing_messages.extend(current_tick_outgoing);

            let leader = find_leader(&nodes);
            if leader.is_some() {
                thread::sleep(Duration::from_millis(config.raft_election_timeout_max_ms / 2)); 
                let mut final_tick_outgoing = Vec::new();
                deliver_messages(&mut nodes, outgoing_messages.drain(..).collect(), &mut network);
                for id in &node_ids {
                    final_tick_outgoing.extend(process_network_queue(id, &mut nodes, &mut network));
                }
                deliver_messages(&mut nodes, final_tick_outgoing.drain(..).collect(), &mut network);
                for id in &node_ids {
                     process_network_queue(id, &mut nodes, &mut network); 
                }

                if find_leader(&nodes).is_some() {
                     println!("Stable leader found.");
                     break;
                } else {
                     println!("Leader lost after waiting, continuing simulation.");
                     outgoing_messages.clear();
                }
            }

            thread::sleep(Duration::from_millis(50)); 
        }

        let leader = find_leader(&nodes);
        assert!(leader.is_some(), "No leader elected after simulation.");

        let leader_id = leader.unwrap();
        let leader_node = nodes.get(&leader_id).unwrap().lock().unwrap();
        // Use leader_id.id which is usize
        println!("Final Leader: Node {}", leader_id.id);
        assert_eq!(leader_node.state.role, RaftRole::Leader);

        for id in &node_ids {
            if id != &leader_id { // Compare TEEIdentity
                let follower_node = nodes.get(id).unwrap().lock().unwrap();
                // Use id.id which is usize
                println!("Node {} final state: Role={:?}, Term={}", id.id, follower_node.state.role, follower_node.state.current_term);
                assert!(follower_node.state.role == RaftRole::Follower, "Node {} should be Follower, but is {:?}", id.id, follower_node.state.role);
                assert_eq!(follower_node.state.current_term, leader_node.state.current_term, "Node {} term mismatch", id.id);
            }
        }
    }

    // Helper to find the current leader among nodes
    // Use TEEIdentity
    fn find_leader(nodes: &HashMap<TEEIdentity, Arc<Mutex<RaftNode>>>) -> Option<TEEIdentity> {
        let mut leader_id = None;
        let mut leader_term = 0;
        let mut leader_count = 0;

        for (id, node_arc) in nodes {
            let node = node_arc.lock().unwrap();
            if node.state.role == RaftRole::Leader {
                if node.state.current_term >= leader_term { 
                    if node.state.current_term > leader_term {
                        leader_term = node.state.current_term;
                        leader_id = Some(id.clone());
                        leader_count = 1;
                    } else {
                        leader_count += 1;
                        leader_id = None; 
                        println!("Warning: Multiple leaders detected in term {}", leader_term);
                    }
                }
            }
        }
        if leader_count == 1 {
            leader_id
        } else {
            if leader_count > 1 {
                 println!("Error: Found {} leaders in term {}", leader_count, leader_term);
            }
            None 
        }
    }
} 