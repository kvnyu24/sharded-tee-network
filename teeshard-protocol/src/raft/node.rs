// Placeholder for the main RaftNode implementation (Algorithm 3)

// This file will eventually contain the RaftNode struct and its methods
// for handling timers, messages, and state transitions.

use crate::{
    config::SystemConfig,
    data_structures::TEEIdentity,
    raft::{messages::{AppendEntriesArgs, AppendEntriesReply, RaftMessage, RequestVoteArgs, RequestVoteReply}, state::{Command, LogEntry, RaftNodeState, RaftRole}, storage::RaftStorage},
    tee_logic::{crypto_sim::SecretKey, enclave_sim::{EnclaveSim, TeeDelayConfig}},
    simulation::metrics::MetricEvent,
};
use rand::Rng;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
    fmt,
};
use tokio::sync::mpsc; // Import mpsc
use tokio::time::sleep; // Only import sleep

// Define ShardId as usize for now within this module context
// TODO: Define ShardId globally if needed, e.g., in data_structures.rs or types.rs
pub type ShardId = usize;

// Represents a Raft node participating in consensus within a shard
// #[derive(Debug)] // Cannot derive because of Box<dyn RaftStorage>
pub struct RaftNode {
    pub state: RaftNodeState,
    // Peers in the same shard (excluding self)
    peers: Vec<TEEIdentity>,
    // System configuration
    config: SystemConfig,
    // Persistent Storage Interface
    // Use Box<dyn Trait> for dynamic dispatch - Add Send + Sync bounds
    storage: Box<dyn RaftStorage + Send + Sync>,
    shard_id: ShardId,
    // Timers
    election_timeout: Duration,
    last_activity: Instant, // Time of last heartbeat/vote received or granted vote
    heartbeat_interval: Duration,
    last_heartbeat_sent: Instant, // Only relevant for leader
    // Votes received in the current term (for candidates)
    votes_received: HashSet<TEEIdentity>,
    // Simulated TEE enclave for this node
    pub enclave: EnclaveSim,
    // Interface for network communication handled via RaftEvent::SendMessage / BroadcastMessage
    // Interface for applying committed entries handled via RaftEvent::ApplyToStateMachine
    metrics_tx: Option<mpsc::Sender<MetricEvent>>, // Added optional metrics sender
}

// Manual Debug implementation
impl fmt::Debug for RaftNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RaftNode")
         .field("state", &self.state)
         .field("peers", &self.peers)
         .field("config", &self.config)
         .field("shard_id", &self.shard_id)
         // Skip storage field for Debug formatting
         .field("election_timeout", &self.election_timeout)
         .field("last_activity", &self.last_activity)
         .field("heartbeat_interval", &self.heartbeat_interval)
         .field("last_heartbeat_sent", &self.last_heartbeat_sent)
         .field("votes_received", &self.votes_received)
         .field("enclave", &self.enclave)
         .field("metrics_tx_present", &self.metrics_tx.is_some())
         .finish()
    }
}

// Output of a Raft node tick/message handling
// Derive Clone
#[derive(Debug, Clone)]
pub enum RaftEvent {
    SendMessage(TEEIdentity, RaftMessage),
    BroadcastMessage(RaftMessage),
    ApplyToStateMachine(Vec<Command>), // Commands to apply
    Noop,
}

impl RaftNode {
    pub fn new(
        identity: TEEIdentity,
        peers: Vec<TEEIdentity>,
        config: SystemConfig,
        storage: Box<dyn RaftStorage + Send + Sync>,
        signing_key: SecretKey,
        shard_id: ShardId,
        delay_config: Arc<TeeDelayConfig>,
        metrics_tx: Option<mpsc::Sender<MetricEvent>>,
    ) -> Self {
        println!("[RaftNode::new START] Creating Node {}", identity.id);
        // Initialize RaftNodeState fields directly here
        let (current_term, voted_for) = storage.load_term_and_vote();
        let log = storage.load_log();
        let state = RaftNodeState {
            id: identity.clone(),
            role: RaftRole::Follower,
            current_term,
            voted_for,
            log,
            commit_index: 0,
            last_applied: 0,
            next_index: HashMap::new(),
            match_index: HashMap::new(),
            // TODO: Load snapshot info from storage if implemented
            last_snapshot_index: 0, 
            last_snapshot_term: 0,  
        };
        
        let enclave = EnclaveSim::new(
            identity.clone(), // Pass the full identity
            signing_key, // Pass the key directly
            delay_config,   
            metrics_tx.clone(),
        );
        
        let mut node = RaftNode {
            state,
            peers,
            config: config.clone(),
            storage,
            shard_id,
            election_timeout: Duration::from_millis(config.raft_election_timeout_max_ms),
            last_activity: Instant::now(),
            heartbeat_interval: Duration::from_millis(config.raft_heartbeat_ms),
            last_heartbeat_sent: Instant::now(),
            votes_received: HashSet::new(),
            enclave,
            metrics_tx,
        };
        println!("[RaftNode::new END] Node {} created. Calling reset_election_timer...", identity.id);
        node.reset_election_timer();
        
        // No initial events needed as state is initialized directly
        // if !initial_events.is_empty() {
        //      eprintln!("[RaftNode {}] Warning: Initial events detected from RaftNodeState::new: {:?}. Handling may be needed.", node.state.id.id, initial_events);
        // }
        node
    }

    fn randomize_election_timeout(&mut self) {
        let min = self.config.raft_election_timeout_min_ms;
        let max = self.config.raft_election_timeout_max_ms;
        // println!("[RaftNode {}] randomize_election_timeout: Calling rand::thread_rng().gen_range({}..={})", self.state.id.id, min, max);
        let timeout_ms = rand::thread_rng().gen_range(min..=max); // Restore random generation
        // let timeout_ms = min; // TEMP FIX: Use fixed minimum timeout - REMOVE THIS
        // println!("[RaftNode {}] randomize_election_timeout: Using fixed timeout_ms = {}", self.state.id.id, timeout_ms); // REMOVE THIS LOG
        self.election_timeout = Duration::from_millis(timeout_ms);
        // println!("[RaftNode {}] randomize_election_timeout: Got timeout_ms = {}", self.state.id.id, timeout_ms);
    }

    fn reset_election_timer(&mut self) {
        self.last_activity = Instant::now();
        self.randomize_election_timeout();
    }

    // Called periodically to drive state machine (timers, etc.)
    // Returns a list of events/actions to be performed
    pub fn tick(&mut self) -> Vec<RaftEvent> {
        println!("[Tick Node {} Term {} Role {:?}] last_activity {:?}, election_timeout {:?}, last_heartbeat {:?}, heartbeat_interval {:?}", 
                 self.state.id.id, self.state.current_term, self.state.role, self.last_activity.elapsed(), self.election_timeout, self.last_heartbeat_sent.elapsed(), self.heartbeat_interval);
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
                    events.extend(self.send_append_entries());
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
        println!("[State Node {} Term {} Role {:?}] Becoming follower for term {}. Current role: {:?}", 
                 self.state.id.id, self.state.current_term, self.state.role, term, self.state.role);
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
        println!("[State Node {} Term {} Role {:?}] Becoming candidate for term {}.", 
                 self.state.id.id, self.state.current_term, self.state.role, self.state.current_term + 1);
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
        println!("[State Node {} Term {} Role {:?}] Attempting to become leader.", 
                 self.state.id.id, self.state.current_term, self.state.role);
        if self.state.role != RaftRole::Candidate {
            println!("[State Node {}] Non-candidate {:?} tried to become leader. Ignoring.", self.state.id.id, self.state.role);
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

        // --- Send Metric --- 
        if let Some(metrics_tx) = self.metrics_tx.clone() { // Clone sender if it exists
            let event = MetricEvent::RaftLeaderElected {
                shard_id: self.shard_id,
                node_id: self.state.id.clone(),
                term: self.state.current_term,
            };
            // Send asynchronously, log error if channel closed
            let node_id_clone = self.state.id.clone(); // Clone for async block
            tokio::spawn(async move {
                if let Err(e) = metrics_tx.send(event).await {
                    // Use cloned node_id for logging
                    eprintln!("[RaftNode {}] Failed to send RaftLeaderElected metric: {}", node_id_clone.id, e);
                }
            });
        }
        // --- End Metric --- 

        // Send initial empty AppendEntries (heartbeats)
        self.send_append_entries() 
    }

    // Send AppendEntries (heartbeats or with entries) to peers
    fn send_append_entries(&mut self) -> Vec<RaftEvent> {
        let mut events = Vec::new();
        for peer in &self.peers {
            events.extend(self.send_append_entries_to_peer(peer));
        }
        events
    }

    // Handle incoming Raft messages
    pub fn handle_message(&mut self, sender: TEEIdentity, message: RaftMessage) -> Vec<RaftEvent> {
        println!("[HandleMsg Node {} Term {} Role {:?}] Received msg from {}: {:?}", 
                 self.state.id.id, self.state.current_term, self.state.role, sender.id, message);
        match message {
            RaftMessage::RequestVote(args) => self.handle_request_vote(sender, args),
            RaftMessage::RequestVoteReply(reply) => self.handle_request_vote_reply(sender, reply),
            RaftMessage::AppendEntries(args) => self.handle_append_entries(sender, args),
            RaftMessage::AppendEntriesReply(reply) => self.handle_append_entries_reply(sender, reply),
        }
    }

    // Algorithm 3, HandleRequestVote RPC
    fn handle_request_vote(&mut self, candidate_id: TEEIdentity, args: RequestVoteArgs) -> Vec<RaftEvent> {
        println!("[HandleRequestVote Node {} Term {} Role {:?}] Args: {:?}", 
                 self.state.id.id, self.state.current_term, self.state.role, args);
        let mut vote_granted = false;
        let _persist_term = false; // Prefix unused variable
        let mut persist_vote = false;

        if args.term < self.state.current_term {
             println!("Node {}: Denying vote to {} (Term {} < Current Term {})", self.state.id.id, candidate_id.id, args.term, self.state.current_term);
        } else {
            if args.term > self.state.current_term {
                println!("Node {}: Received RequestVote from {} with higher term ({} > {}). Becoming follower.", self.state.id.id, candidate_id.id, args.term, self.state.current_term);
                let _old_term = self.state.current_term; // Prefix unused variable
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
        println!("[HandleVoteReply Node {} Term {} Role {:?}] Reply from {}: {:?}", 
                 self.state.id.id, self.state.current_term, self.state.role, voter_id.id, reply);
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
        println!("[HandleAppendEntries Node {} Term {} Role {:?}] Args from {}: PrevIdx={}, PrevTerm={}, Entries={}, LeaderCommit={}", 
                 self.state.id.id, self.state.current_term, self.state.role, leader_id.id, args.prev_log_index, args.prev_log_term, args.entries.len(), args.leader_commit);
        let mut success = false;
        let mut mismatch_index: Option<u64> = None;
        let mut match_index: Option<u64> = None;
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

                // Set match_index to the last replicated entry
                match_index = Some(args.prev_log_index + args.entries.len() as u64);

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
                    }
                }
            }
        }

        let reply = AppendEntriesReply {
            term: self.state.current_term,
            success,
            match_index,
            mismatch_index,
        };
        events.push(RaftEvent::SendMessage(leader_id, RaftMessage::AppendEntriesReply(reply)));
        events
    }

    // Handle reply to our AppendEntries (when we are leader)
    fn handle_append_entries_reply(&mut self, follower_id: TEEIdentity, reply: AppendEntriesReply) -> Vec<RaftEvent> {
        println!("[HandleAppendReply Node {} Term {} Role {:?}] Reply from {}: {:?}", 
                 self.state.id.id, self.state.current_term, self.state.role, follower_id.id, reply);
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

        if reply.success {
            // Use the match_index from the reply to update our state
            if let Some(new_match_index) = reply.match_index {
                // Only update if it increases (monotonicity)
                let current_match = self.state.match_index.get(&follower_id).copied().unwrap_or(0);
                if new_match_index > current_match {
                    self.state.match_index.insert(follower_id.clone(), new_match_index);
                    self.state.next_index.insert(follower_id.clone(), new_match_index + 1);
                    println!("Node {}: AppendEntries success from {}. Updated matchIndex={}, nextIndex={}.",
                             self.state.id.id, follower_id.id, new_match_index, new_match_index + 1);
                     // Potentially update commit index now that matchIndex has advanced
                     self.update_commit_index();
                }
            }
        } else {
            // Use hint if available, otherwise just decrement
            let new_next_index = reply.mismatch_index.unwrap_or_else(|| {
                let current_next = self.state.next_index.get(&follower_id).copied().unwrap_or(1);
                std::cmp::max(1, current_next.saturating_sub(1))
            });
            self.state.next_index.insert(follower_id.clone(), new_next_index);
            println!("Node {}: AppendEntries failed from {}. Updated nextIndex to {}. Will retry on next tick.",
                     self.state.id.id, follower_id.id, new_next_index);
            
            // DO NOT Resend AppendEntries immediately. Let the next tick handle it.
            // return self.send_append_entries_to_peer(&follower_id);
        }

        vec![RaftEvent::Noop] // Return Noop in both success and failure cases (after processing)
    }

    // Helper function to send AppendEntries to a specific peer
    fn send_append_entries_to_peer(&self, peer: &TEEIdentity) -> Vec<RaftEvent> {
        let next_idx = self.state.next_index.get(peer).copied().unwrap_or(1);
        let prev_log_index = next_idx - 1;
        let prev_log_term = if prev_log_index > 0 {
            self.state.log.get(prev_log_index as usize - 1).map_or(0, |e| e.term)
        } else {
            0
        };

        // Get entries to send starting from next_idx
        let entries = if next_idx <= self.state.last_log_index() {
            self.state.log[(next_idx - 1) as usize..].to_vec()
        } else {
            vec![]
        };

        let args = AppendEntriesArgs {
            term: self.state.current_term,
            leader_id: self.state.id.clone(),
            prev_log_index,
            prev_log_term,
            entries,
            leader_commit: self.state.commit_index,
        };

        vec![RaftEvent::SendMessage(peer.clone(), RaftMessage::AppendEntries(args))]
    }

    /// Returns the current role of the Raft node.
    pub fn get_role(&self) -> RaftRole {
        self.state.role
    }

    // Function for the leader to propose a new command to be replicated.
    // Returns events (AppendEntries to followers) if leader, otherwise Noop.
    // Make this public for testing/external proposal.
    pub fn propose_command(&mut self, command: Command) -> Vec<RaftEvent> {
        if self.state.role != RaftRole::Leader {
            println!("Node {}: Non-leader tried to propose command {:?}. Ignoring.", self.state.id.id, command);
            return vec![RaftEvent::Noop];
        }

        println!("Node {}: Leader proposing command: {:?}", self.state.id.id, command);

        // Calculate duration since epoch for the new entry
        let duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_else(|e| {
                eprintln!("Warning: System time is before epoch? Error: {}", e);
                Duration::ZERO // Default to zero duration if time is before epoch
            });

        let new_entry = LogEntry {
            term: self.state.current_term,
            command,
            // Add the missing field with the calculated duration
            proposal_time_since_epoch: duration_since_epoch,
        };

        // Append to leader's log
        let new_log_index = self.state.last_log_index() + 1;
        self.state.log.push(new_entry.clone()); // Clone entry for storage
        self.storage.append_log_entries(&[new_entry]); // Persist

        // Update leader's matchIndex for itself
        self.state.match_index.insert(self.state.id.clone(), new_log_index);

        // Send AppendEntries to followers
        self.send_append_entries()
    }

    // Helper to advance commit index based on follower match indices
    fn update_commit_index(&mut self) {
        if self.state.role != RaftRole::Leader {
            return;
        }
        let cluster_size = self.peers.len() + 1;
        let majority = (cluster_size / 2) + 1;

        // Sort all match indices (including leader's) to find the majority threshold
        let mut potential_commit_indices: Vec<u64> = self.state.match_index.values().cloned().collect();
        // Include the leader's own progress (last log index)
        potential_commit_indices.push(self.state.last_log_index()); 
        potential_commit_indices.sort_unstable();
        potential_commit_indices.reverse();

        let majority_threshold_idx = majority.saturating_sub(1);
        if majority_threshold_idx < potential_commit_indices.len() {
            let n = potential_commit_indices[majority_threshold_idx];
            // Only advance commit_index if the entry at index n is from the current term
            // and n is greater than the current commit_index.
            if n > self.state.commit_index {
                if let Some(entry) = self.state.log.get(n as usize - 1) { // 1-based index N
                    if entry.term == self.state.current_term {
                        println!("Node {}: Updating commitIndex from {} to {} based on majority match.", 
                                 self.state.id.id, self.state.commit_index, n);
                        
                        let old_commit_index = self.state.commit_index;
                        self.state.commit_index = n;

                        // --- Send Metrics for newly committed entries --- 
                        if let Some(metrics_tx) = self.metrics_tx.clone() {
                            // Iterate from the old commit index + 1 up to the new commit index
                            for i in (old_commit_index + 1)..=self.state.commit_index {
                                if let Some(committed_entry) = self.state.log.get(i as usize - 1) {
                                    // Assign the Duration directly, don't convert to millis
                                    let latency = committed_entry.proposal_time_since_epoch; 
                                    let event = MetricEvent::RaftCommit {
                                        shard_id: self.shard_id,
                                        leader_id: self.state.id.clone(),
                                        latency, // Pass the Duration directly
                                    };
                                    let metrics_tx_clone = metrics_tx.clone();
                                    let node_id_clone = self.state.id.clone(); // Clone for async block
                                    // Send asynchronously
                                    tokio::spawn(async move {
                                        if let Err(e) = metrics_tx_clone.send(event).await {
                                            eprintln!("[RaftNode {}] Failed to send RaftCommit metric for index {}: {}", 
                                                     node_id_clone.id, i, e);
                                        }
                                    });
                                } else {
                                    // This shouldn't happen if commit_index logic is correct
                                     eprintln!("[RaftNode {}] Error: Committed entry at index {} not found in log for metrics!", 
                                              self.state.id.id, i);
                                }
                            }
                        }
                        // --- End Metrics --- 

                    } else {
                        // Not safe to commit index n because it's from a previous term
                        println!("Node {}: Cannot update commitIndex to {} because log term is different ({})", 
                                 self.state.id.id, n, entry.term);
                    }
                } else {
                     // This shouldn't happen if n <= last_log_index
                     eprintln!("[RaftNode {}] Error: Log entry at potential commit index {} not found!", self.state.id.id, n);
                }
            }
        }
    }

    // Helper to apply committed entries to the state machine
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
    use crate::tee_logic::crypto_sim::{generate_keypair, SecretKey}; // Import key generation and SecretKey
    // Try absolute path from crate root
    use crate::raft::storage::InMemoryStorage;
    use crate::simulation::metrics::MetricEvent; // Add import for metrics
    use crate::tee_logic::enclave_sim::{EnclaveSim, TeeDelayConfig}; // Import EnclaveSim and config
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};

    // Helper function to create a TEEIdentity and its SecretKey
    fn create_identity_with_key(id: u64) -> (TEEIdentity, SecretKey) {
        let keypair = generate_keypair();
        let identity = TEEIdentity {
            id: id as usize,
            public_key: keypair.verifying_key(),
        };
        (identity, keypair) // Return both identity and secret key
    }

    // Helper function to deliver messages between nodes
    // Use TEEIdentity
    fn deliver_messages(
        _nodes: &mut HashMap<TEEIdentity, Arc<Mutex<RaftNode>>>, // Prefix unused variable
        messages: Vec<(TEEIdentity, TEEIdentity, RaftMessage)>, // (sender, recipient, message)
        network: &mut HashMap<TEEIdentity, VecDeque<(TEEIdentity, RaftMessage)>>, // Queue stores (sender, message)
    ) {
        println!("[TestHarness] deliver_messages: Delivering {} messages", messages.len());
        for (sender_id, recipient_id, msg) in messages {
            if let Some(queue) = network.get_mut(&recipient_id) {
                println!("[TestHarness] deliver_messages: Queuing msg from {} to {}: {:?}", sender_id.id, recipient_id.id, msg);
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
        println!("[TestHarness] process_network_queue: Checking queue for Node {}", node_id.id);
        if let Some(queue) = network.get_mut(node_id) {
            while let Some((sender_id, msg)) = queue.pop_front() {
                println!("[TestHarness] process_network_queue: Processing msg for Node {} from {}: {:?}", node_id.id, sender_id.id, msg);
                if let Some(node_arc) = nodes.get(node_id) {
                    println!("[TestHarness] process_network_queue: Locking Node {}...", node_id.id);
                    let mut node = node_arc.lock().unwrap();
                    println!("[TestHarness] process_network_queue: Locked Node {}. Calling handle_message...", node_id.id);
                    // handle_message expects TEEIdentity, sender_id is now TEEIdentity
                    let events = node.handle_message(sender_id, msg);
                    println!("[TestHarness] process_network_queue: Node {} handle_message returned {} events. Processing events...", node_id.id, events.len());
                    for event in events {
                        match event {
                            RaftEvent::SendMessage(recipient, message) => {
                                println!("[TestHarness] process_network_queue: Node {} generated SendMessage to {}: {:?}", node_id.id, recipient.id, message);
                                // Sender is the current node processing the queue
                                outgoing_messages.push((node_id.clone(), recipient, message));
                            }
                            RaftEvent::BroadcastMessage(message) => {
                                println!("[TestHarness] process_network_queue: Node {} generated BroadcastMessage: {:?}", node_id.id, message);
                                for peer_id in node.peers.iter().cloned() {
                                    if &peer_id != node_id { // Compare TEEIdentity directly
                                        // Sender is the current node
                                        outgoing_messages.push((node_id.clone(), peer_id, message.clone()));
                                    }
                                }
                            }
                            RaftEvent::ApplyToStateMachine(commands) => {
                                println!("[TestHarness] process_network_queue: Node {} generated ApplyToStateMachine ({} commands)", node_id.id, commands.len());
                                // Use node_id.id which is usize
                                println!("Node {}: Applying {} commands", node_id.id, commands.len());
                            }
                            RaftEvent::Noop => {}
                        }
                    }
                    println!("[TestHarness] process_network_queue: Unlocking Node {}...", node_id.id);
                    // Mutex automatically unlocked here when `node` goes out of scope
                } else {
                    println!("[TestHarness] process_network_queue: Node {} Arc not found in map!", node_id.id);
                }
            }
        }
        outgoing_messages
    }

    // Mark test as async tokio test
    #[tokio::test]
    async fn test_leader_election_basic() {
        println!("[TestHarness START] test_leader_election_basic");
        // Use TEEIdentity
        let nodes_data: Vec<(TEEIdentity, SecretKey)> = (1..=3).map(create_identity_with_key).collect();
        let node_ids: Vec<TEEIdentity> = nodes_data.iter().map(|(id, _)| id.clone()).collect();
        let mut nodes: HashMap<TEEIdentity, Arc<Mutex<RaftNode>>> = HashMap::new();
        let mut network: HashMap<TEEIdentity, VecDeque<(TEEIdentity, RaftMessage)>> = HashMap::new();
        let config = SystemConfig::default();
        let delay_config = Arc::new(TeeDelayConfig::default()); // Create default delay config
        let (metrics_tx, _metrics_rx) = mpsc::channel::<MetricEvent>(100); // Use bounded channel

        // 4. Loop to create RaftNode instances
        println!("[TestHarness SETUP] Starting node creation loop...");
        for (id, secret_key) in &nodes_data { // <--- Problem could be in this loop
            println!("[TestHarness SETUP] Creating Node {}...", id.id);
            let peers: Vec<TEEIdentity> = node_ids.iter().filter(|&p| p != id).cloned().collect();
            let storage = Box::new(InMemoryStorage::new());
            // No need for EnclaveSim instance here, it's created inside RaftNode::new
            let node = RaftNode::new(
                id.clone(),
                peers,
                config.clone(),
                storage,
                secret_key.clone(), // Pass the actual secret key
                0, // shard_id (using 0 for tests)
                delay_config.clone(),
                Some(metrics_tx.clone())
            );
            println!("[TestHarness SETUP] Node {} RaftNode::new returned. Inserting into map...", id.id);
             // Insert into maps
            nodes.insert(id.clone(), Arc::new(Mutex::new(node)));
            network.insert(id.clone(), VecDeque::new());
        }
        println!("[TestHarness SETUP] Node creation loop finished.");

        println!("Simulating Raft ticks and message passing...");

        let mut outgoing_messages: Vec<(TEEIdentity, TEEIdentity, RaftMessage)> = Vec::new();

        for i in 0..20 { 
            println!("\n[TestHarness] Starting Loop Iteration {}", i);
            let mut current_tick_outgoing = Vec::new();
            
            println!("[TestHarness] Step 1: deliver_messages ({} messages)", outgoing_messages.len());
            deliver_messages(&mut nodes, outgoing_messages.drain(..).collect(), &mut network);

            println!("[TestHarness] Step 2: process_network_queues for all nodes");
            for id in &node_ids {
                current_tick_outgoing.extend(process_network_queue(id, &mut nodes, &mut network));
            }

            println!("[TestHarness] Step 3: Ticking all nodes");
            for id in &node_ids {
                if let Some(node_arc) = nodes.get(id) {
                    println!("[TestHarness] Ticking: Locking Node {}...", id.id);
                    let mut node = node_arc.lock().unwrap();
                    println!("[TestHarness] Ticking: Locked Node {}. Calling tick()...", id.id);
                    let events = node.tick();
                    println!("[TestHarness] Ticking: Node {} tick() returned {} events. Processing...", id.id, events.len());
                    for event in events {
                        match event {
                            RaftEvent::SendMessage(recipient, message) => {
                                println!("[TestHarness] Ticking: Node {} generated SendMessage to {}: {:?}", id.id, recipient.id, message);
                                current_tick_outgoing.push((id.clone(), recipient, message));
                            }
                            RaftEvent::BroadcastMessage(message) => {
                                println!("[TestHarness] Ticking: Node {} generated BroadcastMessage: {:?}", id.id, message);
                                for peer_id in node.peers.iter().cloned() {
                                    if &peer_id != id {
                                        current_tick_outgoing.push((id.clone(), peer_id, message.clone()));
                                    }
                                }
                            }
                            RaftEvent::ApplyToStateMachine(commands) => {
                                println!("[TestHarness] Ticking: Node {} generated ApplyToStateMachine ({} commands)", id.id, commands.len());
                                // Use id.id which is usize
                                println!("Node {}: Applying {} commands", id.id, commands.len());
                            }
                            RaftEvent::Noop => {}
                        }
                    }
                    println!("[TestHarness] Ticking: Unlocking Node {}...", id.id);
                     // Mutex automatically unlocked here
                } else {
                    println!("[TestHarness] Ticking: Node {} Arc not found in map!", id.id);
                }
            }

            println!("[TestHarness] Step 4: Collecting outgoing messages ({} new)", current_tick_outgoing.len());
            outgoing_messages.extend(current_tick_outgoing);

            println!("[TestHarness] Step 5: Checking for leader and potentially sleeping");
            let leader = find_leader(&nodes);
            if leader.is_some() {
                println!("[TestHarness] Leader found: {:?}. Waiting to stabilize...", leader.as_ref().unwrap().id);
                // Use tokio::time::sleep and qualify Duration
                sleep(tokio::time::Duration::from_millis(config.raft_election_timeout_max_ms / 2)).await;
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
                     outgoing_messages.clear(); // Clear messages if leader lost
                }
            }
            println!("[TestHarness] Sleeping for 50ms...");
            // Use tokio::time::sleep and qualify Duration
            sleep(tokio::time::Duration::from_millis(50)).await;
            println!("[TestHarness] End Loop Iteration {}", i);
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
                        println!("Warning: Potential multiple leaders detected in term {}", leader_term);
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

    // Mark test as async tokio test
    #[tokio::test]
    async fn test_log_replication_and_commit() {
        let nodes_data: Vec<(TEEIdentity, SecretKey)> = (1..=3).map(create_identity_with_key).collect();
        let node_ids: Vec<TEEIdentity> = nodes_data.iter().map(|(id, _)| id.clone()).collect();
        let mut nodes: HashMap<TEEIdentity, Arc<Mutex<RaftNode>>> = HashMap::new();
        let mut network: HashMap<TEEIdentity, VecDeque<(TEEIdentity, RaftMessage)>> = HashMap::new();
        let config = SystemConfig::default();
        let delay_config = Arc::new(TeeDelayConfig::default()); // Create default delay config
        let (metrics_tx, _metrics_rx) = mpsc::channel::<MetricEvent>(100); // Use bounded channel

        for (id, secret_key) in &nodes_data {
            let peers: Vec<TEEIdentity> = node_ids.iter().filter(|&p| p != id).cloned().collect();
            let storage = Box::new(InMemoryStorage::new());
             // No need for EnclaveSim instance here, it's created inside RaftNode::new
            let node = RaftNode::new(
                id.clone(),
                peers,
                config.clone(),
                storage,
                secret_key.clone(), // Pass the actual secret key
                0, // shard_id (using 0 for tests)
                delay_config.clone(), // Pass delay config
                Some(metrics_tx.clone()) // Pass metrics_tx
            );
            nodes.insert(id.clone(), Arc::new(Mutex::new(node)));
            network.insert(id.clone(), VecDeque::new());
        }

        println!("Running simulation until a leader is elected...");
        let mut leader_id_opt: Option<TEEIdentity> = None;
        let mut outgoing_messages: Vec<(TEEIdentity, TEEIdentity, RaftMessage)> = Vec::new();
        for tick in 0..30 { // Increased ticks for election stability
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
                                    if &peer_id != id {
                                        current_tick_outgoing.push((id.clone(), peer_id, message.clone()));
                                    }
                                }
                            }
                            RaftEvent::ApplyToStateMachine(commands) => {
                                println!("Node {}: Applied {} commands during election tick {}", id.id, commands.len(), tick);
                            }
                            RaftEvent::Noop => {}
                        }
                    }
                }
            }
            outgoing_messages.extend(current_tick_outgoing);
            leader_id_opt = find_leader(&nodes);
            if leader_id_opt.is_some() {
                println!("Leader found at tick {}: {:?}", tick, leader_id_opt.as_ref().unwrap().id);
                // Run a few more ticks to stabilize heartbeats
                for _ in 0..3 {
                     let mut stabilization_outgoing = Vec::new();
                     deliver_messages(&mut nodes, outgoing_messages.drain(..).collect(), &mut network);
                     for id in &node_ids {
                         stabilization_outgoing.extend(process_network_queue(id, &mut nodes, &mut network));
                     }
                      for id in &node_ids {
                         if let Some(node_arc) = nodes.get(id) {
                              let mut node = node_arc.lock().unwrap();
                              let events = node.tick();
                              // Process events just for message generation
                               for event in events {
                                     match event {
                                         RaftEvent::SendMessage(recipient, message) => {
                                             stabilization_outgoing.push((id.clone(), recipient, message));
                                         }
                                         RaftEvent::BroadcastMessage(message) => {
                                             for peer_id in node.peers.iter().cloned() {
                                                 if &peer_id != id {
                                                     stabilization_outgoing.push((id.clone(), peer_id, message.clone()));
                                                 }
                                             }
                                         }
                                          RaftEvent::ApplyToStateMachine(commands) => {
                                              println!("Node {}: Applied {} commands during stabilization", id.id, commands.len());
                                          }
                                         _ => {}
                                     }
                                 }
                         }
                     }
                     outgoing_messages.extend(stabilization_outgoing);
                     // Use tokio::time::sleep and qualify Duration
                     sleep(tokio::time::Duration::from_millis(config.raft_heartbeat_ms / 2)).await;
                }
                 // Final delivery before proposing
                 deliver_messages(&mut nodes, outgoing_messages.drain(..).collect(), &mut network);
                 for id in &node_ids {
                     process_network_queue(id, &mut nodes, &mut network);
                 }
                 leader_id_opt = find_leader(&nodes); // Re-confirm leader
                 if leader_id_opt.is_some() { break; } else { println!("Leader lost during stabilization, continuing..."); }
            }
            // Use tokio::time::sleep and qualify Duration
            sleep(tokio::time::Duration::from_millis(50)).await;
        }

        assert!(leader_id_opt.is_some(), "No stable leader elected.");
        let leader_id = leader_id_opt.unwrap();

        // Propose a command to the leader
        let proposed_log_index;
        let command_to_propose = Command::Dummy; // Use Dummy variant
        {
            let leader_node_arc = nodes.get(&leader_id).unwrap();
            let mut leader_node = leader_node_arc.lock().unwrap();
            let events = leader_node.propose_command(command_to_propose.clone()); 
            assert!(!events.is_empty(), "Leader should generate events when proposing command");
            proposed_log_index = leader_node.state.last_log_index();
            
            // Process events from propose_command to generate messages
            for event in events {
                match event {
                    RaftEvent::SendMessage(recipient, message) => {
                        outgoing_messages.push((leader_id.clone(), recipient, message));
                    }
                    RaftEvent::BroadcastMessage(message) => {
                        for peer_id in leader_node.peers.iter().cloned() {
                            if &peer_id != &leader_id {
                                outgoing_messages.push((leader_id.clone(), peer_id, message.clone()));
                            }
                        }
                    }
                    // ApplyToStateMachine shouldn't happen directly from propose, but handle defensively
                    RaftEvent::ApplyToStateMachine(commands) => {
                         println!("Unexpected ApplyToStateMachine event from propose_command on node {}", leader_id.id);
                    }
                    RaftEvent::Noop => {}
                }
            }
        } // Lock released here
        println!("Leader {} proposed command {:?} at index {}", leader_id.id, command_to_propose, proposed_log_index);

         println!("Running simulation for replication and commit...");
         // Run simulation enough times for replication, commit, and application
         for tick in 0..10 {
             let mut current_tick_outgoing = Vec::new();
             deliver_messages(&mut nodes, outgoing_messages.drain(..).collect(), &mut network);

             for id in &node_ids {
                 current_tick_outgoing.extend(process_network_queue(id, &mut nodes, &mut network));
             }

             for id in &node_ids {
                 if let Some(node_arc) = nodes.get(id) {
                     let mut node = node_arc.lock().unwrap();
                     let events = node.tick(); // Ticking handles applying committed entries
                     for event in events {
                         match event {
                             RaftEvent::SendMessage(recipient, message) => {
                                 current_tick_outgoing.push((id.clone(), recipient, message));
                             }
                             RaftEvent::BroadcastMessage(message) => {
                                 for peer_id in node.peers.iter().cloned() {
                                     if &peer_id != id {
                                         current_tick_outgoing.push((id.clone(), peer_id, message.clone()));
                                     }
                                 }
                             }
                             RaftEvent::ApplyToStateMachine(commands) => {
                                 println!("Node {}: Applied {} commands during replication tick {}", id.id, commands.len(), tick);
                                  // Check if the specific command we sent is being applied
                                  if node.state.last_applied >= proposed_log_index {
                                       let applied_entry = &node.state.log[proposed_log_index as usize - 1];
                                       assert_eq!(applied_entry.command, command_to_propose, "Applied command mismatch on Node {}", id.id);
                                  }
                             }
                             RaftEvent::Noop => {}
                         }
                     }
                 }
             }
             outgoing_messages.extend(current_tick_outgoing);
             // Use tokio::time::sleep and qualify Duration
             sleep(tokio::time::Duration::from_millis(config.raft_heartbeat_ms / 2)).await;

             // Check if commit index has advanced on the leader
             let leader_commit_index = nodes.get(&leader_id).unwrap().lock().unwrap().state.commit_index;
             if leader_commit_index >= proposed_log_index {
                  println!("Leader commit index {} reached proposed index {}. Checking followers.", leader_commit_index, proposed_log_index);
                  // Check if followers have also committed
                  let mut all_committed = true;
                  for id in &node_ids {
                      if nodes.get(id).unwrap().lock().unwrap().state.commit_index < proposed_log_index {
                           all_committed = false;
                           break;
                      }
                  }
                  if all_committed {
                       println!("All nodes have committed the entry at index {}. Stopping simulation early.", proposed_log_index);
                       break; // Exit loop once committed everywhere
                  }
             }
         }

         // Final state assertions
         let leader_node = nodes.get(&leader_id).unwrap().lock().unwrap();
         assert!(leader_node.state.commit_index >= proposed_log_index, "Leader commit index ({}) did not reach proposed index ({})", leader_node.state.commit_index, proposed_log_index);
         assert!(leader_node.state.last_applied >= proposed_log_index, "Leader last_applied ({}) did not reach proposed index ({})", leader_node.state.last_applied, proposed_log_index);
         assert_eq!(leader_node.state.log[proposed_log_index as usize - 1].command, command_to_propose, "Leader log entry mismatch");

         for id in &node_ids {
             if id == &leader_id { continue; } // Skip leader, already checked
             let follower_node = nodes.get(id).unwrap().lock().unwrap();
             assert_eq!(follower_node.state.role, RaftRole::Follower, "Node {} should be Follower", id.id);
             assert!(follower_node.state.log.len() >= proposed_log_index as usize, "Follower {} log too short ({})", id.id, follower_node.state.log.len());
             assert_eq!(follower_node.state.log[proposed_log_index as usize - 1].command, command_to_propose, "Follower {} log entry mismatch", id.id);
             assert!(follower_node.state.commit_index >= proposed_log_index, "Follower {} commit index ({}) did not reach proposed index ({})", id.id, follower_node.state.commit_index, proposed_log_index);
             assert!(follower_node.state.last_applied >= proposed_log_index, "Follower {} last_applied ({}) did not reach proposed index ({})", id.id, follower_node.state.last_applied, proposed_log_index);

             // Check leader's view of this follower
             let leader_next_index = leader_node.state.next_index.get(id).copied().unwrap_or(0);
             let leader_match_index = leader_node.state.match_index.get(id).copied().unwrap_or(0);
             assert!(leader_match_index >= proposed_log_index, "Leader match_index for follower {} ({}) is less than proposed index ({})", id.id, leader_match_index, proposed_log_index);
             assert!(leader_next_index == leader_match_index + 1, "Leader next_index for follower {} ({}) should be match_index + 1 ({})", id.id, leader_next_index, leader_match_index + 1);
         }
         println!("Log replication and commit test passed.");
    }

    // Mark test as async tokio test
    #[tokio::test]
    async fn test_propose_command_as_leader() {
        // Manual setup for a single node
        let config = SystemConfig::default();
        let (node_id, secret_key) = create_identity_with_key(1); // Use helper
        let peers = Vec::new(); // No peers for this simple test
        let storage = Box::new(InMemoryStorage::new());
         // No need for EnclaveSim instance here, it's created inside RaftNode::new
        let delay_config = Arc::new(TeeDelayConfig::default()); // Create default delay config
        let (metrics_tx, _metrics_rx) = mpsc::channel::<MetricEvent>(100); // Use bounded channel

        let mut node = RaftNode::new(
            node_id.clone(),
            peers,
            config,
            storage, // Remove clone, RaftNode takes ownership
            secret_key.clone(), // Pass the actual secret key
            0, // shard_id
            delay_config.clone(), // Pass delay config
            Some(metrics_tx) // Pass metrics_tx
        );

        node.state.role = RaftRole::Leader; // Force leader state
        let prev_log_index = node.state.last_log_index();
        let current_term = node.state.current_term;

        let command_to_propose = Command::Dummy; // Use Dummy variant
        let events = node.propose_command(command_to_propose.clone()); 

        // No async operations needed for the assertions themselves
        assert_eq!(events.len(), 0, "Leader with no peers should not generate network events on propose");

        let new_log_index = node.state.last_log_index();
        assert_eq!(new_log_index, prev_log_index + 1, "Log index should increment after propose");

        let last_entry = node.state.log.last().expect("Log should have an entry after propose");
        assert_eq!(last_entry.term, current_term, "New log entry should have the leader's current term");
        assert_eq!(last_entry.command, command_to_propose, "New log entry should contain the proposed command");

        let self_match_index = node.state.match_index.get(&node_id).copied().expect("Leader should have match_index for itself");
        assert_eq!(self_match_index, new_log_index, "Leader's self match_index should be updated");
    }
} 