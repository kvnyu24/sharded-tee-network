// Placeholder for Raft persistent storage logic

use crate::{
    data_structures::TEEIdentity,
    // Correct: Command and LogEntry are defined in raft::state
    raft::state::LogEntry,
};
// Import key generation
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
// Add missing import
use std::time::Instant;
// ADD SystemTime and Duration
use std::time::{SystemTime, Duration};

/// Trait for Raft persistent storage.
/// Implementors must be Send + Sync to be used across threads.
pub trait RaftStorage: Send + Sync {
    // Removed load_state
    // fn load_state(&self) -> RaftNodeState;

    // Added methods to get persisted state components
    fn get_term(&self) -> u64;
    fn get_voted_for(&self) -> Option<TEEIdentity>;
    fn get_log_entry(&self, index: u64) -> Option<LogEntry>; // Get single entry (1-based index)
    fn get_log_len(&self) -> u64;
    fn get_last_log_index(&self) -> u64;
    fn get_last_log_term(&self) -> u64;
    fn get_log_entries_from(&self, start_index: u64) -> Vec<LogEntry>; // Get entries from index (1-based)

    // Save currentTerm
    fn save_term(&mut self, term: u64);

    // Save votedFor
    fn save_voted_for(&mut self, voted_for: Option<&TEEIdentity>);

    // Append entries to the log
    fn append_log_entries(&mut self, entries: &[LogEntry]);

    // Truncate the log starting from a given index (1-based)
    fn truncate_log(&mut self, from_index: u64);

    // Load term and vote
    fn load_term_and_vote(&self) -> (u64, Option<TEEIdentity>);

    // Load the entire log
    fn load_log(&self) -> Vec<LogEntry>;

    // Compact the log up to a certain index (snapshotting)
    // fn compact_log(&mut self, up_to_index: u64) -> Result<(), Error>;
}

// Example in-memory storage (for testing/simulation)
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)] // Clone needed if used in multiple places without Arc
pub struct InMemoryStorage {
    // Use Arc<Mutex<...>> for interior mutability safe across threads
    data: Arc<Mutex<InMemoryStorageData>>,
}

#[derive(Debug, Default)] // Default for easy initialization
struct InMemoryStorageData {
    current_term: u64,
    voted_for: Option<TEEIdentity>,
    log: Vec<LogEntry>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        InMemoryStorage {
            data: Arc::new(Mutex::new(InMemoryStorageData::default())),
        }
    }
}

impl RaftStorage for InMemoryStorage {
    // Removed load_state implementation

    fn get_term(&self) -> u64 {
        self.data.lock().unwrap().current_term
    }

    fn get_voted_for(&self) -> Option<TEEIdentity> {
        self.data.lock().unwrap().voted_for.clone()
    }

    fn get_log_entry(&self, index: u64) -> Option<LogEntry> {
        if index == 0 || (index as usize) > self.data.lock().unwrap().log.len() {
            None
        } else {
            self.data.lock().unwrap().log.get(index as usize - 1).cloned()
        }
    }

    fn get_log_len(&self) -> u64 {
        self.data.lock().unwrap().log.len() as u64
    }

     fn get_last_log_index(&self) -> u64 {
        self.data.lock().unwrap().log.len() as u64 // 1-based index
    }

    fn get_last_log_term(&self) -> u64 {
        self.data.lock().unwrap().log.last().map_or(0, |entry| entry.term)
    }

    fn get_log_entries_from(&self, start_index: u64) -> Vec<LogEntry> {
        if start_index == 0 || (start_index as usize) > self.data.lock().unwrap().log.len() {
            vec![]
        } else {
            self.data.lock().unwrap().log[(start_index as usize - 1)..].to_vec()
        }
    }

    fn save_term(&mut self, term: u64) {
        self.data.lock().unwrap().current_term = term;
        // In a real implementation, write to disk/DB
    }

    fn save_voted_for(&mut self, voted_for: Option<&TEEIdentity>) {
        self.data.lock().unwrap().voted_for = voted_for.cloned();
        // In a real implementation, write to disk/DB
    }

    fn append_log_entries(&mut self, entries: &[LogEntry]) {
        self.data.lock().unwrap().log.extend_from_slice(entries);
        // In a real implementation, write to disk/DB (fsync recommended)
    }

    fn truncate_log(&mut self, from_index: u64) {
        if from_index == 0 {
             self.data.lock().unwrap().log.clear();
        } else if (from_index as usize) <= self.data.lock().unwrap().log.len() {
            // from_index is 1-based, truncate needs 0-based length
             self.data.lock().unwrap().log.truncate(from_index as usize - 1);
        } else {
            // Index out of bounds, do nothing or log error?
            // Raft algorithm implies index might be beyond current log during conflicts,
            // truncate(len) is effectively a no-op which is fine.
            // If from_index is way too high, that's also fine? Let's assume yes.
            // println!("Warning: truncate_log called with index {} beyond log length {}", from_index, self.log.len());
        }
        // In a real implementation, update persistent storage
    }

    fn load_term_and_vote(&self) -> (u64, Option<TEEIdentity>) {
        // Lock the data ONCE to get both term and vote
        let data = self.data.lock().unwrap(); 
        (data.current_term, data.voted_for.clone())
    }

    fn load_log(&self) -> Vec<LogEntry> {
        self.data.lock().unwrap().log.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::state::Command;
    use crate::tee_logic::crypto_sim::generate_keypair;
    // ADD Duration import here too
    use std::time::{Duration, Instant, SystemTime};

     fn create_test_tee(id: usize) -> TEEIdentity {
        // Create TEEIdentity with usize ID and a real public key
        let keypair = generate_keypair();
        TEEIdentity { id, public_key: keypair.verifying_key() }
    }

    #[test]
    fn test_in_memory_storage() {
        let mut storage = InMemoryStorage::new();

        assert_eq!(storage.get_term(), 0);
        assert!(storage.get_voted_for().is_none());
        assert_eq!(storage.get_log_len(), 0);
        assert_eq!(storage.get_last_log_index(), 0);
        assert_eq!(storage.get_last_log_term(), 0);

        storage.save_term(5);
        assert_eq!(storage.get_term(), 5);

        let voter = create_test_tee(1);
        storage.save_voted_for(Some(&voter));
        assert_eq!(storage.get_voted_for(), Some(voter.clone()));
        storage.save_voted_for(None);
        assert!(storage.get_voted_for().is_none());

        // Calculate a duration for the test entries
        let duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::ZERO);

        let entries = vec![
            // Use the correct field name and provide the Duration
            LogEntry { term: 1, command: Command::Dummy, proposal_time_since_epoch: duration_since_epoch },
            LogEntry { term: 2, command: Command::Dummy, proposal_time_since_epoch: duration_since_epoch },
            LogEntry { term: 3, command: Command::Dummy, proposal_time_since_epoch: duration_since_epoch },
        ];
        storage.append_log_entries(&entries);
        assert_eq!(storage.get_log_len(), 3);
        assert_eq!(storage.get_last_log_index(), 3);
        assert_eq!(storage.get_last_log_term(), 3);
        assert_eq!(storage.get_log_entry(2).unwrap().term, 2);
        assert_eq!(storage.get_log_entries_from(2).len(), 2);
        assert_eq!(storage.get_log_entries_from(2)[0].term, 2);
        assert_eq!(storage.get_log_entries_from(4).len(), 0);


        storage.truncate_log(3); // Truncate starting at index 3 (removes entry 3)
        assert_eq!(storage.get_log_len(), 2);
        assert_eq!(storage.get_last_log_index(), 2);
        assert_eq!(storage.get_last_log_term(), 2);
        assert!(storage.get_log_entry(3).is_none());


        storage.truncate_log(1); // Truncate starting at index 1 (removes entry 1, 2)
         assert_eq!(storage.get_log_len(), 0);
         assert_eq!(storage.get_last_log_index(), 0);
         assert_eq!(storage.get_last_log_term(), 0);

         // Test appending again after truncation
         // Calculate a new duration for the new entry
         let new_duration_since_epoch = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
             .unwrap_or_else(|_| Duration::ZERO);
         let new_entries = vec![LogEntry { term: 4, command: Command::Dummy, proposal_time_since_epoch: new_duration_since_epoch }];
         storage.append_log_entries(&new_entries);
         assert_eq!(storage.get_log_len(), 1);
         assert_eq!(storage.get_last_log_index(), 1);
         assert_eq!(storage.get_last_log_term(), 4);
    }

    // Note: load_state test is tricky as it returns a default RaftNodeState
    // A proper test would involve integrating with RaftNode initialization.
    // This comment is now obsolete.
} 