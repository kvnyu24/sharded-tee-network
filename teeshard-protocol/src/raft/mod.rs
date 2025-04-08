// Raft module entry point

pub mod state;
pub mod messages;
pub mod node; // Placeholder for the main RaftNode logic 
pub mod storage; // Declare storage module

// Re-export key components
pub use node::RaftNode;
pub use state::{RaftRole, LogEntry, Command};
pub use messages::RaftMessage; 