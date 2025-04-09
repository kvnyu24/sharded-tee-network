// teeshard-protocol/src/simulation/mod.rs

pub mod node;
pub mod runtime;

// Re-export key simulation components
pub use node::SimulatedTeeNode;
pub use runtime::SimulationRuntime; 