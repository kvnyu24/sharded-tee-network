// teeshard-protocol/src/simulation/mod.rs

pub mod node;
pub mod runtime;
pub mod coordinator;
pub mod mocks;

// Re-export key simulation components
pub use node::SimulatedTeeNode;
pub use runtime::SimulationRuntime;
pub use coordinator::CoordinatorCommand; 