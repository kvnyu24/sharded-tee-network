// Re-export relevant types for easier use
pub use crate::data_structures::{AccountId, AssetId};
pub use interface::{BlockchainInterface, BlockchainError, TransactionId, SwapId, SignatureBytes};

// On-Chain Interaction Simulation module

pub mod chain_simulator; // Placeholder for blockchain simulation
pub mod escrow_contract; // Placeholder for TEE-enabled escrow logic
pub mod interface; // Add this line
pub mod evm_relayer; // Add this line
