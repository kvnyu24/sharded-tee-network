use async_trait::async_trait;
use std::error::Error;

// Define a generic error type for blockchain operations
pub type BlockchainError = Box<dyn Error + Send + Sync>;

// Define a type for transaction identifiers (e.g., hash)
// Using String for now, could be a specific hash type like H256
pub type TransactionId = String;

// Define a type for swap identifiers
pub type SwapId = [u8; 32]; // Assuming 32-byte swap ID

// Define a type for signatures (assuming Vec<u8> for packed signatures)
pub type SignatureBytes = Vec<u8>;


/// Trait defining the necessary interactions with an underlying blockchain.
/// This allows mocking or interfacing with real chains/simulators.
#[async_trait]
pub trait BlockchainInterface: Send + Sync {
    /// Submits a transaction to release funds from escrow on the target chain.
    async fn submit_release(
        &self,
        chain_id: u64,
        swap_id: SwapId,
        token_address: String, // Assuming address as String for simplicity
        amount: u64,
        recipient_address: String,
        tee_signatures: SignatureBytes,
    ) -> Result<TransactionId, BlockchainError>;

    /// Submits a transaction to abort a swap and return funds on the source chain.
    async fn submit_abort(
        &self,
        chain_id: u64,
        swap_id: SwapId,
        token_address: String,
        amount: u64,
        sender_address: String, // Original sender who locked funds
        tee_signatures: SignatureBytes,
    ) -> Result<TransactionId, BlockchainError>;

    /// Retrieves the balance of a specific asset for a given account on a chain.
    async fn get_balance(
        &self,
        chain_id: u64,
        account_address: String,
        token_address: String,
    ) -> Result<u64, BlockchainError>;

    // TODO: Potentially add methods for:
    // - get_lock_proof(chain_id, original_tx_id) -> Result<LockProof, Error>
    // - get_contract_address(chain_id, contract_type) -> Result<String, Error>
    // - wait_for_finality(chain_id, tx_id) -> Result<(), Error>
} 