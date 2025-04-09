// Define types related to Cross-Chain Swap Execution (Algorithm 2)

use crate::data_structures::LockInfo;
// Import the actual Signature type
use crate::tee_logic::types::Signature;
// Import TEEIdentity
use crate::data_structures::TEEIdentity;
// Import PublicKey for SignedCoordinatorDecision
use crate::tee_logic::crypto_sim::PublicKey;
use serde::{Serialize, Deserialize};

// Represents a proof from a shard that a resource has been locked
#[derive(Clone, Debug, PartialEq, Eq)] // Signature derives these
pub struct LockProof {
    pub tx_id: String,       // The global transaction ID
    pub shard_id: usize,     // ID of the shard providing the proof
    pub lock_info: LockInfo, // Details of the lock (account, asset, amount)
    // Need to include the identity of the TEE that signed this proof
    pub signer_identity: TEEIdentity,
    // Signature or attestation from the shard's TEE consensus group
    // proving the lock is valid according to their replicated state.
    pub attestation_or_sig: Signature, // Use the real signature type
}

// Request sent from Coordinator to Shard TEEs to lock resources
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockRequest {
    pub tx_id: String,
    pub lock_info: LockInfo,
    // Potentially add coordinator identity or other metadata
}

// Reasons why a cross-chain swap might be aborted
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbortReason {
    VerificationFailed,
    Timeout,
    LockProofVerificationFailed,
    TimeoutWaitingForLocks,
    LocalValidationError(String), // Validation failed within a shard
    CoordinatorFailure,
    Other(String),
}

// Final outcome of a cross-chain swap attempt
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwapOutcome {
    GlobalCommitSuccess,        // All shards locked and released
    GlobalAbortComplete(AbortReason), // All shards successfully reverted locks
    ImmediateAbort,             // Aborted early due to validation failure
    InconsistentState(String),  // Should not happen in correct implementation
}

// Represents the final, signed instruction from the coordinator(s)
#[derive(Debug, Clone, PartialEq)]
pub struct SignedCoordinatorDecision {
    pub tx_id: String,
    pub commit: bool, // true for Release, false for Abort
    // Placeholder for Threshold Signature:
    // The final implementation should replace this Vec with a structure representing
    // a single, combined threshold signature verifiable against the coordinator group's
    // public key. This might include the signature bytes and potentially metadata
    // like the threshold level (k) or the set of participating signers.
    // TODO: Implement a real threshold signature scheme and update this type.
    pub signature: Vec<(PublicKey, Signature)>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_structures::{AccountId, AssetId, LockInfo, TEEIdentity};
    use ed25519_dalek::Signer;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    // Import key generation for dummy TEE
    use crate::tee_logic::crypto_sim::generate_keypair;
    // Import the actual Signature type for tests
    use crate::tee_logic::types::Signature;

    fn create_test_lock_info() -> LockInfo {
        LockInfo {
            account: AccountId { chain_id: 1, address: "acc1".to_string() },
            asset: AssetId { chain_id: 1, token_symbol: "TOK".to_string() },
            amount: 100,
        }
    }

     // Helper to create a dummy signature for tests
     fn create_dummy_sig(data: &[u8]) -> Signature {
        let key = SigningKey::generate(&mut OsRng);
        key.sign(data)
    }

    #[test]
    fn lock_proof_creation() {
        let lock_info = create_test_lock_info();
        // Create a dummy signature for the test
        let dummy_sig = create_dummy_sig(b"test_data_for_sig");
        // Create a dummy TEE identity for the signer field
        let dummy_keypair = generate_keypair();
        let dummy_tee = TEEIdentity {
            id: 99, // Dummy ID
            public_key: dummy_keypair.verifying_key(),
        };

        let proof = LockProof {
            tx_id: "swap001".to_string(),
            shard_id: 2,
            lock_info: lock_info.clone(),
            signer_identity: dummy_tee.clone(), // Add the signer identity
            attestation_or_sig: dummy_sig,
        };

        assert_eq!(proof.tx_id, "swap001");
        assert_eq!(proof.shard_id, 2);
        assert_eq!(proof.lock_info, lock_info);
        assert_eq!(proof.attestation_or_sig.to_bytes().len(), 64);
    }

    #[test]
    fn abort_reason_enum() {
        let reason1 = AbortReason::TimeoutWaitingForLocks;
        let reason2 = AbortReason::LocalValidationError("Insufficient funds".to_string());
        assert_eq!(reason1, AbortReason::TimeoutWaitingForLocks);
        assert_ne!(reason1, reason2);
        if let AbortReason::LocalValidationError(msg) = reason2 {
            assert_eq!(msg, "Insufficient funds");
        } else {
            panic!("Incorrect AbortReason variant");
        }
    }

    #[test]
    fn swap_outcome_enum() {
        let outcome_commit = SwapOutcome::GlobalCommitSuccess;
        let outcome_abort = SwapOutcome::GlobalAbortComplete(AbortReason::TimeoutWaitingForLocks);
        assert_eq!(outcome_commit, SwapOutcome::GlobalCommitSuccess);
        assert_ne!(outcome_commit, outcome_abort);
        if let SwapOutcome::GlobalAbortComplete(reason) = outcome_abort {
            assert_eq!(reason, AbortReason::TimeoutWaitingForLocks);
        } else {
            panic!("Incorrect SwapOutcome variant");
        }
    }

    pub fn dummy_lock_info() -> LockInfo {
        LockInfo {
            account: AccountId { chain_id: 1, address: "dummy_acc".to_string() },
            asset: AssetId {
                chain_id: 1,
                token_symbol: "TOK".to_string(),
                token_address: "0x0000000000000000000000000000000000000001".to_string(),
            },
            amount: 100,
        }
    }
} 