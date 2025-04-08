// Define types related to Cross-Chain Swap Execution (Algorithm 2)

use crate::data_structures::LockInfo;

// Represents a proof from a shard that a resource has been locked
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockProof {
    pub tx_id: String,       // The global transaction ID
    pub shard_id: usize,     // ID of the shard providing the proof
    pub lock_info: LockInfo, // Details of the lock (account, asset, amount)
    // Signature or attestation from the shard's TEE consensus group
    // proving the lock is valid according to their replicated state.
    pub attestation_or_sig: Vec<u8>, // Placeholder - could be a Signature struct or complex attestation
}

// Reasons why a cross-chain swap might be aborted
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbortReason {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_structures::{AccountId, AssetId};

    fn create_test_lock_info() -> LockInfo {
        LockInfo {
            account: AccountId { chain_id: 1, address: "acc1".to_string() },
            asset: AssetId { chain_id: 1, token_symbol: "TOK".to_string() },
            amount: 100,
        }
    }

    #[test]
    fn lock_proof_creation() {
        let lock_info = create_test_lock_info();
        let proof = LockProof {
            tx_id: "swap001".to_string(),
            shard_id: 2,
            lock_info: lock_info.clone(),
            attestation_or_sig: vec![2, 100], // Dummy data
        };

        assert_eq!(proof.tx_id, "swap001");
        assert_eq!(proof.shard_id, 2);
        assert_eq!(proof.lock_info, lock_info);
        assert_eq!(proof.attestation_or_sig, vec![2, 100]);
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
} 