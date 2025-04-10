// Placeholder for Lock Proof generation and verification logic (Algorithm 2)

use crate::data_structures::{LockInfo, TEEIdentity};
use crate::cross_chain::types::LockProof; // Assuming LockProof is defined here
// Import crypto sim components and TeeDelayConfig from enclave_sim
use crate::tee_logic::crypto_sim::{sign, verify}; // Keep sign/verify
use crate::tee_logic::enclave_sim::TeeDelayConfig; // Correct path for TeeDelayConfig
use crate::tee_logic::crypto_sim::{SecretKey, PublicKey}; // Need SecretKey/PublicKey for types
use crate::tee_logic::types::{LockProofData, Signature};
use tokio::time::{Duration, sleep}; // Import sleep/Duration
use rand::Rng; // Import Rng

// Helper to serialize lock proof data for signing/verification
fn serialize_lock_data(tx_id: &str, shard_id: usize, lock_info: &LockInfo) -> Vec<u8> {
    // Define a canonical serialization order
    let mut data = Vec::new();
    data.extend_from_slice(tx_id.as_bytes());
    data.extend_from_slice(&shard_id.to_le_bytes());
    data.extend_from_slice(lock_info.account.address.as_bytes()); // Assuming address is string
    data.extend_from_slice(lock_info.asset.token_symbol.as_bytes()); // Assuming symbol is string
    data.extend_from_slice(&lock_info.amount.to_le_bytes());
    // Add other relevant fields from LockInfo if needed, e.g.,
    // data.extend_from_slice(&lock_info.account.chain_id.to_le_bytes());
    data
}

/// Generates a lock proof signed by a TEE node.
/// Includes simulated TEE signing delay.
pub async fn generate_lock_proof(
    tx_id: &str,
    shard_id: usize,
    lock_info: &LockInfo,
    signer_identity: &TEEIdentity,
    signing_key: &SecretKey,
    // Delay parameters
    min_delay_ms: u64,
    max_delay_ms: u64,
) -> LockProof {
    let serialized_data = serialize_lock_data(tx_id, shard_id, lock_info);

    // Use the async sign function from crypto_sim, passing delays
    let signature = sign(
        &serialized_data,
        signing_key,
        min_delay_ms,
        max_delay_ms
    ).await;

    LockProof {
        tx_id: tx_id.to_string(),
        shard_id,
        lock_info: lock_info.clone(), // Clone the lock info
        signer_identity: signer_identity.clone(), // Clone the identity
        attestation_or_sig: signature,
    }
}

/// Verifies a lock proof using the signer's public key.
/// Includes simulated TEE verification delay.
pub async fn verify_lock_proof(
    proof: &LockProof,
    public_key: &PublicKey,
    // Delay parameters
    min_delay_ms: u64,
    max_delay_ms: u64,
) -> bool {
    let serialized_data = serialize_lock_data(&proof.tx_id, proof.shard_id, &proof.lock_info);

    // Use the async verify function from crypto_sim, passing delays
    verify(
        &serialized_data,
        &proof.attestation_or_sig,
        public_key,
        min_delay_ms,
        max_delay_ms
    ).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_structures::{AccountId, AssetId};
    use crate::tee_logic::crypto_sim::generate_keypair;
    use tokio::runtime::Runtime;
    use tokio::time::Instant;

    // Helper to run async tests
    fn run_async<F>(future: F) -> F::Output
    where
        F: std::future::Future,
    {
        Runtime::new().unwrap().block_on(future)
    }

    // Helper to create test data
    fn create_test_data() -> (TEEIdentity, SecretKey, LockInfo) {
        let secret_key = generate_keypair();
        let public_key = secret_key.verifying_key();
        let identity = TEEIdentity { id: 1, public_key };
        let lock_info = LockInfo {
            account: AccountId { chain_id: 0, address: "addr1".to_string() },
            asset: AssetId { chain_id: 0, token_symbol: "TKA".to_string(), token_address: "0xA".to_string() },
            amount: 100,
        };
        (identity, secret_key, lock_info)
    }

    #[test]
    fn generate_and_verify_lock_proof_ok_async() {
        run_async(async {
            let (identity, secret_key, lock_info) = create_test_data();
            let tx_id = "test_tx_1";
            let shard_id = 0;

            // Generate with no delay
            let proof = generate_lock_proof(
                tx_id, shard_id, &lock_info, &identity, &secret_key, 0, 0
            ).await;

            assert_eq!(proof.tx_id, tx_id);
            assert_eq!(proof.shard_id, shard_id);
            assert_eq!(proof.lock_info, lock_info);
            assert_eq!(proof.signer_identity, identity);

            // Verify with no delay
            let is_valid = verify_lock_proof(&proof, &identity.public_key, 0, 0).await;
            assert!(is_valid, "Lock proof verification failed");
        });
    }

    #[test]
    fn verify_lock_proof_fail_wrong_key_async() {
        run_async(async {
            let (identity1, secret_key1, lock_info) = create_test_data();
            let (identity2, _secret_key2, _) = create_test_data(); // Generate a second key/identity
            let tx_id = "test_tx_2";
            let shard_id = 1;

            let proof = generate_lock_proof(
                tx_id, shard_id, &lock_info, &identity1, &secret_key1, 0, 0
            ).await;

            // Verify with the wrong public key
            let is_valid = verify_lock_proof(&proof, &identity2.public_key, 0, 0).await;
            assert!(!is_valid, "Lock proof verification should fail with wrong key");
        });
    }

    #[test]
    fn verify_lock_proof_fail_tampered_data_async() {
        run_async(async {
            let (identity, secret_key, lock_info) = create_test_data();
            let tx_id = "test_tx_3";
            let shard_id = 2;

            let mut proof = generate_lock_proof(
                tx_id, shard_id, &lock_info, &identity, &secret_key, 0, 0
            ).await;

            // Tamper the proof data
            proof.lock_info.amount = 999;

            // Verify the tampered proof
            let is_valid = verify_lock_proof(&proof, &identity.public_key, 0, 0).await;
            assert!(!is_valid, "Lock proof verification should fail with tampered data");
        });
    }

    #[test]
    fn generate_lock_proof_adds_delay_async() {
        run_async(async {
            let (identity, secret_key, lock_info) = create_test_data();
            let tx_id = "delay_gen_tx";
            let shard_id = 3;
            let min_delay = 70;
            let max_delay = 75;

            let start = Instant::now();
            let _proof = generate_lock_proof(
                tx_id, shard_id, &lock_info, &identity, &secret_key, min_delay, max_delay
            ).await;
            let duration = start.elapsed();

            assert!(duration >= Duration::from_millis(min_delay), "Generate proof took less than minimum delay. Took: {:?}", duration);
        });
    }

    #[test]
    fn verify_lock_proof_adds_delay_async() {
        run_async(async {
            let (identity, secret_key, lock_info) = create_test_data();
            let tx_id = "delay_verify_tx";
            let shard_id = 4;
            let min_delay = 80;
            let max_delay = 85;

            // Generate proof without delay
            let proof = generate_lock_proof(
                tx_id, shard_id, &lock_info, &identity, &secret_key, 0, 0
            ).await;

            let start = Instant::now();
            let _is_valid = verify_lock_proof(&proof, &identity.public_key, min_delay, max_delay).await;
            let duration = start.elapsed();

            assert!(duration >= Duration::from_millis(min_delay), "Verify proof took less than minimum delay. Took: {:?}", duration);
        });
    }
}