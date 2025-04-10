// TEE Enclave Simulation logic

use crate::data_structures::{LockInfo, TEEIdentity};
use crate::tee_logic::types::{LockProofData, Signature, AttestationReport};
use crate::liveness::types::VerificationResult;
use crate::liveness::types::ChallengeNonce;
// Make crypto_sim methods async
use crate::tee_logic::crypto_sim::{self, SecretKey, generate_keypair, sign, verify, PublicKey};
use ed25519_dalek::{VerifyingKey, SigningKey, Verifier};
use crate::tee_logic::threshold_sig::PartialSignature;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, sleep};
use rand::Rng;

/// Configuration for simulating TEE operation delays.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TeeDelayConfig {
    pub sign_min_ms: u64,
    pub sign_max_ms: u64,
    pub verify_min_ms: u64,
    pub verify_max_ms: u64,
    pub attest_min_ms: u64,
    pub attest_max_ms: u64,
}

// Implement Default for TeeDelayConfig
impl Default for TeeDelayConfig {
    fn default() -> Self {
        TeeDelayConfig {
            sign_min_ms: 0,   // Default to no delay
            sign_max_ms: 0,
            verify_min_ms: 0, // Default to no delay
            verify_max_ms: 0,
            attest_min_ms: 0, // Default to no delay
            attest_max_ms: 0,
        }
    }
}

// Function to get a randomized delay based on config
async fn get_delay(min_ms: u64, max_ms: u64) -> Duration {
    if max_ms == 0 { return Duration::from_millis(0); }
    let delay_ms = if min_ms >= max_ms {
        min_ms
    } else {
        rand::thread_rng().gen_range(min_ms..=max_ms)
    };
    Duration::from_millis(delay_ms)
}

// Simulate a TEE enclave environment
#[derive(Debug, Clone)]
pub struct EnclaveSim {
    pub identity: TEEIdentity,
    secret_key: SecretKey,
    // Store delay config
    delay_config: Arc<TeeDelayConfig>,
}

impl EnclaveSim {
    /// Creates a new simulated enclave with a specific ID and optional key.
    /// If key is None, generates a new one.
    pub fn new(id: usize, key: Option<SecretKey>, delay_config: Arc<TeeDelayConfig>) -> Self {
        let (secret_key, public_key) = match key {
            Some(sk) => (sk.clone(), sk.verifying_key()),
            None => {
                let kp = generate_keypair();
                // Clone kp before moving it into the tuple, kp.verifying_key() borrows kp
                (kp.clone(), kp.verifying_key())
            }
        };
        EnclaveSim {
            identity: TEEIdentity { id, public_key },
            secret_key,
            delay_config, // Store the config
        }
    }

    /// Creates a new simulated enclave, always generating a new key.
    pub fn new_with_generated_key(id: usize, delay_config: Arc<TeeDelayConfig>) -> Self {
        Self::new(id, None, delay_config) // Call the primary constructor
    }

    /// Simulates the TEE signing operation with delay.
    pub async fn sign(&self, message: &[u8]) -> Signature {
        let delay = get_delay(self.delay_config.sign_min_ms, self.delay_config.sign_max_ms).await;
        if delay > Duration::ZERO { sleep(delay).await; }
        // Use the internal crypto_sim::sign which now expects delays itself
        sign(message, &self.secret_key, self.delay_config.sign_min_ms, self.delay_config.sign_max_ms).await
    }

    /// Simulates the TEE generating an attestation report with delay.
    pub async fn generate_attestation(&self, nonce: ChallengeNonce) -> AttestationReport {
        let delay = get_delay(self.delay_config.attest_min_ms, self.delay_config.attest_max_ms).await;
        if delay > Duration::ZERO { sleep(delay).await; }

        // ChallengeNonce is Vec<u8>, treat it as such for signing
        let signed_data: &[u8] = &nonce.nonce; // Access the inner Vec<u8>
        let signature = self.sign(signed_data).await;

        AttestationReport {
            // AttestationReport expects Vec<u8>, clone the inner Vec<u8> from nonce
            report_data: nonce.nonce.to_vec(), // Convert [u8; 32] to Vec<u8>
            signature,
        }
    }

    /// Generates a partial signature share for the given message.
    // Make async and add delay
    pub async fn generate_partial_signature(&self, message: &[u8]) -> PartialSignature {
         println!("EnclaveSim ({}): Generating partial signature for msg {:?}", self.identity.id, message);
         // Use await and pass sign delays
         let signature_data = crypto_sim::sign(
            message,
            &self.secret_key, // Pass a reference to the key
            self.delay_config.sign_min_ms, // Use sign delays
            self.delay_config.sign_max_ms
         ).await;

         PartialSignature {
             signer_id: self.identity.clone(),
             signature_data,
         }
    }

    /// Returns the public key of the simulated enclave.
    pub fn get_public_key(&self) -> Option<PublicKey> {
        Some(self.secret_key.verifying_key())
    }

    // Make async and add delay
    async fn verify_signature(&self, message: &[u8], public_key: &PublicKey, signature: &Signature) -> VerificationResult {
        // Use await and pass verify delays
        let is_ok = crypto_sim::verify(
            message,
            signature,
            public_key,
            self.delay_config.verify_min_ms, // Use verify delays
            self.delay_config.verify_max_ms
        ).await;

        if is_ok {
            VerificationResult::Valid
        } else {
            VerificationResult::InvalidSignature
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee_logic::crypto_sim; // Import module directly
    use ed25519_dalek::{Verifier};
    use tokio::runtime::Runtime; // Add tokio runtime for async tests
    use crate::liveness::types::ChallengeNonce; // Ensure ChallengeNonce is imported
    use std::time::Instant; // For timing tests

    // Helper function to run async tests
    fn run_async<F>(future: F) -> F::Output
    where
        F: std::future::Future,
    {
        Runtime::new().unwrap().block_on(future)
    }

    // Helper to create EnclaveSim for testing
    fn create_test_enclave(id: usize) -> EnclaveSim {
        let signing_key = crypto_sim::generate_keypair();
        // Pass default delay config for tests
        EnclaveSim::new(id, Some(signing_key), Arc::new(TeeDelayConfig::default()))
    }

    #[test]
    fn enclave_sim_creation_with_key() {
        // Remains synchronous
        let sim = create_test_enclave(5);
        assert_eq!(sim.identity.id, 5);
        assert_eq!(sim.identity.public_key, sim.secret_key.verifying_key());
    }

    #[test]
    fn enclave_sim_attestation_async() {
        run_async(async {
            let sim = create_test_enclave(2);
            // Initialize ChallengeNonce correctly
            let nonce_bytes: Vec<u8> = vec![1; 32]; // Ensure it's 32 bytes for try_into
            let nonce = ChallengeNonce {
                // Convert Vec<u8> to [u8; 32] using try_into
                nonce: nonce_bytes.clone().try_into().expect("Test nonce bytes should be 32 bytes"),
                timestamp: 0, // Assuming timestamp 0 for test
                target_node_id: sim.identity.id, // Add the missing field
            };
            let report = sim.generate_attestation(nonce.clone()).await;

            // Compare the report_data (Vec<u8>) with the original nonce bytes
            assert_eq!(report.report_data, nonce_bytes, "Report data should match the original nonce bytes");

            // Use the async verify function
            let is_valid = crypto_sim::verify(
                &report.report_data,
                &report.signature,
                &sim.identity.public_key,
                0, 0 // No delay for test verification
            ).await;
            assert!(is_valid, "Attestation signature should be valid");
        });
    }

     #[test]
    fn enclave_sim_generate_partial_sig_async() {
        run_async(async {
            let sim = create_test_enclave(3);
            let msg = b"message for partial sig async";

            let partial_sig = sim.generate_partial_signature(msg).await;

            assert_eq!(partial_sig.signer_id, sim.identity);

            // Verify the signature using the async verify function
            let is_valid = crypto_sim::verify(
                msg,
                &partial_sig.signature_data,
                &sim.identity.public_key,
                0, 0 // No delay
            ).await;
            assert!(is_valid);
        });
    }

    #[test]
    fn enclave_sim_partial_sig_verify_fail_wrong_key_async() {
        run_async(async {
            let sim1 = create_test_enclave(10);
            let sim2 = create_test_enclave(11); // Different enclave with different key
            let msg = b"another async message";

            let partial_sig = sim1.generate_partial_signature(msg).await;

            // Try to verify with sim2's public key (should fail)
            let is_valid = crypto_sim::verify(
                msg,
                &partial_sig.signature_data,
                &sim2.identity.public_key,
                0, 0 // No delay
            ).await;
            assert!(!is_valid);
        });
    }

    #[test]
    fn test_enclave_sim_creation_and_signing_async() {
        run_async(async {
            // Test creating enclave without a key remains sync
            let signing_key_for_test = generate_keypair();
            let public_key_for_test = signing_key_for_test.verifying_key();
            let enclave_gen_key = EnclaveSim::new(2, Some(signing_key_for_test.clone()), Arc::new(TeeDelayConfig::default()));
            assert_eq!(enclave_gen_key.identity.id, 2);
            assert!(enclave_gen_key.get_public_key().is_some());

            let message = b"test message async";
            // Pass message directly, not &message
            let signature1 = enclave_gen_key.sign(message).await;
            let public_key1 = enclave_gen_key.get_public_key().unwrap();

            let is_valid = crypto_sim::verify(
                message,
                &signature1,
                &public_key1,
                0, 0 // No delay
            ).await;
            assert!(is_valid);
        });
    }

    // Original synchronous verify helper (no longer needed if using crypto_sim::verify)
    // fn verify(msg: &[u8], sig: &Signature, pk: &VerifyingKey) -> bool {
    //     pk.verify(msg, sig).is_ok()
    // }

    // ... rest of tests ...
} 