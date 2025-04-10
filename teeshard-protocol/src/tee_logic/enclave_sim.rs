// TEE Enclave Simulation logic

use crate::data_structures::TEEIdentity;
use crate::tee_logic::types::{Signature, AttestationReport};
use crate::liveness::types::VerificationResult;
use crate::liveness::types::ChallengeNonce;
// Make crypto_sim methods async
use crate::tee_logic::crypto_sim::{self, SecretKey, generate_keypair, sign, PublicKey};
use crate::tee_logic::threshold_sig::PartialSignature;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use rand::Rng;
use crate::simulation::metrics::MetricEvent;
use tokio::sync::mpsc;
use std::time::Instant;

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
    metrics_tx: Option<mpsc::Sender<MetricEvent>>, // Added metrics sender
}

impl EnclaveSim {
    /// Creates a new simulated enclave with a specific TEEIdentity and associated SecretKey.
    /// Asserts that the public key in the identity matches the provided secret key.
    pub fn new(
        identity: TEEIdentity, // Take full identity
        key: SecretKey,        // Take secret key directly
        delay_config: Arc<TeeDelayConfig>,
        metrics_tx: Option<mpsc::Sender<MetricEvent>>,
    ) -> Self {
        // Assert that the provided identity's public key matches the secret key
        assert_eq!(
            identity.public_key,
            key.verifying_key(),
            "Public key in TEEIdentity does not match the provided SecretKey!"
        );

        EnclaveSim {
            identity, // Store the provided identity
            secret_key: key, // Store the provided secret key
            delay_config,
            metrics_tx,
        }
    }

    /// Simulates the TEE signing operation with delay.
    pub async fn sign(&self, message: &[u8]) -> Signature {
        let start_time = Instant::now();
        let function_name = "sign".to_string();
        
        let delay = get_delay(self.delay_config.sign_min_ms, self.delay_config.sign_max_ms).await;
        if delay > Duration::ZERO { sleep(delay).await; }
        
        // Call the actual signing logic
        let result = sign(
            message,
            &self.secret_key,
            self.delay_config.sign_min_ms,
            self.delay_config.sign_max_ms,
            &self.metrics_tx,
            &Some(self.identity.clone()),
        ).await;
        
        let duration = start_time.elapsed();
        self.send_tee_metric(function_name, duration).await;
        
        result // Return the actual result
    }

    /// Simulates the TEE generating an attestation report with delay.
    pub async fn generate_attestation(&self, nonce: ChallengeNonce) -> AttestationReport {
        let start_time = Instant::now();
        let function_name = "generate_attestation".to_string();
        
        let delay = get_delay(self.delay_config.attest_min_ms, self.delay_config.attest_max_ms).await;
        if delay > Duration::ZERO { sleep(delay).await; }

        // ChallengeNonce is Vec<u8>, treat it as such for signing
        let signed_data: &[u8] = &nonce.nonce; // Access the inner Vec<u8>
        let signature = self.sign(signed_data).await;
        
        let duration = start_time.elapsed();
        // Note: This duration includes the time spent in self.sign(), which also sends a metric.
        // Depending on analysis needs, might want to subtract sign duration or only measure outer delay.
        self.send_tee_metric(function_name, duration).await;

        AttestationReport {
            // AttestationReport expects Vec<u8>, clone the inner Vec<u8> from nonce
            report_data: nonce.nonce.to_vec(), // Convert [u8; 32] to Vec<u8>
            signature,
        }
    }

    /// Generates a partial signature share for the given message.
    pub async fn generate_partial_signature(&self, message: &[u8]) -> PartialSignature {
         println!("EnclaveSim ({}): Generating partial signature for msg {:?}", self.identity.id, message);
         let start_time = Instant::now();
         let function_name = "generate_partial_signature".to_string();
         
         // Use await and pass sign delays
         let signature_data = crypto_sim::sign(
            message,
            &self.secret_key, // Pass a reference to the key
            self.delay_config.sign_min_ms, // Use sign delays
            self.delay_config.sign_max_ms,
            &self.metrics_tx,
            &Some(self.identity.clone()),
         ).await;

         let duration = start_time.elapsed();
         self.send_tee_metric(function_name, duration).await;

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
            self.delay_config.verify_max_ms,
            &self.metrics_tx,
            &Some(self.identity.clone()),
        ).await;

        if is_ok {
            VerificationResult::Valid
        } else {
            VerificationResult::InvalidSignature
        }
    }

    /// Helper to send TeeFunctionMeasured metric.
    async fn send_tee_metric(&self, function_name: String, duration: Duration) {
        if let Some(metrics_tx) = self.metrics_tx.clone() {
            let event = MetricEvent::TeeFunctionMeasured {
                node_id: self.identity.clone(),
                function_name,
                duration,
            };
            // Spawn task to send asynchronously
            tokio::spawn(async move {
                if let Err(e) = metrics_tx.send(event).await {
                    // Avoid logging in enclave sim itself, maybe log in collector or runtime?
                    // eprintln!("[EnclaveSim {}] Failed to send TEE metric: {}", self.identity.id, e);
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee_logic::crypto_sim; // Import module directly
    
    use tokio::runtime::Runtime; // Add tokio runtime for async tests
    use crate::liveness::types::ChallengeNonce; // Ensure ChallengeNonce is imported
     // For timing tests

    // Helper function to run async tests
    fn run_async<F>(future: F) -> F::Output
    where
        F: std::future::Future,
    {
        Runtime::new().unwrap().block_on(future)
    }

    // Helper to create EnclaveSim for testing (updated)
    fn create_test_enclave(id: usize) -> EnclaveSim {
        let signing_key = crypto_sim::generate_keypair();
        let identity = TEEIdentity { id, public_key: signing_key.verifying_key() };
        // Pass identity and key directly
        EnclaveSim::new(identity, signing_key, Arc::new(TeeDelayConfig::default()), None)
    }

    #[test]
    fn enclave_sim_creation_with_key() {
        let signing_key = crypto_sim::generate_keypair();
        let identity = TEEIdentity { id: 5, public_key: signing_key.verifying_key() };
        let sim = EnclaveSim::new(identity.clone(), signing_key, Arc::new(TeeDelayConfig::default()), None);
        assert_eq!(sim.identity.id, 5);
        assert_eq!(sim.identity.public_key, sim.secret_key.verifying_key());
    }

    #[test]
    fn enclave_sim_attestation_async() {
        run_async(async {
            let sim = create_test_enclave(2); // Uses updated helper
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
                0, 0, // No delay for test verification
                &sim.metrics_tx,
                &Some(sim.identity.clone()),
            ).await;
            assert!(is_valid, "Attestation signature should be valid");
        });
    }

     #[test]
    fn enclave_sim_generate_partial_sig_async() {
        run_async(async {
            let sim = create_test_enclave(3); // Uses updated helper
            let msg = b"message for partial sig async";

            let partial_sig = sim.generate_partial_signature(msg).await;

            assert_eq!(partial_sig.signer_id, sim.identity);

            // Verify the signature using the async verify function
            let is_valid = crypto_sim::verify(
                msg,
                &partial_sig.signature_data,
                &sim.identity.public_key,
                0, 0, // No delay
                &sim.metrics_tx,
                &Some(sim.identity.clone()),
            ).await;
            assert!(is_valid);
        });
    }

    #[test]
    fn enclave_sim_partial_sig_verify_fail_wrong_key_async() {
        run_async(async {
            let sim1 = create_test_enclave(10); // Uses updated helper
            let sim2 = create_test_enclave(11); // Uses updated helper
            let msg = b"another async message";

            let partial_sig = sim1.generate_partial_signature(msg).await;

            // Try to verify with sim2's public key (should fail)
            let is_valid = crypto_sim::verify(
                msg,
                &partial_sig.signature_data,
                &sim2.identity.public_key,
                0, 0, // No delay
                &sim2.metrics_tx,
                &Some(sim2.identity.clone()),
            ).await;
            assert!(!is_valid);
        });
    }

    #[test]
    fn test_enclave_sim_creation_and_signing_async() {
        run_async(async {
            let signing_key_for_test = generate_keypair();
            let identity_for_test = TEEIdentity { id: 2, public_key: signing_key_for_test.verifying_key() };
            let enclave_gen_key = EnclaveSim::new(
                identity_for_test.clone(), 
                signing_key_for_test.clone(), 
                Arc::new(TeeDelayConfig::default()), 
                None
            );
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
                0, 0, // No delay
                &enclave_gen_key.metrics_tx,
                &Some(enclave_gen_key.identity.clone()),
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