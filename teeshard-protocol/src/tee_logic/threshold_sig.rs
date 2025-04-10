// Threshold Signature generation and verification

use crate::data_structures::TEEIdentity;
// Use the real Signature type
use crate::tee_logic::types::Signature;
use std::collections::{BTreeMap, HashSet}; // Use BTreeMap for deterministic iteration, HashSet for verify_multi
// Import crypto sim components
use crate::tee_logic::crypto_sim::{PublicKey, verify}; 
use crate::tee_logic::enclave_sim::TeeDelayConfig; // Correct path
use std::sync::Arc; // Need Arc for passing config

// Represents a signature share from a single TEE
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialSignature {
    pub signer_id: TEEIdentity,
    // Store the actual Ed25519 signature
    pub signature_data: Signature,
}

// Aggregates partial signatures to form a final threshold signature
#[derive(Debug, Clone)]
pub struct ThresholdAggregator {
    required_threshold: usize,
    // Store verified partial signatures: Map PublicKey bytes -> Signature
    // Key: Signer PK bytes, Value: (Signer PK, Verified Signature)
    verified_signatures: BTreeMap<Vec<u8>, (PublicKey, Signature)>,
    // Store delay config for verify operations
    delay_config: Arc<TeeDelayConfig>, // Use Arc for shared ownership
}

impl ThresholdAggregator {
    /// Creates a new aggregator for a given threshold and delay config.
    pub fn new(required_threshold: usize, delay_config: Arc<TeeDelayConfig>) -> Self {
        ThresholdAggregator {
            required_threshold,
            verified_signatures: BTreeMap::new(),
            delay_config, // Store the config Arc
        }
    }

    /// Adds and verifies a partial signature against the provided message context.
    /// Returns Err if the signature is invalid or the signer has already added one.
    pub async fn add_partial_signature(&mut self, message: &[u8], partial_sig: PartialSignature) -> Result<(), &'static str> {

        // Verify the partial signature using the signer's public key against the provided message
        let is_valid = verify(
            message, 
            &partial_sig.signature_data, 
            &partial_sig.signer_id.public_key,
            self.delay_config.verify_min_ms,
            self.delay_config.verify_max_ms,
        ).await;

        if !is_valid {
            println!(
                "Aggregator: Partial signature verification failed for signer {}. Sig: {:?}, Msg: {:?}, Key: {:?}",
                partial_sig.signer_id.id,
                partial_sig.signature_data,
                message, // Log the message used for verification
                partial_sig.signer_id.public_key
            );
            return Err("Partial signature verification failed");
        }

        let pk_bytes = partial_sig.signer_id.public_key.to_bytes().to_vec();
        if self.verified_signatures.contains_key(&pk_bytes) {
            // Note: We check based on public key bytes now, not TEEIdentity ID
            return Err("Signer (key) has already provided a valid partial signature");
        }

        println!("Aggregator: Adding verified partial signature from signer ID {} (Key: {:?})",
                partial_sig.signer_id.id, pk_bytes);
        self.verified_signatures.insert(pk_bytes, (partial_sig.signer_id.public_key, partial_sig.signature_data));
        Ok(())
    }

    /// Returns the number of verified signatures currently held.
    pub fn signature_count(&self) -> usize {
        self.verified_signatures.len()
    }

    /// Returns the required signature threshold.
    pub fn get_required_threshold(&self) -> usize {
        self.required_threshold
    }

    /// Checks if the threshold has been met.
    pub fn has_reached_threshold(&self) -> bool {
        self.verified_signatures.len() >= self.required_threshold
    }

    /// Attempts to finalize the threshold signature (simulated as multi-sig) if the threshold is met.
    /// Returns None if the threshold is not met.
    /// Returns a Vec of (PublicKey, Signature) pairs meeting the threshold.
    pub fn finalize_multi_signature(&self) -> Option<Vec<(PublicKey, Signature)>> {
        if !self.has_reached_threshold() {
            println!("Aggregator: Threshold not met ({} < {})", self.verified_signatures.len(), self.required_threshold);
            return None;
        }

        println!("Aggregator: Threshold met ({} >= {}). Finalizing multi-signature collection.",
                 self.verified_signatures.len(), self.required_threshold);

        // In this multi-signature simulation, "finalizing" just means returning the collection
        // of verified signatures that meet the threshold.
        // We take the first `required_threshold` signatures based on the BTreeMap iteration order (sorted by PK bytes).
        let multi_sig: Vec<(PublicKey, Signature)> = self.verified_signatures.values().cloned().take(self.required_threshold).collect();

        // Double-check we collected enough (should always be true if threshold was met)
        if multi_sig.len() == self.required_threshold {
             Some(multi_sig)
        } else {
            eprintln!("Error: Could not collect enough signatures ({}) for threshold ({}) during finalization.", multi_sig.len(), self.required_threshold);
            None
        }
    }

    // Remove old finalize_signature which simulated a single hash output
    // pub fn finalize_signature(&self) -> Option<Signature> { ... }
}


// Verify a multi-signature collection produced by the aggregator
pub async fn verify_multi_signature(
    message: &[u8],
    multi_sig: &[(PublicKey, Signature)],
    required_threshold: usize,
    delay_config: Arc<TeeDelayConfig>, // Accept delay config
) -> bool {
    println!("VerifyMultiSig: Verifying {} signatures for message {:?} against threshold {}",
              multi_sig.len(), message, required_threshold);

    if multi_sig.len() < required_threshold {
        println!("VerifyMultiSig: Not enough signatures provided ({}) to meet threshold ({})",
                 multi_sig.len(), required_threshold);
        return false;
    }

    let mut verified_keys = HashSet::new();
    let mut valid_sig_count = 0;

    for (public_key, signature) in multi_sig {
        // Call async verify with delays
        let is_valid = verify(
            message, 
            signature, 
            public_key,
            delay_config.verify_min_ms,
            delay_config.verify_max_ms
        ).await;

        if is_valid {
            if verified_keys.insert(public_key.to_bytes()) {
                valid_sig_count += 1;
            }
        } else {
            println!("VerifyMultiSig: Found invalid signature for key {:?}", public_key);
            // Depending on policy, finding even one invalid signature might invalidate the whole set.
            // For threshold, we just need enough valid ones.
        }
    }

    println!("VerifyMultiSig: Found {} valid unique signatures.", valid_sig_count);
    valid_sig_count >= required_threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    // Import sign/generate from crypto_sim and TeeDelayConfig from enclave_sim
    use crate::tee_logic::crypto_sim::{generate_keypair, sign}; 
    use crate::tee_logic::enclave_sim::TeeDelayConfig; // Correct path
    use crate::data_structures::TEEIdentity; // Import TEEIdentity
    use tokio::runtime::Runtime; // Add tokio runtime for async tests
    use std::sync::Arc; // Import Arc

    // Helper function to run async tests
    fn run_async<F>(future: F) -> F::Output 
    where
        F: std::future::Future,
    {
        Runtime::new().unwrap().block_on(future)
    }

    // Helper to create a TEEIdentity with a real key
    fn create_real_tee(id: usize) -> (TEEIdentity, ed25519_dalek::SigningKey) {
        let keypair = generate_keypair();
        let identity = TEEIdentity { id, public_key: keypair.verifying_key() };
        (identity, keypair)
    }

    // Helper to create a valid partial signature (now async due to crypto_sim::sign)
    async fn create_valid_partial_sig(identity: &TEEIdentity, keypair: &ed25519_dalek::SigningKey, message: &[u8]) -> PartialSignature {
        // Pass 0 delays for test signing
        let signature_data = sign(message, keypair, 0, 0).await;
        PartialSignature {
            signer_id: identity.clone(),
            signature_data,
        }
    }

    #[test]
    fn test_aggregator_flow_success_async() {
        run_async(async {
            let identities_keys: Vec<_> = (0..5).map(create_real_tee).collect();
            let identities: Vec<_> = identities_keys.iter().map(|(id, _)| id.clone()).collect();
            let keypairs: Vec<_> = identities_keys.iter().map(|(_, kp)| kp).collect();

            let message = b"approve_step_1_async";
            let threshold = 3;
            let delay_config = Arc::new(TeeDelayConfig::default()); // Default (no delay) config for test

            let mut aggregator = ThresholdAggregator::new(threshold, Arc::clone(&delay_config));

            assert!(!aggregator.has_reached_threshold());
            assert!(aggregator.finalize_multi_signature().is_none());

            // Create signatures concurrently
            let partial_sig_0 = create_valid_partial_sig(&identities[0], keypairs[0], message).await;
            let partial_sig_2 = create_valid_partial_sig(&identities[2], keypairs[2], message).await;
            let partial_sig_4 = create_valid_partial_sig(&identities[4], keypairs[4], message).await;

            // Add signatures sequentially (or could use join_all)
            assert!(aggregator.add_partial_signature(message, partial_sig_0).await.is_ok());
            assert_eq!(aggregator.signature_count(), 1);
            assert!(!aggregator.has_reached_threshold());
            assert!(aggregator.add_partial_signature(message, partial_sig_4).await.is_ok());
            assert_eq!(aggregator.signature_count(), 2);
            assert!(!aggregator.has_reached_threshold());
            assert!(aggregator.add_partial_signature(message, partial_sig_2).await.is_ok());
            assert_eq!(aggregator.signature_count(), 3);
            assert!(aggregator.has_reached_threshold());

            let multi_sig = aggregator.finalize_multi_signature().expect("Finalization failed");
            assert_eq!(multi_sig.len(), threshold);

            // Verify the finalized multi-sig (also async now)
            let is_valid = verify_multi_signature(message, &multi_sig, threshold, delay_config).await;
            assert!(is_valid);
        });
    }

    #[test]
    fn test_aggregator_add_duplicate_signer_async() {
        run_async(async {
            let (id1, kp1) = create_real_tee(1);
            let message = b"duplicate test";
            let delay_config = Arc::new(TeeDelayConfig::default());
            let mut aggregator = ThresholdAggregator::new(2, Arc::clone(&delay_config));

            let partial_sig1 = create_valid_partial_sig(&id1, &kp1, message).await;
            let partial_sig2 = create_valid_partial_sig(&id1, &kp1, message).await; // Same signer

            assert!(aggregator.add_partial_signature(message, partial_sig1).await.is_ok());
            assert!(aggregator.add_partial_signature(message, partial_sig2).await.is_err()); // Should fail
            assert_eq!(aggregator.signature_count(), 1);
        });
    }

    #[test]
    fn test_aggregator_add_invalid_signature_async() {
        run_async(async {
            let (id1, kp1) = create_real_tee(1);
            let message = b"invalid sig test";
            let wrong_message = b"wrong message";
            let delay_config = Arc::new(TeeDelayConfig::default());
            let mut aggregator = ThresholdAggregator::new(1, Arc::clone(&delay_config));

            // Create sig with wrong message
            let invalid_partial_sig = create_valid_partial_sig(&id1, &kp1, wrong_message).await;
            
            // Try adding it with the correct message context
            assert!(aggregator.add_partial_signature(message, invalid_partial_sig).await.is_err()); // Should fail verification
            assert_eq!(aggregator.signature_count(), 0);
        });
    }

    #[test]
    fn test_aggregator_threshold_not_met_async() {
         run_async(async {
            let (id1, kp1) = create_real_tee(1);
            let (id2, kp2) = create_real_tee(2);
            let message = b"threshold not met";
            let threshold = 3;
            let delay_config = Arc::new(TeeDelayConfig::default());
            let mut aggregator = ThresholdAggregator::new(threshold, Arc::clone(&delay_config));

            let partial_sig1 = create_valid_partial_sig(&id1, &kp1, message).await;
            let partial_sig2 = create_valid_partial_sig(&id2, &kp2, message).await;

            assert!(aggregator.add_partial_signature(message, partial_sig1).await.is_ok());
            assert!(aggregator.add_partial_signature(message, partial_sig2).await.is_ok());

            assert_eq!(aggregator.signature_count(), 2);
            assert!(!aggregator.has_reached_threshold());
            assert!(aggregator.finalize_multi_signature().is_none());
        });
    }
} 