// Threshold Signature generation and verification

use crate::data_structures::TEEIdentity;
// Use the real Signature type
use crate::tee_logic::types::Signature;
use std::collections::BTreeMap; // Use BTreeMap for deterministic iteration
// Import crypto sim components
use crate::tee_logic::crypto_sim::{PublicKey, verify};

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
    message: Vec<u8>, // Store the message being signed
    // Store verified partial signatures: Map PublicKey bytes -> Signature
    // Using BTreeMap for deterministic order if needed later.
    verified_signatures: BTreeMap<Vec<u8>, (PublicKey, Signature)>,
}

impl ThresholdAggregator {
    /// Creates a new aggregator for a given message and threshold.
    pub fn new(message: &[u8], required_threshold: usize) -> Self {
        ThresholdAggregator {
            required_threshold,
            message: message.to_vec(),
            verified_signatures: BTreeMap::new(),
        }
    }

    /// Adds and verifies a partial signature to the aggregator.
    /// Returns Err if the signature is invalid or the signer has already added one.
    pub fn add_partial_signature(&mut self, partial_sig: PartialSignature) -> Result<(), &'static str> {

        // Verify the partial signature using the signer's public key
        if !verify(&self.message, &partial_sig.signature_data, &partial_sig.signer_id.public_key) {
             println!(
                 "Aggregator: Partial signature verification failed for signer {}. Sig: {:?}, Msg: {:?}, Key: {:?}",
                 partial_sig.signer_id.id,
                 partial_sig.signature_data,
                 self.message,
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
pub fn verify_multi_signature(
    message: &[u8],
    // The collection of signatures to verify
    multi_sig: &[(PublicKey, Signature)],
    required_threshold: usize,
) -> bool {
    println!("VerifyMultiSig: Verifying {} signatures for message {:?} against threshold {}",
              multi_sig.len(), message, required_threshold);

    if multi_sig.len() < required_threshold {
        println!("VerifyMultiSig: Not enough signatures provided ({}) to meet threshold ({})",
                 multi_sig.len(), required_threshold);
        return false;
    }

    // Check if we have *at least* `required_threshold` valid signatures in the collection.
    // We also need to ensure no duplicate public keys are counted.
    let mut verified_keys = std::collections::HashSet::new();
    let mut valid_sig_count = 0;

    for (public_key, signature) in multi_sig {
        if verify(message, signature, public_key) {
            // Only count if the public key hasn't been seen before in this verification set
             if verified_keys.insert(public_key.to_bytes()) { // Diffs PublicKey by bytes
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
    use crate::tee_logic::crypto_sim::{generate_keypair, sign};
    use crate::data_structures::TEEIdentity; // Import TEEIdentity

    // Helper to create a TEEIdentity with a real key
    fn create_real_tee(id: usize) -> (TEEIdentity, ed25519_dalek::SigningKey) {
        let keypair = generate_keypair();
        let identity = TEEIdentity { id, public_key: keypair.verifying_key() };
        (identity, keypair)
    }

    // Helper to create a valid partial signature
    fn create_valid_partial_sig(identity: &TEEIdentity, keypair: &ed25519_dalek::SigningKey, message: &[u8]) -> PartialSignature {
        let signature_data = sign(message, keypair);
        PartialSignature {
            signer_id: identity.clone(),
            signature_data,
        }
    }

    #[test]
    fn test_aggregator_flow_success() {
        let identities_keys: Vec<_> = (0..5).map(create_real_tee).collect();
        let identities: Vec<_> = identities_keys.iter().map(|(id, _)| id.clone()).collect();
        let keypairs: Vec<_> = identities_keys.iter().map(|(_, kp)| kp).collect();

        let message = b"approve_step_1";
        let threshold = 3;

        let mut aggregator = ThresholdAggregator::new(message, threshold);

        assert!(!aggregator.has_reached_threshold());
        assert!(aggregator.finalize_multi_signature().is_none());

        // Add valid partial signatures from 3 TEEs (0, 2, 4)
        let partial_sig_0 = create_valid_partial_sig(&identities[0], keypairs[0], message);
        let partial_sig_2 = create_valid_partial_sig(&identities[2], keypairs[2], message);
        let partial_sig_4 = create_valid_partial_sig(&identities[4], keypairs[4], message);

        assert!(aggregator.add_partial_signature(partial_sig_0).is_ok());
        assert_eq!(aggregator.verified_signatures.len(), 1);
        assert!(!aggregator.has_reached_threshold());
        assert!(aggregator.add_partial_signature(partial_sig_4).is_ok());
        assert_eq!(aggregator.verified_signatures.len(), 2);
        assert!(!aggregator.has_reached_threshold());
        assert!(aggregator.add_partial_signature(partial_sig_2).is_ok());
        assert_eq!(aggregator.verified_signatures.len(), 3);
        assert!(aggregator.has_reached_threshold());

        // Finalize (get multi-sig collection)
        let multi_sig = aggregator.finalize_multi_signature().expect("Finalization failed");
        assert_eq!(multi_sig.len(), threshold);

        // Verify the multi-signature collection
        let is_valid = verify_multi_signature(message, &multi_sig, threshold);
        assert!(is_valid, "Multi-signature verification failed");

        // Test verification with lower threshold (should still pass)
        assert!(verify_multi_signature(message, &multi_sig, threshold - 1));

        // Test verification with higher threshold (should fail)
        assert!(!verify_multi_signature(message, &multi_sig, threshold + 1));

        // Test verification with wrong message
        assert!(!verify_multi_signature(b"wrong_message", &multi_sig, threshold));

        // Test verification with a manually constructed invalid signature in the set
        let (invalid_id, invalid_kp) = create_real_tee(99);
        let invalid_sig = sign(b"different_message", &invalid_kp);
        let mut multi_sig_with_invalid = multi_sig.clone();
        multi_sig_with_invalid[0] = (invalid_id.public_key, invalid_sig);
        // Should fail if threshold requires all original 3
        assert!(!verify_multi_signature(message, &multi_sig_with_invalid, threshold));
        // Should pass if threshold is low enough (e.g., 2) to tolerate one invalid sig
        assert!(verify_multi_signature(message, &multi_sig_with_invalid, threshold - 1));

    }

    #[test]
    fn test_aggregator_add_duplicate_signer() {
        let (identity0, keypair0) = create_real_tee(0);
        let message = b"message";
        let threshold = 1;
        let mut aggregator = ThresholdAggregator::new(message, threshold);

        let partial_sig_0 = create_valid_partial_sig(&identity0, &keypair0, message);
        let partial_sig_0_again = partial_sig_0.clone();

        assert!(aggregator.add_partial_signature(partial_sig_0).is_ok());
        let result = aggregator.add_partial_signature(partial_sig_0_again);
        assert!(result.is_err());
        // Error message updated
        assert_eq!(result.unwrap_err(), "Signer (key) has already provided a valid partial signature");
        assert_eq!(aggregator.verified_signatures.len(), 1);
    }

     #[test]
    fn test_aggregator_add_invalid_signature() {
        let (identity0, _) = create_real_tee(0);
        let (_, keypair1) = create_real_tee(1); // Key doesn't match identity0
        let message = b"test_message";
        let threshold = 1;
        let mut aggregator = ThresholdAggregator::new(message, threshold);

        // Create signature with keypair1 but claim it's from identity0
        let invalid_sig_data = sign(message, &keypair1);
        let invalid_partial_sig = PartialSignature {
            signer_id: identity0.clone(), // Claiming to be from ID 0
            signature_data: invalid_sig_data,
        };

        let result = aggregator.add_partial_signature(invalid_partial_sig);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Partial signature verification failed");
        assert!(aggregator.verified_signatures.is_empty());
    }

    #[test]
    fn test_aggregator_threshold_not_met() {
        let identities_keys: Vec<_> = (0..5).map(create_real_tee).collect();
        let identities: Vec<_> = identities_keys.iter().map(|(id, _)| id.clone()).collect();
        let keypairs: Vec<_> = identities_keys.iter().map(|(_, kp)| kp).collect();

        let message = b"another_message";
        let threshold = 3;
        let mut aggregator = ThresholdAggregator::new(message, threshold);

        let partial_sig_1 = create_valid_partial_sig(&identities[1], keypairs[1], message);
        let partial_sig_3 = create_valid_partial_sig(&identities[3], keypairs[3], message);

        aggregator.add_partial_signature(partial_sig_1).unwrap();
        aggregator.add_partial_signature(partial_sig_3).unwrap();

        assert!(!aggregator.has_reached_threshold());
        assert!(aggregator.finalize_multi_signature().is_none());
    }

} 