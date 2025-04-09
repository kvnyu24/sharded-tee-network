// TEE Enclave Simulation logic

use crate::data_structures::{LockInfo, TEEIdentity};
use crate::tee_logic::types::{LockProofData, Signature, AttestationReport};
use crate::liveness::types::VerificationResult;
use crate::tee_logic::crypto_sim::{self, SecretKey, generate_keypair, sign, PublicKey};
use ed25519_dalek::{VerifyingKey, SigningKey, Signer, Verifier};
use crate::tee_logic::threshold_sig::PartialSignature;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// Simulate a TEE enclave environment
#[derive(Debug, Clone)]
pub struct EnclaveSim {
    pub identity: TEEIdentity,
    // Use a real Ed25519 keypair for the enclave
    signing_key: Option<SigningKey>,
    // Store the public key for convenience
    public_key: PublicKey,
    // Placeholder for internal enclave state if needed
    // internal_state: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl EnclaveSim {
    pub fn new(node_id: usize, signing_key: Option<SigningKey>) -> Self {
        let signing_key = signing_key;
        let public_key = signing_key.as_ref().map(|key| key.verifying_key()).unwrap_or_default();
        let identity = TEEIdentity { id: node_id, public_key };
        EnclaveSim {
            identity,
            signing_key,
            public_key,
            // internal_state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // Helper for tests or scenarios where only ID is known
    pub fn new_with_generated_key(id: usize) -> Self {
        Self::new(id, None)
    }

    // Simulate generating a remote attestation report containing the nonce
    pub fn generate_remote_attestation(&self, nonce: &[u8]) -> AttestationReport {
        println!("EnclaveSim ({}): Generating attestation for nonce {:?}", self.identity.id, nonce);
        // Simulates the TEE creating a report containing the nonce and its identity (public key),
        // signed using its attestation key (simulated here by the enclave's main keypair).
        // Real attestation involves complex interaction with TEE hardware/runtime.
        let mut report_data = Vec::new();
        report_data.extend_from_slice(nonce);
        report_data.extend_from_slice(self.identity.public_key.as_bytes());
        // Sign the report data with the enclave's key
        let signature = crypto_sim::sign(&report_data, &self.signing_key.as_ref().unwrap());

        AttestationReport {
            report_data,
            signature,
        }
    }

    /// Generates a partial signature share for the given message.
    pub fn generate_partial_signature(&self, message: &[u8]) -> PartialSignature {
         println!("EnclaveSim ({}): Generating partial signature for msg {:?}", self.identity.id, message);
         // Simulates the TEE using its threshold secret key share to sign the message.
         // Since we aren't implementing DKG/TSS, we use the enclave's main keypair for this.
         // In a real TSS, this would use a share derived from a group key.
         let signature_data = crypto_sim::sign(message, &self.signing_key.as_ref().unwrap());

         PartialSignature {
             signer_id: self.identity.clone(),
             // Store the actual Ed25519 signature
             signature_data,
         }
    }

    /// Returns the public key of the simulated enclave.
    pub fn get_public_key(&self) -> Option<PublicKey> {
        self.signing_key.as_ref().map(|key| key.verifying_key())
    }

    /// Simulates signing a message within the enclave.
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        // Use the stored SigningKey
        if let Some(key) = &self.signing_key {
            key.sign(message) 
        } else {
            // Handle case where enclave doesn't have a key (e.g., read-only node)
            // This shouldn't happen for nodes expected to sign, panic might be okay for sim
            panic!("Enclave for node {} tried to sign without a key!", self.identity.id);
            // Or return a specific error/dummy signature if applicable
        }
    }

    fn verify_signature(&self, message: &[u8], public_key: &PublicKey, signature: &Signature) -> VerificationResult {
        // Directly use the provided public key (VerifyingKey)
        match public_key.verify(message, signature) {
            Ok(_) => VerificationResult::Valid,
            Err(_) => VerificationResult::InvalidSignature,
        }
    }

    // Method to generate an attestation report (simplified)
    fn generate_attestation(&self) -> Option<AttestationReport> {
        self.signing_key.as_ref().map(|key| {
            // Construct report_data based on the current struct definition
            let report_content = format!("Attested TEE Node: {}, Key: {:?}", self.identity.id, key.verifying_key());
            let report_data = report_content.as_bytes().to_vec();
            let signature = key.sign(&report_data);
            AttestationReport {
                // Use fields from struct definition
                report_data,
                signature,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee_logic::crypto_sim::verify;
    use ed25519_dalek::{Signer, Verifier};

    // Helper to create EnclaveSim for testing
    fn create_test_enclave(id: usize) -> EnclaveSim {
        // Generate a key and pass it to new()
        let signing_key = crypto_sim::generate_keypair();
        EnclaveSim::new(id, Some(signing_key))
    }

    #[test]
    fn enclave_sim_creation_with_key() {
        let sim = create_test_enclave(5);
        assert_eq!(sim.identity.id, 5);
        // Check that the public key in identity matches the keypair
        assert_eq!(sim.identity.public_key, sim.signing_key.as_ref().unwrap().verifying_key());
    }

    #[test]
    fn enclave_sim_attestation() {
        let sim = create_test_enclave(2);
        let nonce = vec![100, 101, 102];
        let report = sim.generate_remote_attestation(&nonce);

        // Check if nonce and pubkey bytes are in report data (simple check)
        assert!(report.report_data.windows(nonce.len()).any(|w| w == nonce));
        let pk_bytes = sim.identity.public_key.as_bytes();
        assert!(report.report_data.windows(pk_bytes.len()).any(|w| w == pk_bytes));

        // Verify the signature using the enclave's public key
        assert!(verify(&report.report_data, &report.signature, &sim.identity.public_key));
    }

     #[test]
    fn enclave_sim_generate_partial_sig() {
        let sim = create_test_enclave(3);
        let msg = b"message for partial sig";

        let partial_sig = sim.generate_partial_signature(msg);

        assert_eq!(partial_sig.signer_id, sim.identity);

        // Verify the signature using the enclave's public key
        assert!(verify(msg, &partial_sig.signature_data, &sim.identity.public_key));
    }

    #[test]
    fn enclave_sim_partial_sig_verify_fail_wrong_key() {
        let sim1 = create_test_enclave(10);
        let sim2 = create_test_enclave(11); // Different enclave with different key
        let msg = b"another message";

        // Sign with sim1's key
        let partial_sig = sim1.generate_partial_signature(msg);

        // Try to verify with sim2's public key (should fail)
        assert!(!verify(msg, &partial_sig.signature_data, &sim2.identity.public_key));
    }

    #[test]
    fn test_enclave_sim_creation_and_signing() {
        // Test creating enclave without a key
        let enclave_no_key = EnclaveSim::new(1, None);
        assert_eq!(enclave_no_key.identity.id, 1);
        assert!(enclave_no_key.get_public_key().is_none());

        // Test creating enclave with a generated key
        let enclave_gen_key = EnclaveSim::new(2, Some(generate_keypair()));
        assert_eq!(enclave_gen_key.identity.id, 2);
        assert!(enclave_gen_key.get_public_key().is_some());

        // Sign message
        let message = b"test message";
        let signature1 = enclave_gen_key.sign_message(message);
        let public_key1 = enclave_gen_key.get_public_key().unwrap();

        // Verify function (assuming it exists or using dalek's directly)
        fn verify(msg: &[u8], sig: &Signature, pk: &VerifyingKey) -> bool {
            pk.verify(msg, sig).is_ok()
        }

        // Verify with enclave 1's public key (should pass)
        assert!(verify(message, &signature1, &public_key1));

        // Create another enclave to test verification failure
        let enclave_gen_key2 = EnclaveSim::new(3, Some(generate_keypair()));
        let public_key2 = enclave_gen_key2.get_public_key().unwrap();
        assert!(!verify(message, &signature1, &public_key2));

        // Test providing an existing key
        let signing_key_existing = generate_keypair();
        let verifying_key_existing = signing_key_existing.verifying_key(); // Get verifying key
        let enclave_existing = EnclaveSim::new(4, Some(signing_key_existing));
        assert_eq!(enclave_existing.get_public_key(), Some(verifying_key_existing));

        let signature_existing = enclave_existing.sign_message(message);
        assert!(verify(message, &signature_existing, &verifying_key_existing));
    }

    #[test]
    fn test_enclave_sim_sign_verify() {
        let signing_key = generate_keypair(); // generate_keypair returns SigningKey
        let verifying_key = signing_key.verifying_key(); // Get verifying key from it
        let node_id = 1;

        // Pass SigningKey to new
        let enclave = EnclaveSim::new(node_id, Some(signing_key)); 
        let message = b"test message for enclave";

        // Sign message
        let signature = enclave.sign_message(message);

        // Verify signature using the corresponding verifying key
        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    #[should_panic]
    fn test_enclave_sim_sign_without_key() {
        let node_id = 2;
        // Create enclave without a key
        let enclave = EnclaveSim::new(node_id, None); 
        let message = b"another message";

        // Attempting to sign should panic
        enclave.sign_message(message); 
    }
} 