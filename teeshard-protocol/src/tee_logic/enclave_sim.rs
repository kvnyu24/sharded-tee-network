// TEE Enclave Simulation logic

use crate::data_structures::TEEIdentity;
use crate::tee_logic::types::AttestationReport;
// Import the new PartialSignature struct
use crate::tee_logic::threshold_sig::PartialSignature;
// Import the crypto sim components we need
use crate::tee_logic::crypto_sim::{self, SecretKey, generate_keypair, sign, PublicKey};
use crate::tee_logic::types::Signature;
use std::sync::{Arc, Mutex};
use ed25519_dalek::SigningKey;

// Simulate a TEE enclave environment
#[derive(Debug, Clone)]
pub struct EnclaveSim {
    pub identity: TEEIdentity,
    // Use a real Ed25519 keypair for the enclave
    signing_key: SecretKey,
    // Store the public key for convenience
    public_key: PublicKey,
    // Placeholder for internal enclave state if needed
    // internal_state: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl EnclaveSim {
    pub fn new(id: usize, existing_keypair: Option<SecretKey>) -> Self {
        let signing_key = existing_keypair.unwrap_or_else(|| {
            // Generate a deterministic key based on ID if none provided
            let secret_bytes = [id as u8; 32];
            SecretKey::from_bytes(&secret_bytes)
        });
        let public_key = signing_key.verifying_key();
        let identity = TEEIdentity { id, public_key };
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
        let signature = crypto_sim::sign(&report_data, &self.signing_key);

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
         let signature_data = crypto_sim::sign(message, &self.signing_key);

         PartialSignature {
             signer_id: self.identity.clone(),
             // Store the actual Ed25519 signature
             signature_data,
         }
    }

    /// Returns the public key of the simulated enclave.
    pub fn get_public_key(&self) -> PublicKey {
        self.public_key
    }

    /// Simulates signing a message within the enclave.
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        // Use the imported sign function
        sign(message, &self.signing_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee_logic::crypto_sim::verify;

    // Helper to create EnclaveSim for testing
    fn create_test_enclave(id: usize) -> EnclaveSim {
        // Use the helper that generates a key
        EnclaveSim::new_with_generated_key(id)
    }

    #[test]
    fn enclave_sim_creation_with_key() {
        let sim = create_test_enclave(5);
        assert_eq!(sim.identity.id, 5);
        // Check that the public key in identity matches the keypair
        assert_eq!(sim.identity.public_key, sim.signing_key.verifying_key());
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
        let enclave1 = EnclaveSim::new(1, None); // Generate key
        let enclave2 = EnclaveSim::new(2, None); // Generate different key

        assert_ne!(enclave1.get_public_key(), enclave2.get_public_key());

        let message = b"hello simulation";

        // Sign with enclave 1
        let signature1 = enclave1.sign_message(message);

        // Verify with enclave 1's public key (should pass)
        assert!(verify(message, &signature1, &enclave1.get_public_key()));

        // Verify with enclave 2's public key (should fail)
        assert!(!verify(message, &signature1, &enclave2.get_public_key()));

        // Test providing an existing key
        let secret_bytes = [99u8; 32];
        let existing_key = SecretKey::from_bytes(&secret_bytes);
        let enclave_existing = EnclaveSim::new(3, Some(existing_key.clone()));
        assert_eq!(enclave_existing.get_public_key(), existing_key.verifying_key());

        let signature_existing = enclave_existing.sign_message(message);
        assert!(verify(message, &signature_existing, &existing_key.verifying_key()));
    }
} 