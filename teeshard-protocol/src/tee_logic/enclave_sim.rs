// TEE Enclave Simulation logic

use crate::data_structures::TEEIdentity;
use crate::tee_logic::types::AttestationReport;
// Import the new PartialSignature struct
use crate::tee_logic::threshold_sig::PartialSignature;
// Import the crypto sim components we need
use crate::tee_logic::crypto_sim::{self, SecretKey, generate_keypair};

// Simulate a TEE enclave environment
#[derive(Debug)]
pub struct EnclaveSim {
    pub identity: TEEIdentity,
    // Use a real Ed25519 keypair for the enclave
    keypair: SecretKey,
}

impl EnclaveSim {
    pub fn new(id: usize, existing_keypair: Option<SecretKey>) -> Self {
        // Generate a real keypair for this enclave if not provided
        let keypair = existing_keypair.unwrap_or_else(generate_keypair);
        let public_key = keypair.verifying_key();
        let identity = TEEIdentity { id, public_key };
        EnclaveSim { identity, keypair }
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
        let signature = crypto_sim::sign(&report_data, &self.keypair);

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
         let signature_data = crypto_sim::sign(message, &self.keypair);

         PartialSignature {
             signer_id: self.identity.clone(),
             // Store the actual Ed25519 signature
             signature_data,
         }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee_logic::crypto_sim::{verify, PublicKey};

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
        assert_eq!(sim.identity.public_key, sim.keypair.verifying_key());
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
} 