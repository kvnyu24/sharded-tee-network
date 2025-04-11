// Define types related to TEE logic, signatures, and attestations

// Use the actual signature type from the crypto library
pub use ed25519_dalek::Signature;

// Represents a TEE attestation report
// Contents depend heavily on the TEE technology (e.g., SGX quote)
// Using a simple struct as a placeholder.
#[derive(Clone, Debug, PartialEq, Eq)] // Signature impls necessary traits
pub struct AttestationReport {
    pub report_data: Vec<u8>, // Data included in the report (e.g., nonce, public key hash)
    pub signature: Signature, // Signature over the report data by the TEE's key
    // Add other fields like TEE measurements, identity info, etc.
}

use std::time::Instant;

// Function to provide a default Instant value for serde
fn default_instant() -> Instant {
    Instant::now()
}

// Represents data related to a specific lock event that needs
// consensus and signing by TEEs.
// Remove bincode derives as Instant cannot be encoded
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct LockProofData {
    // Unique identifier for the overall transaction/swap
    pub tx_id: String,
    // Identifier for the source chain where the lock occurred
    pub source_chain_id: u64,
    // Identifier for the target chain where release should happen
    pub target_chain_id: u64,
    // Token being locked
    pub token_address: String, // Assuming address uniquely identifies token on source chain
    // Amount locked
    pub amount: u64,
    // Recipient address on the target chain
    pub recipient: String,
    // Potentially other relevant data like source sender, nonce, etc.
    // pub source_sender: String,
    // pub nonce: u64,

    // Start time of the transaction, used for latency calculation.
    // Skip serialization/deserialization for this field.
    #[serde(skip, default = "default_instant")]
    pub start_time: Instant, 
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use rand::rngs::OsRng;

    // Helper to create a dummy signature
    fn create_dummy_sig(data: &[u8]) -> Signature {
        let key = SigningKey::generate(&mut OsRng);
        key.sign(data)
    }

    // Signature is now a type alias, no specific creation test needed.
    /*
    #[test]
    fn signature_creation() {
        let sig_data = vec![1, 2, 3, 4];
        let sig = Signature(sig_data.clone());
        assert_eq!(sig.0, sig_data);

        let sig2 = Signature(vec![1, 2, 3, 4]);
        assert_eq!(sig, sig2);

        let sig3 = Signature(vec![5, 6]);
        assert_ne!(sig, sig3);
    }
    */

    #[test]
    fn attestation_report_creation() {
        let data = vec![10, 20];
        let signature = create_dummy_sig(&data);
        let report = AttestationReport {
            report_data: data.clone(),
            signature: signature,
        };

        assert_eq!(report.report_data, data);
        // Cannot directly compare signature bytes easily without helper
        // Just check it was created
        assert_eq!(report.signature.to_bytes().len(), 64); // Ed25519 sigs are 64 bytes
    }
} 