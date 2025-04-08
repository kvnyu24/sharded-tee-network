// Define types related to TEE Liveness Verification (Algorithm 4)

use crate::data_structures::TEEIdentity;
use crate::tee_logic::types::AttestationReport;
use std::time::{Duration, Instant};

// Using simple u64 for nonce for now
pub type Nonce = u64;

// State tracked per TEE node for liveness
#[derive(Clone, Debug)]
pub struct LivenessState {
    pub trust_score: f64,
    pub challenge_interval: Duration,
    pub last_challenge_time: Option<Instant>, // Use Option for initial state
    pub consecutive_fails: usize,
}

// Message sent from Challenger to a TEE node
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonceChallenge {
    pub target_tee: TEEIdentity,
    pub nonce: Nonce,
}

// Response sent from a TEE node back to Challenger/Aggregator
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationResponse {
    pub responding_tee: TEEIdentity,
    pub nonce: Nonce, // Nonce received in the challenge
    pub report: AttestationReport,
}

// Result of verifying an attestation response
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationStatus {
    Valid,
    InvalidSignature,
    InvalidNonce,
    InvalidReportData,
    Timeout, // Or node did not respond
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee_logic::types::Signature;
    use crate::tee_logic::crypto_sim::generate_keypair; // Import key generation
    use ed25519_dalek::{Signer, SigningKey}; // Import signing components
    use rand::rngs::OsRng; // Import OsRng

    fn create_test_tee(id: usize) -> TEEIdentity {
        // Create TEEIdentity with usize ID and a real public key
        let keypair = generate_keypair();
        TEEIdentity { id, public_key: keypair.verifying_key() }
    }

    // Helper to create a dummy signature for tests
    fn create_dummy_sig(data: &[u8]) -> Signature {
        let key = SigningKey::generate(&mut OsRng);
        key.sign(data)
    }

    #[test]
    fn liveness_state_creation() {
        let state = LivenessState {
            trust_score: 100.0,
            challenge_interval: Duration::from_secs(5),
            last_challenge_time: None,
            consecutive_fails: 0,
        };
        assert_eq!(state.trust_score, 100.0);
        assert_eq!(state.consecutive_fails, 0);
        assert!(state.last_challenge_time.is_none());
    }

    #[test]
    fn nonce_challenge_creation() {
        let tee = create_test_tee(1);
        let challenge = NonceChallenge {
            target_tee: tee.clone(),
            nonce: 12345,
        };
        assert_eq!(challenge.target_tee, tee);
        assert_eq!(challenge.nonce, 12345);
    }

    #[test]
    fn attestation_response_creation() {
        let tee = create_test_tee(2);
        let report = AttestationReport {
            report_data: vec![1, 2, 3],
            signature: create_dummy_sig(&[1, 2, 3]), // Use helper
        };
        let response = AttestationResponse {
            responding_tee: tee.clone(),
            nonce: 54321,
            report: report.clone(),
        };
        assert_eq!(response.responding_tee, tee);
        assert_eq!(response.nonce, 54321);
        assert_eq!(response.report, report);
    }

    #[test]
    fn verification_status_enum() {
        assert_eq!(VerificationStatus::Valid, VerificationStatus::Valid);
        assert_ne!(VerificationStatus::Valid, VerificationStatus::Timeout);
    }
} 