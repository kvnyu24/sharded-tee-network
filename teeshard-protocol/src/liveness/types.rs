// Define types related to TEE Liveness Verification (Algorithm 4)

use crate::data_structures::TEEIdentity;
use crate::tee_logic::types::AttestationReport;
use std::time::{Duration, Instant};
use ed25519_dalek::Signature;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
// Import TeeDelayConfig
use crate::tee_logic::enclave_sim::TeeDelayConfig;

// Using simple u64 for nonce for now
pub type Nonce = u64;

// Represents a unique challenge sent to a TEE node
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChallengeNonce {
    pub nonce: [u8; 32], // Unique nonce value
    pub target_node_id: usize, // ID of the node being challenged
    pub timestamp: u64, // Timestamp when challenge was issued (e.g., milliseconds since epoch)
}

// Represents the attestation response from a TEE node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessAttestation {
    pub node_id: usize,
    pub nonce: [u8; 32], // Nonce received in the challenge
    pub timestamp: u64, // Timestamp from the original challenge
    pub signature: Signature, // Signature over (node_id || nonce || timestamp) or similar
    // Optionally include attestation report data if needed for deeper verification
    // pub attestation_report: Vec<u8>,
}

// Result of verifying a single liveness attestation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    Valid,
    InvalidSignature,
    NonceMismatch,
    TimestampMismatch,
    // Other potential error types
}

// Configuration parameters for the liveness system
#[derive(Debug, Clone)]
pub struct LivenessConfig {
    pub default_trust: f64,
    pub trust_increment: f64,
    pub trust_decrement: f64,
    pub trust_threshold: f64,
    pub high_trust_threshold: f64,
    pub min_interval: Duration,
    pub max_interval: Duration,
    pub max_failures: usize,
    // Consider adding challenge window duration
    pub challenge_window: Duration,
    // Add TEE delay config for verification
    pub tee_delays: TeeDelayConfig,
}

// Sensible defaults for configuration
impl Default for LivenessConfig {
    fn default() -> Self {
        LivenessConfig {
            default_trust: 100.0,
            trust_increment: 1.0,
            trust_decrement: 10.0,
            trust_threshold: 50.0,
            high_trust_threshold: 150.0,
            min_interval: Duration::from_secs(10),
            max_interval: Duration::from_secs(300),
            max_failures: 3,
            challenge_window: Duration::from_secs(5), // Example window
            // Default to no TEE delay
            tee_delays: TeeDelayConfig::default(),
        }
    }
}

// State maintained for each TEE node regarding liveness
#[derive(Debug, Clone)]
pub struct LivenessState {
    pub trust_score: f64,
    pub challenge_interval: Duration,
    pub last_challenge_time: Instant,
    pub consecutive_failures: usize,
}

impl LivenessState {
    // Constructor using LivenessConfig
    pub fn new(config: &LivenessConfig) -> Self {
        LivenessState {
            trust_score: config.default_trust,
            // Calculate initial interval based on config min/max
            challenge_interval: Duration::from_secs_f64(
                (config.min_interval.as_secs_f64() + config.max_interval.as_secs_f64()) / 2.0
            ),
            last_challenge_time: Instant::now(), // Initialize to current time
            consecutive_failures: 0,
        }
    }
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
        let config = LivenessConfig::default();
        let state = LivenessState::new(&config);
        assert_eq!(state.trust_score, 100.0);
        assert_eq!(state.consecutive_failures, 0);
        assert!(state.last_challenge_time <= Instant::now());
        // Check default delays were added
        assert_eq!(config.tee_delays.verify_min_ms, 0);
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