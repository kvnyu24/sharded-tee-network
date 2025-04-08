// Liveness module entry point

pub mod types;
pub mod challenger; // Placeholder for Algorithm 4 challenger logic
pub mod aggregator; // Placeholder for Algorithm 4 aggregator logic

// Re-export key types
pub use types::{LivenessState, Nonce, NonceChallenge, AttestationResponse, VerificationStatus}; 