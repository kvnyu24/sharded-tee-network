// Placeholder for Liveness Challenger logic (Algorithm 4)

use crate::data_structures::TEEIdentity;
use crate::liveness::types::{Nonce, NonceChallenge};
use rand::Rng;
use crate::tee_logic::crypto_sim::generate_keypair; // Import key generation

// Represents a TEE node acting as a challenger
pub struct Challenger {
    pub identity: TEEIdentity,
    // Potentially track last challenge times per target node if stateful
}

impl Challenger {
    pub fn new(identity: TEEIdentity) -> Self {
        Challenger { identity }
    }

    // Issue a nonce challenge to a target TEE node
    pub fn issue_nonce_challenge(&self, target_tee: &TEEIdentity) -> NonceChallenge {
        let nonce: Nonce = rand::thread_rng().gen();
        println!(
            "Challenger ({}): Issuing nonce {} to TEE {}",
            self.identity.id,
            nonce,
            target_tee.id
        );
        NonceChallenge {
            target_tee: target_tee.clone(),
            nonce,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_tee(id: usize) -> TEEIdentity {
        // Create TEEIdentity with usize ID and a real public key
        let keypair = generate_keypair();
        TEEIdentity { id, public_key: keypair.verifying_key() }
    }

    #[test]
    fn challenger_creation() {
        let tee_id = create_test_tee(10);
        let challenger = Challenger::new(tee_id.clone());
        assert_eq!(challenger.identity, tee_id);
    }

    #[test]
    fn issue_nonce_challenge() {
        let challenger_id = create_test_tee(10);
        let target_id = create_test_tee(20);
        let challenger = Challenger::new(challenger_id);

        let challenge1 = challenger.issue_nonce_challenge(&target_id);
        let challenge2 = challenger.issue_nonce_challenge(&target_id);

        assert_eq!(challenge1.target_tee, target_id);
        assert_eq!(challenge2.target_tee, target_id);
        // Nonces should be different (highly likely with random generation)
        assert_ne!(challenge1.nonce, challenge2.nonce);
    }
} 