// teeshard-protocol/src/tee_logic/crypto_sim.rs

// Simplified cryptographic operations for simulation purposes

// Re-export types from the actual crypto library for consistency
pub use ed25519_dalek::{
    Signature,
    Signer,
    SigningKey as SecretKey, // Alias for clarity
    VerifyingKey as PublicKey, // Alias for clarity
    Verifier
};
use rand::rngs::OsRng;
use tokio::time::{Duration, sleep}; // Import sleep and Duration
use rand::Rng; // Import Rng trait for random number generation

// Helper function to generate a random delay within a range
async fn random_delay(min_ms: u64, max_ms: u64) {
    if max_ms == 0 { return; } // No delay if max is 0
    let delay_ms = if min_ms >= max_ms {
        min_ms
    } else {
        rand::thread_rng().gen_range(min_ms..=max_ms)
    };
    if delay_ms > 0 {
        sleep(Duration::from_millis(delay_ms)).await;
    }
}

// Generate a new keypair (secret and public key)
pub fn generate_keypair() -> SecretKey {
    // In a real scenario, this would involve interaction with secure hardware/enclaves
    SecretKey::generate(&mut OsRng)
}

// Sign a message using a secret key
// Make async and add delay simulation
pub async fn sign(message: &[u8], key: &SecretKey, min_delay_ms: u64, max_delay_ms: u64) -> Signature {
    // Simulate TEE signing overhead
    random_delay(min_delay_ms, max_delay_ms).await;

    // Actual signing operation
    key.sign(message)
}

// Verify a signature using a public key
// Make async and add delay simulation
pub async fn verify(message: &[u8], signature: &Signature, public_key: &PublicKey, min_delay_ms: u64, max_delay_ms: u64) -> bool {
    // Simulate TEE verification overhead
    random_delay(min_delay_ms, max_delay_ms).await;

    // Actual verification operation
    public_key.verify(message, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*; // Import items from the outer module
    use tokio::runtime::Runtime; // For running async tests
    use tokio::time::Instant; // For timing

    // Helper to run async tests
    fn run_async<F>(future: F) -> F::Output
    where
        F: std::future::Future,
    {
        Runtime::new().unwrap().block_on(future)
    }

    #[test]
    fn keypair_generation() {
        // Synchronous test
        let keypair = generate_keypair();
        let public_key = keypair.verifying_key();
        assert!(true); // Basic check that generation doesn't panic
        let _ = public_key; // Avoid unused variable warning
    }

    #[test]
    fn sign_and_verify_ok_async() {
        run_async(async {
            let keypair = generate_keypair();
            let public_key = keypair.verifying_key();
            let message = b"This is a test message.";

            // Sign with no delay
            let signature = sign(message, &keypair, 0, 0).await;

            // Verify with no delay
            let is_valid = verify(message, &signature, &public_key, 0, 0).await;
            assert!(is_valid, "Signature should be valid");
        });
    }

    #[test]
    fn verify_fails_wrong_key_async() {
        run_async(async {
            let keypair1 = generate_keypair();
            let keypair2 = generate_keypair(); // Different keypair
            let public_key2 = keypair2.verifying_key();
            let message = b"Another test message.";

            let signature = sign(message, &keypair1, 0, 0).await; // Sign with key 1

            // Verify with key 2 (should fail)
            let is_valid = verify(message, &signature, &public_key2, 0, 0).await;
            assert!(!is_valid, "Verification should fail with the wrong public key");
        });
    }

    #[test]
    fn verify_fails_tampered_message_async() {
        run_async(async {
            let keypair = generate_keypair();
            let public_key = keypair.verifying_key();
            let message = b"Original message.";
            let tampered_message = b"Tampered message.";

            let signature = sign(message, &keypair, 0, 0).await;

            // Verify with tampered message (should fail)
            let is_valid = verify(tampered_message, &signature, &public_key, 0, 0).await;
            assert!(!is_valid, "Verification should fail with a tampered message");
        });
    }

    #[test]
    fn sign_adds_delay_async() {
        run_async(async {
            let keypair = generate_keypair();
            let message = b"Message with signing delay.";
            let min_delay = 50;
            let max_delay = 55;

            let start = Instant::now();
            let _signature = sign(message, &keypair, min_delay, max_delay).await;
            let duration = start.elapsed();

            assert!(duration >= Duration::from_millis(min_delay), "Signing took less than minimum delay. Took: {:?}", duration);
             // Add a small buffer for timing inaccuracies if needed
            // assert!(duration <= Duration::from_millis(max_delay + 10), "Signing took longer than maximum delay (with buffer). Took: {:?}", duration);
        });
    }

    #[test]
    fn verify_adds_delay_async() {
        run_async(async {
            let keypair = generate_keypair();
            let public_key = keypair.verifying_key();
            let message = b"Message with verification delay.";
            let min_delay = 60;
            let max_delay = 65;

            let signature = sign(message, &keypair, 0, 0).await; // Sign without delay

            let start = Instant::now();
            let _is_valid = verify(message, &signature, &public_key, min_delay, max_delay).await;
            let duration = start.elapsed();

            assert!(duration >= Duration::from_millis(min_delay), "Verification took less than minimum delay. Took: {:?}", duration);
            // assert!(duration <= Duration::from_millis(max_delay + 10), "Verification took longer than maximum delay (with buffer). Took: {:?}", duration);
        });
    }
} 