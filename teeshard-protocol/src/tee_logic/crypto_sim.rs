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
use crate::simulation::metrics::MetricEvent; // Add metrics import
use tokio::sync::mpsc; // Add mpsc import
use std::time::Instant; // Add Instant import
use crate::data_structures::TEEIdentity; // Add TEEIdentity import

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

// Helper to send metric if sender is provided
async fn send_metric(
    metrics_tx: &Option<mpsc::Sender<MetricEvent>>, 
    node_id: &Option<TEEIdentity>, 
    function_name: String, 
    start_time: Instant
) {
    if let (Some(tx), Some(id)) = (metrics_tx.as_ref(), node_id.as_ref()) {
        let duration = start_time.elapsed();
        let event = MetricEvent::TeeFunctionMeasured {
            node_id: id.clone(),
            function_name,
            duration,
        };
        let tx_clone = tx.clone();
        let id_clone = id.clone(); // Clone for error logging
        tokio::spawn(async move {
            if let Err(e) = tx_clone.send(event).await {
                // eprintln!("[crypto_sim {}] Failed to send metric: {}", id_clone.id, e); // Avoid excessive logging
            }
        });
    }
}

// Sign a message using a secret key
// Make async and add delay simulation
pub async fn sign(
    message: &[u8], 
    key: &SecretKey, 
    min_delay_ms: u64, 
    max_delay_ms: u64,
    // Add optional metrics params
    metrics_tx: &Option<mpsc::Sender<MetricEvent>>, 
    node_id: &Option<TEEIdentity>, 
) -> Signature {
    let start_time = Instant::now();
    let function_name = "sign".to_string();

    // Simulate TEE signing overhead (delay)
    random_delay(min_delay_ms, max_delay_ms).await;

    // Actual signing operation (measure this part)
    let work_start_time = Instant::now();
    let signature = key.sign(message);
    let work_duration = work_start_time.elapsed(); // Measure only the core work

    // Send metric for the core work duration
    if let (Some(tx), Some(id)) = (metrics_tx.as_ref(), node_id.as_ref()) {
        let event = MetricEvent::TeeFunctionMeasured {
            node_id: id.clone(),
            function_name: function_name.clone(), // Function name is just "sign"
            duration: work_duration, // Send the work duration, not total
        };
        let tx_clone = tx.clone();
        let id_clone = id.clone(); // Clone for error logging
        tokio::spawn(async move {
            if let Err(e) = tx_clone.send(event).await {
                // eprintln!("[crypto_sim {}] Failed to send sign metric: {}", id_clone.id, e);
            }
        });
    }
    
    // The function returns the signature, total time is implicitly measured by caller if needed
    signature
}

// Verify a signature using a public key
// Make async and add delay simulation
pub async fn verify(
    message: &[u8], 
    signature: &Signature, 
    public_key: &PublicKey, 
    min_delay_ms: u64, 
    max_delay_ms: u64,
    // Add optional metrics params
    metrics_tx: &Option<mpsc::Sender<MetricEvent>>, 
    node_id: &Option<TEEIdentity>,
) -> bool {
     let start_time = Instant::now();
    let function_name = "verify".to_string();
    
    // Simulate TEE verification overhead
    random_delay(min_delay_ms, max_delay_ms).await;

    // Actual verification operation (measure this part)
    let work_start_time = Instant::now();
    let is_ok = public_key.verify(message, signature).is_ok();
    let work_duration = work_start_time.elapsed();

    // Send metric for the core work duration
    if let (Some(tx), Some(id)) = (metrics_tx.as_ref(), node_id.as_ref()) {
        let event = MetricEvent::TeeFunctionMeasured {
            node_id: id.clone(),
            function_name: function_name.clone(), // Function name is just "verify"
            duration: work_duration, // Send the work duration, not total
        };
        let tx_clone = tx.clone();
        let id_clone = id.clone(); // Clone for error logging
        tokio::spawn(async move {
            if let Err(e) = tx_clone.send(event).await {
                 // eprintln!("[crypto_sim {}] Failed to send verify metric: {}", id_clone.id, e);
            }
        });
    }
    
    is_ok
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
            let signature = sign(message, &keypair, 0, 0, &None, &None).await;

            // Verify with no delay
            let is_valid = verify(message, &signature, &public_key, 0, 0, &None, &None).await;
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

            let signature = sign(message, &keypair1, 0, 0, &None, &None).await; // Sign with key 1

            // Verify with key 2 (should fail)
            let is_valid = verify(message, &signature, &public_key2, 0, 0, &None, &None).await;
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

            let signature = sign(message, &keypair, 0, 0, &None, &None).await;

            // Verify with tampered message (should fail)
            let is_valid = verify(tampered_message, &signature, &public_key, 0, 0, &None, &None).await;
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
            // Pass None for metrics params in test
            let _signature = sign(message, &keypair, min_delay, max_delay, &None, &None).await;
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

            let signature = sign(message, &keypair, 0, 0, &None, &None).await; // Sign without delay

            let start = Instant::now();
            // Pass None for metrics params in test
            let _is_valid = verify(message, &signature, &public_key, min_delay, max_delay, &None, &None).await;
            let duration = start.elapsed();

            assert!(duration >= Duration::from_millis(min_delay), "Verification took less than minimum delay. Took: {:?}", duration);
            // assert!(duration <= Duration::from_millis(max_delay + 10), "Verification took longer than maximum delay (with buffer). Took: {:?}", duration);
        });
    }
} 