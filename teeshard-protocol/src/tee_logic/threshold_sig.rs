// Threshold Signature generation and verification

use crate::data_structures::TEEIdentity; // Remove unused: LockProofData, ShardId, Signature
// Use the real Signature type
use crate::tee_logic::types::Signature;
 // Use BTreeMap for deterministic iteration, HashSet for verify_multi
// Import crypto sim components
use crate::tee_logic::crypto_sim::{PublicKey, verify};
use crate::tee_logic::enclave_sim::TeeDelayConfig; // Correct path
 // Need Arc for passing config
use crate::simulation::metrics::MetricEvent; // Import MetricEvent
use tokio::sync::mpsc; // Import mpsc
use std::time::{Duration, Instant}; // Import Instant
use tokio::time::sleep; // Import sleep
use rand::Rng; // Import Rng for random_delay
use std::collections::HashMap; // Add this import

// Represents a signature share from a single TEE
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialSignature {
    pub signer_id: TEEIdentity,
    // Store the actual Ed25519 signature
    pub signature_data: Signature,
}

/// Aggregates partial signatures until a threshold is met.
#[derive(Debug, Clone)]
pub struct ThresholdAggregator {
    message: Vec<u8>,
    threshold: usize,
    committee: HashMap<TEEIdentity, PublicKey>,
    partial_signatures: HashMap<TEEIdentity, Signature>,
    combined_signature: Option<Signature>, // Store the final signature
    delay_config: TeeDelayConfig,
    // Add metrics sender and node ID
    metrics_tx: Option<mpsc::Sender<MetricEvent>>,
    node_id: Option<TEEIdentity>,
}

impl ThresholdAggregator {
    /// Creates a new ThresholdAggregator.
    pub fn new(
        message: Vec<u8>,
        threshold: usize,
        committee: HashMap<TEEIdentity, PublicKey>,
        delay_config: TeeDelayConfig,
        // Accept metrics sender and node ID
        metrics_tx: Option<mpsc::Sender<MetricEvent>>,
        node_id: Option<TEEIdentity>,
    ) -> Self {
        ThresholdAggregator {
            message,
            threshold,
            committee,
            partial_signatures: HashMap::new(),
            combined_signature: None,
            delay_config,
            // Store metrics fields
            metrics_tx,
            node_id,
        }
    }

    /// Adds a partial signature from a TEE node.
    pub async fn add_partial_signature(&mut self, signer_id: TEEIdentity, signature: Signature) -> Result<bool, String> {
        // Check if the signer is part of the committee
        let public_key = match self.committee.get(&signer_id) {
            Some(pk) => pk,
            None => return Err(format!("Signer {} is not part of the committee.", signer_id.id)),
        };

        // Verify the partial signature (uses TEE simulation delay)
        let is_valid = verify(
            &self.message,
            &signature,
            public_key,
            self.delay_config.verify_min_ms,
            self.delay_config.verify_max_ms,
            &self.metrics_tx,
            &self.node_id,
        ).await;

        if !is_valid {
            return Err(format!("Invalid partial signature from signer {}.
", signer_id.id));
        }

        // Add the valid signature if not already present
        if self.partial_signatures.insert(signer_id, signature).is_none() {
            // Check if the threshold is met
            if self.partial_signatures.len() >= self.threshold {
                match self.aggregate_signatures().await {
                    Ok(combined_sig) => {
                        self.combined_signature = Some(combined_sig);
                        return Ok(true); // Threshold met and aggregation successful
                    }
                    Err(e) => {
                        // Aggregation failed, log error but don't block forever
                        eprintln!("Error aggregating signatures: {}", e); // Keep this minimal
                        return Err(format!("Failed to aggregate signatures after reaching threshold: {}", e));
                    }
                }
            }
        }

        Ok(false) // Threshold not yet met or signature was a duplicate
    }

    /// Attempts to aggregate the collected partial signatures.
    /// This is a simplified placeholder. Real aggregation is complex.
    async fn aggregate_signatures(&self) -> Result<Signature, String> {
        let start_time = Instant::now();
        let function_name = "aggregate_signatures".to_string();

        // Simulate aggregation overhead
        random_delay(self.delay_config.sign_min_ms, self.delay_config.sign_max_ms).await;

        // **Placeholder:** Real aggregation is complex.
        // Here, sort keys by ID and take the first one's signature.
        if self.partial_signatures.len() >= self.threshold {
            // Sort keys by ID to deterministically pick one
            let mut sorted_keys: Vec<&TEEIdentity> = self.partial_signatures.keys().collect();
            sorted_keys.sort_by_key(|k| k.id);
            
            let chosen_signer_id = sorted_keys.first()
                .ok_or("No signatures available to aggregate after sorting")?;
            
            let work_duration = start_time.elapsed(); // Measure including the simulated delay

            // Send metric
            if let (Some(tx), Some(id)) = (self.metrics_tx.as_ref(), self.node_id.as_ref()) {
                let event = MetricEvent::TeeFunctionMeasured {
                    node_id: id.clone(),
                    function_name,
                    duration: work_duration, // includes simulated delay
                };
                let tx_clone = tx.clone();
                let _id_clone = id.clone(); // Prefix unused clone
                 tokio::spawn(async move {
                    if let Err(_e) = tx_clone.send(event).await { // Prefix unused error
                        // eprintln!("[threshold_sig {}] Failed to send aggregate metric: {}", _id_clone.id, _e);
                    }
                });
            }

            // Return the chosen signature (PLACEHOLDER)
            Ok(self.partial_signatures[*chosen_signer_id].clone())
        } else {
            Err(format!("Threshold not met. Required: {}, Available: {}", self.threshold, self.partial_signatures.len()))
        }
    }

    /// Verifies the combined multi-signature against the message.
    /// This currently just verifies the placeholder 'combined' signature.
    pub async fn verify_multi_signature(&self, combined_signature: &Signature) -> bool {
         // In a real threshold scheme, verification uses the combined signature
        // and the group's public key. Here we just verify the placeholder.
        // Find the public key corresponding to the placeholder signature (first signer by ID).
        let mut sorted_keys: Vec<&TEEIdentity> = self.partial_signatures.keys().collect();
        sorted_keys.sort_by_key(|k| k.id);

        if let Some(chosen_signer_id) = sorted_keys.first() {
             if let Some(pk) = self.committee.get(chosen_signer_id) {
                 verify(
                    &self.message,
                    combined_signature,
                    pk, // Use the specific signer's PK for the placeholder
                    self.delay_config.verify_min_ms,
                    self.delay_config.verify_max_ms,
                    &self.metrics_tx, // Pass metrics sender
                    &self.node_id,    // Pass node ID
                ).await
            } else {
                false // Signer not found (shouldn't happen if aggregation succeeded)
            }
        } else {
            false // No signatures were ever added
        }
    }

    /// Returns the combined signature if the threshold has been met and aggregation was successful.
    pub fn get_combined_signature(&self) -> Option<&Signature> {
        self.combined_signature.as_ref()
    }

    /// Returns the number of valid partial signatures collected so far.
    pub fn signature_count(&self) -> usize {
        self.partial_signatures.len()
    }

    /// Returns the required threshold for this aggregator.
    pub fn get_threshold(&self) -> usize {
        self.threshold
    }
}

// Helper function to generate a random delay within a range
// Moved outside the test module
async fn random_delay(min_ms: u64, max_ms: u64) {
    if min_ms == 0 && max_ms == 0 {
        return; // No delay configured
    }
    let delay_ms = if min_ms >= max_ms {
        min_ms
    } else {
        rand::thread_rng().gen_range(min_ms..=max_ms)
    };
    if delay_ms > 0 {
        sleep(Duration::from_millis(delay_ms)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Comment out unresolved import
    // use crate::test_utils::run_async; 
    use crate::tee_logic::crypto_sim::{self, SecretKey};
    use std::collections::HashMap;
    
    

    // Helper to create identities and keys for tests
    fn setup_committee(num_nodes: usize) -> (Vec<TEEIdentity>, HashMap<TEEIdentity, PublicKey>, Vec<SecretKey>) {
        let mut identities = Vec::new();
        let mut public_keys = HashMap::new();
        let mut secret_keys = Vec::new();

        for i in 0..num_nodes {
            let secret_key = crypto_sim::generate_keypair();
            let public_key = secret_key.verifying_key().clone();
            let identity = TEEIdentity { id: i, public_key: public_key.clone() };
            identities.push(identity.clone());
            public_keys.insert(identity.clone(), public_key);
            secret_keys.push(secret_key);
        }
        (identities, public_keys, secret_keys)
    }

    // Basic test for successful aggregation
    #[tokio::test]
    async fn threshold_aggregation_success() {
        // run_async(async {
            let num_nodes = 5;
        let threshold = 3;
            let (identities, committee, secret_keys) = setup_committee(num_nodes);
            let message = b"Test message for threshold signature".to_vec();
            let delay_config = TeeDelayConfig::default(); // No delay for simplicity
            let (metrics_tx, mut metrics_rx) = mpsc::channel(100); // Mock metrics channel
            let node_id = Some(identities[0].clone()); // Mock node ID

            let mut aggregator = ThresholdAggregator::new(
                message.clone(),
                threshold,
                committee.clone(),
                delay_config,
                Some(metrics_tx.clone()), // Pass the sender
                node_id,
            );

            let mut threshold_met = false;
            for i in 0..threshold {
                // Sign synchronously for test simplicity
                // Pass borrowed &None
                let sig = crypto_sim::sign(&message, &secret_keys[i], 0, 0, &None, &None).await;
                let result = aggregator.add_partial_signature(identities[i].clone(), sig).await;
                assert!(result.is_ok());
                threshold_met = result.unwrap();
                if threshold_met {
                    break;
                }
            }

            assert!(threshold_met, "Threshold should have been met");
            assert!(aggregator.get_combined_signature().is_some(), "Combined signature should be available");
            assert_eq!(aggregator.signature_count(), threshold);

            // Wait briefly for the async metric tasks to send
            tokio::time::sleep(Duration::from_millis(50)).await; // Increased sleep slightly

            // Expect `threshold` number of "verify" metrics, followed by one "aggregate"
            for i in 0..threshold {
                match tokio::time::timeout(Duration::from_millis(100), metrics_rx.recv()).await {
                    Ok(Some(MetricEvent::TeeFunctionMeasured { function_name, node_id: metric_node_id, .. })) => {
                        assert_eq!(function_name, "verify", "Expected metric for verify on signature {}", i);
                        assert_eq!(metric_node_id, identities[0], "Metric node ID mismatch for verify {}", i);
                    }
                    Ok(Some(other)) => panic!("Received unexpected metric type while expecting verify {}: {:?}", i, other),
                    Ok(None) => panic!("Metrics channel closed unexpectedly before verify metric {}", i),
                    Err(_) => panic!("Timeout waiting for verify metric event {}", i),
                }
            }

            // Now expect the "aggregate_signatures" metric
            match tokio::time::timeout(Duration::from_millis(100), metrics_rx.recv()).await {
                Ok(Some(MetricEvent::TeeFunctionMeasured { function_name, node_id: metric_node_id, .. })) => {
                    assert_eq!(function_name, "aggregate_signatures", "Expected metric for aggregate_signatures");
                    assert_eq!(metric_node_id, identities[0], "Metric node ID mismatch for aggregate");
                }
                Ok(Some(other)) => panic!("Received unexpected metric type while expecting aggregate: {:?}", other),
                Ok(None) => panic!("Metrics channel closed unexpectedly before aggregate metric"),
                Err(_) => panic!("Timeout waiting for aggregate_signatures metric event"),
            }

            // Ensure no more metrics are unexpectedly sent
            assert!(metrics_rx.try_recv().is_err(), "Should be no more metrics");

        // }); // End run_async if used
    }

    // Test adding a signature from a node not in the committee
    #[tokio::test]
    async fn add_signature_from_non_committee_member() {
        // run_async(async {
             let (identities, committee, _) = setup_committee(3);
            let message = b"Test message".to_vec();
            let delay_config = TeeDelayConfig::default();
            let (metrics_tx, _) = mpsc::channel(100);
            let node_id = Some(identities[0].clone());

            let mut aggregator = ThresholdAggregator::new(
                message.clone(),
                2,
                committee,
                delay_config,
                Some(metrics_tx),
                node_id.clone(),
            );

            // Create a non-committee identity and key
            let non_committee_sk = crypto_sim::generate_keypair();
            let non_committee_pk = non_committee_sk.verifying_key().clone();
            let non_committee_id = TEEIdentity { id: 99, public_key: non_committee_pk }; // Add pk
            // Pass aggregator metrics config to sign
            let signature = crypto_sim::sign(&message, &non_committee_sk, 0, 0, &aggregator.metrics_tx, &aggregator.node_id).await;

            let result = aggregator.add_partial_signature(non_committee_id.clone(), signature).await;
            assert!(result.is_err(), "Adding signature from non-committee member should fail");
            assert!(result.clone().unwrap_err().contains("not part of the committee"), "Error message mismatch: {}", result.unwrap_err());
        // });
    }

    // Test adding an invalid signature (e.g., wrong message signed)
    #[tokio::test]
    async fn add_invalid_signature() {
         // run_async(async {
            let (identities, committee, secret_keys) = setup_committee(3);
            let message = b"Correct message".to_vec();
            let wrong_message = b"Wrong message".to_vec();
            let delay_config = TeeDelayConfig::default();
             let (metrics_tx, _) = mpsc::channel(100);
             let node_id = Some(identities[0].clone());

            let mut aggregator = ThresholdAggregator::new(
                message.clone(),
                2,
                committee,
                delay_config,
                Some(metrics_tx),
                node_id.clone(),
            );

            // Sign the *wrong* message
            // Pass aggregator metrics config to sign
            let signature = crypto_sim::sign(&wrong_message, &secret_keys[0], 0, 0, &aggregator.metrics_tx, &aggregator.node_id).await;

            let result = aggregator.add_partial_signature(identities[0].clone(), signature).await;
            assert!(result.is_err(), "Adding invalid signature should fail");
            assert!(result.clone().unwrap_err().contains("Invalid partial signature"), "Error message mismatch: {}", result.unwrap_err());
         // });
    }

    // Test adding a duplicate signature from the same signer
    #[tokio::test]
    async fn duplicate_signature_ignored() {
        // run_async(async {
            let (identities, committee, secret_keys) = setup_committee(3);
            let message = b"Test message".to_vec();
            let delay_config = TeeDelayConfig::default();
            let (metrics_tx, _) = mpsc::channel(100);
            let node_id = Some(identities[0].clone());

            let mut aggregator = ThresholdAggregator::new(
                message.clone(),
                2,
                committee,
                delay_config,
                Some(metrics_tx),
                node_id.clone(),
            );

            // Add the first signature
            // Pass aggregator metrics config to sign
            let signature1 = crypto_sim::sign(&message, &secret_keys[0], 0, 0, &aggregator.metrics_tx, &aggregator.node_id).await;
            let result1 = aggregator.add_partial_signature(identities[0].clone(), signature1.clone()).await;
            assert!(result1.is_ok() && !result1.unwrap(), "First signature add failed or met threshold unexpectedly");
            assert_eq!(aggregator.partial_signatures.len(), 1);

            // Add the same signature again
            let result2 = aggregator.add_partial_signature(identities[0].clone(), signature1).await;
            assert!(result2.is_ok() && !result2.unwrap(), "Duplicate signature add failed or met threshold unexpectedly");
            assert_eq!(aggregator.partial_signatures.len(), 1, "Duplicate signature should not increase count");
            assert!(aggregator.get_combined_signature().is_none());

             // Add a different signature to meet threshold
             // Pass aggregator metrics config to sign
             let signature2 = crypto_sim::sign(&message, &secret_keys[1], 0, 0, &aggregator.metrics_tx, &aggregator.node_id).await;
             let result3 = aggregator.add_partial_signature(identities[1].clone(), signature2).await;
             assert!(result3.is_ok() && result3.unwrap(), "Second unique signature failed to meet threshold");
             assert_eq!(aggregator.partial_signatures.len(), 2);
             assert!(aggregator.get_combined_signature().is_some());
        // });
    }

    // Test scenario where threshold is not met
    #[tokio::test]
    async fn threshold_not_met() {
        // run_async(async {
            let (identities, committee, secret_keys) = setup_committee(5);
        let threshold = 3;
            let message = b"Test message".to_vec();
            let delay_config = TeeDelayConfig::default();
            let (metrics_tx, _) = mpsc::channel(100);
            let node_id = Some(identities[0].clone());

            let mut aggregator = ThresholdAggregator::new(
                message.clone(),
                threshold,
                committee,
                delay_config,
                Some(metrics_tx),
                node_id.clone(),
            );

            // Add fewer signatures than the threshold
            for i in 0..(threshold - 1) {
                // Pass aggregator metrics config to sign
                let signature = crypto_sim::sign(&message, &secret_keys[i], 0, 0, &aggregator.metrics_tx, &aggregator.node_id).await;
                let result = aggregator.add_partial_signature(identities[i].clone(), signature).await;
                assert!(result.is_ok() && !result.unwrap(), "Signature add failed or met threshold too early");
            }

            assert_eq!(aggregator.partial_signatures.len(), threshold - 1);
            assert!(aggregator.get_combined_signature().is_none(), "Combined signature should be None when threshold is not met");

            // Attempting aggregation directly (though internal) should fail
            let aggregation_result = aggregator.aggregate_signatures().await;
            assert!(aggregation_result.is_err(), "Direct aggregation should fail if threshold not met");
            assert!(aggregation_result.unwrap_err().contains("Threshold not met"));
        // });
    }
} 