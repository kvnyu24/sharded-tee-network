// Liveness Aggregator logic (Algorithm 4)

use crate::data_structures::TEEIdentity;
use crate::liveness::types::{
    LivenessAttestation, VerificationResult, LivenessState, LivenessConfig, ChallengeNonce
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
 // Add Verifier trait
use std::time::Duration;
use tokio::time::timeout; // Import timeout for batching
use crate::simulation::runtime::SimulationRuntime; // Import
 // Import SimulationConfig
use crate::simulation::metrics::MetricEvent; 

// Aggregator TEE responsible for verifying liveness attestations
pub struct Aggregator {
    // Identity of the aggregator node itself
    identity: TEEIdentity,
    config: LivenessConfig,
    // Shared state needs Arc<Mutex<...>>
    liveness_states: Arc<Mutex<HashMap<usize, LivenessState>>>, 
    node_identities: Arc<Mutex<HashMap<usize, TEEIdentity>>>, 
    runtime: SimulationRuntime, // Keep runtime for report_isolated_nodes
    metrics_tx: Option<mpsc::Sender<MetricEvent>>, // Store metrics sender
    // Store the most recent challenge issued to each node
    pending_challenges: Arc<Mutex<HashMap<usize, ChallengeNonce>>>, 
    // challenge_rx is returned by new()
}

impl Aggregator {
    // Return the aggregator instance AND the receiver
    pub fn new(
        identity: TEEIdentity,
        config: LivenessConfig, 
        initial_nodes: Vec<TEEIdentity>,
        runtime: SimulationRuntime, 
        metrics_tx: Option<mpsc::Sender<MetricEvent>>, // Accept metrics sender
        challenge_rx: mpsc::Receiver<ChallengeNonce>, 
    ) -> (Self, mpsc::Receiver<ChallengeNonce>) {
        let mut liveness_states_map = HashMap::new();
        let mut node_identities_map = HashMap::new();

        for node in initial_nodes {
            let node_id = node.id;
            liveness_states_map.insert(node_id, LivenessState::new(&config));
            node_identities_map.insert(node_id, node);
        }

        let aggregator = Aggregator {
            identity,
            config,
            liveness_states: Arc::new(Mutex::new(liveness_states_map)),
            node_identities: Arc::new(Mutex::new(node_identities_map)),
            runtime, 
            metrics_tx, // Store the passed sender
            pending_challenges: Arc::new(Mutex::new(HashMap::new())), 
        };
        
        (aggregator, challenge_rx)
    }

    // Process a batch of received attestations and update liveness states
    pub async fn process_attestation_batch(&self, batch: Vec<LivenessAttestation>) {
        println!("[Aggregator {}] Received batch of {} attestations. Processing...", self.identity.id, batch.len());

        let mut received_attestations = HashMap::new();
        for attestation in batch {
            received_attestations.insert(attestation.node_id, attestation);
        }

        // Lock necessary state maps
        let mut states_guard = self.liveness_states.lock().await;
        let identities_guard = self.node_identities.lock().await;
        let mut pending_guard = self.pending_challenges.lock().await;
        
        // Get node IDs from the current liveness state map
        let node_ids: Vec<usize> = states_guard.keys().cloned().collect();

        for node_id in node_ids {
            // Get mutable access to state - must check if node still exists
            if let Some(state) = states_guard.get_mut(&node_id) {
                let identity = identities_guard.get(&node_id).expect("Identity must exist if state exists");

                let verification_result = match received_attestations.get(&node_id) {
                    Some(attestation) => {
                        // Check if we were expecting a challenge response
                        if let Some(expected_challenge) = pending_guard.get(&node_id) {
                            // 1. Verify Nonce
                            if attestation.nonce != expected_challenge.nonce {
                                println!("[Aggregator {}] Nonce mismatch for Node {}: Expected {:?}, Got {:?}",
                                         self.identity.id, node_id, expected_challenge.nonce, attestation.nonce);
                                VerificationResult::NonceMismatch
                            } 
                            // 2. Verify Timestamp
                            else if attestation.timestamp != expected_challenge.timestamp {
                                 println!("[Aggregator {}] Timestamp mismatch for Node {}: Expected {}, Got {}",
                                          self.identity.id, node_id, expected_challenge.timestamp, attestation.timestamp);
                                 VerificationResult::TimestampMismatch
                            } 
                            // 3. Verify Signature
                            else {
                                let mut message = Vec::new();
                                message.extend_from_slice(&node_id.to_ne_bytes());
                                message.extend_from_slice(&attestation.nonce);
                                message.extend_from_slice(&attestation.timestamp.to_ne_bytes());
                                
                                // Use crypto_sim::verify and pass delays from self.config
                                let verify_min_ms = self.config.tee_delays.verify_min_ms;
                                let verify_max_ms = self.config.tee_delays.verify_max_ms;

                                // Call async verify using self.metrics_tx
                                let is_valid = crate::tee_logic::crypto_sim::verify(
                                    &message,
                                    &attestation.signature,
                                    &identity.public_key,
                                    verify_min_ms,
                                    verify_max_ms,
                                    &self.metrics_tx, // Use stored metrics_tx
                                    &Some(self.identity.clone()),
                                ).await;

                                // Check result
                                if is_valid {
                                        // Valid attestation matching pending challenge
                                        // Remove the pending challenge after successful verification
                                        // We clone the result because we still hold the pending_guard lock
                                        let result = VerificationResult::Valid;
                                        pending_guard.remove(&node_id);
                                        println!("[Aggregator {}] Attestation from Node {} verified successfully. Pending challenge removed.", self.identity.id, node_id);
                                        result
                                } else {
                                        println!("[Aggregator {}] Invalid signature from node {}", self.identity.id, node_id);
                                        VerificationResult::InvalidSignature
                                }
                            }
                        } else {
                            // No pending challenge found for this node - unsolicited attestation?
                            println!("[Aggregator {}] Received attestation from Node {} but no pending challenge found.", self.identity.id, node_id);
                            VerificationResult::NonceMismatch // Treat as NonceMismatch for penalty
                        }
                    }
                    None => {
                        // No attestation received in this batch. 
                        // Timeout logic will handle penalties for genuinely missed challenges.
                        // We skip processing/penalizing based on absence in this *specific* batch.
                        continue; // Go to next node_id without updating state
                    }
                };

                // Update Liveness State based on verification result
                match verification_result {
                    VerificationResult::Valid => {
                        state.trust_score += self.config.trust_increment;
                        state.consecutive_failures = 0;
                        // Optional: Clamp trust score?
                    }
                    // All failure types result in penalty and removal of pending challenge
                    failure_type => { 
                        println!("[Aggregator {}] Verification failed for Node {} ({:?}). Applying penalty.", self.identity.id, node_id, failure_type);
                        state.trust_score -= self.config.trust_decrement;
                        state.trust_score = state.trust_score.max(0.0); // Clamp minimum score
                        state.consecutive_failures += 1;
                        // Remove pending challenge on any failure to prevent repeated penalties for the same stale challenge
                        pending_guard.remove(&node_id);
                    }
                }
                 println!("[Aggregator {}] Updated state for node {}: Score={}, Fails={}",
                          self.identity.id, node_id, state.trust_score, state.consecutive_failures);
            } // end if let Some(state)
        } // end for node_id

        // Drop MutexGuards explicitly after the loop
        drop(states_guard);
        drop(identities_guard);
        drop(pending_guard);
    }

    // Identify nodes that have failed too many consecutive challenges
    pub async fn identify_and_isolate_nodes(&self) -> Vec<usize> {
        println!("[Aggregator {}] Identifying nodes to isolate based on consecutive failures...", self.identity.id);
        let mut nodes_to_isolate = Vec::new();
        let states = self.liveness_states.lock().await;
        for (node_id, state) in states.iter() {
            if state.consecutive_failures >= self.config.max_failures {
                println!("[Aggregator {}] Node {} marked for isolation ({} consecutive failures >= threshold {}).",
                         self.identity.id, node_id, state.consecutive_failures, self.config.max_failures);
                nodes_to_isolate.push(*node_id);
            }
        }
        nodes_to_isolate
    }

    // Main run loop for the aggregator task (Not used directly anymore, but kept for reference)
    /*
    pub async fn run(&mut self, mut attestation_rx: mpsc::Receiver<LivenessAttestation>) {
        println!("[Aggregator {}] Starting run loop...", self.identity.id);
        
        let batch_timeout = Duration::from_secs(1); // Collect attestations for 1 second
        let mut batch = Vec::new();

        loop {
            match timeout(batch_timeout, attestation_rx.recv()).await {
                Ok(Some(attestation)) => {
                    // Received an attestation before timeout
                    batch.push(attestation);
                }
                Ok(None) => {
                    // Channel closed, exit loop
                    println!("[Aggregator {}] Attestation channel closed. Exiting run loop.", self.identity.id);
                    break;
                }
                Err(_) => {
                    // Timeout elapsed
                    if !batch.is_empty() {
                        println!("[Aggregator {}] Batch timeout reached. Processing {} attestations.", self.identity.id, batch.len());
                        // Process the collected batch
                        self.process_attestation_batch(batch.drain(..).collect()).await;
                        
                        // After processing, check for nodes to isolate
                        let nodes_to_isolate = self.identify_and_isolate_nodes().await;
                        if !nodes_to_isolate.is_empty() {
                            println!("[Aggregator {}] Sending isolation report for nodes: {:?}", self.identity.id, nodes_to_isolate);
                            // Send isolation report via runtime
                            self.runtime.report_isolated_nodes(nodes_to_isolate).await;
                        }
                    }
                }
            }
        }
    }
    */

    // NEW: Run loop for listening to challenge info from Challenger
    // This task needs to own the receiver.
    pub async fn run_challenge_listener(self: Arc<Self>, mut challenge_rx: mpsc::Receiver<ChallengeNonce>) {
        println!("[Aggregator {}] Starting challenge listener run loop...", self.identity.id);
        
        while let Some(challenge) = challenge_rx.recv().await {
            println!("[Aggregator {}] Received challenge info for Node {}: Nonce={:?}", self.identity.id, challenge.target_node_id, challenge.nonce);
            let mut pending_guard = self.pending_challenges.lock().await;
            // Only insert if no challenge is currently pending for this node
            // Use entry API for efficiency
            use std::collections::hash_map::Entry;
            if let Entry::Vacant(e) = pending_guard.entry(challenge.target_node_id) {
                println!("[Aggregator {}] Inserting new pending challenge for Node {}.", self.identity.id, challenge.target_node_id); // Added log
                e.insert(challenge);
            } else {
                 println!("[Aggregator {}] Ignoring new challenge info for Node {} as one is already pending.", self.identity.id, challenge.target_node_id); // Added log
            }
            drop(pending_guard);
        }
        
        println!("[Aggregator {}] Challenge listener loop finished (channel closed).", self.identity.id);
    }

    // run_attestation_listener also needs adjustment if it was using self.attestation_rx (it wasn't)
    // It should take Arc<Self> and the attestation_rx receiver
    pub async fn run_attestation_listener(self: Arc<Self>, mut attestation_rx: mpsc::Receiver<LivenessAttestation>) {
        println!("[Aggregator {}] Starting attestation listener run loop...", self.identity.id);
        
        let batch_timeout = Duration::from_secs(1); // Collect attestations for 1 second
        let mut batch = Vec::new();

        loop {
            match timeout(batch_timeout, attestation_rx.recv()).await {
                Ok(Some(attestation)) => {
                    batch.push(attestation);
                }
                Ok(None) => {
                    println!("[Aggregator {}] Attestation channel closed. Exiting run loop.", self.identity.id);
                    break;
                }
                Err(_) => {
                    if !batch.is_empty() {
                        println!("[Aggregator {}] Batch timeout reached. Processing {} attestations.", self.identity.id, batch.len());
                        // process_attestation_batch takes &self, so cloning Arc is fine
                        self.process_attestation_batch(batch.drain(..).collect()).await;
                        
                        // identify_and_isolate_nodes takes &self
                        let nodes_to_isolate = self.identify_and_isolate_nodes().await;
                        if !nodes_to_isolate.is_empty() {
                            println!("[Aggregator {}] Sending isolation report for nodes: {:?}", self.identity.id, nodes_to_isolate);
                            // runtime field access is fine via Arc
                            self.runtime.report_isolated_nodes(nodes_to_isolate).await;
                        }
                    }
                }
            }
        }
    }

    // NEW: Task to periodically check for timed-out challenges
    pub async fn run_timeout_checker(self: Arc<Self>) {
        // --- Add very early log --- 
        println!("!!! [Aggregator {}][Timeout] run_timeout_checker task has STARTED !!!", self.identity.id);

        // Check interval slightly shorter than the window to catch timeouts reliably
        let check_interval = self.config.challenge_window / 2; 
        let mut interval = tokio::time::interval(check_interval);
        println!("[Aggregator {}] Starting timeout checker loop (Interval: {:?})...", self.identity.id, check_interval);

        loop {
            interval.tick().await;
            println!("[Aggregator {}][Timeout] Checker task running...", self.identity.id);
            let current_time_millis = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            
            let challenge_window_millis = self.config.challenge_window.as_millis() as u64;
            let mut timed_out_nodes = Vec::new();

            // --- First pass: Identify timed-out nodes --- 
            {
                let pending_guard = self.pending_challenges.lock().await;
                 println!("[Aggregator {}][Timeout] Checking {} pending challenges.", self.identity.id, pending_guard.len());
                for (node_id, challenge) in pending_guard.iter() {
                    let time_since_challenge = current_time_millis.saturating_sub(challenge.timestamp);
                     println!("[Aggregator {}][Timeout] Checking Node {}: Time since challenge = {}ms (Window: {}ms)",
                              self.identity.id, node_id, time_since_challenge, challenge_window_millis);
                    if time_since_challenge > challenge_window_millis {
                        // --- ADD LOG 1 --- 
                        println!("!!! [Aggregator {}][Timeout] DETECTED timeout for Node {} !!!", self.identity.id, node_id);
                        // --- END LOG 1 --- 
                        println!("[Aggregator {}][Timeout] Detected timeout for Node {}. Challenge timestamp: {}, Current: {}, Window: {}",
                                 self.identity.id, node_id, challenge.timestamp, current_time_millis, challenge_window_millis);
                        timed_out_nodes.push(*node_id);
                    }
                }
            } // Drop pending_guard lock

            // --- Second pass: Apply penalties and remove --- 
            if !timed_out_nodes.is_empty() {
                println!("[Aggregator {}][Timeout] Applying penalties for timed-out nodes: {:?}", self.identity.id, timed_out_nodes);
                let mut states_guard = self.liveness_states.lock().await;
                let mut pending_guard = self.pending_challenges.lock().await;

                for node_id in &timed_out_nodes {
                    // Remove the timed-out challenge regardless of state update success
                    if pending_guard.remove(node_id).is_some() {
                         println!("[Aggregator {}][Timeout] Removed pending challenge for Node {}", self.identity.id, node_id);
                    }

                    // Apply penalty if the node's state still exists
                    if let Some(state) = states_guard.get_mut(node_id) {
                        println!("[Aggregator {}][Timeout] Penalizing Node {}", self.identity.id, node_id);
                        state.trust_score -= self.config.trust_decrement;
                        state.trust_score = state.trust_score.max(0.0); // Clamp minimum score
                        state.consecutive_failures += 1;
                        // --- ADD LOG 2 --- 
                        println!("!!! [Aggregator {}][Timeout] APPLIED penalty to Node {}. New failure count: {} !!!",
                                 self.identity.id, node_id, state.consecutive_failures);
                        // --- END LOG 2 --- 
                         println!("[Aggregator {}][Timeout] Updated state for node {}: Score={}, Fails={}",
                                  self.identity.id, node_id, state.trust_score, state.consecutive_failures);
                    } else {
                         println!("[Aggregator {}][Timeout] Node {} state not found, cannot apply penalty (already removed?).", self.identity.id, node_id);
                    }
                }
                // Drop locks after loop
                drop(states_guard);
                drop(pending_guard);

                // --- Third pass: Check for isolation --- 
                // Check if any penalized nodes now need isolation
                let nodes_to_isolate = self.identify_and_isolate_nodes().await;
                // --- ADD LOG 3 --- 
                println!("!!! [Aggregator {}][Timeout] identify_and_isolate_nodes result: {:?} !!!", self.identity.id, nodes_to_isolate);
                // --- END LOG 3 ---
                if !nodes_to_isolate.is_empty() {
                    println!("[Aggregator {}][Timeout] Sending isolation report triggered by timeouts for nodes: {:?}", self.identity.id, nodes_to_isolate);
                    self.runtime.report_isolated_nodes(nodes_to_isolate).await;
                }
            }
        }
        // println!("[Aggregator] Timeout checker loop finished."); // Loop should ideally run forever
    }

    // --- Remove old verification methods --- 
    /*
    pub fn verify_attestations(...) -> ... {}
    fn verify_single_response(...) -> ... {}
    pub fn expect_nonce(...) {}
    */
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simulation::runtime::SimulationRuntime;
    use crate::simulation::config::SimulationConfig;
     
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    
    use std::sync::Arc;
    use crate::data_structures::TEEIdentity;
    use crate::liveness::types::{LivenessConfig, ChallengeNonce, LivenessAttestation};
    use std::time::Duration;

    // Helper to create TEE Identity and SigningKey
    fn create_test_tee(id: usize) -> (TEEIdentity, SigningKey) {
        let mut csprng = OsRng{};
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        let identity = TEEIdentity { id, public_key: signing_key.verifying_key() };
        (identity, signing_key)
    }

    // Test setup helper updated
    async fn setup_aggregator_test(
        config: LivenessConfig,
        initial_nodes: Vec<TEEIdentity>,
    ) -> (
        Arc<Aggregator>,
        mpsc::Sender<ChallengeNonce>,
        mpsc::Sender<LivenessAttestation>,
        SimulationRuntime,
        mpsc::Receiver<Vec<usize>>,
        mpsc::Sender<MetricEvent>,
    ) {
        let (challenge_tx, challenge_rx_for_aggregator) = mpsc::channel::<ChallengeNonce>(100);
        let (attestation_tx, attestation_rx) = mpsc::channel::<LivenessAttestation>(100);

        // Create SimulationRuntime and get metrics handle
        let (runtime, _result_rx, isolation_rx, _metrics_join_handle) = 
            SimulationRuntime::new(SimulationConfig::default());
        let (metrics_tx_for_agg, _metrics_rx_test) = mpsc::channel::<MetricEvent>(100); 

        let (aggregator_identity, _) = create_test_tee(0); // ID 0 for aggregator

        // Pass runtime and the extracted metrics_tx
        let (aggregator_instance, _challenge_rx_returned_by_new) = Aggregator::new(
            aggregator_identity,
            config,
            initial_nodes,
            runtime.clone(),
            Some(metrics_tx_for_agg.clone()), // Pass the test sender
            challenge_rx_for_aggregator,
        );

        let aggregator = Arc::new(aggregator_instance);

        // Spawn the aggregator's attestation listener loop
        let agg_clone_attestation = aggregator.clone();
        tokio::spawn(async move {
             agg_clone_attestation.run_attestation_listener(attestation_rx).await;
        });

        (aggregator, challenge_tx, attestation_tx, runtime, isolation_rx, metrics_tx_for_agg)
    }

    #[tokio::test]
    async fn aggregator_initialization() {
        let config = LivenessConfig::default();
        let (node1_id, _) = create_test_tee(1);
        let (node2_id, _) = create_test_tee(2);
        let initial_nodes = vec![node1_id.clone(), node2_id.clone()];
        
        // Use the setup helper which now returns Arc<Aggregator> and metrics_tx
        let (aggregator, _challenge_tx, _attestation_tx, _runtime, _isolation_rx, _metrics_tx) =
            setup_aggregator_test(config.clone(), initial_nodes).await;
        
        // Check aggregator identity
        assert_eq!(aggregator.identity.id, 0); // Check the assigned ID

        // Access fields through the Arc
        let identities = aggregator.node_identities.lock().await;
        assert_eq!(identities.len(), 2);
        assert!(identities.contains_key(&1));
        assert!(identities.contains_key(&2));
        drop(identities); // Drop lock
        
        let states = aggregator.liveness_states.lock().await;
        assert_eq!(states.len(), 2);
        assert!(states.contains_key(&1));
        assert!(states.contains_key(&2));
        let state1 = states.get(&1).unwrap();
        assert_eq!(state1.trust_score, config.default_trust);
        assert_eq!(state1.consecutive_failures, 0);
        let expected_interval = (config.min_interval + config.max_interval) / 2;
        assert_eq!(state1.challenge_interval, expected_interval);
        drop(states); // Drop lock
    }

    #[tokio::test]
    async fn test_process_attestation_batch_and_isolate() {
        let mut config = LivenessConfig::default();
        config.max_failures = 2; // Lower threshold for easier testing
        config.trust_decrement = 60.0; // Faster trust decrease

        let (node1_id, node1_sk) = create_test_tee(1);
        let (node2_id, node2_sk) = create_test_tee(2);
        let (node3_id, node3_sk) = create_test_tee(3);
        let initial_nodes = vec![node1_id.clone(), node2_id.clone(), node3_id.clone()];

        // Use updated setup_aggregator_test, capture metrics_tx
        let (aggregator, _challenge_tx, _attestation_tx, _runtime, mut isolation_rx, _metrics_tx) =
            setup_aggregator_test(config, initial_nodes).await;

        // Let's manually add the challenges to the pending_challenges map for direct testing.
        {
             let mut pending_guard = aggregator.pending_challenges.lock().await;
             let nonce1 = [1u8; 32];
             let nonce2 = [2u8; 32];
             let nonce3 = [3u8; 32];
             let ts: u64 = 1000;
             pending_guard.insert(1, ChallengeNonce { nonce: nonce1, target_node_id: 1, timestamp: ts });
             pending_guard.insert(2, ChallengeNonce { nonce: nonce2, target_node_id: 2, timestamp: ts });
             pending_guard.insert(3, ChallengeNonce { nonce: nonce3, target_node_id: 3, timestamp: ts });
             println!("[Test Setup] Manually inserted pending challenges.");
        } // drop lock

        // Create attestations (Node 2 has invalid signature)
        let nonce1 = [1u8; 32];
        let nonce2 = [2u8; 32];
        let nonce3 = [3u8; 32];
        let ts: u64 = 1000; // Explicitly type ts as u64
        let msg1 = [1_usize.to_ne_bytes().as_slice(), &nonce1, &ts.to_ne_bytes()].concat();
        let sig1 = node1_sk.sign(&msg1);
        let att1 = LivenessAttestation { node_id: 1, nonce: nonce1, timestamp: ts, signature: sig1 };

        let msg2 = [2_usize.to_ne_bytes().as_slice(), &nonce2, &ts.to_ne_bytes()].concat();
        let sig2_invalid = node2_sk.sign(b"wrong_message"); // Invalid signature
        let att2 = LivenessAttestation { node_id: 2, nonce: nonce2, timestamp: ts, signature: sig2_invalid };

        let msg3 = [3_usize.to_ne_bytes().as_slice(), &nonce3, &ts.to_ne_bytes()].concat();
        let sig3 = node3_sk.sign(&msg3);
        let att3 = LivenessAttestation { node_id: 3, nonce: nonce3, timestamp: ts, signature: sig3 };

        // Process batch 1 (Node 2 fails)
        // tokio::time::sleep(Duration::from_millis(50)).await; // Not needed if not using channels
        println!("[Test] Processing batch 1...");
        aggregator.process_attestation_batch(vec![att1.clone(), att2.clone(), att3.clone()]).await;
        println!("[Test] Batch 1 processed.");

        // Check states after batch 1
        {
            let states = aggregator.liveness_states.lock().await;
            assert!(states.get(&1).unwrap().trust_score > 100.0);
            assert_eq!(states.get(&1).unwrap().consecutive_failures, 0);
            assert!(states.get(&2).unwrap().trust_score < 100.0);
            assert_eq!(states.get(&2).unwrap().consecutive_failures, 1);
            assert!(states.get(&3).unwrap().trust_score > 100.0);
            assert_eq!(states.get(&3).unwrap().consecutive_failures, 0);
            assert!(isolation_rx.try_recv().is_err(), "No isolation expected yet");
        }

        // Simulate another round of challenges (manual insertion)
        {
             let mut pending_guard = aggregator.pending_challenges.lock().await;
             let nonce1b = [11u8; 32];
             let nonce2b = [22u8; 32];
             let nonce3b = [33u8; 32];
             let ts_b: u64 = 2000; // Explicitly type ts_b as u64
             pending_guard.insert(1, ChallengeNonce { nonce: nonce1b, target_node_id: 1, timestamp: ts_b });
             pending_guard.insert(2, ChallengeNonce { nonce: nonce2b, target_node_id: 2, timestamp: ts_b });
             pending_guard.insert(3, ChallengeNonce { nonce: nonce3b, target_node_id: 3, timestamp: ts_b });
              println!("[Test Setup] Manually inserted round 2 pending challenges.");
        } // drop lock

        // Create attestations for round 2 (Node 2 fails again)
        let nonce1b = [11u8; 32];
        let nonce2b = [22u8; 32];
        let nonce3b = [33u8; 32];
        let ts_b: u64 = 2000; // Explicitly type ts_b as u64
        let msg1b = [1_usize.to_ne_bytes().as_slice(), &nonce1b, &ts_b.to_ne_bytes()].concat();
        let sig1b = node1_sk.sign(&msg1b);
        let att1b = LivenessAttestation { node_id: 1, nonce: nonce1b, timestamp: ts_b, signature: sig1b };

        let msg2b = [2_usize.to_ne_bytes().as_slice(), &nonce2b, &ts_b.to_ne_bytes()].concat();
        let sig2b_invalid = node2_sk.sign(b"another_wrong_message"); // Invalid signature
        let att2b = LivenessAttestation { node_id: 2, nonce: nonce2b, timestamp: ts_b, signature: sig2b_invalid };

        let msg3b = [3_usize.to_ne_bytes().as_slice(), &nonce3b, &ts_b.to_ne_bytes()].concat();
        let sig3b = node3_sk.sign(&msg3b);
        let att3b = LivenessAttestation { node_id: 3, nonce: nonce3b, timestamp: ts_b, signature: sig3b };

        // Process batch 2 (Node 2 fails again, reaches isolation threshold)
        // tokio::time::sleep(Duration::from_millis(50)).await; // Not needed
        println!("[Test] Processing batch 2...");
        aggregator.process_attestation_batch(vec![att1b.clone(), att2b.clone(), att3b.clone()]).await;
         println!("[Test] Batch 2 processed.");

        // Check states after batch 2
        {
            let states = aggregator.liveness_states.lock().await;
            assert!(states.get(&1).unwrap().trust_score > 100.0);
            assert_eq!(states.get(&1).unwrap().consecutive_failures, 0);
            assert!(states.get(&2).unwrap().trust_score < 40.0); // 100 - 60 - 60 = -20, clamped to 0
            assert_eq!(states.get(&2).unwrap().consecutive_failures, 2);
            assert!(states.get(&3).unwrap().trust_score > 100.0);
            assert_eq!(states.get(&3).unwrap().consecutive_failures, 0);
        }

        // Explicitly check for isolation after processing the batch in the test
        let nodes_to_isolate = aggregator.identify_and_isolate_nodes().await;
        if !nodes_to_isolate.is_empty() {
            println!("[Test][IsolationTrigger] Sending isolation report for nodes: {:?}", nodes_to_isolate);
            aggregator.runtime.report_isolated_nodes(nodes_to_isolate).await;
        }

        // Check for isolation report immediately after processing the invalid attestation
        match timeout(Duration::from_secs(1), isolation_rx.recv()).await {
            Ok(Some(isolated_nodes)) => {
                assert_eq!(isolated_nodes, vec![2], "Node 2 should be isolated");
            }
            _ => panic!("Did not receive expected isolation report for Node 2"),
        } 
    }

    #[tokio::test]
    async fn test_process_valid_attestation() {
        let config = LivenessConfig::default();
        let (node1_id, node1_sk) = create_test_tee(1);
        let initial_nodes = vec![node1_id.clone()];
        // Use updated setup_aggregator_test, ignore channel senders
        let (aggregator, _, _, _, _, _) =
            setup_aggregator_test(config, initial_nodes).await;

        // Manually add pending challenge
        let nonce = [1u8; 32];
        let ts = 1000;
        {
            let mut pending_guard = aggregator.pending_challenges.lock().await;
             pending_guard.insert(1, ChallengeNonce { nonce, target_node_id: 1, timestamp: ts });
        }

        let msg = [1_usize.to_ne_bytes().as_slice(), &nonce, &ts.to_ne_bytes()].concat();
        let sig = node1_sk.sign(&msg);
        let att = LivenessAttestation { node_id: 1, nonce, timestamp: ts, signature: sig };

        // Process directly
        aggregator.process_attestation_batch(vec![att]).await;

            let states = aggregator.liveness_states.lock().await;
            let state1 = states.get(&1).unwrap();
        assert!(state1.trust_score > 100.0);
            assert_eq!(state1.consecutive_failures, 0);
    }

    #[tokio::test]
    async fn test_process_invalid_signature_attestation() {
        let config = LivenessConfig::default();
        let (node1_id, node1_sk) = create_test_tee(1);
        let initial_nodes = vec![node1_id.clone()];
        let (aggregator, _, _, _, _, _) =
            setup_aggregator_test(config, initial_nodes).await;

        // Manually add pending challenge
        let nonce = [2u8; 32];
        let ts = 2000;
         {
             let mut pending_guard = aggregator.pending_challenges.lock().await;
             pending_guard.insert(1, ChallengeNonce { nonce, target_node_id: 1, timestamp: ts });
        }

        let _msg = [1_usize.to_ne_bytes().as_slice(), &nonce, &ts.to_ne_bytes()].concat();
        let invalid_sig = node1_sk.sign(b"wrong message"); // Sign wrong data
        let att = LivenessAttestation { node_id: 1, nonce, timestamp: ts, signature: invalid_sig };

        // Process directly
        aggregator.process_attestation_batch(vec![att]).await;

            let states = aggregator.liveness_states.lock().await;
            let state1 = states.get(&1).unwrap();
        assert!(state1.trust_score < 100.0);
            assert_eq!(state1.consecutive_failures, 1);
    }
    
    #[tokio::test]
    async fn test_process_nonce_mismatch_attestation() {
         let config = LivenessConfig::default();
        let (node1_id, node1_sk) = create_test_tee(1);
        let initial_nodes = vec![node1_id.clone()];
        let (aggregator, _, _, _, _, _) =
            setup_aggregator_test(config, initial_nodes).await;

        let correct_nonce = [3u8; 32];
        let wrong_nonce = [99u8; 32];
        let ts = 3000;
         {
             let mut pending_guard = aggregator.pending_challenges.lock().await;
             pending_guard.insert(1, ChallengeNonce { nonce: correct_nonce, target_node_id: 1, timestamp: ts });
        }

        let msg = [1_usize.to_ne_bytes().as_slice(), &wrong_nonce, &ts.to_ne_bytes()].concat(); // Use wrong nonce in msg for sig
        let sig = node1_sk.sign(&msg);
        let att = LivenessAttestation { node_id: 1, nonce: wrong_nonce, timestamp: ts, signature: sig }; // Send wrong nonce

        // Process directly
        aggregator.process_attestation_batch(vec![att]).await;

            let states = aggregator.liveness_states.lock().await;
            let state1 = states.get(&1).unwrap();
        assert!(state1.trust_score < 100.0);
            assert_eq!(state1.consecutive_failures, 1);
    }
    
    #[tokio::test]
    async fn test_isolation_report_triggered() {
        let mut config = LivenessConfig::default();
        config.max_failures = 1; // Isolate after one failure
        config.trust_decrement = 101.0; // Ensure trust drops below threshold immediately
        config.challenge_window = Duration::from_millis(100); // Timeout window for the challenge
        config.min_interval = Duration::from_millis(10); // Faster timeout checks
        config.max_interval = Duration::from_millis(20);

        let (node1_id, node1_sk) = create_test_tee(1);
        let (node2_id, _node2_sk) = create_test_tee(2); // Node 2 will be ignored
        let initial_nodes = vec![node1_id.clone(), node2_id.clone()];
        let (aggregator, _challenge_tx, _attestation_tx, runtime, mut isolation_rx, _metrics_tx) =
            setup_aggregator_test(config.clone(), initial_nodes).await;
        
        // Need to manually insert challenge for test to work without listener
        let nonce1 = [5u8; 32];
        let ts1 = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
         {
             let mut pending_guard = aggregator.pending_challenges.lock().await;
             pending_guard.insert(1, ChallengeNonce { nonce: nonce1, target_node_id: 1, timestamp: ts1 });
         }

        // Node 1 fails to respond - simulate an invalid attestation instead of timeout for quicker check
        let invalid_sig = node1_sk.sign(b"wrong message");
        let invalid_att = LivenessAttestation {
            node_id: 1,
            nonce: nonce1, // Correct nonce
            timestamp: ts1, // Correct timestamp
            signature: invalid_sig, // Invalid signature
        };

        // Process directly
        aggregator.process_attestation_batch(vec![invalid_att]).await;

        // Explicitly check for isolation after processing the batch in the test
        let nodes_to_isolate = aggregator.identify_and_isolate_nodes().await;
        if !nodes_to_isolate.is_empty() {
            println!("[Test][IsolationTrigger] Sending isolation report for nodes: {:?}", nodes_to_isolate);
            aggregator.runtime.report_isolated_nodes(nodes_to_isolate).await;
        }

        // Check for isolation report immediately after processing the invalid attestation
        match timeout(Duration::from_secs(1), isolation_rx.recv()).await {
            Ok(Some(isolated_nodes)) => {
                assert_eq!(isolated_nodes, vec![1], "Node 1 should be isolated due to failure");
            }
            Ok(None) => panic!("Isolation channel closed unexpectedly"),
            Err(_) => panic!("Did not receive expected isolation report for Node 1 within timeout"),
        }
    }

    #[tokio::test]
    async fn test_timeout_checker() {
        let mut config = LivenessConfig::default();
        config.challenge_window = Duration::from_millis(100); // Short timeout window
        config.min_interval = Duration::from_millis(10); // Frequent checks
        config.max_interval = Duration::from_millis(20);
        config.max_failures = 1; // Isolate after one failure
        config.trust_decrement = 101.0; // Ensure trust drops below threshold

        let (node1_id, _node1_sk) = create_test_tee(1);
        let (node2_id, _node2_sk) = create_test_tee(2);
        let initial_nodes = vec![node1_id.clone(), node2_id.clone()];
        let (aggregator, _challenge_tx, _attestation_tx, runtime, mut isolation_rx, metrics_tx) =
            setup_aggregator_test(config.clone(), initial_nodes).await;

        // Run only the timeout checker loop in the background for this test
        let agg_clone_timeout = aggregator.clone();
        let _handle = tokio::spawn(async move { // Use the clone in the task
             println!("!!! [Test] Spawning run_timeout_checker task..."); // Add log
             agg_clone_timeout.run_timeout_checker().await;
        });

        // Add a small delay to allow the timeout checker to start its internal loop
        tokio::time::sleep(Duration::from_millis(50)).await; // Increased delay slightly

        // Simulate a challenge being issued for Node 1 by MANUALLY adding it
        // We don't use challenge_tx here because the listener isn't running
        let nonce1 = [4u8; 32];
        let ts1 = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        {
            let mut pending_guard = aggregator.pending_challenges.lock().await;
            pending_guard.insert(1, ChallengeNonce { nonce: nonce1, target_node_id: 1, timestamp: ts1 });
            println!("[Test][Timeout] Manually inserted challenge for Node 1 at ts {}", ts1);
        }

        // Wait for longer than the challenge window to trigger the timeout checker
        println!("[Test][Timeout] Waiting for challenge window ({}ms) + buffer...", config.challenge_window.as_millis());
        tokio::time::sleep(config.challenge_window + Duration::from_millis(50)).await;
        println!("[Test][Timeout] Wait finished. Checking for isolation report...");

        // Node 1 should have timed out and been penalized.
        // With max_failures = 1, it should be isolated.
        match timeout(Duration::from_secs(2), isolation_rx.recv()).await {
            Ok(Some(isolated_nodes)) => {
                assert_eq!(isolated_nodes, vec![1], "Node 1 should be isolated due to timeout");
                println!("[Test][Timeout] Received correct isolation report for Node 1.");
            }
            Ok(None) => panic!("[Test][Timeout] Isolation channel closed unexpectedly"),
            Err(_) => panic!("[Test][Timeout] Did not receive expected isolation report for Node 1 within timeout"),
        }
    }

    // Add more tests: timestamp mismatch, unsolicited attestations, multiple nodes timing out, etc.

} 