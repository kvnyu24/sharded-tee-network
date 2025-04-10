// Liveness Aggregator logic (Algorithm 4)

use crate::data_structures::TEEIdentity;
use crate::liveness::types::{
    LivenessAttestation, VerificationResult, LivenessState, LivenessConfig, ChallengeNonce
};
use crate::raft::{messages::RaftMessage, node::RaftNode};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Verifier}; // Add Verifier trait
use rand::rngs::OsRng;
use std::time::{Duration, Instant};
use tokio::time::timeout; // Import timeout for batching
use crate::simulation::runtime::SimulationRuntime; // Import
use crate::simulation::config::SimulationConfig; // Import SimulationConfig

// Aggregator TEE responsible for verifying liveness attestations
pub struct Aggregator {
    // Identity of the aggregator node itself (optional, could be implicit)
    // pub identity: TEEIdentity, 
    config: LivenessConfig,
    // Shared state needs Arc<Mutex<...>>
    liveness_states: Arc<Mutex<HashMap<usize, LivenessState>>>, 
    node_identities: Arc<Mutex<HashMap<usize, TEEIdentity>>>, 
    runtime: SimulationRuntime, 
    // Store the most recent challenge issued to each node
    pending_challenges: Arc<Mutex<HashMap<usize, ChallengeNonce>>>, 
    // Receiver for incoming challenge info from Challenger
    // challenge_rx is no longer stored here, it's returned by new()
}

impl Aggregator {
    // Return the aggregator instance AND the receiver
    pub fn new(
        config: LivenessConfig, 
        initial_nodes: Vec<TEEIdentity>,
        runtime: SimulationRuntime, 
        challenge_rx: mpsc::Receiver<ChallengeNonce>, 
    ) -> (Self, mpsc::Receiver<ChallengeNonce>) { // Return tuple
        let mut liveness_states_map = HashMap::new();
        let mut node_identities_map = HashMap::new();

        for node in initial_nodes {
            let node_id = node.id;
            liveness_states_map.insert(node_id, LivenessState::new(&config));
            node_identities_map.insert(node_id, node);
        }

        let aggregator = Aggregator {
            config,
            liveness_states: Arc::new(Mutex::new(liveness_states_map)),
            node_identities: Arc::new(Mutex::new(node_identities_map)),
            runtime, 
            pending_challenges: Arc::new(Mutex::new(HashMap::new())), 
            // Don't store challenge_rx
        };
        
        (aggregator, challenge_rx) // Return instance and receiver
    }

    // Process a batch of received attestations and update liveness states
    // Needs to lock shared state
    pub async fn process_attestation_batch(&self, batch: Vec<LivenessAttestation>) {
        println!("[Aggregator] Received batch of {} attestations. Processing...", batch.len());

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
                                println!("[Aggregator] Nonce mismatch for Node {}: Expected {:?}, Got {:?}", 
                                         node_id, expected_challenge.nonce, attestation.nonce);
                                VerificationResult::NonceMismatch
                            } 
                            // 2. Verify Timestamp
                            else if attestation.timestamp != expected_challenge.timestamp {
                                 println!("[Aggregator] Timestamp mismatch for Node {}: Expected {}, Got {}", 
                                          node_id, expected_challenge.timestamp, attestation.timestamp);
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
                                
                                // Call async verify
                                let is_valid = crate::tee_logic::crypto_sim::verify(
                                    &message, 
                                    &attestation.signature, 
                                    &identity.public_key, 
                                    verify_min_ms, 
                                    verify_max_ms
                                ).await;

                                // Check result
                                if is_valid {
                                        // Valid attestation matching pending challenge
                                        // Remove the pending challenge after successful verification
                                        // We clone the result because we still hold the pending_guard lock
                                        let result = VerificationResult::Valid;
                                        pending_guard.remove(&node_id);
                                        println!("[Aggregator] Attestation from Node {} verified successfully. Pending challenge removed.", node_id);
                                        result
                                } else {
                                        println!("[Aggregator] Invalid signature from node {}", node_id);
                                        VerificationResult::InvalidSignature
                                }
                            }
                        } else {
                            // No pending challenge found for this node - unsolicited attestation?
                            println!("[Aggregator] Received attestation from Node {} but no pending challenge found.", node_id);
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
                        println!("[Aggregator] Verification failed for Node {} ({:?}). Applying penalty.", node_id, failure_type);
                        state.trust_score -= self.config.trust_decrement;
                        state.trust_score = state.trust_score.max(0.0); // Clamp minimum score
                        state.consecutive_failures += 1;
                        // Remove pending challenge on any failure to prevent repeated penalties for the same stale challenge
                        pending_guard.remove(&node_id);
                    }
                }
                 println!("[Aggregator] Updated state for node {}: Score={}, Fails={}", 
                          node_id, state.trust_score, state.consecutive_failures);
            } // end if let Some(state)
        } // end for node_id

        // Drop MutexGuards explicitly after the loop
        drop(states_guard);
        drop(identities_guard);
        drop(pending_guard);
    }

    // Identify nodes that have failed too many consecutive challenges
    pub async fn identify_and_isolate_nodes(&self) -> Vec<usize> {
        println!("[Aggregator] Identifying nodes to isolate based on consecutive failures...");
        let mut nodes_to_isolate = Vec::new();
        let states = self.liveness_states.lock().await;
        for (node_id, state) in states.iter() {
            if state.consecutive_failures >= self.config.max_failures {
                println!("[Aggregator] Node {} marked for isolation ({} consecutive failures >= threshold {}).", 
                         node_id, state.consecutive_failures, self.config.max_failures);
                nodes_to_isolate.push(*node_id);
            }
        }
        nodes_to_isolate
    }

    // Main run loop for the aggregator task
    pub async fn run(&mut self, mut attestation_rx: mpsc::Receiver<LivenessAttestation>) {
        println!("[Aggregator] Starting run loop...");
        
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
                    println!("[Aggregator] Attestation channel closed. Exiting run loop.");
                    break;
                }
                Err(_) => {
                    // Timeout elapsed
                    if !batch.is_empty() {
                        println!("[Aggregator] Batch timeout reached. Processing {} attestations.", batch.len());
                        // Process the collected batch
                        self.process_attestation_batch(batch.drain(..).collect()).await;
                        
                        // After processing, check for nodes to isolate
                        let nodes_to_isolate = self.identify_and_isolate_nodes().await;
                        if !nodes_to_isolate.is_empty() {
                            println!("[Aggregator] Sending isolation report for nodes: {:?}", nodes_to_isolate);
                            // Send isolation report via runtime
                            self.runtime.report_isolated_nodes(nodes_to_isolate).await;
                        }
                    }
                }
            }
        }
    }

    // NEW: Run loop for listening to challenge info from Challenger
    // This task needs to own the receiver.
    pub async fn run_challenge_listener(self: Arc<Self>, mut challenge_rx: mpsc::Receiver<ChallengeNonce>) {
        println!("[Aggregator] Starting challenge listener run loop...");
        
        while let Some(challenge) = challenge_rx.recv().await {
            println!("[Aggregator] Received challenge info for Node {}: Nonce={:?}", challenge.target_node_id, challenge.nonce);
            let mut pending_guard = self.pending_challenges.lock().await;
            pending_guard.insert(challenge.target_node_id, challenge);
            drop(pending_guard);
        }
        
        println!("[Aggregator] Challenge listener loop finished (channel closed).");
    }

    // run_attestation_listener also needs adjustment if it was using self.attestation_rx (it wasn't)
    // It should take Arc<Self> and the attestation_rx receiver
    pub async fn run_attestation_listener(self: Arc<Self>, mut attestation_rx: mpsc::Receiver<LivenessAttestation>) {
        println!("[Aggregator] Starting attestation listener run loop...");
        
        let batch_timeout = Duration::from_secs(1); // Collect attestations for 1 second
        let mut batch = Vec::new();

        loop {
            match timeout(batch_timeout, attestation_rx.recv()).await {
                Ok(Some(attestation)) => {
                    batch.push(attestation);
                }
                Ok(None) => {
                    println!("[Aggregator] Attestation channel closed. Exiting run loop.");
                    break;
                }
                Err(_) => {
                    if !batch.is_empty() {
                        println!("[Aggregator] Batch timeout reached. Processing {} attestations.", batch.len());
                        // process_attestation_batch takes &self, so cloning Arc is fine
                        self.process_attestation_batch(batch.drain(..).collect()).await;
                        
                        // identify_and_isolate_nodes takes &self
                        let nodes_to_isolate = self.identify_and_isolate_nodes().await;
                        if !nodes_to_isolate.is_empty() {
                            println!("[Aggregator] Sending isolation report for nodes: {:?}", nodes_to_isolate);
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
        println!("!!! [Aggregator][Timeout] run_timeout_checker task has STARTED !!!"); 

        // Check interval slightly shorter than the window to catch timeouts reliably
        let check_interval = self.config.challenge_window / 2; 
        let mut interval = tokio::time::interval(check_interval);
        println!("[Aggregator] Starting timeout checker loop (Interval: {:?})...", check_interval);

        loop {
            interval.tick().await;
            println!("[Aggregator][Timeout] Checker task running...");
            let current_time_millis = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            
            let challenge_window_millis = self.config.challenge_window.as_millis() as u64;
            let mut timed_out_nodes = Vec::new();

            // --- First pass: Identify timed-out nodes --- 
            {
                let pending_guard = self.pending_challenges.lock().await;
                 println!("[Aggregator][Timeout] Checking {} pending challenges.", pending_guard.len());
                for (node_id, challenge) in pending_guard.iter() {
                    let time_since_challenge = current_time_millis.saturating_sub(challenge.timestamp);
                     println!("[Aggregator][Timeout] Checking Node {}: Time since challenge = {}ms (Window: {}ms)", 
                              node_id, time_since_challenge, challenge_window_millis);
                    if time_since_challenge > challenge_window_millis {
                        // --- ADD LOG 1 --- 
                        println!("!!! [Aggregator][Timeout] DETECTED timeout for Node {} !!!", node_id);
                        // --- END LOG 1 --- 
                        println!("[Aggregator][Timeout] Detected timeout for Node {}. Challenge timestamp: {}, Current: {}, Window: {}", 
                                 node_id, challenge.timestamp, current_time_millis, challenge_window_millis);
                        timed_out_nodes.push(*node_id);
                    }
                }
            } // Drop pending_guard lock

            // --- Second pass: Apply penalties and remove --- 
            if !timed_out_nodes.is_empty() {
                println!("[Aggregator][Timeout] Applying penalties for timed-out nodes: {:?}", timed_out_nodes);
                let mut states_guard = self.liveness_states.lock().await;
                let mut pending_guard = self.pending_challenges.lock().await;

                for node_id in &timed_out_nodes {
                    // Remove the timed-out challenge regardless of state update success
                    if pending_guard.remove(node_id).is_some() {
                         println!("[Aggregator][Timeout] Removed pending challenge for Node {}", node_id);
                    }

                    // Apply penalty if the node's state still exists
                    if let Some(state) = states_guard.get_mut(node_id) {
                        println!("[Aggregator][Timeout] Penalizing Node {}", node_id);
                        state.trust_score -= self.config.trust_decrement;
                        state.trust_score = state.trust_score.max(0.0); // Clamp minimum score
                        state.consecutive_failures += 1;
                        // --- ADD LOG 2 --- 
                        println!("!!! [Aggregator][Timeout] APPLIED penalty to Node {}. New failure count: {} !!!", 
                                 node_id, state.consecutive_failures);
                        // --- END LOG 2 --- 
                         println!("[Aggregator][Timeout] Updated state for node {}: Score={}, Fails={}", 
                                  node_id, state.trust_score, state.consecutive_failures);
                    } else {
                         println!("[Aggregator][Timeout] Node {} state not found, cannot apply penalty (already removed?).", node_id);
                    }
                }
                // Drop locks after loop
                drop(states_guard);
                drop(pending_guard);

                // --- Third pass: Check for isolation --- 
                // Check if any penalized nodes now need isolation
                let nodes_to_isolate = self.identify_and_isolate_nodes().await;
                // --- ADD LOG 3 --- 
                println!("!!! [Aggregator][Timeout] identify_and_isolate_nodes result: {:?} !!!", nodes_to_isolate);
                // --- END LOG 3 ---
                if !nodes_to_isolate.is_empty() {
                    println!("[Aggregator][Timeout] Sending isolation report triggered by timeouts for nodes: {:?}", nodes_to_isolate);
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
    use crate::simulation::runtime::SimulationRuntime; // Import
    use crate::tee_logic::crypto_sim::SecretKey; 
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey}; // Remove Keypair
    use rand::rngs::OsRng;
    use tokio::sync::Mutex as TokioMutex;

    // Helper to create TEE Identity and SigningKey
    fn create_test_tee(id: usize) -> (TEEIdentity, SigningKey) {
        let mut csprng = OsRng{};
        // Generate SigningKey directly if Keypair isn't needed elsewhere
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        let identity = TEEIdentity { id, public_key: signing_key.verifying_key() };
        (identity, signing_key)
    }

    // Test setup helper now returns challenge_rx separately
    async fn setup_aggregator_test(config: LivenessConfig, initial_nodes: Vec<TEEIdentity>) 
        -> (Arc<Aggregator>, mpsc::Sender<ChallengeNonce>, mpsc::Receiver<ChallengeNonce>, SimulationRuntime, mpsc::Receiver<Vec<usize>>) 
    {
        let (runtime, _, _, isolation_rx) = SimulationRuntime::new(SimulationConfig::default());
        let (challenge_tx, challenge_rx) = mpsc::channel(10);
        // Get aggregator instance and receiver separately
        let (aggregator_instance, challenge_rx_returned) = Aggregator::new(config, initial_nodes, runtime.clone(), challenge_rx);
        let aggregator_arc = Arc::new(aggregator_instance); // Wrap in Arc
        (aggregator_arc, challenge_tx, challenge_rx_returned, runtime, isolation_rx)
    }

    #[tokio::test]
    async fn aggregator_initialization() {
        let config = LivenessConfig::default();
        let (node1_id, _) = create_test_tee(1);
        let (node2_id, _) = create_test_tee(2);
        let initial_nodes = vec![node1_id.clone(), node2_id.clone()];
        
        // Use the setup helper which now returns Arc<Aggregator>
        let (aggregator, _challenge_tx, _challenge_rx_returned, _runtime, _isolation_rx) = 
            setup_aggregator_test(config.clone(), initial_nodes).await;
        
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
        // Setup
        let mut config = LivenessConfig::default();
        config.max_failures = 2; // Lower threshold for easier testing
        config.trust_decrement = 60.0; // Faster trust decrease

        let (node1_id, node1_sk) = create_test_tee(1);
        let (node2_id, node2_sk) = create_test_tee(2);
        let (node3_id, node3_sk) = create_test_tee(3);
        let initial_nodes = vec![node1_id.clone(), node2_id.clone(), node3_id.clone()];
        // Capture challenge_rx_returned
        let (aggregator, challenge_tx, challenge_rx_returned, runtime, mut isolation_rx) = 
            setup_aggregator_test(config, initial_nodes).await;

        // Spawn the challenge listener task
        let agg_clone_listener = aggregator.clone();
        tokio::spawn(async move {
            agg_clone_listener.run_challenge_listener(challenge_rx_returned).await;
        });

        // Simulate challenges being issued and stored
        let nonce1 = [1u8; 32];
        let nonce2 = [2u8; 32];
        let nonce3 = [3u8; 32];
        let ts = 1000;
        let challenge1 = ChallengeNonce { nonce: nonce1, target_node_id: 1, timestamp: ts };
        let challenge2 = ChallengeNonce { nonce: nonce2, target_node_id: 2, timestamp: ts };
        let challenge3 = ChallengeNonce { nonce: nonce3, target_node_id: 3, timestamp: ts };
        challenge_tx.send(challenge1).await.unwrap();
        challenge_tx.send(challenge2).await.unwrap();
        challenge_tx.send(challenge3).await.unwrap();
        
        // Allow time for listener to process challenges and update pending_challenges
        tokio::time::sleep(Duration::from_millis(50)).await; 

        // Create attestations (Node 2 has invalid signature)
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
        tokio::time::sleep(Duration::from_millis(50)).await;
        aggregator.process_attestation_batch(vec![att1.clone(), att2.clone(), att3.clone()]).await; // Added .await

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

        // Simulate another round of challenges
        let nonce1b = [11u8; 32];
        let nonce2b = [22u8; 32];
        let nonce3b = [33u8; 32];
        let ts_b = 2000;
        let challenge1b = ChallengeNonce { nonce: nonce1b, target_node_id: 1, timestamp: ts_b };
        let challenge2b = ChallengeNonce { nonce: nonce2b, target_node_id: 2, timestamp: ts_b };
        let challenge3b = ChallengeNonce { nonce: nonce3b, target_node_id: 3, timestamp: ts_b };
        challenge_tx.send(challenge1b).await.unwrap();
        challenge_tx.send(challenge2b).await.unwrap();
        challenge_tx.send(challenge3b).await.unwrap();
        
        // Allow time for listener to process challenges
        tokio::time::sleep(Duration::from_millis(50)).await; 

        // Create attestations for round 2 (Node 2 fails again)
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
        tokio::time::sleep(Duration::from_millis(50)).await;
        aggregator.process_attestation_batch(vec![att1b.clone(), att2b.clone(), att3b.clone()]).await; // Added .await

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
        // Capture challenge_rx_returned
        let (aggregator, challenge_tx, challenge_rx_returned, _, _) = 
            setup_aggregator_test(config, initial_nodes).await;

        // Spawn the challenge listener task
        let agg_clone_listener = aggregator.clone();
        tokio::spawn(async move {
            agg_clone_listener.run_challenge_listener(challenge_rx_returned).await;
        });

        let nonce = [1u8; 32];
        let ts = 1000;
        let challenge = ChallengeNonce { nonce, target_node_id: 1, timestamp: ts };
        challenge_tx.send(challenge).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let msg = [1_usize.to_ne_bytes().as_slice(), &nonce, &ts.to_ne_bytes()].concat();
        let sig = node1_sk.sign(&msg);
        let att = LivenessAttestation { node_id: 1, nonce, timestamp: ts, signature: sig };

        tokio::time::sleep(Duration::from_millis(50)).await;
        aggregator.process_attestation_batch(vec![att]).await; // Added .await

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
        let (aggregator, challenge_tx, _challenge_rx, _, _) = 
            setup_aggregator_test(config, initial_nodes).await;

        let nonce = [2u8; 32];
        let ts = 2000;
        let challenge = ChallengeNonce { nonce, target_node_id: 1, timestamp: ts };
        challenge_tx.send(challenge).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let _msg = [1_usize.to_ne_bytes().as_slice(), &nonce, &ts.to_ne_bytes()].concat();
        let invalid_sig = node1_sk.sign(b"wrong message"); // Sign wrong data
        let att = LivenessAttestation { node_id: 1, nonce, timestamp: ts, signature: invalid_sig };

        tokio::time::sleep(Duration::from_millis(50)).await;
        aggregator.process_attestation_batch(vec![att]).await; // Added .await

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
        let (aggregator, challenge_tx, _challenge_rx, _, _) = 
            setup_aggregator_test(config, initial_nodes).await;

        let correct_nonce = [3u8; 32];
        let wrong_nonce = [99u8; 32];
        let ts = 3000;
        let challenge = ChallengeNonce { nonce: correct_nonce, target_node_id: 1, timestamp: ts };
        challenge_tx.send(challenge).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let msg = [1_usize.to_ne_bytes().as_slice(), &wrong_nonce, &ts.to_ne_bytes()].concat(); // Use wrong nonce in msg for sig
        let sig = node1_sk.sign(&msg);
        let att = LivenessAttestation { node_id: 1, nonce: wrong_nonce, timestamp: ts, signature: sig }; // Send wrong nonce

        tokio::time::sleep(Duration::from_millis(50)).await;
        aggregator.process_attestation_batch(vec![att]).await; // Added .await

            let states = aggregator.liveness_states.lock().await;
            let state1 = states.get(&1).unwrap();
        assert!(state1.trust_score < 100.0);
            assert_eq!(state1.consecutive_failures, 1);
    }
    
    #[tokio::test]
    async fn test_isolation_report_triggered() {
        // Setup
        let mut config = LivenessConfig::default();
        config.max_failures = 1; // Isolate after one failure
        config.trust_decrement = 101.0; // Ensure trust drops below threshold immediately
        config.challenge_window = Duration::from_millis(100); // Timeout window for the challenge
        config.min_interval = Duration::from_millis(10); // Faster timeout checks
        config.max_interval = Duration::from_millis(20);


        let (node1_id, node1_sk) = create_test_tee(1);
        let (node2_id, _node2_sk) = create_test_tee(2); // Node 2 will be ignored
        let initial_nodes = vec![node1_id.clone(), node2_id.clone()];
        let (aggregator, challenge_tx, challenge_rx_returned, runtime, mut isolation_rx) =
            setup_aggregator_test(config.clone(), initial_nodes).await;

        // Run the aggregator's listener and checker loops in the background
        let agg_clone_listener = aggregator.clone();
        // Spawn the challenge listener with the returned receiver
        tokio::spawn(async move {
            agg_clone_listener.run_challenge_listener(challenge_rx_returned).await;
        });
        let agg_clone_timeout = aggregator.clone();
        tokio::spawn(async move {
            agg_clone_timeout.run_timeout_checker().await;
        });

        // Add a small delay to allow the challenge listener/timeout checker to start
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Issue a challenge for Node 1
        let nonce1 = [5u8; 32];
        let ts1 = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let challenge1 = ChallengeNonce { nonce: nonce1, target_node_id: 1, timestamp: ts1 };
        challenge_tx.send(challenge1.clone()).await.unwrap();

        // Allow time for challenge to be registered and timeout checker to potentially run
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Node 1 fails to respond - simulate an invalid attestation instead of timeout for quicker check
        let invalid_sig = node1_sk.sign(b"wrong message");
        let invalid_att = LivenessAttestation {
            node_id: 1,
            nonce: nonce1, // Correct nonce
            timestamp: ts1, // Correct timestamp
            signature: invalid_sig, // Invalid signature
        };

        tokio::time::sleep(Duration::from_millis(50)).await;
        aggregator.process_attestation_batch(vec![invalid_att]).await; // Added .await

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
        // Setup
        let mut config = LivenessConfig::default();
        config.challenge_window = Duration::from_millis(100); // Short timeout window
        config.min_interval = Duration::from_millis(10); // Frequent checks
        config.max_interval = Duration::from_millis(20);
        config.max_failures = 1; // Isolate after one failure
        config.trust_decrement = 101.0; // Ensure trust drops below threshold

        let (node1_id, _node1_sk) = create_test_tee(1);
        let (node2_id, _node2_sk) = create_test_tee(2);
        let initial_nodes = vec![node1_id.clone(), node2_id.clone()];
        let (aggregator, challenge_tx, challenge_rx_returned, runtime, mut isolation_rx) =
            setup_aggregator_test(config.clone(), initial_nodes).await;

        // Run the aggregator's listener and checker loops in the background
        let agg_clone_listener = aggregator.clone();
        // Spawn the challenge listener with the returned receiver
        tokio::spawn(async move {
            agg_clone_listener.run_challenge_listener(challenge_rx_returned).await;
        });
        let agg_clone_timeout = aggregator.clone();
        let _handle = tokio::spawn(async move { // Use the clone in the task
            agg_clone_timeout.run_timeout_checker().await;
        });

        // Add a small delay to allow the challenge listener/timeout checker to start
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Simulate a challenge being issued for Node 1
        let nonce1 = [4u8; 32];
        let ts1 = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let challenge1 = ChallengeNonce { nonce: nonce1, target_node_id: 1, timestamp: ts1 };
        // Send the challenge via challenge_tx
        challenge_tx.send(challenge1.clone()).await.unwrap();

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