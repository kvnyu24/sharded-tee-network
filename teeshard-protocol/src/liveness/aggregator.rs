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
                                
                                match identity.public_key.verify(&message, &attestation.signature) {
                                    Ok(_) => {
                                        // Valid attestation matching pending challenge
                                        // Remove the pending challenge after successful verification
                                        // We clone the result because we still hold the pending_guard lock
                                        let result = VerificationResult::Valid;
                                        pending_guard.remove(&node_id);
                                        println!("[Aggregator] Attestation from Node {} verified successfully. Pending challenge removed.", node_id);
                                        result
                                    }
                                    Err(_) => {
                                        println!("[Aggregator] Invalid signature from node {}", node_id);
                                        VerificationResult::InvalidSignature
                                    }
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
        let (runtime, _, _, isolation_rx) = SimulationRuntime::new();
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
        let mut config = LivenessConfig::default();
        config.trust_decrement = 40.0; 
        config.max_failures = 2;      

        let (node1_id_key, node1_skey) = create_test_tee(1); 
        let (node2_id_key, node2_skey) = create_test_tee(2);
        let (node3_id_key, _node3_skey) = create_test_tee(3); 
        let initial_nodes = vec![node1_id_key.clone(), node2_id_key.clone(), node3_id_key.clone()];
        
        // Use setup helper to get Arc<Aggregator> and runtime
        let (aggregator, _challenge_tx, _challenge_rx, runtime, mut isolation_rx) = 
            setup_aggregator_test(config.clone(), initial_nodes).await;

        // --- Batch 1 --- 
        let node_id_1: usize = 1;
        let nonce1 = [1u8; 32];
        let ts1: u64 = 1000;
        let msg1 = [&node_id_1.to_ne_bytes(), &nonce1[..], &ts1.to_ne_bytes()].concat();
        let sig1 = node1_skey.sign(&msg1);
        let att1 = LivenessAttestation { node_id: 1, nonce: nonce1, timestamp: ts1, signature: sig1 };

        let node_id_2: usize = 2;
        let nonce2 = [2u8; 32];
        let ts2: u64 = 1001;
        let msg2 = [&node_id_2.to_ne_bytes(), &nonce2[..], &ts2.to_ne_bytes()].concat();
        let bad_sig2 = node1_skey.sign(&msg2); // Invalid sig
        let att2 = LivenessAttestation { node_id: 2, nonce: nonce2, timestamp: ts2, signature: bad_sig2 };
        
        // Manually add pending challenges for this test (since listener isn't running)
        {
             let mut pending = aggregator.pending_challenges.lock().await;
             pending.insert(1, ChallengeNonce { nonce: nonce1, target_node_id: 1, timestamp: ts1 });
             pending.insert(2, ChallengeNonce { nonce: nonce2, target_node_id: 2, timestamp: ts2 });
             // Assume node 3 was also challenged but didn't respond
             pending.insert(3, ChallengeNonce { nonce: [3u8; 32], target_node_id: 3, timestamp: 1002 }); 
        }
        
        // Call method on aggregator Arc
        aggregator.process_attestation_batch(vec![att1.clone(), att2.clone()]).await;
        
        // Check states after Batch 1
        {
            let states = aggregator.liveness_states.lock().await;
            assert_eq!(states[&1].trust_score, 100.0 + config.trust_increment);
            assert_eq!(states[&1].consecutive_failures, 0);
            assert_eq!(states[&2].trust_score, 100.0 - config.trust_decrement);
            assert_eq!(states[&2].consecutive_failures, 1);
             // Node 3 state wasn't updated because it wasn't in the batch
             assert_eq!(states[&3].trust_score, config.default_trust); 
             assert_eq!(states[&3].consecutive_failures, 0); 
        }
        // Call method on aggregator Arc
        assert!(aggregator.identify_and_isolate_nodes().await.is_empty());
        assert!(tokio::time::timeout(Duration::from_millis(10), isolation_rx.recv()).await.is_err());

        // --- Batch 2 --- 
        let nonce1_2 = [11u8; 32];
        let ts1_2: u64 = 2000;
        let msg1_2 = [&node_id_1.to_ne_bytes(), &nonce1_2[..], &ts1_2.to_ne_bytes()].concat();
        let sig1_2 = node1_skey.sign(&msg1_2);
        let att1_2 = LivenessAttestation { node_id: 1, nonce: nonce1_2, timestamp: ts1_2, signature: sig1_2 };

        // Manually add pending challenge for node 1
        { 
            let mut pending = aggregator.pending_challenges.lock().await;
            pending.insert(1, ChallengeNonce { nonce: nonce1_2, target_node_id: 1, timestamp: ts1_2 });
            // Assume nodes 2 and 3 were challenged again too, but didn't respond in this batch
             pending.insert(2, ChallengeNonce { nonce: [12u8; 32], target_node_id: 2, timestamp: 2001 });
             pending.insert(3, ChallengeNonce { nonce: [13u8; 32], target_node_id: 3, timestamp: 2002 });
        }

        // Call method on aggregator Arc
        aggregator.process_attestation_batch(vec![att1_2.clone()]).await;

        // Check states after Batch 2
        {
            let states = aggregator.liveness_states.lock().await;
            assert_eq!(states[&1].trust_score, 100.0 + 2.0 * config.trust_increment);
            assert_eq!(states[&1].consecutive_failures, 0);
            // State for 2 and 3 unchanged by this batch
            assert_eq!(states[&2].trust_score, 100.0 - config.trust_decrement);
            assert_eq!(states[&2].consecutive_failures, 1);
            assert_eq!(states[&3].trust_score, config.default_trust);
            assert_eq!(states[&3].consecutive_failures, 0); 
        }
        
        // Check isolation - still no isolation expected, timeout logic handles missed attestations
        // Call method on aggregator Arc
        let isolated = aggregator.identify_and_isolate_nodes().await;
        assert!(isolated.is_empty());
        
        // --- Batch 3 --- 
        let nonce2_3 = [22u8; 32];
        let ts2_3: u64 = 3000;
        let msg2_3 = [&node_id_2.to_ne_bytes(), &nonce2_3[..], &ts2_3.to_ne_bytes()].concat();
        let sig2_3 = node2_skey.sign(&msg2_3);
        let att2_3 = LivenessAttestation { node_id: 2, nonce: nonce2_3, timestamp: ts2_3, signature: sig2_3 };

        // Manually add pending challenge for node 2
        { 
            let mut pending = aggregator.pending_challenges.lock().await;
            pending.insert(2, ChallengeNonce { nonce: nonce2_3, target_node_id: 2, timestamp: ts2_3 });
        }

        // Call method on aggregator Arc
        aggregator.process_attestation_batch(vec![att2_3.clone()]).await;
        
        // Check states after Batch 3
        {
            let states = aggregator.liveness_states.lock().await;
            // Node 2 responded validly, score increases, failures reset
            assert_eq!(states[&2].trust_score, 100.0 - config.trust_decrement + config.trust_increment);
            assert_eq!(states[&2].consecutive_failures, 0); 
        } 
    }

    #[tokio::test]
    async fn test_process_valid_attestation() {
        let config = LivenessConfig::default();
        let (node1_id, node1_skey) = create_test_tee(1);
        let initial_nodes = vec![node1_id.clone()];
        // Use setup helper
        let (aggregator, challenge_tx, _challenge_rx_returned, _runtime, _isolation_rx) = 
            setup_aggregator_test(config.clone(), initial_nodes).await;

        // 1. Simulate Challenger sending challenge info via tx
        let node_id_1 = 1;
        let nonce1 = [1u8; 32];
        let ts1 = 1000u64;
        let challenge = ChallengeNonce { nonce: nonce1, target_node_id: node_id_1, timestamp: ts1 };
        challenge_tx.send(challenge.clone()).await.unwrap();
        
        // In test, manually update pending_challenges since listener task isn't running
        {
            let mut pending_guard = aggregator.pending_challenges.lock().await;
            pending_guard.insert(challenge.target_node_id, challenge.clone());
        }

        // 2. Simulate Node sending valid attestation
        let msg1 = [&node_id_1.to_ne_bytes(), &nonce1[..], &ts1.to_ne_bytes()].concat(); 
        let sig1 = node1_skey.sign(&msg1); 
        let att1 = LivenessAttestation { node_id: 1, nonce: nonce1, timestamp: ts1, signature: sig1 };

        // 3. Aggregator processes the batch
        aggregator.process_attestation_batch(vec![att1]).await;

        // 4. Verify state update (access via Arc)
        {
            let states = aggregator.liveness_states.lock().await;
            let state1 = states.get(&1).unwrap();
            assert_eq!(state1.trust_score, config.default_trust + config.trust_increment);
            assert_eq!(state1.consecutive_failures, 0);
        }

        // 5. Verify pending challenge was removed (access via Arc)
        {
            let pending = aggregator.pending_challenges.lock().await;
            assert!(!pending.contains_key(&1));
        }
    }

    #[tokio::test]
    async fn test_process_invalid_signature_attestation() {
        let config = LivenessConfig::default();
        let (node1_id, node1_skey) = create_test_tee(1);
        let (node2_id, _node2_skey) = create_test_tee(2); // Key for signing wrong sig
        let initial_nodes = vec![node1_id.clone()];
        let (aggregator, challenge_tx, _challenge_rx, _runtime, _isolation_rx) = 
            setup_aggregator_test(config.clone(), initial_nodes).await;

        // ... (steps 1, 2, 3 as before) ...
        // 1. Simulate Challenge
        let node_id_1 = 1;
        let nonce1 = [1u8; 32];
        let ts1 = 1000u64;
        let challenge = ChallengeNonce { nonce: nonce1, target_node_id: node_id_1, timestamp: ts1 };
        challenge_tx.send(challenge.clone()).await.unwrap();
        { let mut p = aggregator.pending_challenges.lock().await; p.insert(1, challenge); }

        // 2. Simulate Attestation with WRONG signature
        let msg1 = [&node_id_1.to_ne_bytes(), &nonce1[..], &ts1.to_ne_bytes()].concat(); 
        let bad_sig = _node2_skey.sign(&msg1);
        let att1 = LivenessAttestation { node_id: 1, nonce: nonce1, timestamp: ts1, signature: bad_sig };

        // 3. Process
        aggregator.process_attestation_batch(vec![att1]).await;
        
        // 4. Verify state update (failure) (access via Arc)
        {
            let states = aggregator.liveness_states.lock().await;
            let state1 = states.get(&1).unwrap();
            assert_eq!(state1.trust_score, config.default_trust - config.trust_decrement);
            assert_eq!(state1.consecutive_failures, 1);
        }
        
        // 5. Verify pending challenge removed (even on failure) (access via Arc)
        {
            let pending = aggregator.pending_challenges.lock().await;
            assert!(!pending.contains_key(&1));
        }
    }
    
    #[tokio::test]
    async fn test_process_nonce_mismatch_attestation() {
         let config = LivenessConfig::default();
        let (node1_id, node1_skey) = create_test_tee(1);
        let initial_nodes = vec![node1_id.clone()];
        let (aggregator, challenge_tx, _challenge_rx, _runtime, _isolation_rx) = 
            setup_aggregator_test(config.clone(), initial_nodes).await;

        // ... (steps 1, 2, 3 as before) ...
         // 1. Simulate Challenge
        let node_id_1 = 1;
        let nonce_expected = [1u8; 32];
        let nonce_received = [2u8; 32]; // Different nonce
        let ts1 = 1000u64;
        let challenge = ChallengeNonce { nonce: nonce_expected, target_node_id: node_id_1, timestamp: ts1 };
        challenge_tx.send(challenge.clone()).await.unwrap();
        { let mut p = aggregator.pending_challenges.lock().await; p.insert(1, challenge); }

        // 2. Simulate Attestation with WRONG nonce
        let msg_signed = [&node_id_1.to_ne_bytes(), &nonce_received[..], &ts1.to_ne_bytes()].concat(); 
        let sig = node1_skey.sign(&msg_signed);
        let att1 = LivenessAttestation { node_id: 1, nonce: nonce_received, timestamp: ts1, signature: sig };

        // 3. Process
        aggregator.process_attestation_batch(vec![att1]).await;

        // 4. Verify state update (failure) (access via Arc)
        {
            let states = aggregator.liveness_states.lock().await;
            let state1 = states.get(&1).unwrap();
            assert_eq!(state1.trust_score, config.default_trust - config.trust_decrement);
            assert_eq!(state1.consecutive_failures, 1);
        }
        
        // 5. Verify pending challenge removed (access via Arc)
        {
            let pending = aggregator.pending_challenges.lock().await;
            assert!(!pending.contains_key(&1));
        }
    }
    
    #[tokio::test]
    async fn test_isolation_report_triggered() {
        let mut config = LivenessConfig::default();
        config.max_failures = 2; 
        config.trust_decrement = 60.0;

        let (node1_id, node1_skey) = create_test_tee(1);
        let (node2_id, _node2_skey) = create_test_tee(2);
        let initial_nodes = vec![node1_id.clone()];
        // Use setup helper, get runtime handle back
        let (aggregator, challenge_tx, _challenge_rx, runtime, mut isolation_rx) = 
            setup_aggregator_test(config.clone(), initial_nodes).await;
        
        // --- Fail 1 --- 
        let nonce1 = [1u8; 32]; let ts1 = 1000u64;
        let challenge1 = ChallengeNonce { nonce: nonce1, target_node_id: 1, timestamp: ts1 };
        challenge_tx.send(challenge1.clone()).await.unwrap();
        { let mut p = aggregator.pending_challenges.lock().await; p.insert(1, challenge1); }
        let msg1 = [&1usize.to_ne_bytes(), &nonce1[..], &ts1.to_ne_bytes()].concat(); 
        let bad_sig1 = _node2_skey.sign(&msg1);
        let att1 = LivenessAttestation { node_id: 1, nonce: nonce1, timestamp: ts1, signature: bad_sig1 };
        aggregator.process_attestation_batch(vec![att1]).await;
        { let s = aggregator.liveness_states.lock().await; assert_eq!(s[&1].consecutive_failures, 1); }

        // --- Fail 2 --- 
        let nonce2 = [2u8; 32]; let ts2 = 2000u64;
        let challenge2 = ChallengeNonce { nonce: nonce2, target_node_id: 1, timestamp: ts2 };
        challenge_tx.send(challenge2.clone()).await.unwrap();
        { let mut p = aggregator.pending_challenges.lock().await; p.insert(1, challenge2); }
        let msg2 = [&1usize.to_ne_bytes(), &nonce2[..], &ts2.to_ne_bytes()].concat(); 
        let bad_sig2 = _node2_skey.sign(&msg2);
        let att2 = LivenessAttestation { node_id: 1, nonce: nonce2, timestamp: ts2, signature: bad_sig2 };
        aggregator.process_attestation_batch(vec![att2]).await;
        { let s = aggregator.liveness_states.lock().await; assert_eq!(s[&1].consecutive_failures, 2); }

        // --- Check for Isolation Report --- 
        // Manually call identify_and_isolate and report
        let nodes_to_isolate = aggregator.identify_and_isolate_nodes().await;
        assert_eq!(nodes_to_isolate, vec![1]);
        runtime.report_isolated_nodes(nodes_to_isolate).await;
        
        // Check reception
        let isolated_report = tokio::time::timeout(Duration::from_millis(100), isolation_rx.recv()).await
            .expect("Timeout waiting for isolation report")
            .expect("Isolation channel unexpectedly closed");
        assert_eq!(isolated_report, vec![1]);
    }

    #[tokio::test]
    async fn test_timeout_checker() {
        let mut config = LivenessConfig::default();
        config.challenge_window = Duration::from_millis(100); // Short window for test
        config.max_failures = 1; // Isolate after 1 timeout
        config.trust_decrement = 100.0; // Ensure score drops enough
        
        let (node1_id, _) = create_test_tee(1);
        let initial_nodes = vec![node1_id.clone()];
        let (aggregator, _challenge_tx, challenge_rx, runtime, mut isolation_rx) = 
            setup_aggregator_test(config.clone(), initial_nodes).await;

        // Spawn the timeout checker task
        let checker_agg_clone = aggregator.clone();
        let checker_handle = tokio::spawn(async move {
            checker_agg_clone.run_timeout_checker().await;
        });

        // Manually insert a pending challenge with an old timestamp
        let old_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 - 200; // 200ms ago
        let old_challenge = ChallengeNonce {
            nonce: [9u8; 32],
            target_node_id: 1,
            timestamp: old_timestamp,
        };
        {
            let mut pending = aggregator.pending_challenges.lock().await;
            pending.insert(1, old_challenge);
        }

        // Wait longer than the check interval for the checker to run
        tokio::time::sleep(config.challenge_window * 2).await; 

        // Verify state update (penalty applied)
        {
            let states = aggregator.liveness_states.lock().await;
            let state1 = states.get(&1).unwrap();
            assert_eq!(state1.trust_score, config.default_trust - config.trust_decrement, "Trust score should decrease on timeout");
            assert_eq!(state1.consecutive_failures, 1, "Failures should increment on timeout");
        }

        // Verify pending challenge was removed
        {
            let pending = aggregator.pending_challenges.lock().await;
            assert!(!pending.contains_key(&1), "Pending challenge should be removed after timeout");
        }

        // Verify isolation report was sent (since max_failures = 1)
        let isolated_report = tokio::time::timeout(Duration::from_millis(100), isolation_rx.recv()).await
            .expect("Timeout waiting for isolation report after timeout check")
            .expect("Isolation channel unexpectedly closed after timeout check");
        assert_eq!(isolated_report, vec![1], "Isolation report should contain node 1 after timeout");

        // Cleanup
        checker_handle.abort();
        // Need to explicitly drop challenge_rx to close channel for listener task if it were running
        drop(challenge_rx); 
    }
} 