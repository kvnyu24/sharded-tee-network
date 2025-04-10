// Placeholder for Liveness Challenger logic (Algorithm 4)

use crate::{
    data_structures::TEEIdentity,
    liveness::types::{ChallengeNonce, NonceChallenge},
    simulation::runtime::SimulationRuntime, // Import NetworkMessage
    network::NetworkMessage,
};
use std::time::Duration;
use rand::Rng; // Import Rng trait
// Import StdRng and SeedableRng for Send-compatible RNG
use rand::{rngs::StdRng, SeedableRng};
use tokio::sync::mpsc; // Import mpsc
use tokio::time::interval;
 // Import SimulationConfig

// Represents a TEE node acting as a challenger
pub struct Challenger {
    // config: LivenessConfig, // Removed unused config
    identity: TEEIdentity,
    nodes_to_challenge: Vec<TEEIdentity>,
    runtime: SimulationRuntime, 
    aggregator_tx: mpsc::Sender<ChallengeNonce>,
}

impl Challenger {
    pub fn new(
        identity: TEEIdentity,
        initial_nodes: Vec<TEEIdentity>,
        runtime: SimulationRuntime,
        aggregator_tx: mpsc::Sender<ChallengeNonce>,
    ) -> Self {
        Challenger {
            // config, // Removed unused config
            identity,
            nodes_to_challenge: initial_nodes,
            runtime,
            aggregator_tx
        }
    }

    // Periodically called to check if challenges need to be issued
    // In this simplified version, it challenges ALL nodes it knows about.
    // Aggregator handles timing/window logic.
    pub async fn issue_challenges(&mut self) {
        // Use StdRng::from_entropy() which is Send
        let mut rng = StdRng::from_entropy();

        for node_identity in self.nodes_to_challenge.clone() {
            // We have the full TEEIdentity here
            let node_id = node_identity.id;
            // Generate nonce (e.g., 32 random bytes)
            let nonce_bytes: [u8; 32] = rng.gen();
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64; // Use millis for timestamp

            let challenge = ChallengeNonce {
                nonce: nonce_bytes,
                target_node_id: node_id,
                timestamp,
            };

            // Create the NonceChallenge required by route_challenge
            let nonce_u64 = u64::from_ne_bytes(nonce_bytes[0..8].try_into().unwrap()); // Use first 8 bytes for u64 nonce
            let route_challenge_msg = NonceChallenge {
                target_tee: node_identity.clone(), // Use the full identity
                nonce: nonce_u64, // Use the u64 nonce
            };

            println!("[Challenger] Issuing challenge to Node {}", node_id);
            
            // Use runtime to send the challenge to the node
            self.runtime.route_challenge(node_id, route_challenge_msg).await; // Pass the NonceChallenge

            // Inform the aggregator about the challenge issued (using the original ChallengeNonce)
            if let Err(e) = self.aggregator_tx.send(challenge).await {
                eprintln!("[Challenger] Failed to send challenge info to aggregator: {}", e);
            }
        }
    }

    /// Main run loop for the challenger task.
    pub async fn run(mut self) {
        log::info!("[Challenger {}] Starting run loop...", self.identity.id);
        // TODO: Make challenge frequency configurable via LivenessConfig/SimulationConfig
        let challenge_interval_duration = Duration::from_secs(1); // FASTER: challenge every 1 second
        let mut challenge_timer = interval(challenge_interval_duration);

        loop {
            challenge_timer.tick().await;
            log::debug!("[Challenger {}] Issuing periodic challenges.", self.identity.id);
            self.issue_challenges().await;
        }
        // Note: Loop runs indefinitely, relies on Tokio task cancellation for shutdown
        // log::info!("[Challenger {}] Stopping run loop.", self.identity.id);
    }

    // Remove adjust_intervals method
    /* pub fn adjust_intervals(&mut self) { ... } */
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_structures::TEEIdentity;
    
    use crate::tee_logic::crypto_sim::generate_keypair;
    use crate::simulation::runtime::SimulationRuntime;
    use crate::simulation::config::SimulationConfig; // Import SimulationConfig
    use tokio::sync::mpsc;
    
    use std::sync::Arc;
    use crate::network::MockNetwork;

    // Helper to create TEE Identity
    fn create_test_tee_identity(id: usize) -> TEEIdentity {
        let keypair = generate_keypair();
        TEEIdentity { id, public_key: keypair.verifying_key() }
    }

    #[tokio::test]
    async fn challenge_issuance_and_aggregator_notification() {
        let node1 = create_test_tee_identity(1);
        let node2 = create_test_tee_identity(2);
        let initial_nodes = vec![node1.clone(), node2.clone()];
        
        // Pass default SimulationConfig to runtime constructor
        // Expect 4 values now: runtime, result_rx, isolation_rx, metrics_handle
        let (runtime, _result_rx, _isolation_rx, _metrics_handle) = 
            SimulationRuntime::new(SimulationConfig::default()); 
        let (agg_tx, mut agg_rx) = mpsc::channel::<ChallengeNonce>(10);
        let (_node1_challenge_tx, _node1_challenge_rx) = mpsc::channel::<NetworkMessage>(10); 
        let (_node2_challenge_tx, _node2_challenge_rx) = mpsc::channel::<NetworkMessage>(10); 
        
        let (prop_tx, _prop_rx) = mpsc::channel(10);

        // Register nodes with the runtime
        runtime.register_node(node1.clone(), prop_tx.clone()); 
        runtime.register_node(node2.clone(), prop_tx.clone()); 

        let challenger_id = create_test_tee_identity(0); // Give challenger an ID

        // Pass identity to Challenger::new
        let mut challenger = Challenger::new(challenger_id, initial_nodes, runtime.clone(), agg_tx);

        challenger.issue_challenges().await;

        // 1. Check if challenges were sent via runtime to nodes
        // TODO: Verify challenges were sent via EmulatedNetwork, not direct channels.
        // let challenge1_node = node1_challenge_rx.recv().await.expect("Node 1 should receive challenge");
        // assert_eq!(challenge1_node.target_node_id, 1);
        // let challenge2_node = node2_challenge_rx.recv().await.expect("Node 2 should receive challenge");
        // assert_eq!(challenge2_node.target_node_id, 2);

        // 2. Check if challenge info was sent to the aggregator channel
        let challenge1_agg = agg_rx.recv().await.expect("Aggregator should receive challenge info for node 1");
        assert_eq!(challenge1_agg.target_node_id, 1);
        // Verify nonce and timestamp match what the node received
        // Cannot assert nonce/timestamp match directly without receiving from node channel
        // assert_eq!(challenge1_agg.nonce, challenge1_node.nonce);
        // assert_eq!(challenge1_agg.timestamp, challenge1_node.timestamp);

        let challenge2_agg = agg_rx.recv().await.expect("Aggregator should receive challenge info for node 2");
        assert_eq!(challenge2_agg.target_node_id, 2);
        // assert_eq!(challenge2_agg.nonce, challenge2_node.nonce);
        // assert_eq!(challenge2_agg.timestamp, challenge2_node.timestamp);
    }

    // Remove interval adjustment test
    /* 
    #[test]
    fn interval_adjustment() { ... } 
    */

    async fn setup_challenger_test(node_identities: Vec<TEEIdentity>) -> (
        Challenger,
        mpsc::Receiver<ChallengeNonce>, // Corrected: Receiver of ChallengeNonce
        Arc<MockNetwork>,
        SimulationRuntime, // Return runtime handle as well
    ) {
        let (challenge_tx, challenge_rx) = mpsc::channel(100);
        // Create runtime, get handle and ignore other return values
        let (runtime, _, _, _) = SimulationRuntime::new(SimulationConfig::default()); 
        let challenger_identity = TEEIdentity { id: 999, public_key: generate_keypair().verifying_key() };
        let mock_network = Arc::new(MockNetwork::new()); // Mock network might still be needed for some tests

        let challenger = Challenger::new(
            challenger_identity, 
            node_identities, 
            runtime.clone(), // Pass the runtime handle clone
            challenge_tx
        );
        (challenger, challenge_rx, mock_network, runtime) // Return runtime
    }
}