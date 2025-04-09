// teeshard-protocol/tests/simulation_tests.rs

use teeshard_protocol::{
    config::SystemConfig,
    data_structures::TEEIdentity,
    raft::messages::{RaftMessage, RequestVoteArgs}, // Example message for testing
    simulation::{
        runtime::SimulationRuntime,
        node::SimulatedTeeNode,
    },
    tee_logic::crypto_sim::SecretKey,
};
use std::time::Duration;

// Helper to create TEE Identity and SecretKey
fn create_test_tee(id: usize) -> (TEEIdentity, SecretKey) {
    // Use deterministic keys for testing if needed, otherwise random
    let secret_bytes = [id as u8; 32]; // Simple deterministic key
    let secret_key = SecretKey::from_bytes(&secret_bytes);
    let public_key = secret_key.verifying_key();
    (TEEIdentity { id, public_key }, secret_key)
}

#[tokio::test]
async fn test_simulation_runtime_and_node_startup() {
    println!("--- Starting Simulation Runtime Test ---");

    let runtime = SimulationRuntime::new();
    let config = SystemConfig::default(); // Use default config for simplicity
    let num_nodes = 3;
    let mut node_handles = Vec::new();
    let mut node_identities = Vec::new();
    let mut node_senders = Vec::new();

    // 1. Create Node Identities
    for i in 0..num_nodes {
        let (identity, _) = create_test_tee(i);
        node_identities.push(identity);
    }

    // 2. Create and Register Nodes
    for i in 0..num_nodes {
        let (identity, secret_key) = create_test_tee(i);
        let peers = node_identities.iter().filter(|id| id.id != i).cloned().collect();
        let node = SimulatedTeeNode::new(
            identity.clone(),
            secret_key,
            peers,
            config.clone(),
            runtime.clone(), // Clone runtime handle for the node
        );
        let sender = node.get_message_sender();
        node_senders.push(sender.clone()); // Keep sender for potential manual message sending
        // Register with identity
        runtime.register_node(identity.clone(), sender);

        // 3. Spawn the node's run task
        let handle = tokio::spawn(node.run());
        node_handles.push(handle);
        println!("[Test] Spawned node {} task.", identity.id);
    }

    // 4. Let the simulation run for a bit
    println!("[Test] Letting simulation run for leader election/heartbeats...");
    tokio::time::sleep(Duration::from_secs(2)).await; // Adjust duration as needed
    println!("[Test] Simulation run time finished.");

    // 5. Optional: Send a dummy message to a node
    // println!("[Test] Sending dummy RequestVote to Node 0...");
    // let dummy_msg = RaftMessage::RequestVote(RequestVoteArgs {
    //     term: 100, // High term to trigger state change
    //     candidate_id: TEEIdentity { id: 99, public_key: node_identities[0].public_key }, // Dummy candidate
    //     last_log_index: 0,
    //     last_log_term: 0,
    // });
    // if let Some(sender_0) = node_senders.get(0) {
    //     if let Err(e) = sender_0.send(dummy_msg).await {
    //         eprintln!("[Test] Failed to send dummy message: {}", e);
    //     }
    //     // Allow time for processing
    //     tokio::time::sleep(Duration::from_millis(100)).await;
    // }

    // Cleanup: Although tasks will exit when the test ends, explicit shutdown/cleanup could be added
    // For now, just ensure the test doesn't panic and runs to completion.
    // Dropping handles might cause tasks to be aborted if they haven't finished naturally.
    println!("[Test] Test finished. Nodes should have run and potentially elected a leader.");

    // We don't explicitly check for leader election here, just that the setup runs without crashing.
    // More specific tests would check Raft state via debug interfaces if available.
} 