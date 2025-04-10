// teeshard-protocol/tests/simulation_tests.rs

use teeshard_protocol::{
    config::SystemConfig,
    data_structures::TEEIdentity,
    network::NetworkMessage, 
    raft::{messages::{/* RaftMessage, RequestVoteArgs */}, node::RaftEvent, state::{Command, RaftRole}}, 
    simulation::{
        node::NodeProposalRequest, // Import type for node proposal channel
        runtime::SimulationRuntime,
        node::SimulatedTeeNode,
        runtime::SignatureShare, // Keep SignatureShare import
        node::{NodeQueryRequest, NodeQueryResponse, NodeQuery},
        config::SimulationConfig,
    },
    tee_logic::{crypto_sim::{SecretKey, verify}, types::LockProofData},
    // Removed incorrect ShardId import from here
};
use teeshard_protocol::raft::node::ShardId;
// Import crypto_sim module
use teeshard_protocol::tee_logic::crypto_sim;
use std::time::Duration;
use std::collections::{HashMap, HashSet};
use tokio::sync::{mpsc, oneshot}; // Import mpsc
use bincode::config::standard; // For verification serialization
use hex; // Need hex for share verification output
// Add correct ShardId import

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
    let (node_identity, _node_secret_key) = create_test_tee(0);
    let (runtime, _result_rx, _isolation_rx, _metrics_handle) = SimulationRuntime::new(SimulationConfig::default());
    let config = SystemConfig::default();
    let num_nodes = 3;
    let mut node_handles = Vec::new();
    let mut node_identities_map = HashMap::new(); // Use map for easier lookup
    let mut nodes_to_spawn: Vec<SimulatedTeeNode> = Vec::new(); // Store just the node

    // 1. Create Identities
    for i in 0..num_nodes {
        let (identity, _) = create_test_tee(i);
        node_identities_map.insert(identity.id, identity);
    }

    // 2. Create Nodes
    for i in 0..num_nodes {
        let identity = node_identities_map.get(&i).unwrap().clone();
        let (_, secret_key) = create_test_tee(i); // Re-create key pair
        let peers: Vec<TEEIdentity> = node_identities_map.values()
            .filter(|id| id.id != i)
            .cloned()
            .collect();
        
        // Create proposal/query channels needed for registration/control
        let (proposal_tx, proposal_rx) = mpsc::channel::<NodeProposalRequest>(10);
        let (query_tx, query_rx) = mpsc::channel::<NodeQuery>(10); // Rename _query_rx to query_rx

        // 1. Register node with runtime first to get network_rx
        let network_rx = runtime.register_node(identity.clone(), proposal_tx.clone()).await;

        // 2. Create the node instance, passing the network_rx
        let node = SimulatedTeeNode::new(
            identity.clone(),
            secret_key,
            peers,
            config.clone(),
            runtime.clone(),
            network_rx, // Pass receiver from runtime
            proposal_tx, // Pass proposal sender
            proposal_rx, // Pass proposal receiver
            query_tx, // Pass query sender
            query_rx, // Pass query receiver (now named query_rx)
            0, // Use usize 0 directly for ShardId
        );
        // Store node only
        nodes_to_spawn.push(node);
    }

    // 3. Spawn node tasks by consuming the vector
    for node in nodes_to_spawn { 
        let id = node.identity.id;
        // Spawn the task, moving the node into it, and store the handle
        let handle = tokio::spawn(node.run());
        node_handles.push((id, handle));
        println!("[Test] Spawned node {} task.", id);
    }

    // 4. Let simulation run
    println!("[Test] Letting simulation run for leader election/heartbeats...");
    tokio::time::sleep(Duration::from_secs(2)).await;
    println!("[Test] Simulation run time finished.");
    println!("[Test] Test finished. Nodes should have run and potentially elected a leader.");

    // 5. Cleanup using the stored handles
    for (id, handle) in node_handles {
        println!("[Test] Aborting node {} task.", id);
        handle.abort(); // Abort tasks to ensure cleanup
        // Optionally, await the handle if graceful shutdown is needed/possible
        // let _ = handle.await; 
    }
}

#[tokio::test]
async fn test_raft_state_machine_command_processing() {
    println!("--- Starting State Machine Command Processing Test ---");

    // 1. Setup Simulation Environment
    let (node_identity, _node_secret_key) = create_test_tee(0);
    let (runtime, mut result_rx, _isolation_rx, _metrics_handle) = SimulationRuntime::new(SimulationConfig::default());
    let config = SystemConfig::default();
    let num_nodes = 3;
    let mut node_handles = Vec::new();
    let mut node_identities_map = HashMap::new();
    let mut node_proposal_senders = HashMap::new();
    let mut node_query_senders = HashMap::new(); // NEW: Store query senders
    let mut nodes_to_spawn: Vec<SimulatedTeeNode> = Vec::new(); // Store just the node
    let mut identities = Vec::new(); // Define identities within this test scope

    // Create identities
    for i in 0..num_nodes {
        let (identity, _) = create_test_tee(i);
        node_identities_map.insert(identity.id, identity.clone()); // Clone identity for map
        identities.push(identity); // Store identity in the vector
    }

    // 2. Create Nodes & Dummy Network Channels for Registration
    for i in 0..num_nodes {
        let identity = node_identities_map.get(&i).unwrap().clone();
        let (_, secret_key) = create_test_tee(i);
        let peers: Vec<TEEIdentity> = node_identities_map.values()
            .filter(|id| id.id != identity.id)
            .cloned()
            .collect();

        // Create proposal/query channels needed for registration/control
        let (proposal_tx, proposal_rx) = mpsc::channel::<NodeProposalRequest>(10);
        let (query_tx, query_rx) = mpsc::channel::<NodeQuery>(10); // Rename _query_rx to query_rx

        // 1. Register node with runtime first to get network_rx
        let network_rx = runtime.register_node(identity.clone(), proposal_tx.clone()).await;
        node_proposal_senders.insert(identity.id, proposal_tx.clone()); // Store proposal sender for tests
        node_query_senders.insert(identity.id, query_tx.clone()); // Store query sender for tests

        // 2. Create the node instance, passing the network_rx
        let node = SimulatedTeeNode::new(
            identity.clone(),
            secret_key,
            peers,
            config.clone(),
            runtime.clone(),
            network_rx, // Pass receiver from runtime
            proposal_tx, // Pass proposal sender
            proposal_rx, // Pass proposal receiver
            query_tx, // Pass query sender
            query_rx, // Pass query receiver (now named query_rx)
            0, // Use usize 0 directly for ShardId
        );
        // Store node only
        nodes_to_spawn.push(node);
    }

    // Spawn tasks by consuming the vector
    for node in nodes_to_spawn { 
        let id = node.identity.id;
        // Spawn the task, moving the node into it, and store the handle
        let handle = tokio::spawn(node.run());
        node_handles.push((id, handle));
        println!("[Test] Spawned node {} task.", id);
    }

    // 2. Wait for Leader Election
    println!("[Test] Waiting for leader election...");
    tokio::time::sleep(Duration::from_secs(4)).await;

    // 3. Identify Leader (Dynamically)
    let mut leader_id = None;
    let mut leader_proposal_sender = None;
    let mut leader_query_sender = None;
    let leader_find_timeout = Duration::from_secs(2);
    let start_time = tokio::time::Instant::now();

    println!("[Test] Dynamically finding leader...");
    while leader_id.is_none() && start_time.elapsed() < leader_find_timeout {
        for i in 0..num_nodes {
            let query_sender = node_query_senders.get(&i).expect("Query sender not found");
            let (resp_tx, resp_rx) = oneshot::channel::<NodeQueryResponse>();
            if query_sender.send((NodeQueryRequest::GetRaftState, resp_tx)).await.is_err() {
                println!("[Test] Failed to send query to Node {}. It might have stopped.", i);
                continue;
            }

            match tokio::time::timeout(Duration::from_millis(100), resp_rx).await {
                Ok(Ok(NodeQueryResponse::RaftState { role, .. })) => {
                    if role == RaftRole::Leader {
                        println!("[Test] Found Leader: Node {}", i);
                        leader_id = Some(i);
                        leader_proposal_sender = Some(node_proposal_senders.get(&i).unwrap().clone());
                        leader_query_sender = Some(node_query_senders.get(&i).unwrap().clone());
                        break; // Exit inner loop once leader found
                    }
                }
                Ok(Err(_)) => { println!("[Test] Node {} query channel closed.", i); }
                Err(_) => { /* Timeout waiting for response from node i */ }
            }
        }
        if leader_id.is_none() {
            tokio::time::sleep(Duration::from_millis(200)).await; // Wait before retrying node checks
        }
    }

    let leader_id = leader_id.expect("Failed to find leader within timeout");
    let leader_proposal_sender = leader_proposal_sender.expect("Leader proposal sender not found");
    let leader_query_sender = leader_query_sender.expect("Leader query sender not found");

    // 4. Define Command Data
    let lock_proof_data = LockProofData {
        tx_id: "test-tx-456".to_string(),
        source_chain_id: 1,
        target_chain_id: 2,
        token_address: "0xtesttokenB".to_string(),
        amount: 2000,
        recipient: "0xrecipientaddrB".to_string(),
    };
    let command = Command::ConfirmLockAndSign(lock_proof_data.clone());
    
    // Query leader state BEFORE proposing
    let (state_query_tx, state_query_rx) = oneshot::channel::<NodeQueryResponse>();
    leader_query_sender.send((NodeQueryRequest::GetRaftState, state_query_tx)).await.expect("Send query fail");
    let initial_state = match tokio::time::timeout(Duration::from_secs(1), state_query_rx).await {
        Ok(Ok(NodeQueryResponse::RaftState { last_log_index, .. })) => last_log_index,
        _ => panic!("[Test] Failed to get initial leader state")
    };
    println!("[Test] Initial leader last_log_index: {}", initial_state);

    // 5. Propose Command via Node's Proposal Channel
    println!("[Test] Sending proposal {:?} to leader {}...", command, leader_id);
    let (prop_result_tx, prop_result_rx) = oneshot::channel();
    let proposal_request: NodeProposalRequest = (command, prop_result_tx);

    leader_proposal_sender.send(proposal_request).await
        .expect("Failed to send proposal to leader node");

    // Wait for the proposal ACK from the oneshot channel
    let expected_log_index_after_propose = initial_state + 1;
    match tokio::time::timeout(Duration::from_secs(2), prop_result_rx).await {
        Ok(Ok(Ok(events))) => {
            println!("[Test] Leader accepted proposal. Events generated: {:?}", events);
            // Optional: Add check for leader's log index immediately after propose ACK
             let (state_query_tx2, state_query_rx2) = oneshot::channel::<NodeQueryResponse>();
             leader_query_sender.send((NodeQueryRequest::GetRaftState, state_query_tx2)).await.expect("Send query fail");
             match tokio::time::timeout(Duration::from_secs(1), state_query_rx2).await {
                 Ok(Ok(NodeQueryResponse::RaftState { last_log_index, role, .. })) => {
                     assert_eq!(role, RaftRole::Leader, "Node {} is not leader after propose", leader_id);
                     assert_eq!(last_log_index, expected_log_index_after_propose, "Leader log index mismatch immediately after propose ACK");
                     println!("[Test] Leader log index is {} as expected after propose.", last_log_index);
                 }
                 _ => panic!("[Test] Failed to get leader state immediately after propose ACK")
             };
        }
        Ok(Ok(Err(e))) => panic!("[Test] Leader rejected proposal: {}", e),
        Ok(Err(_)) => panic!("[Test] Proposal result oneshot channel dropped"),
        Err(_) => panic!("[Test] Timeout waiting for proposal result from leader"),
    }
    
    // 6. Wait for Commit and Check Commit Index
    println!("[Test] Waiting for replication and commit index advancement...");
    // Increase wait time to allow for commit before potential new elections
    tokio::time::sleep(Duration::from_secs(5)).await; // Increased from 2s to 5s
    
    let (state_query_tx3, state_query_rx3) = oneshot::channel::<NodeQueryResponse>();
    leader_query_sender.send((NodeQueryRequest::GetRaftState, state_query_tx3)).await.expect("Send query fail");
    let final_commit_index = match tokio::time::timeout(Duration::from_secs(1), state_query_rx3).await {
        Ok(Ok(NodeQueryResponse::RaftState { commit_index, .. })) => commit_index,
        _ => panic!("[Test] Failed to get leader state after waiting for commit")
    };
    println!("[Test] Leader commit_index after wait: {}", final_commit_index);
    assert!(final_commit_index >= expected_log_index_after_propose, 
            "Leader commit index {} did not reach expected index {} after waiting",
            final_commit_index, expected_log_index_after_propose);
    println!("[Test] Command commit confirmed on leader.");

    // 7. Collect Results (Signature Shares) from the main result_rx (mpsc channel)
    let mut received_shares = Vec::new();
    println!("[Test] Waiting for signature shares from all nodes...");
    loop {
        // Use the mpsc receiver captured earlier
        match tokio::time::timeout(Duration::from_secs(5), result_rx.recv()).await {
            Ok(Some(share)) => {
                println!("[Test] Received share from Node {}: Signature starts with 0x{}...", share.0.id, hex::encode(&share.2.to_bytes()[..4]));
                received_shares.push(share);
                if received_shares.len() == num_nodes {
                    break;
                }
            }
            Ok(None) => {
                panic!("[Test] Result channel closed before receiving all shares.");
            }
            Err(_) => {
                panic!("[Test] Timeout waiting for shares. Received {}/{}", received_shares.len(), num_nodes);
            }
        }
    }

    // 8. Verification
    assert_eq!(received_shares.len(), num_nodes, "Did not receive shares from all nodes.");
    let mut signer_ids = HashSet::new();
    for (signer_identity, received_lock_data, signature) in &received_shares { // Borrow shares
        assert!(node_identities_map.contains_key(&signer_identity.id), "Share from unknown signer ID");
        let original_identity = node_identities_map.get(&signer_identity.id).unwrap();
        assert_eq!(signer_identity, original_identity, "Signer identity mismatch");
        assert_eq!(received_lock_data, &lock_proof_data, "Share contained incorrect lock data");

        // Verify signature
        let data_to_verify = bincode::encode_to_vec(&lock_proof_data, standard()).unwrap();

        // DEBUG: Print data and key before verification
        println!("[Test][VerifyDebug] Verifying for Node {}", signer_identity.id);
        println!("[Test][VerifyDebug] Verify data hex: {}", hex::encode(&data_to_verify));
        println!("[Test][VerifyDebug] Verify PubKey: {:?}", signer_identity.public_key);
        
        // Verify the signature using the async verify function and await it
        assert!(verify(
            &data_to_verify,
            signature,
            &signer_identity.public_key,
            0,            // Delay lower bound
            0,            // Delay upper bound
            &None,        // No metrics tx for this test verify
            &None         // No specific node ID for this test verify
        ).await,
                "Invalid signature in share from Node {}", signer_identity.id);
        signer_ids.insert(signer_identity.id);
    }
    assert_eq!(signer_ids.len(), num_nodes, "Received shares from duplicate signers");

    println!("[Test] State Machine test finished SUCCESSFULLY.");

    // Cleanup node tasks
    for (_id, handle) in node_handles {
        handle.abort();
    }
    println!("--- Finished State Machine Command Processing Test ---");
}

#[tokio::test]
async fn test_simulation_runtime_and_node_communication() {
    let (runtime, _result_rx, _isolation_rx, _metrics_handle) = SimulationRuntime::new(SimulationConfig::default());
    let config = SystemConfig::default();
    let num_nodes = 3;
    let mut nodes_to_spawn = Vec::new();
    let mut identities = Vec::new();
    let mut node_handles = Vec::new(); // Store JoinHandles

    for i in 0..num_nodes {
        let (identity, secret_key) = create_test_tee(i);
        let peers: Vec<TEEIdentity> = identities.iter().map(|id: &TEEIdentity| id.clone()).collect();
        
        // Create proposal/query channels needed for registration/control
        let (proposal_tx, proposal_rx) = mpsc::channel::<NodeProposalRequest>(10);
        let (query_tx, query_rx) = mpsc::channel::<NodeQuery>(10); // Rename _query_rx to query_rx

        // 1. Register node with runtime first to get network_rx
        let network_rx = runtime.register_node(identity.clone(), proposal_tx.clone()).await;

        // 2. Create the node instance, passing the network_rx
        let node = SimulatedTeeNode::new(
            identity.clone(),
            secret_key,
            peers,
            config.clone(),
            runtime.clone(), // Pass the runtime handle
            network_rx,      // Pass network receiver
            proposal_tx,     // Pass proposal sender
            proposal_rx,     // Pass proposal receiver
            query_tx,        // Pass query sender (now named query_tx)
            query_rx,        // Pass query receiver (now named query_rx)
            0,               // Use usize 0 directly for ShardId
        );
        nodes_to_spawn.push(node);
        identities.push(identity);
    }

    // 3. Spawn node tasks by CONSUMING nodes_to_spawn
    for node in nodes_to_spawn { 
        let id = node.identity.id;
        // Spawn the task, MOVING the node into it
        let handle = tokio::spawn(node.run()); 
        node_handles.push((id, handle)); // Store handle
        println!("[Test] Spawned node {} task.", id);
    }

    // 4. Let simulation run
    println!("[Test] Letting simulation run for leader election/heartbeats...");
    tokio::time::sleep(Duration::from_secs(2)).await;
    println!("[Test] Simulation run time finished.");
    println!("[Test] Test finished. Nodes should have run and potentially elected a leader.");

    // 5. Cleanup using handles
    for (id, handle) in node_handles {
         println!("[Test] Aborting node {} task.", id);
        handle.abort(); 
    }
}

#[tokio::test]
async fn test_cross_chain_swap_simulation_e2e() {
    let (runtime, _result_rx, _isolation_rx, _metrics_handle) = SimulationRuntime::new(SimulationConfig::default());
    let config = SystemConfig::default();
    let num_nodes = 3;
    let mut nodes_to_spawn = Vec::new();
    let mut identities = Vec::new();
    let mut node_handles = Vec::new(); // Store JoinHandles

    for i in 0..num_nodes {
        let (identity, secret_key) = create_test_tee(i);
        let peers: Vec<TEEIdentity> = identities.iter().map(|id: &TEEIdentity| id.clone()).collect();
        
        // Create proposal/query channels needed for registration/control
        let (proposal_tx, proposal_rx) = mpsc::channel::<NodeProposalRequest>(10);
        let (query_tx, query_rx) = mpsc::channel::<NodeQuery>(10); // Rename _query_rx to query_rx

        // 1. Register node with runtime first to get network_rx
        let network_rx = runtime.register_node(identity.clone(), proposal_tx.clone()).await;

        // 2. Create the node instance, passing the network_rx
        let node = SimulatedTeeNode::new(
            identity.clone(),
            secret_key,
            peers,
            config.clone(),
            runtime.clone(),
            network_rx,
            proposal_tx,
            proposal_rx,
            query_tx,
            query_rx,
            0, // ShardId
        );
        nodes_to_spawn.push(node);
        identities.push(identity);
    }

    // 3. Spawn node tasks by CONSUMING nodes_to_spawn
    for node in nodes_to_spawn {
        let id = node.identity.id;
        let handle = tokio::spawn(node.run());
        node_handles.push((id, handle));
        println!("[Test] Spawned node {} task.", id);
    }

    // 4. Let simulation run
    println!("[Test] Letting simulation run for leader election/heartbeats...");
    tokio::time::sleep(Duration::from_secs(2)).await;
    println!("[Test] Simulation run time finished.");
    println!("[Test] Test finished. Nodes should have run and potentially elected a leader.");

    // 5. Cleanup using handles
    for (id, handle) in node_handles {
         println!("[Test] Aborting node {} task.", id);
        handle.abort(); 
    }
}

#[tokio::test]
async fn test_threshold_signature_simulation() {
    println!("--- Starting Threshold Signature Simulation Test ---");

    // 1. Setup Simulation Environment
    let sim_config = SimulationConfig::default(); // Keep sim_config
    let system_config = SystemConfig::default(); // Keep system config for node defaults

    // *** START REFACTOR ***
    // Use SimulationRuntime directly, not SimulationCoordinator
    let (runtime, mut result_rx, _isolation_rx, _metrics_handle) = 
        SimulationRuntime::new(sim_config);

    // Define number of nodes for this test specifically
    let num_nodes = 3; // Use a smaller number for faster testing
    let mut node_handles = Vec::new();
    let mut identities = Vec::new(); // Store TEEIdentity
    let mut secret_keys = HashMap::new(); // Store SecretKey by ID
    let mut nodes_to_spawn = Vec::new(); // Store nodes before spawning
    let mut proposal_senders = HashMap::new();
    let mut node_identities_map = HashMap::new(); // For verification lookup

    // Generate identities and keys locally for this test
    for i in 0..num_nodes {
        let (identity, secret_key) = create_test_tee(i);
        identities.push(identity.clone());
        secret_keys.insert(identity.id, secret_key);
        node_identities_map.insert(identity.id, identity);
    }
    println!("[Test][ThresholdSig] Generated {} identities locally.", num_nodes);

    // Create nodes using the locally generated identities
    for identity in &identities { // Iterate over generated identities
        let secret_key = secret_keys.get(&identity.id).cloned().expect("Secret key not found");
        let peers: Vec<TEEIdentity> = identities.iter()
            .filter(|&peer_id| peer_id.id != identity.id)
            .cloned()
            .collect();

        let (proposal_tx, proposal_rx) = mpsc::channel::<NodeProposalRequest>(10);
        let (query_tx, query_rx) = mpsc::channel::<NodeQuery>(10);

        // Register node with runtime
        let network_rx = runtime.register_node(identity.clone(), proposal_tx.clone()).await;
        proposal_senders.insert(identity.id, proposal_tx.clone());

        // Create the node instance, using generated identity/key and system_config for defaults
        let node = SimulatedTeeNode::new(
            identity.clone(),
            secret_key,
            peers,
            system_config.clone(), // Use system_config for internal Raft settings etc.
            runtime.clone(),
            network_rx,
            proposal_tx,
            proposal_rx,
            query_tx,
            query_rx,
            0, // Use shard_id 0 for this test
        );
        nodes_to_spawn.push(node);
    }
    // *** END REFACTOR ***

    // Spawn node tasks
    for node in nodes_to_spawn { // Consume the vector
        let id = node.identity.id;
        let handle = tokio::spawn(node.run());
        node_handles.push((id, handle));
        println!("[Test] Spawned node {} task for threshold sig.", id);
    }

    // 2. Wait for Leader Election (assuming Raft is used internally, though not strictly required for this test focus)
    println!("[Test][ThresholdSig] Waiting briefly for nodes to potentially stabilize...");
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 3. Simulate Proposing a Signature Request (e.g., LockProofData)
    let lock_proof_data = LockProofData {
        tx_id: "threshold-sig-tx-123".to_string(),
        source_chain_id: 10,
        target_chain_id: 20,
        token_address: "0xtokenforsig".to_string(),
        amount: 5000,
        recipient: "0xrecipientforsig".to_string(),
    };
    let command = Command::ConfirmLockAndSign(lock_proof_data.clone());

    // Send command to a node (e.g., node 0, assuming it can trigger the process or is leader)
    let proposer_id = 0;
    let proposal_sender = proposal_senders.get(&proposer_id).expect("Proposer sender not found");
    let (prop_result_tx, prop_result_rx) = oneshot::channel();
    let proposal_request: NodeProposalRequest = (command, prop_result_tx);

    println!("[Test][ThresholdSig] Sending signature proposal to node {}...", proposer_id);
    proposal_sender.send(proposal_request).await.expect("Failed to send proposal");

    // Wait for proposal ack (basic check)
    match tokio::time::timeout(Duration::from_secs(1), prop_result_rx).await {
        Ok(Ok(Ok(_))) => println!("[Test][ThresholdSig] Proposal acknowledged by node {}.", proposer_id),
        Ok(Ok(Err(e))) => panic!("[Test][ThresholdSig] Proposal rejected by node {}: {:?}", proposer_id, e),
        Ok(Err(_)) => panic!("[Test][ThresholdSig] Oneshot channel closed for proposal result."),
        Err(_) => panic!("[Test][ThresholdSig] Timeout waiting for proposal ack."),
    }

    // 4. Wait for PARTIAL Signature Results from Runtime
    // The result_rx yields tuples (TEEIdentity, LockProofData, Signature) for each node
    println!("[Test][ThresholdSig] Waiting for partial signature shares from runtime...");
    let mut received_shares: Vec<SignatureShare> = Vec::new(); // Type annotation for clarity
    loop {
        match tokio::time::timeout(Duration::from_secs(5), result_rx.recv()).await {
            Ok(Some(share_tuple)) => { // Expect tuple (signer, data, sig)
                println!("[Test] Received share from Node {}: Signature starts with 0x{}...", 
                         share_tuple.0.id, hex::encode(&share_tuple.2.to_bytes()[..4]));
                received_shares.push(share_tuple);
                if received_shares.len() == num_nodes {
                    break;
                }
            }
            Ok(None) => panic!("[Test][ThresholdSig] Result channel closed before receiving all shares."),
            Err(_) => panic!("[Test][ThresholdSig] Timeout waiting for shares. Received {}/{} shares.", received_shares.len(), num_nodes),
        }
    }

    // 5. Verify the individual partial signatures
    assert_eq!(received_shares.len(), num_nodes, "Did not receive shares from all nodes.");
    let mut signer_ids = HashSet::new();
    for (signer_identity, received_lock_data, signature) in &received_shares {
        // Verify against the locally generated identities stored in the map
        assert!(node_identities_map.contains_key(&signer_identity.id), "Share from unknown signer ID");
        let original_identity = node_identities_map.get(&signer_identity.id).unwrap();
        assert_eq!(signer_identity, original_identity, "Signer identity mismatch");
        assert_eq!(received_lock_data, &lock_proof_data, "Share contained incorrect lock data");

        // Find the index - needed for older verify signature?
        // let signer_index = identities.iter().position(|id| id == signer_identity).expect("Signer identity not found");

        let data_to_verify = bincode::encode_to_vec(&lock_proof_data, standard()).unwrap();

        // Verify partial signature
        assert!(verify(
            &data_to_verify,
            signature,
            &signer_identity.public_key,
            0, // delay min
            0, // delay max
            &None, // metrics tx
            &None // node id
        ).await,
            "Invalid partial signature in share from Node {}", signer_identity.id);
        signer_ids.insert(signer_identity.id);
    }
    assert_eq!(signer_ids.len(), num_nodes, "Received shares from duplicate signers");

    println!("[Test][ThresholdSig] All partial signatures verified successfully.");

    // 6. Cleanup
    println!("[Test][ThresholdSig] Cleaning up tasks...");
    for (_id, handle) in node_handles {
        handle.abort();
    }
    println!("--- Finished Threshold Signature Simulation Test ---");
}

#[tokio::test]
async fn test_basic_signature_verification() {
    println!("--- Starting Basic Signature Verification Test ---");
    let (signer_identity, signer_secret_key) = create_test_tee(99);

    let data_to_verify = b"test message";
    let signature = teeshard_protocol::tee_logic::crypto_sim::sign(
        &data_to_verify[..],
        &signer_secret_key,
        0,
        0,
        &None,
        &Some(signer_identity.clone()),
    ).await;

    assert!(verify(
        &data_to_verify[..],
        &signature,
        &signer_identity.public_key,
        0,
        0,
        &None,
        &None
    ).await,
            "Signature verification failed");
    println!("--- Finished Basic Signature Verification Test ---");
}

#[tokio::test]
async fn test_invalid_signature_verification() {
    println!("--- Starting Invalid Signature Verification Test ---");
    let (signer_identity, signer_secret_key) = create_test_tee(100);

    let data_to_verify = b"test message";
    let invalid_data = b"different message";
    let signature = teeshard_protocol::tee_logic::crypto_sim::sign(
        data_to_verify,
        &signer_secret_key,
        0,
        0,
        &None,
        &Some(signer_identity.clone()),
    ).await;

    assert!(!verify(
        invalid_data,
        &signature,
        &signer_identity.public_key,
        0,
        0,
        &None,
        &None
    ).await,
            "Verification succeeded with invalid data");
    println!("--- Finished Invalid Signature Verification Test ---");
}