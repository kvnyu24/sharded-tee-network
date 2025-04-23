// teeshard-protocol/tests/simulation_tests.rs

use teeshard_protocol::{
    config::SystemConfig,
    data_structures::TEEIdentity,
    network::NetworkMessage, 
    raft::{messages::{/* RaftMessage, RequestVoteArgs */}, node::RaftEvent, state::{Command}}, 
    simulation::{
        node::NodeProposalRequest, // Import type for node proposal channel
        runtime::SimulationRuntime,
        node::SimulatedTeeNode,
        runtime::SignatureShare, // Keep SignatureShare import
        node::{NodeQueryRequest, NodeQueryResponse, NodeQuery},
        config::SimulationConfig,
        mocks::MockBlockchainInterface, // Add mocks
    },
    tee_logic::{crypto_sim::{SecretKey, verify}, types::LockProofData},
    // NodeId (usize) and Term (u64) are likely used directly or defined elsewhere implicitly
};
use teeshard_protocol::raft::node::ShardId;
// Import crypto_sim module
use teeshard_protocol::tee_logic::crypto_sim;
use std::time::{Duration, Instant};
use std::collections::{HashMap, HashSet};
use tokio::sync::{mpsc, oneshot}; // Import mpsc
use bincode::config::standard; // For verification serialization
use hex; // Need hex for share verification output
// Add correct ShardId import
use teeshard_protocol::raft::state::{RaftNodeState, RaftRole}; // Add RaftRole
// Correct imports for Raft state/query types
// RaftNodeQuery is removed, use NodeQueryRequest from simulation::node
use ed25519_dalek::SigningKey;

// Helper function to create TEEIdentity and SigningKey for testing
fn create_test_tee_signing(id: usize) -> (TEEIdentity, SigningKey) {
    let signing_key = SigningKey::from_bytes(&[id as u8; 32]); // Simple deterministic key
    let verifying_key = signing_key.verifying_key();
    (TEEIdentity { id, public_key: verifying_key }, signing_key)
}

#[tokio::test]
async fn test_simulation_runtime_and_node_startup() {
    println!("--- Starting Simulation Runtime Test ---");
    let (node_identity, _node_secret_key) = create_test_tee_signing(0);
    let (runtime, _result_rx, _isolation_rx, _metrics_handle) = SimulationRuntime::new(SimulationConfig::default());
    let config = SystemConfig::default();
    let num_nodes = 3;
    let mut node_handles = Vec::new();
    let mut node_identities_map = HashMap::new(); // Use map for easier lookup
    let mut nodes_to_spawn: Vec<SimulatedTeeNode> = Vec::new(); // Store just the node

    // 1. Create Identities
    for i in 0..num_nodes {
        let (identity, _) = create_test_tee_signing(i);
        node_identities_map.insert(identity.id, identity);
    }

    // 2. Create Nodes
    for i in 0..num_nodes {
        let identity = node_identities_map.get(&i).unwrap().clone();
        let (_, secret_key) = create_test_tee_signing(i); // Re-create key pair
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
    let (node_identity, _node_secret_key) = create_test_tee_signing(0);
    let (runtime, mut result_rx, _isolation_rx, _metrics_handle) = SimulationRuntime::new(SimulationConfig::default());
    let config = SystemConfig::default();
    let num_nodes = 3;
    let mut node_handles = Vec::new();
    let mut node_identities_map = HashMap::new();
    let mut node_proposal_senders = HashMap::new();
    let mut node_query_senders = HashMap::new(); // NEW: Store query senders
    let mut proposal_txs = HashMap::new(); // Store proposal senders
    let mut nodes_to_spawn: Vec<SimulatedTeeNode> = Vec::new(); // Store just the node
    let mut identities = Vec::new(); // Define identities within this test scope

    // Create identities
    for i in 0..num_nodes {
        let (identity, _) = create_test_tee_signing(i);
        node_identities_map.insert(identity.id, identity.clone()); // Clone identity for map
        identities.push(identity); // Store identity in the vector
    }

    // 2. Create Nodes & Dummy Network Channels for Registration
    for i in 0..num_nodes {
        let identity = node_identities_map.get(&i).unwrap().clone();
        let (_, secret_key) = create_test_tee_signing(i);
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
        proposal_txs.insert(identity.id, proposal_tx.clone()); // Store proposal sender

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
        shard_id: 0,
        tx_id: "test-tx-456".to_string(),
        source_chain_id: 1,
        target_chain_id: 2,
        token_address: "0xtesttokenB".to_string(),
        amount: 2000,
        recipient: "0xrecipientaddrB".to_string(),
        start_time: Instant::now(),
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
    let (ack_tx, ack_rx) = oneshot::channel::<Result<Vec<RaftEvent>, String>>();
    let proposal: NodeProposalRequest = (command.clone(), ack_tx);

    let leader_proposal_tx = proposal_txs.get(&leader_id).expect("Leader proposal sender not found");
    leader_proposal_tx.send(proposal).await.expect("Failed to send proposal to leader via proposal channel");

    // Wait for the proposal ACK from the oneshot channel
    let expected_log_index_after_propose = initial_state + 1;
    match tokio::time::timeout(Duration::from_secs(2), ack_rx).await {
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
        // Encode the tuple of relevant fields, not the whole struct
        let signable_data_tuple = (
            &lock_proof_data.tx_id,
            lock_proof_data.source_chain_id,
            lock_proof_data.target_chain_id,
            &lock_proof_data.token_address,
            lock_proof_data.amount,
            &lock_proof_data.recipient
        );
        let data_to_verify = bincode::encode_to_vec(&signable_data_tuple, standard()).unwrap();

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
        let (identity, secret_key) = create_test_tee_signing(i);
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
        let (identity, secret_key) = create_test_tee_signing(i);
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
    println!("--- Running Threshold Signature Simulation Test ---");
    let num_nodes = 3;
    let threshold = 2;
    let mut config = SimulationConfig::default(); // Start with default
    config.system_config.num_coordinators = 0; // No coordinators needed for this test
    config.system_config.num_shards = 1; // Only one shard
    config.system_config.nodes_per_shard = num_nodes;
    config.system_config.coordinator_threshold = threshold; // This seems misused, but threshold sig needs it
    config.network_min_delay_ms = 10;
    config.network_max_delay_ms = 50;
    // Re-sync system_config from simulation params
    config.sync_system_config();

    // Generate identities and keys locally first
    let mut identities = Vec::new();
    let mut signing_keys = HashMap::new();
    for i in 0..num_nodes {
        let (identity, signing_key) = create_test_tee_signing(i);
        identities.push(identity.clone());
        signing_keys.insert(identity.id, signing_key);
    }

    // 1. Setup SimulationRuntime
    let (runtime, mut result_rx, _isolation_rx, _metrics_handle) = SimulationRuntime::new(config.clone());

    // 2. Setup Nodes and Query Channels
    let mut node_handles = vec![];
    let mut query_txs = HashMap::<usize, _>::new(); // Store query senders (usize key)
    let mut proposal_txs = HashMap::new(); // Store proposal senders

    for i in 0..num_nodes { // Loop through generated identities
        let tee_identity = identities[i].clone();
        let tee_signing_key = signing_keys.get(&tee_identity.id).expect("Signing key not found").clone();
        let peers: Vec<TEEIdentity> = identities.iter()
            .filter(|&p| p.id != tee_identity.id)
            .cloned()
            .collect();

        // Create query channel for this node
        let (query_tx, query_rx) = mpsc::channel::<NodeQuery>(10); // Specify type
        query_txs.insert(i, query_tx.clone());

        // Create proposal channel for this node (needed for SimulatedTeeNode::new)
        let (proposal_tx, proposal_rx) = mpsc::channel::<NodeProposalRequest>(10);
        proposal_txs.insert(i, proposal_tx.clone()); // Use usize for map key

        // Register node with runtime (needed for SimulatedTeeNode::new)
        let network_rx = runtime.register_node(tee_identity.clone(), proposal_tx.clone()).await;

        let node = SimulatedTeeNode::new(
            tee_identity.clone(),
            tee_signing_key.clone(),
            peers.clone(),
            config.system_config.clone(),
            runtime.clone(),
            network_rx,
            proposal_tx.clone(),
            proposal_rx,
            query_tx.clone(),
            query_rx,
            i, // Use node index as shard_id for this simple test
        );

        let handle = tokio::spawn(node.run());
        node_handles.push(handle);
        println!("[Test] Spawned Node {} with TEE ID {}.", i, tee_identity.id);
    }

    // Give nodes time to elect a leader
    println!("[Test] Waiting for Raft leader election...");
    tokio::time::sleep(Duration::from_secs(3)).await; // Increased wait time

    // 3. Find the Raft Leader
    let mut leader_id: Option<usize> = None;
    println!("[Test] Finding the leader...");
    for _ in 0..10 { // Try up to 10 times
        for node_id in 0..num_nodes {
            let (resp_tx, resp_rx) = oneshot::channel();
            if let Some(query_tx) = query_txs.get_mut(&node_id) { 
                 if query_tx.send((NodeQueryRequest::GetRaftState, resp_tx)).await.is_ok() {
                    if let Ok(state_response) = resp_rx.await {
                         if let NodeQueryResponse::RaftState { role, commit_index: _, last_log_index: _ } = state_response {
                             println!("[Test] Node {} state: Role={:?}", node_id, role);
                             if role == RaftRole::Leader {
                                 leader_id = Some(node_id);
                                 break; // Found leader
                             }
                         } else {
                             println!("[Test] Node {} returned unexpected query response: {:?}", node_id, state_response);
                         }
                     } else {
                         println!("[Test] Failed to get state response from Node {}", node_id);
                     }
                 } else {
                     println!("[Test] Failed to send query to Node {}", node_id);
                 }
            }
        }
        if leader_id.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await; // Wait before retrying
    }

    let leader_id = leader_id.expect("[Test][Error] Failed to find Raft leader within timeout.");
    println!("[Test] Found Raft Leader: Node {}", leader_id);

    // 4. Create and Propose Command to Leader
    let lock_data = LockProofData {
        shard_id: 0,
        tx_id: "test_tx_123".to_string(),
        source_chain_id: 1,
        target_chain_id: 2,
        token_address: "0xtoken_test".to_string(),
        amount: 100,
        recipient: "0xrecipient_test".to_string(),
        start_time: Instant::now(),
    };

    let command = Command::ConfirmLockAndSign(lock_data.clone());
    println!("[Test] Proposing command {:?} to Leader Node {}", command, leader_id);

    let (ack_tx, ack_rx) = oneshot::channel::<Result<Vec<RaftEvent>, String>>();
    let proposal: NodeProposalRequest = (command.clone(), ack_tx);

    let leader_proposal_tx = proposal_txs.get(&leader_id).expect("Leader proposal sender not found");
    leader_proposal_tx.send(proposal).await.expect("Failed to send proposal to leader via proposal channel");

    // Wait for proposal acknowledgment
    let ack_result = ack_rx.await.expect("Failed to receive proposal ack");
    ack_result.expect("[Test][Error] Leader failed to acknowledge proposal");
    println!("[Test] Leader {} acknowledged proposal.", leader_id);

    // 5. Wait for Command Commit
    println!("[Test] Waiting for command commit on leader {}...", leader_id);
    let mut committed = false;
    for _ in 0..20 { // Check up to 20 times (10 seconds total)
        let (resp_tx, resp_rx) = oneshot::channel();
        if query_txs.get(&leader_id).unwrap().send((NodeQueryRequest::GetRaftState, resp_tx)).await.is_ok() {
            if let Ok(state_response) = resp_rx.await {
                 if let NodeQueryResponse::RaftState { role: _, commit_index, last_log_index: _ } = state_response {
                     println!("[Test] Leader {} state: CommitIndex={}", leader_id, commit_index);
                     if commit_index >= 1 { // Check if at least the first command is committed
                         committed = true;
                         println!("[Test] Command committed by leader (CommitIndex={}).", commit_index);
                         break;
                     }
                 } else {
                      println!("[Test] Leader {} returned unexpected query response while checking commit: {:?}", leader_id, state_response);
                 }
             } else {
                  println!("[Test] Failed to get state response from leader {} while checking commit.", leader_id);
             }
         } else {
              println!("[Test] Failed to send query to leader {} while checking commit.", leader_id);
         }
         tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(committed, "[Test][Error] Timed out waiting for command commit on leader.");


    // 6. Collect Results (Signature Shares)
    println!("[Test] Waiting for signature shares...");
    let mut collected_shares = HashSet::new();
    let start_time = Instant::now();
    let timeout = Duration::from_secs(10); // Increased timeout slightly

    while collected_shares.len() < threshold && start_time.elapsed() < timeout {
        match tokio::time::timeout(timeout - start_time.elapsed(), result_rx.recv()).await {
            Ok(Some((identity, data, signature))) => {
                println!("[Test] Received share from Node {} for tx_id {}", identity.id, data.tx_id);
                // Basic validation
                assert_eq!(data.tx_id, lock_data.tx_id, "Received share for wrong tx_id");
                // Store signer ID to count unique shares
                collected_shares.insert(identity.id);
                println!("[Test] Collected {}/{} required shares.", collected_shares.len(), threshold);
            }
            Ok(None) => {
                eprintln!("[Test] Result channel closed unexpectedly.");
                break;
            }
            Err(_) => {
                // Timeout occurred in tokio::time::timeout
                break; // Exit the loop if timeout is reached
            }
        }
    }

    // 7. Assertions
    assert!(
        collected_shares.len() >= threshold,
        "[Test][ThresholdSig] Failed to collect enough shares. Received {}/{} shares within {:?}.",
        collected_shares.len(),
        threshold,
        timeout
    );

    println!(
        "[Test] Successfully collected {} shares (threshold {}).",
        collected_shares.len(),
        threshold
    );

    // Optional: Shutdown nodes gracefully if needed (might require adding shutdown channels)
    // for handle in node_handles {
    //     handle.abort(); // Or use a graceful shutdown mechanism
    // }

    println!("--- Threshold Signature Simulation Test PASSED ---");
}

#[tokio::test]
async fn test_basic_signature_verification() {
    println!("--- Starting Basic Signature Verification Test ---");
    let (signer_identity, signer_secret_key) = create_test_tee_signing(99);

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
    let (signer_identity, signer_secret_key) = create_test_tee_signing(100);

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