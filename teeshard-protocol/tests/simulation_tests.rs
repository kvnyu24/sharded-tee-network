// teeshard-protocol/tests/simulation_tests.rs

use teeshard_protocol::{
    config::SystemConfig,
    data_structures::TEEIdentity,
    raft::{messages::{RaftMessage, RequestVoteArgs}, node::RaftEvent, state::{Command, RaftRole}},
    simulation::{
        node::NodeProposalRequest, // Import type for node proposal channel
        runtime::SimulationRuntime,
        node::SimulatedTeeNode,
        runtime::SignatureShare,
        node::{NodeQueryRequest, NodeQueryResponse, NodeQuery},
    },
    tee_logic::{crypto_sim::{SecretKey, verify}, types::LockProofData},
};
use std::time::Duration;
use std::collections::{HashMap, HashSet};
use tokio::sync::{mpsc, oneshot}; // Import mpsc
use bincode::config::standard; // For verification serialization
use hex; // Need hex for share verification output
// Import liveness types needed for node creation
use teeshard_protocol::liveness::types::ChallengeNonce;

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
    let (runtime, _result_rx, _attestation_rx, _isolation_rx) = SimulationRuntime::new(); // Capture all 4, ignore 3
    let config = SystemConfig::default();
    let num_nodes = 3;
    let mut node_handles = Vec::new();
    let mut node_identities_map = HashMap::new(); // Use map for easier lookup
    let mut nodes_to_spawn = Vec::new(); // Collect nodes before spawning

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
        let (challenge_tx, challenge_rx) = mpsc::channel::<ChallengeNonce>(10);
        let node = SimulatedTeeNode::new(
            identity.clone(),
            secret_key,
            peers,
            config.clone(),
            runtime.clone(),
            challenge_rx,
            challenge_tx.clone(),
        );
        runtime.register_node(
            identity, 
            node.get_message_sender(),
            node.get_proposal_sender(),
            challenge_tx,
        );
        nodes_to_spawn.push(node);
    }

    // 3. Spawn node tasks
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

    // 5. Cleanup
    for (_id, handle) in node_handles {
        handle.abort(); // Abort tasks to ensure cleanup
    }
}

#[tokio::test]
async fn test_raft_state_machine_command_processing() {
    println!("--- Starting State Machine Command Processing Test ---");

    // 1. Setup Simulation Environment
    let (runtime, mut result_rx, _attestation_rx, _isolation_rx) = SimulationRuntime::new(); // Capture all 4, ignore 2
    let config = SystemConfig::default();
    let num_nodes = 3;
    let mut node_handles = Vec::new();
    let mut node_identities_map = HashMap::new();
    let mut node_proposal_senders = HashMap::new();
    let mut node_query_senders = HashMap::new(); // NEW: Store query senders
    let mut nodes_to_spawn = Vec::new();

    // Create identities
    for i in 0..num_nodes {
        let (identity, _) = create_test_tee(i);
        node_identities_map.insert(identity.id, identity);
    }

    // Create nodes
    for i in 0..num_nodes {
         let identity = node_identities_map.get(&i).unwrap().clone();
         let (_, secret_key) = create_test_tee(i);
         let peers: Vec<TEEIdentity> = node_identities_map.values()
            .filter(|id| id.id != identity.id)
            .cloned()
            .collect();

        let (challenge_tx, challenge_rx) = mpsc::channel::<ChallengeNonce>(10);
        let node = SimulatedTeeNode::new(
            identity.clone(),
            secret_key,
            peers,
            config.clone(),
            runtime.clone(),
            challenge_rx,
            challenge_tx.clone(),
        );
        node_proposal_senders.insert(identity.id, node.get_proposal_sender());
        node_query_senders.insert(identity.id, node.get_query_sender()); // NEW: Store query sender
        runtime.register_node(
            identity, 
            node.get_message_sender(),
            node.get_proposal_sender(),
            challenge_tx,
        );
        nodes_to_spawn.push(node);
    }

    // Spawn tasks
     for node in nodes_to_spawn {
        let id = node.identity.id;
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
    tokio::time::sleep(Duration::from_secs(2)).await; // Give time for AppendEntries round trip
    
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
        // Use the mpsc receiver from runtime.new()
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
        let data_to_verify = bincode::encode_to_vec(received_lock_data, standard()).expect("Serialization failed for verification");
        assert!(verify(&data_to_verify, signature, &signer_identity.public_key),
                "Invalid signature in share from Node {}", signer_identity.id);
        signer_ids.insert(signer_identity.id);
    }
    assert_eq!(signer_ids.len(), num_nodes, "Received shares from duplicate signers");

    println!("[Test] State Machine test finished SUCCESSFULLY.");

    // Cleanup node tasks
    for (_id, handle) in node_handles {
        handle.abort();
    }
}