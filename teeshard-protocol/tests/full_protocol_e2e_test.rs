// teeshard-protocol/tests/full_protocol_e2e_test.rs

// Integration test simulating the full protocol flow:
// ShardManager -> Raft Consensus -> Coordinator -> Relayer -> EVM

use teeshard_protocol::{
    config::SystemConfig,
    data_structures::{
        AccountId, AssetId, LockInfo, Transaction, TEEIdentity, TxType,
    },
    shard_manager::ShardManager,
    tee_logic::{crypto_sim::SecretKey, types::LockProofData},
    simulation::{SimulationRuntime, SimulatedTeeNode, coordinator::SimulatedCoordinator, node::{NodeProposalRequest, NodeQuery}},
    raft::messages::RaftMessage,
    liveness::types::{LivenessAttestation, ChallengeNonce},
    liveness::{
        aggregator::Aggregator,
        challenger::Challenger,
        types::{LivenessConfig},
    },
};
use ethers::{types::{Address, U256}, prelude::*};
use tokio::sync::mpsc;
use std::path::PathBuf;
use std::time::Duration;
use std::sync::Arc;
use std::collections::HashMap;
use regex::Regex;
use teeshard_protocol::onchain::evm_relayer::{EvmRelayer, EvmRelayerConfig, ChainConfig};
use tokio::process::Command as TokioCommand;
use teeshard_protocol::simulation::CoordinatorCommand;
use teeshard_protocol::onchain::BlockchainInterface;

// Helper to create TEE Identity and SecretKey (can be shared with other tests)
fn create_test_tee(id: usize) -> (TEEIdentity, SecretKey) {
    let secret_bytes = [id as u8; 32];
    let secret_key = SecretKey::from_bytes(&secret_bytes);
    let public_key = secret_key.verifying_key();
    (TEEIdentity { id, public_key }, secret_key)
}

#[derive(Debug, Clone)]
struct DeployedContracts {
    token_addr_a: Address,
    escrow_addr_a: Address,
    token_addr_b: Address,
    escrow_addr_b: Address,
}

async fn run_forge_script_and_get_addresses() -> Result<DeployedContracts, String> {
    println!("[Setup] Running forge script to deploy contracts...");

    // Determine the root of the workspace
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf();
    let evm_sim_path = workspace_root.join("evm-simulation");
    let script_path = evm_sim_path.join("script/CrossChainSwap.s.sol:CrossChainSwapScript");

    // --- Define RPC URLs used by the script --- 
    // Must match the running Anvil instances
    let rpc_url_a = "http://localhost:8545";
    // let rpc_url_b = "http://localhost:8546"; // Only need A for broadcasting from script deployer

    // Use aliased TokioCommand
    println!("[Setup] Forge script command starting...");
    let output = TokioCommand::new("forge") // Use alias
        .arg("script")
        .arg(script_path)
        // .arg("--json") // Remove --json, parse stdout directly
        .arg("--broadcast") // Add broadcast flag to actually deploy
        .arg("--rpc-url")
        .arg(rpc_url_a) // Specify RPC for the broadcast
        // Optional: Specify private key if not using default Anvil 0 key in script
        // .arg("--private-key")
        // .arg("...") 
        .current_dir(&evm_sim_path) // Run from within the evm-simulation directory
        .output() // This returns a future
        .await // .await is now correct
        .map_err(|e| format!("Failed to execute forge script: {}", e))?;

    let stdout_str = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr_str = String::from_utf8_lossy(&output.stderr).to_string();

    println!("[Setup] Forge script stdout:\n{}", stdout_str);
    println!("[Setup] Forge script stderr:\n{}", stderr_str);

    if !output.status.success() {
        return Err(format!(
            "Forge script execution failed with status {}\nStderr: {}", 
            output.status, stderr_str
        ));
    }

    // Parse stdout string directly for the log lines
    println!("[Setup] Parsing stdout for contract addresses...");
    let token_addr_a: Address = extract_address_from_log(&stdout_str, "Token A deployed at:")?;
    let escrow_addr_a: Address = extract_address_from_log(&stdout_str, "Escrow A deployed at:")?;
    let token_addr_b: Address = extract_address_from_log(&stdout_str, "Token B deployed at:")?;
    let escrow_addr_b: Address = extract_address_from_log(&stdout_str, "Escrow B deployed at:")?;

    println!("[Setup] Extracted Deployed Contract Addresses:");
    println!("  Token A: {:?}", token_addr_a);
    println!("  Escrow A: {:?}", escrow_addr_a);
    println!("  Token B: {:?}", token_addr_b);
    println!("  Escrow B: {:?}", escrow_addr_b);

    Ok(DeployedContracts {
        token_addr_a,
        escrow_addr_a,
        token_addr_b,
        escrow_addr_b,
    })
}

// Helper to parse addresses from logs (adjust regex if needed)
fn extract_address_from_log(log_output: &str, label: &str) -> Result<Address, String> {
    let pattern = format!(r"{}\s*(0x[a-fA-F0-9]{{40}})", regex::escape(label));
    let re = Regex::new(&pattern).unwrap(); // Panic if regex invalid - should be fixed in code
    if let Some(caps) = re.captures(log_output) {
        if let Some(addr_match) = caps.get(1) {
            addr_match.as_str().parse::<Address>()
                .map_err(|e| format!("Failed to parse address '{}' for label '{}': {}", addr_match.as_str(), label, e))
        } else {
            Err(format!("Could not find address capture group for label '{}'", label))
        }
    } else {
        Err(format!("Could not find log line with label '{}'", label))
    }
}

#[tokio::test]
async fn test_full_protocol_e2e() -> Result<(), String> {
    println!("--- Starting Full Protocol E2E Test ---");

    // *** ADD: Run Forge Script FIRST ***
    let deployed_contracts = run_forge_script_and_get_addresses().await?;

    // 1. System Configuration & Identities
    let num_nodes = 6; // Example: 6 nodes total
    let num_shards = 2; // Example: Target 2 shards
    let mut identities = Vec::new();
    for i in 0..num_nodes {
        let (identity, _) = create_test_tee(i);
        identities.push(identity);
    }

    let config = SystemConfig {
        nodes_per_shard: num_nodes / num_shards, // Aim for even distribution
        // Coordinator config (placeholder for now)
        coordinator_identities: vec![identities[0].clone()], // Node 0 is coordinator for now
        coordinator_threshold: 1,
        ..Default::default() // Use default raft timings etc.
    };
    println!("[Setup] System configured with {} nodes, aiming for {} shards.", num_nodes, num_shards);

    // 2. Shard Manager Integration

    // 2a. Instantiate Shard Manager
    // ShardManager now only takes config
    let mut shard_manager = ShardManager::new(config.clone()); // Clone config if needed elsewhere
    println!("[Setup] ShardManager instantiated.");

    // 2b. Create Sample Transactions
    // Define some accounts and assets involved in potential swaps
    let user_a_addr_str = "0xF38cA7A356584B8ede96615fd09E130A02b8b8c6"; // From script default
    let user_b_addr_str = "0x60B162Ba495Ce3E498E805B49f439D0246FC0c07"; // From script default
    let chain_id_a: u64 = 1; // MUST match Anvil instance
    let chain_id_b: u64 = 10; // MUST match Anvil instance

    let user_a_chain1 = AccountId { chain_id: chain_id_a, address: user_a_addr_str.to_string() };
    let user_b_chain2 = AccountId { chain_id: chain_id_b, address: user_b_addr_str.to_string() };

    // Use deployed contract addresses for assets
    let token_a_chain1 = AssetId {
        chain_id: chain_id_a,
        token_symbol: "TKA".to_string(), // Symbol remains descriptive
        token_address: format!("{:?}", deployed_contracts.token_addr_a),
    };
    let token_b_chain2 = AssetId {
        chain_id: chain_id_b,
        token_symbol: "TKB".to_string(),
        token_address: format!("{:?}", deployed_contracts.token_addr_b),
    };

    let swap_amount = 100u64; // Match script's SWAP_AMOUNT, USE u64
    // --- Define scaled amount early --- 
    let decimals = 18;
    let scale = U256::from(10).pow(U256::from(decimals));
    let swap_amount_u256 = U256::from(swap_amount) * scale;
    // --- End scaled amount definition ---

    let transactions = vec![
        // Swap 1: A (Chain 1) -> B (Chain 2)
        Transaction {
            tx_id: "e2e_swap1".to_string(),
            tx_type: TxType::CrossChainSwap,
            accounts: vec![user_a_chain1.clone(), user_b_chain2.clone()],
            amounts: vec![swap_amount], // Use u64
            required_locks: vec![LockInfo { account: user_a_chain1.clone(), asset: token_a_chain1.clone(), amount: swap_amount }], // Use u64
            target_asset: Some(token_b_chain2.clone()),
            timeout: Duration::from_secs(300),
        },
    ];
    println!("[Setup] Created {} sample transactions.", transactions.len());

    // 2c. Run Shard Manager Algorithms
    println!("[Setup] Running ShardManager partitioning...");
    
    // Construct graph (modifies internal state)
    shard_manager.construct_and_weight_graph(&transactions);
    println!("[Setup] Constructed graph."); // Simplified log
    
    // Perform initial partition (uses config.num_shards internally)
    shard_manager.initial_partition();
    println!("[Setup] Generated initial partition."); // Simplified log
    
    // Run iterative refinement (uses config.max_iterations internally)
    shard_manager.iterative_refine();
    println!("[Setup] Iterative refinement complete.");

    // Assign TEE nodes to the calculated partitions
    shard_manager.assign_tee_nodes(&identities);
    println!("[Setup] TEE nodes assigned to shards.");

    // Retrieve results from the manager's state
    let final_partitions = shard_manager.partitions.clone(); // Clone if needed later
    let final_mapping = shard_manager.account_to_shard.clone(); // Clone if needed later

    println!("[Setup] Final Partition Mapping (Account -> Shard ID): {:?}", final_mapping);
    println!("[Setup] Final Shard Partitions (Shard ID -> Nodes):");
    for partition in &final_partitions { // Iterate over the cloned results
         let node_ids: Vec<usize> = partition.tee_nodes.iter().map(|n| n.id).collect();
         println!("  Shard {}: Nodes {:?}", partition.shard_id, node_ids);
    }

    // 2d. TODO: Use Partitioning Results
    // - The `final_partitions` (Vec<ShardPartition>) tells us which TEEIdentity belongs to which shard_id.
    //   This will be used to configure the SimulationRuntime, assigning nodes to shards.
    // - The `final_mapping` (PartitionMapping: HashMap<AccountId, usize>) tells us which shard_id is responsible for which account.
    //   This needs to be given to the CrossChainCoordinator so it knows where to send commands.

    // 3. Setup Simulation Runtime & Nodes based on Sharding
    println!("[Setup] Setting up Simulation Runtime and Nodes...");
    let (runtime, mut result_rx, attestation_rx_agg, mut isolation_rx) = SimulationRuntime::new();

    let mut node_handles = Vec::new();
    let mut node_message_senders: HashMap<usize, tokio::sync::mpsc::Sender<(TEEIdentity, RaftMessage)>> = HashMap::new();
    let mut node_proposal_senders: HashMap<usize, tokio::sync::mpsc::Sender<NodeProposalRequest>> = HashMap::new();
    let mut node_query_senders: HashMap<usize, tokio::sync::mpsc::Sender<NodeQuery>> = HashMap::new();
    let mut nodes_to_spawn: Vec<SimulatedTeeNode> = Vec::new(); // Store nodes before spawning

    // --- Create and Register Nodes for each Shard --- 
    for partition in &final_partitions {
        let shard_id = partition.shard_id;
        let nodes_in_shard = &partition.tee_nodes;
        println!("[Setup] Creating nodes for Shard {}: {:?}", shard_id, nodes_in_shard.iter().map(|n| n.id).collect::<Vec<_>>());
        for tee_identity in nodes_in_shard {
            let (_, secret_key) = create_test_tee(tee_identity.id);
            let peers: Vec<TEEIdentity> = nodes_in_shard.iter().filter(|&p| p.id != tee_identity.id).cloned().collect();
            let (challenge_tx, challenge_rx) = mpsc::channel(10);
            let node = SimulatedTeeNode::new(
                tee_identity.clone(), secret_key, peers, config.clone(), runtime.clone(),
                challenge_rx, challenge_tx.clone(), 
            );
            runtime.register_node(tee_identity.clone(), node.get_message_sender(), node.get_proposal_sender(), node.get_challenge_sender());
            nodes_to_spawn.push(node);
        }
        runtime.assign_nodes_to_shard(shard_id, nodes_in_shard.clone());
    }
    
    // --- Spawn Node Tasks --- 
    let node_to_fail_id = 2; // Choose a node to fail (ensure it exists)
    let mut failed_node_handle = None;
    for node in nodes_to_spawn {
        let id = node.identity.id;
        let handle = tokio::spawn(node.run());
        if id == node_to_fail_id {
            println!("[Test Setup] Intentionally failing Node {} by aborting its task shortly.", id);
            failed_node_handle = Some(handle); // Store handle to abort later
        } else {
            node_handles.push(handle); // Store handles for cleanup
        }
        println!("[Setup] Spawned node {} task.", id);
    }
    // Abort the designated failed node's task after a brief moment
    if let Some(ref handle) = failed_node_handle {
        println!("[Test Setup] Waiting 30 seconds before failing Node {}...", node_to_fail_id);
        tokio::time::sleep(Duration::from_secs(30)).await; // NEW longer sleep
        handle.abort();
        println!("[Test Setup] Aborted task for Node {}.", node_to_fail_id);
    }
    println!("[Setup] Spawned/Managed {} node tasks.", node_handles.len() + if failed_node_handle.is_some() {1} else {0});
    
    // --- Setup Liveness Components --- 
    println!("[Setup] Setting up Liveness Challenger and Aggregator...");
    let liveness_config = LivenessConfig::from(&config);
    let (agg_challenge_tx, agg_challenge_rx) = mpsc::channel::<ChallengeNonce>(50);
    
    // Create Challenger
    let mut challenger = Challenger::new(identities.clone(), runtime.clone(), agg_challenge_tx);
    
    // Create Aggregator
    let (aggregator_instance, challenge_rx_agg) = Aggregator::new(liveness_config.clone(), identities.clone(), runtime.clone(), agg_challenge_rx);
    let aggregator = Arc::new(aggregator_instance); 
    
    // --- Register Aggregator Sender with Runtime --- 
    let aggregator_attestation_sender = runtime.take_aggregator_attestation_sender()
        .expect("Runtime should have an aggregator attestation sender to take");
    runtime.register_aggregator(aggregator_attestation_sender);
    println!("[Setup] Registered Aggregator attestation sender with Runtime.");

    // Spawn Challenger Task
    let challenger_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5)); // Example challenge interval
        loop {
            interval.tick().await;
            challenger.issue_challenges().await;
        }
    });
    println!("[Setup] Spawned Challenger task.");

    // Spawn Aggregator Listener Tasks
    let agg_challenge_listener_handle = {
        let agg_clone = aggregator.clone();
        tokio::spawn(async move {
            agg_clone.run_challenge_listener(challenge_rx_agg).await;
        })
    };
    let agg_attestation_listener_handle = {
        let agg_clone = aggregator.clone();
        tokio::spawn(async move {
            agg_clone.run_attestation_listener(attestation_rx_agg).await;
        })
    };
    
    // --- Add print BEFORE spawning timeout checker ---
    println!("!!! [Setup] About to spawn run_timeout_checker task..."); 
    let agg_timeout_checker_handle = {
        tokio::spawn(async move {
            let agg_clone = aggregator.clone(); 
            agg_clone.run_timeout_checker().await;
        })
    };
    println!("[Setup] Spawned Aggregator listener and checker tasks."); // Original log remains

    // 4. Setup *Actual* EVM Relayer
    println!("[Setup] Setting up EVM Relayer...");
    // Configure Relayer
    let relayer_private_key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // Anvil default 0
    let rpc_url_a = "http://localhost:8545";
    let rpc_url_b = "http://localhost:8546";

    // --- Adjust config structure --- 
    let mut chain_details = HashMap::new();
    chain_details.insert(chain_id_a, ChainConfig {
        rpc_url: rpc_url_a.to_string(),
        escrow_address: format!("{:?}", deployed_contracts.escrow_addr_a),
    });
    chain_details.insert(chain_id_b, ChainConfig {
        rpc_url: rpc_url_b.to_string(),
        escrow_address: format!("{:?}", deployed_contracts.escrow_addr_b),
    });

    let relayer_config = EvmRelayerConfig {
        // Assuming cast is in PATH or provide full path
        cast_path: PathBuf::from("cast"), 
        chain_details,
        relayer_private_key: relayer_private_key_hex.to_string(),
        // Remove fields not present in the struct:
        // chain_rpc_urls: ...,
        // escrow_addresses: ...,
        // token_addresses: ...,
        // relayer_wallet: ...,
        // tee_committee: ...,
        // tee_threshold: ...,
    };
    // ---

    // Create the actual relayer instance
    let evm_relayer = Arc::new(EvmRelayer::new(relayer_config));
    println!("[Setup] EVM Relayer initialized.");

    // 5. Setup Refactored CrossChainCoordinator
    println!("[Setup] Setting up Coordinator and tasks...");
    // Need to interact with the coordinator running in its task. Use channels.
    // Import the command enum instead of defining it locally
    // use teeshard_protocol::simulation::coordinator::CoordinatorCommand;

    // REMOVE local definition
    // #[derive(Debug)]
    // pub enum CoordinatorCommand {
    //     ProcessObservedLock { tx: Transaction, lock_data: LockProofData },
    //     // Add other commands if needed
    // }
    let (coord_cmd_tx, coord_cmd_rx) = mpsc::channel::<CoordinatorCommand>(10);

    let (coord_identity, coord_secret) = create_test_tee(0); // Still assuming node 0 is coordinator
    let coordinator = Arc::new(SimulatedCoordinator::new( // Wrap coordinator in Arc for cloning into tasks
        coord_identity.clone(),
        coord_secret,
        config.clone(),
        runtime.clone(), // Runtime handle is Clone
        evm_relayer.clone(), // Relayer is Arc, clone is cheap
        final_mapping,
        // Don't pass receiver to new() anymore
    ));
    println!("[Setup] Coordinator instance created.");

    // Spawn the coordinator tasks
    let coordinator_share_listener = coordinator.clone(); // Clone Arc for the task
    let share_listener_handle = tokio::spawn(async move {
        coordinator_share_listener.run_share_listener(result_rx).await;
    });
    println!("[Setup] Coordinator share listener task spawned.");

    let coordinator_command_listener = coordinator.clone(); // Clone Arc for the task
    let command_listener_handle = tokio::spawn(async move {
        coordinator_command_listener.run_command_listener(coord_cmd_rx).await;
    });
    println!("[Setup] Coordinator command listener task spawned.");

    // --- Get Initial Balance for Verification ---
    println!("\n[Setup] Querying initial balances...");
    let initial_user_a_balance_a = evm_relayer.get_balance(
        chain_id_a,
        user_a_chain1.address.clone(), // User A address string
        token_a_chain1.token_address.clone() // Token A address string
    ).await.map_err(|e| format!("Failed to get initial User A balance on Chain A: {}", e))?;
    println!("[Setup] Initial User A Balance (Chain A): {}", initial_user_a_balance_a);
    // ---

    // 6. Execute Test Scenario

    // A. Calculate Swap ID (Assume lock transaction was done by deploy script)
    println!("\n[Test] Assuming User A lock funds on Chain A was performed by deploy script...");
    let user_a_pk_hex = "9b2391031a7612fc7003c8fa79b50982471c694892bdc273dd9c379631751a59"; // Keep for potential future use? Maybe remove if not needed.
    let swap_id_bytes: [u8; 32] = ethers::utils::keccak256(transactions[0].tx_id.as_bytes());
    println!("[Test] Generated/Expected bytes32 swap_id: 0x{}", hex::encode(swap_id_bytes));

    // --- REMOVED ERC20 Approve Call --- 
    // println!("[Test] Approving Escrow A to spend User A's tokens...");
    // let approve_tx_hash = evm_relayer.approve_erc20(...).await?;
    // println!("[Test] Approve transaction sent, tx_hash: {}", approve_tx_hash);
    // tokio::time::sleep(Duration::from_secs(2)).await;
    // ---

    // --- REMOVED Explicit Lock Call --- 
    // println!("[Test] User A locking funds on Chain A via Relayer..."); // Adjusted print statement
    // let lock_tx_receipt = evm_relayer.lock(
    //     chain_id_a,
    //     user_a_pk_hex.to_string(),
    //     swap_id_bytes, 
    //     transactions[0].accounts[1].address.clone(),
    //     transactions[0].required_locks[0].asset.token_address.clone(), 
    //     swap_amount_u256, // <-- USE SCALED U256 AMOUNT HERE
    //     3600 
    // ).await.map_err(|e| format!("Failed to execute lock transaction: {}", e))?;
    // println!("[Test] Lock transaction sent, tx_hash: {}", lock_tx_receipt);
    // ---

    // B. Simulate observing the lock event and informing the coordinator
    println!("\n[Test] Simulating lock observation (from deploy script) and sending command to Coordinator...");
    // Construct LockProofData - IMPORTANT: Ensure tx_id here matches the hex of swap_id_bytes
    let lock_data_swap1 = LockProofData {
        tx_id: hex::encode(swap_id_bytes), // Use the hex-encoded swap_id_bytes
        source_chain_id: transactions[0].required_locks[0].asset.chain_id,
        target_chain_id: transactions[0].target_asset.as_ref().unwrap().chain_id,
        token_address: transactions[0].required_locks[0].asset.token_address.clone(),
        amount: transactions[0].required_locks[0].amount,
        recipient: transactions[0].accounts[1].address.clone(),
    };

    // Send command to the coordinator task using the correct variant
    coord_cmd_tx.send(CoordinatorCommand::ProcessObservedLock { // Use correct variant
        tx: transactions[0].clone(),
        lock_data: lock_data_swap1,
    }).await.map_err(|e| format!("Failed to send command to coordinator: {}", e))?;
     println!("[Test] ProcessObservedLock command sent to coordinator.");

    // C. Allow time for simulation and processing
    println!("[Test] Waiting for Raft consensus, share generation, aggregation, and release...");
    tokio::time::sleep(Duration::from_secs(10)).await; 

    // 7. Verification (Fetch Balances First)
    println!("\n[Test] Fetching final state on EVM chains for verification...");

    // Fetch final balances on Chain A
    let user_a_balance_a_final = evm_relayer.get_balance(
        chain_id_a,
        user_a_chain1.address.clone(), // Use address string directly
        token_a_chain1.token_address.clone()
    ).await.map_err(|e| format!("Failed to get User A balance on Chain A: {}", e))?;
    let escrow_a_balance_final = evm_relayer.get_balance(
        chain_id_a,
        format!("{:?}", deployed_contracts.escrow_addr_a), // Escrow address as string
        format!("{:?}", deployed_contracts.token_addr_a)  // Token address as string
    ).await.map_err(|e| format!("Failed to get Escrow A balance on Chain A: {}", e))?;
    
    // Fetch final balances on Chain B
    let user_b_balance_b_final = evm_relayer.get_balance(
        chain_id_b,
        user_b_chain2.address.clone(), // User B address string
        token_b_chain2.token_address.clone() // Token B address string
    ).await.map_err(|e| format!("Failed to get User B balance on Chain B: {}", e))?;
     let escrow_b_balance_final = evm_relayer.get_balance(
        chain_id_b,
        format!("{:?}", deployed_contracts.escrow_addr_b), // Escrow address string
        format!("{:?}", deployed_contracts.token_addr_b) // Token address string
    ).await.map_err(|e| format!("Failed to get Escrow B balance on Chain B: {}", e))?;

    println!("[Verify] Fetched Balances:");
    println!("  User A (Chain A): Final={}, Initial={}", user_a_balance_a_final, initial_user_a_balance_a);
    println!("  Escrow A (Chain A): Final={}, Expected={}", escrow_a_balance_final, swap_amount_u256);
    println!("  User B (Chain B): Final={}, Expected={}", user_b_balance_b_final, swap_amount_u256);
    println!("  Escrow B (Chain B): Final={}, Expected={}", escrow_b_balance_final, U256::zero());

    // --- Store Balance Check Results --- 
    let initial_escrow_a_balance = U256::zero(); // Escrow starts empty
    let user_a_balance_ok = user_a_balance_a_final == initial_user_a_balance_a;
    let escrow_a_balance_ok = escrow_a_balance_final == initial_escrow_a_balance + swap_amount_u256;
    let user_b_balance_ok = user_b_balance_b_final == swap_amount_u256;
    let escrow_b_balance_ok = escrow_b_balance_final == U256::zero();
    let all_balances_ok = user_a_balance_ok && escrow_a_balance_ok && user_b_balance_ok && escrow_b_balance_ok;

    // 8. Wait for Liveness Failure Detection and Isolation
    let liveness_wait_secs = 60; 
    println!("\n[Test] Waiting {} seconds for liveness system to isolate Node {}...", liveness_wait_secs, node_to_fail_id);
    tokio::time::sleep(Duration::from_secs(liveness_wait_secs)).await;

    // 9. Verify Isolation Report
    println!("[Test] Checking for isolation report for Node {}...", node_to_fail_id);
    let isolation_check_result = tokio::time::timeout(Duration::from_secs(1), isolation_rx.recv()).await;

    // --- Store Liveness Check Result --- 
    let mut isolation_ok = false;
    let mut isolation_report_content = "None received".to_string();
    match isolation_check_result {
        Ok(Some(isolated_ids)) => {
            println!("[Test] Received isolation report: {:?}", isolated_ids);
            isolation_report_content = format!("{:?}", isolated_ids);
            if isolated_ids.contains(&node_to_fail_id) {
                isolation_ok = true;
            } else {
                println!("[Verify FAIL] Isolation report {:?} did not contain failed node ID {}", isolated_ids, node_to_fail_id);
            }
        }
        Ok(None) => {
            println!("[Verify FAIL] Isolation channel closed unexpectedly while waiting for report for node {}", node_to_fail_id);
            isolation_report_content = "Channel closed".to_string();
        }
        Err(_) => {
            println!("[Verify FAIL] Timeout waiting for isolation report for node {}", node_to_fail_id);
            isolation_report_content = "Timeout".to_string();
        }
    }

    // 10. Final Summary and Assertion
    println!("\n--- Final E2E Test Summary ---");
    println!("Balance Checks (Expected Amount: {})", swap_amount_u256);
    // --- Update Print Statements for Balances --- 
    println!("  User A (Chain A): {} (Initial: {}, Final: {})", 
             if user_a_balance_ok { "OK" } else { "FAILED" }, 
             initial_user_a_balance_a, 
             user_a_balance_a_final);
    println!("  Escrow A (Chain A): {} (Expected: {}, Final: {})", 
             if escrow_a_balance_ok { "OK" } else { "FAILED" }, 
             swap_amount_u256, // Expected = initial (0) + swap_amount 
             escrow_a_balance_final);
    println!("  User B (Chain B): {} (Expected: {}, Final: {})", 
             if user_b_balance_ok { "OK" } else { "FAILED" }, 
             swap_amount_u256, 
             user_b_balance_b_final);
    println!("  Escrow B (Chain B): {} (Expected: 0, Final: {})", 
             if escrow_b_balance_ok { "OK" } else { "FAILED" }, 
             escrow_b_balance_final);
    // --- End Balance Print Updates --- 
    println!("Liveness Isolation Check:");
    println!("  Isolation of Node {}: {} (Report: {})", node_to_fail_id, if isolation_ok { "OK" } else { "FAILED" }, isolation_report_content);

    // Abort tasks *before* final assert to avoid hangs on failure
    println!("\n[Cleanup] Aborting remaining tasks...");
    challenger_handle.abort();
    agg_challenge_listener_handle.abort();
    agg_attestation_listener_handle.abort();
    agg_timeout_checker_handle.abort();
    share_listener_handle.abort();
    command_listener_handle.abort();
    for handle in node_handles { // Only abort nodes that weren't the failed one
        handle.abort();
    }
    
    // Final assertion for the overall test result
    assert!(all_balances_ok && isolation_ok, "One or more E2E checks failed. See summary above.");

    println!("--- Full Protocol E2E Test (with Liveness Failure) Completed Successfully --- TBD by final assert");

    Ok(()) // Return Ok if the final assert passes
}
