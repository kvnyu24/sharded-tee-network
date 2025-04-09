// teeshard-protocol/tests/e2e_swap_test.rs

// This is an end-to-end integration test for the CrossChainCoordinator
// interacting with a real EvmRelayer and live Anvil instances.

// Test dependencies need to be added to Cargo.toml's [dependencies]
// if they are not already there (like rand, hex, regex, tokio)
// AND ensure dev-dependencies are sufficient for test helpers.

use teeshard_protocol::{
    config::SystemConfig,
    cross_chain::{
        swap_coordinator::{CrossChainCoordinator, SwapStatus},
        types::{LockProof, AbortReason},
    },
    data_structures::{
        AccountId, AssetId, LockInfo, TEEIdentity, Transaction, TxType,
    },
    // NetworkInterface needed for Coordinator::new
    network::{NetworkInterface, MockNetwork},
    onchain::{
        evm_relayer::{EvmRelayer, EvmRelayerConfig, ChainConfig},
        interface::{BlockchainInterface, BlockchainError, SwapId, SignatureBytes, TransactionId},
    },
    // Need crypto primitives for creating valid proofs/signatures
    tee_logic::{
        crypto_sim::{sign, generate_keypair, SecretKey, PublicKey},
        types::Signature,
    },
};

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    process::{Command as StdCommand, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
use regex::Regex;
use hex;
use rand::Rng; // For generating random swap IDs

// --- Test Configuration & Constants ---
const RPC_URL_A: &str = "http://localhost:8545";
const RPC_URL_B: &str = "http://localhost:8546";
const CHAIN_A_ID: u64 = 31337; // Default Anvil ID
const CHAIN_B_ID: u64 = 31337; // Use 31337 again if using the same Anvil instance

// Use known Anvil keys for testing
const RELAYER_PK: &str = "0x59c6995e998f97a5300194dc6916aa8c096e6d7d7f81a78f05791c43177926b8"; // Anvil default key 1
const USER_A_ADDR: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"; // Anvil default key 0
const USER_B_ADDR: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"; // Anvil default key 1

// Assume coordinator uses a pre-defined key for this test
// Important: The corresponding TEEIdentity with this public key must be in the SystemConfig
const COORDINATOR_TEE_ID: usize = 100;
const COORDINATOR_SECRET_KEY_BYTES: [u8; 32] = [100u8; 32];

// TEE key used *only* for signing the mock lock proof (doesn't need to be part of coordinator set)
const MOCK_SHARD_TEE_SECRET_KEY_BYTES: [u8; 32] = [50u8; 32];
const MOCK_SHARD_TEE_ID: usize = 50;

const CAST_PATH: &str = "cast"; // Assume cast is in PATH
// Paths relative to workspace root
const FORGE_SCRIPT_PATH: &str = "evm-simulation/script/CrossChainSwap.s.sol";
const EVM_SIM_DIR: &str = "evm-simulation"; // Root dir for forge script command


struct DeployedContracts {
    token_a_addr: String,
    escrow_a_addr: String,
    token_b_addr: String,
    escrow_b_addr: String,
}

// --- Helper Functions ---\n

// Runs forge script and parses contract addresses
// Adapted from evm_relayer tests
fn run_forge_script() -> Result<DeployedContracts, String> {
    println!("[HELPER] Running forge script to deploy contracts...");

    // Construct paths relative to CARGO_MANIFEST_DIR
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map_err(|_| "[HELPER] CARGO_MANIFEST_DIR env var not set".to_string())?;
    let workspace_root = std::path::Path::new(&manifest_dir).parent()
        .ok_or("[HELPER] Failed to get parent directory of CARGO_MANIFEST_DIR".to_string())?;
    
    // Use constants defined relative to workspace root
    let evm_sim_path = workspace_root.join(EVM_SIM_DIR);
    let script_path = workspace_root.join(FORGE_SCRIPT_PATH);

    println!("[HELPER] Workspace root calculated as: {:?}", workspace_root);
    println!("[HELPER] Using EVM Sim directory: {:?}", evm_sim_path);
    println!("[HELPER] Using Script path: {:?}", script_path);

    if !evm_sim_path.exists() {
        return Err(format!("[HELPER] EVM Sim directory not found at calculated path: {:?}", evm_sim_path));
    }
     if !script_path.exists() {
        return Err(format!("[HELPER] Forge script not found at calculated path: {:?}", script_path));
    }

    // Note: This assumes Anvil instances are already running on RPC_URL_A and RPC_URL_B
    let output = StdCommand::new("forge")
        .arg("script")
        .arg(&script_path) // Use the constructed script path
        .arg("--rpc-url")
        .arg(RPC_URL_A)
        .arg("--broadcast")
        .arg("--private-key") // Use relayer key to pay for deployment
        .arg(RELAYER_PK)
        .current_dir(&evm_sim_path) // Run from the calculated evm-simulation directory
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("[HELPER] Failed to execute forge script process: {}. Ensure 'forge' is in PATH.", e))?;

    if !output.status.success() {
        return Err(format!(
            "[HELPER] Forge script failed:\nStatus: {}\nStdout: {}\nStderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("[HELPER] Forge script output:\n{}
---", stdout);

    let token_a_re = Regex::new(r"Token A deployed at: (0x[a-fA-F0-9]{40})").unwrap();
    let escrow_a_re = Regex::new(r"Escrow A deployed at: (0x[a-fA-F0-9]{40})").unwrap();
    let token_b_re = Regex::new(r"Token B deployed at: (0x[a-fA-F0-9]{40})").unwrap();
    let escrow_b_re = Regex::new(r"Escrow B deployed at: (0x[a-fA-F0-9]{40})").unwrap();

    let token_a_addr = token_a_re.captures(&stdout).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());
    let escrow_a_addr = escrow_a_re.captures(&stdout).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());
    let token_b_addr = token_b_re.captures(&stdout).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());
    let escrow_b_addr = escrow_b_re.captures(&stdout).and_then(|c| c.get(1)).map(|m| m.as_str().to_string());

    match (token_a_addr, escrow_a_addr, token_b_addr, escrow_b_addr) {
        (Some(tka), Some(esca), Some(tkb), Some(escb)) => Ok(DeployedContracts {
            token_a_addr: tka,
            escrow_a_addr: esca,
            token_b_addr: tkb,
            escrow_b_addr: escb,
        }),
        _ => Err("[HELPER] Failed to parse all contract addresses from forge script output".to_string()),
    }
}

// Helper to call `cast call` and get output
// Adapted from evm_relayer tests
async fn cast_call(rpc_url: &str, to: &str, sig: &str, args: &[&str]) -> Result<String, String> {
    let mut cmd = tokio::process::Command::new(CAST_PATH); // Use tokio command
    cmd.arg("call")
       .arg(to)
       .arg(sig);
    for arg in args {
        cmd.arg(arg);
    }
    cmd.arg("--rpc-url").arg(rpc_url);
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    println!("[HELPER] Executing cast call: {:?}", cmd);
    let output = cmd.output().await.map_err(|e| format!("[HELPER] Failed to run cast call: {}", e))?;

    if !output.status.success() {
         Err(format!(
            "[HELPER] cast call failed:\nStatus: {}\\nStderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
    } else {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}

// Helper to create TEE Identity
fn create_tee_identity(id: usize, secret_bytes: &[u8; 32]) -> (TEEIdentity, SecretKey) {
    let signing_key = SecretKey::from_bytes(secret_bytes);
    let public_key = signing_key.verifying_key();
    (TEEIdentity { id, public_key }, signing_key)
}

// Helper to parse balance output from cast call
fn parse_hex_balance(hex_output: &str) -> Result<u128, String> {
     u128::from_str_radix(hex_output.trim_start_matches("0x"), 16)
        .map_err(|e| format!("[HELPER] Failed to parse balance output '{}' as hex: {}", hex_output, e))
}

// Helper to generate a deterministic swap_id (bytes32) from a string seed
// Note: This is different from how the Solidity script generates it, use cautiously.
fn generate_swap_id_bytes32(seed: &str) -> SwapId {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let result = hasher.finalize();
    result.into() // Convert GenericArray<u8, N> into [u8; 32]
}

// --- Main E2E Test ---\n

#[tokio::test]
#[ignore] // Ignore by default due to external dependencies (Anvil, forge script)
async fn test_e2e_coordinator_relayer_swap() -> Result<(), String> {
    println!("--- Starting E2E Coordinator <> Relayer Test ---");
    println!("Requires Anvil running on {} and {}", RPC_URL_A, RPC_URL_B);

    // 1. Setup: Deploy contracts via Forge Script
    let contracts = run_forge_script()?;
    println!("[Setup] Contracts deployed: EscrowA={}, TokenB={}",
             contracts.escrow_a_addr, contracts.token_b_addr);

    // 2. Setup: Create EvmRelayer instance
    let mut chain_details = HashMap::new();
    chain_details.insert(CHAIN_A_ID, ChainConfig {
        rpc_url: RPC_URL_A.to_string(),
        escrow_address: contracts.escrow_a_addr.clone(),
    });
    chain_details.insert(CHAIN_B_ID, ChainConfig {
        rpc_url: RPC_URL_B.to_string(),
        escrow_address: contracts.escrow_b_addr.clone(),
    });
    let relayer_config = EvmRelayerConfig {
        cast_path: CAST_PATH.into(),
        chain_details,
        relayer_private_key: RELAYER_PK.to_string(),
    };
    // Wrap in Arc for coordinator
    let evm_relayer = Arc::new(EvmRelayer::new(relayer_config));
    println!("[Setup] EvmRelayer created.");

    // 3. Setup: Create CrossChainCoordinator instance
    let (coord_identity, coord_secret_key) = create_tee_identity(COORDINATOR_TEE_ID, &COORDINATOR_SECRET_KEY_BYTES);

    // Create SystemConfig with threshold 1 for simplicity
    let system_config = SystemConfig {
        // Only this coordinator matters for threshold 1
        coordinator_identities: vec![coord_identity.clone()],
        coordinator_threshold: 1,
        nodes_per_shard: 1, // Keep simple
        ..Default::default()
    };

    // Create MockNetwork (coordinator needs a network interface)
    let mock_network = Arc::new(MockNetwork::new());

    // Need shard assignments (even if empty/unused for this test flow)
    let shard_assignments: HashMap<usize, Vec<TEEIdentity>> = HashMap::new();

    let mut coordinator = CrossChainCoordinator::new(
        coord_identity.clone(),
        coord_secret_key,
        system_config.clone(),
        mock_network as Arc<dyn NetworkInterface + Send + Sync>,
        // Pass the real relayer!
        evm_relayer.clone() as Arc<dyn BlockchainInterface + Send + Sync>,
        shard_assignments,
    );
    println!("[Setup] CrossChainCoordinator created (Threshold=1).");

    // 4. Execution: Define Swap Transaction
    let swap_seed = format!("e2e-swap-{}", rand::thread_rng().gen::<u32>());
    // Generate bytes32 swap ID deterministically for contract calls
    let swap_id_bytes = generate_swap_id_bytes32(&swap_seed);
    let swap_id_hex = format!("0x{}", hex::encode(swap_id_bytes)); // For contract calls
    let swap_id_str = swap_id_hex.clone(); // Use hex string as internal tx_id for coordinator simplicity

    let release_amount = 50u64;
    let lock_amount = 50u64; // Must match release amount for this test flow

    let swap_tx = Transaction {
        tx_id: swap_id_str.clone(),
        tx_type: TxType::CrossChainSwap,
        accounts: vec![
            AccountId { chain_id: CHAIN_A_ID, address: USER_A_ADDR.to_string() }, // Sender on A
            AccountId { chain_id: CHAIN_B_ID, address: USER_B_ADDR.to_string() }, // Recipient on B
        ],
        amounts: vec![lock_amount], // Amount locked on A / released on B
        required_locks: vec![LockInfo {
            account: AccountId { chain_id: CHAIN_A_ID, address: USER_A_ADDR.to_string() },
            asset: AssetId { 
                chain_id: CHAIN_A_ID, 
                token_symbol: "TKA".to_string(), 
                token_address: contracts.token_a_addr.clone(),
            },
            amount: lock_amount, 
        }],
        // Populate target_asset with Chain B token details
        target_asset: Some(AssetId { 
            chain_id: CHAIN_B_ID, 
            token_symbol: "TKB".to_string(), // Token B symbol
            token_address: contracts.token_b_addr.clone(), // Use deployed Token B address
        }),
        timeout: Duration::from_secs(300),
    };
    println!("[Exec] Defined swap transaction: {}", swap_id_str);

    // 5. Execution: Initiate Swap (in coordinator memory)
    // Define which shards are relevant (only shard 0 in this simplified setup)
    let relevant_shards: HashSet<usize> = [0].into_iter().collect();
    coordinator.initiate_swap(swap_tx.clone(), relevant_shards);
    println!("[Exec] Coordinator initiated swap.");

    // 6. Execution: Create *valid* mock LockProof for shard 0
    let (mock_shard_tee_identity, mock_shard_secret_key) = create_tee_identity(MOCK_SHARD_TEE_ID, &MOCK_SHARD_TEE_SECRET_KEY_BYTES);
    
    // Get LockInfo from the transaction (assuming first lock)
    let lock_info_for_proof = swap_tx.required_locks.get(0).cloned()
        .ok_or_else(|| "Swap transaction missing required_locks[0] for proof".to_string())?;

    // Construct the data that the TEE would sign for the proof
    // Match the reconstruction logic in verify_lock_proof
    let mut proof_data_to_sign = swap_id_str.as_bytes().to_vec();
    proof_data_to_sign.extend_from_slice(&0usize.to_le_bytes()); // shard_id = 0
    proof_data_to_sign.extend_from_slice(lock_info_for_proof.account.address.as_bytes());
    proof_data_to_sign.extend_from_slice(&lock_info_for_proof.asset.token_symbol.as_bytes());
    proof_data_to_sign.extend_from_slice(&lock_info_for_proof.amount.to_le_bytes());
    
    // The sign function returns ed25519_dalek::Signature, which is aliased as Signature
    let proof_signature: Signature = sign(&proof_data_to_sign, &mock_shard_secret_key);

    let lock_proof = LockProof {
        tx_id: swap_id_str.clone(),
        shard_id: 0,
        lock_info: lock_info_for_proof, // Add the missing lock_info
        signer_identity: mock_shard_tee_identity, 
        attestation_or_sig: proof_signature, // This is now correctly type Signature
    };
     println!("[Exec] Created valid mock LockProof for shard 0.");

    // 7. Execution: Process the proof (should trigger submit_release)
    println!("[Exec] Calling coordinator.process_proof_and_finalize...");
    // Ensure the swap exists before processing
    assert!(coordinator.active_swaps.contains_key(&swap_id_str), "Swap should exist before processing proof");

    // Check initial balance of User B before release
    let balance_b_before = evm_relayer.get_balance(CHAIN_B_ID, USER_B_ADDR.to_string(), contracts.token_b_addr.clone())
        .await
        .map_err(|e| e.to_string())?;
    println!("[Verify] User B balance before release: {}", balance_b_before);


    let finalization_result = coordinator.process_proof_and_finalize(lock_proof);

    // Check if coordinator attempted finalization
    assert!(finalization_result.is_some(), "Finalization should produce a decision with threshold 1");
    let decision = finalization_result.unwrap();
    assert!(decision.commit, "Decision should be COMMIT (release)");
    println!("[Exec] Coordinator finalized COMMIT decision for swap {}", swap_id_str);

    // Give the relayer call (submit_release) time to execute and mine
    println!("[Exec] Waiting for blockchain transaction...");
    thread::sleep(Duration::from_secs(4)); // Adjust if needed

    // 8. Verification: Check EVM state after relayer call
    println!("[Verify] Verifying state on Chain B after release...");

    // Check recipient balance on Chain B
    let balance_b_after = evm_relayer.get_balance(CHAIN_B_ID, USER_B_ADDR.to_string(), contracts.token_b_addr.clone())
        .await
        .map_err(|e| e.to_string())?;
    println!("[Verify] User B balance on Chain B after release: {}", balance_b_after);
    // User B starts with 0 (minted to escrow), should receive release_amount
    assert_eq!(u128::from(balance_b_after), u128::from(balance_b_before) + u128::from(release_amount), "User B balance is incorrect after release.");

    // Check finalization state on Escrow B
    let is_finalized_output = cast_call(
        RPC_URL_B,
        &contracts.escrow_b_addr,
        "isFinalized(bytes32)",
        &[&swap_id_hex] // Use the correct bytes32 hex string
    ).await?;
    println!("[Verify] isFinalized({}) on Chain B: {}", swap_id_hex, is_finalized_output);
    // cast call returns hex bool: 0x...01 for true, 0x...00 for false
    assert!(is_finalized_output.ends_with("1"), "Swap should be finalized on Chain B");

    // Check if swap was removed from coordinator state *after* successful finalization
    assert!(!coordinator.active_swaps.contains_key(&swap_id_str), "Swap should be removed after finalization attempt");


    println!("--- E2E Coordinator <> Relayer Test PASSED ---");
    Ok(())
}
