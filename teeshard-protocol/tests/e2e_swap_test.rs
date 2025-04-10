// teeshard-protocol/tests/e2e_swap_test.rs

// This is an end-to-end integration test for the CrossChainCoordinator
// interacting with a real EvmRelayer and live Anvil instances.

// Test dependencies need to be added to Cargo.toml's [dependencies]
// if they are not already there (like rand, hex, regex, tokio)
// AND ensure dev-dependencies are sufficient for test helpers.

use teeshard_protocol::{
    config::SystemConfig,
    cross_chain::{
        swap_coordinator::CrossChainCoordinator,
        types::LockProof,
    },
    data_structures::{
        AccountId, AssetId, LockInfo, TEEIdentity, Transaction, TxType,
    },
    // NetworkInterface needed for Coordinator::new
    network::{NetworkInterface, MockNetwork},
    onchain::{
        evm_relayer::{EvmRelayer, EvmRelayerConfig, ChainConfig},
        interface::{BlockchainInterface, SwapId},
    },
    // Need crypto primitives for creating valid proofs/signatures
    tee_logic::{
        crypto_sim::{sign, SecretKey},
        types::Signature,
    },
};

use std::{
    collections::{HashMap, HashSet},
    process::{Command as StdCommand, Stdio},
    sync::Arc,
    time::Duration,
};
use regex::Regex;
use hex;
use rand::Rng; // For generating random swap IDs
use ethers::middleware::Middleware;
use ethers::providers::{Provider, Http};
use ethers::signers::{LocalWallet, Signer};
use ethers::types::{TransactionRequest, U256, Address, H256, Bytes, BigEndianHash}; // Import BigEndianHash
use std::str::FromStr;
use ethers::middleware::SignerMiddleware; // Import SignerMiddleware
use ethers::abi::{encode_packed, Token}; // Added abi encoding
use std::sync::Arc as StdArc;
use bincode;

// --- Test Configuration & Constants ---
const RPC_URL_A: &str = "http://localhost:8545";
const RPC_URL_B: &str = "http://localhost:8546";
const CHAIN_A_ID: u64 = 1; // Default Anvil ID -> Changed to 1
const CHAIN_B_ID: u64 = 10; // Use 10 for Chain B

// Use known Anvil keys for testing -> Update User addresses to match script
const RELAYER_PK: &str = "0x59c6995e998f97a5300194dc6916aa8c096e6d7d7f81a78f05791c43177926b8"; // Anvil default key 1 - Matches key used for deployment in script
const USER_A_ADDR: &str = "0xF38cA7A356584B8ede96615fd09E130A02b8b8c6"; // Derived from script userAPrivateKey
const USER_B_ADDR: &str = "0x60B162Ba495Ce3E498E805B49f439D0246FC0c07"; // Derived from script userBPrivateKey

// TEE Committee Keys (from CrossChainSwap.s.sol for ECDSA signing)
const COMMITTEE_MEMBER_1_PK: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const COMMITTEE_MEMBER_2_PK: &str = "0x6370fd033278c143179d81c5526140625662b8daa446c22ee2d73db3707e620c";
// const COMMITTEE_MEMBER_3_PK: &str = "0x646f1ce2fdad0e6dee9cbf8d8e9a01932f8349b816954563c94686ca85773086"; // Threshold is 2

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

// Helper to fund an account with ETH using cast send and wait for receipt
async fn fund_account_on_chain(
    rpc_url: &str,
    recipient_address: &str,
    amount_wei: &str, // Amount in Wei as a string
    sender_pk: &str, // Private key of the sender (must be funded)
) -> Result<(), String> {
    println!(
        "[HELPER] Funding {} with {} wei on {} from sender ending in {}...",
        recipient_address,
        amount_wei,
        rpc_url,
        &sender_pk[sender_pk.len()-4..]
    );
    let mut cmd_send = tokio::process::Command::new(CAST_PATH);
    cmd_send.arg("send")
       .arg(recipient_address)
       .arg("--value")
       .arg(amount_wei)
       .arg("--private-key")
       .arg(sender_pk)
       .arg("--rpc-url")
       .arg(rpc_url)
       .stdout(Stdio::piped())
       .stderr(Stdio::piped());

    let output_send = cmd_send.output().await
        .map_err(|e| format!("[HELPER] Failed to execute cast send (funding): {}", e))?;

    if !output_send.status.success() {
        return Err(format!(
            "[HELPER] cast send failed (funding): Status: {}\nStderr: {}",
            output_send.status,
            String::from_utf8_lossy(&output_send.stderr)
        ));
    }

    // Parse transaction hash from stdout
    let stdout_send = String::from_utf8_lossy(&output_send.stdout);
    let tx_hash = stdout_send.lines()
        .find(|line| line.trim_start().starts_with("transactionHash"))
        .and_then(|line| line.split_whitespace().nth(1))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| format!("[HELPER] Failed to parse funding tx hash from output: {}", stdout_send))?;

    println!("[HELPER] Funding transaction sent: {}. Waiting for receipt...", tx_hash);

    // Wait for receipt using cast receipt in a loop
    let max_retries = 10;
    let retry_delay = Duration::from_secs(1);
    for attempt in 0..max_retries {
        let mut cmd_receipt = tokio::process::Command::new(CAST_PATH);
        cmd_receipt.arg("receipt")
            .arg(&tx_hash)
            .arg("--rpc-url")
            .arg(rpc_url)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        
        let output_receipt = cmd_receipt.output().await
            .map_err(|e| format!("[HELPER] Failed to execute cast receipt (funding): {}", e))?;
        
        if output_receipt.status.success() {
            let stdout_receipt = String::from_utf8_lossy(&output_receipt.stdout);
            // Check if the receipt contains a block number (indicating it's mined)
            if stdout_receipt.contains("blockNumber") {
                 println!("[HELPER] Funding transaction confirmed in receipt.");
                 return Ok(());
            }
        }
        // If receipt not found or not mined yet, wait and retry
        println!("[HELPER] Receipt attempt {} failed or tx not mined yet. Retrying...", attempt + 1);
        tokio::time::sleep(retry_delay).await;
    }

    Err(format!("[HELPER] Timed out waiting for funding transaction receipt ({})", tx_hash))
}

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

// Helper to generate a deterministic swap_id (bytes32) from a string seed
// Note: This is different from how the Solidity script generates it, use cautiously.
fn generate_swap_id_bytes32(seed: &str) -> SwapId {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let result = hasher.finalize();
    result.into() // Convert GenericArray<u8, N> into [u8; 32]
}

// Helper to send funds (requires anvil running and funded deployer)
async fn fund_account(rpc_url: &str, recipient: Address, amount: U256) -> Result<(), Box<dyn std::error::Error>> {
    let provider = Provider::<Http>::try_from(rpc_url)?;
    // This private key corresponds to the default Anvil[0] account
    let deployer_pk = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7341b46290";
    let chain_id = provider.get_chainid().await?.as_u64(); // Get chain ID
    let deployer_wallet = LocalWallet::from_str(deployer_pk)?.with_chain_id(chain_id);
    let deployer_address = deployer_wallet.address();

    // Create SignerMiddleware
    let signer_client = SignerMiddleware::new(provider, deployer_wallet);
    let client = StdArc::new(signer_client); // Wrap in Arc

    println!("[HELPER] Funding {} with {} wei on {} from sender ending in {}...", 
             recipient, amount, rpc_url, format!("{:x}", deployer_address).chars().skip(36).collect::<String>());

    // Fund with 1 ETH instead of 100
    let tx_amount = U256::from(10).pow(U256::from(18)); 
    let tx = TransactionRequest::new()
        .to(recipient)
        .value(tx_amount) // Use 1 ETH
        .from(deployer_address); // From is optional when using SignerMiddleware

    // Use the signer client to send the transaction
    let pending_tx = client.send_transaction(tx, None).await?;
    println!("[HELPER] Funding transaction sent: {:?}. Waiting for receipt...", pending_tx.tx_hash());
    let _receipt = pending_tx.await?.ok_or("Funding transaction dropped")?;
    println!("[HELPER] Funding transaction confirmed in receipt.");

    Ok(())
}

// --- Main E2E Test ---\n

#[tokio::test]
// #[ignore] // Removed ignore to run the test
async fn test_e2e_coordinator_relayer_swap() -> Result<(), String> {
    println!("--- Starting E2E Coordinator <> Relayer Test ---");
    println!("Requires Anvil running on {} and {}", RPC_URL_A, RPC_URL_B);

    // Use constants directly for clarity
    let chain_a_url = RPC_URL_A;
    let chain_b_url = RPC_URL_B;
    let chain_a_id = CHAIN_A_ID;
    let chain_b_id = CHAIN_B_ID;

    // Define the funder PK - Use User A's PK from the script, as script uses this key
    let funder_pk = "0x9b2391031a7612fc7003c8fa79b50982471c694892bdc273dd9c379631751a59"; // Script's userAPrivateKey

    // --- Fund Relayer on Chain B ---
    // Must happen BEFORE deploying contracts, as deployment uses relayer key
    let relayer_wallet = LocalWallet::from_str(RELAYER_PK)
        .map_err(|e| format!("Invalid Relayer PK: {}", e))?;
    let relayer_address = relayer_wallet.address();
    let relayer_address_hex = format!("{:?}", relayer_address); // Get hex string representation
    println!("[Setup] Funding Relayer account {} on Chain B ({}) using fund_account_on_chain...", relayer_address_hex, chain_b_url);
    // Use fund_account_on_chain, sending 1 ETH from default Anvil[0] account
    fund_account_on_chain(
        chain_b_url, 
        &relayer_address_hex, 
        "1000000000000000000", // 1 ETH in Wei
        funder_pk // Explicitly use the default Anvil[0] PK as sender
    )
        .await
        .map_err(|e| format!("Failed to fund relayer account on Chain B: {}", e))?;
        // .expect("Failed to fund relayer account on Chain B"); // Original expect
    println!("[Setup] Funding transaction likely sent to Relayer account on Chain B (receipt confirmed by helper).");

    // Deploy contracts using forge script
    let contracts = 
        run_forge_script().map_err(|e| format!("[Setup] Forge script failed: {}", e))?;
    println!("[Setup] Contracts deployed: EscrowA={}, TokenB={}", contracts.escrow_a_addr, contracts.token_b_addr);

    // 2. Setup: Create EvmRelayer instance
    let mut chain_details = HashMap::new();
    chain_details.insert(chain_a_id, ChainConfig { // Use variable chain_a_id
        rpc_url: chain_a_url.to_string(), // Use variable chain_a_url
        escrow_address: contracts.escrow_a_addr.clone(),
    });
    chain_details.insert(chain_b_id, ChainConfig { // Use variable chain_b_id
        rpc_url: chain_b_url.to_string(), // Use variable chain_b_url
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

    // Create shard assignments map - MUST include the relevant shard ID
    let mut shard_assignments: HashMap<usize, Vec<TEEIdentity>> = HashMap::new();
    // Assign the coordinator itself as the handler for the relevant shard ID for this test
    shard_assignments.insert(chain_a_id as usize, vec![coord_identity.clone()]); // Use variable chain_a_id

    let mut coordinator = CrossChainCoordinator::new(
        coord_identity.clone(),
        coord_secret_key,
        system_config.clone(),
        system_config.coordinator_identities.clone(), // Add peers argument (arg 4)
        mock_network as Arc<dyn NetworkInterface + Send + Sync>,
        evm_relayer.clone() as Arc<dyn BlockchainInterface + Send + Sync>,
        shard_assignments
    );
    println!("[Setup] CrossChainCoordinator created (Threshold=1).");

    // 4. Execution: Define Swap Transaction
    let swap_seed = format!("e2e-swap-{}-{}", chain_a_id, chain_b_id); // Make seed chain-specific if running parallel tests
    // Generate bytes32 swap ID deterministically for contract calls
    let swap_id_bytes = generate_swap_id_bytes32(&swap_seed);
    let swap_id_hex = format!("0x{}", hex::encode(swap_id_bytes)); // For contract calls
    let swap_id_str = swap_id_hex.clone(); // Use hex string as internal tx_id for coordinator simplicity

    // Calculate release amount using U256 arithmetic to avoid u64 overflow
    let amount_base = 50u64;
    let decimals_u256 = U256::from(18);
    let scale = U256::from(10).pow(decimals_u256);
    let release_amount = U256::from(amount_base) * scale;

    let _token_a_addr = Address::from_str(&contracts.token_a_addr).map_err(|_| "Invalid Token A address".to_string())?;
    let _token_b_addr = Address::from_str(&contracts.token_b_addr).map_err(|_| "Invalid Token B address".to_string())?;
    let _escrow_a_addr = Address::from_str(&contracts.escrow_a_addr).map_err(|_| "Invalid Escrow A address".to_string())?;
    let _escrow_b_addr = Address::from_str(&contracts.escrow_b_addr).map_err(|_| "Invalid Escrow B address".to_string())?;
    let _user_a_addr = Address::from_str(USER_A_ADDR).map_err(|_| "Invalid User A address".to_string())?;
    let _user_b_addr = Address::from_str(USER_B_ADDR).map_err(|_| "Invalid User B address".to_string())?;

    let swap_tx = Transaction {
        tx_id: swap_id_str.clone(),
        tx_type: TxType::CrossChainSwap,
        accounts: vec![
            AccountId { chain_id: chain_a_id, address: USER_A_ADDR.to_string() }, 
            AccountId { chain_id: chain_b_id, address: USER_B_ADDR.to_string() }, 
        ],
        amounts: vec![amount_base], // Use raw amount here
        required_locks: vec![LockInfo {
            account: AccountId { chain_id: chain_a_id, address: USER_A_ADDR.to_string() }, 
            asset: AssetId { 
                chain_id: chain_a_id, 
                token_symbol: "TKA".to_string(), 
                token_address: contracts.token_a_addr.clone(), 
            },
            amount: amount_base, // Use raw amount here
        }],
        target_asset: Some(AssetId { 
            chain_id: chain_b_id, 
            token_symbol: "TKB".to_string(), 
            token_address: contracts.token_b_addr.clone(), 
        }),
        timeout: Duration::from_secs(300),
    };
    println!("[Exec] Defined swap transaction: {}", swap_id_str);

    // 5. Execution: Initiate Swap (in coordinator memory)
    // The relevant "shard" is identified by the chain ID where the lock occurs.
    let relevant_shards: HashSet<usize> = [chain_a_id as usize].into_iter().collect(); // Use variable chain_a_id
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
    // Use the correct shard ID (chain_a_id) in the signed data
    proof_data_to_sign.extend_from_slice(&(chain_a_id as usize).to_le_bytes()); // shard_id = chain_a_id
    proof_data_to_sign.extend_from_slice(lock_info_for_proof.account.address.as_bytes());
    proof_data_to_sign.extend_from_slice(&lock_info_for_proof.asset.token_symbol.as_bytes());
    proof_data_to_sign.extend_from_slice(&lock_info_for_proof.amount.to_le_bytes());
    
    // Use async sign, provide delay args (0,0 for test), and await the result
    let proof_signature: Signature = sign(
        &proof_data_to_sign, 
        &mock_shard_secret_key, 
        0, 
        0, 
        &None, // Add metrics_tx argument (arg 5)
        &None  // Add node_id argument (arg 6)
    ).await;

    let lock_proof = LockProof {
        tx_id: swap_id_str.clone(),
        shard_id: chain_a_id as usize, // Use the correct shard ID (chain_a_id)
        lock_info: lock_info_for_proof, // Add the missing lock_info
        signer_identity: mock_shard_tee_identity, 
        attestation_or_sig: proof_signature, // This is now correctly type Signature
    };
     println!("[Exec] Created valid mock LockProof for shard {}.", chain_a_id);

    // 7. Execution: Process the proof and trigger Coordinator's internal finalization
    println!("[Exec] Calling coordinator.process_proof_and_finalize (will trigger internal submission)...");
    // Ensure the swap exists before processing
    assert!(coordinator.active_swaps.contains_key(&swap_id_str), "Swap should exist before processing proof");

    // Check initial balance of User B before release
    let balance_b_before = evm_relayer.get_balance(chain_b_id, USER_B_ADDR.to_string(), contracts.token_b_addr.clone()) // Use variable chain_b_id
        .await
        .map_err(|e| e.to_string())?;
    println!("[Verify] User B balance before release: {}", balance_b_before);

    // Await the async call and handle the Result/Option
    // This call will now internally trigger the evm_relayer.submit_release
    let finalization_result = coordinator.process_proof_and_finalize(lock_proof).await;

    // --- Check Coordinator Decision ---
    match finalization_result {
        Ok(Some(decision)) => {
            assert!(decision.commit, "Coordinator finalization decision should be COMMIT");
            println!(
                "[Exec] Coordinator decided COMMIT for swap {}. Submission was triggered internally.", 
                swap_id_str
            );
            // NO manual submission here anymore
        }
        Ok(None) => {
            panic!("Coordinator did not reach final decision - Unexpected for threshold 1");
        }
        Err(abort_reason) => {
            panic!("Coordinator aborted swap unexpectedly: {:?}", abort_reason);
        }
    }
    // --- End Coordinator Decision Check ---

    // 8. Verification: Check EVM state after coordinator's internal relayer call
    println!("[Verify] Verifying state on Chain B after coordinator's internal release submission...");

    // Give some time for the transaction to be mined
    tokio::time::sleep(Duration::from_secs(3)).await; // Increased slightly

    // Check recipient balance on Chain B - should be release_amount (with decimals)
    let balance_b_after = evm_relayer.get_balance(chain_b_id, USER_B_ADDR.to_string(), contracts.token_b_addr.clone()) 
        .await
        .map_err(|e| e.to_string())?;
    println!("[Verify] User B balance on Chain B after release: {}", balance_b_after);
    
    // Assume User B starts with 0 TKB on Chain B
    let expected_balance_b = balance_b_before + release_amount; // Check relative change
    assert_eq!(balance_b_after, expected_balance_b, "User B balance is incorrect after release.");

    // Check finalization state on Escrow B
    let is_finalized_output = cast_call(
        chain_b_url, 
        &contracts.escrow_b_addr,
        "isFinalized(bytes32)",
        &[&swap_id_hex] 
    ).await?;
    println!("[Verify] isFinalized({}) on Chain B: {}", swap_id_hex, is_finalized_output);
    // isFinalized returns a uint256 which cast outputs as hex (0x0...01 or 0x0...00)
    assert!(is_finalized_output.ends_with("1"), "Swap should be finalized on Chain B. Output: {}", is_finalized_output);

    // Optional: Check if coordinator cleaned up the swap state
    assert!(!coordinator.active_swaps.contains_key(&swap_id_str), "Coordinator should remove finalized swap from active_swaps");
    println!("[Verify] Coordinator successfully removed swap {} from internal state.", swap_id_str);


    println!("--- E2E Coordinator <> Relayer Test PASSED ---");
    Ok(())
}
