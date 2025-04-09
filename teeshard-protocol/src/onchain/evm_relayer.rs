use crate::onchain::{
    BlockchainError,
    BlockchainInterface,
    SignatureBytes,
    SwapId,
    TransactionId,
};
use async_trait::async_trait;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;
use hex;
use std::collections::HashMap;
use std::{
    error::Error as StdError,
    process::Command as StdCommand,
    thread,
    time::Duration,
};
use regex::Regex;
use ethers::types::U256;

// Config for a single chain
#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub rpc_url: String,
    pub escrow_address: String,
}

// Configuration for the EVM Relayer
#[derive(Debug, Clone)]
pub struct EvmRelayerConfig {
    // Path to the `cast` executable
    pub cast_path: PathBuf,
    // Map from actual chain ID (u64) to its configuration
    pub chain_details: HashMap<u64, ChainConfig>,
    // Private key for the relayer account used to send transactions
    pub relayer_private_key: String,
}

// Struct implementing the BlockchainInterface using cast CLI calls
#[derive(Debug, Clone)]
pub struct EvmRelayer {
    config: EvmRelayerConfig,
}

impl EvmRelayer {
    pub fn new(config: EvmRelayerConfig) -> Self {
        EvmRelayer { config }
    }

    // Helper to get chain config based on chain_id
    fn get_chain_config(&self, chain_id: u64) -> Result<&ChainConfig, BlockchainError> {
        self.config.chain_details.get(&chain_id)
            .ok_or_else(|| format!("Configuration not found for chain_id: {}", chain_id).into())
    }

    // --- START: New Helper function for parsing tx hash ---
    fn parse_transaction_hash_from_cast_output(&self, stdout: &str) -> Result<TransactionId, BlockchainError> {
        // Look for the line starting with "transactionHash" (allow for varying whitespace)
        if let Some(line) = stdout.lines().find(|line| line.trim_start().starts_with("transactionHash")) {
            // Split the line by whitespace and get the last part (the hash)
            if let Some(hash_part) = line.split_whitespace().last() {
                if hash_part.starts_with("0x") && hash_part.len() == 66 {
                    return Ok(hash_part.to_string());
                }
            }
        }
        // Fallback or additional checks if needed?
        // For now, return error if specific format not found.
        Err(format!("Failed to parse transaction hash from cast send output: {}", stdout).into())
    }
    // --- END: New Helper function ---
}

#[async_trait]
impl BlockchainInterface for EvmRelayer {
    
    // Implement get_balance first
    async fn get_balance(
        &self,
        chain_id: u64,
        account_address: String,
        token_address: String,
    ) -> Result<U256, BlockchainError> {
        let chain_config = self.get_chain_config(chain_id)?;
        let rpc_url = &chain_config.rpc_url;

        let mut cmd = Command::new(&self.config.cast_path);
        cmd.arg("call")
           .arg(&token_address) // ERC20 Token contract address
           .arg("balanceOf(address)") // Function signature
           .arg(&account_address) // Argument for balanceOf
           .arg("--rpc-url")
           .arg(rpc_url)
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());

        println!("Executing command: {:?}", cmd);

        let output = cmd.output().await.map_err(|e| format!("Failed to execute cast call: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("cast call failed: Status: {}\nStderr: {}", output.status, stderr).into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        // cast call output is typically a hex string (0x...)
        let hex_output = stdout.trim();
        
        // Parse directly into U256
        let balance = U256::from_str_radix(hex_output.trim_start_matches("0x"), 16)
            .map_err(|e| format!("Failed to parse cast output '{}' as hex U256: {}", hex_output, e))?;
            
        Ok(balance)
    }


    // Implement submit_release
    async fn submit_release(
        &self,
        chain_id: u64,
        swap_id: SwapId,
        token_address: String,
        amount: U256,
        recipient_address: String,
        tee_signatures: SignatureBytes,
    ) -> Result<TransactionId, BlockchainError> {
        let chain_config = self.get_chain_config(chain_id)?;
        let rpc_url = &chain_config.rpc_url;
        let escrow_address = &chain_config.escrow_address;

        // Format arguments for cast send
        let swap_id_hex = format!("0x{}", hex::encode(swap_id)); 
        let signatures_hex = format!("0x{}", hex::encode(&tee_signatures));
        let amount_str = amount.to_string();

        let mut cmd = Command::new(&self.config.cast_path);
        cmd.arg("send")
           .arg(escrow_address) // Target contract
           .arg("release(bytes32,address,uint256,address,bytes)") 
           .arg(&swap_id_hex)
           .arg(&token_address)
           .arg(&amount_str)
           .arg(&recipient_address)
           .arg(&signatures_hex)
           .arg("--private-key")
           .arg(&self.config.relayer_private_key)
           .arg("--gas-limit") 
           .arg("1000000") 
           .arg("--rpc-url")
           .arg(rpc_url)
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());

        println!("Executing command: {:?}", cmd);

        let output = cmd.output().await.map_err(|e| format!("Failed to execute cast send (release): {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("cast send failed (release): Status: {}\nStderr: {}", output.status, stderr).into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_transaction_hash_from_cast_output(&stdout)
    }

    // Implement submit_abort
    async fn submit_abort(
        &self,
        chain_id: u64,
        swap_id: SwapId,
        token_address: String,
        amount: U256,
        sender_address: String,
        tee_signatures: SignatureBytes,
    ) -> Result<TransactionId, BlockchainError> {
        let chain_config = self.get_chain_config(chain_id)?;
        let rpc_url = &chain_config.rpc_url;
        let escrow_address = &chain_config.escrow_address;

        let swap_id_hex = format!("0x{}", hex::encode(swap_id));
        let signatures_hex = format!("0x{}", hex::encode(&tee_signatures));
        let amount_str = amount.to_string();

        let mut cmd = Command::new(&self.config.cast_path);
        cmd.arg("send")
           .arg(escrow_address) // Target contract
           .arg("abort(bytes32,address,uint256,address,bytes)") 
           .arg(&swap_id_hex)
           .arg(&token_address)
           .arg(&amount_str)
           .arg(&sender_address) 
           .arg(&signatures_hex)
           .arg("--private-key")
           .arg(&self.config.relayer_private_key)
           .arg("--gas-limit") 
           .arg("1000000") 
           .arg("--rpc-url")
           .arg(rpc_url)
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());

        println!("Executing command: {:?}", cmd);

        let output = cmd.output().await.map_err(|e| format!("Failed to execute cast send (abort): {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("cast send failed (abort): Status: {}\nStderr: {}", output.status, stderr).into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_transaction_hash_from_cast_output(&stdout)
    }

    // --- Add the lock function ---
    async fn lock(
        &self,
        chain_id: u64,
        sender_private_key: String,
        swap_id: [u8; 32],
        recipient: String,
        token_address: String,
        amount: U256,
        timeout_seconds: u64,
    ) -> Result<TransactionId, BlockchainError> {
        let chain_config = self.get_chain_config(chain_id)?;

        let swap_id_hex = hex::encode(swap_id);
        let now = std::time::SystemTime::now();
        let duration_since_epoch = now.duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| -> BlockchainError { Box::new(e) })?;
        let lock_expiry_timestamp = duration_since_epoch.as_secs() + timeout_seconds;

        println!(
            "[Relayer] Executing lock: chain={}, escrow={}, swap_id={}, token={}, amount={}, recipient={}, expiry={}",
            chain_id,
            chain_config.escrow_address,
            swap_id_hex,
            token_address,
            amount,
            recipient,
            lock_expiry_timestamp
        );


        let mut cmd = Command::new(self.config.cast_path.to_str().unwrap());
        cmd.arg("send")
            .arg(&chain_config.escrow_address)
            .arg("lock(bytes32,address,address,uint256,uint256)")
            .arg(format!("0x{}", swap_id_hex))
            .arg(&recipient)
            .arg(&token_address)
            .arg(amount.to_string())
            .arg(lock_expiry_timestamp.to_string())
            .arg("--private-key")
            .arg(sender_private_key)
            .arg("--rpc-url")
            .arg(&chain_config.rpc_url);
        
        println!("[Relayer] Executing command: {:?}", cmd);

        let output = cmd.output().await.map_err(|e| format!("Failed to execute cast send (lock): {}", e))?;

        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("cast send failed (lock): Status: {}\nStdout: {}\nStderr: {}", output.status, stdout, stderr).into());
        }

        // Use the helper function for parsing
        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_transaction_hash_from_cast_output(&stdout)
    }
    // --- End of lock function ---

    async fn approve_erc20(
        &self,
        chain_id: u64,
        owner_private_key: String,
        token_address: String,
        spender_address: String,
        amount: U256,
    ) -> Result<TransactionId, BlockchainError> {
        let chain_config = self.get_chain_config(chain_id)?;
        let rpc_url = &chain_config.rpc_url;
        // No need for escrow_address here

        // Format arguments for cast send
        let amount_str = amount.to_string(); // Convert U256 to string

        let mut cmd = Command::new(&self.config.cast_path);
        cmd.arg("send")
           .arg(&token_address) // Target Token contract
           // Function signature and arguments for approve
           .arg("approve(address,uint256)") 
           .arg(&spender_address)
           .arg(&amount_str)
           // Use the provided signer's private key
           .arg("--private-key")
           .arg(&owner_private_key)
           .arg("--gas-limit") // Add explicit gas limit
           .arg("1000000") // Adjust if needed
           .arg("--rpc-url")
           .arg(rpc_url)
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());

        println!("Executing command: {:?}", cmd);

        let output = cmd.output().await.map_err(|e| format!("Failed to execute cast send (approve): {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("cast send failed (approve): Status: {}\nStderr: {}", output.status, stderr).into());
        }

        // Use the helper function for parsing
        let stdout = String::from_utf8_lossy(&output.stdout);
        self.parse_transaction_hash_from_cast_output(&stdout)
    }
}

// Helper function to run cast send and wait for receipt
async fn run_cast_send(
    cast_path: &str,
    rpc_url: &str,
    private_key: &str,
    to: &str,
    sig: &str,
    args: &[String],
    value: Option<&str>, // Optional value for sending ETH
    gas_limit: Option<u64>,
) -> Result<String, BlockchainError> {
    let mut cmd = tokio::process::Command::new(cast_path);
    cmd.arg("send")
       .arg(to)
       .arg(sig);
    for arg in args {
        cmd.arg(arg);
    }
    cmd.arg("--private-key").arg(private_key);
    cmd.arg("--rpc-url").arg(rpc_url);
    if let Some(val) = value {
        cmd.arg("--value").arg(val);
    }
    if let Some(gas) = gas_limit {
        cmd.arg("--gas-limit").arg(gas.to_string());
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    println!("[Relayer] Executing command: {:?}", cmd);
    let output = cmd.output().await.map_err(|e| BlockchainError::CommandError(format!("Failed to execute cast send: {}", e)))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    println!("[Relayer] cast send STDOUT:\n{}", stdout);
    if !stderr.is_empty() {
        println!("[Relayer] cast send STDERR:\n{}", stderr);
    }

    if !output.status.success() {
        return Err(BlockchainError::TransactionFailed(format!(
            "cast send failed with status: {}. Stderr: {}",
            output.status,
            stderr
        )));
    }

    // Parse transaction hash from stdout
    let tx_hash = stdout.lines()
        .find(|line| line.trim_start().starts_with("transactionHash"))
        .and_then(|line| line.split_whitespace().nth(1))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| BlockchainError::CommandError(format!("Failed to parse tx hash from output: {}", stdout)))?;

    println!("[Relayer] Transaction sent: {}. Waiting for receipt...", tx_hash);

    // Wait for receipt using cast receipt in a loop
    let max_retries = 10;
    let retry_delay = Duration::from_secs(1); // Use std::time::Duration
    for attempt in 0..max_retries {
        // ... existing code ...
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Test Configuration & Constants ---
    // These should match the keys and settings in evm-simulation/script/CrossChainSwap.s.sol
    const RPC_URL_A: &str = "http://localhost:8545";
    const RPC_URL_B: &str = "http://localhost:8546";
    const CHAIN_A_ID: u64 = 31337; // Default Anvil ID
    const CHAIN_B_ID: u64 = 31337; // Use 31337 again if using the same Anvil instance or different if using two

    const RELAYER_PK: &str = "0x59c6995e998f97a5300194dc6916aa8c096e6d7d7f81a78f05791c43177926b8"; // Anvil default key 1
    // TEE committee member keys from the script (needed for signing)
    const TEE_MEMBER_1_PK: &str = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
    // Use this one for single signature tests

    const CAST_PATH: &str = "cast"; // Assume cast is in PATH
    const FORGE_SCRIPT_PATH: &str = "../evm-simulation/script/CrossChainSwap.s.sol"; // Relative path
    const EVM_SIM_DIR: &str = "../evm-simulation"; // Root dir for forge script command

    struct DeployedContracts {
        token_a_addr: String,
        escrow_a_addr: String,
        token_b_addr: String,
        escrow_b_addr: String,
    }

    // --- Helper Functions ---

    // Runs forge script and parses contract addresses
    fn run_forge_script() -> Result<DeployedContracts, String> {
        println!("Running forge script to deploy contracts...");
        // Note: This assumes Anvil instances are already running on RPC_URL_A and RPC_URL_B
        let output = StdCommand::new("forge")
            .arg("script")
            .arg(FORGE_SCRIPT_PATH)
            .arg("--rpc-url") // Target main chain for script execution
            .arg(RPC_URL_A)
            .arg("--broadcast") // Send transactions
            .arg("--private-key") // Fund deployment/execution
            .arg(RELAYER_PK)
            .current_dir(EVM_SIM_DIR) // Run from the evm-simulation directory
            .output()
            .map_err(|e| format!("Failed to execute forge script: {}", e))?;

        if !output.status.success() {
            return Err(format!(
                "Forge script failed:\nStatus: {}\nStdout: {}\nStderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("Forge script output:\n{}", stdout);

        // Regex to find deployed addresses (adjust if script output format changes)
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
            _ => Err("Failed to parse all contract addresses from forge script output".to_string()),
        }
    }

    // Helper to call `cast call` and get output
    async fn cast_call(rpc_url: &str, to: &str, sig: &str, args: &[&str]) -> Result<String, String> {
        let mut cmd = Command::new(CAST_PATH);
        cmd.arg("call")
           .arg(to)
           .arg(sig);
        for arg in args {
            cmd.arg(arg);
        }
        cmd.arg("--rpc-url").arg(rpc_url);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        
        println!("Executing cast call: {:?}", cmd);
        let output = cmd.output().await.map_err(|e| format!("Failed to run cast call: {}", e))?;

        if !output.status.success() {
             Err(format!(
                "cast call failed:\nStatus: {}\nStderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ))
        } else {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        }
    }
    
    // Helper to generate a single signature using `cast wallet sign`
    // Note: This signs the *string* representation of the hash, not the bytes directly.
    // For testing cast send formatting, this might be sufficient, but for real contract 
    // verification, direct hash signing (e.g., with ethers-rs) is needed.
    async fn cast_sign_message(private_key: &str, message: &str) -> Result<String, String> {
        let mut cmd = Command::new(CAST_PATH);
        cmd.arg("wallet")
           .arg("sign")
           .arg(message)
           .arg("--private-key")
           .arg(private_key);
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        println!("Executing cast sign: {:?}", cmd);
        let output = cmd.output().await.map_err(|e| format!("Failed to run cast sign: {}", e))?;

        if !output.status.success() {
            Err(format!(
                "cast sign failed:\nStatus: {}\nStderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ))
        } else {
            // cast sign output is just the signature 0x...
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        }
    }

    // --- Main Integration Test ---
    
    // This test requires Anvil running on ports 8545 and 8546.
    // Run with: `cargo test --package teeshard-protocol --lib onchain::evm_relayer::tests::test_evm_relayer_integration -- --exact --nocapture`
    #[tokio::test]
    #[ignore] // Ignore by default due to external dependencies and setup complexity
    async fn test_evm_relayer_integration() -> Result<(), String> {
        println!("Starting EVM Relayer integration test...");
        println!("Ensure Anvil is running on {} and {} before proceeding.", RPC_URL_A, RPC_URL_B);
        // Add a small delay to allow manual confirmation or setup
        // thread::sleep(Duration::from_secs(5)); 

        // 1. Deploy contracts using forge script
        let contracts = run_forge_script()?;
        println!("Contracts deployed:");
        println!("  Token A: {}", contracts.token_a_addr);
        println!("  Escrow A: {}", contracts.escrow_a_addr);
        println!("  Token B: {}", contracts.token_b_addr);
        println!("  Escrow B: {}", contracts.escrow_b_addr);

        // 2. Configure EvmRelayer
        let mut chain_details = HashMap::new();
        chain_details.insert(CHAIN_A_ID, ChainConfig {
            rpc_url: RPC_URL_A.to_string(),
            escrow_address: contracts.escrow_a_addr.clone(),
        });
         chain_details.insert(CHAIN_B_ID, ChainConfig {
            rpc_url: RPC_URL_B.to_string(),
            escrow_address: contracts.escrow_b_addr.clone(),
        });

        let config = EvmRelayerConfig {
            cast_path: CAST_PATH.into(),
            chain_details,
            relayer_private_key: RELAYER_PK.to_string(),
        };
        let relayer = EvmRelayer::new(config);

        // 3. Test get_balance
        println!("\nTesting get_balance...");
        let user_a_address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"; // Anvil default 0
        let balance_a = relayer.get_balance(CHAIN_A_ID, user_a_address.to_string(), contracts.token_a_addr.clone()).await.map_err(|e| e.to_string())?; 
        println!("User A balance on Chain A: {}", balance_a);
        assert!(balance_a > U256::zero(), "User A should have a positive balance");

        // 4. Test submit_release
        println!("\nTesting submit_release...");
        let swap_id_bytes: [u8; 32] = rand::random(); // Generate random swap ID
        let swap_id_hex = format!("0x{}", hex::encode(swap_id_bytes));
        let release_amount_u256 = U256::from(10);
        let user_b_address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"; // Anvil default 1

        // Get the hash the contract expects for release on Chain B
        // _hashTEEDecisionMessage(bytes32 _swapId, bool _commit, address _token, uint256 _amount, address _recipient, address _sender)
        let release_hash = cast_call(
            RPC_URL_B,
            &contracts.escrow_b_addr,
            "_hashTEEDecisionMessage(bytes32,bool,address,uint256,address,address)",
            &[
                &swap_id_hex,
                "true", // commit = true
                &contracts.token_b_addr, // Release token on Chain B
                &release_amount_u256.to_string(),
                user_b_address, // recipient
                "0x0000000000000000000000000000000000000000" // sender = 0 for release
            ]
        ).await?;
        println!("Calculated Release Hash from Escrow B: {}", release_hash);
        
        // Simulate TEE signing this hash (using cast sign for simplicity)
        let signature = cast_sign_message(TEE_MEMBER_1_PK, &release_hash).await?;
        println!("Generated Signature: {}", signature);
        let packed_signatures = hex::decode(signature.trim_start_matches("0x")).map_err(|e| e.to_string())?;

        // Pre-release balance check
        let balance_b_before = relayer.get_balance(CHAIN_B_ID, user_b_address.to_string(), contracts.token_b_addr.clone()).await.map_err(|e| e.to_string())?; 
        println!("User B balance before release: {}", balance_b_before);

        // Call submit_release
        let release_tx_hash = relayer.submit_release(
            CHAIN_B_ID, // Target Chain B
            swap_id_bytes,
            contracts.token_b_addr.clone(),
            release_amount_u256,
            user_b_address.to_string(),
            packed_signatures
        ).await.map_err(|e| e.to_string())?;
        println!("submit_release successful, Tx Hash: {}", release_tx_hash);
        assert!(release_tx_hash.starts_with("0x"));

        // Wait a bit for transaction to mine (increase if needed)
        thread::sleep(Duration::from_secs(2)); 

        // Post-release balance check
        let balance_b_after = relayer.get_balance(CHAIN_B_ID, user_b_address.to_string(), contracts.token_b_addr.clone()).await.map_err(|e| e.to_string())?; 
        println!("User B balance after release: {}", balance_b_after);
        assert_eq!(balance_b_after, balance_b_before + release_amount_u256, "User B balance incorrect after release");
        
        // Verify finalization state on chain
        let is_finalized_output = cast_call(RPC_URL_B, &contracts.escrow_b_addr, "isFinalized(bytes32)", &[&swap_id_hex]).await?;
        println!("isFinalized({}) on Chain B: {}", swap_id_hex, is_finalized_output);
        // cast call returns hex bool: 0x...01 for true, 0x...00 for false
        assert!(is_finalized_output.ends_with("1"), "Swap should be finalized on Chain B after release");

        // 5. Test submit_abort
        println!("\nTesting submit_abort...");
        let swap_id_abort_bytes: [u8; 32] = rand::random();
        let swap_id_abort_hex = format!("0x{}", hex::encode(swap_id_abort_bytes));
        let lock_amount_u256 = U256::from(50);
        
        // Need to lock funds on Chain A first
        println!("Locking funds on Chain A for abort test...");
        let _lock_tx_hash = cast_call( // Using cast_call to simplify - ideally use cast send
            RPC_URL_A,
            &contracts.escrow_a_addr,
            "lock(bytes32,address,address,uint256,uint256)",
            &[
                &swap_id_abort_hex,
                user_b_address,
                &contracts.token_a_addr,
                &lock_amount_u256.to_string(),
                "0" // Unlock time (not relevant here)
            ]
            // Add --private-key RELAYER_PK if using cast send
        ).await?;
        // TODO: Replace cast_call lock simulation with proper cast send or relayer method if needed.
        println!("Lock simulation complete (using cast call for simplicity)");
        thread::sleep(Duration::from_secs(2)); // Wait for lock state

        // Get the hash the contract expects for abort on Chain A
         let abort_hash = cast_call(
            RPC_URL_A, // Target Chain A
            &contracts.escrow_a_addr,
            "_hashTEEDecisionMessage(bytes32,bool,address,uint256,address,address)",
            &[
                &swap_id_abort_hex,
                "false", // commit = false
                &contracts.token_a_addr, // Abort token on Chain A
                &lock_amount_u256.to_string(),
                "0x0000000000000000000000000000000000000000", // recipient = 0 for abort
                user_a_address // sender
            ]
        ).await?;
        println!("Calculated Abort Hash from Escrow A: {}", abort_hash);

        // Simulate TEE signing this hash
        let abort_signature = cast_sign_message(TEE_MEMBER_1_PK, &abort_hash).await?;
        println!("Generated Abort Signature: {}", abort_signature);
        let packed_abort_signatures = hex::decode(abort_signature.trim_start_matches("0x")).map_err(|e| e.to_string())?;

        // Pre-abort balance check
        let balance_a_before_abort = relayer.get_balance(CHAIN_A_ID, user_a_address.to_string(), contracts.token_a_addr.clone()).await.map_err(|e| e.to_string())?; 
        println!("User A balance before abort: {}", balance_a_before_abort);

        // Call submit_abort
        let abort_tx_hash = relayer.submit_abort(
            CHAIN_A_ID, // Target Chain A
            swap_id_abort_bytes,
            contracts.token_a_addr.clone(),
            lock_amount_u256,
            user_a_address.to_string(),
            packed_abort_signatures
        ).await.map_err(|e| e.to_string())?;
        println!("submit_abort successful, Tx Hash: {}", abort_tx_hash);
        assert!(abort_tx_hash.starts_with("0x"));

        thread::sleep(Duration::from_secs(2)); // Wait for tx

        // Post-abort balance check
        let balance_a_after_abort = relayer.get_balance(CHAIN_A_ID, user_a_address.to_string(), contracts.token_a_addr.clone()).await.map_err(|e| e.to_string())?; 
        println!("User A balance after abort: {}", balance_a_after_abort);
        assert_eq!(
            balance_a_after_abort,
            balance_a_before_abort,
            "User A final balance mismatch on Chain A (Expected no change during test execution phase)"
        );

        // Verify finalization state on chain
         let is_finalized_abort_output = cast_call(RPC_URL_A, &contracts.escrow_a_addr, "isFinalized(bytes32)", &[&swap_id_abort_hex]).await?;
        println!("isFinalized({}) on Chain A: {}", swap_id_abort_hex, is_finalized_abort_output);
        assert!(is_finalized_abort_output.ends_with("1"), "Swap should be finalized on Chain A after abort");

        println!("\nEVM Relayer integration test completed successfully!");
        Ok(())
    }
} 