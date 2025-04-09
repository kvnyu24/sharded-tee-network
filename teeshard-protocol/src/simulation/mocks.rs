use crate::{
    config::SystemConfig,
    data_structures::{AccountId, TEEIdentity, Transaction},
    onchain::interface::{BlockchainInterface, BlockchainError, SwapId, TransactionId},
    simulation::runtime::{SimulationRuntime, SignatureShare},
    raft::state::Command,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};
use async_trait::async_trait;
use tokio::sync::mpsc;
use hex;
use ethers::types::U256;
use ethers::types::Address;

// --- Mock SimulationRuntime ---

// Contains the actual runtime handle and tracks interactions
#[derive(Clone)]
pub struct MockSimulationRuntime {
    handle: SimulationRuntime,
    // Track commands sent to shards: Arc<Mutex<Vec<(shard_id, command)>>>
    sent_shard_commands: Arc<Mutex<Vec<(usize, Command)>>>,
}

impl MockSimulationRuntime {
    // Creates a mock runtime and the result receiver
    pub fn new() -> (Self, mpsc::Receiver<SignatureShare>) {
        let (runtime_handle, result_rx) = SimulationRuntime::new();
        (Self {
            handle: runtime_handle,
            sent_shard_commands: Arc::new(Mutex::new(Vec::new())),
        }, result_rx)
    }

    // Provides the actual runtime handle for interaction
    pub fn get_handle(&self) -> SimulationRuntime {
        self.handle.clone()
    }

    // Helper for tests to verify sent commands
    pub async fn get_sent_shard_commands(&self) -> Vec<(usize, Command)> {
        self.sent_shard_commands.lock().unwrap().clone()
    }

    // Mock method now calls the real handle
    pub fn assign_nodes_to_shard(&self, shard_id: usize, nodes: Vec<TEEIdentity>) {
         println!("[MockRuntime] assign_nodes_to_shard called for Shard {}. Forwarding to real handle.", shard_id);
         // Call the real handle's method
         self.handle.assign_nodes_to_shard(shard_id, nodes);
    }
}

// --- Mock Blockchain Interface (Relayer) ---

// Define mock data structures
#[derive(Debug, Clone)]
pub struct MockBalanceEntry {
    pub balance: U256,
}

#[derive(Debug, Clone)]
pub struct MockApprovalEntry {
    pub owner: String,
    pub spender: String,
    pub amount: U256,
}

#[derive(Debug, Clone)]
pub struct MockLockEntry {
    pub chain_id: u64,
    pub swap_id: [u8; 32],
    pub recipient: String,
    pub token_address: String,
    pub amount: U256,
    pub timeout_seconds: u64,
}

// Define the state for a single mock chain
#[derive(Default, Clone, Debug)]
pub struct MockChainState {
    balances: HashMap<String, HashMap<String, U256>>,
    locks: HashMap<String, MockLockEntry>,
    approvals: HashMap<String, MockApprovalEntry>,
}

// Define the main Mock Blockchain Interface struct
#[derive(Clone)]
pub struct MockBlockchainInterface {
    state: Arc<Mutex<HashMap<u64, MockChainState>>>,
}

impl MockBlockchainInterface {
    pub fn new() -> Self {
        MockBlockchainInterface {
            state: Arc::new(Mutex::new(HashMap::new()))
        }
    }

    // Helper to get chain state, creating if it doesn't exist
    fn get_or_create_chain_state(&self, chain_id: u64) -> MutexGuard<HashMap<u64, MockChainState>> {
        let mut state_map = self.state.lock().unwrap();
        if !state_map.contains_key(&chain_id) {
            state_map.insert(chain_id, MockChainState::default());
        }
        state_map
    }
}

#[async_trait]
impl BlockchainInterface for MockBlockchainInterface {
    async fn get_balance(
        &self,
        chain_id: u64,
        account_address: String,
        token_address: String
    ) -> Result<U256, BlockchainError> {
        let state_map = self.state.lock().unwrap();
        match state_map.get(&chain_id) {
            Some(chain_state) => {
                Ok(*chain_state.balances
                    .get(&account_address)
                    .and_then(|token_balances| token_balances.get(&token_address))
                    .unwrap_or(&U256::zero()))
            },
            None => Ok(U256::zero())
        }
    }

    async fn submit_release(
        &self,
        chain_id: u64,
        swap_id: [u8; 32],
        token_address: String,
        amount: U256,
        recipient: String,
        tee_signatures: Vec<u8>,
    ) -> Result<TransactionId, BlockchainError> {
        let mut state_map = self.state.lock().unwrap();
        let chain_state = state_map.entry(chain_id).or_insert_with(MockChainState::default);
        let swap_id_hex = hex::encode(swap_id);

        println!(
            "[Mock] Release called: chain={}, swap_id={}, recipient={}, token={}, amount={}, sig_len={}",
            chain_id, swap_id_hex, recipient, token_address, amount, tee_signatures.len()
        );

        if !chain_state.locks.contains_key(&swap_id_hex) {
            println!("[Mock] Warning: Releasing non-existent lock: {}", swap_id_hex);
        }

        chain_state.locks.remove(&swap_id_hex);

        Ok(format!("mock_release_tx_{}", swap_id_hex))
    }

    async fn submit_abort(
        &self,
        chain_id: u64,
        swap_id: [u8; 32],
        token_address: String,
        amount: U256,
        sender_address: String,
        tee_signatures: Vec<u8>,
    ) -> Result<TransactionId, BlockchainError> {
        let mut state_map = self.state.lock().unwrap();
        let chain_state = state_map.entry(chain_id).or_insert_with(MockChainState::default);
        let swap_id_hex = hex::encode(swap_id);

        println!("[Mock] Abort called: chain={}, swap_id={}, token={}, amount={}, sender={}, sig_len={}", 
                 chain_id, swap_id_hex, token_address, amount, sender_address, tee_signatures.len());

        if !chain_state.locks.contains_key(&swap_id_hex) {
            println!("[Mock] Warning: Aborting non-existent lock: {}", swap_id_hex);
        }

        chain_state.locks.remove(&swap_id_hex);

        Ok(format!("mock_abort_tx_{}", swap_id_hex))
    }

    async fn lock(
        &self,
        chain_id: u64,
        _sender_private_key: String,
        swap_id: [u8; 32],
        recipient: String,
        token_address: String,
        amount: U256,
        timeout_seconds: u64,
    ) -> Result<TransactionId, BlockchainError> {
        let mut state_map = self.state.lock().unwrap();
        let chain_state = state_map.entry(chain_id).or_insert_with(MockChainState::default);
        let swap_id_hex = hex::encode(swap_id);

        if chain_state.locks.contains_key(&swap_id_hex) {
            println!("[Mock] Lock for swap_id {} already exists, overwriting.", swap_id_hex);
        }

        let entry = MockLockEntry {
            chain_id,
            swap_id,
            recipient,
            token_address,
            amount,
            timeout_seconds,
        };

        println!("[Mock] Locking funds: {:?}", entry);
        chain_state.locks.insert(swap_id_hex.clone(), entry);

        Ok(format!("mock_lock_tx_{}", swap_id_hex))
    }

    async fn approve_erc20(
        &self,
        chain_id: u64,
        owner_private_key: String,
        token_address: String,
        spender_address: String,
        amount: U256,
    ) -> Result<TransactionId, BlockchainError> {
        let mut state_map = self.state.lock().unwrap();
        let chain_state = state_map.entry(chain_id).or_insert_with(MockChainState::default);

        let owner_address = format!("mock_owner_for_key_len_{}", owner_private_key.len());

        let approval_key = format!("{}-{}", token_address, owner_address);

        let entry = MockApprovalEntry {
            owner: owner_address.clone(),
            spender: spender_address,
            amount,
        };

        println!("[Mock] Approving ERC20: {:?}", entry);
        chain_state.approvals.insert(approval_key.clone(), entry);

        Ok(format!("mock_approve_tx_{}", approval_key))
    }
}
