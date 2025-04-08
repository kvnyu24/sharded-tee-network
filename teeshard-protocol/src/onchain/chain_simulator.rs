// Placeholder for Blockchain Simulation

use crate::data_structures::{AccountId, AssetId};
use crate::onchain::escrow_contract::EscrowCall; // Assuming defined here
use std::collections::HashMap;

// Represents a block in the simulated chain
#[derive(Clone, Debug)]
pub struct Block {
    pub block_number: u64,
    // For simplicity, just store the calls finalized in this block
    pub finalized_calls: Vec<EscrowCall>,
}

// Simulate a single blockchain environment
#[derive(Debug)]
pub struct ChainSimulator {
    pub chain_id: u64,
    pub current_block_number: u64,
    pub blocks: Vec<Block>, // History of blocks
    // Simple state representation: Account -> Asset -> Balance
    pub balances: HashMap<AccountId, HashMap<AssetId, u64>>,
    // Simulate finality delay (number of blocks)
    pub finality_delay: u64,
    // Pending calls waiting for finalization
    pending_calls: Vec<(u64, EscrowCall)>, // (block_number_added, call)
}

impl ChainSimulator {
    pub fn new(chain_id: u64, finality_delay: u64) -> Self {
        ChainSimulator {
            chain_id,
            current_block_number: 0,
            blocks: Vec::new(),
            balances: HashMap::new(),
            finality_delay,
            pending_calls: Vec::new(),
        }
    }

    // Simulate applying a call to the escrow contract (adds to pending)
    pub fn apply_escrow_call(&mut self, call: EscrowCall) {
        // Basic validation (does it match chain_id?)
        // Real chain would do more validation before accepting into mempool
        if call.chain_id() != self.chain_id {
            eprintln!("ChainSim {}: Received escrow call intended for different chain ({})",
                      self.chain_id, call.chain_id());
            return;
        }
        println!("ChainSim {}: Received pending escrow call: {:?}", self.chain_id, call);
        self.pending_calls.push((self.current_block_number, call));
    }

    // Simulate mining a new block, which includes pending calls and finalizes old ones
    pub fn finalize_next_block(&mut self) {
        self.current_block_number += 1;
        println!("ChainSim {}: Finalizing block {}", self.chain_id, self.current_block_number);

        let mut calls_in_this_block = Vec::new();
        let finalized_block_cutoff = self.current_block_number.saturating_sub(self.finality_delay);

        // Process calls added in blocks that are now final
        let (finalized_now, still_pending): (Vec<_>, Vec<_>) = self.pending_calls.drain(..)
            .partition(|(block_added, _call)| *block_added < finalized_block_cutoff);

        for (_block_added, call) in finalized_now {
            println!("ChainSim {}: Finalizing call in block {}: {:?}",
                     self.chain_id, self.current_block_number, call);
            // Apply the state change based on the call type
            self.execute_finalized_call(&call);
            calls_in_this_block.push(call);
        }

        // Keep the calls that are not yet final
        self.pending_calls = still_pending;

        let new_block = Block {
            block_number: self.current_block_number,
            finalized_calls: calls_in_this_block,
        };
        self.blocks.push(new_block);
    }

    // Internal: Execute the state change for a finalized call
    fn execute_finalized_call(&mut self, call: &EscrowCall) {
        match call {
            EscrowCall::Lock { account, asset, amount, .. } => {
                let account_balances = self.balances.entry(account.clone()).or_default();
                let current_balance = account_balances.entry(asset.clone()).or_insert(0);
                // Assume lock decreases external balance and increases internal escrow balance (not modeled here)
                // For simplicity, just record the balance change
                if *current_balance >= *amount {
                    *current_balance -= *amount;
                     println!("ChainSim {}: Locked {} {} from {}", self.chain_id, amount, asset.token_symbol, account.address);
                } else {
                     eprintln!("ChainSim {}: Insufficient balance to lock {} {} from {}", self.chain_id, amount, asset.token_symbol, account.address);
                }
            }
            EscrowCall::Release { account, asset, amount, .. } => {
                let account_balances = self.balances.entry(account.clone()).or_default();
                let current_balance = account_balances.entry(asset.clone()).or_insert(0);
                 // Assume release increases external balance
                *current_balance += *amount;
                 println!("ChainSim {}: Released {} {} to {}", self.chain_id, amount, asset.token_symbol, account.address);
            }
            EscrowCall::Abort { account, asset, amount, .. } => {
                 let account_balances = self.balances.entry(account.clone()).or_default();
                let current_balance = account_balances.entry(asset.clone()).or_insert(0);
                 // Assume abort returns locked funds, increasing external balance
                 *current_balance += *amount;
                 println!("ChainSim {}: Aborted lock, returned {} {} to {}", self.chain_id, amount, asset.token_symbol, account.address);
            }
        }
    }

    // Query balance
    pub fn get_balance(&self, account: &AccountId, asset: &AssetId) -> u64 {
        self.balances.get(account)
            .and_then(|assets| assets.get(asset))
            .copied()
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tee_logic::Signature;

    fn create_test_account(chain_id: u64, addr: &str) -> AccountId {
        AccountId { chain_id, address: addr.to_string() }
    }

    fn create_test_asset(chain_id: u64, symbol: &str) -> AssetId {
        AssetId { chain_id, token_symbol: symbol.to_string() }
    }

    #[test]
    fn chain_simulator_new() {
        let sim = ChainSimulator::new(1, 5);
        assert_eq!(sim.chain_id, 1);
        assert_eq!(sim.current_block_number, 0);
        assert_eq!(sim.finality_delay, 5);
        assert!(sim.blocks.is_empty());
        assert!(sim.balances.is_empty());
    }

    #[test]
    fn chain_simulator_apply_and_finalize() {
        let mut sim = ChainSimulator::new(1, 2); // Finality delay of 2 blocks
        let acc1 = create_test_account(1, "addr1");
        let asset1 = create_test_asset(1, "ETH");

        // Set initial balance
        sim.balances.entry(acc1.clone()).or_default().insert(asset1.clone(), 1000);
        assert_eq!(sim.get_balance(&acc1, &asset1), 1000);

        // Block 1: Apply Lock call
        let lock_call = EscrowCall::Lock {
            chain_id: 1,
            tx_id: "tx1".to_string(),
            account: acc1.clone(),
            asset: asset1.clone(),
            amount: 100,
        };
        sim.apply_escrow_call(lock_call.clone());
        sim.finalize_next_block(); // Mined in Block 1
        assert_eq!(sim.current_block_number, 1);
        assert!(sim.blocks[0].finalized_calls.is_empty()); // Not final yet
        assert_eq!(sim.get_balance(&acc1, &asset1), 1000); // Balance unchanged

        // Block 2: Mine another block
        sim.finalize_next_block(); // Mined in Block 2
         assert_eq!(sim.current_block_number, 2);
        assert!(sim.blocks[1].finalized_calls.is_empty()); // Lock call still not final (needs block 3)
        assert_eq!(sim.get_balance(&acc1, &asset1), 1000);

        // Block 3: Mine another block - Lock call should finalize
        sim.finalize_next_block(); // Mined in Block 3
         assert_eq!(sim.current_block_number, 3);
        assert_eq!(sim.blocks[2].finalized_calls.len(), 1);
        assert_eq!(sim.blocks[2].finalized_calls[0], lock_call);
        assert_eq!(sim.get_balance(&acc1, &asset1), 900); // Balance updated

         // Block 4: Apply Release call
         let release_call = EscrowCall::Release {
            chain_id: 1,
            tx_id: "tx1".to_string(),
            account: acc1.clone(),
            asset: asset1.clone(),
            amount: 100,
            tee_signature: Signature(vec![]), // Dummy sig
         };
         sim.apply_escrow_call(release_call.clone());
         sim.finalize_next_block(); // Mined in block 4
         assert_eq!(sim.current_block_number, 4);
         assert!(sim.blocks[3].finalized_calls.is_empty());
         assert_eq!(sim.get_balance(&acc1, &asset1), 900);

         // Block 5: Mine block 5
         sim.finalize_next_block();
         assert_eq!(sim.current_block_number, 5);
         assert!(sim.blocks[4].finalized_calls.is_empty());
         assert_eq!(sim.get_balance(&acc1, &asset1), 900);

        // Block 6: Mine block 6 - Release call should finalize
         sim.finalize_next_block();
         assert_eq!(sim.current_block_number, 6);
         assert_eq!(sim.blocks[5].finalized_calls.len(), 1);
         assert_eq!(sim.blocks[5].finalized_calls[0], release_call);
         assert_eq!(sim.get_balance(&acc1, &asset1), 1000); // Balance restored

    }
} 