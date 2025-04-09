use crate::{
    config::SystemConfig,
    data_structures::{AccountId, TEEIdentity, Transaction},
    shard_manager::PartitionMapping,
    tee_logic::crypto_sim::SecretKey,
    tee_logic::threshold_sig::ThresholdAggregator,
    onchain::interface::{BlockchainInterface, SwapId},
    simulation::runtime::{SimulationRuntime, SignatureShare},
    raft::state::Command,
    tee_logic::types::LockProofData,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex}; // Added Mutex
use bincode;
use bincode::config::standard;
use crate::tee_logic::threshold_sig::PartialSignature;
use crate::tee_logic::crypto_sim::verify;
use hex;
use crate::network::MockNetwork;
use std::{
    collections::{HashSet},
    sync::{Mutex as StdMutex},
    time::Duration,
};
use tokio::sync::{oneshot, Mutex as TokioMutex}; // mpsc was duplicate
use ed25519_dalek::SigningKey; // For test key generation
use ethers::types::U256;

// --- Command Enum ---
#[derive(Debug)]
pub enum CoordinatorCommand {
    ProcessObservedLock { tx: Transaction, lock_data: LockProofData },
    // Add other commands if needed
}
// ---

/// A simulated version of the CrossChainCoordinator for testing purposes.
pub struct SimulatedCoordinator {
    identity: TEEIdentity,
    secret_key: SecretKey, // No longer needs to be Clone
    config: SystemConfig,
    runtime: SimulationRuntime,
    relayer: Arc<dyn BlockchainInterface + Send + Sync>,
    partition_mapping: PartitionMapping,
    // Wrap state that needs mutation from multiple tasks in Arc<Mutex>
    pending_shares: Arc<Mutex<HashMap<String, ThresholdAggregator>>>,
}

impl SimulatedCoordinator {
    pub fn new(
        identity: TEEIdentity,
        secret_key: SecretKey,
        config: SystemConfig,
        runtime: SimulationRuntime,
        relayer: Arc<dyn BlockchainInterface + Send + Sync>,
        partition_mapping: PartitionMapping,
    ) -> Self {
        SimulatedCoordinator {
            identity,
            secret_key,
            config,
            runtime,
            relayer,
            partition_mapping,
            pending_shares: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Internal logic to handle an observed lock event.
    /// Called by the command listener.
    async fn process_observed_lock(&self, transaction: &Transaction, lock_details: &LockProofData) {
        println!(
            "[Coordinator {}] Processing observed lock event for tx: {}. Looking up shard...",
            self.identity.id,
            transaction.tx_id
        );
        let locked_account = transaction.accounts.get(0)
            .expect("Transaction must have at least one account for lock event").clone();

        let target_shard_id = self.partition_mapping.get(&locked_account)
            .copied()
            .expect("Account not found in partition mapping - ShardManager error?");

        println!(
            "[Coordinator {}] Account {:?} belongs to Shard {}. Sending ConfirmLock command...",
            self.identity.id,
            locked_account.address,
            target_shard_id
        );

        let command = Command::ConfirmLockAndSign(lock_details.clone());
        self.runtime.send_command_to_shard(target_shard_id, command).await;
        println!("[Coordinator {}] Command sent to Shard {}.", self.identity.id, target_shard_id);
    }


    /// Processes incoming signature shares received from the runtime.
    /// Takes `&self` and uses `Arc<Mutex<...>>` for state.
    async fn process_signature_share(&self, share_tuple: SignatureShare) {
        let (signer_id, lock_data, signature) = share_tuple;
        let tx_id = lock_data.tx_id.clone(); // tx_id is the hex string here

        let partial_sig = PartialSignature {
            signer_id: signer_id.clone(),
            signature_data: signature.clone(),
        };

        println!(
            "[Coordinator {}] Received signature share for tx {} from Node {}",
            self.identity.id,
            tx_id, // Log the hex tx_id
            signer_id.id
        );

        // --- Verify Signature ---
        // The message signed by TEE nodes is the *serialized LockProofData*
        let message_bytes = match bincode::encode_to_vec(&lock_data, standard()) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!(
                    "[Coordinator {}] Failed to serialize LockProofData for tx {}: {}. Discarding share.",
                    self.identity.id, tx_id, e
                );
                return;
            }
        };

        if !verify(&message_bytes, &signature, &signer_id.public_key) {
             eprintln!(
                 "[Coordinator {}] Invalid signature share received for tx {} from Node {}. Discarding.",
                 self.identity.id, tx_id, signer_id.id
             );
             return;
        }
        println!("[Coordinator {}] Signature share for tx {} from Node {} VERIFIED.", self.identity.id, tx_id, signer_id.id);
        // --- End Verification ---

        // --- Access pending_shares via mutex ---
        let mut shares_map = self.pending_shares.lock().await;

        // Retrieve or create the aggregator specific to this tx_id
        let aggregator = shares_map.entry(tx_id.clone()) // Use entry API
            .or_insert_with(|| ThresholdAggregator::new(self.config.coordinator_threshold));

        // Add the share
        if let Err(e) = aggregator.add_partial_signature(&message_bytes, partial_sig) {
            eprintln!(
                "[Coordinator {}] Failed to add share for tx {} from Node {}: {}. Discarding.",
                self.identity.id, tx_id, signer_id.id, e
            );
            // Decide if we should remove the entry if adding fails (e.g., duplicate share error)
            // If the error is non-fatal (like duplicate), maybe just log and continue.
            // If it's fatal, potentially remove: shares_map.remove(&tx_id);
            drop(shares_map); // Drop the lock before returning early
            return;
        }

        println!(
            "[Coordinator {}] Stored share for tx {}. Total shares received: {}/{}",
            self.identity.id,
            tx_id,
            aggregator.signature_count(),
            aggregator.get_required_threshold()
        );

        // Check if threshold is met
        let threshold_met = aggregator.has_reached_threshold();
        let finalized_sig_opt = if threshold_met {
            println!(
                "[Coordinator {}] Threshold reached for tx {}. Finalizing multi-signature...",
                self.identity.id,
                tx_id
            );
            // Assuming finalize_multi_signature does not mutate state or clones needed data
            aggregator.finalize_multi_signature()
        } else {
            None
        };

        // --- End access to pending_shares ---
        // Drop the lock explicitly AFTER we're done needing the aggregator state for this share
        drop(shares_map);

        // If threshold was met and finalization succeeded, proceed to submit release
        if let Some(multi_sig_collection) = finalized_sig_opt {
            println!(
                "[Coordinator {}] Multi-signature collection finalized for tx {}. Submitting release...",
                self.identity.id,
                tx_id // Log hex tx_id
            );

            let mut aggregated_sig_bytes = Vec::new();
            for (_pk, sig) in multi_sig_collection {
                aggregated_sig_bytes.extend_from_slice(&sig.to_bytes());
            }

            // The swap_id for the relayer is the *original* identifier, likely the bytes32 hash,
            // NOT the hex string tx_id used internally in LockProofData.
            // We need the original Transaction or a way to get the bytes32 swap_id.
            // **MAJOR REFACTOR NEEDED:** LockProofData needs the original bytes32 swap_id,
            // or the coordinator needs access to the original Transaction based on tx_id.
            // Let's assume for now LockProofData.tx_id *is* the bytes32 hex string, and decode it.
            let swap_id_result: Result<[u8; 32], String> = hex::decode(&tx_id) // Decode hex tx_id
                .map_err(|e| format!("Failed to decode tx_id hex '{}': {}", tx_id, e))
                .and_then(|bytes| bytes.try_into().map_err(|_| format!("Decoded tx_id '{}' is not 32 bytes long", tx_id)));

            match swap_id_result {
                Ok(swap_id) => {
                     match self.relayer.submit_release(
                        lock_data.target_chain_id,
                        swap_id, // Use the decoded [u8; 32] swap_id
                        lock_data.token_address.clone(),
                        lock_data.amount.into(),
                        lock_data.recipient.clone(),
                        aggregated_sig_bytes,
                    ).await {
                        Ok(onchain_tx_hash) => {
                            println!(
                                "[Coordinator {}] Relayer submitted release for swap_id 0x{}. On-chain Tx: {}",
                                self.identity.id,
                                hex::encode(swap_id), // Log bytes32 swap_id
                                onchain_tx_hash
                            );
                            // Remove processed swap from pending shares map
                            let mut shares_map_for_removal = self.pending_shares.lock().await;
                            shares_map_for_removal.remove(&tx_id); // Remove using hex tx_id key
                            drop(shares_map_for_removal);
                        }
                        Err(e) => {
                            eprintln!(
                                "[Coordinator {}] Relayer failed to submit release for swap_id 0x{}: {}",
                                self.identity.id,
                                hex::encode(swap_id), // Log bytes32 swap_id
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "[Coordinator {}] Error preparing swap_id from tx_id '{}' for release: {}",
                        self.identity.id,
                        tx_id, // Log hex tx_id
                        e
                    );
                    // Decide if we should stop processing here
                }
            }
        }
        // Else: threshold not met, do nothing more for this share
    }

    /// Runs a loop to listen for incoming signature shares from the runtime.
    /// Takes `&self` because state mutation happens via mutex.
    /// Processes shares sequentially within the loop.
    pub async fn run_share_listener(&self, mut result_rx: mpsc::Receiver<SignatureShare>) {
        println!("[Coordinator {}] Starting share listener loop...", self.identity.id);
        while let Some(share) = result_rx.recv().await {
            // Process the received share directly
            self.process_signature_share(share).await;
        }
        println!("[Coordinator {}] Share listener loop finished (channel closed).", self.identity.id);
    }

    /// Runs a loop to listen for commands from the test harness or other sources.
    /// Takes `&self` as state access is via mutex or read-only.
    pub async fn run_command_listener(&self, mut command_rx: mpsc::Receiver<CoordinatorCommand>) {
        println!("[Coordinator {}] Starting command listener loop...", self.identity.id);
        while let Some(command) = command_rx.recv().await {
             println!("[Coordinator {}] Received command: {:?}", self.identity.id, command);
             match command {
                 CoordinatorCommand::ProcessObservedLock { tx, lock_data } => {
                     self.process_observed_lock(&tx, &lock_data).await;
                 }
             }
         }
         println!("[Coordinator {}] Command listener loop finished (channel closed).", self.identity.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Import items from outer module
    use crate::simulation::mocks::MockBlockchainInterface;
    use crate::network::MockNetwork; // Use corrected path here too
    use crate::tee_logic::crypto_sim::sign; // Add missing import for sign
    use std::time::Duration;
    use tokio::sync::Mutex as TokioMutex; // Keep alias for clarity
    use ethers::types::U256;

    // Helper to create TEE Identity and SecretKey for tests
    fn create_test_tee(id: usize) -> (TEEIdentity, SecretKey) {
        let secret_bytes = [id as u8; 32];
        let secret_key = SecretKey::from_bytes(&secret_bytes);
        let public_key = secret_key.verifying_key();
        (TEEIdentity { id, public_key }, secret_key)
    }

    // Helper function to create a SystemConfig for tests
    // Copied from cross_chain/swap_coordinator.rs tests
    fn create_test_config(num_coordinators: usize, threshold: usize) -> SystemConfig {
        let mut coordinator_identities = Vec::new();
        for i in 0..num_coordinators {
            let (id, _) = create_test_tee(100 + i); // Generate unique IDs
            coordinator_identities.push(id);
        }

        SystemConfig {
            coordinator_identities,
            coordinator_threshold: threshold, // Set threshold
            nodes_per_shard: 2, // Default or adjust if needed
            ..Default::default() // Use defaults for other fields
        }
    }

    // --- Test: Share Processing, Aggregation, and Release Trigger ---
    #[tokio::test]
    async fn test_coordinator_processes_shares_and_triggers_release() {
         // Setup
         let threshold = 2;
        let (coord_identity, coord_secret) = create_test_tee(0);
        let mut config = SystemConfig::default();
        config.coordinator_threshold = threshold;
        
        let mock_relayer = Arc::new(MockBlockchainInterface::new());
        // Use the non-mock SimulationRuntime here, as the coordinator interacts with its handle
        let (runtime, _result_rx, _, _) = SimulationRuntime::new(); 
        let partition_mapping = PartitionMapping::new(); // Not needed for this specific test focus

        // No receiver needed for this test, as we call process_signature_share directly
        let coordinator = SimulatedCoordinator::new(
            coord_identity, coord_secret, config, 
            runtime, // Pass the real runtime 
            mock_relayer.clone(), partition_mapping
        );

        // Create identities and keys for simulated TEE nodes
        let (tee1_id, tee1_sk) = create_test_tee(1);
        let (tee2_id, tee2_sk) = create_test_tee(2);

        // Use a fixed 32-byte array for the SwapId
        let tx_id_bytes: SwapId = [15u8; 32]; // Example 32-byte ID
        let tx_id_string = hex::encode(tx_id_bytes); // String version used as key

        let lock_data = LockProofData {
            tx_id: tx_id_string.clone(), // Use string version for LockProofData consistency
            source_chain_id: 1, target_chain_id: 2, token_address: "token".to_string(), amount: 100, recipient: "rec".to_string()
        };
        let message_bytes = bincode::encode_to_vec(&lock_data, standard()).unwrap();

        // Create valid shares
        let sig1 = sign(&message_bytes, &tee1_sk);
        let share1: SignatureShare = (tee1_id.clone(), lock_data.clone(), sig1.clone()); // Clone sig1
        
        let sig2 = sign(&message_bytes, &tee2_sk);
        let share2: SignatureShare = (tee2_id.clone(), lock_data.clone(), sig2.clone()); // Clone sig2
        
        // Action & Verification
        // Initialize aggregator by processing first share
        coordinator.process_signature_share(share1).await;
        {
            // Acquire lock to check state
            let shares_map = coordinator.pending_shares.lock().await;
            assert_eq!(shares_map.get(&tx_id_string).expect("Aggregator for tx1 should exist after first share").signature_count(), 1);
        } // Lock dropped here
        assert!(!mock_relayer.submit_release_called().await, "Relayer should not be called yet");

        // Process second share (meets threshold)
        coordinator.process_signature_share(share2).await;
        {
            // Acquire lock again to check state
            let shares_map = coordinator.pending_shares.lock().await;
            // Aggregator might still exist briefly *during* finalization, 
            // but should be removed shortly *after* successful submit_release call finishes.
            // Let's wait briefly before asserting removal.
            tokio::time::sleep(Duration::from_millis(50)).await; 
            assert!(shares_map.get(&tx_id_string).is_none(), "Aggregator should be removed after processing and release submission");
        } // Lock dropped here
        assert!(mock_relayer.submit_release_called().await, "Relayer should be called after threshold met");
        
        // Verify details passed to relayer
        let (chain_id, swap_id, token, amount, recipient, sig_bytes) = mock_relayer.get_last_release_args().await.unwrap();
        assert_eq!(chain_id, lock_data.target_chain_id);
        assert_eq!(swap_id, tx_id_bytes, "Swap ID passed to relayer mismatch"); // Compare with the byte array
        assert_eq!(token, lock_data.token_address);
        assert_eq!(amount, U256::from(lock_data.amount), "Amount mismatch");
        assert_eq!(recipient, lock_data.recipient);
        
        // Verify signature bytes: Construct expected bytes in the order determined by PK sorting
        let pk1_bytes = tee1_id.public_key.to_bytes();
        let pk2_bytes = tee2_id.public_key.to_bytes();
        
        // Signatures are concatenated based on the public key sorting order
        let expected_sig_bytes = if pk1_bytes < pk2_bytes {
            [sig1.to_bytes().as_slice(), sig2.to_bytes().as_slice()].concat()
        } else {
            [sig2.to_bytes().as_slice(), sig1.to_bytes().as_slice()].concat()
        };
        assert_eq!(sig_bytes, expected_sig_bytes, "Aggregated signature bytes mismatch");
    }

    #[tokio::test]
    async fn test_coordinator_initiates_swap_and_collects_shares() {
        // Setup: Coordinators, Network, Blockchain
        let num_coordinators = 3;
        let threshold = 2;
        let config = create_test_config(num_coordinators, threshold);
        let mock_network = Arc::new(MockNetwork::new());
        let mock_blockchain = Arc::new(MockBlockchainInterface::new()); // Call ::new()

        // Use the actual runtime for node interaction simulation if needed, 
        // or stick with MockNetwork if only testing coordinator logic.
        // Let's assume MockNetwork is sufficient for this specific unit test.
        let (runtime, _result_rx, _att_rx, _iso_rx) = SimulationRuntime::new(); // Fix destructuring

        let mut coordinators: HashMap<TEEIdentity, Arc<TokioMutex<SimulatedCoordinator>>> = HashMap::new();
        let mut coordinator_keys: Vec<SecretKey> = Vec::new();
    }
}
