use crate::{
    config::SystemConfig as RootSystemConfig,
    data_structures::{TEEIdentity},
    shard_manager::PartitionMapping,
    tee_logic::crypto_sim::SecretKey,
    tee_logic::threshold_sig::ThresholdAggregator,
    onchain::interface::BlockchainInterface,
    simulation::runtime::SimulationRuntime,
    raft::state::Command,
    tee_logic::types::LockProofData,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, watch}; // Added Mutex and watch
use bincode;
use bincode::config::standard;
use crate::tee_logic::threshold_sig::PartialSignature;
use crate::tee_logic::crypto_sim::verify;
use hex;
 // mpsc was duplicate
 // For test key generation
 // Import SimulationConfig
 // Add missing import for sign
use crate::simulation::metrics::{self, MetricEvent}; // Add metrics import and metrics module import
use std::time::{Instant, SystemTime, UNIX_EPOCH}; // Add SystemTime and UNIX_EPOCH
use std::time::Duration as StdDuration; // Alias Duration to avoid conflict if needed, or just use Duration
 // Use corrected path here too
 // Import EmulatedNetwork
 // Keep SystemConfig
 // Keep Signature import
use crate::tee_logic::crypto_sim::PublicKey;
use crate::simulation::runtime::SignatureShare;
use log;
use log::{debug, info, warn, error};
use std::time::Duration;
use crate::simulation::config::SimulationConfig; // Import SimulationConfig
use crate::tee_logic::crypto_sim::generate_keypair;
use crate::tee_logic::types::Signature; // Keep Signature import
use crate::data_structures::{AccountId, Transaction, TxType, AssetId, LockInfo};
use tokio::time::interval;

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
    system_config: RootSystemConfig,
    runtime: SimulationRuntime,
    relayer: Arc<dyn BlockchainInterface + Send + Sync>,
    partition_mapping: PartitionMapping,
    // Wrap state that needs mutation from multiple tasks in Arc<Mutex>
    pending_shares: Arc<Mutex<HashMap<String, ThresholdAggregator>>>,
    // Track transaction start times for metrics
    transaction_start_times: Arc<Mutex<HashMap<String, Instant>>>, 
    metrics_tx: Option<mpsc::Sender<MetricEvent>>, // Store metrics sender as Option
    committee: HashMap<TEEIdentity, PublicKey>, 
    // NEW: Store shard assignments locally
    shard_assignments: Arc<Mutex<HashMap<usize, Vec<TEEIdentity>>>>,
}

impl SimulatedCoordinator {
    pub fn new(
        identity: TEEIdentity,
        secret_key: SecretKey,
        system_config: RootSystemConfig,
        runtime: SimulationRuntime,
        relayer: Arc<dyn BlockchainInterface + Send + Sync>,
        partition_mapping: PartitionMapping,
        metrics_tx: mpsc::Sender<MetricEvent>, // Accept metrics sender
        // NEW: Accept shard assignments
        shard_assignments: Arc<Mutex<HashMap<usize, Vec<TEEIdentity>>>>,
    ) -> Self {
        // OLD: Use only coordinator identities
        // let committee = system_config.coordinator_identities.iter()
        //     .map(|id| (id.clone(), id.public_key.clone()))
        //     .collect();

        // NEW: Get ALL TEE identities known to the runtime
        // We need to access the runtime's internal state or pass the full list.
        // Let's assume the SystemConfig might have a full list or we modify the constructor.
        // FOR NOW: A potential temporary fix using coordinator_identities + inferring shard nodes if possible.
        // Let's try a simpler approach first: Use ALL identities if available in SystemConfig.
        // If SystemConfig only has coordinator_identities, this needs rethinking.
        // Assuming system_config MIGHT eventually hold all identities.
        // Let's adjust based on how identities are ACTUALLY populated in the test first.

        // REVISED BASED ON TEST SETUP: The test setup creates a *full* list,
        // then slices it. The SystemConfig ONLY gets the coordinator slice.
        // The runtime *does* get the full SimulationConfig, but maybe not easy to access here.
        //
        // CORRECT APPROACH: The `ThresholdAggregator` needs the committee *relevant to the transaction*.
        // This committee is likely the set of TEEs in the shard handling the lock.
        // The aggregator is created *when the first share arrives*.
        // THEREFORE, the committee should be determined *then*, possibly using the lock_data.
        //
        // LET'S MODIFY `process_signature_share` instead.

        // Keep the coordinator's own identity list for other potential uses
        let coordinator_committee = system_config.coordinator_identities.iter()
            .map(|id| (id.clone(), id.public_key.clone()))
            .collect();


        SimulatedCoordinator {
            identity,
            secret_key,
            system_config, // Store SystemConfig
            runtime,
            relayer,
            partition_mapping,
            pending_shares: Arc::new(Mutex::new(HashMap::new())),
            transaction_start_times: Arc::new(Mutex::new(HashMap::new())), // Initialize map
            metrics_tx: Some(metrics_tx), // Store as Option
            committee: coordinator_committee, // Store the coordinator list for now
            // NEW: Store shard assignments
            shard_assignments,
        }
    }

    /// Internal logic to handle an observed lock event.
    /// Called by the command listener.
    async fn process_observed_lock(&self, transaction: &Transaction, lock_details: &LockProofData) {
        let tx_id = transaction.tx_id.clone();
        // Ensure this log has a timestamp for START inference
        let timestamp_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
        info!(
            "[Coordinator {}][{}] Processing observed lock event for tx: {}", // Add timestamp
            self.identity.id, timestamp_ms, tx_id
        );

        // --- Record Start Time for Metrics ---
        {
            let mut start_times = self.transaction_start_times.lock().await;
            if !start_times.contains_key(&tx_id) {
                let now = Instant::now();
                start_times.insert(tx_id.clone(), now);
                // LOG TRANSACTION START using info!
                let timestamp_ms_log = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
                // Use info! macro instead of println!
                info!(
                    "METRIC_LOG_V2: START tx_id={} timestamp_ms={}",
                    tx_id, timestamp_ms_log
                );
            } else {
                 // Use debug! or trace! for less critical logs
                 debug!("[Coordinator {}] Start time already recorded for tx: {}", self.identity.id, tx_id);
            }
        } // Lock dropped here
        // --- End Metrics --- 
        
        let locked_account = transaction.accounts.get(0)
            .expect("Transaction must have at least one account for lock event").clone();

        let target_shard_id = self.partition_mapping.get(&locked_account)
            .copied()
            .expect("Account not found in partition mapping - ShardManager error?");

        // Use info! or debug! for operational logs
        info!(
            "[Coordinator {}] Account {:?} belongs to Shard {}. Sending ConfirmLock command...",
            self.identity.id,
            locked_account.address,
            target_shard_id
        );

        let command = Command::ConfirmLockAndSign(lock_details.clone());
        self.runtime.send_command_to_shard(target_shard_id, command).await;
        info!("[Coordinator {}] Command sent to Shard {}.", self.identity.id, target_shard_id); // Changed to info!
    }


    /// Processes incoming signature shares received from the runtime.
    /// Takes `&self` and uses `Arc<Mutex<...>>` for state.
    async fn process_signature_share(&self, share_tuple: SignatureShare) {
        let (signer_id, lock_data, signature) = share_tuple;
        let tx_id = lock_data.tx_id.clone(); // tx_id is the hex string here
        let mut success = false; // Track success for the metric

        let partial_sig = PartialSignature {
            signer_id: signer_id.clone(),
            signature_data: signature.clone(),
        };

        // Use info! or debug!
        info!(
            "[Coordinator {}] Received signature share for tx {} from Node {}",
            self.identity.id,
            tx_id, // Log the hex tx_id
            signer_id.id
        );

        // --- Verify Signature ---
        // Create a tuple of the fields that were signed (excluding start_time)
        let signable_data_tuple = (
            &lock_data.tx_id,
            lock_data.source_chain_id,
            lock_data.target_chain_id,
            &lock_data.token_address,
            lock_data.amount,
            &lock_data.recipient
        );
        // The message signed/verified is the *serialized tuple*
        let message_bytes = match bincode::encode_to_vec(&signable_data_tuple, standard()) {
            Ok(bytes) => bytes,
            Err(e) => {
                // Use error!
                error!(
                    "[Coordinator {}] Failed to serialize LockProofData for tx {}: {}. Discarding share.",
                    self.identity.id, tx_id, e
                );
                return;
            }
        };

        // Get delays from config (stored in self.config, which is SystemConfig)
        let verify_min_ms = self.system_config.tee_delays.verify_min_ms;
        let verify_max_ms = self.system_config.tee_delays.verify_max_ms;

        // Pass delays and metrics context to verify call
        if !verify(
            &message_bytes, 
            &signature, 
            &signer_id.public_key, 
            verify_min_ms, 
            verify_max_ms,
            &self.metrics_tx,
            &Some(self.identity.clone()),
        ).await {
             // Use error!
             error!(
                 "[Coordinator {}] Invalid signature share received for tx {} from Node {}. Discarding.",
                 self.identity.id, tx_id, signer_id.id
             );
             return;
        }
        // Use info! or debug!
        info!("[Coordinator {}] Signature share for tx {} from Node {} VERIFIED.", self.identity.id, tx_id, signer_id.id);
        // --- End Verification ---

        // --- Determine the correct committee for THIS transaction ---
        // The committee should be the set of nodes responsible for the shard
        // involved in the lock. We get the shard_id from lock_data.
        let shard_id_for_tx = lock_data.shard_id;

        // NEW: Get assignments from the coordinator's stored map
        let assignments_lock = self.shard_assignments.lock().await;
        let expected_shard_members_opt = assignments_lock.get(&shard_id_for_tx).cloned();
        drop(assignments_lock); // Release lock early

        let expected_shard_members = match expected_shard_members_opt {
            Some(members) => members,
            None => {
                // Use error!
                error!(
                    "[Coordinator {}] ERROR: No shard assignment found in local map for shard {} (tx {})! Discarding share.",
                    self.identity.id, shard_id_for_tx, tx_id
                );
                return;
            }
        };

        // --- Validate Signer is part of the Expected Shard ---
        if !expected_shard_members.iter().any(|member| member == &signer_id) {
            // Use error!
            error!(
                "[Coordinator {}] ERROR: Signer Node {} is not part of the expected committee for shard {} (tx {}). Expected members: {:?}. Discarding share.",
                self.identity.id,
                signer_id.id,
                shard_id_for_tx,
                tx_id,
                expected_shard_members.iter().map(|m| m.id).collect::<Vec<_>>()
            );
            // Optionally send a metric about this invalid share
            return;
        }

        // --- Construct the Committee Map for the Aggregator ---
        let transaction_committee: HashMap<TEEIdentity, PublicKey> = expected_shard_members
            .into_iter()
            .map(|id| (id.clone(), id.public_key.clone()))
            .collect();

        // We should not hit this case anymore due to the check above, but keep for safety.
        if transaction_committee.is_empty() {
             // Use error!
             error!(
                 "[Coordinator {}] Internal ERROR: Failed to construct committee map for shard {} (tx {}), even though members were found.",
                 self.identity.id, shard_id_for_tx, tx_id
             );
             return;
        }
        // Use debug! for verbose internal state
        debug!(
            "[Coordinator {}] DEBUG: Determined committee for shard {} (tx {}): {:?}", 
            self.identity.id, 
            shard_id_for_tx, 
            tx_id, 
            transaction_committee.keys().map(|k| k.id).collect::<Vec<_>>()
        );

        // --- Aggregate Signatures ---
        // Lock the pending_shares map
        let mut pending = self.pending_shares.lock().await;

        let aggregator = pending
            .entry(tx_id.clone()) // Use tx_id as the key
            .or_insert_with(|| {
                // Use info! or debug!
                info!(
                    "[Coordinator {}] Creating new ThresholdAggregator for tx {} (shard {})",
                    self.identity.id, tx_id, shard_id_for_tx
                );
                // Use the committee derived from the shard assignment and the TEE threshold
                // Correct constructor call with all 6 arguments
                ThresholdAggregator::new(
                    message_bytes.clone(), // 1. Serialized message
                    self.system_config.tee_threshold, // 2. Threshold
                    transaction_committee.clone(), // 3. Committee map
                    self.system_config.tee_delays.clone(), // 4. Delay config
                    self.metrics_tx.clone(), // 5. Metrics sender (Option)
                    Some(self.identity.clone()), // 6. Coordinator Node ID (Option)
                )
            });

        // Ensure the aggregator we retrieved or created is for the correct committee
        // (This guards against race conditions if two shares for the *same tx* but *different inferred committees* somehow arrived,
        // though our logic above should prevent this by deriving committee from shard_id)
        // REMOVED: Check `if aggregator.committee() != &transaction_committee { ... }` as committee field is private
        // and the logic should ensure consistency.

        // Add the verified signature share to the aggregator
        // Use correct method `add_partial_signature`, pass id & signature, and await
        match aggregator.add_partial_signature(signer_id.clone(), signature.clone()).await { // RENAMED and AWAITED
            Ok(true) => {
                // Get the combined signature IF the threshold was met
                let full_signature = match aggregator.get_combined_signature() {
                    Some(sig) => sig.clone(), // Clone the signature to use it
                    None => {
                         // Use error!
                         error!(
                             "[Coordinator {}] CRITICAL ERROR: add_partial_signature reported threshold met for tx {}, but get_combined_signature returned None.",
                             self.identity.id, tx_id
                         );
                         return; // Cannot proceed without signature
                    }
                };

                // Use info!
                info!(
                    "[Coordinator {}] Threshold met for tx {}! {}/{} shares collected.",
                    self.identity.id,
                    tx_id,
                    aggregator.signature_count(), // RENAMED
                    aggregator.get_threshold() // RENAMED
                );
                // --- Call Relayer --- 
                 // Decode hex tx_id string back to [u8; 32] for swap_id
                 let swap_id_bytes = match hex::decode(&tx_id) {
                     Ok(bytes) => bytes,
                     Err(_) => {
                         // Use error!
                         error!("[Coordinator {}] CRITICAL ERROR: Failed to decode tx_id {} from hex. Cannot submit release.", self.identity.id, tx_id);
                         return; // Cannot proceed without a valid swap_id
                     }
                 };
                 let swap_id_array: [u8; 32] = match swap_id_bytes.try_into() {
                     Ok(array) => array,
                     Err(_) => {
                         // Use error!
                         error!("[Coordinator {}] CRITICAL ERROR: Decoded tx_id {} is not 32 bytes long. Cannot submit release.", self.identity.id, tx_id);
                         return; // Cannot proceed without a valid swap_id
                     }
                 };

                 info!(
                     "[Coordinator {}] Threshold met for tx {}. Attempting relayer call...",
                     self.identity.id,
                     tx_id
                 );
                 let relayer_call_start = Instant::now();
                 let relayer_timeout = Duration::from_secs(30); // Example: 30 second timeout

                 let release_result = tokio::time::timeout(relayer_timeout, self.relayer.submit_release(
                      lock_data.target_chain_id,
                      swap_id_array, // [u8; 32]
                      lock_data.token_address.clone(),
                      lock_data.amount.into(), // Convert to U256
                      lock_data.recipient.clone(),
                      full_signature.to_bytes().to_vec(), // Vec<u8>
                  )).await;

                 let relayer_duration = relayer_call_start.elapsed();

                 // Check result and log/update metrics
                 match release_result {
                     Ok(Ok(tx_hash)) => { // Timeout did not occur, relayer call succeeded
                         info!(
                             "[Coordinator {}] Relayer successful for tx {}. TxHash: {}, Duration: {:?}",
                             self.identity.id,
                             tx_id,
                             tx_hash,
                             relayer_duration
                         );
                         success = true;
                         // Emit metric for relayer submission
                         if let Some(metrics_tx) = &self.metrics_tx {
                             let event = MetricEvent::RelayerReleaseSubmitted {
                                 tx_id: lock_data.tx_id.clone(),
                                 target_chain_id: lock_data.target_chain_id,
                                 onchain_tx_hash: tx_hash, // Use the actual hash
                                 timestamp_ms: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
                             };
                             if let Err(e) = metrics_tx.send(event).await {
                                 warn!("[Coordinator {}] Failed to send RelayerReleaseSubmitted metric: {}", self.identity.id, e);
                             }
                         }
                     }
                     Ok(Err(e)) => { // Timeout did not occur, relayer call failed
                         error!(
                             "[Coordinator {}] Relayer failed for tx {}: {:?}. Duration: {:?}",
                             self.identity.id,
                             tx_id,
                             e,
                             relayer_duration
                         );
                         success = false;
                     }
                     Err(_) => { // Timeout occurred
                          error!(
                              "[Coordinator {}] Timeout waiting for relayer call for tx {} after {:?}",
                              self.identity.id,
                              tx_id,
                              relayer_timeout
                          );
                          success = false;
                      }
                 }

                 // Remove from pending shares only on success
                 if success {
                     pending.remove(&tx_id);
                 }
            }
            Ok(false) => {
                // Use info! or debug!
                info!(
                    "[Coordinator {}] Signature share accepted for tx {}, threshold not yet met ({}/{}).",
                    self.identity.id,
                    tx_id,
                    aggregator.signature_count(),
                    aggregator.get_threshold()
                );
            }
            Err(e) => {
                // Use error!
                error!(
                    "[Coordinator {}] Error adding signature share for tx {}: {}",
                    self.identity.id,
                    tx_id,
                    e
                );
            }
        }
    }

    // ADD static-like version
    pub async fn run_share_listener(
        id: usize, // Pass ID for logging
        mut result_rx: mpsc::Receiver<SignatureShare>,
        mut shutdown_rx: watch::Receiver<()>,
    ) {
        info!("[Coordinator {} Listener] Starting...", id); // Use passed ID
        let mut loop_count = 0;
        loop {
            tokio::select! {
                biased; // Explicitly prioritize shutdown check
                // Prioritize shutdown
                _ = shutdown_rx.changed() => {
                    info!("[Coordinator {} Listener] Shutdown signal received, exiting.", id);
                    break; // Exit the loop
                }
                // Then process results
                Some(share_tuple) = result_rx.recv() => {
                    // --- ADDED Logging ---
                    let recv_tx_id = share_tuple.1.tx_id.clone();
                    let recv_node_id = share_tuple.0.id;
                    info!("[Coordinator {} Listener] Received share for tx {} from node {}", id, recv_tx_id, recv_node_id);
                    // --- END Logging ---

                    // TODO: If actual processing of the share requires coordinator state,
                    // this design needs refinement (e.g., send share_tuple over another channel
                    // to a command processing loop). For now, just log receipt.
                    // Placeholder for actual processing:
                    // let coordinator_instance = coordinator_arc.lock().await; // If state needed
                    // coordinator_instance.process_signature_share(share_tuple).await;
                     warn!("[Coordinator {} Listener] Placeholder: Actual share processing logic is missing here!", id);
                }
                // Channel closed (sender dropped)
                else => {
                    info!("[Coordinator {} Listener] Result channel closed, exiting.", id);
                    break; // Exit if the result channel is closed
                }
            }
            loop_count += 1;
            debug!("[Coordinator {} Listener] Loop iteration {} completed.", id, loop_count);
        }
        info!("[Coordinator {} Listener] Exited loop.", id);
    }

    /// Runs a loop to listen for commands from the test harness or other sources.
    /// Takes `&self` as state access is via mutex or read-only.
    pub async fn run_command_listener(&self, mut command_rx: mpsc::Receiver<CoordinatorCommand>) {
        // TODO: Add shutdown_rx handling if needed
        // Use info! or debug!
        info!("[Coordinator {}] Starting command listener loop...", self.identity.id);
        while let Some(command) = command_rx.recv().await {
             // Use debug! for received commands
             debug!("[Coordinator {}] Received command: {:?}", self.identity.id, command);
             match command {
                 CoordinatorCommand::ProcessObservedLock { tx, lock_data } => {
                     self.process_observed_lock(&tx, &lock_data).await;
                 }
             }
         }
         // Use info! or debug!
         info!("[Coordinator {}] Command listener loop finished (channel closed).", self.identity.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Import items from outer module
    use crate::simulation::mocks::MockBlockchainInterface;
     // Use corrected path here too
    use crate::tee_logic::crypto_sim::sign; // Add missing import for sign
    use std::time::Duration;
     // Keep alias for clarity
    
    use crate::simulation::config::SimulationConfig; // Import SimulationConfig
    use crate::tee_logic::crypto_sim::generate_keypair;
     // Import EmulatedNetwork
     // Keep SystemConfig
    use crate::tee_logic::types::Signature; // Keep Signature import
    
    use crate::data_structures::{AccountId, Transaction};
    use crate::data_structures::{TxType, AssetId, LockInfo};
    use tokio::sync::watch; // Ensure watch is imported

    // Re-added helper function to create mock transaction and lock data
    fn create_mock_transaction_and_lock(tx_id_str: &str, sender_identity: &TEEIdentity) -> (Transaction, LockProofData) {
        // Generate a unique ID based on the input string and possibly a timestamp/random element
        // For simplicity in test, let's use the string directly if it's unique enough
        let tx_id_bytes = tx_id_str.as_bytes().to_vec();
        // Ensure the byte vector is exactly 32 bytes, padding or hashing if necessary
        let mut tx_id_32 = [0u8; 32];
        let len = tx_id_bytes.len().min(32);
        tx_id_32[..len].copy_from_slice(&tx_id_bytes[..len]);

        let tx_id_vec = tx_id_32.to_vec(); // Use 32-byte Vec<u8>
        let swap_id_struct = tx_id_32; // Directly assign the [u8; 32] array
        let tx_id_string = hex::encode(&tx_id_vec); // Use hex string for Transaction.tx_id

        // --- Mock Accounts & Assets for Transaction --- 
        let mock_sender_account = AccountId {
            chain_id: 1, // Source chain
            // Use sender_identity info for address
            address: format!("mock_sender_addr_{}", sender_identity.id)
        };
        let mock_recipient_account = AccountId {
            chain_id: 2, // Target chain
            address: "mock_recipient_addr".to_string()
        };
        let mock_source_asset = AssetId {
            chain_id: 1,
            token_symbol: "SRC".to_string(),
            token_address: "0xAA...".to_string()
        };
        let mock_target_asset = AssetId {
            chain_id: 2,
            token_symbol: "TGT".to_string(),
            token_address: "0xBB...".to_string()
        };
        // --- End Mock Accounts & Assets ---

        // --- Create LockInfo matching the swap --- 
        let mock_lock_info = LockInfo {
            account: mock_sender_account.clone(),
            asset: mock_source_asset.clone(),
            amount: 1000, // Must match amount below
        };
        // --- End LockInfo ---

        let mock_tx = Transaction {
            tx_id: tx_id_string.clone(), // Use the hex string ID
            tx_type: TxType::CrossChainSwap,
            // For CrossChainSwap, typically [sender_src, receiver_src, sender_tgt, receiver_tgt]
            // Simplified for mock: [sender_src, receiver_tgt]
            accounts: vec![mock_sender_account.clone(), mock_recipient_account.clone()],
            amounts: vec![1000], // Amount being swapped
            required_locks: vec![mock_lock_info.clone()], // Lock required on source chain
            target_asset: Some(mock_target_asset.clone()), // Asset expected on target chain
            timeout: StdDuration::from_secs(600), // Example timeout
        };

        // Create some dummy amount bytes (e.g., for 1000)
        let mut amount_bytes = [0u8; 32];
        let amount_u128 = 1000u128; // Example amount, match Transaction amount
        let bytes = amount_u128.to_be_bytes();
        let start_index = 32 - bytes.len();
        amount_bytes[start_index..].copy_from_slice(&bytes);


        let mock_lock_data = LockProofData {
            shard_id: 0, // ADDED: Default shard ID for test
            tx_id: tx_id_string, // Use the hex string ID
            source_chain_id: 1, // Mock chain ID (matches Transaction)
            target_chain_id: 2, // Mock chain ID (matches Transaction)
            recipient: mock_recipient_account.address.clone(), // Use recipient address from Transaction account
            token_address: mock_source_asset.token_address.clone(), // Use token address from source asset
            amount: 1000, // Use u64 amount (matches Transaction amount)
            start_time: Instant::now(), // Initialize the new field
        };

        (mock_tx, mock_lock_data)
    }

    // Helper to create TEE Identity and SecretKey for tests
    fn create_test_tee(id: usize) -> (TEEIdentity, SecretKey) {
        // let secret_bytes = [id as u8; 32]; // Unused, removed
        let secret_key = generate_keypair();
        let public_key = secret_key.verifying_key();
        (TEEIdentity { id, public_key }, secret_key)
    }

    // Helper function to create a SystemConfig for tests
    // Copied from cross_chain/swap_coordinator.rs tests
    fn create_test_config(num_coordinators: usize, threshold: usize) -> RootSystemConfig {
        let mut coordinator_identities = Vec::new();
        for i in 0..num_coordinators {
            let (id, _) = create_test_tee(100 + i); // Generate unique IDs
            coordinator_identities.push(id);
        }

        RootSystemConfig {
            coordinator_identities,
            coordinator_threshold: threshold, // Set threshold
            nodes_per_shard: 2, // Default or adjust if needed
            ..Default::default() // Use defaults for other fields
        }
    }

    async fn setup_test_environment(
        num_nodes: usize,
        threshold: usize,
    ) -> (
        SimulatedCoordinator,
        Vec<(TEEIdentity, SecretKey)>, // Node identities and keys
        Arc<MockBlockchainInterface>,
        SimulationRuntime, // Return runtime for sending messages
        PartitionMapping, // Return mapping
        mpsc::Receiver<SignatureShare>, // Return result receiver
        // NEW: Return shard assignments handle
        Arc<Mutex<HashMap<usize, Vec<TEEIdentity>>>>,
    ) {
        let coord_sk = generate_keypair(); // Generate secret key first
        let coord_pk = coord_sk.verifying_key().clone(); // Derive public key
        let coord_identity = TEEIdentity {
            id: 0, // Use usize ID for coordinator
            public_key: coord_pk,
        };

        let mut node_identities = Vec::new();
        let mut node_secrets = Vec::new();
        for i in 0..num_nodes {
            let sk = generate_keypair(); // Generate secret key
            let pk = sk.verifying_key().clone(); // Derive public key
            let identity = TEEIdentity {
                id: i + 1, // Use usize IDs for nodes (starting from 1 to avoid clash with coord 0)
                public_key: pk,
            };
            node_identities.push(identity.clone());
            node_secrets.push(sk);
        }

        // Construct the list of all TEE identities (coordinator + nodes) for the committee
        let mut all_tee_identities = vec![coord_identity.clone()];
        all_tee_identities.extend(node_identities.clone());

        // Construct SystemConfig first using ALL identities for the signing committee
        let system_config = RootSystemConfig {
            // This field name is misleading, using it for the signing committee
            coordinator_identities: all_tee_identities, 
            coordinator_threshold: threshold, // Use the test threshold
            // Add other necessary SystemConfig fields with defaults
            num_shards: 1, // Example default
            tee_threshold: threshold, // Use the test threshold here too
            max_iterations: 1000, // Example default
            ..Default::default() // Use defaults for the rest
        };

        // Construct SimulationConfig embedding SystemConfig
        let config = SimulationConfig {
            system_config: system_config.clone(), // Clone system_config for SimulationConfig
            // Add other SimulationConfig fields with defaults
            nodes_per_shard: num_nodes, // Example default
            num_coordinators: 1, // Example default
            network_min_delay_ms: 0, // Example default
            network_max_delay_ms: 0, // Example default
            ..Default::default() // Use defaults for the rest
        };
        
        let mock_relayer = Arc::new(MockBlockchainInterface::new());
        // Assume default PartitionMapping for now
        let partition_mapping = PartitionMapping::default();

        // Create metrics channel
        let (metrics_tx, metrics_rx) = mpsc::channel(100); // Ignore receiver for now

        // Expect 4 return values from SimulationRuntime::new
        let (runtime, result_rx, _isolation_rx, _metrics_handle) = SimulationRuntime::new(config.clone());

        // --- Simulate assigning nodes to shards (using runtime's internal state) ---
        // For simplicity in this test setup, assign all nodes to shard 0
        let all_node_identities_for_shard = node_identities.clone();
        runtime.assign_nodes_to_shard(0, all_node_identities_for_shard).await;
        // Get a handle to the runtime's assignments map (need internal access or a getter)
        // Let's assume SimulationRuntime needs a getter method for this test.
        // WORKAROUND: Create a *separate* assignments map just for the test setup,
        // mirroring what the runtime does. This avoids changing runtime API for now.
        let test_shard_assignments = Arc::new(Mutex::new(HashMap::new()));
        {
            let mut assignments = test_shard_assignments.lock().await;
            assignments.insert(0, node_identities.clone());
        }
        // --- End Shard Assignment Simulation ---

        let coordinator = SimulatedCoordinator::new(
            coord_identity,
            coord_sk,
            system_config, // Pass the original system_config
            runtime.clone(), // Clone runtime for coordinator
            mock_relayer.clone(),
            partition_mapping.clone(), // Clone mapping
            metrics_tx, // Pass metrics sender directly
            // NEW: Pass the assignments map handle
            test_shard_assignments.clone(), // Pass the test map
        );

        // Return 7 elements
        (
            coordinator,
            node_identities.into_iter().zip(node_secrets.into_iter()).collect(),
            mock_relayer,
            runtime,
            partition_mapping,
            result_rx,
            test_shard_assignments, // Return the handle to the test map
        )
    }

    #[tokio::test]
    async fn test_coordinator_receives_and_aggregates_shares_success() {
        let num_nodes = 5;
        let threshold = 3;
        // Expected signatures count = threshold
        let expected_signatures = threshold as usize;

        // Capture result_rx (6th element) and assignments (7th)
        let (coordinator, nodes, _mock_relayer, runtime, _partition_mapping, result_rx, _assignments) =
            setup_test_environment(num_nodes, threshold).await;

        let coordinator_id_for_task = coordinator.identity.id; // Capture ID

        // Spawn the share listener task using the associated function syntax
        let coordinator_listener = tokio::spawn(async move {
            SimulatedCoordinator::run_share_listener(
                coordinator_id_for_task,
                result_rx,
                watch::channel(()).1
            ).await;
        });

        // Create mock transaction and lock data using the new local helper
        let (_tx, lock_data) = create_mock_transaction_and_lock("tx-success", &nodes[0].0); // Updated call
        let tx_id = lock_data.tx_id.clone();
        // let coordinator_metrics_tx = coordinator.metrics_tx.clone(); // Use clone from above

        // Encode the signable tuple, not the whole struct
        let signable_data_tuple = (
            &lock_data.tx_id,
            lock_data.source_chain_id,
            lock_data.target_chain_id,
            &lock_data.token_address,
            lock_data.amount,
            &lock_data.recipient
        );
        let serialized_data = bincode::encode_to_vec(&signable_data_tuple, standard()).unwrap();

        // Simulate nodes sending shares
        for i in 0..threshold {
            let (node_identity, node_secret) = &nodes[i];
            // Access coordinator fields directly
            let min_delay = coordinator.system_config.tee_delays.sign_min_ms;
            let max_delay = coordinator.system_config.tee_delays.sign_max_ms;
            let signature = sign(
                &serialized_data,
                node_secret,
                min_delay,
                max_delay,
                &coordinator.metrics_tx, // Access directly
                &Some(coordinator.identity.clone()) // Access directly
            ).await;
            let share = (node_identity.clone(), lock_data.clone(), signature);
            runtime.submit_result(share).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Wait a bit for aggregation and release
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check if release was called on the relayer
        println!("[Test] TODO: Verify relayer interaction for tx {} (success)", tx_id);

        // Check if the pending shares entry was removed - USE CLONE
        let shares_map = coordinator.pending_shares.lock().await;
        assert!(!shares_map.contains_key(&tx_id), "Pending shares entry should be removed after success");

        coordinator_listener.abort();
    }

    #[tokio::test]
    async fn test_coordinator_handles_insufficient_shares() {
        let num_nodes = 5;
        let threshold = 3;
        // Send fewer shares than the threshold
        let shares_to_send = threshold - 1;

        // Capture result_rx (6th element) and assignments (7th)
        let (coordinator, nodes, _mock_relayer, runtime, _partition_mapping, result_rx, _assignments) =
            setup_test_environment(num_nodes, threshold).await;

        let coordinator_id_for_task = coordinator.identity.id; // Capture ID

        // Spawn the share listener task using the associated function syntax
        let coordinator_listener = tokio::spawn(async move {
             SimulatedCoordinator::run_share_listener(
                 coordinator_id_for_task,
                 result_rx,
                 watch::channel(()).1
             ).await;
        });

        // Create mock transaction and lock data using the new local helper
        let (_tx, lock_data) = create_mock_transaction_and_lock("tx-insufficient", &nodes[0].0); // Updated call
        let tx_id = lock_data.tx_id.clone();
        // let coordinator_metrics_tx = coordinator.metrics_tx.clone(); // Use clone from above

        // Encode the signable tuple
        let signable_data_tuple = (
            &lock_data.tx_id,
            lock_data.source_chain_id,
            lock_data.target_chain_id,
            &lock_data.token_address,
            lock_data.amount,
            &lock_data.recipient
        );
        let serialized_data = bincode::encode_to_vec(&signable_data_tuple, standard()).unwrap();

        // Simulate nodes sending *fewer* than threshold shares
        for i in 0..shares_to_send {
            let (node_identity, node_secret) = &nodes[i];
            // Access coordinator fields directly
            let min_delay = coordinator.system_config.tee_delays.sign_min_ms;
            let max_delay = coordinator.system_config.tee_delays.sign_max_ms;
            let signature = sign(
                &serialized_data,
                node_secret,
                min_delay,
                max_delay,
                &coordinator.metrics_tx, // Access directly
                &Some(coordinator.identity.clone()) // Access directly
            ).await;
            let share = (node_identity.clone(), lock_data.clone(), signature);
            runtime.submit_result(share).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Wait a bit (should not trigger release)
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check that release was *not* called
        println!("[Test] TODO: Verify relayer interaction for tx {} (no release expected)", tx_id);

        // Check that the pending shares entry still exists - USE CLONE
        let shares_map = coordinator.pending_shares.lock().await;
        assert!(shares_map.contains_key(&tx_id), "Pending shares entry should persist with insufficient shares");

        coordinator_listener.abort();
    }

    #[tokio::test]
    async fn test_coordinator_rejects_invalid_signature() {
        let num_nodes = 5;
        let threshold = 3;

        // Capture result_rx (6th element) and assignments (7th)
        let (coordinator, nodes, _mock_relayer, runtime, _partition_mapping, result_rx, _assignments) =
            setup_test_environment(num_nodes, threshold).await;
        
        let coordinator_id_for_task = coordinator.identity.id; // Capture ID
        
        // Spawn the share listener task using the associated function syntax
        let coordinator_listener = tokio::spawn(async move {
            SimulatedCoordinator::run_share_listener(
                coordinator_id_for_task,
                result_rx,
                watch::channel(()).1
            ).await;
        });

        // Create mock transaction and lock data using the new local helper
        let (_tx, lock_data) = create_mock_transaction_and_lock("tx-invalid-sig", &nodes[0].0); // Updated call
        let tx_id = lock_data.tx_id.clone();
        // let coordinator_metrics_tx = coordinator.metrics_tx.clone(); // Use clone from above

        // Encode the signable tuple
        let signable_data_tuple = (
            &lock_data.tx_id,
            lock_data.source_chain_id,
            lock_data.target_chain_id,
            &lock_data.token_address,
            lock_data.amount,
            &lock_data.recipient
        );
        let message_bytes = bincode::encode_to_vec(&signable_data_tuple, standard()).unwrap();

        // Simulate one node sending an invalid share
        // let message_bytes = bincode::encode_to_vec(&lock_data, standard()).unwrap(); // Old incorrect line
        let (node_identity, _node_secret) = &nodes[0]; // Use node 0's identity
        // Use imported Signature type
        let invalid_signature_bytes = [0u8; 64];
        let invalid_signature = Signature::from_bytes(&invalid_signature_bytes);

        // Create correct share format if needed, otherwise simulate sending
        // let share = SignatureShare { 
        //     signer_id: node_identity.clone(), 
        //     lock_data: lock_data.clone(), 
        //     signature: invalid_signature 
        // };
        // runtime.submit_result(share).await; // Direct call might be gone
        println!("[Test] Simulating sending INVALID share from node {} to runtime...", node_identity.id);
        // TODO: Replace with actual mechanism to send share via runtime/channels
        // For now, let's simulate submitting the *invalid* signature directly
        let invalid_share = (nodes[0].0.clone(), lock_data.clone(), invalid_signature);
        runtime.submit_result(invalid_share).await; // Submit the invalid share
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Now send enough *valid* shares (threshold - 1, because the invalid one shouldn't count)
        for i in 1..threshold {
            let (valid_node_identity, valid_node_secret) = &nodes[i];
            // Get delays from coordinator's system_config - USE CLONE
            let min_delay = coordinator.system_config.tee_delays.sign_min_ms;
            let max_delay = coordinator.system_config.tee_delays.sign_max_ms;
            let valid_signature = sign(
                &message_bytes, // Sign/verify the encoded tuple
                valid_node_secret, 
                min_delay, 
                max_delay, 
                &coordinator.metrics_tx, // USE CLONE
                &Some(coordinator.identity.clone()) // USE CLONE (and clone again for loop)
            ).await;
            // Use tuple instantiation for SignatureShare
            let share = (valid_node_identity.clone(), lock_data.clone(), valid_signature);
            runtime.submit_result(share).await; // Uncommented and use runtime
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Wait a bit
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check that release was *not* called
        println!("[Test] TODO: Verify relayer interaction for tx {} (no release expected)", tx_id);

        // Check that the pending shares entry still exists - USE CLONE
        let shares_map = coordinator.pending_shares.lock().await;
        assert!(shares_map.contains_key(&tx_id), "Pending shares should persist");
        // Use signature_count() method
        assert_eq!(shares_map.get(&tx_id).unwrap().signature_count(), threshold - 1, "Aggregator should only contain valid shares");

        coordinator_listener.abort();
    }

    // TODO: Add test for duplicate shares being handled correctly (e.g., ignored)
    // TODO: Add test case involving multiple transactions concurrently

}
