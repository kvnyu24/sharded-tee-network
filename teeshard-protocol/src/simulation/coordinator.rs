use crate::{
    config::SystemConfig as RootSystemConfig,
    data_structures::{TEEIdentity, Transaction},
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
use tokio::sync::{mpsc, Mutex}; // Added Mutex
use bincode;
use bincode::config::standard;
use crate::tee_logic::threshold_sig::PartialSignature;
use crate::tee_logic::crypto_sim::verify;
use hex;
 // mpsc was duplicate
 // For test key generation
 // Import SimulationConfig
 // Add missing import for sign
use crate::simulation::metrics::MetricEvent; // Add metrics import
use std::time::Instant; // Add Instant
use std::time::Duration as StdDuration; // Alias Duration to avoid conflict if needed, or just use Duration
 // Use corrected path here too
 // Import EmulatedNetwork
 // Keep SystemConfig
 // Keep Signature import
use crate::tee_logic::crypto_sim::PublicKey;
use crate::simulation::runtime::SignatureShare;

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
    ) -> Self {
        let committee = system_config.coordinator_identities.iter()
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
            committee, // Initialize the committee field
        }
    }

    /// Internal logic to handle an observed lock event.
    /// Called by the command listener.
    async fn process_observed_lock(&self, transaction: &Transaction, lock_details: &LockProofData) {
        let tx_id = transaction.tx_id.clone(); // Use the String tx_id
        println!(
            "[Coordinator {}] Processing observed lock event for tx: {}. Looking up shard...",
            self.identity.id,
            tx_id
        );

        // --- Record Start Time for Metrics ---
        {
            let mut start_times = self.transaction_start_times.lock().await;
            if !start_times.contains_key(&tx_id) {
                start_times.insert(tx_id.clone(), Instant::now());
                println!("[Coordinator {}] Recorded start time for tx: {}", self.identity.id, tx_id);
            } else {
                 println!("[Coordinator {}] Start time already recorded for tx: {}", self.identity.id, tx_id);
            }
        } // Lock dropped here
        // --- End Metrics --- 
        
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
        let mut success = false; // Track success for the metric

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
            // Get delay config from runtime
            .or_insert_with(|| {
                // Correctly clone metrics_tx and node_id for the new aggregator
                let metrics_tx_clone = self.metrics_tx.clone();
                let node_id_clone = Some(self.identity.clone()); // Coordinator's ID for its own aggregator
                let delay_config = self.system_config.tee_delays.clone();
                // Pass all required args, including message (tx_id bytes) and committee
                ThresholdAggregator::new(
                    message_bytes.clone(), // Pass the message bytes
                    self.system_config.coordinator_threshold,
                    self.committee.clone(), // Pass the committee map
                    delay_config,
                    metrics_tx_clone,
                    node_id_clone,
                )
            });

        // Add the share (now async), passing signer_id and the signature data
        let threshold_met_result = aggregator.add_partial_signature(signer_id.clone(), signature).await;

        // Handle potential error from add_partial_signature
        let threshold_met = match threshold_met_result {
            Ok(met) => met,
            Err(e) => {
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
        };

        println!(
            "[Coordinator {}] Stored share for tx {}. Total shares received: {}/{}",
            self.identity.id,
            tx_id,
            aggregator.signature_count(), // Use public method
            aggregator.get_threshold() // Use public method
        );

        // Check if threshold is met (using the boolean returned by add_partial_signature)
        // Need to store the finalized sig outside the mutex scope if threshold is met
        let finalized_sig_opt = if threshold_met {
            println!(
                "[Coordinator {}] Threshold reached for tx {}. Retrieving combined signature...",
                self.identity.id,
                tx_id
            );
            // Get the combined signature if available
            aggregator.get_combined_signature().cloned() // Clone the Option<&Signature>
        } else {
            None
        };

        // --- End access to pending_shares ---
        // Drop the lock explicitly AFTER we're done needing the aggregator state for this share
        drop(shares_map);

        // If threshold was met and we got a signature, proceed to submit release
        if let Some(multi_sig) = finalized_sig_opt { // Use the signature stored outside the lock
            println!(
                "[Coordinator {}] Multi-signature retrieved for tx {}. Submitting release...",
                self.identity.id,
                tx_id // Log hex tx_id
            );

            // The aggregated signature is now just a single Signature
            let aggregated_sig_bytes = multi_sig.to_bytes().to_vec();

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
                    // --- Call Relayer --- 
                     match self.relayer.submit_release(
                        lock_data.target_chain_id,
                        swap_id, // Use the decoded [u8; 32] swap_id
                        lock_data.token_address.clone(),
                        lock_data.amount.into(),
                        lock_data.recipient.clone(),
                        aggregated_sig_bytes,
                    ).await {
                        Ok(onchain_tx_hash) => {
                            success = true; // Mark as successful
                            println!(
                                "[Coordinator {}] Relayer submitted release for swap_id 0x{}. On-chain Tx: {}",
                                self.identity.id,
                                hex::encode(swap_id), // Log bytes32 swap_id
                                onchain_tx_hash
                            );
                            // Remove processed swap from pending shares map AFTER sending metric
                        }
                        Err(e) => {
                            success = false; // Mark as failed
                            eprintln!(
                                "[Coordinator {}] Relayer failed to submit release for swap_id 0x{}: {}",
                                self.identity.id,
                                hex::encode(swap_id), // Log bytes32 swap_id
                                e
                            );
                            // TODO: Potentially trigger ABORT logic here instead of just failing?
                        }
                    }
                }
                Err(e) => {
                    success = false; // Mark as failed
                    eprintln!(
                        "[Coordinator {}] Error preparing swap_id from tx_id '{}' for release: {}",
                        self.identity.id,
                        tx_id, // Log hex tx_id
                        e
                    );
                }
            }

            // --- Send Metric --- 
            let end_time = Instant::now();
            let start_time = {
                let mut start_times = self.transaction_start_times.lock().await;
                start_times.remove(&tx_id) 
            };
            
            if let Some(start) = start_time {
                 let duration = end_time.duration_since(start);
                 // Clone tx_id specifically for the metric event
                 let metric_tx_id = tx_id.clone(); 
                 // Clone AGAIN for the error logging inside the closure
                 let error_log_tx_id = metric_tx_id.clone(); 
                 let event = MetricEvent::TransactionCompleted {
                    id: metric_tx_id, // Use the first clone for the event
                    start_time: start,
                    end_time,
                    duration,
                    is_cross_chain: true, 
                    success, 
                 };
                 let metrics_tx_clone = self.metrics_tx.clone();
                 let coord_id_clone = self.identity.clone();
                 tokio::spawn(async move { // `event` (containing metric_tx_id) is moved here
                     if let Some(tx) = metrics_tx_clone {
                         if let Err(e) = tx.send(event).await {
                             eprintln!("[Coordinator {}] Failed to send TransactionCompleted metric for tx {}: {}", 
                                      coord_id_clone.id, error_log_tx_id, e); 
                         }
                     } else {
                          eprintln!("[Coordinator {}] Metrics sender was None, cannot send TransactionCompleted metric for tx {}", 
                                    coord_id_clone.id, error_log_tx_id);
                     }
                 });
            } else {
                 eprintln!("[Coordinator {}] Error: Could not find start time for tx {} to send metric.", self.identity.id, tx_id);
            }
            // --- End Metric --- 

            // Remove from pending shares *after* sending metric, using the original tx_id
            if success { // Only remove if successfully submitted
                 let mut shares_map_for_removal = self.pending_shares.lock().await;
                 // Use the original tx_id here, which is still valid in this scope
                 shares_map_for_removal.remove(&tx_id); 
                 drop(shares_map_for_removal);
            }

        } 
        // Else: finalized_sig_opt was None (shouldn't happen if threshold_met was true)
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
     // Use corrected path here too
    use crate::tee_logic::crypto_sim::sign; // Add missing import for sign
    use std::time::Duration;
     // Keep alias for clarity
    
    use crate::simulation::config::SimulationConfig; // Import SimulationConfig
    use crate::tee_logic::crypto_sim::generate_keypair;
     // Import EmulatedNetwork
     // Keep SystemConfig
    use crate::tee_logic::types::Signature; // Keep Signature import
    
    use crate::simulation::runtime::SignatureShare;
    
    use crate::data_structures::{AccountId, Transaction};
    use crate::data_structures::{TxType, AssetId, LockInfo};

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
            tx_id: tx_id_string, // Use the hex string ID
            source_chain_id: 1, // Mock chain ID (matches Transaction)
            target_chain_id: 2, // Mock chain ID (matches Transaction)
            recipient: mock_recipient_account.address.clone(), // Use recipient address from Transaction account
            token_address: mock_source_asset.token_address.clone(), // Use token address from source asset
            amount: 1000, // Use u64 amount (matches Transaction amount)
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

        let coordinator = SimulatedCoordinator::new(
            coord_identity,
            coord_sk,
            system_config, // Pass the original system_config
            runtime.clone(), // Clone runtime for coordinator
            mock_relayer.clone(),
            partition_mapping.clone(), // Clone mapping
            metrics_tx, // Pass metrics sender directly
        );

        // Return 6 elements
        (coordinator, node_identities.into_iter().zip(node_secrets.into_iter()).collect(), mock_relayer, runtime, partition_mapping, result_rx)
    }

    #[tokio::test]
    async fn test_coordinator_receives_and_aggregates_shares_success() {
        let num_nodes = 5;
        let threshold = 3;
        // Expected signatures count = threshold
        let expected_signatures = threshold as usize;

        // Capture result_rx (6th element)
        let (coordinator, nodes, mock_relayer, runtime, _partition_mapping, result_rx) =
            setup_test_environment(num_nodes, threshold).await;

        // Clone needed coordinator fields BEFORE moving coordinator into the listener
        let pending_shares_clone = coordinator.pending_shares.clone();
        let coordinator_identity_clone = coordinator.identity.clone();
        let tee_delays_clone = coordinator.system_config.tee_delays.clone();
        let metrics_tx_clone_for_sign = coordinator.metrics_tx.clone();

        // Spawn the share listener task
        let coordinator_listener = tokio::spawn(async move {
            coordinator.run_share_listener(result_rx).await;
        });

        // Create mock transaction and lock data using the new local helper
        let (_tx, lock_data) = create_mock_transaction_and_lock("tx-success", &nodes[0].0); // Updated call
        let tx_id = lock_data.tx_id.clone();
        // let coordinator_metrics_tx = coordinator.metrics_tx.clone(); // Use clone from above

        let serialized_lock_data = bincode::encode_to_vec(&lock_data, standard()).unwrap();

        // Simulate nodes sending shares
        for i in 0..threshold {
            let (node_identity, node_secret) = &nodes[i];
            // Access tee_delays from coordinator's stored system_config - USE CLONE
            let min_delay = tee_delays_clone.sign_min_ms;
            let max_delay = tee_delays_clone.sign_max_ms;
            let signature = sign(
                &serialized_lock_data, 
                node_secret, 
                min_delay, 
                max_delay, 
                &metrics_tx_clone_for_sign, // USE CLONE
                &Some(coordinator_identity_clone.clone()) // USE CLONE (and clone again for loop)
            ).await;
            // Use tuple instantiation for SignatureShare
            let share = (node_identity.clone(), lock_data.clone(), signature);
            runtime.submit_result(share).await; // Uncommented and use runtime
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Wait a bit for aggregation and release
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check if release was called on the relayer
        println!("[Test] TODO: Verify relayer interaction for tx {} (success)", tx_id);

        // Check if the pending shares entry was removed - USE CLONE
        let shares_map = pending_shares_clone.lock().await;
        assert!(!shares_map.contains_key(&tx_id), "Pending shares entry should be removed after success");

        // Shutdown listener
        coordinator_listener.abort();
    }

    #[tokio::test]
    async fn test_coordinator_handles_insufficient_shares() {
        let num_nodes = 5;
        let threshold = 3;
        // Send fewer shares than the threshold
        let shares_to_send = threshold - 1;

        // Capture result_rx (6th element)
        let (coordinator, nodes, mock_relayer, runtime, _partition_mapping, result_rx) =
            setup_test_environment(num_nodes, threshold).await;

        // Clone needed coordinator fields BEFORE moving coordinator into the listener
        let pending_shares_clone = coordinator.pending_shares.clone();
        let coordinator_identity_clone = coordinator.identity.clone();
        let tee_delays_clone = coordinator.system_config.tee_delays.clone();
        let metrics_tx_clone_for_sign = coordinator.metrics_tx.clone();

        // Spawn the share listener task
        let coordinator_listener = tokio::spawn(async move {
            coordinator.run_share_listener(result_rx).await;
        });

        // Create mock transaction and lock data using the new local helper
        let (_tx, lock_data) = create_mock_transaction_and_lock("tx-insufficient", &nodes[0].0); // Updated call
        let tx_id = lock_data.tx_id.clone();
        // let coordinator_metrics_tx = coordinator.metrics_tx.clone(); // Use clone from above

        let serialized_lock_data = bincode::encode_to_vec(&lock_data, standard()).unwrap();

        // Simulate nodes sending *fewer* than threshold shares
        for i in 0..shares_to_send {
            let (node_identity, node_secret) = &nodes[i];
            // USE CLONE
            let min_delay = tee_delays_clone.sign_min_ms;
            let max_delay = tee_delays_clone.sign_max_ms;
            let signature = sign(
                &serialized_lock_data, 
                node_secret, 
                min_delay, 
                max_delay, 
                &metrics_tx_clone_for_sign, // USE CLONE
                &Some(coordinator_identity_clone.clone()) // USE CLONE (and clone again for loop)
            ).await;
            // Use tuple instantiation for SignatureShare
            let share = (node_identity.clone(), lock_data.clone(), signature);
            runtime.submit_result(share).await; // Uncommented and use runtime
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Wait a bit (should not trigger release)
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check that release was *not* called
        println!("[Test] TODO: Verify relayer interaction for tx {} (no release expected)", tx_id);

        // Check that the pending shares entry still exists - USE CLONE
        let shares_map = pending_shares_clone.lock().await;
        assert!(shares_map.contains_key(&tx_id), "Pending shares entry should persist with insufficient shares");

        // Shutdown listener
        coordinator_listener.abort();
    }

    #[tokio::test]
    async fn test_coordinator_rejects_invalid_signature() {
        let num_nodes = 5;
        let threshold = 3;

        // Capture result_rx (6th element)
        let (coordinator, nodes, mock_relayer, runtime, _partition_mapping, result_rx) =
            setup_test_environment(num_nodes, threshold).await;
        
        // Clone needed coordinator fields BEFORE moving coordinator into the listener
        let pending_shares_clone = coordinator.pending_shares.clone();
        let coordinator_identity_clone = coordinator.identity.clone();
        let tee_delays_clone = coordinator.system_config.tee_delays.clone();
        let metrics_tx_clone_for_sign = coordinator.metrics_tx.clone();

        // Spawn the share listener task
        let coordinator_listener = tokio::spawn(async move {
            coordinator.run_share_listener(result_rx).await;
        });

        // Create mock transaction and lock data using the new local helper
        let (_tx, lock_data) = create_mock_transaction_and_lock("tx-invalid-sig", &nodes[0].0); // Updated call
        let tx_id = lock_data.tx_id.clone();
        // let coordinator_metrics_tx = coordinator.metrics_tx.clone(); // Use clone from above

        let serialized_lock_data = bincode::encode_to_vec(&lock_data, standard()).unwrap();

        // Simulate one node sending an invalid share
        let message_bytes = bincode::encode_to_vec(&lock_data, standard()).unwrap();
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
            let min_delay = tee_delays_clone.sign_min_ms;
            let max_delay = tee_delays_clone.sign_max_ms;
            let valid_signature = sign(
                &message_bytes, 
                valid_node_secret, 
                min_delay, 
                max_delay, 
                &metrics_tx_clone_for_sign, // USE CLONE
                &Some(coordinator_identity_clone.clone()) // USE CLONE (and clone again for loop)
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
        let shares_map = pending_shares_clone.lock().await;
        assert!(shares_map.contains_key(&tx_id), "Pending shares should persist");
        // Use signature_count() method
        assert_eq!(shares_map.get(&tx_id).unwrap().signature_count(), threshold - 1, "Aggregator should only contain valid shares");

        // Shutdown the listener task to avoid resource leaks (optional but good practice)
        coordinator_listener.abort();
    }

    // TODO: Add test for duplicate shares being handled correctly (e.g., ignored)
    // TODO: Add test case involving multiple transactions concurrently

}
