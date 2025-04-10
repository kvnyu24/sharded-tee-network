// Placeholder for Cross-Chain Swap Coordinator logic (Algorithm 2)

use crate::data_structures::{TEEIdentity, Transaction, AccountId, AssetId};
use crate::config::SystemConfig;
use crate::network::{NetworkInterface, NetworkMessage, Message};
use crate::onchain::interface::{BlockchainInterface, SignatureBytes, TransactionId, BlockchainError, SwapId};
use crate::onchain::evm_relayer::EvmRelayerError;
use crate::tee_logic::threshold_sig::{ThresholdAggregator, PartialSignature};
use crate::cross_chain::types::{LockProof, AbortReason, SignedCoordinatorDecision, LockRequest}; // Keep other types
use crate::tee_logic::crypto_sim::SecretKey;
use ed25519_dalek::Signer;
use ed25519_dalek::VerifyingKey as PublicKey;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use ethers::types::U256;
use hex;
use tokio;
use crate::tee_logic::lock_proofs; // Import the module
use crate::raft::state::{Command, RaftRole};
use crate::tee_logic::types::Signature;
use crate::data_structures::LockInfo;

// Constants
const DEFAULT_SWAP_TIMEOUT_SECS: u64 = 3600; // 1 hour

// Represents the state of a coordinator TEE managing a swap
#[derive(Clone)]
pub struct CrossChainCoordinator {
    pub identity: TEEIdentity,
    pub signing_key: SecretKey, // Coordinator needs its own key to sign placeholder decisions
    pub config: SystemConfig, // Access to system-wide parameters
    pub committee: Vec<TEEIdentity>, // The set of coordinators
    // Track ongoing swaps and their state
    pub active_swaps: HashMap<String, SwapState>,
    // Network interface for sending messages
    network: Arc<dyn NetworkInterface + Send + Sync>,
    // Blockchain interface for submitting final txs (release/abort)
    blockchain_interface: Arc<dyn BlockchainInterface + Send + Sync>,
    // Mapping from shard ID to the TEEs managing it
    shard_tee_assignments: HashMap<usize, Vec<TEEIdentity>>,
    // Add Liveness Aggregator if needed for verification
    // pub liveness_aggregator: crate::liveness::aggregator::Aggregator,
}

// Status of an ongoing swap
#[derive(Debug, Clone, PartialEq)]
pub enum SwapStatus {
    Active,
    Aborted(AbortReason),
}

// State tracked per active cross-chain swap
#[derive(Debug, Clone)] // Added derive for tests potentially cloning state
pub struct SwapState {
    pub transaction: Transaction, // The original swap transaction
    pub relevant_shards: HashSet<usize>, // Shards involved in this swap
    pub received_proofs: HashMap<usize, LockProof>, // shard_id -> LockProof
    pub initiation_time: std::time::Instant, // Time the swap was initiated
    pub status: SwapStatus, // Current status of the swap
    // Aggregators for coordinator threshold signatures (multi-sig simulation)
    // One for RELEASE decision, one for ABORT decision.
    // Created lazily when a coordinator first signs one way or the other.
    pub release_aggregator: Option<ThresholdAggregator>,
    pub abort_aggregator: Option<ThresholdAggregator>,
    // Timer info, coordinator set, etc.
}

impl CrossChainCoordinator {
     // Updated constructor to include signing key, network interface, and shard assignments
     pub fn new(
         identity: TEEIdentity,
         signing_key: SecretKey,
         config: SystemConfig,
         committee: Vec<TEEIdentity>, // Add committee parameter
         network: Arc<dyn NetworkInterface + Send + Sync>,
         blockchain_interface: Arc<dyn BlockchainInterface + Send + Sync>,
         shard_tee_assignments: HashMap<usize, Vec<TEEIdentity>>, // Add assignments map
     ) -> Self {
         CrossChainCoordinator {
             identity,
             signing_key,
             config,
             committee, // Store the committee
             active_swaps: HashMap::new(),
             network,
             blockchain_interface,
             shard_tee_assignments, // Store the map
         }
     }

    // Placeholder: Initiate a new swap coordination process
    pub fn initiate_swap(&mut self, tx: Transaction, relevant_shards: HashSet<usize>) {
        let tx_id = tx.tx_id.clone();
        println!("Coordinator ({}): Initiating swap {}", self.identity.id, tx_id);
        // Ensure relevant_shards is not empty if tx needs locks
        if !tx.required_locks.is_empty() && relevant_shards.is_empty() {
             println!("Coordinator Warning: Initiating swap {} with locks but no relevant shards provided.", tx_id);
             // Depending on policy, might return error or proceed assuming no locks needed
        }

        // Clone values needed later *before* moving tx and relevant_shards
        let tx_id_clone = tx_id.clone();
        let relevant_shards_clone = relevant_shards.clone();

        let state = SwapState {
            transaction: tx, // tx is moved here
            relevant_shards, // relevant_shards is moved here
            received_proofs: HashMap::new(),
            initiation_time: std::time::Instant::now(), // Record initiation time
            status: SwapStatus::Active, // Set initial status
            // Initialize aggregators as None
            release_aggregator: None,
            abort_aggregator: None,
        };
        self.active_swaps.insert(tx_id_clone.clone(), state); // Clone tx_id_clone again for insertion

        // Timer starting and coordinator selection are implicitly handled or TBD elsewhere.
        // Timeout checking is done via the `check_timeouts` method.
        // Sending LOCK_REQUEST is handled below.

        // 2. Broadcast LOCK_REQUEST to involved shards (placeholder)
        // The following print statements simulate sending network messages.
        // TODO: Replace with actual network layer calls to send LockRequest messages.
        println!(
            "Coordinator [{}]: Broadcasting LOCK_REQUEST for swap {} to shards: {:?}",
            self.identity.id,
            tx_id_clone, // Use the clone
            relevant_shards_clone // Use the clone
        );
        for shard_id in &relevant_shards_clone { // Iterate over the clone
            // Find the LockInfo relevant for this shard (assuming one lock per shard for now)
            // A more robust implementation would handle multiple locks targeting the same shard.
            // Convert shard_id (usize) to u64 for comparison with chain_id (u64)
            // Access required_locks via the state stored in self.active_swaps
            if let Some(state_ref) = self.active_swaps.get(&tx_id_clone) {
                if let Some(lock_info) = state_ref.transaction.required_locks.iter().find(|li| li.account.chain_id == (*shard_id as u64)) {
                    let request = LockRequest {
                        tx_id: tx_id_clone.clone(),
                        lock_info: lock_info.clone(),
                    };

                    // Get target TEE identities for the shard
                    let target_tees = self.get_tee_identities_for_shard(*shard_id);
                    println!("  -> Sending LockRequest to shard {} TEEs ({:?}): {:?}",
                             shard_id, target_tees.iter().map(|t| t.id).collect::<Vec<_>>(), request);

                    // Send message to each TEE in the target shard
                    for target_tee in target_tees {
                        let network_msg = NetworkMessage {
                            sender: self.identity.clone(),
                            receiver: target_tee, // Send to specific TEE
                            message: Message::ShardLockRequest(request.clone()),
                        };
                        self.network.send_message(network_msg);
                    }
                } else {
                    // This case suggests an inconsistency in the request (shard listed but no lock)
                    eprintln!(
                        "Warning: Shard {} listed in involved_shards but no corresponding lock found for swap {}",
                        shard_id, tx_id_clone // Use the clone
                    );
                }
            } else {
                // This should ideally not happen as we just inserted it
                eprintln!("Error: Could not find newly inserted swap state for {}", tx_id_clone);
            }
        }

        // Timeout setting is implicitly handled by recording `initiation_time`
        // and checking against `transaction.timeout` in `check_timeouts`.
    }

    // Handles incoming lock proofs, stores them, and triggers finalization if ready.
    // Returns Ok(true) if ready to finalize, Ok(false) if waiting, Err on verification failure.
    // Make async due to verify_lock_proof call
    pub async fn handle_lock_proof(&mut self, proof: LockProof) -> Result<bool, AbortReason> {
        let tx_id = proof.tx_id.clone();
        println!("Coordinator ({}): Received lock proof for swap {} from shard {}",
                 self.identity.id, tx_id, proof.shard_id);

        let swap = self.active_swaps.get_mut(&tx_id)
            .ok_or_else(|| {
                println!("Coordinator Error: Swap {} not found when handling proof from shard {}", tx_id, proof.shard_id);
                AbortReason::Other("Swap not found".to_string())
            })?;

        // Get verify delays from config
        let verify_min_ms = self.config.tee_delays.verify_min_ms;
        let verify_max_ms = self.config.tee_delays.verify_max_ms;

        // Verify the proof using the signer's public key (now async)
        if !lock_proofs::verify_lock_proof(&proof, &proof.signer_identity.public_key, verify_min_ms, verify_max_ms).await {
            println!("Coordinator ({}): Lock proof verification failed for swap {} from signer {}",
                     self.identity.id, tx_id, proof.signer_identity.id);
            swap.status = SwapStatus::Aborted(AbortReason::LockProofVerificationFailed);
            return Err(AbortReason::LockProofVerificationFailed);
        }

        // Store the verified proof if it's from a relevant shard
        if swap.relevant_shards.contains(&proof.shard_id) {
             let _ = swap.received_proofs.insert(proof.shard_id, proof.clone()); // Use proof.clone() if needed later, or just insert proof
             // Corrected println! - added proof.shard_id as the 3rd argument
             println!("Coordinator ({}): Stored valid proof for swap {} from shard {}. ({}/{}) proofs received.",
                      self.identity.id, tx_id, proof.shard_id, swap.received_proofs.len(), swap.relevant_shards.len());
         } else {
             println!("Coordinator Warning: Received proof for swap {} from irrelevant shard {}. Ignoring.",
                      tx_id, proof.shard_id);
             // Don't count it towards completion, but don't error.
             return Ok(false); // Not ready yet
         }


        // Check if all proofs are received
        if self.evaluate_all_locks(&tx_id) {
             println!("Coordinator ({}): All lock proofs received for swap {}.", self.identity.id, tx_id);
             // Ready to finalize, but don't remove swap state yet. Let caller handle finalization.
             Ok(true)
        } else {
            // Still waiting for more proofs
            Ok(false)
        }
    }

    /// Checks if all required lock proofs have been received and verified for a given transaction.
    pub fn evaluate_all_locks(&self, tx_id: &str) -> bool {
        if let Some(swap) = self.active_swaps.get(tx_id) {
            let received_count = swap.received_proofs.len();
            let required_count = swap.relevant_shards.len();
             println!("Coordinator ({}): Evaluating locks for swap {}. Received: {}, Required: {}",
                      self.identity.id, tx_id, received_count, required_count);
            // Check if required count is > 0 before comparing? Only if swap needs locks.
            // If relevant_shards is empty, maybe it should evaluate true? Assume for now > 0 check needed.
            required_count > 0 && received_count == required_count
        } else {
            println!("Coordinator Warning: evaluate_all_locks called for unknown swap {}", tx_id);
            false // Swap doesn't exist
        }
    }

    // Helper function to get the coordinator signature threshold from config
    fn get_coordinator_threshold(&self) -> usize {
        // Read the threshold from the system configuration
        self.config.coordinator_threshold
    }

    /// Adds the local coordinator's signature share for a RELEASE or ABORT decision.
    /// Ensures the appropriate aggregator exists and adds the partial signature.
    /// Returns Ok if added, Err if the swap doesn't exist or signing fails.
    // Make async due to add_partial_signature call
    async fn add_local_signature_share(&mut self, tx_id: &str, commit: bool) -> Result<(), String> {
        let message_bytes = Self::prepare_decision_message(tx_id, commit);
        let threshold = self.get_coordinator_threshold();
        // Clone the TeeDelayConfig from SystemConfig and wrap in Arc
        let delay_config_arc = Arc::new(self.config.tee_delays.clone());

        // Get the correct aggregator (release or abort) based on the 'commit' flag
        let aggregator_option = if commit {
            self.active_swaps.get_mut(tx_id).map(|swap| &mut swap.release_aggregator)
        } else {
            self.active_swaps.get_mut(tx_id).map(|swap| &mut swap.abort_aggregator)
        };

        let aggregator_option = match aggregator_option {
            Some(agg) => agg,
            None => return Err(format!("Swap {} not found for adding signature.", tx_id)),
        };

        // If the aggregator hasn't been created yet for this decision, create it.
        if aggregator_option.is_none() {
            println!("Coordinator ({}): Creating {} aggregator for swap {}",
                     self.identity.id, if commit {"RELEASE"} else {"ABORT"}, tx_id);
            // Gather all necessary arguments for ThresholdAggregator::new
            let committee_map: HashMap<TEEIdentity, PublicKey> = self.committee.iter()
                .map(|id| (id.clone(), id.public_key.clone()))
                .collect();
            let delay_config = (*delay_config_arc).clone(); // Clone the inner config
            let node_id = Some(self.identity.clone());

            // Pass the cloned delay config Arc when creating
            *aggregator_option = Some(ThresholdAggregator::new(
                message_bytes.clone(), // Message needs to be passed
                threshold,
                committee_map, // Use the created HashMap
                delay_config, // Pass the cloned config, not the Arc
                None, // Pass None for metrics_tx for now
                node_id,
            ));
        }

        // Re-borrow mutably AFTER the potential assignment above.
        let aggregator = aggregator_option.as_mut().unwrap(); // Safe to unwrap

        // Create and add the partial signature
        // Signing the decision message itself doesn't use TEE delays currently
        let local_signature = self.signing_key.sign(&message_bytes);
        let partial_sig = PartialSignature {
            signer_id: self.identity.clone(),
            signature_data: local_signature,
        };

        // Add the verified share to the aggregator (now async)
        match aggregator.add_partial_signature(partial_sig.signer_id.clone(), partial_sig.signature_data.clone()).await {
            Ok(_) => {
                println!("Coordinator ({}): Added local {} signature share for swap {}. Total shares: {}",
                         self.identity.id, if commit {"RELEASE"} else {"ABORT"}, tx_id, aggregator.signature_count());

                // Broadcast the partial signature to peers
                let peer_coordinators = self.get_peer_coordinator_identities();
                println!("Coordinator ({}): Broadcasting partial {} sig for {} to peers: {:?}",
                         self.identity.id, if commit {"RELEASE"} else {"ABORT"}, tx_id,
                         peer_coordinators.iter().map(|p| p.id).collect::<Vec<_>>());

                for peer in peer_coordinators {
                    let network_msg = NetworkMessage {
                        sender: self.identity.clone(),
                        receiver: peer,
                        message: Message::CoordPartialSig {
                            tx_id: tx_id.to_string(),
                            commit,
                            signature: partial_sig.clone(), // Clone again for each message
                        },
                    };
                    self.network.send_message(network_msg);
                }

                Ok(())
            },
            Err(e) => {
                eprintln!("Coordinator ({}): Failed to add local {} signature share for swap {}: {}",
                          self.identity.id, if commit {"RELEASE"} else {"ABORT"}, tx_id, e);
                Err(format!("Failed to add local signature share: {}", e))
            }
        }
    }

    /// Placeholder function to handle receiving a partial signature from another coordinator.
    // Make async due to add_partial_signature call
    async fn handle_partial_signature(&mut self, partial_sig: PartialSignature, tx_id: &str, commit: bool) -> Result<(), String> {
        let swap = self.active_swaps.get_mut(tx_id)
            .ok_or_else(|| format!("Swap {} not found for receiving partial signature", tx_id))?;

        let aggregator_option = if commit {
            &mut swap.release_aggregator
        } else {
            &mut swap.abort_aggregator
        };

        if let Some(aggregator) = aggregator_option {
            let message_bytes = Self::prepare_decision_message(tx_id, commit);
            
            // Call async version and await
            match aggregator.add_partial_signature(partial_sig.signer_id.clone(), partial_sig.signature_data.clone()).await {
                Ok(_) => {
                     println!("Coordinator ({}): Added remote {} signature share for swap {}. Total shares: {}",
                              self.identity.id, if commit {"RELEASE"} else {"ABORT"}, tx_id, aggregator.signature_count());
                     Ok(())
                },
                Err(e) => {
                     eprintln!("Coordinator ({}): Failed to add remote {} signature share for swap {}: {}",
                               self.identity.id, if commit {"RELEASE"} else {"ABORT"}, tx_id, e);
                     Err(format!("Failed to add remote signature share: {}", e))
                }
            }
        } else {
             eprintln!("Coordinator ({}): Received partial {} signature for swap {} but no corresponding aggregator exists yet.",
                       self.identity.id, if commit {"RELEASE"} else {"ABORT"}, tx_id);
             Err("Aggregator not initialized".to_string())
        }
    }

    /// Attempts to finalize the decision by collecting enough signature shares.
    /// Returns the signed decision if the threshold is met.
    fn finalize_decision(&self, tx_id: &str, commit: bool) -> Option<SignedCoordinatorDecision> {
         let swap = self.active_swaps.get(tx_id)?; // Return None if swap doesn't exist

         let aggregator_option = if commit {
             &swap.release_aggregator
         } else {
             &swap.abort_aggregator
         };

         if let Some(aggregator) = aggregator_option {
              println!("Coordinator ({}): Attempting to finalize {} for swap {}. Threshold: {}, Have: {}",
                       self.identity.id, if commit {"RELEASE"} else {"ABORT"}, tx_id,
                       aggregator.get_threshold(), aggregator.signature_count());

             // Try to finalize using the multi-sig logic
             if let Some(combined_sig) = aggregator.get_combined_signature() {
                 println!("Coordinator ({}): Finalized {} decision for swap {} with {} signatures.",
                          self.identity.id, if commit {"RELEASE"} else {"ABORT"}, tx_id, aggregator.signature_count());
                 Some(SignedCoordinatorDecision {
                     tx_id: tx_id.to_string(),
                     commit,
                     signature: combined_sig.clone(),
                 })
             } else {
                  println!("Coordinator ({}): Threshold not yet met for {} decision on swap {}.",
                           self.identity.id, if commit {"RELEASE"} else {"ABORT"}, tx_id);
                 None // Threshold not met
             }
         } else {
              println!("Coordinator ({}): Cannot finalize {} decision for swap {}, aggregator not initialized.",
                       self.identity.id, if commit {"RELEASE"} else {"ABORT"}, tx_id);
             None // Aggregator doesn't exist
         }
    }

    // Helper to prepare the canonical byte representation of the decision message for signing
    fn prepare_decision_message(tx_id: &str, commit: bool) -> Vec<u8> {
        let mut message_bytes = Vec::new();
        message_bytes.extend_from_slice(if commit { b"RELEASE" } else { b"ABORT" });
        message_bytes.extend_from_slice(tx_id.as_bytes());
        message_bytes
    }

    // Optional: A combined function to handle proof and finalize if ready
    // This function now needs to call async add_local_signature_share
    pub async fn process_proof_and_finalize(&mut self, proof: LockProof) -> Result<Option<SignedCoordinatorDecision>, AbortReason> {
        let tx_id_str = proof.tx_id.clone(); // Clone tx_id for use throughout
        
        // --- Lock Proof Handling Logic (extracted from handle_lock_proof) --- 
        println!("Coordinator ({}): Received lock proof for swap {} from shard {}",
                 self.identity.id, tx_id_str, proof.shard_id);
        
        let swap = self.active_swaps.get_mut(&tx_id_str)
            .ok_or_else(|| {
                println!("Coordinator Error: Swap {} not found when handling proof from shard {}", tx_id_str, proof.shard_id);
                AbortReason::Other("Swap not found".to_string())
            })?;

        // Get verify delays from config
        let verify_min_ms = self.config.tee_delays.verify_min_ms;
        let verify_max_ms = self.config.tee_delays.verify_max_ms;

        // Verify the proof (now async)
        // TODO: Add verification delay here? YES - now implemented.
        if !lock_proofs::verify_lock_proof(&proof, &proof.signer_identity.public_key, verify_min_ms, verify_max_ms).await {
            println!("Coordinator ({}): Lock proof verification failed for swap {} from signer {}",
                     self.identity.id, tx_id_str, proof.signer_identity.id);
            swap.status = SwapStatus::Aborted(AbortReason::LockProofVerificationFailed);
            return Err(AbortReason::LockProofVerificationFailed);
        }

        if swap.relevant_shards.contains(&proof.shard_id) {
            let _ = swap.received_proofs.insert(proof.shard_id, proof.clone()); 
            println!("Coordinator ({}): Stored valid proof for swap {} from shard {}. ({}/{}) proofs received.",
                     self.identity.id, tx_id_str, proof.shard_id, swap.received_proofs.len(), swap.relevant_shards.len());
        } else {
            println!("Coordinator Warning: Received proof for swap {} from irrelevant shard {}. Ignoring.", tx_id_str, proof.shard_id);
            return Ok(None); // Not ready yet
        }
        // --- End Lock Proof Handling Logic --- 

        // Check if all proofs are received
        if self.evaluate_all_locks(&tx_id_str) {
            println!("Coordinator ({}): All lock proofs received for swap {}. Attempting to finalize COMMIT.", self.identity.id, tx_id_str);
            
            let commit = true;
            // Attempt to add local signature share (now async)
            if let Err(e) = self.add_local_signature_share(&tx_id_str, commit).await { // Added .await
                eprintln!("Coordinator ({}): Failed to add local signature share during finalization for {}: {}. Aborting potentially?",
                         self.identity.id, tx_id_str, e);
                // Decide policy: Abort or just log? Returning Ok(None) for now, assuming broadcast might still succeed.
                return Ok(None);
            }

            // Check if threshold is met *after* adding local share
            // finalize_decision remains synchronous as it just checks state
            if let Some(signed_decision) = self.finalize_decision(&tx_id_str, commit) {
                println!("Coordinator ({}): COMMIT decision threshold met for swap {}. Submitting to blockchain...", self.identity.id, tx_id_str);
                // Call submit_decision_to_blockchain with the SignedCoordinatorDecision object
                match self.submit_decision_to_blockchain(signed_decision.clone()).await { 
                    Ok(blockchain_tx_id) => {
                        println!("Coordinator ({}): Blockchain submission successful for swap {}: {}",
                                 self.identity.id, tx_id_str, blockchain_tx_id);
                        // Clean up the swap state upon successful submission
                        self.active_swaps.remove(&tx_id_str);
                        // Return the signed decision object
                        return Ok(Some(signed_decision));
                    }
                    Err(e) => {
                        eprintln!("Coordinator ({}): Blockchain submission FAILED for swap {}: {:?}. Swap remains active locally.",
                                 self.identity.id, tx_id_str, e);
                        // TODO: Should we attempt to abort here? Or rely on timeout?
                        // Swap state is NOT removed on blockchain failure.
                        // Returning Ok(None) as the decision was reached but not submitted.
                        return Ok(None); 
                    }
                }
            } else {
                println!("Coordinator ({}): COMMIT threshold not met yet for swap {} after adding local share.", self.identity.id, tx_id_str);
                // Threshold not met, wait for more partial signatures from peers
                Ok(None)
            }
        } else {
            // Still waiting for more proofs
            Ok(None)
        }
    }

    /// Checks for timed-out swaps, marks them as Aborted, adds local ABORT share,
    /// potentially finalizes, and returns a list of signed decisions if finalized.
    // Make async because it calls add_local_signature_share
    pub async fn check_timeouts(&mut self) -> Vec<SignedCoordinatorDecision> {
        let now = std::time::Instant::now();
        let mut decisions = Vec::new();
        // let timeout_duration = self.config.swap_timeout; // Field doesn't exist
        let mut timed_out_swaps = Vec::new();

        // Identify timed-out swaps using transaction's timeout
        for (tx_id, state) in &self.active_swaps {
            // Use state.transaction.timeout
            if state.status == SwapStatus::Active && now.duration_since(state.initiation_time) > state.transaction.timeout {
                println!("Coordinator ({}): Swap {} timed out.", self.identity.id, tx_id);
                timed_out_swaps.push(tx_id.clone());
            }
        }

        // Process timed-out swaps
        for tx_id in timed_out_swaps {
            // Ensure swap still exists and is Active (in case of race conditions)
            if let Some(state) = self.active_swaps.get_mut(&tx_id) {
                if state.status == SwapStatus::Active {
                    state.status = SwapStatus::Aborted(AbortReason::Timeout);
                    // Attempt to sign and finalize ABORT due to timeout
                    match self.add_local_signature_share(&tx_id, false).await { // false for ABORT
                        Ok(_) => {
                            if let Some(decision) = self.finalize_decision(&tx_id, false) {
                                println!(
                                    "Coordinator ({}): Finalized ABORT decision for timed-out swap {}. Submitting.",
                                    self.identity.id,
                                    tx_id
                                );

                                // --- Submit to Blockchain (Timeout Abort) --- 
                                let tx_id_clone = tx_id.clone(); // Clone tx_id for the closure

                                // Spawn a task to call the refactored submit function
                                let self_clone = Arc::new(self.clone()); // Need to clone self or relevant parts safely
                                let decision_clone_for_spawn = decision.clone(); // Clone decision BEFORE spawn
                                tokio::spawn(async move {
                                    match self_clone.submit_decision_to_blockchain(decision_clone_for_spawn).await { // Use the clone
                                        Ok(tx_hash) => println!("Blockchain submission SUCCESS (Timeout Abort) for swap {}: TxHash {}", tx_id_clone, tx_hash),
                                        Err(e) => eprintln!("Blockchain submission FAILED (Timeout Abort) for swap {}: {}", tx_id_clone, e),
                                    }
                                });
                                
                                // --- End Submit (Timeout Abort) ---
                                decisions.push(decision);
                                self.active_swaps.remove(&tx_id);
                            }
                            // else: threshold not met, decision stays None
                        }
                        Err(e) => {
                             eprintln!("Coordinator ({}): Failed to add signature share for ABORT on timed-out swap {}: {}", self.identity.id, tx_id, e);
                        }
                    }
                }
            } // else: swap was already processed or removed
        }

        decisions
    }

    // --- Helper Functions for Network Integration ---

    /// Returns TEE identities responsible for a given shard using the stored assignment map.
    fn get_tee_identities_for_shard(&self, shard_id: usize) -> Vec<TEEIdentity> {
        self.shard_tee_assignments.get(&shard_id)
            .cloned() // Clone the Vec<TEEIdentity> if found
            .unwrap_or_else(|| {
                // Handle case where shard ID is unknown
                eprintln!("Warning: No TEE assignment found for shard {}", shard_id);
                Vec::new() // Return empty vector
            })
    }

    /// Returns identities of peer coordinators based on the system config.
    fn get_peer_coordinator_identities(&self) -> Vec<TEEIdentity> {
        // Get the full list from config and filter out self
        self.config.coordinator_identities.iter()
            .filter(|&id| id != &self.identity) // Exclude self (compare full TEEIdentity)
            .cloned()
            .collect()
    }
    // --- End Helper Functions ---

    /// Finalizes the decision and submits it to the blockchain interface.
    /// Takes the finalized SignedCoordinatorDecision containing threshold signatures.
    async fn submit_decision_to_blockchain(
        &self,
        decision: SignedCoordinatorDecision,
    ) -> Result<TransactionId, BlockchainError> { 
        let relayer = self.blockchain_interface.clone(); 
        let tx_id_str = decision.tx_id.clone();
        let commit = decision.commit;
        let swap_info = self.active_swaps.get(&tx_id_str).cloned(); // Clone swap state

        if let Some(swap_state) = swap_info { 
             println!(
                 "Coordinator ({}): Finalized {} decision for swap {}. Preparing submission...", 
                 self.identity.id, 
                 if commit { "COMMIT" } else { "ABORT" }, 
                 tx_id_str
             );

            // Decode the swap_id hex string into bytes32
            let swap_id_bytes = hex::decode(tx_id_str.trim_start_matches("0x"))
                .map_err(|e| EvmRelayerError::HexError(e))?;
            let swap_id: SwapId = swap_id_bytes.try_into()
                .map_err(|_| EvmRelayerError::ParseError("Failed to convert Vec<u8> to SwapId [u8; 32]".to_string()))?;

            // Construct the signature bytes needed by the relayer
            // Use decision.signature which is now a single Signature
            let final_signature_bytes: SignatureBytes = decision.signature
                .to_bytes()
                .to_vec();

            println!("[Coordinator {}] Submitting with packed threshold signatures ({} bytes) for swap {}", self.identity.id, final_signature_bytes.len(), tx_id_str);

            // Now submit to the blockchain using the *correctly* signed hash
            if commit {
                // Access fields via swap_state.transaction
                if let Some(target_asset) = swap_state.transaction.target_asset.clone() {
                    let recipient_address = swap_state.transaction.accounts.get(1).map(|acc| acc.address.clone())
                        .ok_or_else(|| EvmRelayerError::Other("Missing recipient account in swap info".to_string()))?;

                    let amount_u64 = swap_state.transaction.amounts.get(0).cloned()
                        .ok_or_else(|| EvmRelayerError::Other("Missing amount in swap info".to_string()))?;
                    let amount_u256 = U256::from(amount_u64);

                    println!("[Coordinator {}] Calling relayer.submit_release for swap 0x{}...", self.identity.id, hex::encode(swap_id));
                    relayer.submit_release(
                        target_asset.chain_id,
                        swap_id,
                        target_asset.token_address,
                        amount_u256,
                        recipient_address,
                        final_signature_bytes, // Use the newly generated signature
                    ).await
                 } else {
                     println!("[Coordinator {}] ERROR - Cannot submit RELEASE for swap {} - target_asset info missing!", self.identity.id, tx_id_str);
                     Err(EvmRelayerError::ConfigNotFound("Missing target asset info".to_string()))
                 }
            } else { // ABORT case
                 if let Some(lock_info) = swap_state.transaction.required_locks.get(0) {
                    let sender_address = lock_info.account.address.clone();
                    let amount_u256 = U256::from(lock_info.amount);
                    let token_address = lock_info.asset.token_address.clone();
                    let chain_id = lock_info.asset.chain_id; 

                     println!("[Coordinator {}] Calling relayer.submit_abort for swap 0x{}...", self.identity.id, hex::encode(swap_id));
                     relayer.submit_abort(
                        chain_id, 
                        swap_id,
                        token_address, 
                        amount_u256, 
                        sender_address, 
                        final_signature_bytes, // Use the newly generated signature
                    ).await
                 } else {
                     println!("[Coordinator {}] ERROR - Cannot submit ABORT for swap {} - lock_info missing!", self.identity.id, tx_id_str);
                     Err(EvmRelayerError::ConfigNotFound("Missing lock info".to_string()))
                 }
            }
        } else {
             println!("[Coordinator {}] ERROR - Swap info not found for {} during blockchain submission.", self.identity.id, tx_id_str);
             Err(EvmRelayerError::ConfigNotFound(format!("Swap info not found for {}", tx_id_str)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_structures::{Transaction, AccountId, AssetId, TxType}; // Added missing imports
    use crate::tee_logic::crypto_sim::{generate_keypair, sign}; // Import PublicKey for verify call
    use crate::config::SystemConfig;
    use crate::cross_chain::types::LockProof; // Import LockProof
    use crate::network::{MockNetwork, Message}; // Import MockNetwork directly from network module now
    use crate::onchain::interface::{BlockchainInterface, BlockchainError, SwapId, SignatureBytes, TransactionId};
     // Added
     // Added
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use async_trait::async_trait;

    // create_test_tee now returns keypair as SecretKey
    fn create_test_tee(id: usize) -> (TEEIdentity, SecretKey) {
        let keypair = generate_keypair();
        let identity = TEEIdentity { id, public_key: keypair.verifying_key() };
        (identity, keypair)
    }

    // Helper function to create a SystemConfig for tests
    // Updated to take num_coordinators and threshold
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

    // Helper to create a dummy transaction for testing
    fn create_dummy_swap_tx(tx_id: &str) -> Transaction {
        // Define dummy accounts and assets
        let acc_a1 = AccountId { chain_id: 0, address: format!("user_a_{}", tx_id) };
        let acc_b1 = AccountId { chain_id: 1, address: format!("user_b_{}", tx_id) };
        // Add dummy token addresses
        let asset_a = AssetId { chain_id: 0, token_symbol: "TOK_A".to_string(), token_address: "0xA...".to_string() }; 
        let asset_b = AssetId { chain_id: 1, token_symbol: "TOK_B".to_string(), token_address: "0xB...".to_string() }; 

        Transaction {
            tx_id: tx_id.to_string(),
            tx_type: TxType::CrossChainSwap,
            accounts: vec![acc_a1.clone(), acc_b1.clone()],
            amounts: vec![100], // Dummy amount
            required_locks: vec![LockInfo {
                account: acc_a1.clone(),
                asset: asset_a.clone(), 
                amount: 100,
            }],
            // Add dummy target_asset (or None if not needed for specific tests)
            target_asset: Some(asset_b.clone()), 
            timeout: Duration::from_secs(600),
        }
    }

    // create_dummy_lock_proof needs signer identity
    // Make async because it calls sign
    async fn create_dummy_lock_proof(tx_id: &str, shard_id: usize, signing_tee: &TEEIdentity, signing_key: &SecretKey) -> LockProof {
        let lock_info = LockInfo {
            account: AccountId { chain_id: 0, address: format!("dummy_acc_{}", shard_id) }, // Make distinct
            asset: AssetId {
                chain_id: 0,
                token_symbol: "DUM".into(),
                token_address: "0x0000000000000000000000000000000000000000".to_string(), // Placeholder added
            },
            amount: 10 + shard_id as u64 // Make distinct
        };
        let mut data_to_sign = tx_id.as_bytes().to_vec();
        data_to_sign.extend_from_slice(&shard_id.to_le_bytes());
        data_to_sign.extend_from_slice(lock_info.account.address.as_bytes());
        data_to_sign.extend_from_slice(&lock_info.asset.token_symbol.as_bytes());
        data_to_sign.extend_from_slice(&lock_info.amount.to_le_bytes());
        // Provide delay arguments (0, 0 for tests) and await the async sign function
        let signature = sign(
            &data_to_sign, 
            signing_key, 
            0, 0, // No delays for this internal signing
            &None, // No direct metrics context here
            &None  // No direct node ID context here
        ).await;

        LockProof {
            tx_id: tx_id.to_string(),
            shard_id,
            lock_info,
            signer_identity: signing_tee.clone(),
            // Signature is now the correct type after awaiting
            attestation_or_sig: signature,
        }
    }

    // Helper to create a dummy LockRequest for tests
    fn create_dummy_lock_request() -> LockRequest {
        // Create the needed LockInfo directly
        let dummy_lock_info = LockInfo {
            account: AccountId { chain_id: 1, address: "dummy_recv_addr".to_string() },
            asset: AssetId {
                chain_id: 0,
                token_symbol: "DUM".into(),
                token_address: "0x0000000000000000000000000000000000000000".to_string(),
            },
            amount: 100,
            // Add timeout if LockInfo needs it, otherwise remove.
            // timeout: Duration::from_secs(120), // Assuming LockInfo does NOT have timeout based on its definition
        };

        LockRequest {
            tx_id: "dummy_swap_id".to_string(),
            lock_info: dummy_lock_info,
        }
    }

    // --- Mock Blockchain Interface for Tests ---
    #[derive(Clone, Debug)] // Add Debug
    struct MockBlockchainInterface;

    #[async_trait]
    impl BlockchainInterface for MockBlockchainInterface {
        // --- Fix Return Type: u64 -> U256 ---
        async fn get_balance(
            &self,
            _chain_id: u64,
            _account_address: String,
            _token_address: String,
        ) -> Result<U256, BlockchainError> { // Changed return type
            Ok(U256::from(1000)) // Return a dummy U256 balance
        }

        // --- Fix Param Type: u64 -> U256 ---
        async fn submit_release(
            &self,
            _chain_id: u64,
            _swap_id: SwapId,
            _token_address: String,
            _amount: U256, // Changed param type
            _recipient_address: String,
            _tee_signatures: SignatureBytes,
        ) -> Result<TransactionId, BlockchainError> {
            Ok("mock_tx_release_hash_123".to_string())
        }

        // --- Fix Param Type: u64 -> U256 ---
        async fn submit_abort(
            &self,
            _chain_id: u64,
            _swap_id: SwapId,
            _token_address: String,
            _amount: U256, // Changed param type
            _sender_address: String,
            _tee_signatures: SignatureBytes,
        ) -> Result<TransactionId, BlockchainError> {
            Ok("mock_tx_abort_hash_456".to_string())
        }

        // --- Add Missing Method: lock (dummy implementation) ---
        async fn lock(
            &self,
            _chain_id: u64,
            _sender_private_key: String,
            _swap_id: SwapId,
            _recipient_address: String,
            _token_address: String,
            _amount: U256,
            _timeout_seconds: u64,
        ) -> Result<TransactionId, BlockchainError> {
            println!("MockBlockchainInterface: lock called (dummy)");
            Ok("mock_tx_lock_hash_789".to_string()) 
        }

        // --- Add Missing Method: approve_erc20 (dummy implementation) ---
        async fn approve_erc20(
            &self,
            _chain_id: u64,
            _owner_private_key: String,
            _token_address: String,
            _spender_address: String,
            _amount: U256,
        ) -> Result<TransactionId, BlockchainError> {
            println!("MockBlockchainInterface: approve_erc20 called (dummy)");
            Ok("mock_tx_approve_hash_101".to_string())
        }
    }
    // --- End Mock Blockchain Interface ---

    // Helper to dispatch messages from mock network to coordinators
    // Make async because it calls handle_partial_signature
    // Updated to take only 2 arguments
    async fn dispatch_messages(
        network: &Arc<MockNetwork>, // Network to retrieve messages from
        coordinators: &HashMap<TEEIdentity, Arc<Mutex<CrossChainCoordinator>>>,
        // shared_mock_network: &Arc<MockNetwork> // Removed redundant arg
    ) {
        for (coord_id, coord_arc) in coordinators {
            // Retrieve messages specifically for this coordinator from the mock network
            let messages = network.retrieve_messages_for(coord_id); // Use the 'network' arg
            if !messages.is_empty() {
                // Lock the specific coordinator to process its messages
                let mut coordinator = coord_arc.lock().unwrap();
                for network_msg in messages {
                     println!(" Dispatcher: Routing {:?} to {}", network_msg.message, coord_id.id);
                     match network_msg.message {
                         Message::CoordPartialSig { tx_id, commit, signature } => {
                             // Call the handler on the coordinator instance
                             // Need to await the async function call here
                            if let Err(e) = coordinator.handle_partial_signature(signature, &tx_id, commit).await { // ADDED .await
                                 eprintln!("   -> Dispatch Error handling PartialSig for {}: {}", coord_id.id, e);
                             }
                         }
                         // Coordinators shouldn't receive lock requests directly in this model
                         _ => eprintln!("   -> Dispatch Error: Unexpected msg type {:?} for coordinator {}", network_msg.message, coord_id.id),
                     }
                 }
            }
        }
    }

    #[tokio::test]
    async fn test_multi_coordinator_signing() {
        let num_coordinators = 3;
        let threshold = 2;
        // Call updated create_test_config
        let config = create_test_config(num_coordinators, threshold);
        let mock_network = Arc::new(MockNetwork::new());
        let mock_blockchain = Arc::new(MockBlockchainInterface); // Create mock blockchain interface

        let mut coordinators: HashMap<TEEIdentity, Arc<Mutex<CrossChainCoordinator>>> = HashMap::new();
        let mut coordinator_keys = Vec::new();

        // Create coordinator identities and keys based on the config
        // Use correct field name: coordinator_identities
        let coord100_id = config.coordinator_identities.get(0).unwrap().clone(); 
        // Remove .unwrap() from SecretKey::from_bytes
        let coord100_key = SecretKey::from_bytes(&[100u8; 32]); // Consistent dummy key
        let coord101_id = config.coordinator_identities.get(1).unwrap().clone(); 
        let coord101_key = SecretKey::from_bytes(&[101u8; 32]);
        let coord102_id = config.coordinator_identities.get(2).unwrap().clone();
        let coord102_key = SecretKey::from_bytes(&[102u8; 32]);
        
        coordinator_keys.push(coord100_key.clone());
        coordinator_keys.push(coord101_key.clone());
        coordinator_keys.push(coord102_key.clone());

        // Create shard assignments map (needed for coordinator init)
        let mut shard_assignments: HashMap<usize, Vec<TEEIdentity>> = HashMap::new();
        shard_assignments.insert(0, vec![coord100_id.clone()]); // Example assignment

        // Instantiate coordinators
        // Add cast for mock_blockchain
        coordinators.insert(coord100_id.clone(), Arc::new(Mutex::new(CrossChainCoordinator::new(coord100_id.clone(), coord100_key, config.clone(), vec![coord100_id.clone()], Arc::clone(&mock_network) as Arc<_>, Arc::clone(&mock_blockchain) as Arc<dyn BlockchainInterface + Send + Sync>, shard_assignments.clone()))));
        coordinators.insert(coord101_id.clone(), Arc::new(Mutex::new(CrossChainCoordinator::new(coord101_id.clone(), coord101_key, config.clone(), vec![coord101_id.clone()], Arc::clone(&mock_network) as Arc<_>, Arc::clone(&mock_blockchain) as Arc<dyn BlockchainInterface + Send + Sync>, shard_assignments.clone()))));
        coordinators.insert(coord102_id.clone(), Arc::new(Mutex::new(CrossChainCoordinator::new(coord102_id.clone(), coord102_key, config.clone(), vec![coord102_id.clone()], Arc::clone(&mock_network) as Arc<_>, Arc::clone(&mock_blockchain) as Arc<dyn BlockchainInterface + Send + Sync>, shard_assignments.clone()))));

        // For simplicity, create a dummy transaction. Replace with actual logic.
        // Prefix unused swap_tx
        let _swap_tx = create_dummy_swap_tx("swap_tx_payload"); 
        // This might involve signing, nonce management, etc.

        // Simulate multiple rounds of dispatching until no more messages are flowing
        let max_rounds = num_coordinators * 2; // Heuristic limit
        for round in 0..max_rounds {
            println!("--- Dispatcher Round {} ---", round + 1);
            let messages_before = mock_network.get_sent_messages().len();
            // Call site already uses 2 args, now matches updated definition
            dispatch_messages(&mock_network, &coordinators).await; 
            let messages_after = mock_network.get_sent_messages().len();
            if messages_before > 0 && messages_after == 0 {
                println!("--- Dispatcher: Quiesced ---");
                break; // Stop if messages were processed and no new ones were generated
            }
            if round == max_rounds - 1 {
                println!("--- Dispatcher: Max rounds reached ---");
            }
        }

        // 7. Finalize and Verify
        println!("--- Final Verification ---");
    }

    #[tokio::test]
    async fn coordinator_check_timeouts() {
        let num_coordinators = 3;
        let threshold = 1;
        let config = create_test_config(num_coordinators, threshold);
        let mock_network = Arc::new(MockNetwork::new());
        let mock_blockchain = Arc::new(MockBlockchainInterface);

        let mut coordinators: HashMap<TEEIdentity, Arc<Mutex<CrossChainCoordinator>>> = HashMap::new();
        let mut coordinator_keys = Vec::new();

        let (coord100_id, coord100_key) = create_test_tee(100);
        let (coord101_id, coord101_key) = create_test_tee(101);
        let (coord102_id, coord102_key) = create_test_tee(102);
        
        coordinator_keys.push(coord100_key.clone());
        coordinator_keys.push(coord101_key.clone());
        coordinator_keys.push(coord102_key.clone());

        let mut shard_assignments: HashMap<usize, Vec<TEEIdentity>> = HashMap::new();
        shard_assignments.insert(0, vec![coord100_id.clone()]);
        shard_assignments.insert(1, vec![coord101_id.clone()]);
        shard_assignments.insert(2, vec![coord102_id.clone()]);

        coordinators.insert(coord100_id.clone(), Arc::new(Mutex::new(CrossChainCoordinator::new(coord100_id.clone(), coord100_key, config.clone(), vec![coord100_id.clone()], Arc::clone(&mock_network) as Arc<_>, Arc::clone(&mock_blockchain) as Arc<dyn BlockchainInterface + Send + Sync>, shard_assignments.clone()))));
        coordinators.insert(coord101_id.clone(), Arc::new(Mutex::new(CrossChainCoordinator::new(coord101_id.clone(), coord101_key, config.clone(), vec![coord101_id.clone()], Arc::clone(&mock_network) as Arc<_>, Arc::clone(&mock_blockchain) as Arc<dyn BlockchainInterface + Send + Sync>, shard_assignments.clone()))));
        coordinators.insert(coord102_id.clone(), Arc::new(Mutex::new(CrossChainCoordinator::new(coord102_id.clone(), coord102_key, config.clone(), vec![coord102_id.clone()], Arc::clone(&mock_network) as Arc<_>, Arc::clone(&mock_blockchain) as Arc<dyn BlockchainInterface + Send + Sync>, shard_assignments.clone()))));

        let tx_timeout = Transaction {
           tx_id: "swap_timeout".to_string(),
           tx_type: TxType::CrossChainSwap,
           accounts: vec![],
           amounts: vec![],
           required_locks: vec![], // Keep simple
           target_asset: None, // Add target_asset (None is fine here)
           timeout: Duration::from_secs(60), // Use short timeout
       };

        // Simulate timed-out swap
        let mut coordinator = coordinators.get_mut(&coord100_id).unwrap().lock().unwrap();
        // Set initiation time far in the past to trigger timeout
        let initiation_time_far_past = std::time::Instant::now().checked_sub(Duration::from_secs(tx_timeout.timeout.as_secs() + 10)).unwrap_or_else(std::time::Instant::now);
        coordinator.active_swaps.insert("swap_timeout".to_string(), SwapState {
            transaction: tx_timeout,
            relevant_shards: HashSet::new(),
            received_proofs: HashMap::new(),
            initiation_time: initiation_time_far_past, // Use time in the past
            status: SwapStatus::Active,
            release_aggregator: None,
            abort_aggregator: None,
        });

        // Check timeouts immediately after setup (should detect the old swap)
        let timed_out_swaps = coordinator.check_timeouts().await;
        assert!(!timed_out_swaps.is_empty(), "Expected to find timed out swaps");
    }
} // end tests mod 