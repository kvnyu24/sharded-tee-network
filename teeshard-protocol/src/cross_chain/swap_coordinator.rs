// Placeholder for Cross-Chain Swap Coordinator logic (Algorithm 2)

use crate::data_structures::{TEEIdentity, Transaction, LockInfo, AccountId, AssetId, TxType}; // Added LockInfo etc. for test helpers
use crate::cross_chain::types::{LockProof, SwapOutcome, AbortReason, SignedCoordinatorDecision, LockRequest}; // Import new types
use crate::config::SystemConfig;
// Use the actual Signature type
use crate::tee_logic::types::Signature;
// Import crypto components
use crate::tee_logic::crypto_sim::{sign, generate_keypair, SecretKey, verify}; // Added SecretKey, verify
// Import the Signer trait for the .sign() method
use ed25519_dalek::Signer;
// Import multi-sig aggregator components
use crate::tee_logic::threshold_sig::{PartialSignature, ThresholdAggregator};
use crate::network::{NetworkInterface, NetworkMessage, Message}; // Import network trait and types

use std::collections::{HashMap, HashSet};
use std::time::Duration; // For timeout
use std::sync::Arc; // Import Arc
use std::sync::Mutex;

// Represents the state of a coordinator TEE managing a swap
pub struct CrossChainCoordinator {
    pub identity: TEEIdentity,
    pub signing_key: SecretKey, // Coordinator needs its own key to sign placeholder decisions
    pub config: SystemConfig, // Access to system-wide parameters
    // Track ongoing swaps and their state
    pub active_swaps: HashMap<String, SwapState>,
    // Network interface for sending messages
    network: Arc<dyn NetworkInterface + Send + Sync>,
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
         network: Arc<dyn NetworkInterface + Send + Sync>,
         shard_tee_assignments: HashMap<usize, Vec<TEEIdentity>>, // Add assignments map
     ) -> Self {
         CrossChainCoordinator {
             identity,
             signing_key,
             config,
             active_swaps: HashMap::new(),
             network,
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
                if let Some(lock_info) = state_ref.transaction.required_locks.iter().find(|li| li.account.chain_id == (*shard_id).try_into().unwrap()) {
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
    pub fn handle_lock_proof(&mut self, proof: LockProof) -> Result<bool, AbortReason> {
        let tx_id = proof.tx_id.clone();
        println!("Coordinator ({}): Received lock proof for swap {} from shard {}",
                 self.identity.id, tx_id, proof.shard_id);

        let swap = self.active_swaps.get_mut(&tx_id)
            .ok_or_else(|| {
                println!("Coordinator Error: Swap {} not found when handling proof from shard {}", tx_id, proof.shard_id);
                AbortReason::Other("Swap not found".to_string())
            })?;

        // Verify the proof using the signer's public key
        if !crate::tee_logic::lock_proofs::verify_lock_proof(&proof, &proof.signer_identity.public_key) {
            println!("Coordinator ({}): Lock proof verification failed for swap {} from signer {}",
                     self.identity.id, tx_id, proof.signer_identity.id);
            // Mark swap as aborted instead of removing immediately
            swap.status = SwapStatus::Aborted(AbortReason::LockProofVerificationFailed);
            // self.active_swaps.remove(&tx_id); // Don't remove yet
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
    fn add_local_signature_share(&mut self, tx_id: &str, commit: bool) -> Result<(), String> {
        let message_bytes = Self::prepare_decision_message(tx_id, commit);
        let threshold = self.get_coordinator_threshold();

        let swap = self.active_swaps.get_mut(tx_id)
            .ok_or_else(|| format!("Swap {} not found for signing", tx_id))?;

        let aggregator_option = if commit {
            &mut swap.release_aggregator
        } else {
            &mut swap.abort_aggregator
        };

        // Ensure aggregator exists
        if aggregator_option.is_none() {
            println!("Coordinator ({}): Creating {} aggregator for swap {}",
                     self.identity.id, if commit {"RELEASE"} else {"ABORT"}, tx_id);
            *aggregator_option = Some(ThresholdAggregator::new(&message_bytes, threshold));
        }

        // We need to re-borrow mutably AFTER the potential assignment above.
        let aggregator = aggregator_option.as_mut().unwrap(); // Safe to unwrap due to check above

        // Check if the message matches (in case aggregator was created for a different older message? Unlikely here)
        // if aggregator.message != message_bytes { ... error handling ... }

        // Create and add the partial signature
        let local_signature = self.signing_key.sign(&message_bytes);
        let partial_sig = PartialSignature {
            signer_id: self.identity.clone(),
            signature_data: local_signature,
        };

        match aggregator.add_partial_signature(partial_sig.clone()) { // Clone partial_sig for potential broadcast
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
                // Log error, but don't necessarily fail the whole operation?
                // Might fail if we already signed.
                eprintln!("Coordinator ({}): Failed to add local {} signature share for swap {}: {}",
                          self.identity.id, if commit {"RELEASE"} else {"ABORT"}, tx_id, e);
                Err(format!("Failed to add local signature share: {}", e))
            }
        }
    }

    /// Placeholder function to handle receiving a partial signature from another coordinator.
    // TODO: Integrate with network layer to receive and route PartialSignature messages here.
    fn handle_partial_signature(&mut self, partial_sig: PartialSignature, tx_id: &str, commit: bool) -> Result<(), String> {
        let swap = self.active_swaps.get_mut(tx_id)
            .ok_or_else(|| format!("Swap {} not found for receiving partial signature", tx_id))?;

        let aggregator_option = if commit {
            &mut swap.release_aggregator
        } else {
            &mut swap.abort_aggregator
        };

        if let Some(aggregator) = aggregator_option {
            // Verification against the message stored in the aggregator happens within add_partial_signature.
            match aggregator.add_partial_signature(partial_sig) {
                Ok(_) => {
                     println!("Coordinator ({}): Added remote {} signature share for swap {}. Total shares: {}",
                              self.identity.id, if commit {"RELEASE"} else {"ABORT"}, tx_id, aggregator.signature_count());
                     // Optional: Check if threshold met and trigger finalization?
                     // if aggregator.has_reached_threshold() { ... }
                     Ok(())
                },
                Err(e) => {
                     eprintln!("Coordinator ({}): Failed to add remote {} signature share for swap {}: {}",
                               self.identity.id, if commit {"RELEASE"} else {"ABORT"}, tx_id, e);
                     Err(format!("Failed to add remote signature share: {}", e))
                }
            }
        } else {
            // This might happen if a partial signature arrives before the local coordinator
            // has even initialized the aggregator (e.g., before deciding to sign locally).
            // Policy decision: Should we store it pending aggregator creation, or reject it?
            // Rejecting for now.
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
                       aggregator.get_required_threshold(), aggregator.signature_count());

             // Try to finalize using the multi-sig logic
             if let Some(multi_sig) = aggregator.finalize_multi_signature() {
                 println!("Coordinator ({}): Finalized {} decision for swap {} with {} signatures.",
                          self.identity.id, if commit {"RELEASE"} else {"ABORT"}, tx_id, multi_sig.len());
                 Some(SignedCoordinatorDecision {
                     tx_id: tx_id.to_string(),
                     commit,
                     signature: multi_sig,
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
    pub fn process_proof_and_finalize(&mut self, proof: LockProof) -> Option<SignedCoordinatorDecision> {
        let tx_id_clone = proof.tx_id.clone(); // Clone tx_id before proof is moved
        match self.handle_lock_proof(proof) {
            Ok(ready_to_finalize) => {
                if ready_to_finalize {
                    println!("Coordinator ({}): All proofs received for {}. Adding local RELEASE share.", self.identity.id, tx_id_clone);

                    // Add local signature share for COMMIT
                    if let Err(e) = self.add_local_signature_share(&tx_id_clone, true) {
                        eprintln!("Coordinator Error: Failed to add local RELEASE share for {}: {}", tx_id_clone, e);
                        // What to do here? Maybe try to abort?
                        return None; // Or maybe try to sign abort?
                    }

                    // Attempt to finalize (will only work if threshold is 1 or others signed concurrently)
                    let decision = self.finalize_decision(&tx_id_clone, true);

                    // Finalize *logic* (remove swap state) only if decision *could* be signed (threshold met)
                    if decision.is_some() {
                        self.active_swaps.remove(&tx_id_clone);
                        println!("Coordinator ({}): Finalized swap {} as COMMIT after reaching threshold.", self.identity.id, tx_id_clone);
                    } else {
                         println!("Coordinator ({}): Swap {} ready for COMMIT, waiting for more signatures.", self.identity.id, tx_id_clone);
                    }
                    decision // Return decision if finalized, None otherwise
                } else {
                    None // Still waiting for more proofs
                }
            }
            Err(abort_reason) => {
                 println!("Coordinator ({}): Aborting swap {} due to: {:?}. Adding local ABORT share.", self.identity.id, tx_id_clone, abort_reason);
                 // Mark as aborted (already done in handle_lock_proof)

                 // Add local signature share for ABORT
                 if let Err(e) = self.add_local_signature_share(&tx_id_clone, false) {
                     eprintln!("Coordinator Error: Failed to add local ABORT share for {}: {}", tx_id_clone, e);
                     // Even if signing fails, we should probably keep it marked Aborted?
                     // Maybe return None here? The state is already Aborted.
                     return None;
                 }

                 // Attempt to finalize
                 let decision = self.finalize_decision(&tx_id_clone, false);

                 // Finalize *logic* (remove swap state) only if decision *could* be signed
                 if decision.is_some() {
                     self.active_swaps.remove(&tx_id_clone);
                     println!("Coordinator ({}): Finalized swap {} as ABORT after reaching threshold.", self.identity.id, tx_id_clone);
                 } else {
                    println!("Coordinator ({}): Swap {} ABORTED, waiting for more signatures.", self.identity.id, tx_id_clone);
                 }
                 decision // Return signed abort message if finalized
            }
        }
    }

    /// Checks for timed-out swaps, marks them as Aborted, adds local ABORT share,
    /// potentially finalizes, and returns a list of signed decisions if finalized.
    pub fn check_timeouts(&mut self) -> Vec<SignedCoordinatorDecision> {
        let now = std::time::Instant::now();
        let mut finalized_decisions = Vec::new();
        let mut timed_out_tx_ids = Vec::new(); // Collect IDs to process after iteration

        // First pass: Identify timed-out swaps and mark them
        for (tx_id, swap) in self.active_swaps.iter_mut() {
            // Only check active swaps that haven't already been aborted
            if swap.status == SwapStatus::Active {
                // Get timeout duration from the transaction itself
                let timeout_duration = swap.transaction.timeout;
                if now.duration_since(swap.initiation_time) > timeout_duration {
                    println!("Coordinator ({}): Swap {} timed out after {:?}.",
                             self.identity.id, tx_id, timeout_duration);
                    swap.status = SwapStatus::Aborted(AbortReason::TimeoutWaitingForLocks);
                    timed_out_tx_ids.push(tx_id.clone());
                }
            }
        }

        // Second pass: Process timed-out swaps
        for tx_id in timed_out_tx_ids {
            // Add local ABORT signature share
            if let Err(e) = self.add_local_signature_share(&tx_id, false) {
                 eprintln!("Coordinator Error: Failed to add local ABORT share for timed-out swap {}: {}", tx_id, e);
                 // Continue processing other timed-out swaps
                 continue;
            }

            // Attempt to finalize the ABORT decision
            if let Some(decision) = self.finalize_decision(&tx_id, false) {
                 finalized_decisions.push(decision);
                 // Remove the swap state only if successfully finalized
                 self.active_swaps.remove(&tx_id);
                  println!("Coordinator ({}): Finalized swap {} as ABORT due to timeout after reaching threshold.", self.identity.id, tx_id);
            } else {
                 println!("Coordinator ({}): Timed-out swap {} ABORTED, waiting for more signatures.", self.identity.id, tx_id);
                 // Do not remove swap state yet, waiting for more signatures
            }
        }

        finalized_decisions
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_structures::{Transaction, AccountId, AssetId, TxType}; // Added missing imports
    use crate::tee_logic::crypto_sim::{generate_keypair, sign, verify, PublicKey}; // Import PublicKey for verify call
    use crate::config::SystemConfig;
    use crate::cross_chain::types::LockProof; // Import LockProof
    use crate::network::mock_network::MockNetwork; // Import MockNetwork for tests
    use std::collections::HashSet;
    use std::sync::Arc;

    // create_test_tee now returns keypair as SecretKey
    fn create_test_tee(id: usize) -> (TEEIdentity, SecretKey) {
        let keypair = generate_keypair();
        let identity = TEEIdentity { id, public_key: keypair.verifying_key() };
        (identity, keypair)
    }

    // Test helper to create config, allowing override for coordinator identities
    fn create_test_config(coordinators: Option<Vec<TEEIdentity>>) -> SystemConfig {
        let mut cfg = SystemConfig::default();
        cfg.tee_threshold = 1; // Simplify TEE threshold for testing
        cfg.coordinator_threshold = 1; // Override default, simplify coordinator threshold for testing single signer finalization
        cfg.nodes_per_shard = 2; // Set explicitly for initiate_swap test expectations
        // Override default coordinators if provided
        if let Some(coords) = coordinators {
            cfg.coordinator_identities = coords;
        }
        cfg
    }

     fn create_dummy_swap_tx(id: &str) -> Transaction {
        Transaction {
            tx_id: id.to_string(),
            tx_type: TxType::CrossChainSwap,
            accounts: vec![], // Keep simple for these tests
            amounts: vec![],
            required_locks: vec![ // Add dummy required lock to make relevant_shards meaningful
                LockInfo {
                     account: AccountId { chain_id: 0, address: "dummy".into() },
                     asset: AssetId { chain_id: 0, token_symbol: "DUM".into() },
                     amount: 1
                 }
            ],
            timeout: std::time::Duration::from_secs(60), // Add a default timeout
        }
    }

    // create_dummy_lock_proof needs signer identity
     fn create_dummy_lock_proof(tx_id: &str, shard_id: usize, signing_tee: &TEEIdentity, signing_key: &SecretKey) -> LockProof {
         let lock_info = LockInfo {
            account: AccountId { chain_id: 0, address: format!("dummy_acc_{}", shard_id) }, // Make distinct
            asset: AssetId { chain_id: 0, token_symbol: "DUM".into() },
            amount: 10 + shard_id as u64 // Make distinct
        };
        let mut data_to_sign = tx_id.as_bytes().to_vec();
        data_to_sign.extend_from_slice(&shard_id.to_le_bytes());
        data_to_sign.extend_from_slice(lock_info.account.address.as_bytes());
        data_to_sign.extend_from_slice(&lock_info.asset.token_symbol.as_bytes());
        data_to_sign.extend_from_slice(&lock_info.amount.to_le_bytes());
        let signature = sign(&data_to_sign, signing_key);

         LockProof {
            tx_id: tx_id.to_string(),
            shard_id,
            lock_info,
            signer_identity: signing_tee.clone(),
            attestation_or_sig: signature,
        }
    }

    #[test]
    fn coordinator_creation() {
        let (tee_id, signing_key) = create_test_tee(100);
        let config = create_test_config(None);
        let mock_network = Arc::new(MockNetwork::default()); // Keep original Arc<MockNetwork>
        let coordinator = CrossChainCoordinator::new(
            tee_id.clone(),
            signing_key,
            config,
            // Pass a clone coerced to the trait object
            Arc::clone(&mock_network) as Arc<dyn NetworkInterface + Send + Sync>,
            HashMap::new()
        );
        assert_eq!(coordinator.identity, tee_id);
        assert!(coordinator.active_swaps.is_empty());
        // Can optionally check mock_network.get_sent_messages() is empty
    }

    #[test]
    fn coordinator_initiate_swap() {
        let (tee_id, signing_key) = create_test_tee(100);
        let config = create_test_config(None);
        let mock_network = Arc::new(MockNetwork::default()); // Keep original Arc<MockNetwork>
        // Create dummy assignments for the test
        let mut assignments = HashMap::new();
        let shard0_tees = vec![create_test_tee(0).0, create_test_tee(1).0];
        let shard1_tees = vec![create_test_tee(10).0, create_test_tee(11).0];
        assignments.insert(0, shard0_tees.clone());
        assignments.insert(1, shard1_tees.clone());

        let mut coordinator = CrossChainCoordinator::new(
            tee_id.clone(),
            signing_key,
            config.clone(),
            // Pass a clone coerced to the trait object
            Arc::clone(&mock_network) as Arc<dyn NetworkInterface + Send + Sync>,
            assignments
        );
        let tx = create_dummy_swap_tx("swap1");
        let shards: HashSet<usize> = [0, 1].into_iter().collect();
        coordinator.initiate_swap(tx.clone(), shards.clone());

        assert_eq!(coordinator.active_swaps.len(), 1);
        assert!(coordinator.active_swaps.contains_key("swap1"));
        let swap_state = coordinator.active_swaps.get("swap1").unwrap();
        assert_eq!(swap_state.transaction.tx_id, "swap1");
        assert_eq!(swap_state.relevant_shards, shards);
        assert!(matches!(swap_state.status, SwapStatus::Active));

        // Verify network messages sent
        let sent = mock_network.get_sent_messages(); // Use original Arc
        // Expecting messages only to TEEs in shard 0, because the dummy
        // transaction only requires a lock on chain_id 0.
        let expected_msgs = shard0_tees.len();
        assert_eq!(sent.len(), expected_msgs, "Incorrect number of ShardLockRequest messages sent");

        let mut sent_to_shard0 = 0;
        for msg in sent.iter() {
            assert_eq!(msg.sender.id, tee_id.id);
            match &msg.message {
                Message::ShardLockRequest(req) => {
                    assert_eq!(req.tx_id, "swap1");
                    // Check if receiver is in shard 0 or shard 1 list
                    if shard0_tees.contains(&msg.receiver) {
                        sent_to_shard0 += 1;
                    } else {
                        panic!("Message sent to unexpected TEE: {:?}", msg.receiver);
                    }
                }
                _ => panic!("Unexpected message type sent: {:?}", msg.message),
            }
        }
        assert_eq!(sent_to_shard0, shard0_tees.len(), "Incorrect messages sent to shard 0");
        // assert_eq!(sent_to_shard1, shard1_tees.len(), "Incorrect messages sent to shard 1"); // No messages expected for shard 1
    }

     // Updated test for the new flow
     #[test]
     fn coordinator_collect_evaluate_sign_commit() {
         // Create consistent coordinator identities for the test
         let (coord100_id, coord100_key) = create_test_tee(100);
         let (coord101_id, _) = create_test_tee(101);
         let (coord102_id, _) = create_test_tee(102);
         let coordinator_identities = vec![coord100_id.clone(), coord101_id.clone(), coord102_id.clone()];

         let (shard0_id, shard0_key) = create_test_tee(0);
         let (shard1_id, shard1_key) = create_test_tee(1);

         // Pass identities to config creation
         let config = create_test_config(Some(coordinator_identities.clone()));
         let mock_network = Arc::new(MockNetwork::default());
         let mut coordinator = CrossChainCoordinator::new(
             coord100_id.clone(), // Use consistent ID
             coord100_key,     // Use consistent key
             config,
             Arc::clone(&mock_network) as Arc<dyn NetworkInterface + Send + Sync>,
             HashMap::new()
         );
         let tx = create_dummy_swap_tx("swap2");
         let shards: HashSet<usize> = [0, 1].into_iter().collect();
         coordinator.initiate_swap(tx.clone(), shards.clone());

         let proof0 = create_dummy_lock_proof("swap2", 0, &shard0_id, &shard0_key);
         let proof1 = create_dummy_lock_proof("swap2", 1, &shard1_id, &shard1_key);

         // Handle first proof
         let res0 = coordinator.handle_lock_proof(proof0.clone());
         assert!(res0.is_ok());
         assert_eq!(res0.unwrap(), false); // Not ready yet
         assert!(coordinator.active_swaps.contains_key("swap2")); // Check swap still exists
         assert_eq!(coordinator.active_swaps.get("swap2").unwrap().received_proofs.len(), 1);
         assert!(coordinator.active_swaps.get("swap2").unwrap().received_proofs.contains_key(&0));
         assert!(!coordinator.evaluate_all_locks("swap2"));

         // Handle second proof
         let res1 = coordinator.handle_lock_proof(proof1.clone());
         assert!(res1.is_ok());
         assert_eq!(res1.unwrap(), true); // Ready now
         assert!(coordinator.active_swaps.contains_key("swap2")); // Check swap still exists
         assert_eq!(coordinator.active_swaps.get("swap2").unwrap().received_proofs.len(), 2);
         assert!(coordinator.active_swaps.get("swap2").unwrap().received_proofs.contains_key(&1));
         assert!(coordinator.evaluate_all_locks("swap2")); // Should evaluate true

         // Check network messages *before* finalizing (should be empty for CoordPartialSig)
         let sent_before_finalize = mock_network.get_sent_messages(); // Use original Arc
         assert!(sent_before_finalize.is_empty(), "No CoordPartialSig should be sent before finalize attempt");

         // Finalize (which now adds local share and tries to finalize)
         let decision = coordinator.process_proof_and_finalize(proof1).expect("Finalization failed");
         assert_eq!(decision.tx_id, "swap2");
         assert_eq!(decision.commit, true);

         // Verify network messages sent *after* finalize attempt (should contain CoordPartialSig)
         let sent_after_finalize = mock_network.get_sent_messages();
         // Peers are 101, 102
         let expected_peers = 2;
         assert_eq!(sent_after_finalize.len(), expected_peers, "Incorrect number of CoordPartialSig messages sent");
         for msg in sent_after_finalize.iter() {
             assert_eq!(msg.sender.id, coord100_id.id);
             // Check receiver is one of the expected peers (e.g., 101 or 102)
             assert!(msg.receiver == coord101_id || msg.receiver == coord102_id);
             match &msg.message {
                 Message::CoordPartialSig { tx_id, commit, signature } => {
                     assert_eq!(tx_id, "swap2");
                     assert_eq!(*commit, true);
                     let mut expected_data = b"RELEASE".to_vec();
                     expected_data.extend_from_slice(b"swap2");
                     // Add borrow for signature_data
                     assert!(verify(&expected_data, &signature.signature_data, &coord100_id.public_key));
                 }
                 _ => panic!("Unexpected message type sent: {:?}", msg.message),
             }
         }
         // drop(sent_after_finalize); // Release lock - not needed with get_sent_messages

         // Verify the finalized decision signature (multi-sig collection)
         // let decision_opt = coordinator.finalize_decision("swap2", true); // No need to call again
         // assert!(decision_opt.is_some());
         // let decision = decision_opt.unwrap(); // Decision already returned by process_proof_and_finalize
         assert_eq!(decision.tx_id, "swap2");
         assert_eq!(decision.commit, true);
         assert_eq!(decision.signature.len(), 1);
         let (signer_pk, sig) = &decision.signature[0];
         assert_eq!(signer_pk, &coord100_id.public_key);
         let mut expected_data = b"RELEASE".to_vec();
         expected_data.extend_from_slice(b"swap2");
         assert!(verify(&expected_data, sig, &coord100_id.public_key));

         // Swap should be removed from active list
         assert!(!coordinator.active_swaps.contains_key("swap2"));
     }

     // Test using the combined handler
     #[test]
     fn coordinator_process_proof_and_finalize_commit() {
         // Create consistent coordinator identities for the test
         let (coord100_id, coord100_key) = create_test_tee(100);
         let (coord101_id, _) = create_test_tee(101);
         let (coord102_id, _) = create_test_tee(102);
         let coordinator_identities = vec![coord100_id.clone(), coord101_id.clone(), coord102_id.clone()];

         let (shard0_id, shard0_key) = create_test_tee(0);
         let (shard1_id, shard1_key) = create_test_tee(1);

         // Pass identities to config creation
         let config = create_test_config(Some(coordinator_identities.clone()));
         let mock_network = Arc::new(MockNetwork::default());
         let mut coordinator = CrossChainCoordinator::new(
             coord100_id.clone(), // Use consistent ID
             coord100_key,     // Use consistent key
             config,
             Arc::clone(&mock_network) as Arc<dyn NetworkInterface + Send + Sync>,
             HashMap::new()
         );
         let tx = create_dummy_swap_tx("swap4");
         let shards: HashSet<usize> = [0, 1].into_iter().collect();
         coordinator.initiate_swap(tx.clone(), shards.clone());

         let proof0 = create_dummy_lock_proof("swap4", 0, &shard0_id, &shard0_key);
         let proof1 = create_dummy_lock_proof("swap4", 1, &shard1_id, &shard1_key);

         // Process first proof - should return None
         let maybe_decision0 = coordinator.process_proof_and_finalize(proof0);
         assert!(maybe_decision0.is_none());
         assert!(coordinator.active_swaps.contains_key("swap4")); // Still active

         // Process second proof - should return Some(CommitDecision)
         let maybe_decision1 = coordinator.process_proof_and_finalize(proof1);
         assert!(maybe_decision1.is_some());
         let decision = maybe_decision1.unwrap();
         assert_eq!(decision.tx_id, "swap4");
         assert!(decision.commit);

         // Verify network messages (CoordPartialSig should have been sent)
         let sent_messages = mock_network.get_sent_messages();
         // Peers are 101, 102
         let expected_peers = 2;
         assert_eq!(sent_messages.len(), expected_peers, "Incorrect number of CoordPartialSig messages sent");
         for msg in sent_messages.iter() {
             assert_eq!(msg.sender.id, coord100_id.id);
             assert!(msg.receiver == coord101_id || msg.receiver == coord102_id);
             match &msg.message {
                 Message::CoordPartialSig { tx_id, commit, signature } => {
                     assert_eq!(tx_id, "swap4");
                     assert_eq!(*commit, true);
                     let mut expected_data = b"RELEASE".to_vec();
                     expected_data.extend_from_slice(b"swap4");
                     // Add borrow for signature_data
                     assert!(verify(&expected_data, &signature.signature_data, &coord100_id.public_key));
                 }
                 _ => panic!("Unexpected message type sent: {:?}", msg.message),
             }
         }

         // Verify signature in the final decision
         // let decision_opt = coordinator.finalize_decision("swap4", true); // No need to call again
         // assert!(decision_opt.is_some());
         // let decision = decision_opt.unwrap(); // Decision already returned by process_proof_and_finalize
         assert_eq!(decision.tx_id, "swap4");
         assert_eq!(decision.commit, true);
         assert_eq!(decision.signature.len(), 1);
         let (signer_pk, sig) = &decision.signature[0];
         assert_eq!(signer_pk, &coord100_id.public_key);
         let mut expected_data = b"RELEASE".to_vec();
         expected_data.extend_from_slice(b"swap4");
         assert!(verify(&expected_data, sig, &coord100_id.public_key));

         // Swap should be removed from active list
         assert!(!coordinator.active_swaps.contains_key("swap4"));
     }


     #[test]
     fn coordinator_handle_lock_proof_fail_verification() {
         let (coord_id, coord_key) = create_test_tee(100);
         let (shard0_id, shard0_key) = create_test_tee(0);
         let config = create_test_config(None);
         let network = Arc::new(MockNetwork::default()); // Use default() for instantiation
         let mut coordinator = CrossChainCoordinator::new(coord_id.clone(), coord_key, config, network, HashMap::new());
         let tx = create_dummy_swap_tx("swap3");
         let shards: HashSet<usize> = [0].into_iter().collect();
         coordinator.initiate_swap(tx.clone(), shards.clone());

         let mut bad_proof = create_dummy_lock_proof("swap3", 0, &shard0_id, &shard0_key);
         // Create an invalid signature by signing different data
         let other_key = generate_keypair(); // Need a key
         let bad_sig_data = sign(b"different data", &other_key); // Sign wrong data
         bad_proof.attestation_or_sig = bad_sig_data; // Replace signature

         // Handle the bad proof
         let res = coordinator.handle_lock_proof(bad_proof); // bad_proof moved here
         assert!(res.is_err());
         assert_eq!(res.unwrap_err(), AbortReason::LockProofVerificationFailed);

         // Swap should still exist but be marked as Aborted
         assert!(coordinator.active_swaps.contains_key("swap3"), "Swap should still exist after failed verification");
         let swap_state = coordinator.active_swaps.get("swap3").unwrap();
         assert!(matches!(swap_state.status, SwapStatus::Aborted(AbortReason::LockProofVerificationFailed)), "Swap status should be Aborted");

         // The ABORT signing flow is tested implicitly via process_proof_and_finalize_abort
         // and check_timeouts tests.

     }

      // Test signing abort after failure using combined handler
     #[test]
     fn coordinator_process_proof_and_finalize_abort() {
         // Create consistent coordinator identities for the test
         let (coord100_id, coord100_key) = create_test_tee(100);
         let (coord101_id, _) = create_test_tee(101);
         let (coord102_id, _) = create_test_tee(102);
         let coordinator_identities = vec![coord100_id.clone(), coord101_id.clone(), coord102_id.clone()];

         let (shard0_id, shard0_key) = create_test_tee(0);
         // Pass identities to config creation
         let config = create_test_config(Some(coordinator_identities.clone()));
         let mock_network = Arc::new(MockNetwork::default());
         let mut coordinator = CrossChainCoordinator::new(
             coord100_id.clone(), // Use consistent ID
             coord100_key,     // Use consistent key
             config,
             Arc::clone(&mock_network) as Arc<dyn NetworkInterface + Send + Sync>,
             HashMap::new()
         );
         let tx = create_dummy_swap_tx("swap5");
         let shards: HashSet<usize> = [0].into_iter().collect();
         coordinator.initiate_swap(tx.clone(), shards.clone());

         let mut bad_proof = create_dummy_lock_proof("swap5", 0, &shard0_id, &shard0_key);
         let other_key = generate_keypair();
         bad_proof.attestation_or_sig = sign(b"tampered", &other_key);

         // Process bad proof - should now return Some(AbortDecision)
         let maybe_decision = coordinator.process_proof_and_finalize(bad_proof);
         assert!(maybe_decision.is_some());
         let decision = maybe_decision.unwrap();
         assert_eq!(decision.tx_id, "swap5");
         assert!(!decision.commit); // Should be ABORT

         // Verify network messages (CoordPartialSig for ABORT should have been sent)
         let sent_messages = mock_network.get_sent_messages();
         // Peers are 101, 102
         let expected_peers = 2;
         assert_eq!(sent_messages.len(), expected_peers, "Incorrect number of CoordPartialSig messages sent");
         for msg in sent_messages.iter() {
             assert_eq!(msg.sender.id, coord100_id.id);
             assert!(msg.receiver == coord101_id || msg.receiver == coord102_id);
             match &msg.message {
                 Message::CoordPartialSig { tx_id, commit, signature } => {
                     assert_eq!(tx_id, "swap5");
                     assert_eq!(*commit, false); // Check for ABORT flag
                     let mut expected_data = b"ABORT".to_vec(); // Check ABORT message
                     expected_data.extend_from_slice(b"swap5");
                     // Add borrow for signature_data
                     assert!(verify(&expected_data, &signature.signature_data, &coord100_id.public_key));
                 }
                 _ => panic!("Unexpected message type sent: {:?}", msg.message),
             }
         }

         // Verify signature in the final decision
         // let decision_opt = coordinator.finalize_decision("swap5", false); // No need to call again
         // assert!(decision_opt.is_some());
         // let decision = decision_opt.unwrap(); // Decision already returned by process_proof_and_finalize
         assert_eq!(decision.tx_id, "swap5");
         assert_eq!(decision.commit, false);
         assert_eq!(decision.signature.len(), 1);
         let (signer_pk, sig) = &decision.signature[0];
         assert_eq!(signer_pk, &coord100_id.public_key);
         let mut expected_data = b"ABORT".to_vec();
         expected_data.extend_from_slice(b"swap5");
         assert!(verify(&expected_data, sig, &coord100_id.public_key));

         // Swap should be removed from active list
         assert!(!coordinator.active_swaps.contains_key("swap5"));
     }

    #[test]
    fn coordinator_check_timeouts() {
        // Create consistent coordinator identities for the test
        let (coord100_id, coord100_key) = create_test_tee(100);
        let (coord101_id, _) = create_test_tee(101);
        let (coord102_id, _) = create_test_tee(102);
        let coordinator_identities = vec![coord100_id.clone(), coord101_id.clone(), coord102_id.clone()];

        // Pass identities to config creation
        let mut config = create_test_config(Some(coordinator_identities.clone()));
        let mock_network = Arc::new(MockNetwork::default());

        // Create a transaction with a very short timeout
        let short_timeout = Duration::from_millis(50);
        let tx_timeout = Transaction {
           tx_id: "swap_timeout".to_string(),
           tx_type: TxType::CrossChainSwap,
           accounts: vec![],
           amounts: vec![],
           required_locks: vec![], // Keep simple
           timeout: short_timeout, // Use short timeout
       };

        // Pass mock network clone to coordinator
        let mut coordinator = CrossChainCoordinator::new(
            coord100_id.clone(), // Use consistent ID
            coord100_key,     // Use consistent key
            config.clone(),
            Arc::clone(&mock_network) as Arc<dyn NetworkInterface + Send + Sync>,
            HashMap::new()
        );

       coordinator.initiate_swap(tx_timeout, HashSet::new());
       assert_eq!(coordinator.active_swaps.len(), 1);

       // Check timeouts immediately - should do nothing
       let decisions = coordinator.check_timeouts();
       assert!(decisions.is_empty(), "Should not finalize yet");

       // Wait for longer than the timeout
       std::thread::sleep(short_timeout + Duration::from_millis(10)); // Wait slightly longer

       // Check timeouts again - should now abort and return decision
       let decisions_after_timeout = coordinator.check_timeouts();
       assert_eq!(decisions_after_timeout.len(), 1, "Expected 1 timed out decision");
       let decision = &decisions_after_timeout[0];
       assert_eq!(decision.tx_id, "swap_timeout");
       assert!(!decision.commit); // Should be ABORT

       // Verify network messages (CoordPartialSig for ABORT should have been sent)
       let sent_messages = mock_network.get_sent_messages();
       // Peers are 101, 102
       let expected_peers = 2;
       assert_eq!(sent_messages.len(), expected_peers, "Incorrect number of CoordPartialSig messages sent for timeout");
       for msg in sent_messages.iter() {
           assert_eq!(msg.sender.id, coord100_id.id);
           assert!(msg.receiver == coord101_id || msg.receiver == coord102_id);
           match &msg.message {
               Message::CoordPartialSig { tx_id, commit, signature } => {
                   assert_eq!(tx_id, "swap_timeout");
                   assert_eq!(*commit, false); // Check for ABORT flag
                   let mut expected_data = b"ABORT".to_vec(); // Check ABORT message
                   expected_data.extend_from_slice(b"swap_timeout");
                   // Add borrow for signature_data
                   assert!(verify(&expected_data, &signature.signature_data, &coord100_id.public_key));
               }
               _ => panic!("Unexpected message type sent: {:?}", msg.message),
           }
       }

       // Verify signature in the returned decision
       assert_eq!(decision.signature.len(), 1);
       let (signer_pk, sig) = &decision.signature[0];
       assert_eq!(signer_pk, &coord100_id.public_key);
       let mut expected_data = b"ABORT".to_vec();
       expected_data.extend_from_slice(b"swap_timeout");
       assert!(verify(&expected_data, sig, &coord100_id.public_key));

       // Swap should be removed from active list after finalization
       assert!(!coordinator.active_swaps.contains_key("swap_timeout"));
    }

    // Helper function for the dispatcher logic in multi-coordinator tests
    fn dispatch_messages(
        coordinators: &HashMap<TEEIdentity, Arc<Mutex<CrossChainCoordinator>>>,
        shared_mock_network: &Arc<MockNetwork> // Use concrete MockNetwork to call retrieve
    ) {
        for (coord_id, coord_arc) in coordinators {
            // Retrieve messages specifically for this coordinator from the mock network
            let messages = shared_mock_network.retrieve_messages_for(coord_id);
            if !messages.is_empty() {
                // Lock the specific coordinator to process its messages
                let mut coordinator = coord_arc.lock().unwrap();
                for network_msg in messages {
                     println!(" Dispatcher: Routing {:?} to {}", network_msg.message, coord_id.id);
                     match network_msg.message {
                         Message::CoordPartialSig { tx_id, commit, signature } => {
                             // Call the handler on the coordinator instance
                            if let Err(e) = coordinator.handle_partial_signature(signature, &tx_id, commit) {
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

    #[test]
    fn test_multi_coordinator_signing() {
        // 1. Setup - Identities & Config
        let (coord100_id, coord100_key) = create_test_tee(100);
        let (coord101_id, coord101_key) = create_test_tee(101);
        let (coord102_id, coord102_key) = create_test_tee(102);
        let coordinator_identities = vec![coord100_id.clone(), coord101_id.clone(), coord102_id.clone()];

        // Use a config with threshold 2 for this test
        let mut config = SystemConfig::default();
        config.coordinator_identities = coordinator_identities.clone();
        config.coordinator_threshold = 2;
        config.nodes_per_shard = 2; // Keep consistent

        let shard_assignments = HashMap::new(); // Keep simple, no lock requests needed here
        let mock_network = Arc::new(MockNetwork::default());

        // 2. Create Coordinators
        let mut coordinators = HashMap::new();
        coordinators.insert(coord100_id.clone(), Arc::new(Mutex::new(CrossChainCoordinator::new(
            coord100_id.clone(), coord100_key, config.clone(), Arc::clone(&mock_network) as Arc<_>, shard_assignments.clone()
        ))));
        coordinators.insert(coord101_id.clone(), Arc::new(Mutex::new(CrossChainCoordinator::new(
            coord101_id.clone(), coord101_key, config.clone(), Arc::clone(&mock_network) as Arc<_>, shard_assignments.clone()
        ))));
        coordinators.insert(coord102_id.clone(), Arc::new(Mutex::new(CrossChainCoordinator::new(
            coord102_id.clone(), coord102_key, config.clone(), Arc::clone(&mock_network) as Arc<_>, shard_assignments.clone()
        ))));

        // 3. Initiate Swap & Add First Signature
        let tx_id = "multi_swap";
        let tx = create_dummy_swap_tx(tx_id);
        {
            let mut coord100 = coordinators.get(&coord100_id).unwrap().lock().unwrap();
            coord100.initiate_swap(tx, HashSet::new()); // Initiate (ignore LockRequests for this test)
            coord100.add_local_signature_share(tx_id, true).expect("Coord 100 failed to add share");
        } // Release lock

        // **Crucial Fix**: Ensure all coordinators know about the swap *before* processing signatures
        let initial_swap_state_template = { // Get structure from initiator
             let coord100 = coordinators.get(&coord100_id).unwrap().lock().unwrap();
             coord100.active_swaps.get(tx_id).expect("Swap should exist in initiator").clone()
         };
        for i in 1..coordinator_identities.len() { // Iterate over 101, 102
            let coord_id = &coordinator_identities[i];
            let coord_mutex = coordinators.get(coord_id).unwrap();
            let mut coordinator = coord_mutex.lock().unwrap();

            // Create the swap state if it doesn't exist
            if !coordinator.active_swaps.contains_key(tx_id) {
                 println!("Coordinator [{}]: Manually adding initial state for swap {}", coord_id.id, tx_id);
                 let mut new_state = initial_swap_state_template.clone(); // Clone basic structure

                 // Explicitly create new, empty aggregators with correct context
                 use crate::tee_logic::crypto_sim::PublicKey; // For PublicKey type
                 use std::collections::HashSet; // For HashSet type
                 let all_coordinator_pks: HashSet<PublicKey> = config.coordinator_identities.iter()
                                                                    .map(|id| id.public_key)
                                                                    .collect();

                 new_state.release_aggregator = Some(ThresholdAggregator::new(
                     &CrossChainCoordinator::prepare_decision_message(tx_id, true),
                     config.coordinator_threshold,
                 ));
                 new_state.abort_aggregator = Some(ThresholdAggregator::new(
                     &CrossChainCoordinator::prepare_decision_message(tx_id, false),
                     config.coordinator_threshold,
                 ));

                 coordinator.active_swaps.insert(tx_id.to_string(), new_state);
            }
        }

        // 4. Simulate Dispatcher - Round 1
        // Coord 100 sent its share to 101 and 102
        println!("--- Dispatcher Round 1 ---");
        dispatch_messages(&coordinators, &mock_network);

        // 5. Add Second Signature
        {
            let mut coord101 = coordinators.get(&coord101_id).unwrap().lock().unwrap();
            // It received 100's share. Now add its own.
            assert!(coord101.active_swaps.contains_key(tx_id));
            let release_agg = coord101.active_swaps[tx_id].release_aggregator.as_ref().expect("Aggregator missing");
            assert_eq!(release_agg.signature_count(), 1, "Coord 101 should have 1 sig after dispatch");
            coord101.add_local_signature_share(tx_id, true).expect("Coord 101 failed to add share");
            // It should now have 2 signatures and reach threshold
             let release_agg_after = coord101.active_swaps[tx_id].release_aggregator.as_ref().expect("Aggregator missing");
             assert_eq!(release_agg_after.signature_count(), 2, "Coord 101 should have 2 sigs after adding its own");
             assert!(release_agg_after.has_reached_threshold(), "Coord 101 aggregator should have reached threshold");
        } // Release lock

        // 6. Simulate Dispatcher - Round 2
        // Coord 101 sent its share to 100 and 102
        println!("--- Dispatcher Round 2 ---");
        dispatch_messages(&coordinators, &mock_network);


        // 7. Finalize and Verify
        // Check Coord 100 (Received 101's sig, now has 2)
        {
            let coord100 = coordinators.get(&coord100_id).unwrap().lock().unwrap();
            let decision100 = coord100.finalize_decision(tx_id, true);
            assert!(decision100.is_some(), "Coord 100 failed to finalize");
            assert_eq!(decision100.as_ref().unwrap().signature.len(), 2, "Coord 100 final sig count mismatch"); // Threshold is 2
        }
        // Check Coord 101 (Added its own, has 2)
        {
            let coord101 = coordinators.get(&coord101_id).unwrap().lock().unwrap();
             let decision101 = coord101.finalize_decision(tx_id, true);
            assert!(decision101.is_some(), "Coord 101 failed to finalize");
             assert_eq!(decision101.as_ref().unwrap().signature.len(), 2, "Coord 101 final sig count mismatch");
        }
         // Check Coord 102 (Received 100's and 101's sigs, has 2)
        {
             let coord102 = coordinators.get(&coord102_id).unwrap().lock().unwrap();
             let release_agg = coord102.active_swaps[tx_id].release_aggregator.as_ref().expect("Aggregator missing");
             assert_eq!(release_agg.signature_count(), 2, "Coord 102 should have 2 sigs after dispatch");
             let decision102 = coord102.finalize_decision(tx_id, true);
             assert!(decision102.is_some(), "Coord 102 failed to finalize");
             assert_eq!(decision102.as_ref().unwrap().signature.len(), 2, "Coord 102 final sig count mismatch");
        }
    }

} // end tests mod 