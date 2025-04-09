// teeshard-protocol/src/simulation/runtime.rs
use crate::data_structures::TEEIdentity;
use crate::raft::messages::RaftMessage;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use futures;

/// Manages the simulated network and nodes.
/// Cloning this struct allows multiple components (nodes, coordinator) to interact with the runtime.
#[derive(Clone)]
pub struct SimulationRuntime {
    // Store sender channels keyed by node ID for routing messages
    // The channel now sends a tuple: (sender_identity, message)
    node_channels: Arc<Mutex<HashMap<usize, mpsc::Sender<(TEEIdentity, RaftMessage)>>>>,
    // Store identities for lookup when broadcasting
    node_identities: Arc<Mutex<HashMap<usize, TEEIdentity>>>,
    // TODO: Potentially add channels for coordinator communication, event logging, etc.
}

impl SimulationRuntime {
    /// Creates a new simulation runtime.
    pub fn new() -> Self {
        SimulationRuntime {
            node_channels: Arc::new(Mutex::new(HashMap::new())),
            node_identities: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Registers a node's communication channel and identity with the runtime.
    pub fn register_node(&self, identity: TEEIdentity, sender: mpsc::Sender<(TEEIdentity, RaftMessage)>) {
        let mut channels = self.node_channels.lock().unwrap();
        let mut identities = self.node_identities.lock().unwrap();
        println!("[Runtime] Registering node {}.", identity.id);
        channels.insert(identity.id, sender);
        identities.insert(identity.id, identity);
    }

    /// Sends a message to a specific node, including the sender's identity.
    pub async fn route_message(&self, sender_identity: TEEIdentity, target_node_id: usize, message: RaftMessage) {
        let sender_channel = {
            let channels = self.node_channels.lock().unwrap();
            channels.get(&target_node_id).cloned()
        };

        if let Some(tx) = sender_channel {
            println!("[Runtime] Routing message from {} to {}: {:?}", sender_identity.id, target_node_id, message);
            // Send the tuple (sender_identity, message)
            if let Err(e) = tx.send((sender_identity, message)).await {
                eprintln!("[Runtime] Failed to send message to node {}: {}. Channel likely closed.", target_node_id, e);
            }
        } else {
            eprintln!("[Runtime] Warning: No channel registered for target node {}. Dropping message.", target_node_id);
        }
    }

    /// Sends a message to all registered nodes except the sender.
    pub async fn broadcast_message(&self, sender_identity: TEEIdentity, message: RaftMessage) {
        // Collect channels outside the lock to avoid holding the guard across awaits
        let channels_to_send: Vec<_> = {
            let channels_map = self.node_channels.lock().unwrap();
            channels_map.iter()
                .filter(|(node_id, _)| **node_id != sender_identity.id)
                .map(|(node_id, tx)| (*node_id, tx.clone())) // Clone senders needed
                .collect()
        };

        let mut send_futures = Vec::new();

        for (node_id_clone, sender_clone) in channels_to_send {
            let message_clone = message.clone();
            let sender_identity_clone = sender_identity.clone(); // Clone sender identity

            send_futures.push(tokio::spawn(async move {
                // Send the tuple (sender_identity, message)
                if let Err(e) = sender_clone.send((sender_identity_clone, message_clone)).await {
                    eprintln!("[Runtime] Broadcast failed for node {}: {}", node_id_clone, e);
                }
            }));
        }
        futures::future::join_all(send_futures).await;
    }

    // TODO: Add methods for coordinator interaction, logging, etc.
} 