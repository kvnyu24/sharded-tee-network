use std::collections::HashMap;
use std::time::Duration;

// Assuming TxType is defined elsewhere, e.g., crate::data_structures::TxType
// We'll need to make TxType Hashable and Eq later if not already.
use crate::data_structures::TxType; // Placeholder import
use crate::data_structures::TEEIdentity; // Added TEEIdentity
use crate::tee_logic::crypto_sim::generate_keypair; // For default TEE identities
use crate::liveness::types::LivenessConfig; // Need import for LivenessConfig

#[derive(Clone, Debug)]
pub struct SystemConfig {
    // General
    pub num_shards: usize,
    pub tee_threshold: usize, // Threshold for TEE signatures/consensus

    // Sharding / Partitioning
    pub max_iterations: usize, // Max iterations for shard refinement
    pub node_weight_alpha: f64, // Tuning constant for node weight calculation
    pub edge_weight_config: HashMap<TxType, f64>, // Weights for different tx types in partitioning
    pub partition_overload_threshold: f64, // Threshold for detecting overloaded shards
    // Define how TEEs are assigned, e.g., fixed number per shard
    pub nodes_per_shard: usize,

    // Raft Consensus (within shards)
    pub raft_heartbeat_ms: u64,
    pub raft_election_timeout_min_ms: u64,
    pub raft_election_timeout_max_ms: u64,

    // Cross-Chain Swaps
    pub cross_chain_swap_timeout_ms: u64, // Timeout for lock proof aggregation
    pub num_coordinators: usize,          // Number of TEEs coordinating a single swap

    // TEE Liveness Verification
    pub liveness_default_trust: f64,
    pub liveness_trust_increment: f64,
    pub liveness_trust_decrement: f64,
    pub liveness_trust_threshold: f64,       // Below this, check more often
    pub liveness_high_trust_threshold: f64,  // Above this, check less often
    pub liveness_min_interval_ms: u64,       // Fastest check interval
    pub liveness_max_interval_ms: u64,       // Slowest check interval
    pub liveness_max_consecutive_fails: usize, // Max failures before isolation

    // Network Simulation / Assumptions
    pub network_delay_range_ms: (u64, u64), // Min/Max simulated network delay

    // Required number of coordinator signatures for cross-chain decisions (multi-sig)
    pub coordinator_threshold: usize,

    // List of TEEs designated as coordinators
    pub coordinator_identities: Vec<TEEIdentity>,
}

// Helper function to create TEEIdentity for default config
fn create_default_tee(id: usize) -> TEEIdentity {
    let keypair = generate_keypair();
    TEEIdentity { id, public_key: keypair.verifying_key() }
}

impl Default for SystemConfig {
    fn default() -> Self {
        let mut edge_weights = HashMap::new();
        edge_weights.insert(TxType::SingleChainTransfer, 1.0);
        edge_weights.insert(TxType::CrossChainSwap, 5.0); // Cross-chain edges are more 'expensive'

        SystemConfig {
            // General
            num_shards: 3,
            tee_threshold: 2, // Requires 2 out of N TEEs to sign/agree

            // Sharding
            max_iterations: 10,
            node_weight_alpha: 0.5,
            edge_weight_config: edge_weights,
            partition_overload_threshold: 1.5, // e.g., 50% over average load
            nodes_per_shard: 3, // Assign 3 TEE nodes to each shard by default

            // Raft
            raft_heartbeat_ms: 100,
            raft_election_timeout_min_ms: 150,
            raft_election_timeout_max_ms: 300,

            // Cross-Chain
            cross_chain_swap_timeout_ms: 5000, // 5 seconds
            num_coordinators: 3, // Use 3 TEEs for coordination (threshold is tee_threshold)

            // Liveness
            liveness_default_trust: 100.0,
            liveness_trust_increment: 1.0,
            liveness_trust_decrement: 10.0,
            liveness_trust_threshold: 50.0,
            liveness_high_trust_threshold: 150.0,
            liveness_min_interval_ms: 1000, // 1 second
            liveness_max_interval_ms: 10000, // 10 seconds
            liveness_max_consecutive_fails: 5,

            // Network
            network_delay_range_ms: (10, 50),

            // Threshold for coordinator multi-signatures (e.g., 2 out of 3)
            coordinator_threshold: 2, // Set default to 2 (matches default tee_threshold)

            // Default coordinator identities
            coordinator_identities: vec![
                create_default_tee(100),
                create_default_tee(101),
                create_default_tee(102),
            ],
        }
    }
}

// Helper struct to convert SystemConfig to LivenessConfig
impl From<&SystemConfig> for LivenessConfig {
    fn from(sys_config: &SystemConfig) -> Self {
        // --- Calculate challenge_window based on heartbeat --- 
        let heartbeat_duration = Duration::from_millis(sys_config.raft_heartbeat_ms);
        // Set window to e.g., 10x heartbeat interval, minimum 500ms?
        let calculated_window = heartbeat_duration * 10; 
        let min_window = Duration::from_millis(500); // Ensure a minimum reasonable window
        let challenge_window = calculated_window.max(min_window);
        println!("[Config] Calculated Liveness Challenge Window: {:?} (based on {:?} heartbeat)", 
                 challenge_window, heartbeat_duration);
        // --- End calculation --- 
        
        LivenessConfig {
            default_trust: sys_config.liveness_default_trust,
            trust_increment: sys_config.liveness_trust_increment,
            trust_decrement: sys_config.liveness_trust_decrement,
            trust_threshold: sys_config.liveness_trust_threshold,
            high_trust_threshold: sys_config.liveness_high_trust_threshold,
            min_interval: Duration::from_millis(sys_config.liveness_min_interval_ms),
            max_interval: Duration::from_millis(sys_config.liveness_max_interval_ms),
            max_failures: sys_config.liveness_max_consecutive_fails,
            // Remove hardcoded value
            // challenge_window: Duration::from_secs(10), 
            challenge_window, // Use calculated value
        }
    }
}

// Unit test to ensure config creation and default values
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SystemConfig::default();
        assert_eq!(config.num_shards, 3);
        assert_eq!(config.tee_threshold, 2);
        assert_eq!(config.max_iterations, 10);
        assert_eq!(config.raft_heartbeat_ms, 100);
        assert_eq!(config.network_delay_range_ms, (10, 50));
        assert_eq!(config.edge_weight_config.get(&TxType::CrossChainSwap), Some(&5.0));
        assert_eq!(config.liveness_max_consecutive_fails, 5);
        assert_eq!(config.nodes_per_shard, 3);
        assert_eq!(config.coordinator_threshold, 2);
        assert_eq!(config.coordinator_identities.len(), 3);
        assert_eq!(config.coordinator_identities[0].id, 100);
        // Add more checks for other default fields
    }
} 