use std::collections::HashMap;

// Assuming TxType is defined elsewhere, e.g., crate::data_structures::TxType
// We'll need to make TxType Hashable and Eq later if not already.
use crate::data_structures::TxType; // Placeholder import

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
        // Add more checks for other default fields
    }
} 