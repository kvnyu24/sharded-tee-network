use crate::config::SystemConfig; // Import SystemConfig
// Import TeeDelayConfig
use crate::tee_logic::enclave_sim::TeeDelayConfig;

// Configuration specific to the simulation environment and experiments
// Removed Serialize, Deserialize, PartialEq temporarily due to missing derives in members
#[derive(Debug, Clone)]
pub struct SimulationConfig {
    // Base system configuration used by simulated components
    pub system_config: SystemConfig,

    // Simulation-specific parameters
    pub num_shards: usize,
    pub nodes_per_shard: usize,
    pub num_coordinators: usize,
    pub coordinator_threshold: usize,

    // Network simulation parameters
    pub network_min_delay_ms: u64,
    pub network_max_delay_ms: u64,
    pub network_drop_rate: f64,

    // TEE performance overhead simulation
    // pub tee_sign_delay_ms: u64,
    // pub tee_verify_delay_ms: u64,
    // pub tee_attest_delay_ms: u64,
    // Replace individual delays with the TeeDelayConfig struct
    pub tee_delays: TeeDelayConfig,

    // Workload generation
    pub total_transactions: usize,
    // pub transaction_rate_per_sec: f64,
    pub tx_mix: Vec<(crate::data_structures::TxType, f64)>, // (Type, Percentage)

    // Liveness simulation parameters (can override SystemConfig ones if needed)
    // pub liveness_check_interval_ms: u64,

    // Failure scenarios
    // pub node_failure_rate: f64,
    // pub coordinator_failure_rate: f64,
    // pub network_partition_config: Option<...>,

    // Logging and output
    pub log_level: log::LevelFilter,
    // pub output_metrics_file: Option<String>,

    // Interval for the network emulation queue processing task
    pub network_tick_interval_ms: Option<u64>,

    // Add other simulation-specific parameters as needed
    // E.g., duration of the simulation run
    pub simulation_duration_secs: Option<u64>,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        // Use SystemConfig default as a base
        let base_config = SystemConfig::default();

        SimulationConfig {
            system_config: base_config.clone(), // Clone base config

            // Simulation params often mirror SystemConfig, but can be overridden
            num_shards: base_config.num_shards,
            nodes_per_shard: base_config.nodes_per_shard,
            num_coordinators: base_config.num_coordinators,
            coordinator_threshold: base_config.coordinator_threshold,

            network_min_delay_ms: base_config.network_delay_range_ms.0,
            network_max_delay_ms: base_config.network_delay_range_ms.1,
            network_drop_rate: 0.0, // Default to no packet drops

            // Use default TEE delays from SystemConfig
            tee_delays: base_config.tee_delays.clone(),

            // Default workload
            total_transactions: 100,
            tx_mix: vec![
                (crate::data_structures::TxType::SingleChainTransfer, 0.7),
                (crate::data_structures::TxType::CrossChainSwap, 0.3),
            ],

            log_level: log::LevelFilter::Info,

            network_tick_interval_ms: Some(5), // Default queue check interval
            // Simulation Run Duration Default (None = run until total transactions)
            simulation_duration_secs: None,
        }
    }
}

impl SimulationConfig {
    /// Convenience method to update the internal SystemConfig from simulation parameters.
    /// Call this after modifying simulation parameters if they should reflect in the SystemConfig.
    pub fn sync_system_config(&mut self) {
        self.system_config.num_shards = self.num_shards;
        self.system_config.nodes_per_shard = self.nodes_per_shard;
        self.system_config.num_coordinators = self.num_coordinators;
        self.system_config.coordinator_threshold = self.coordinator_threshold;
        self.system_config.network_delay_range_ms = (self.network_min_delay_ms, self.network_max_delay_ms);
        self.system_config.tee_delays = self.tee_delays.clone();
        // Sync other relevant fields as needed
    }
} 