use crate::config::SystemConfig;
use crate::data_structures::{AccountId, Transaction, GraphNode, GraphEdge, TEEIdentity, TxType, AssetId};
use std::collections::{HashMap, HashSet};
use crate::tee_logic::crypto_sim::generate_keypair;

// Represents the mapping from AccountId to shard ID
pub type PartitionMapping = HashMap<AccountId, usize>;

// Represents a single shard after partitioning
#[derive(Clone, Debug, Default)]
pub struct ShardPartition {
    pub shard_id: usize,
    pub accounts: HashSet<AccountId>,
    pub tee_nodes: Vec<TEEIdentity>,
    pub load_metric: f64,
}

// Manages the partitioning of the transaction graph into shards
#[derive(Debug)]
pub struct ShardManager {
    pub config: SystemConfig,
    pub partitions: Vec<ShardPartition>,
    pub account_to_shard: PartitionMapping,
    pub graph_nodes: HashMap<AccountId, GraphNode>,
    pub graph_edges: Vec<GraphEdge>,
    unique_accounts: Vec<AccountId>,
}

impl ShardManager {
    pub fn new(config: SystemConfig) -> Self {
        ShardManager {
            config,
            partitions: Vec::new(),
            account_to_shard: HashMap::new(),
            graph_nodes: HashMap::new(),
            graph_edges: Vec::new(),
            unique_accounts: Vec::new(),
        }
    }

    // Algorithm 1, Step 1 & 2: Build graph and assign weights
    pub fn construct_and_weight_graph(&mut self, txs: &[Transaction]) {
        println!("Constructing and weighting graph for {} transactions...", txs.len());
        self.graph_nodes.clear();
        self.graph_edges.clear();
        self.unique_accounts.clear();

        let mut account_tx_counts: HashMap<AccountId, usize> = HashMap::new();
        let mut edges_set: HashSet<(AccountId, AccountId)> = HashSet::new();

        // Step 1: Collect accounts and edges
        for tx in txs {
            for acc in &tx.accounts {
                *account_tx_counts.entry(acc.clone()).or_insert(0) += 1;
            }
            match tx.tx_type {
                TxType::SingleChainTransfer => {
                    if tx.accounts.len() >= 2 {
                        let from = &tx.accounts[0];
                        let to = &tx.accounts[1];
                        if edges_set.insert((from.clone(), to.clone())) {
                             let weight = tx.amounts.first().copied().unwrap_or(0) as f64
                                 * self.config.edge_weight_config.get(&tx.tx_type).copied().unwrap_or(1.0);
                             self.graph_edges.push(GraphEdge {
                                src: from.clone(), dst: to.clone(), edge_weight: weight,
                            });
                        }
                    }
                }
                TxType::CrossChainSwap => {
                    if tx.accounts.len() >= 4 {
                        let a1 = &tx.accounts[0];
                        let a2 = &tx.accounts[1];
                        let b1 = &tx.accounts[2];
                        let b2 = &tx.accounts[3];
                        let weight_a = tx.amounts.get(0).copied().unwrap_or(0) as f64
                            * self.config.edge_weight_config.get(&tx.tx_type).copied().unwrap_or(1.0);
                        let weight_b = tx.amounts.get(1).copied().unwrap_or(0) as f64
                            * self.config.edge_weight_config.get(&tx.tx_type).copied().unwrap_or(1.0);
                        if edges_set.insert((a1.clone(), a2.clone())) {
                            self.graph_edges.push(GraphEdge {
                                src: a1.clone(), dst: a2.clone(), edge_weight: weight_a
                            });
                        }
                         if edges_set.insert((b1.clone(), b2.clone())) {
                             self.graph_edges.push(GraphEdge {
                                src: b1.clone(), dst: b2.clone(), edge_weight: weight_b
                            });
                        }
                    }
                }
            }
        }
        // Step 2: Create GraphNodes and assign weights
        self.unique_accounts = account_tx_counts.keys().cloned().collect();
        for acc in &self.unique_accounts {
            let freq = *account_tx_counts.get(acc).unwrap_or(&0) as f64;
            let bal_factor = 1.0f64;
            let asset_variety_factor = 1.0f64;
            let weight = freq * bal_factor * asset_variety_factor.powf(self.config.node_weight_alpha);
            self.graph_nodes.insert(acc.clone(), GraphNode {
                account: acc.clone(), node_weight: weight,
            });
        }
         println!("Graph constructed: {} nodes, {} edges", self.graph_nodes.len(), self.graph_edges.len());
    }

    // Algorithm 1, Step 3 (Initial Partitioning - Placeholder)
    pub fn initial_partition(&mut self) {
        println!("Performing placeholder initial partitioning into {} shards...", self.config.num_shards);
        self.partitions.clear();
        self.account_to_shard.clear();
        if self.unique_accounts.is_empty() || self.config.num_shards == 0 {
             println!("Cannot partition: No accounts or zero shards specified.");
            return;
        }
        self.partitions = (0..self.config.num_shards)
            .map(|i| ShardPartition { shard_id: i, ..Default::default() })
            .collect();
        for (idx, account) in self.unique_accounts.iter().enumerate() {
            let shard_id = idx % self.config.num_shards;
            if let Some(partition) = self.partitions.get_mut(shard_id) {
                partition.accounts.insert(account.clone());
                partition.load_metric += self.graph_nodes.get(account).map_or(0.0, |n| n.node_weight);
                self.account_to_shard.insert(account.clone(), shard_id);
            }
        }
        println!("Initial Partitioning complete:");
        self.print_partition_loads();
    }

    // Algorithm 1, Step 3 (Iterative Refinement - Simple Placeholder)
    pub fn iterative_refine(&mut self) {
        println!("Performing simple iterative refinement ({} iterations)...", self.config.max_iterations);
        if self.partitions.len() < 2 || self.config.max_iterations == 0 {
            println!("Skipping refinement: Not enough partitions or max_iterations is 0.");
            return;
        }

        for iter in 0..self.config.max_iterations {
            // 1. Find most and least loaded shards
            let Some((most_loaded_idx, least_loaded_idx)) = self.find_most_least_loaded_shards() else {
                println!("Refinement Iter {}: Could not find distinct most/least loaded shards. Stopping.", iter + 1);
                break;
            };

            // Basic check for load difference - avoid trivial moves
            let most_load = self.partitions[most_loaded_idx].load_metric;
            let least_load = self.partitions[least_loaded_idx].load_metric;
            if most_load <= least_load || (most_load - least_load) < 1e-6 { // Check for significant difference
                println!("Refinement Iter {}: Load difference insignificant or balanced. Stopping.", iter + 1);
                break;
            }

             println!("Refinement Iter {}: Most loaded Shard {} (Load: {:.2}), Least loaded Shard {} (Load: {:.2})",
                      iter + 1, self.partitions[most_loaded_idx].shard_id, most_load, self.partitions[least_loaded_idx].shard_id, least_load);

            // 2. Find heaviest node in the most loaded shard
            let Some((heaviest_node_acc, node_weight)) = self.find_heaviest_node_in_shard(most_loaded_idx) else {
                 println!("Refinement Iter {}: Most loaded shard {} is empty? Stopping.", iter + 1, self.partitions[most_loaded_idx].shard_id);
                break; // Should not happen if load > 0
            };

             println!("Refinement Iter {}: Attempting to move node {:?} (Weight: {:.2}) from Shard {} to Shard {}",
                      iter + 1, heaviest_node_acc.address, node_weight, self.partitions[most_loaded_idx].shard_id, self.partitions[least_loaded_idx].shard_id);

            // 3. Move the node
            // Update account_to_shard mapping
            let target_shard_id = self.partitions[least_loaded_idx].shard_id;
            self.account_to_shard.insert(heaviest_node_acc.clone(), target_shard_id);

            // Update partitions (accounts and load metrics)
            let node_to_move = self.partitions[most_loaded_idx].accounts.take(&heaviest_node_acc)
                .expect("Node to move must exist in the source shard's account set");
            self.partitions[least_loaded_idx].accounts.insert(node_to_move);

            self.partitions[most_loaded_idx].load_metric -= node_weight;
            self.partitions[least_loaded_idx].load_metric += node_weight;

            println!("Refinement Iter {}: Move complete.", iter + 1);
            self.print_partition_loads(); // Print loads after each move

            // Optional: Check overload threshold after move - more complex logic needed here
            // let avg_load = self.calculate_average_load();
            // let overload_limit = avg_load * self.config.partition_overload_threshold;
            // if self.partitions[least_loaded_idx].load_metric > overload_limit {
            //     println!("Warning: Move caused target shard {} to become overloaded.", target_shard_id);
            //     // Consider reverting or alternative strategy
            // }
        }
        println!("Iterative refinement finished.");
    }

    // Helper to find indices of most and least loaded shards
    fn find_most_least_loaded_shards(&self) -> Option<(usize, usize)> {
        if self.partitions.len() < 2 {
            return None;
        }
        let mut min_load = f64::MAX;
        let mut max_load = f64::MIN;
        let mut min_idx = 0;
        let mut max_idx = 0;

        for (idx, partition) in self.partitions.iter().enumerate() {
            if partition.load_metric < min_load {
                min_load = partition.load_metric;
                min_idx = idx;
            }
            if partition.load_metric > max_load {
                max_load = partition.load_metric;
                max_idx = idx;
            }
        }

        // Ensure they are distinct indices unless all loads are identical
        if max_idx == min_idx && self.partitions.windows(2).all(|w| (w[0].load_metric - w[1].load_metric).abs() < 1e-6) {
            None // All loads are effectively the same
        } else {
            Some((max_idx, min_idx))
        }
    }

    // Helper to find the account with the highest weight in a given shard partition
    fn find_heaviest_node_in_shard(&self, shard_idx: usize) -> Option<(AccountId, f64)> {
        self.partitions.get(shard_idx)?
            .accounts
            .iter()
            .filter_map(|acc| self.graph_nodes.get(acc).map(|node| (acc.clone(), node.node_weight)))
            .max_by(|(_, w1), (_, w2)| w1.partial_cmp(w2).unwrap_or(std::cmp::Ordering::Equal))
    }

    // Helper to print current partition loads
    fn print_partition_loads(&self) {
        for p in &self.partitions {
            println!("  Load - Shard {}: {} accounts, Load: {:.2}", p.shard_id, p.accounts.len(), p.load_metric);
        }
    }

    // Algorithm 1, Step 5 (Assigning TEEs - Using previous placeholder)
    pub fn assign_tee_nodes(&mut self, all_available_tees: &[TEEIdentity]) {
        println!("Assigning TEE nodes ({} available, {} per shard target)...",
                 all_available_tees.len(), self.config.nodes_per_shard);
        if self.partitions.is_empty() {
             println!("No partitions exist to assign TEE nodes to.");
            return;
        }
        let mut tee_iter = all_available_tees.iter();
        for partition in self.partitions.iter_mut() {
            partition.tee_nodes.clear();
            for _ in 0..self.config.nodes_per_shard {
                if let Some(tee) = tee_iter.next() {
                    partition.tee_nodes.push(tee.clone());
                } else {
                    eprintln!("Warning: Ran out of TEE nodes while assigning to shard {}. Requested {} per shard.",
                              partition.shard_id, self.config.nodes_per_shard);
                    break;
                }
            }
             println!("  Shard {}: Assigned {} TEE nodes ({:?})",
                      partition.shard_id, partition.tee_nodes.len(), partition.tee_nodes.iter().map(|t|t.id).collect::<Vec<_>>());
        }
    }

     // Helper to get the shard for a given account
    pub fn get_shard_for_account(&self, account: &AccountId) -> Option<&ShardPartition> {
        self.account_to_shard.get(account)
            .and_then(|shard_id| self.partitions.get(*shard_id))
    }

    // Helper function to create AssetId for testing
    fn create_test_asset(chain_id: u64, symbol: &str) -> AssetId {
        AssetId {
            chain_id,
            token_symbol: symbol.to_string(),
            token_address: format!("0x{}_ADDRESS", symbol), // Use a derived placeholder
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_structures::{AssetId, LockInfo};

    fn create_test_config() -> SystemConfig {
        let mut cfg = SystemConfig::default();
        cfg.num_shards = 2;
        cfg.nodes_per_shard = 2;
        cfg.max_iterations = 3; // Allow multiple refinement iterations
        cfg
    }

    fn create_test_tees(count: usize) -> Vec<TEEIdentity> {
        (0..count).map(|i| {
            let keypair = generate_keypair();
            TEEIdentity { id: i, public_key: keypair.verifying_key() }
        }).collect()
    }

    fn create_test_account(chain_id: u64, addr_id: usize) -> AccountId {
        AccountId { chain_id, address: format!("addr{}", addr_id) }
    }

    fn create_test_asset(chain_id: u64, symbol: &str) -> AssetId {
        AssetId {
            chain_id,
            token_symbol: symbol.to_string(),
            token_address: format!("0x{}_ADDRESS", symbol), // Use a derived placeholder
        }
    }

    // Simplified transactions for refinement test
    fn create_refinement_transactions() -> Vec<Transaction> {
        let acc_a = create_test_account(1, 1); // High weight target (Expect 5)
        let acc_b = create_test_account(1, 2); // Expect 2
        let acc_c = create_test_account(1, 3); // Expect 2
        let acc_d = create_test_account(1, 4); // Expect 1
        // Define E, F - though not strictly needed if A is source
        let _acc_e = create_test_account(1, 5);
        let _acc_f = create_test_account(1, 6);

        // Transactions designed to give weights A=5, B=2, C=2, D=1
        vec![
            Transaction { tx_id: "t1".into(), tx_type: TxType::SingleChainTransfer, accounts: vec![acc_a.clone(), acc_b.clone()], amounts: vec![10], required_locks: vec![], timeout: std::time::Duration::from_secs(60), target_asset: None },
            Transaction { tx_id: "t2".into(), tx_type: TxType::SingleChainTransfer, accounts: vec![acc_a.clone(), acc_c.clone()], amounts: vec![10], required_locks: vec![], timeout: std::time::Duration::from_secs(60), target_asset: None },
            Transaction { tx_id: "t3".into(), tx_type: TxType::SingleChainTransfer, accounts: vec![acc_a.clone(), acc_d.clone()], amounts: vec![10], required_locks: vec![], timeout: std::time::Duration::from_secs(60), target_asset: None },
             Transaction { tx_id: "t4".into(), tx_type: TxType::SingleChainTransfer, accounts: vec![acc_a.clone(), acc_b.clone()], amounts: vec![10], required_locks: vec![], timeout: std::time::Duration::from_secs(60), target_asset: None }, // A and B again
             Transaction { tx_id: "t5".into(), tx_type: TxType::SingleChainTransfer, accounts: vec![acc_a.clone(), acc_c.clone()], amounts: vec![10], required_locks: vec![], timeout: std::time::Duration::from_secs(60), target_asset: None }, // A and C again
        ]
    }

    #[test]
    fn test_iterative_refinement() {
        let config = create_test_config(); // 2 shards, 3 iterations
        let mut manager = ShardManager::new(config.clone());
        let transactions = create_refinement_transactions();

        manager.construct_and_weight_graph(&transactions);
        // Assert nodes exist (count might be 4 if E, F aren't sinks)
        assert!(manager.graph_nodes.len() >= 4);
        let acc_a = create_test_account(1, 1);
        let acc_b = create_test_account(1, 2);
        let acc_c = create_test_account(1, 3);
        let acc_d = create_test_account(1, 4);
        // Assert the weights expected by the test setup
        assert_eq!(manager.graph_nodes.get(&acc_a).unwrap().node_weight, 5.0);
        assert_eq!(manager.graph_nodes.get(&acc_b).unwrap().node_weight, 2.0);
        assert_eq!(manager.graph_nodes.get(&acc_c).unwrap().node_weight, 2.0);
        assert_eq!(manager.graph_nodes.get(&acc_d).unwrap().node_weight, 1.0);

        // Initial Partition
        manager.initial_partition();
        assert_eq!(manager.partitions.len(), 2);
        assert_eq!(manager.account_to_shard.len(), 4);
        let total_load: f64 = manager.partitions.iter().map(|p| p.load_metric).sum();
        assert!((total_load - 10.0).abs() < 1e-6); // Total weight = 5+2+2+1 = 10.0

        // Determine initial shard for the heavy node 'A'
        let initial_shard_a = *manager.account_to_shard.get(&acc_a).expect("Node A must be assigned");
        let other_shard = if initial_shard_a == 0 { 1 } else { 0 };
        println!("Initial state: Node A in Shard {}, Other Shard is {}", initial_shard_a, other_shard);
        println!("Initial loads: Shard 0={:.2}, Shard 1={:.2}", manager.partitions[0].load_metric, manager.partitions[1].load_metric);

        // Iterative Refinement (1st iteration should move A to the *other* shard)
        manager.iterative_refine();
        let shard_a_after_1_iter = *manager.account_to_shard.get(&acc_a).expect("Node A must be assigned");
        assert_eq!(shard_a_after_1_iter, other_shard, "Node A should have moved to the other shard after 1st iteration");
        let total_load_after_1: f64 = manager.partitions.iter().map(|p| p.load_metric).sum();
        assert!((total_load_after_1 - 10.0).abs() < 1e-6, "Total load changed after 1st iteration");
        println!("After 1 iter: Node A in Shard {}, Loads: Shard 0={:.2}, Shard 1={:.2}",
                 shard_a_after_1_iter, manager.partitions[0].load_metric, manager.partitions[1].load_metric);

        // Run refine again - should oscillate back (move A back to its original shard)
        manager.iterative_refine();
        let shard_a_after_2_iter = *manager.account_to_shard.get(&acc_a).expect("Node A must be assigned");
        assert_eq!(shard_a_after_2_iter, initial_shard_a, "Node A should have moved back to its original shard after 2nd iteration");
         let total_load_after_2: f64 = manager.partitions.iter().map(|p| p.load_metric).sum();
        assert!((total_load_after_2 - 10.0).abs() < 1e-6, "Total load changed after 2nd iteration");
        println!("After 2 iter: Node A in Shard {}, Loads: Shard 0={:.2}, Shard 1={:.2}",
                 shard_a_after_2_iter, manager.partitions[0].load_metric, manager.partitions[1].load_metric);
    }

    // ... (create_sample_transactions and shard_manager_full_flow_placeholder as before) ...
    fn create_sample_transactions() -> Vec<Transaction> {
        let acc_a1 = create_test_account(1, 1);
        let acc_a2 = create_test_account(1, 2);
        let acc_a3 = create_test_account(1, 3);
        let acc_b1 = create_test_account(2, 1);
        let acc_b2 = create_test_account(2, 2);
        let asset_a = create_test_asset(1, "AAA");
        let asset_b = create_test_asset(2, "BBB");
        vec![
            Transaction { tx_id: "tx1".to_string(), tx_type: TxType::SingleChainTransfer, accounts: vec![acc_a1.clone(), acc_a2.clone()], amounts: vec![10], required_locks: vec![], timeout: std::time::Duration::from_secs(60), target_asset: None },
            Transaction { tx_id: "tx2".to_string(), tx_type: TxType::SingleChainTransfer, accounts: vec![acc_a2.clone(), acc_a3.clone()], amounts: vec![50], required_locks: vec![], timeout: std::time::Duration::from_secs(60), target_asset: None },
            Transaction { 
                tx_id: "tx3".to_string(), 
                tx_type: TxType::CrossChainSwap, 
                accounts: vec![acc_a1.clone(), acc_a2.clone(), acc_b1.clone(), acc_b2.clone()], 
                amounts: vec![200, 300], 
                required_locks: vec![ 
                    LockInfo { account: acc_a1.clone(), asset: asset_a.clone(), amount: 200 }, 
                    LockInfo { account: acc_b1.clone(), asset: asset_b.clone(), amount: 300 }, 
                ], 
                timeout: std::time::Duration::from_secs(60), 
                target_asset: Some(asset_b.clone()) // Corrected: Set target asset for swap
            },
            Transaction { tx_id: "tx4".to_string(), tx_type: TxType::SingleChainTransfer, accounts: vec![acc_a1.clone(), acc_a3.clone()], amounts: vec![75], required_locks: vec![], timeout: std::time::Duration::from_secs(60), target_asset: None },
        ]
    }
    #[test]
    fn shard_manager_full_flow_placeholder() {
        let config = create_test_config();
        let mut manager = ShardManager::new(config.clone());
        let transactions = create_sample_transactions();
        let available_tees = create_test_tees(5);
        manager.construct_and_weight_graph(&transactions);
        assert_eq!(manager.graph_nodes.len(), 5);
        assert_eq!(manager.graph_edges.len(), 4);
        assert_eq!(manager.unique_accounts.len(), 5);
        assert_eq!(manager.graph_nodes.get(&create_test_account(1, 1)).unwrap().node_weight, 3.0);
        assert_eq!(manager.graph_nodes.get(&create_test_account(1, 2)).unwrap().node_weight, 3.0);
        assert_eq!(manager.graph_nodes.get(&create_test_account(1, 3)).unwrap().node_weight, 2.0);
        assert_eq!(manager.graph_nodes.get(&create_test_account(2, 1)).unwrap().node_weight, 1.0);
        assert_eq!(manager.graph_nodes.get(&create_test_account(2, 2)).unwrap().node_weight, 1.0);
        manager.initial_partition();
        assert_eq!(manager.partitions.len(), config.num_shards);
        assert_eq!(manager.account_to_shard.len(), 5);
        let total_accounts_in_partitions: usize = manager.partitions.iter().map(|p| p.accounts.len()).sum();
        assert_eq!(total_accounts_in_partitions, 5);
        assert!(!manager.partitions[0].accounts.is_empty());
        assert!(!manager.partitions[1].accounts.is_empty());
        let acc_a1 = create_test_account(1, 1);
        let shard_a1 = manager.get_shard_for_account(&acc_a1).expect("a1 should be assigned");
        assert!(shard_a1.shard_id == 0 || shard_a1.shard_id == 1);
        // Iterative Refine (Now implemented - check if loads change)
        let loads_before: Vec<_> = manager.partitions.iter().map(|p| p.load_metric).collect();
        manager.iterative_refine();
        let loads_after: Vec<_> = manager.partitions.iter().map(|p| p.load_metric).collect();
        // In this specific round-robin assignment, refinement might happen depending on node order
        // We only assert that the sum of loads remains constant
        let sum_before: f64 = loads_before.iter().sum();
        let sum_after: f64 = loads_after.iter().sum();
        assert!((sum_before - sum_after).abs() < 1e-6, "Total load changed during refinement");
        // Optionally, assert if loads actually changed or not based on predictable scenario
        // assert_ne!(loads_before, loads_after, "Loads should have changed due to refinement");
        manager.assign_tee_nodes(&available_tees);
         assert_eq!(manager.partitions.len(), config.num_shards);
         let total_assigned_tees: usize = manager.partitions.iter().map(|p| p.tee_nodes.len()).sum();
         assert_eq!(total_assigned_tees, 4);
         assert_eq!(manager.partitions[0].tee_nodes.len(), config.nodes_per_shard);
         assert_eq!(manager.partitions[1].tee_nodes.len(), config.nodes_per_shard);
         assert_eq!(manager.partitions[0].tee_nodes[0].id, 0);
         assert_eq!(manager.partitions[0].tee_nodes[1].id, 1);
         assert_eq!(manager.partitions[1].tee_nodes[0].id, 2);
         assert_eq!(manager.partitions[1].tee_nodes[1].id, 3);
    }
    // ... (rest of existing tests: shard_partition_creation, shard_manager_new, assign_tee_nodes_*) ...
     #[test]
    fn shard_partition_creation() {
        let keypair1 = generate_keypair();
        let tee1 = TEEIdentity { id: 1, public_key: keypair1.verifying_key() };
        let acc1 = create_test_account(1, 1);
        let acc2 = create_test_account(1, 2);
        let mut accounts = HashSet::new();
        accounts.insert(acc1.clone());
        accounts.insert(acc2.clone());
        let partition = ShardPartition {
            shard_id: 0,
            accounts: accounts.clone(),
            tee_nodes: vec![tee1.clone()],
            load_metric: 0.0,
        };
        assert_eq!(partition.shard_id, 0);
        assert_eq!(partition.accounts.len(), 2);
        assert!(partition.accounts.contains(&acc1));
        assert_eq!(partition.tee_nodes.len(), 1);
        assert_eq!(partition.tee_nodes[0], tee1);
    }
    #[test]
    fn shard_manager_new() {
        let config = create_test_config();
        let manager = ShardManager::new(config.clone());
        assert_eq!(manager.config.num_shards, config.num_shards);
        assert!(manager.partitions.is_empty());
        assert!(manager.account_to_shard.is_empty());
    }
    #[test]
    fn shard_manager_assign_tee_nodes_sufficient() {
        let config = create_test_config(); // nodes_per_shard = 2, num_shards = 2
        let mut manager = ShardManager::new(config.clone());
        let available_tees = create_test_tees(5); // Need 4, have 5
        manager.partitions = (0..config.num_shards).map(|i| ShardPartition {
            shard_id: i,
             ..Default::default()
        }).collect();
        manager.assign_tee_nodes(&available_tees);
        assert_eq!(manager.partitions.len(), config.num_shards);
        for partition in &manager.partitions {
            assert_eq!(partition.tee_nodes.len(), config.nodes_per_shard);
            let ids: HashSet<usize> = partition.tee_nodes.iter().map(|t| t.id).collect();
            assert_eq!(ids.len(), config.nodes_per_shard);
        }
        let total_assigned: usize = manager.partitions.iter().map(|p| p.tee_nodes.len()).sum();
        assert_eq!(total_assigned, 4);
    }
     #[test]
    fn shard_manager_assign_tee_nodes_insufficient() {
        let mut config = create_test_config();
        config.num_shards = 3; // 3 shards
        config.nodes_per_shard = 2; // 2 per shard -> Need 6 total
        let mut manager = ShardManager::new(config.clone());
        let available_tees = create_test_tees(5); // Only 5 available
        manager.partitions = (0..config.num_shards).map(|i| ShardPartition {
            shard_id: i,
            ..Default::default()
        }).collect();
        manager.assign_tee_nodes(&available_tees);
        let total_assigned: usize = manager.partitions.iter().map(|p| p.tee_nodes.len()).sum();
        assert_eq!(total_assigned, 5);
        assert_eq!(manager.partitions[0].tee_nodes.len(), 2);
        assert_eq!(manager.partitions[1].tee_nodes.len(), 2);
        assert_eq!(manager.partitions[2].tee_nodes.len(), 1); // Last shard gets remaining node
    }
} 