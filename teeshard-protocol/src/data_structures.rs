use std::hash::{Hash, Hasher};
use std::collections::HashSet;

// Represent a user account on some chain
#[derive(Clone, Debug, Eq)]
pub struct AccountId {
    pub chain_id: u64,
    pub address: String, // Using String for simplicity, could be H160 or similar fixed-size type
}

// Implement PartialEq manually because of String
impl PartialEq for AccountId {
    fn eq(&self, other: &Self) -> bool {
        self.chain_id == other.chain_id && self.address == other.address
    }
}

// Implement Hash manually
impl Hash for AccountId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.chain_id.hash(state);
        self.address.hash(state);
    }
}

// Represent a specific asset on a specific chain
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AssetId {
    pub chain_id: u64,
    pub token_symbol: String, // e.g., "ETH", "USDC"
}

// Information about a required lock for a transaction
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LockInfo {
    pub account: AccountId,
    pub asset: AssetId,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TxType {
    SingleChainTransfer,
    CrossChainSwap,
    // Add other transaction types as needed
}

// Represent a single transaction
#[derive(Clone, Debug)]
pub struct Transaction {
    pub tx_id: String, // Unique transaction identifier
    pub tx_type: TxType,
    // Involved accounts - interpretation depends on TxType
    // For SingleChain: [from, to]
    // For CrossChain: [from_chain_a, to_chain_a, from_chain_b, to_chain_b]
    pub accounts: Vec<AccountId>,
    // Corresponding amounts
    pub amounts: Vec<u64>,
    // List of resources that must be locked for this transaction to proceed (esp. for CrossChainSwap)
    pub required_locks: Vec<LockInfo>,
    // Add other transaction details like timestamps, nonces, etc.
}

// Weighted graph node representation for partitioning
#[derive(Clone, Debug)]
pub struct GraphNode {
    pub account: AccountId,
    pub node_weight: f64, // Represents activity or balance, influencing partitioning
}

// Weighted graph edge representation for partitioning
#[derive(Clone, Debug)]
pub struct GraphEdge {
    pub src: AccountId,
    pub dst: AccountId,
    pub edge_weight: f64, // Represents interaction frequency or volume
}

// Represents a TEE Node Identity
// Could include public key, attestation details, etc. later
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TEEIdentity {
    pub id: usize, // Simple numeric ID for now
    pub public_key: Vec<u8>, // Placeholder for cryptographic key material
}

#[cfg(test)]
mod tests {
    use super::*; // Import items from the parent module (data_structures)
    use std::collections::HashSet;

    #[test]
    fn account_id_equality_and_hash() {
        let acc1 = AccountId { chain_id: 1, address: "addr1".to_string() };
        let acc2 = AccountId { chain_id: 1, address: "addr1".to_string() };
        let acc3 = AccountId { chain_id: 2, address: "addr1".to_string() };
        let acc4 = AccountId { chain_id: 1, address: "addr2".to_string() };

        assert_eq!(acc1, acc2);
        assert_ne!(acc1, acc3);
        assert_ne!(acc1, acc4);
        assert_ne!(acc3, acc4);

        let mut set = HashSet::new();
        set.insert(acc1.clone());
        set.insert(acc2.clone()); // Should not increase set size
        set.insert(acc3.clone());
        set.insert(acc4.clone());

        assert!(set.contains(&acc1));
        assert!(set.contains(&acc2));
        assert!(set.contains(&acc3));
        assert!(set.contains(&acc4));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn asset_id_creation() {
        let asset_eth = AssetId { chain_id: 1, token_symbol: "ETH".to_string() };
        let asset_usdc = AssetId { chain_id: 1, token_symbol: "USDC".to_string() };
        let asset_matic = AssetId { chain_id: 2, token_symbol: "MATIC".to_string() };

        assert_eq!(asset_eth.chain_id, 1);
        assert_eq!(asset_usdc.token_symbol, "USDC");
        assert_ne!(asset_eth, asset_matic);
    }

    #[test]
    fn lock_info_creation() {
        let acc1 = AccountId { chain_id: 1, address: "addr1".to_string() };
        let asset1 = AssetId { chain_id: 1, token_symbol: "ETH".to_string() };
        let lock = LockInfo {
            account: acc1.clone(),
            asset: asset1.clone(),
            amount: 100,
        };
        assert_eq!(lock.account, acc1);
        assert_eq!(lock.asset, asset1);
        assert_eq!(lock.amount, 100);
    }

    #[test]
    fn transaction_creation_with_locks() {
        let acc_a1 = AccountId { chain_id: 1, address: "a1".to_string() };
        let acc_a2 = AccountId { chain_id: 1, address: "a2".to_string() };
        let acc_b1 = AccountId { chain_id: 2, address: "b1".to_string() };
        let acc_b2 = AccountId { chain_id: 2, address: "b2".to_string() };
        let asset_a = AssetId { chain_id: 1, token_symbol: "AAA".to_string() };
        let asset_b = AssetId { chain_id: 2, token_symbol: "BBB".to_string() };

        let lock1 = LockInfo { account: acc_a1.clone(), asset: asset_a.clone(), amount: 50 };
        let lock2 = LockInfo { account: acc_b1.clone(), asset: asset_b.clone(), amount: 30 };

        let tx_cross = Transaction {
            tx_id: "tx2".to_string(),
            tx_type: TxType::CrossChainSwap,
            accounts: vec![acc_a1.clone(), acc_a2.clone(), acc_b1.clone(), acc_b2.clone()],
            amounts: vec![50, 30], // e.g., 50 units from a1->a2, 30 units from b1->b2
            required_locks: vec![lock1.clone(), lock2.clone()],
        };

        assert_eq!(tx_cross.tx_type, TxType::CrossChainSwap);
        assert_eq!(tx_cross.accounts.len(), 4);
        assert_eq!(tx_cross.required_locks.len(), 2);
        assert_eq!(tx_cross.required_locks[0], lock1);
        assert_eq!(tx_cross.required_locks[1], lock2);
    }

     #[test]
    fn graph_structs_creation() {
        let acc1 = AccountId { chain_id: 1, address: "addr1".to_string() };
        let acc2 = AccountId { chain_id: 1, address: "addr2".to_string() };

        let node1 = GraphNode {
            account: acc1.clone(),
            node_weight: 10.5,
        };

        let edge1 = GraphEdge {
            src: acc1.clone(),
            dst: acc2.clone(),
            edge_weight: 5.0,
        };

        assert_eq!(node1.account, acc1);
        assert_eq!(node1.node_weight, 10.5);
        assert_eq!(edge1.src, acc1);
        assert_eq!(edge1.dst, acc2);
        assert_eq!(edge1.edge_weight, 5.0);
    }

    #[test]
    fn tee_identity_creation() {
        let tee1 = TEEIdentity { id: 1, public_key: vec![1, 2, 3] };
        let tee2 = TEEIdentity { id: 1, public_key: vec![1, 2, 3] };
        let tee3 = TEEIdentity { id: 2, public_key: vec![4, 5, 6] };

        assert_eq!(tee1, tee2);
        assert_ne!(tee1, tee3);
        assert_eq!(tee1.id, 1);
        assert_eq!(tee3.public_key, vec![4, 5, 6]);

        let mut set = HashSet::new();
        set.insert(tee1.clone());
        set.insert(tee2.clone()); // Dupe
        set.insert(tee3.clone());
        assert_eq!(set.len(), 2);
        assert!(set.contains(&tee1));
        assert!(set.contains(&tee3));
    }
} 