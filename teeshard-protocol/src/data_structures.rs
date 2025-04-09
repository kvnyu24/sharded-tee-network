use std::hash::{Hash, Hasher};
// Import the PublicKey type
use crate::tee_logic::crypto_sim::PublicKey; // VerifyingKey re-exported as PublicKey
// Import HashSet which was removed by cargo fix
use std::collections::HashSet;

// Represent a user account on some chain
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct AccountId {
    pub chain_id: u64,
    pub address: String, // Using String for simplicity, could be H160 or similar fixed-size type
}

// Represent a specific asset on a specific chain
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct AssetId {
    pub chain_id: u64,
    pub token_symbol: String, // e.g., "ETH", "USDC"
    pub token_address: String, // e.g., "0x..."
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
#[derive(Clone, Debug, PartialEq)]
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
    // Asset to be released or acted upon on the target chain (for CrossChainSwap)
    pub target_asset: Option<AssetId>, // Added target asset info
    pub timeout: std::time::Duration, // Added timeout duration
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
// Now using a real cryptographic public key type
#[derive(Clone, Debug)]
pub struct TEEIdentity {
    pub id: usize, // Simple numeric ID for now
    // pub public_key: Vec<u8>, // Placeholder for cryptographic key material
    pub public_key: PublicKey,
}

// Implement PartialEq manually because PublicKey doesn't derive Eq fully (uses constant time eq)
impl PartialEq for TEEIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.public_key == other.public_key
    }
}

// Implement Eq manually
impl Eq for TEEIdentity {}

// Implement Hash manually using the public key bytes
impl Hash for TEEIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.public_key.as_bytes().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*; // Import items from the parent module (data_structures)
    use crate::tee_logic::crypto_sim::generate_keypair;

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
        let asset_eth = AssetId { chain_id: 1, token_symbol: "ETH".to_string(), token_address: "0x...".to_string() };
        let asset_usdc = AssetId { chain_id: 1, token_symbol: "USDC".to_string(), token_address: "0x...".to_string() };
        let asset_matic = AssetId { chain_id: 2, token_symbol: "MATIC".to_string(), token_address: "0x...".to_string() };

        assert_eq!(asset_eth.chain_id, 1);
        assert_eq!(asset_usdc.token_symbol, "USDC");
        assert_ne!(asset_eth, asset_matic);
    }

    #[test]
    fn lock_info_creation() {
        let acc1 = AccountId { chain_id: 1, address: "addr1".to_string() };
        let asset1 = AssetId { chain_id: 1, token_symbol: "ETH".to_string(), token_address: "0x...".to_string() };
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
        let asset_a = AssetId { chain_id: 1, token_symbol: "AAA".to_string(), token_address: "0x...".to_string() };
        let asset_b = AssetId { chain_id: 2, token_symbol: "BBB".to_string(), token_address: "0x...".to_string() };

        let lock1 = LockInfo { account: acc_a1.clone(), asset: asset_a.clone(), amount: 50 };
        let lock2 = LockInfo { account: acc_b1.clone(), asset: asset_b.clone(), amount: 30 };

        let tx_cross = Transaction {
            tx_id: "tx2".to_string(),
            tx_type: TxType::CrossChainSwap,
            accounts: vec![acc_a1.clone(), acc_a2.clone(), acc_b1.clone(), acc_b2.clone()],
            amounts: vec![50, 30], // e.g., 50 units from a1->a2, 30 units from b1->b2
            required_locks: vec![lock1.clone(), lock2.clone()],
            target_asset: Some(asset_b.clone()),
            timeout: std::time::Duration::from_secs(0),
        };

        assert_eq!(tx_cross.tx_type, TxType::CrossChainSwap);
        assert_eq!(tx_cross.accounts.len(), 4);
        assert_eq!(tx_cross.required_locks.len(), 2);
        assert_eq!(tx_cross.required_locks[0], lock1);
        assert_eq!(tx_cross.required_locks[1], lock2);
        assert_eq!(tx_cross.target_asset, Some(asset_b));
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
        let keypair1 = generate_keypair();
        let keypair2 = generate_keypair();
        let tee1 = TEEIdentity { id: 1, public_key: keypair1.verifying_key() };
        let tee2 = TEEIdentity { id: 1, public_key: keypair1.verifying_key() }; // Same ID and Key
        let tee3 = TEEIdentity { id: 2, public_key: keypair2.verifying_key() }; // Different ID and Key
        let tee4 = TEEIdentity { id: 1, public_key: keypair2.verifying_key() }; // Same ID, different Key

        assert_eq!(tee1, tee2);
        assert_ne!(tee1, tee3);
        assert_ne!(tee1, tee4);
        assert_eq!(tee1.id, 1);
        assert_eq!(tee3.public_key.as_bytes(), keypair2.verifying_key().as_bytes());

        let mut set = HashSet::new();
        set.insert(tee1.clone());
        set.insert(tee2.clone()); // Dupe
        set.insert(tee3.clone());
        set.insert(tee4.clone()); // Different key, should be added
        assert_eq!(set.len(), 3);
        assert!(set.contains(&tee1));
        assert!(set.contains(&tee3));
        assert!(set.contains(&tee4));
    }
} 