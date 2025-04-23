// teeshard-protocol/src/test_utils.rs
// NOTE: Moved from tests/test_utils.rs

use crate::{ // Changed from teeshard_protocol:: to crate:: as it's now part of the lib
    data_structures::{TEEIdentity, Transaction, AccountId, AssetId, LockInfo, TxType},
    simulation::metrics::MetricEvent,
};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use ed25519_dalek::{SigningKey, VerifyingKey}; // Directly import needed types
use rand::Rng;
use log::warn;
use hex;

// Helper function to create deterministic keys for testing
pub fn create_test_tee_signing(id: usize) -> (TEEIdentity, SigningKey) {
    let seed = [(id % 256) as u8; 32];
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key: VerifyingKey = signing_key.verifying_key(); // Explicit type
    (TEEIdentity { id, public_key: verifying_key }, signing_key)
}

/// Generates a sample transaction for testing purposes.
pub fn generate_test_transaction(
    tx_index: usize,
    is_cross_chain: bool,
    num_blockchains: usize,
) -> (Transaction, [u8; 32]) { // Return the raw bytes32 ID as well
    // Generate a unique but deterministic byte array ID based on index
    let mut tx_id_bytes = [0u8; 32];
    let index_bytes = tx_index.to_be_bytes();
    // Place index bytes at the end for uniqueness, pad with a prefix
    tx_id_bytes[0] = if is_cross_chain { 0xCC } else { 0x5C }; // 'CC' or 'SC'
    let start = 32 - index_bytes.len();
    tx_id_bytes[start..].copy_from_slice(&index_bytes);
    let tx_id_hex = hex::encode(&tx_id_bytes); // Hex encode the bytes

    let source_chain_id = (tx_index % num_blockchains) as u64;
    let target_chain_id = if is_cross_chain {
        ((tx_index + 1) % num_blockchains) as u64
    } else {
        source_chain_id
    };

    let acc_a1 = AccountId { chain_id: source_chain_id, address: format!("user_a_{}", tx_index) };
    let acc_a2 = AccountId { chain_id: source_chain_id, address: format!("pool_{}", source_chain_id) };
    let asset_a = AssetId { chain_id: source_chain_id, token_symbol: format!("TKA{}", source_chain_id), token_address: format!("0xA{}", source_chain_id) };

    let mut mock_swap_id = [0u8; 32];
    let num_bytes = (tx_index as u64).to_be_bytes();
    let start_index = mock_swap_id.len() - num_bytes.len();
    mock_swap_id[start_index..].copy_from_slice(&num_bytes);

    if is_cross_chain && source_chain_id != target_chain_id {
        let acc_b1 = AccountId { chain_id: target_chain_id, address: format!("user_b_{}", tx_index) };
        let acc_b2 = AccountId { chain_id: target_chain_id, address: format!("pool_{}", target_chain_id) };
        let asset_b = AssetId { chain_id: target_chain_id, token_symbol: format!("TKB{}", target_chain_id), token_address: format!("0xB{}", target_chain_id) };
        let tx = Transaction {
            tx_id: tx_id_hex, // Use the hex-encoded string ID
            tx_type: TxType::CrossChainSwap,
            accounts: vec![acc_a1.clone(), acc_a2, acc_b1.clone(), acc_b2],
            amounts: vec![100, 50], // Example amounts
            required_locks: vec![
                LockInfo { account: acc_a1, asset: asset_a.clone(), amount: 100 },
                LockInfo { account: acc_b1, asset: asset_b.clone(), amount: 50 },
            ],
            target_asset: Some(asset_b), // Target asset for the swap
            timeout: Duration::from_secs(300),
        };
        (tx, mock_swap_id)
    } else {
        let tx = Transaction {
            tx_id: tx_id_hex, // Use the hex-encoded string ID
            tx_type: TxType::SingleChainTransfer,
            accounts: vec![acc_a1.clone(), acc_a2],
            amounts: vec![100],
            required_locks: vec![LockInfo { account: acc_a1, asset: asset_a, amount: 100 }],
            target_asset: None,
            timeout: Duration::from_secs(300),
        };
        (tx, mock_swap_id)
    }
}

// --- Enhanced Performance Analysis Function ---
pub fn analyze_perf_results(
    scenario_name: &str,
    scenario_params: &HashMap<String, String>,
    metrics: &[MetricEvent],
    submitted_count: usize,
    submission_duration: Duration,
) {
    let mut latencies_cc = Vec::new();
    let mut latencies_sc = Vec::new();
    let mut completed_count = 0;
    let mut successful_count_cc = 0;
    let mut successful_count_sc = 0;

    // Separate latencies based on is_cross_chain flag
    for event in metrics {
        if let MetricEvent::TransactionCompleted { start_time: _ , end_time: _, success, is_cross_chain, duration, .. } = event {
            completed_count += 1;
            if *success {
                let latency_micros = duration.as_micros(); // Use pre-calculated duration
                if *is_cross_chain {
                    successful_count_cc += 1;
                    latencies_cc.push(latency_micros);
                } else {
                    successful_count_sc += 1;
                    latencies_sc.push(latency_micros);
                }
            }
        }
        // Extract other relevant metrics based on scenario (e.g., Raft, TEE) if needed later
    }

    latencies_cc.sort_unstable();
    latencies_sc.sort_unstable();

    let calculate_stats = |latencies: &[u128]| -> (f64, u128, u128) {
        if latencies.is_empty() { return (0.0, 0, 0); }
        let avg = latencies.iter().sum::<u128>() as f64 / latencies.len() as f64;
        // Ensure index calculation doesn't panic on empty or single-element slices
        let p95_idx = ((latencies.len() as f64 * 0.95).floor() as usize).min(latencies.len().saturating_sub(1));
        let p99_idx = ((latencies.len() as f64 * 0.99).floor() as usize).min(latencies.len().saturating_sub(1));
        let p95 = latencies.get(p95_idx).copied().unwrap_or(avg as u128);
        let p99 = latencies.get(p99_idx).copied().unwrap_or(avg as u128);
        (avg, p95, p99)
    };


    let (avg_lat_cc, p95_lat_cc, p99_lat_cc) = calculate_stats(&latencies_cc);
    let (avg_lat_sc, p95_lat_sc, p99_lat_sc) = calculate_stats(&latencies_sc);

    let throughput_tps = if submission_duration > Duration::ZERO { // Use tps acronym
        completed_count as f64 / submission_duration.as_secs_f64()
    } else { 0.0 };

    println!("
--- {} Analysis (Params: {:?}) ---", scenario_name, scenario_params);
    println!("Submitted Transactions: {}", submitted_count);
    println!("Completed Transactions: {}", completed_count);
    println!("  Successful Cross-Chain: {} ({} samples)", successful_count_cc, latencies_cc.len());
    println!("  Successful Single-Chain: {} ({} samples)", successful_count_sc, latencies_sc.len());
    println!("Submission Duration: {:.2?}", submission_duration);
    println!("Calculated Throughput (Completed/SubmissionTime): {:.2} [TPS]", throughput_tps); // Changed format slightly

    if !latencies_cc.is_empty() {
        println!("Latency CC (ms): Avg={:.3}, P95={:.3}, P99={:.3}", avg_lat_cc / 1000.0, p95_lat_cc as f64 / 1000.0, p99_lat_cc as f64 / 1000.0);
    } else { println!("Latency CC (ms): No successful cross-chain transactions."); }
    if !latencies_sc.is_empty() {
        println!("Latency SC (ms): Avg={:.3}, P95={:.3}, P99={:.3}", avg_lat_sc / 1000.0, p95_lat_sc as f64 / 1000.0, p99_lat_sc as f64 / 1000.0);
    } else { println!("Latency SC (ms): No successful single-chain transactions."); }
    println!("-------------------------------------
");
}

// Add more shared test utilities here if needed... 