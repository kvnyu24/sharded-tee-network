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

// --- Helper for stats calculation (moved from scenario_e) ---
fn calculate_stats_micros(latencies: &[u128]) -> (f64, u128, u128) {
    if latencies.is_empty() { return (0.0, 0, 0); }
    let count = latencies.len();
    let avg = latencies.iter().sum::<u128>() as f64 / count as f64;
    let p95_idx = ((count as f64 * 0.95).floor() as usize).min(count.saturating_sub(1));
    let p99_idx = ((count as f64 * 0.99).floor() as usize).min(count.saturating_sub(1));
    let p95 = *latencies.get(p95_idx).unwrap_or(latencies.last().unwrap_or(&0));
    let p99 = *latencies.get(p99_idx).unwrap_or(latencies.last().unwrap_or(&0));
    (avg, p95, p99)
}

// --- Enhanced Performance Analysis Function ---
pub fn analyze_perf_results(
    scenario_name: &str,
    scenario_params: &HashMap<String, String>,
    metrics: &[MetricEvent],
    submitted_count: usize,
    submission_duration: Duration,
) {
    let mut latencies_completion_cc = Vec::new();
    let mut latencies_completion_sc = Vec::new();
    let mut latencies_tee_finality = Vec::new();
    let mut latencies_onchain_finality = Vec::new();
    let mut tee_function_times: HashMap<String, Vec<u128>> = HashMap::new(); // Store durations as micros

    let mut completed_count = 0;
    let mut successful_count_cc = 0;
    let mut successful_count_sc = 0;
    let mut raft_election_count = 0;

    let mut tx_start_times_ms: HashMap<String, u64> = HashMap::new();

    // First pass: Find the earliest proposal time for each transaction
    for event in metrics {
        if let MetricEvent::NodeCommandProposed { tx_id, timestamp_ms, .. } = event {
            tx_start_times_ms.entry(tx_id.clone()).or_insert(*timestamp_ms);
        }
    }

    // Second pass: Calculate latencies and count events
    for event in metrics {
        match event {
            MetricEvent::TransactionCompleted { duration, success, is_cross_chain, .. } => {
                completed_count += 1;
                if *success {
                    let latency_micros = duration.as_micros();
                    if *is_cross_chain {
                        successful_count_cc += 1;
                        latencies_completion_cc.push(latency_micros);
                    } else {
                        successful_count_sc += 1;
                        latencies_completion_sc.push(latency_micros);
                    }
                }
            }
            MetricEvent::RaftLeaderElected { .. } => {
                raft_election_count += 1;
            }
            MetricEvent::CoordinatorThresholdReached { tx_id, timestamp_ms, .. } => {
                if let Some(start_ms) = tx_start_times_ms.get(tx_id) {
                    if *timestamp_ms >= *start_ms {
                        let latency_ms = timestamp_ms - start_ms;
                        latencies_tee_finality.push(latency_ms as u128 * 1000);
                    }
                }
            }
            MetricEvent::RelayerReleaseSubmitted { tx_id, timestamp_ms, .. } => {
                if let Some(start_ms) = tx_start_times_ms.get(tx_id) {
                    if *timestamp_ms >= *start_ms {
                        let latency_ms = timestamp_ms - start_ms;
                        latencies_onchain_finality.push(latency_ms as u128 * 1000);
                    }
                }
            }
            MetricEvent::TeeFunctionMeasured { function_name, duration, .. } => {
                tee_function_times.entry(function_name.clone()).or_default().push(duration.as_micros());
            }
            _ => {} // Ignore other events like RaftCommit, NodeIsolated etc. for this summary
        }
    }

    latencies_completion_cc.sort_unstable();
    latencies_completion_sc.sort_unstable();
    latencies_tee_finality.sort_unstable();
    latencies_onchain_finality.sort_unstable();
    // Sort TEE function times
    for times in tee_function_times.values_mut() {
        times.sort_unstable();
    }

    // Use the calculate_stats_micros helper now
    let (avg_comp_cc, p95_comp_cc, p99_comp_cc) = calculate_stats_micros(&latencies_completion_cc);
    let (avg_comp_sc, p95_comp_sc, p99_comp_sc) = calculate_stats_micros(&latencies_completion_sc);
    let (avg_tee_fin, p95_tee_fin, p99_tee_fin) = calculate_stats_micros(&latencies_tee_finality);
    let (avg_onchain_fin, p95_onchain_fin, p99_onchain_fin) = calculate_stats_micros(&latencies_onchain_finality);

    let throughput_tps = if submission_duration > Duration::ZERO {
        completed_count as f64 / submission_duration.as_secs_f64()
    } else { 0.0 };

    println!("\n--- {} Analysis (Params: {:?}) ---", scenario_name, scenario_params);
    println!("Target Submitted Transactions: {}", submitted_count);
    println!("Completed Transactions (end-to-end): {}", completed_count);
    println!("  Successful Cross-Chain: {} ({} samples)", successful_count_cc, latencies_completion_cc.len());
    println!("  Successful Single-Chain: {} ({} samples)", successful_count_sc, latencies_completion_sc.len());
    println!("Submission Duration: {:.2?}", submission_duration);
    println!("Calculated Throughput (Completed/SubmissionTime): {:.2} [TPS]", throughput_tps);
    println!("Raft Elections Triggered: {}", raft_election_count);

    if !latencies_completion_cc.is_empty() {
        println!("E2E Completion Latency CC (ms): Avg={:.3}, P95={:.3}, P99={:.3}", avg_comp_cc / 1000.0, p95_comp_cc as f64 / 1000.0, p99_comp_cc as f64 / 1000.0);
    } else { println!("E2E Completion Latency CC (ms): No successful cross-chain transactions."); }
    if !latencies_completion_sc.is_empty() {
        println!("E2E Completion Latency SC (ms): Avg={:.3}, P95={:.3}, P99={:.3}", avg_comp_sc / 1000.0, p95_comp_sc as f64 / 1000.0, p99_comp_sc as f64 / 1000.0);
    } else { println!("E2E Completion Latency SC (ms): No successful single-chain transactions."); }

    if !latencies_tee_finality.is_empty() {
        println!("TEE Finality Latency (ms, Proposal->Threshold): Avg={:.3}, P95={:.3}, P99={:.3} ({} samples)", avg_tee_fin / 1000.0, p95_tee_fin as f64 / 1000.0, p99_tee_fin as f64 / 1000.0, latencies_tee_finality.len());
    } else { println!("TEE Finality Latency (ms): No TEE finality events recorded or matched."); }
    if !latencies_onchain_finality.is_empty() {
        println!("On-Chain Finality Latency (ms, Proposal->Release): Avg={:.3}, P95={:.3}, P99={:.3} ({} samples)", avg_onchain_fin / 1000.0, p95_onchain_fin as f64 / 1000.0, p99_onchain_fin as f64 / 1000.0, latencies_onchain_finality.len());
    } else { println!("On-Chain Finality Latency (ms): No on-chain finality events recorded or matched."); }

    // --- Print TEE Overhead Stats --- 
    println!("\nTEE Function Overheads (ms):");
    let mut sorted_tee_func_names: Vec<_> = tee_function_times.keys().cloned().collect();
    sorted_tee_func_names.sort();
    if sorted_tee_func_names.is_empty() {
        println!("  No TEE function measurements recorded.");
    } else {
        for func_name in sorted_tee_func_names {
            if let Some(times) = tee_function_times.get(&func_name) {
                 if !times.is_empty() {
                    let (avg, p95, p99) = calculate_stats_micros(times);
                    println!("  - {}: Avg={:.3}, P95={:.3}, P99={:.3} ({} samples)",
                             func_name, avg / 1000.0, p95 as f64 / 1000.0, p99 as f64 / 1000.0, times.len());
                 } else {
                     println!("  - {}: No samples recorded.", func_name);
                 }
            }
        }
    }
    // --- End TEE Overhead --- 

    println!("-------------------------------------\n");
}

// Add more shared test utilities here if needed... 
// Add more shared test utilities here if needed... 