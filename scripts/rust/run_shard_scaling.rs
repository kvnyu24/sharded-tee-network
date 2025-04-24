use std::time::Duration;
use tee::experiments::shard_scaling::{ShardScalingExperiment, ExperimentResults};

#[tokio::main]
async fn main() {
    // Configure experiment parameters
    let experiment = ShardScalingExperiment::new(
        10000,
        Duration::from_millis(10),
        Duration::from_secs(300),
    );

    // Test different shard configurations
    let shard_counts = vec![2, 5, 10];
    let mut results = Vec::new();

    for &shard_count in &shard_counts {
        println!("Testing configuration with {} shards...", shard_count);
        
        // Run experiment 3 times for each configuration
        let mut shard_results = Vec::new();
        for i in 1..=3 {
            println!("  Run {} of 3", i);
            let result = experiment.run_shard_configuration(shard_count).await;
            shard_results.push(result);
        }

        // Calculate averages
        let avg_result = average_results(&shard_results);
        results.push(avg_result);
        
        println!("Results for {} shards:", shard_count);
        println!("  Throughput: {:.2} ops/sec", avg_result.throughput);
        println!("  Average Latency: {:?}", avg_result.avg_latency);
        println!("  Load Balance Score: {:.3}", avg_result.load_balance_score);
        println!("  Fault Recovery Time: {:?}", avg_result.fault_recovery_time);
        println!();
    }

    // Output comparative analysis
    output_analysis(&results);
}

fn average_results(results: &[ExperimentResults]) -> ExperimentResults {
    // Calculate average metrics across multiple runs
    let count = results.len() as f64;
    ExperimentResults {
        shard_count: results[0].shard_count,
        throughput: results.iter().map(|r| r.throughput).sum::<f64>() / count,
        avg_latency: Duration::from_secs_f64(
            results.iter()
                .map(|r| r.avg_latency.as_secs_f64())
                .sum::<f64>() / count
        ),
        load_balance_score: results.iter().map(|r| r.load_balance_score).sum::<f64>() / count,
        fault_recovery_time: Duration::from_secs_f64(
            results.iter()
                .map(|r| r.fault_recovery_time.as_secs_f64())
                .sum::<f64>() / count
        ),
    }
}