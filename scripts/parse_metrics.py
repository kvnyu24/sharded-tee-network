import re
import sys
import statistics
from collections import defaultdict
import json
import argparse # Use argparse for better argument handling

# Regex for the START log
start_pattern = re.compile(
    # Ensure METRIC_LOG_V2 is at the start of the string after potential whitespace
    r"^\s*METRIC_LOG_V2: START tx_id=(?P<tx_id>\S+)\s+timestamp_ms=(?P<start_ts>\d+)"
)

# Regex for the END log (Success) - More robust version
end_pattern_success = re.compile(
    # Match coordinator ID, timestamp, specific text, tx_id, hash, and cross_chain flag
    r"\[Coordinator \d+\]\[(?P<end_ts>\d+)\]\s+Relayer success\s+tx_id=(?P<tx_id>\S+)\s+onchain_hash=\S+\s+is_cross_chain=(?P<cross>true|false)"
)

# Regex for the END log (Failure) - More robust version
end_pattern_failure = re.compile(
    # Match coordinator ID, timestamp, specific text, tx_id, error message, and cross_chain flag
    r"\[Coordinator \d+\]\[(?P<end_ts>\d+)\]\s+Relayer FAILED\s+tx_id=(?P<tx_id>\S+)\s+error='[^']+'\s+is_cross_chain=(?P<cross>true|false)"
)

# Regex to extract parameters from test header
param_pattern = re.compile(r"Starting Scenario \S+ Trial \((.*?)\)")

def extract_params(line):
    """Extracts key=value pairs from the scenario header line."""
    match = param_pattern.search(line)
    params = {}
    if match:
        pairs = match.group(1).split(', ')
        for pair in pairs:
            try:
                # Handle simple key=value and key=[v1,v2]
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    params[key.strip()] = value.strip()
            except ValueError:
                print(f"Warning: Could not parse parameter pair: {pair}")
    return params


def analyze_log_file(log_file_path, scenario_params=None):
    """
    Parses the log file for specific START and END log lines and calculates statistics.
    """
    transactions = {} # tx_id -> {start_ts, end_ts, duration, success, is_cross_chain}
    min_start_ts = float('inf')
    max_end_ts = 0
    extracted_params = {} # Store params found in the log file itself
    lines_read = 0 # DEBUG
    matches_found = 0 # DEBUG

    print(f"\n--- Analyzing Log File: {log_file_path} ---")

    try:
        with open(log_file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                lines_read += 1
                # Strip leading/trailing whitespace from line for matching
                processed_line = line.strip()

                # Extract params from header if not provided
                if not scenario_params and not extracted_params:
                     found_params = extract_params(processed_line)
                     if found_params:
                         extracted_params = found_params
                         print(f"Extracted Params: {extracted_params}")

                # Process START log
                start_match = start_pattern.search(processed_line)
                if start_match:
                    matches_found += 1 # DEBUG
                    print(f"DEBUG Line {line_num}: START Match Found!") # DEBUG
                    data = start_match.groupdict()
                    print(f"DEBUG Captured START Data: {data}") # DEBUG
                    tx_id = data['tx_id']
                    start_ts = int(data['start_ts'])
                    if tx_id not in transactions:
                        transactions[tx_id] = {}
                    if 'start_ts' in transactions[tx_id]:
                        # This might indicate the transaction was retried or observed multiple times
                        print(f"Warning: Multiple START logs for tx_id {tx_id} (lines {transactions[tx_id].get('start_line', '?')} & {line_num}). Using latest.")
                    transactions[tx_id]['start_ts'] = start_ts
                    transactions[tx_id]['start_line'] = line_num # Store line number for debugging warnings
                    min_start_ts = min(min_start_ts, start_ts)
                    continue # Move to next line once matched

                # Process END log (Success)
                end_success_match = end_pattern_success.search(processed_line)
                if end_success_match:
                    matches_found += 1 # DEBUG
                    print(f"DEBUG Line {line_num}: END Success Match Found!") # DEBUG
                    data = end_success_match.groupdict()
                    print(f"DEBUG Captured END Success Data: {data}") # DEBUG
                    tx_id = data['tx_id']
                    end_ts = int(data['end_ts'])
                    is_cross_chain = data['cross'] == 'true'
                    if tx_id not in transactions:
                        transactions[tx_id] = {}
                        print(f"Warning: END log found before START for tx_id {tx_id} (line {line_num}).")
                    # Check if this END log is already processed
                    if 'end_ts' in transactions[tx_id]:
                         print(f"Warning: Multiple END logs for tx_id {tx_id} (lines {transactions[tx_id].get('end_line', '?')} & {line_num}). Overwriting previous.")
                    transactions[tx_id]['end_ts'] = end_ts
                    transactions[tx_id]['success'] = True
                    transactions[tx_id]['is_cross_chain'] = is_cross_chain
                    transactions[tx_id]['end_line'] = line_num # Store line number
                    if 'start_ts' in transactions[tx_id]:
                        duration = end_ts - transactions[tx_id]['start_ts']
                        transactions[tx_id]['duration'] = duration if duration >= 0 else -1
                    else:
                         transactions[tx_id]['duration'] = -1
                    max_end_ts = max(max_end_ts, end_ts)
                    continue # Move to next line

                # Process END log (Failure)
                end_failure_match = end_pattern_failure.search(processed_line)
                if end_failure_match:
                    matches_found += 1 # DEBUG
                    print(f"DEBUG Line {line_num}: END Failure Match Found!") # DEBUG
                    data = end_failure_match.groupdict()
                    print(f"DEBUG Captured END Failure Data: {data}") # DEBUG
                    tx_id = data['tx_id']
                    end_ts = int(data['end_ts'])
                    is_cross_chain = data['cross'] == 'true'
                    if tx_id not in transactions:
                        transactions[tx_id] = {}
                        print(f"Warning: END log found before START for tx_id {tx_id} (line {line_num}).")
                     # Check if this END log is already processed
                    if 'end_ts' in transactions[tx_id]:
                         print(f"Warning: Multiple END logs for tx_id {tx_id} (lines {transactions[tx_id].get('end_line', '?')} & {line_num}). Overwriting previous.")
                    transactions[tx_id]['end_ts'] = end_ts
                    transactions[tx_id]['success'] = False
                    transactions[tx_id]['is_cross_chain'] = is_cross_chain
                    transactions[tx_id]['end_line'] = line_num # Store line number
                    if 'start_ts' in transactions[tx_id]:
                         duration = end_ts - transactions[tx_id]['start_ts']
                         transactions[tx_id]['duration'] = duration if duration >= 0 else -1
                    else:
                         transactions[tx_id]['duration'] = -1
                    max_end_ts = max(max_end_ts, end_ts)
                    continue # Move to next line


    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
        return
    except Exception as e:
        print(f"Error reading or parsing log file line {line_num}: {e}")
        return

    # DEBUG: Print total lines read and matches found
    print(f"\nDEBUG: Total lines read: {lines_read}")
    print(f"DEBUG: Total matching START/END log lines found: {matches_found}")

    # If still no matches, print a sample of lines that *didn't* match for manual inspection
    if matches_found == 0 and lines_read > 0:
        print("\nDEBUG: No START/END log lines matched. Sample of non-matching lines:")
        non_match_count = 0
        try:
            with open(log_file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    processed_line = line.strip()
                    if not (start_pattern.search(processed_line) or
                            end_pattern_success.search(processed_line) or
                            end_pattern_failure.search(processed_line) or
                            param_pattern.search(processed_line)): # Also exclude param line
                        print(f"  Line {line_num}: {processed_line[:150]}") # Print first 150 chars
                        non_match_count += 1
                        if non_match_count >= 20: # Print up to 20 non-matching lines
                            break
        except Exception as e:
            print(f"Error re-reading log file for non-matches: {e}")


    # Use provided params or fallback to extracted ones
    params_to_display = scenario_params if scenario_params else extracted_params
    if params_to_display:
        print(f"Scenario Parameters: {params_to_display}")
    else:
        print("Scenario Parameters: Not found in log or arguments.")

    # --- Analysis ---
    completed_count = 0
    successful_count_cc = 0
    successful_count_sc = 0
    failed_count_cc = 0 # Track failures
    failed_count_sc = 0 # Track failures
    latencies_cc_ms = []
    latencies_sc_ms = []

    for tx_id, data in transactions.items():
        # Ensure both START and END were logged and duration is valid (non-negative)
        if 'start_ts' in data and 'end_ts' in data and 'duration' in data and data['duration'] >= 0:
            completed_count += 1 # Count only txs with valid start/end/duration
            is_cc = data.get('is_cross_chain', False) # Default to False if missing somehow
            if data['success']:
                duration_ms = data['duration']
                if is_cc:
                    successful_count_cc += 1
                    latencies_cc_ms.append(duration_ms)
                else:
                    successful_count_sc += 1
                    latencies_sc_ms.append(duration_ms)
            else:
                # Count failures separately
                if is_cc:
                    failed_count_cc += 1
                else:
                    failed_count_sc += 1
        elif 'start_ts' in data and 'end_ts' not in data:
             print(f"Warning: Transaction {tx_id} has START but no END log (recorded on line {data.get('start_line', '?')}).")
        elif 'start_ts' not in data and 'end_ts' in data:
             print(f"Warning: Transaction {tx_id} has END but no START log (recorded on line {data.get('end_line', '?')}).")
        # Ignore transactions with negative duration (indicates issue)

    total_successful = successful_count_cc + successful_count_sc
    total_failed = failed_count_cc + failed_count_sc
    print(f"\nTransaction Counts:")
    print(f"  Found Logs For: {len(transactions)} unique transaction IDs") # Changed wording slightly
    print(f"  Completed (Valid Start/End/Duration): {completed_count}")
    print(f"  Successful: {total_successful}")
    print(f"    Cross-Chain: {successful_count_cc}")
    print(f"    Single-Chain: {successful_count_sc}")
    print(f"  Failed (with Start/End): {total_failed}")
    print(f"    Cross-Chain: {failed_count_cc}")
    print(f"    Single-Chain: {failed_count_sc}")


    # --- Throughput Calculation ---
    # Calculate overall duration from the earliest START to the latest END log entry
    observed_duration_ms = 0
    throughput_tps = 0.0
    if max_end_ts > min_start_ts:
         observed_duration_ms = max_end_ts - min_start_ts
         observed_duration_s = observed_duration_ms / 1000.0
         print(f"\nObserved Test Timespan (Log-Based): {observed_duration_s:.2f} s")
         if observed_duration_s > 0:
            # Calculate throughput based on *successful* transactions over the observed timespan
            throughput_tps = total_successful / observed_duration_s
            print(f"Achieved Average Throughput (Successful/Timespan): {throughput_tps:.2f} TPS")
         else:
             print("Achieved Average Throughput: Cannot calculate (zero or invalid time span).")
    elif completed_count > 0:
        print("\nObserved Test Timespan: Could not determine bounds from logs (min_start or max_end missing/invalid).")
        print("Achieved Average Throughput: Cannot calculate.")
    else: # No completed transactions
        print("\nObserved Test Timespan: No completed transactions found.")
        print("Achieved Average Throughput: 0.00 TPS")

    print("  (Note: This is average throughput for the *completed* run, not necessarily peak sustainable)")


    # --- Latency Calculation ---
    print(f"\nLatency Statistics (ms):")
    def calculate_stats(latencies_ms):
        if not latencies_ms:
            return "N/A" # Return string if no data

        avg = statistics.mean(latencies_ms)
        latencies_ms.sort() # Sort for percentile calculation

        # Handle edge case of very small lists for percentiles
        count = len(latencies_ms)
        p50_index = min(int(count * 0.50), count - 1) if count > 0 else 0
        p95_index = min(int(count * 0.95), count - 1) if count > 0 else 0
        p99_index = min(int(count * 0.99), count - 1) if count > 0 else 0

        p50 = latencies_ms[p50_index] if count > 0 else 0
        p95 = latencies_ms[p95_index] if count > 0 else 0
        p99 = latencies_ms[p99_index] if count > 0 else 0

        # Include Min/Max
        min_lat = latencies_ms[0] if count > 0 else 0
        max_lat = latencies_ms[-1] if count > 0 else 0


        return f"Avg={avg:.1f}, P50={p50:.1f}, P95={p95:.1f}, P99={p99:.1f}, Min={min_lat:.1f}, Max={max_lat:.1f} (count={count})"

    cc_stats = calculate_stats(latencies_cc_ms)
    sc_stats = calculate_stats(latencies_sc_ms)

    print(f"  Cross-Chain Latency (ms): {cc_stats}")
    print(f"  Single-Chain Latency (ms): {sc_stats}")

    # --- Missing Scenario A Metrics ---
    print("\nOther Scenario A Metrics:")
    print("  - Peak Sustainable Throughput: Not directly measured by this script (requires multiple runs at different loads).")
    print("  - Cross-shard Message Volume: Not currently logged by the simulation.")
    print("-" * 40)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze teeshard simulation logs for performance metrics.")
    parser.add_argument("log_files", nargs='+', help="Path(s) to the simulation log file(s).")
    # Optional arguments to manually specify parameters if not found in log
    parser.add_argument("-k", "--shards", type=int, help="Number of shards (k)")
    parser.add_argument("-m", "--nodes-per-shard", type=int, help="Nodes per shard (m)")
    parser.add_argument("-t", "--threshold", type=int, help="Coordinator threshold (t)")
    parser.add_argument("-r", "--rho", type=float, help="Cross-chain ratio (rho)")
    # Add other params as needed (n, delay, etc.)

    args = parser.parse_args()

    # Store manually provided params
    manual_params = {}
    if args.shards is not None: manual_params['k'] = str(args.shards)
    if args.nodes_per_shard is not None: manual_params['m'] = str(args.nodes_per_shard)
    if args.threshold is not None: manual_params['t'] = str(args.threshold)
    if args.rho is not None: manual_params['rho'] = f"{args.rho:.1f}" # Format rho

    for log_file in args.log_files:
        # Pass manual_params if they exist, otherwise script tries to extract from log
        analyze_log_file(log_file, scenario_params=manual_params if manual_params else None)