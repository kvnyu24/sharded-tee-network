#!/usr/bin/env python3
import re
import argparse
from datetime import datetime, timedelta, timezone
import statistics
from collections import defaultdict
import sys
import math # For checking NaN

# --- WARNING: This script uses embedded, potentially inaccurate time sources due to missing log timestamps ---

# --- Regexes ---

# Captures the overall configuration being tested (number of chains)
EXPERIMENT_CONFIG_RE = re.compile(
    r'>>> Testing Configuration: n=(?P<n>\d+) <<<'
)

# Captures the start of a specific Scenario F trial and its parameters
SCENARIO_F_START_RE = re.compile(
    # Use single backslashes for escapes: \(, \), \d, \.
    r'--- Starting Scenario F Trial \(n=(?P<n_trial>\d+), k=(?P<k>\d+), m=(?P<m>\d+), tx=\d+, tps=\d+, rho=(?P<rho>\d+\.?\d*)\) ---'
)

# Captures transaction "start" time (tv_sec) and details from ConfirmLockAndSign processing logs
CONFIRM_CMD_RE = re.compile(
    # Use single backslashes for escapes: \[, \], \d, \s, \(, \), \{, \}
    r'\[Node (?P<node_id>\d+)\]\[StateMachine\] Processing command: ConfirmLockAndSign\(LockProofData\s*\{.*?tx_id:\s*"(?P<tx_id>[a-f0-9]+)".*?source_chain_id:\s*(?P<source_chain>\d+).*?target_chain_id:\s*(?P<target_chain>\d+).*?shard_id:\s*(?P<shard_id>\d+).*?start_time:\s*Instant\s*\{\s*tv_sec:\s*(?P<tv_sec>\d+),\s*tv_nsec:\s*(?P<tv_nsec>\d+)\s*\}\}.*?\}\)',
    re.DOTALL
)

# Captures the *first* proposal time for a tx_id found within *any* AppendEntries log
PROPOSAL_TIME_RE = re.compile(
    r'LogEntry\s*\{\s*'
    r'term:\s*\d+,\s*command:\s*ConfirmLockAndSign\(LockProofData\s*\{\s*tx_id:\s*"(?P<tx_id>[a-f0-9]+)".*?\}\),\s*'
    r'proposal_time_since_epoch:\s*(?P<proposal_time>\d+\.?\d*)s'
    r'\s*\}'
)

# Captures the runtime.submit_result call (proxy for cross-shard message count)
SUBMIT_RESULT_RE = re.compile(
    r'\[Node \d+\]\[StateMachine\] (?:PRE|POST) runtime\.submit_result for tx_id: ([a-f0-9]+)'
)

# --- Helper Function to Save Trial Block Data ---
def save_current_trial_block(all_results, current_trial_params, confirm_cmd_data, pseudo_completion_times, submit_result_tx_ids):
    # Only save if we have parameters and some data for the trial
    if current_trial_params and (confirm_cmd_data or pseudo_completion_times or submit_result_tx_ids):
        print(f"  Saving data for trial block: {current_trial_params}")
        all_results.append({
            'params': current_trial_params.copy(), # Store n, k, m, rho
            'confirm_cmd_data': confirm_cmd_data.copy(),
            'pseudo_completion_times': pseudo_completion_times.copy(),
            'submit_result_tx_ids': submit_result_tx_ids.copy()
        })

# --- Main Parsing Function ---
def parse_log_file(log_file_path):
    """
    Parses the Scenario F log file containing multiple experiment configurations (n=1, n=4)
    and potentially multiple trials within each configuration.
    Extracts approximate transaction timings, details, and parameters (n, k, m, rho) for each trial block.
    WARNING: Uses embedded time fields (tv_sec, proposal_time_since_epoch) as proxies
             due to missing wall-clock timestamps on log lines. Results WILL BE INACCURATE.
    """
    all_results = []            # List to store results for each completed trial block
    current_n_config = None     # Stores the active 'n' from >>> Testing Configuration
    current_trial_params = None # Dictionary for current trial block's params {n, k, m, rho}
    confirm_cmd_data = []       # List to store (tx_id, tv_sec, tv_nsec, details) tuples for the current trial
    pseudo_completion_times = {}# tx_id -> float(proposal_time_since_epoch) for the current trial
    submit_result_tx_ids = set() # Tracks unique tx_ids for 'submit_result' in the current trial

    print(f"Parsing Scenario F log file: {log_file_path} ... (Using embedded times - accuracy limitations apply)")
    line_count = 0

    try:
        with open(log_file_path, 'r') as f:
            for line in f:
                line_count += 1

                # --- Check for Outer Experiment Configuration Start ---
                match_config = EXPERIMENT_CONFIG_RE.search(line)
                if match_config:
                    # Save data from the previous trial (if any) before changing config
                    save_current_trial_block(all_results, current_trial_params, confirm_cmd_data, pseudo_completion_times, submit_result_tx_ids)
                    # Reset trial-specific data
                    current_trial_params = None
                    confirm_cmd_data = []
                    pseudo_completion_times = {}
                    submit_result_tx_ids = set()
                    # Set the new outer config 'n'
                    try:
                        current_n_config = int(match_config.group('n'))
                        print(f"\nDetected Experiment Configuration: n={current_n_config}")
                    except (ValueError, TypeError):
                        print(f"  Warning: Could not parse 'n' from config line {line_count}: {line.strip()}. Disabling parsing until next config.")
                        current_n_config = None # Disable parsing if config line is bad

                # --- Check for Inner Trial Start --- (Only if we have a valid outer config 'n')
                if current_n_config is not None:
                    match_trial_start = SCENARIO_F_START_RE.search(line)
                    if match_trial_start:
                        # Save data from the previous trial block (if any)
                        save_current_trial_block(all_results, current_trial_params, confirm_cmd_data, pseudo_completion_times, submit_result_tx_ids)

                        # Reset for the new trial block
                        try:
                            n_trial = int(match_trial_start.group('n_trial'))
                            # Sanity check: n from trial line should match current_n_config
                            if n_trial != current_n_config:
                                print(f"  Warning: Mismatch between config n={current_n_config} and trial line n={n_trial} at line {line_count}. Using n={current_n_config}.")

                            current_trial_params = {
                                'n': current_n_config, # Use n from the outer config line
                                'k': int(match_trial_start.group('k')),
                                'm': int(match_trial_start.group('m')),
                                'rho': float(match_trial_start.group('rho'))
                            }
                            print(f"  Detected Trial Start: {current_trial_params}")
                            # Clear data collections for the new trial block
                            confirm_cmd_data = []
                            pseudo_completion_times = {}
                            submit_result_tx_ids = set()
                        except (ValueError, TypeError) as e:
                            print(f"  Warning: Could not parse parameters from trial start line {line_count}: {e}. Skipping trial block.")
                            current_trial_params = None # Invalidate current trial block

                # --- Parse Data Lines only if we are within a valid trial block ---
                if current_trial_params: # Check if we have valid parameters for the current trial
                    # --- Check for ConfirmLockAndSign Processing (Extracts Pseudo Start Time) ---
                    for match_confirm in CONFIRM_CMD_RE.finditer(line):
                        data = match_confirm.groupdict()
                        tx_id = data['tx_id']
                        try:
                            tv_sec = int(data['tv_sec'])
                            tv_nsec = int(data['tv_nsec'])
                            details = {
                                'node_id': int(data['node_id']),
                                'shard_id': int(data['shard_id']),
                                'source_chain': int(data['source_chain']),
                                'target_chain': int(data['target_chain'])
                            }
                            confirm_cmd_data.append((tx_id, tv_sec, tv_nsec, details))
                        except (ValueError, TypeError, KeyError) as e:
                            print(f"  Warning (Trial {current_trial_params}): Could not parse ConfirmLockAndSign for tx {tx_id} on line {line_count}: {e}")

                    # --- Check for Proposal Time within AppendEntries (Pseudo Completion Time) ---
                    for match_proposal in PROPOSAL_TIME_RE.finditer(line):
                        data = match_proposal.groupdict()
                        tx_id = data['tx_id']
                        if tx_id not in pseudo_completion_times:
                            try:
                                pseudo_completion_times[tx_id] = float(data['proposal_time'])
                            except (ValueError, TypeError) as e:
                                print(f"  Warning (Trial {current_trial_params}): Could not parse proposal time for tx {tx_id} on line {line_count}: {e}")
                                if tx_id in pseudo_completion_times: del pseudo_completion_times[tx_id]

                    # --- Check for submit_result call (Message proxy) ---
                    for match_submit_result in SUBMIT_RESULT_RE.finditer(line):
                        tx_id = match_submit_result.group(1)
                        submit_result_tx_ids.add(tx_id)

        # --- Save the last trial block's data after reaching EOF ---
        save_current_trial_block(all_results, current_trial_params, confirm_cmd_data, pseudo_completion_times, submit_result_tx_ids)

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred during parsing line ~{line_count}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\nParsing Complete: Read {line_count} lines. Found {len(all_results)} trial blocks.")

    # --- Post-process each trial block to calculate intervals ---
    processed_results = []
    for block_data in all_results:
        params = block_data['params']
        confirm_cmd_raw = block_data['confirm_cmd_data']
        completions = block_data['pseudo_completion_times']
        submit_ids = block_data['submit_result_tx_ids']

        print(f"\nProcessing data for trial block: {params}...")

        # Process confirm_cmd_data: Remove duplicates, sort
        processed_confirm_data = {}
        for tx_id, tv_sec, tv_nsec, details in confirm_cmd_raw:
            if tx_id not in processed_confirm_data:
                processed_confirm_data[tx_id] = (tv_sec, tv_nsec, details)

        sorted_confirm_list = sorted(
            [(tx_id, data[0], data[1], data[2]) for tx_id, data in processed_confirm_data.items()],
            key=lambda item: (item[1], item[2]) # Sort by tv_sec, then tv_nsec
        )
        print(f"  Found {len(sorted_confirm_list)} unique ConfirmLockAndSign processings with start_time.")

        # Calculate inter-submission intervals for this block
        inter_submission_intervals = {}
        transaction_details = {}
        valid_interval_tx_ids = set()

        for i in range(len(sorted_confirm_list) - 1):
            tx_id_curr, sec_curr, nsec_curr, details_curr = sorted_confirm_list[i]
            tx_id_next, sec_next, nsec_next, _ = sorted_confirm_list[i+1]

            sec_diff = sec_next - sec_curr
            nsec_diff = nsec_next - nsec_curr
            duration = sec_diff + nsec_diff / 1_000_000_000.0

            if duration >= 0:
                inter_submission_intervals[tx_id_curr] = duration
                valid_interval_tx_ids.add(tx_id_curr)
                transaction_details[tx_id_curr] = details_curr
            else:
                print(f"  Warning (Trial {params}): Negative interval ({duration:.6f}s) calculated between tx {tx_id_curr} ({sec_curr}.{nsec_curr:09d}) and {tx_id_next} ({sec_next}.{nsec_next:09d}). Skipping.")

        print(f"  Calculated {len(inter_submission_intervals)} inter-submission intervals.")
        print(f"  Found {len(completions)} unique TXs with embedded proposal_time_since_epoch.")
        print(f"  Found {len(submit_ids)} unique transaction IDs with a 'submit_result' call.")

        if not completions:
             print("  WARNING: No pseudo-completion times found for this trial block. Throughput calculation impossible.")

        processed_results.append({
            'params': params,
            'inter_submission_intervals': inter_submission_intervals,
            'pseudo_completion_times': completions,
            'transaction_details': transaction_details,
            'valid_interval_tx_ids': valid_interval_tx_ids,
            'submit_result_count': len(submit_ids)
        })

    return processed_results


def analyze_results(params, inter_submission_intervals, pseudo_completion_times, transaction_details, valid_tx_ids, submit_result_count):
    """
    Calculates and prints APPROXIMATE throughput and interval metrics for a specific Scenario F trial block
    based on EMBEDDED log times.
    WARNING: Results derived from this function have SIGNIFICANT ACCURACY LIMITATIONS.
    """
    # Create a more descriptive parameter string for Scenario F
    param_string = f"n={params['n']}, k={params['k']}, m={params['m']}, rho={params['rho']:.1f}"
    print(f"\n--- Analysis Results (Scenario F Trial: {param_string}) (APPROXIMATE - Based on Embedded Log Times) ---")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("!!! WARNING: Accuracy Limitations Apply!                                   !!!")
    print("!!! - 'Start Time' is tv_sec from log data (NOT true submission time).     !!!")
    print("!!! - 'Completion Time' is proposal_time from AppendEntries (NOT true end).!!!")
    print("!!! - Treating tv_sec as Unix time is technically incorrect.               !!!")
    print("!!! Results useful for relative comparison ONLY, not absolute performance. !!!")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

    print(f"\nApproximate Throughput (Based on Proposal Times for Trial: {param_string}):")
    if not pseudo_completion_times:
        print("  - Average TPS: N/A (No pseudo-completion times found for this trial).")
    else:
        completion_times_list = list(pseudo_completion_times.values())
        num_total_completed_tx = len(completion_times_list)

        if num_total_completed_tx > 0:
            valid_completion_times = [t for t in completion_times_list if isinstance(t, float)]
            if not valid_completion_times:
                 print("  - Average TPS: Error - No valid float completion time values found for this trial.")
            elif len(valid_completion_times) == 1:
                 print(f"  - Average TPS: N/A (Only 1 transaction found with proposal time: {valid_completion_times[0]})")
            else:
                try:
                    first_completion_time = min(valid_completion_times)
                    last_completion_time = max(valid_completion_times)
                    processing_duration = last_completion_time - first_completion_time
                except ValueError:
                    print("  - Average TPS: Error calculating time range.")
                    processing_duration = -1

                if processing_duration > 1e-9:
                    average_tps = len(valid_completion_times) / processing_duration
                    print(f"  - Average TPS: {average_tps:.2f}")
                    print(f"  - Calculated over {processing_duration:.2f} seconds (proposal time range)")
                    print(f"  - Based on {len(valid_completion_times)} transactions with valid proposal times (out of {num_total_completed_tx} total)")
                    try:
                        if first_completion_time > 0 and last_completion_time > 0:
                             print(f"  - Pseudo-Completion Window: {datetime.fromtimestamp(first_completion_time, tz=timezone.utc).isoformat()} to {datetime.fromtimestamp(last_completion_time, tz=timezone.utc).isoformat()}")
                        else:
                             print("  - Pseudo-Completion Window: Timestamps are zero or negative, cannot convert.")
                    except (ValueError, OverflowError):
                        print("  - Pseudo-Completion Window: Could not convert proposal times to datetime (likely out of range).")
                elif len(valid_completion_times) > 1 and processing_duration >= 0:
                    print(f"  - Average TPS: Infinite? ({len(valid_completion_times)} transactions proposed in effectively zero time: {processing_duration:.2e}s)")
                elif processing_duration < 0:
                    pass
                else:
                     print("  - Average TPS: N/A (Could not determine valid duration).")
        else:
             print("  - Average TPS: N/A (No transactions with proposal times found for this trial).")

    print(f"\n--- Approximate Inter-Submission Interval Analysis (Trial: {param_string}) ---")
    if not valid_tx_ids:
        print("❌ APPROXIMATE INTERVALS CANNOT BE CALCULATED FOR THIS TRIAL.")
        print("  Reason: Could not find valid pairs of consecutive transactions with pseudo-start (tv_sec) times.")
    else:
        # Use the interval analysis logic consistent with other scripts
        analyze_intervals(inter_submission_intervals, transaction_details, valid_tx_ids)

    # Report proxy for cross-shard message volume (might be less relevant in n=1 case)
    print(f"\nCross-Shard Message Volume Proxy (Trial: {param_string}):")
    print(f"  - Unique Txs with 'submit_result' call: {submit_result_count}")

    print("\n--- End of Analysis for Trial Block ---")
    print("!!! REMINDER: Results are approximate due to reliance on embedded, non-standard time fields. !!!")

# Use the same interval analysis logic as other scripts
def analyze_intervals(intervals_data, transaction_details, valid_tx_ids):
    """
    Calculates statistics on the provided inter-submission intervals for a specific trial block,
    mimicking the logic from parse_scalability_metrics.py.
    """
    intervals = []
    cross_chain_intervals = []
    intra_chain_intervals = []

    print(f"\nCalculating interval statistics for {len(valid_tx_ids)} potential intervals in this trial...")
    skipped_missing_data = 0

    for tx_id in valid_tx_ids:
        interval = intervals_data.get(tx_id)

        if interval is not None and isinstance(interval, float) and interval >= 0:
            intervals.append(interval)
            details = transaction_details.get(tx_id)
            if details:
                try:
                    # Define cross-chain: source != target AND target != 0
                    # Note: For n=1, target_chain should always be 0, so this should always be False.
                    is_cross_chain = (details['source_chain'] != details['target_chain']) and (details['target_chain'] != 0)
                    if is_cross_chain:
                        cross_chain_intervals.append(interval)
                    else:
                        intra_chain_intervals.append(interval)
                except KeyError:
                    print(f"  Warning: Missing chain details for tx {tx_id}", file=sys.stderr)
                    skipped_missing_data += 1
            else:
                print(f"  Warning: Missing details struct for tx {tx_id}", file=sys.stderr)
                skipped_missing_data += 1

    if skipped_missing_data > 0:
        print(f"  Note: {skipped_missing_data} valid intervals could not be categorized as cross/intra-chain due to missing details.")

    # --- Calculate and Print Overall Stats ---
    if intervals:
        try:
            avg_interval = statistics.mean(intervals)
            median_interval = statistics.median(intervals)
            min_interval = min(intervals)
            max_interval = max(intervals)
            p95_interval = float('nan')
            p99_interval = float('nan')
            try:
                if len(intervals) >= 20: p95_interval = statistics.quantiles(intervals, n=100)[94]
                if len(intervals) >= 100: p99_interval = statistics.quantiles(intervals, n=100)[98]
            except statistics.StatisticsError:
                print("  Warning: Could not calculate P95/P99 quantile(s).")

            print(f"\nApproximate Overall Inter-Submission Interval ({len(intervals)} valid intervals):")
            print(f"  (Time between start prep of Tx N and start prep of Tx N+1)")
            print(f"  - Average: {avg_interval:.4f} seconds")
            print(f"  - Median:  {median_interval:.4f} seconds")
            print(f"  - Min:     {min_interval:.4f} seconds")
            print(f"  - Max:     {max_interval:.4f} seconds")
            print(f"  - P95:     {p95_interval:.4f} seconds" if not math.isnan(p95_interval) else "  - P95:     N/A (Insufficient data)")
            print(f"  - P99:     {p99_interval:.4f} seconds" if not math.isnan(p99_interval) else "  - P99:     N/A (Insufficient data)")

        except statistics.StatisticsError as e:
            print(f"\nError calculating overall interval statistics: {e}")
        except ValueError as e:
            print(f"\nError calculating overall interval statistics (potentially empty list): {e}")

    else:
        print("\nNo valid positive inter-submission intervals recorded for this trial.")

    # --- Calculate and Print Cross-Chain Stats (Mean/Median only) ---
    if cross_chain_intervals:
        try:
            avg_cc_interval = statistics.mean(cross_chain_intervals)
            median_cc_interval = statistics.median(cross_chain_intervals)
            print(f"\nApproximate Cross-Chain Inter-Submission Interval ({len(cross_chain_intervals)} intervals):")
            print(f"  - Average: {avg_cc_interval:.4f} seconds")
            print(f"  - Median:  {median_cc_interval:.4f} seconds")
        except statistics.StatisticsError as e:
             print(f"\nError calculating cross-chain interval statistics: {e}")
        except ValueError as e:
             print(f"\nError calculating cross-chain interval statistics (potentially empty list): {e}")
    else:
        # For n=1, we expect no cross-chain txs
        if params and params.get('n') == 1:
             print("\nNo cross-chain intervals found (as expected for n=1).")
        else:
             print("\nNo cross-chain transactions with valid interval data found for this trial.")

    # --- Calculate and Print Intra-Chain Stats (Mean/Median only) ---
    if intra_chain_intervals:
        try:
            avg_ic_interval = statistics.mean(intra_chain_intervals)
            median_ic_interval = statistics.median(intra_chain_intervals)
            print(f"\nApproximate Intra-Chain Inter-Submission Interval ({len(intra_chain_intervals)} intervals):")
            print(f"  - Average: {avg_ic_interval:.4f} seconds")
            print(f"  - Median:  {median_ic_interval:.4f} seconds")
        except statistics.StatisticsError as e:
             print(f"\nError calculating intra-chain interval statistics: {e}")
        except ValueError as e:
             print(f"\nError calculating intra-chain interval statistics (potentially empty list): {e}")
    else:
        print("\nNo intra-chain transactions with valid interval data found for this trial.")


def main():
    parser = argparse.ArgumentParser(description="Analyze Scenario F (Single vs Multi-Chain) log files with multiple trials using embedded time fields (APPROXIMATE RESULTS).")
    parser.add_argument("log_file", help="Path to the Scenario F output log file")
    args = parser.parse_args()

    # Parse log file into separate trial blocks
    all_trial_results = parse_log_file(args.log_file)

    if not all_trial_results:
        print("\nNo valid Scenario F trial blocks found in the log file.")
        return

    print(f"\n\n{'='*20} SUMMARY OF ANALYSIS ACROSS {len(all_trial_results)} TRIAL BLOCKS {'='*20}")

    # Analyze each trial block's results
    for trial_result in all_trial_results:
        analyze_results(
            trial_result['params'],
            trial_result['inter_submission_intervals'],
            trial_result['pseudo_completion_times'],
            trial_result['transaction_details'],
            trial_result['valid_interval_tx_ids'],
            trial_result['submit_result_count']
        )
        print(f"\n{'-'*70}\n") # Separator between trial analyses

    print(f"{'='*20} END OF SUMMARY {'='*20}")


if __name__ == "__main__":
    main() 