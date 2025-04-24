import re
import argparse
from datetime import datetime, timedelta, timezone
import statistics
from collections import defaultdict
import sys
import math # For checking NaN

# --- WARNING: This script uses embedded, potentially inaccurate time sources due to missing log timestamps ---

# --- Regexes ---

# Captures transaction start attempt (OLD format, cannot be used)
SUBMISSION_ATTEMPT_RE = re.compile(
    r'\[Debug\] >>> Sending command for tx \d+ to shard \d+'
)

# Captures transaction "start" time (tv_sec) and details from the *embedded* data in ConfirmLockAndSign processing logs
# ASSUMPTION: tv_sec is treated as a Unix timestamp (INCORRECT, but necessary without wall-clock times)
# Example: [Node 8][StateMachine] Processing command: ConfirmLockAndSign(LockProofData { tx_id: "...", source_chain_id: 1, target_chain_id: 0, shard_id: 1, ..., start_time: Instant { tv_sec: 190226, tv_nsec: 257836125 } })
CONFIRM_CMD_RE = re.compile(
    r'\[Node (?P<node_id>\d+)\]\[StateMachine\] Processing command: ConfirmLockAndSign\(LockProofData\s*\{.*?tx_id:\s*"(?P<tx_id>[a-f0-9]+)".*?source_chain_id:\s*(?P<source_chain>\d+).*?target_chain_id:\s*(?P<target_chain>\d+).*?shard_id:\s*(?P<shard_id>\d+).*?start_time:\s*Instant\s*\{\s*tv_sec:\s*(?P<tv_sec>\d+),\s*tv_nsec:\s*(?P<tv_nsec>\d+)\s*\}.*?\}\)',
    re.DOTALL # Allow .* to match newlines if the log message wraps
)

# Captures the *first* proposal time for a tx_id found within *any* AppendEntries log
# ASSUMPTION: proposal_time_since_epoch is a usable Unix timestamp (likely more accurate than tv_sec)
# Example: ..., entries: [..., LogEntry { term: ..., command: ConfirmLockAndSign(LockProofData { tx_id: "...", ... }), proposal_time_since_epoch: 1745447412.480918s }, ...], ...
# This regex finds the tx_id and time within a specific LogEntry containing ConfirmLockAndSign
PROPOSAL_TIME_RE = re.compile(
    r'LogEntry \{ '
    r'term: \d+, command: ConfirmLockAndSign\(LockProofData \{ tx_id: "(?P<tx_id>[a-f0-9]+)".*?\}\), ' # Match tx_id inside LogEntry's command
    r'proposal_time_since_epoch: (?P<proposal_time>\d+\.?\d*)s'
    r' \}'
)

# Captures the runtime.submit_result call (still useful for message count proxy)
SUBMIT_RESULT_RE = re.compile(
    r'\[Node \d+\]\[StateMachine\] (?:PRE|POST) runtime.submit_result for tx_id: ([a-f0-9]+)'
)


def parse_log_file(log_file_path):
    """
    Parses the log file to extract approximate transaction timings and details.
    WARNING: Uses embedded time fields (tv_sec, proposal_time_since_epoch) as proxies
             due to missing wall-clock timestamps on log lines. Results WILL BE INACCURATE.
    """
    pseudo_start_times = {}     # tx_id -> float(tv_sec) from ConfirmLockAndSign start_time
    pseudo_completion_times = {}# tx_id -> float(proposal_time_since_epoch) from first AppendEntries appearance
    transaction_details = {}    # tx_id -> {'node_id', 'shard_id', 'source_chain', 'target_chain'}
    submit_result_tx_ids = set() # Tracks unique tx_ids for which submit_result was called
    submission_attempts_count = 0 # Count of OLD submission format logs

    print(f"Parsing log file: {log_file_path} ... (Using embedded times - accuracy limitations apply)")
    line_count = 0

    # Store extracted raw data before processing
    confirm_cmd_data = [] # List to store (tx_id, tv_sec, tv_nsec, details) tuples

    try:
        with open(log_file_path, 'r') as f:
            for line in f:
                line_count += 1

                # --- Check for OLD Submission Format (Count only) ---
                match_submit_attempt = SUBMISSION_ATTEMPT_RE.search(line)
                if match_submit_attempt:
                    submission_attempts_count += 1

                # --- Check for ConfirmLockAndSign Processing (Extracts Pseudo Start Time) ---
                match_confirm = CONFIRM_CMD_RE.search(line)
                if match_confirm:
                    data = match_confirm.groupdict()
                    tx_id = data['tx_id']

                    # Store raw data; we'll check for duplicates and sort later
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
                        print(f"  Warning: Could not parse data from ConfirmLockAndSign for tx {tx_id} on line {line_count}: {e}")

                # --- Check for Proposal Time within AppendEntries (Pseudo Completion Time) ---
                # Use finditer as one AppendEntries line can contain multiple LogEntries
                for match_proposal in PROPOSAL_TIME_RE.finditer(line):
                    data = match_proposal.groupdict()
                    tx_id = data['tx_id']

                    # Record the *first* proposal time found for this tx_id
                    if tx_id not in pseudo_completion_times:
                         try:
                             pseudo_completion_times[tx_id] = float(data['proposal_time'])
                         except (ValueError, TypeError) as e:
                             print(f"  Warning: Could not parse proposal time for tx {tx_id} on line {line_count}: {e}")
                             if tx_id in pseudo_completion_times: del pseudo_completion_times[tx_id] # Ensure partial data is removed


                # --- Check for submit_result call (Message proxy) ---
                match_submit_result = SUBMIT_RESULT_RE.search(line)
                if match_submit_result:
                    tx_id = match_submit_result.group(1)
                    submit_result_tx_ids.add(tx_id)

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred during parsing line ~{line_count}: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\nParsing Complete: Read {line_count} lines.")
    print(f"Found {submission_attempts_count} submission attempt logs (OLD format, no tx_id).")
    print(f"Found {len(pseudo_start_times)} unique TXs with embedded start_time (tv_sec).")
    print(f"Found {len(pseudo_completion_times)} unique TXs with embedded proposal_time_since_epoch.")
    print(f"Found {len(submit_result_tx_ids)} unique transaction IDs with a 'submit_result' call.")

    # --- Process confirm_cmd_data: Remove duplicates, sort, calculate intervals ---
    processed_confirm_data = {}
    for tx_id, tv_sec, tv_nsec, details in confirm_cmd_data:
        # Keep only the first occurrence of each tx_id based on its start time
        if tx_id not in processed_confirm_data:
            processed_confirm_data[tx_id] = (tv_sec, tv_nsec, details)
        else:
            # If a duplicate tx_id appears later, ignore it (or decide how to handle)
            pass # Keeping the first one encountered

    # Convert to list and sort by start time (tv_sec, then tv_nsec)
    sorted_confirm_list = sorted(
        [(tx_id, data[0], data[1], data[2]) for tx_id, data in processed_confirm_data.items()],
        key=lambda item: (item[1], item[2]) # Sort by tv_sec, then tv_nsec
    )

    print(f"Found {len(sorted_confirm_list)} unique ConfirmLockAndSign command processings with start_time.")

    # Calculate inter-submission intervals
    inter_submission_intervals = {}
    valid_latency_tx_ids = set() # Tx IDs for which we calculated an interval
    for i in range(len(sorted_confirm_list) - 1):
        tx_id_curr, sec_curr, nsec_curr, _ = sorted_confirm_list[i]
        tx_id_next, sec_next, nsec_next, _ = sorted_confirm_list[i+1]

        # Calculate duration in seconds
        sec_diff = sec_next - sec_curr
        nsec_diff = nsec_next - nsec_curr
        duration = sec_diff + nsec_diff / 1_000_000_000.0

        if duration >= 0: # Store non-negative intervals
            inter_submission_intervals[tx_id_curr] = duration
            valid_latency_tx_ids.add(tx_id_curr)
            # Populate pseudo_start_times and transaction_details for these valid IDs
            # Note: We are storing the *interval* not the start time here
            pseudo_start_times[tx_id_curr] = (sec_curr, nsec_curr) # Store original start time for reference if needed
            transaction_details[tx_id_curr] = sorted_confirm_list[i][3] # Get details back
        else:
            print(f"  Warning: Negative interval calculated between tx {tx_id_curr} and {tx_id_next}. Skipping.")

    print(f"Calculated {len(inter_submission_intervals)} inter-submission intervals.")

    # --- Check for availability of proposal times (for throughput) ---
    if not pseudo_completion_times:
        print("\nERROR: No pseudo-completion times (proposal_time_since_epoch from AppendEntries) could be extracted. Throughput calculation impossible.")

    # Return intervals, completion times, details, and submit count
    # Note: valid_tx_ids now refers to IDs with calculated *intervals*
    return inter_submission_intervals, pseudo_completion_times, transaction_details, valid_latency_tx_ids, len(submit_result_tx_ids)


def analyze_results(inter_submission_intervals, pseudo_completion_times, transaction_details, valid_tx_ids, submit_result_count):
    """
    Calculates and prints APPROXIMATE throughput and latency metrics based on EMBEDDED log times.
    WARNING: Results derived from this function have SIGNIFICANT ACCURACY LIMITATIONS.
             Do not treat them as true end-to-end performance figures.
    """
    intervals = []
    cross_chain_intervals = []
    intra_chain_intervals = []

    print("\n--- Analysis Results (APPROXIMATE - Based on Embedded Log Times) ---")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("!!! WARNING: Accuracy Limitations Apply!                                   !!!")
    print("!!! - 'Start Time' is tv_sec from log data (NOT true submission time).     !!!")
    print("!!! - 'Completion Time' is proposal_time from AppendEntries (NOT true end).!!!")
    print("!!! - Treating tv_sec as Unix time is technically incorrect.               !!!")
    print("!!! Results useful for relative comparison ONLY, not absolute performance. !!!")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

    cross_chain_intervals = []
    intra_chain_intervals = []

    print("\nApproximate Throughput (Based on Proposal Times):")
    if not pseudo_completion_times:
        print("  - Average TPS: N/A (No pseudo-completion times found).")
    else:
        completion_times_list = list(pseudo_completion_times.values())
        num_total_completed_tx = len(completion_times_list)

        if num_total_completed_tx > 0:
            first_completion_time = min(completion_times_list)
            last_completion_time = max(completion_times_list)

            if isinstance(first_completion_time, float) and isinstance(last_completion_time, float):
                processing_duration = last_completion_time - first_completion_time

                if processing_duration > 0:
                    average_tps = num_total_completed_tx / processing_duration
                    print(f"  - Average TPS: {average_tps:.2f}")
                    print(f"  - Calculated over {processing_duration:.2f} seconds (proposal time range)")
                    print(f"  - Based on {num_total_completed_tx} transactions with proposal times")
                    try:
                        print(f"  - Pseudo-Completion Window: {datetime.fromtimestamp(first_completion_time, tz=timezone.utc).isoformat()} to {datetime.fromtimestamp(last_completion_time, tz=timezone.utc).isoformat()}")
                    except ValueError:
                        print("  - Pseudo-Completion Window: Could not convert proposal times to datetime.")
                elif num_total_completed_tx == 1:
                    print("  - Average TPS: N/A (Only 1 transaction found with proposal time)")
                elif num_total_completed_tx > 1:
                    print(f"  - Average TPS: Infinite? ({num_total_completed_tx} transactions proposed in effectively zero time)")
                else: # Should not happen if num_total_completed_tx > 0
                    print("  - Average TPS: Error calculating.")
            else:
                print("  - Average TPS: Error - Invalid completion time values found.")
        else:
             print("  - Average TPS: N/A (No transactions with proposal times found).")

    print("\n--- Approximate Inter-Submission Interval Calculation Status ---")
    if not valid_tx_ids:
        print("\n--- Approximate Inter-Submission Interval Calculation Status ---")
        print("❌ APPROXIMATE LATENCY CANNOT BE CALCULATED.")
        print("  Reason: Could not find transactions with *both* pseudo-start (tv_sec)")
        print("          and pseudo-completion (proposal_time_since_epoch) times.")
    else:
        analyze_intervals(inter_submission_intervals, transaction_details, valid_tx_ids)

    # Report proxy for cross-shard message volume (always report this if parsing succeeded)
    print(f"\nCross-Shard Message Volume Proxy:")
    print(f"  - Unique Txs with 'submit_result' call: {submit_result_count}")

    print("\n--- End of Analysis ---")
    print("!!! REMINDER: Results are approximate due to reliance on embedded, non-standard time fields. !!!")


def analyze_intervals(intervals_data, transaction_details, valid_tx_ids):
    """Calculates statistics on the provided inter-submission intervals."""
    intervals = []
    cross_chain_intervals = []
    intra_chain_intervals = []

    print(f"\nCalculating statistics for {len(valid_tx_ids)} inter-submission intervals...")
    skipped_missing_data = 0
    for tx_id in valid_tx_ids:
        interval = intervals_data.get(tx_id)

        if interval is not None:
            if isinstance(interval, float) and interval >= 0:
                intervals.append(interval)

                details = transaction_details.get(tx_id)
                if details:
                    try:
                        is_cross_chain = (details['source_chain'] != details['target_chain']) and (details['target_chain'] != 0)
                        if is_cross_chain:
                            cross_chain_intervals.append(interval)
                        else:
                            intra_chain_intervals.append(interval)
                    except KeyError:
                        print(f"  Warning: Missing chain details for tx {tx_id}", file=sys.stderr)
                else:
                    print(f"  Warning: Missing details struct for tx {tx_id}", file=sys.stderr)
            else:
                # This covers non-float or negative intervals (already warned during calculation)
                skipped_missing_data += 1
        else:
            skipped_missing_data += 1 # Should not happen if tx_id is in valid_tx_ids

    if intervals:
        avg_interval = statistics.mean(intervals)
        median_interval = statistics.median(intervals)
        min_interval = min(intervals)
        max_interval = max(intervals)
        p95_interval = statistics.quantiles(intervals, n=100)[94] if len(intervals) > 20 else float('nan')
        p99_interval = statistics.quantiles(intervals, n=100)[98] if len(intervals) > 100 else float('nan')

        print(f"\nApproximate Overall Inter-Submission Interval ({len(intervals)} valid intervals):")
        print(f"  (Time between start prep of Tx N and start prep of Tx N+1)")
        print(f"  - Average: {avg_interval:.4f} seconds")
        print(f"  - Median:  {median_interval:.4f} seconds")
        print(f"  - Min:     {min_interval:.4f} seconds")
        print(f"  - Max:     {max_interval:.4f} seconds")
        print(f"  - P95:     {p95_interval:.4f} seconds" if not math.isnan(p95_interval) else "  - P95:     N/A (Insufficient data)")
        print(f"  - P99:     {p99_interval:.4f} seconds" if not math.isnan(p99_interval) else "  - P99:     N/A (Insufficient data)")

    else:
        print("\nNo valid positive inter-submission intervals recorded.")

    if cross_chain_intervals:
        avg_cc_interval = statistics.mean(cross_chain_intervals)
        median_cc_interval = statistics.median(cross_chain_intervals)
        print(f"\nApproximate Cross-Chain Inter-Submission Interval ({len(cross_chain_intervals)} intervals):")
        print(f"  - Average: {avg_cc_interval:.4f} seconds")
        print(f"  - Median:  {median_cc_interval:.4f} seconds")
    else:
        print("\nNo cross-chain transactions with valid interval data found.")

    if intra_chain_intervals:
        avg_ic_interval = statistics.mean(intra_chain_intervals)
        median_ic_interval = statistics.median(intra_chain_intervals)
        print(f"\nApproximate Intra-Chain Inter-Submission Interval ({len(intra_chain_intervals)} intervals):")
        print(f"  - Average: {avg_ic_interval:.4f} seconds")
        print(f"  - Median:  {median_ic_interval:.4f} seconds")
    else:
        print("\nNo intra-chain transactions with valid interval data found.")


def main():
    parser = argparse.ArgumentParser(description="Analyze Scenario A (Shard Scalability) log files using embedded time fields (APPROXIMATE RESULTS).")
    parser.add_argument("log_file", help="Path to the scenario_a_output.log file")
    args = parser.parse_args()

    # Parse log file using embedded times
    inter_submission_intervals, pseudo_completion_times, transaction_details, valid_tx_ids, submit_result_count = parse_log_file(args.log_file)

    # Proceed with analysis if parsing found *some* data, even if incomplete
    if inter_submission_intervals is not None or pseudo_completion_times is not None:
        analyze_results(inter_submission_intervals, pseudo_completion_times, transaction_details, valid_tx_ids, submit_result_count)
    else:
        print("\nAnalysis skipped due to fatal parsing errors.")

if __name__ == "__main__":
    main()