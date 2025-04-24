import re
import sys
import numpy as np
from collections import defaultdict, Counter
import datetime
import math

# --- Regular Expressions ---

# Matches RaftLeaderElected events
election_pattern = re.compile(
    r'RaftLeaderElected\s*{.*?'
    r'term:\s*(?P<term>\d+)'
    r'.*?'
    r'leader_id:\s*(?P<leader_id>\d+)'
    r'.*?'
    r'timestamp_ms:\s*(?P<timestamp_ms>\d+)'
    r'.*?}'
)

# Matches TransactionCompleted events
transaction_pattern = re.compile(
    r'TransactionCompleted\s*{.*?'
    # Capture end_time_ms (renamed from timestamp_ms for clarity)
    r'end_time_ms:\s*(?P<end_time_ms>\d+)' 
    r'.*?'
    r'duration:\s*Duration\s*{\s*secs:\s*(?P<secs>\d+),\s*nanos:\s*(?P<nanos>\d+)\s*}'
    r'.*?'
    r'success:\s*(?P<success>true|false)'
    r'.*?'
    r'is_cross_chain:\s*(?P<is_cross_chain>true|false)'
    r'.*?}'
)

# Matches NodeIsolated events
isolated_pattern = re.compile(
    r'NodeIsolated\s*{.*?'
    r'node_id:\s*(?P<node_id>\d+)'
    r'.*?'
    r'timestamp_ms:\s*(?P<timestamp_ms>\d+)'
    r'.*?}'
)

# --- ADDED: Matches NodeRejoined events ---
rejoined_pattern = re.compile(
    r'NodeRejoined\s*{.*?'
    r'node_id:\s*(?P<node_id>\d+)'
    r'.*?'
    r'timestamp_ms:\s*(?P<timestamp_ms>\d+)'
    r'.*?}'
)


# Matches the fault injection start message (optional context)
fault_injection_start_pattern = re.compile(
    r'\[Run\] Starting Fault Injection Task'
)


# --- Helper Functions ---

def duration_to_ms(secs, nanos):
    """Converts secs and nanos to total milliseconds."""
    return (secs * 1000) + (nanos / 1_000_000)

def calculate_latency_stats_ms(latencies_ms):
    """Calculates Avg, P95, P99 in milliseconds."""
    if not latencies_ms:
        return 0.0, 0.0, 0.0, 0 # Return count as well
    
    latencies_array = np.array(latencies_ms)
    avg = np.mean(latencies_array)
    p95 = np.percentile(latencies_array, 95)
    p99 = np.percentile(latencies_array, 99)
    count = len(latencies_array)
    return avg, p95, p99, count

# --- ADDED: Function to reconstruct crash intervals ---
def reconstruct_crash_intervals(isolation_events, rejoin_events, default_duration_ms=30000):
    """Matches isolation and rejoin events to create crash intervals."""
    # Sort events by timestamp to process chronologically
    isolation_events.sort()
    rejoin_events.sort()
    
    crash_intervals = [] # List of (start_ms, end_ms, node_id)
    
    # Use dicts for quick lookup: {node_id: [timestamps]}
    iso_times = defaultdict(list)
    rejoin_times = defaultdict(list)
    
    for ts, node_id in isolation_events:
        iso_times[node_id].append(ts)
    for ts, node_id in rejoin_events:
        rejoin_times[node_id].append(ts)
        
    processed_rejoins = defaultdict(set) # Keep track of used rejoins {node_id: {timestamp}}

    # Match isolation events with subsequent rejoin events for the same node
    for node_id, iso_list in iso_times.items():
        for iso_ts in iso_list:
            found_rejoin = False
            # Find the *earliest* rejoin time for this node *after* this isolation time
            # that hasn't already been used
            best_rejoin_ts = None
            if node_id in rejoin_times:
                for rejoin_ts in rejoin_times[node_id]:
                     if rejoin_ts > iso_ts and rejoin_ts not in processed_rejoins[node_id]:
                         # Is this the earliest valid rejoin we've found for this iso_ts?
                         if best_rejoin_ts is None or rejoin_ts < best_rejoin_ts:
                             best_rejoin_ts = rejoin_ts

            if best_rejoin_ts is not None:
                 # Found a match
                 crash_intervals.append((iso_ts, best_rejoin_ts, node_id))
                 processed_rejoins[node_id].add(best_rejoin_ts) # Mark rejoin as used
                 found_rejoin = True
            
            if not found_rejoin:
                # If no rejoin found (e.g., test ended), use default duration
                print(f"  Warning: No matching rejoin found for Node {node_id} isolated at {iso_ts} ms. Assuming {default_duration_ms} ms duration.")
                crash_intervals.append((iso_ts, iso_ts + default_duration_ms, node_id))

    # Sort final intervals by start time
    crash_intervals.sort()
    return crash_intervals


# --- Main Parsing Function ---

def parse_log_file(log_file_path):
    """Parses Scenario E log file."""
    results = {
        "election_events": [], # List of (timestamp_ms, leader_id, term)
        "transaction_results": [], # List of (end_time_ms, duration_ms, success, is_cross_chain)
        "isolation_events": [], # List of (timestamp_ms, node_id)
        "rejoin_events": [], # List of (timestamp_ms, node_id)  # ADDED
        "first_event_ms": None,
        "last_event_ms": None,
        "fault_injection_start_detected": False,
        "lines_processed": 0,
        "matches_found": Counter(),
        "errors": []
    }
    
    lines_processed = 0
    start_time = datetime.datetime.now()
    print(f"Starting analysis of {log_file_path}...")

    try:
        with open(log_file_path, 'r', encoding='ISO-8859-1') as f:
            for i, line in enumerate(f):
                lines_processed = i + 1
                current_event_ms = None

                # --- Check all patterns ---
                election_match = election_pattern.search(line)
                transaction_match = transaction_pattern.search(line)
                isolated_match = isolated_pattern.search(line)
                rejoined_match = rejoined_pattern.search(line) # ADDED Check
                fault_start_match = fault_injection_start_pattern.search(line)

                # --- Process matches ---
                if election_match:
                    data = election_match.groupdict()
                    ts = int(data['timestamp_ms'])
                    results["election_events"].append((ts, int(data['leader_id']), int(data['term'])))
                    results["matches_found"]["election"] += 1
                    current_event_ms = ts
                elif transaction_match:
                    data = transaction_match.groupdict()
                    # --- Use end_time_ms from the regex ---
                    ts = int(data['end_time_ms']) 
                    duration = duration_to_ms(int(data['secs']), int(data['nanos']))
                    success = data['success'] == 'true'
                    is_cross_chain = data['is_cross_chain'] == 'true'
                    results["transaction_results"].append((ts, duration, success, is_cross_chain))
                    results["matches_found"]["transaction"] += 1
                    current_event_ms = ts
                elif isolated_match:
                    data = isolated_match.groupdict()
                    ts = int(data['timestamp_ms'])
                    node_id = int(data['node_id'])
                    results["isolation_events"].append((ts, node_id))
                    results["matches_found"]["isolation"] += 1
                    # Don't treat isolation as first/last event anchor
                elif rejoined_match: # ADDED block
                     data = rejoined_match.groupdict()
                     ts = int(data['timestamp_ms'])
                     node_id = int(data['node_id'])
                     results["rejoin_events"].append((ts, node_id))
                     results["matches_found"]["rejoin"] += 1
                     # Don't treat rejoin as first/last event anchor
                elif fault_start_match:
                     results["fault_injection_start_detected"] = True
                     results["matches_found"]["fault_start"] += 1


                # Update overall time window based on transaction/election events
                if current_event_ms:
                    if results["first_event_ms"] is None or current_event_ms < results["first_event_ms"]:
                        results["first_event_ms"] = current_event_ms
                    if results["last_event_ms"] is None or current_event_ms > results["last_event_ms"]:
                        results["last_event_ms"] = current_event_ms

                # Progress reporting
                if lines_processed % 5_000_000 == 0:
                     elapsed = (datetime.datetime.now() - start_time).total_seconds()
                     print(f"  Processed {lines_processed:,} lines... "
                           f"({results['matches_found'].total()} matches found) [{elapsed:.1f}s]")

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}", file=sys.stderr)
        return None
    except Exception as e:
        results["errors"].append(f"Error during parsing line {lines_processed}: {e}")
        print(f"An error occurred during parsing line {lines_processed}: {e}", file=sys.stderr)
        # Continue processing if possible, maybe log the problematic line
        # print(f"Problematic line content (first 100 chars): {line[:100]}", file=sys.stderr)

    results["lines_processed"] = lines_processed
    end_time = datetime.datetime.now()
    total_time = (end_time - start_time).total_seconds()
    print(f"Finished analysis in {total_time:.2f} seconds.")
    print(f"Processed {lines_processed:,} lines.")
    print(f"Found: {results['matches_found']['transaction']} transactions, "
          f"{results['matches_found']['election']} elections, "
          f"{results['matches_found']['isolation']} isolations, "
          f"{results['matches_found']['rejoin']} rejoins.") # ADDED Rejoin count
    if not results["fault_injection_start_detected"]:
         print("Warning: Fault injection start message not detected in log.")


    return results

# --- Main Analysis Logic ---

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <path_to_log_file>")
        sys.exit(1)

    log_file_path = sys.argv[1]
    
    parsed_data = parse_log_file(log_file_path)

    if parsed_data is None:
        sys.exit(1)
        
    if parsed_data["errors"]:
        print("\n--- Parsing Errors ---")
        for err in parsed_data["errors"]:
            print(err)
            
    # --- Reconstruct crash intervals ---
    print("\nReconstructing crash intervals...")
    crash_intervals = reconstruct_crash_intervals(
        parsed_data["isolation_events"], 
        parsed_data["rejoin_events"]
    )
    print(f"Reconstructed {len(crash_intervals)} crash intervals.")
    # --- END Crash Interval Reconstruction ---
    
    # Time window based on election events (or crash events if elections are missing)
    first_ts = parsed_data["first_event_ms"] # This is based on Election or Tx events
    last_ts = parsed_data["last_event_ms"]   # This is based on Election or Tx events
    
    # --- ADDED: Fallback timing if no election/tx events found ---
    if first_ts is None or last_ts is None:
        all_fault_times = [ts for ts, _ in parsed_data["isolation_events"]] + \
                          [ts for ts, _ in parsed_data["rejoin_events"]]
        if all_fault_times:
            first_ts = min(all_fault_times)
            last_ts = max(all_fault_times)
            print("Warning: Using fault event timestamps to estimate duration (no election/tx events).")
        else:
             print("Warning: Cannot determine run duration (no election/tx/fault events with timestamps).")
    # --- END Fallback timing ---

    total_duration_ms = 0
    total_duration_sec = 0
    if first_ts is not None and last_ts is not None and last_ts > first_ts:
         total_duration_ms = last_ts - first_ts
         total_duration_sec = total_duration_ms / 1000.0
    
    # Elections
    num_elections = len(parsed_data["election_events"])
    avg_minutes_per_election = float('inf')
    if num_elections > 0 and total_duration_sec > 0:
        total_duration_min = total_duration_sec / 60.0
        avg_minutes_per_election = total_duration_min / num_elections

    # --- ADDED: Analyze elections relative to crashes, leader distribution, term progression ---
    elections_during_crash = 0
    elections_outside_crash = 0
    leader_counts = Counter()
    term_progression = [] # List of (timestamp_ms, term)
    terms_seen = set()

    if parsed_data["election_events"]:
        # Sort events by timestamp just in case they aren't already
        sorted_elections = sorted(parsed_data["election_events"])
        
        for ts, leader_id, term in sorted_elections:
            leader_counts[leader_id] += 1
            term_progression.append((ts, term))
            terms_seen.add(term)

            is_during_crash = False
            for start_ms, end_ms, _node_id in crash_intervals:
                if ts >= start_ms and ts <= end_ms:
                    is_during_crash = True
                    break
            
            if is_during_crash:
                elections_during_crash += 1
            else:
                elections_outside_crash += 1
                
        start_term = sorted_elections[0][2]
        end_term = sorted_elections[-1][2]
    else:
        start_term = None
        end_term = None
    # --- END ADDED Section ---

    # --- ADDED: Calculate crash durations and election rates ---
    total_crash_duration_ms = sum(end - start for start, end, _ in crash_intervals)
    normal_duration_ms = total_duration_ms - total_crash_duration_ms

    election_rate_during_crash_per_sec = 0
    if total_crash_duration_ms > 0:
        election_rate_during_crash_per_sec = elections_during_crash / (total_crash_duration_ms / 1000.0)
        
    election_rate_outside_crash_per_sec = 0
    # Ensure normal duration is positive to avoid division by zero
    if normal_duration_ms > 0: 
        election_rate_outside_crash_per_sec = elections_outside_crash / (normal_duration_ms / 1000.0)
    # --- END Calculation ---

    # --- Print Results ---
    print("\n--- Scenario E Analysis (Limited due to missing transaction logs) ---")

    print("\n1. Raft Elections & Faults:")
    print(f"  - Total leader elections triggered: {num_elections}")
    if total_duration_sec > 0 :
        print(f"  - Estimated run duration: {total_duration_sec:.2f} seconds ({total_duration_sec/60.0:.2f} minutes)")
        if num_elections > 0:
            print(f"  - Average time between elections: {avg_minutes_per_election:.2f} minutes")
            # --- ADDED: Print elections during/outside crash intervals ---
            print(f"  - Elections during reconstructed crash intervals: {elections_during_crash}")
            print(f"  - Elections outside reconstructed crash intervals: {elections_outside_crash}")
            # --- END ADDED ---
        else:
            print("  - No elections detected during this period.")
    else:
        print("  - Could not determine run duration from logs.")
    print(f"  - Node isolation events detected: {len(parsed_data['isolation_events'])}")
    print(f"  - Node rejoin events detected: {len(parsed_data['rejoin_events'])}")
    print(f"  - Reconstructed crash intervals: {len(crash_intervals)}")
    # --- ADDED: Print crash interval details ---
    if crash_intervals:
        print("    Crash Interval Details:")
        total_calculated_crash_duration_sec = 0
        for i, (start, end, node_id) in enumerate(crash_intervals):
            duration_sec = (end - start) / 1000.0
            total_calculated_crash_duration_sec += duration_sec
            print(f"      - Interval {i+1}: Node {node_id}, Duration={duration_sec:.2f}s (Start: {start}ms, End: {end}ms)")
        print(f"      - Total Duration of Crash Intervals: {total_calculated_crash_duration_sec:.2f}s ({total_crash_duration_ms/1000.0:.2f}s)") # Verify calculation
    # --- END ADDED ---

    # --- ADDED: Print Leader Distribution and Term Progression --- 
    print("\n2. Leader Distribution & Term Progression:")
    if leader_counts:
        print("  - Leader Election Counts (Top 5):")
        for leader_id, count in leader_counts.most_common(5):
            print(f"    - Node {leader_id}: {count} times")
    else:
        print("  - No leaders elected.")

    if start_term is not None and end_term is not None:
        print(f"  - Raft Term Progression: Started at Term {start_term}, Ended at Term {end_term}")
        print(f"  - Total unique terms with elections: {len(terms_seen)}")
    else:
        print("  - Could not determine Raft term progression.")
    # --- END ADDED ---

    # --- MODIFIED: Section 4 (Interpretation Notes) --- ## Renumber section
    print("\n3. Interpretation Notes (Compare with LaTeX goals - Limited):") # Renumbered
    print(f"  - LaTeX Goal: Elections ~ every 2-3 min. Observed Overall: ~ every {avg_minutes_per_election:.2f} min.")
    print("    Election Rates:")
    print(f"      - During Crash Intervals: {election_rate_during_crash_per_sec:.2f} elections/sec (~ every {1/election_rate_during_crash_per_sec:.2f} sec)")
    print(f"      - Outside Crash Intervals: {election_rate_outside_crash_per_sec:.2f} elections/sec (~ every {1/election_rate_outside_crash_per_sec:.2f} sec)")
    print(f"  - LaTeX Goal: Latency spike ~1-2s during elections.")
    print("    - Latency cannot be measured from these logs.")
    print(f"  - LaTeX Goal: Minimal throughput drop (<10%).")
    print(f"  - LaTeX Goal: CC abort rate near zero.")
    print("    - Abort rate cannot be measured from these logs.")

    print("\n--------------------------")

if __name__ == "__main__":
    main()
