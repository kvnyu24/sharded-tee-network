import re
import sys
import numpy as np
from collections import defaultdict
import datetime

# Regex updated to match the format in the screenshot:
# "... TeeFunctionMeasured metric for 'FunctionName' (duration: XX.XXXXms)"
log_pattern = re.compile(
    r"TeeFunctionMeasured metric for '(?P<func_name>[^']+)' " # Capture function name in single quotes
    r"\(duration: (?P<ms>\d+\.\d+)ms\)" # Capture duration in ms
)

def calculate_stats_ms(durations_ms_list):
    """Calculates Avg, P95, P99 in milliseconds from a list of millisecond values."""
    if not durations_ms_list:
        return 0.0, 0.0, 0.0, 0
    
    # Durations are already in milliseconds
    durations_ms_array = np.array(durations_ms_list)
    
    avg = np.mean(durations_ms_array)
    p95 = np.percentile(durations_ms_array, 95)
    p99 = np.percentile(durations_ms_array, 99)
    count = len(durations_ms_array)
    
    return avg, p95, p99, count

def parse_log_file(log_file_path):
    """Parses the log file to extract TEE function durations in milliseconds."""
    # Store times directly in milliseconds now
    tee_function_times_ms = defaultdict(list) 
    lines_processed = 0
    matches_found = 0
    start_time = datetime.datetime.now()
    print(f"Starting analysis of {log_file_path}...")

    try:
        # Use 'ISO-8859-1' or 'latin-1' if 'utf-8' fails on special characters
        with open(log_file_path, 'r', encoding='ISO-8859-1') as f: 
            for i, line in enumerate(f):
                lines_processed = i + 1
                match = log_pattern.search(line)
                if match:
                    matches_found += 1
                    data = match.groupdict()
                    func_name = data['func_name']
                    # Duration is already in ms, convert string to float
                    duration_ms = float(data['ms']) 
                    tee_function_times_ms[func_name].append(duration_ms)
                
                # Print progress occasionally for large files
                if lines_processed % 5_000_000 == 0: # Adjusted progress reporting interval
                     elapsed = (datetime.datetime.now() - start_time).total_seconds()
                     print(f"  Processed {lines_processed:,} lines... ({matches_found} matches found) [{elapsed:.1f}s]")

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"An error occurred during parsing line {lines_processed}: {e}", file=sys.stderr)
        print(f"Problematic line content (first 100 chars): {line[:100]}", file=sys.stderr)
        return None # Stop processing on error

    end_time = datetime.datetime.now()
    total_time = (end_time - start_time).total_seconds()
    print(f"Finished analysis in {total_time:.2f} seconds.")
    print(f"Processed {lines_processed:,} lines, found {matches_found} TeeFunctionMeasured events.")

    return tee_function_times_ms

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <path_to_log_file>")
        sys.exit(1)

    log_file_path = sys.argv[1]
    
    tee_times = parse_log_file(log_file_path)

    if tee_times is None:
        sys.exit(1)

    if not tee_times:
        print("\nNo TeeFunctionMeasured events found in the log file matching the pattern.")
        return

    print("\n--- TEE Function Overhead Analysis ---")
    print("Function Name          | Avg (ms) | P95 (ms) | P99 (ms) | Samples")
    print("-----------------------|----------|----------|----------|---------")

    # Sort by function name for consistent output
    sorted_func_names = sorted(tee_times.keys())

    for func_name in sorted_func_names:
        # Pass the list of millisecond durations
        durations_ms = tee_times[func_name] 
        avg_ms, p95_ms, p99_ms, count = calculate_stats_ms(durations_ms)
        print(f"{func_name:<22} | {avg_ms:>8.3f} | {p95_ms:>8.3f} | {p99_ms:>8.3f} | {count:>7}")

    print("--------------------------------------")

if __name__ == "__main__":
    main()