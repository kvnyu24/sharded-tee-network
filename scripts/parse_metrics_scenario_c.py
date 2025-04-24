"""
Parses simulation logs specifically for Scenario C TEE overhead results.
Looks for '[MetricsCollector] Received event: TeeFunctionMeasured ...' lines
and calculates statistics (count, average, p95, p99) for each measured TEE function.
"""
import re
import sys
import statistics
import math
from collections import defaultdict
import argparse

# Regex to capture the TeeFunctionMeasured event details logged by MetricsCollector
# Assumes the Debug format of the event. Robustness depends on stable Debug format.
# Captures: function_name, duration_value, duration_unit (s, ms, µs, ns)
metric_pattern = re.compile(
    r"\[MetricsCollector\]\s+Received\s+event:\s+TeeFunctionMeasured\s*\{" # Match start
    r".*?" # Non-greedily match anything until the function name
    r"function_name:\s*\"(?P<func_name>\w+)\"" # Capture function name
    r".*?" # Non-greedily match until the duration
    r"duration:\s*(?P<duration_val>[\d\.]+)(?P<duration_unit>s|ms|us|µs|ns)" # Capture duration
    r".*?\}" # Match the rest until the closing brace
)

def parse_duration_to_ms(value_str, unit):
    """Converts parsed duration string and unit to milliseconds."""
    try:
        value = float(value_str)
        if unit == 's':
            return value * 1000.0
        elif unit == 'ms':
            return value
        elif unit == 'µs' or unit == 'us': # Handle both microsecond symbols
            return value / 1000.0
        elif unit == 'ns':
            return value / 1_000_000.0
        else:
            print(f"Warning: Unknown duration unit '{unit}'. Skipping value {value_str}.")
            return None
    except ValueError:
        print(f"Warning: Could not parse duration value '{value_str}'. Skipping.")
        return None

def calculate_percentile(data, percentile):
    """Calculates the specified percentile for a list of durations."""
    if not data:
        return None
    data.sort()
    # Calculate index (0-based) using linear interpolation method (adjust if needed)
    k = (len(data) - 1) * (percentile / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return data[int(k)]
    # Linear interpolation
    d0 = data[int(f)] * (c - k)
    d1 = data[int(c)] * (k - f)
    return d0 + d1


def analyze_tee_log_file(log_file_path):
    """
    Parses a log file for TeeFunctionMeasured events and calculates stats.
    """
    tee_function_times = defaultdict(list) # func_name -> list of durations in ms
    lines_read = 0
    metrics_found = 0

    print(f"\n--- Analyzing TEE Overhead Log: {log_file_path} ---")

    try:
        with open(log_file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                lines_read += 1
                match = metric_pattern.search(line)
                if match:
                    metrics_found += 1
                    data = match.groupdict()
                    func_name = data['func_name']
                    duration_ms = parse_duration_to_ms(data['duration_val'], data['duration_unit'])

                    if duration_ms is not None:
                        tee_function_times[func_name].append(duration_ms)

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file_path}")
        return
    except Exception as e:
        print(f"Error reading or parsing log file line {line_num}: {e}")
        return

    print(f"Read {lines_read} lines, found {metrics_found} TeeFunctionMeasured events.")

    if not tee_function_times:
        print("No valid TeeFunctionMeasured metrics found in the log file.")
        return

    # --- Analysis ---
    print("\n[Results] TEE Function Call Overheads (ms):")
    sorted_func_names = sorted(tee_function_times.keys())

    for func_name in sorted_func_names:
        times_ms = tee_function_times[func_name]
        count = len(times_ms)
        print(f"  - {func_name}: {count} calls")

        if count > 0:
            avg_ms = statistics.mean(times_ms)
            p95_ms = calculate_percentile(times_ms, 95.0) # times_ms is sorted by calculate_percentile
            p99_ms = calculate_percentile(times_ms, 99.0) # times_ms remains sorted

            print(f"    - Avg: {avg_ms:.3f} ms")
            if p95_ms is not None:
                print(f"    - P95: {p95_ms:.3f} ms")
            if p99_ms is not None:
                print(f"    - P99: {p99_ms:.3f} ms")
        else:
            print("    - (No timing data collected)")

    print("-" * 40)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Analyze Scenario C simulation logs for TEE function overhead metrics."
    )
    parser.add_argument(
        "log_files",
        nargs='+',
        help="Path(s) to the Scenario C simulation log file(s)."
    )

    args = parser.parse_args()

    for log_file in args.log_files:
        analyze_tee_log_file(log_file) 