#!/usr/bin/env python3
"""
TrigGuard Load Test

Measure execution gate performance under load.

Run with:
    python tests/load_test_gate.py

Metrics:
- Average latency
- P95 latency
- Throughput (decisions/sec)
"""

import time
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

from sdk import gate
from telemetry import get_telemetry, reset_telemetry


def run_single_evaluation(request_num: int) -> Tuple[int, float, bool]:
    """
    Run a single gate evaluation.

    Returns:
        (request_num, latency_ms, success)
    """
    request = {
        "surface": "inference",
        "action": f"test_action_{request_num}",
        "arguments": {"data": f"payload_{request_num}"},
    }

    start = time.perf_counter()
    try:
        result = gate.check(request)
        latency_ms = (time.perf_counter() - start) * 1000
        return (request_num, latency_ms, True)
    except Exception as e:
        latency_ms = (time.perf_counter() - start) * 1000
        return (request_num, latency_ms, False)


def run_sequential_load_test(count: int) -> List[float]:
    """Run sequential evaluations."""
    latencies = []

    print(f"Running {count} sequential evaluations...")

    for i in range(count):
        _, latency, _ = run_single_evaluation(i)
        latencies.append(latency)

        if (i + 1) % 1000 == 0:
            print(f"  Completed {i + 1}/{count}")

    return latencies


def run_concurrent_load_test(count: int, workers: int = 10) -> List[float]:
    """Run concurrent evaluations."""
    latencies = []

    print(f"Running {count} concurrent evaluations ({workers} workers)...")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(run_single_evaluation, i) for i in range(count)]

        completed = 0
        for future in as_completed(futures):
            _, latency, _ = future.result()
            latencies.append(latency)
            completed += 1

            if completed % 1000 == 0:
                print(f"  Completed {completed}/{count}")

    return latencies


def calculate_percentile(data: List[float], percentile: float) -> float:
    """Calculate percentile of data."""
    sorted_data = sorted(data)
    index = int(len(sorted_data) * percentile / 100)
    return sorted_data[min(index, len(sorted_data) - 1)]


def print_results(latencies: List[float], total_time: float, test_name: str):
    """Print test results."""
    print()
    print("=" * 60)
    print(f"RESULTS: {test_name}")
    print("=" * 60)

    count = len(latencies)
    avg_latency = statistics.mean(latencies)
    p50_latency = calculate_percentile(latencies, 50)
    p95_latency = calculate_percentile(latencies, 95)
    p99_latency = calculate_percentile(latencies, 99)
    min_latency = min(latencies)
    max_latency = max(latencies)
    throughput = count / total_time

    print(f"Total evaluations:     {count:,}")
    print(f"Total time:            {total_time:.2f}s")
    print()
    print("LATENCY (ms)")
    print("-" * 40)
    print(f"  Average:             {avg_latency:.3f}")
    print(f"  P50 (median):        {p50_latency:.3f}")
    print(f"  P95:                 {p95_latency:.3f}")
    print(f"  P99:                 {p99_latency:.3f}")
    print(f"  Min:                 {min_latency:.3f}")
    print(f"  Max:                 {max_latency:.3f}")
    print()
    print("THROUGHPUT")
    print("-" * 40)
    print(f"  Decisions/sec:       {throughput:.1f}")
    print(f"  Decisions/min:       {throughput * 60:.0f}")
    print()


def run_load_test(count: int = 10000, concurrent: bool = True, workers: int = 10):
    """Run the full load test."""
    reset_telemetry()

    print()
    print("╔════════════════════════════════════════════════════════════╗")
    print("║          TRIGGUARD LOAD TEST                               ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print()
    print(f"Configuration:")
    print(f"  Evaluations: {count:,}")
    print(f"  Mode: {'Concurrent' if concurrent else 'Sequential'}")
    if concurrent:
        print(f"  Workers: {workers}")
    print()

    start_time = time.perf_counter()

    if concurrent:
        latencies = run_concurrent_load_test(count, workers)
    else:
        latencies = run_sequential_load_test(count)

    total_time = time.perf_counter() - start_time

    test_name = (
        f"{'Concurrent' if concurrent else 'Sequential'} ({count:,} evaluations)"
    )
    print_results(latencies, total_time, test_name)

    # Verify telemetry
    telemetry = get_telemetry()
    print("TELEMETRY VERIFICATION")
    print("-" * 40)
    print(f"  Gates evaluated:     {telemetry.gates_evaluated.value:,}")
    print()

    return latencies, total_time


def main():
    """Run load tests."""
    import argparse

    parser = argparse.ArgumentParser(description="TrigGuard Load Test")
    parser.add_argument(
        "-n",
        "--count",
        type=int,
        default=10000,
        help="Number of evaluations (default: 10000)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=10,
        help="Number of concurrent workers (default: 10)",
    )
    parser.add_argument(
        "--sequential", action="store_true", help="Run sequential instead of concurrent"
    )

    args = parser.parse_args()

    run_load_test(
        count=args.count,
        concurrent=not args.sequential,
        workers=args.workers,
    )

    print("=" * 60)
    print("LOAD TEST COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
