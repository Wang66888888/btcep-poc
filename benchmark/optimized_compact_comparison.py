"""Fair three-way comparison of expiration manager implementations."""
import csv
import gc
import random
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmark.compact_threshold_ablation import events_for, SEED
from engine.compact_expiration_runtime import CompactExpirationBTRuntime
from engine.expiration_indexed_runtime import ExpirationIndexedBTRuntime
from engine.optimized_compact_expiration_runtime import (
    OptimizedCompactExpirationBTRuntime,
)
from patterns.security_attack import privilege_attack_pattern


SCALES = (100, 1000, 3000)
REPEATS = 10
POLICIES = (
    "expiration_indexed",
    "compact_default",
    "optimized_default",
    "compact_128_3A",
    "optimized_128_3A",
)
WORKLOADS = (
    "many_active_few_complete",
    "rapid_completion",
    "continuous_create_expire",
    "high_active_threshold_pressure",
)
RESULT_DIR = Path(__file__).resolve().parent / "results"


def output_path(stem):
    for suffix in range(1, 10000):
        tail = "" if suffix == 1 else f"_{suffix}"
        path = RESULT_DIR / f"{stem}{tail}.csv"
        if not path.exists():
            return path
    raise RuntimeError("No unused benchmark output path")


def make_runtime(policy):
    if policy == "expiration_indexed":
        return ExpirationIndexedBTRuntime(privilege_attack_pattern)
    if policy == "compact_default":
        return CompactExpirationBTRuntime(privilege_attack_pattern)
    if policy == "optimized_default":
        return OptimizedCompactExpirationBTRuntime(privilege_attack_pattern)
    if policy == "compact_128_3A":
        return CompactExpirationBTRuntime(
            privilege_attack_pattern, compact_min=128, compact_factor=3.0
        )
    if policy == "optimized_128_3A":
        return OptimizedCompactExpirationBTRuntime(
            privilege_attack_pattern, compact_min=128, compact_factor=3.0
        )
    raise ValueError(policy)


def process_result(runtime):
    manager = runtime.manager
    return {
        "active": runtime.active_instances(),
        "heap": len(manager.expiration_heap),
        "compactions": getattr(manager, "compaction_count", 0),
    }


def validate_equivalence(events):
    reference = None
    for policy in POLICIES:
        runtime = make_runtime(policy)
        history = []
        detections = []
        for event in events:
            detected = runtime.process_event(event)
            detections.extend(detected)
            state = process_result(runtime)
            history.append((tuple(detected), state["active"]))
        outcome = (detections, history, runtime.active_instances(), runtime.peak_instances())
        if reference is None:
            reference = outcome
        else:
            assert outcome == reference, f"behavior mismatch for {policy}"


def run_once(policy, events):
    gc.collect()
    runtime = make_runtime(policy)
    manager = runtime.manager
    detected = []
    peak_heap = 0
    start = time.perf_counter()
    for event in events:
        result = runtime.process_event(event)
        if result:
            detected.extend(result)
        heap_size = len(manager.expiration_heap)
        if heap_size > peak_heap:
            peak_heap = heap_size
    elapsed = time.perf_counter() - start
    return {
        "detection_count": len(detected),
        "detections": detected,
        "final_active": runtime.active_instances(),
        "peak_active": runtime.peak_instances(),
        "elapsed_s": elapsed,
        "throughput_eps": len(events) / elapsed if elapsed else 0,
        "avg_event_latency_ms": elapsed * 1000 / len(events),
        "peak_heap_records": peak_heap,
        "final_heap_records": len(manager.expiration_heap),
        "compaction_count": getattr(manager, "compaction_count", 0),
        "compaction_check_count": getattr(manager, "compaction_check_count", 0),
    }


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def summarize(rows):
    metrics = (
        "elapsed_s", "throughput_eps", "avg_event_latency_ms", "peak_active",
        "peak_heap_records", "final_heap_records", "compaction_count",
        "compaction_check_count",
    )
    summaries = []
    for workload in WORKLOADS:
        for users in SCALES:
            for policy in POLICIES:
                selected = [r for r in rows if r["workload"] == workload
                            and r["users"] == users and r["policy"] == policy]
                row = {"workload": workload, "users": users, "policy": policy}
                for metric in metrics:
                    values = [float(r[metric]) for r in selected]
                    row[f"{metric}_mean"] = statistics.mean(values)
                    row[f"{metric}_std"] = statistics.stdev(values)
                summaries.append(row)
    for summary in summaries:
        base = next(r for r in summaries if r["workload"] == summary["workload"]
                    and r["users"] == summary["users"]
                    and r["policy"] == "expiration_indexed")
        for metric in ("throughput_eps", "elapsed_s", "peak_heap_records", "final_heap_records"):
            denominator = base[f"{metric}_mean"]
            summary[f"{metric}_change_pct_vs_expiration_indexed"] = (
                (summary[f"{metric}_mean"] / denominator - 1) * 100
                if denominator else ""
            )
    return summaries


def main():
    RESULT_DIR.mkdir(exist_ok=True)
    raw_path = output_path("optimized_compact_comparison_raw")
    summary_path = output_path("optimized_compact_comparison_summary")
    rows = []
    order_rng = random.Random(SEED)
    for workload in WORKLOADS:
        for users in SCALES:
            events = events_for(users, workload)
            validate_equivalence(events)
            reference_detections = None
            for repeat in range(1, REPEATS + 1):
                order = list(POLICIES)
                order_rng.shuffle(order)
                for policy in order:
                    result = run_once(policy, events)
                    if reference_detections is None:
                        reference_detections = result["detections"]
                    assert result["detections"] == reference_detections
                    rows.append({k: v for k, v in result.items() if k != "detections"} | {
                        "workload": workload, "users": users, "events": len(events),
                        "repeat": repeat, "seed": SEED, "policy": policy,
                    })
            print(f"completed {workload} users={users} events={len(events)}", flush=True)

    summaries = summarize(rows)
    write_csv(raw_path, rows)
    write_csv(summary_path, summaries)
    print(f"Raw: {raw_path}\nSummary: {summary_path}")
    print("Per-event detections, active-count histories, final and peak active counts matched.")


if __name__ == "__main__":
    main()
