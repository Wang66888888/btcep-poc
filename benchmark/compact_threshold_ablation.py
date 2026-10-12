"""Threshold ablation and low-instrumentation overhead attribution."""
import csv
import gc
import random
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmark.compact_expiration_benchmark import (
    RESULT_DIR,
    generate_events,
    peak_process_memory_mb,
)
from engine.compact_expiration_runtime import CompactExpirationBTRuntime
from engine.expiration_indexed_runtime import ExpirationIndexedBTRuntime
from patterns.security_attack import privilege_attack_pattern


USER_SCALES = (100, 1000, 3000)
REPEATS = 5
SEED = 20261008
POLICIES = {
    "no_compaction": None,
    "max32_1.5A": (32, 1.5),
    "max64_2A": (64, 2.0),
    "max128_3A": (128, 3.0),
    "max256_4A": (256, 4.0),
}
WORKLOADS = (
    "many_active_few_complete",
    "rapid_completion",
    "continuous_create_expire",
    "high_active_threshold_pressure",
)
RAW_STEM = "compact_threshold_ablation_raw"
SUMMARY_STEM = "compact_threshold_ablation_summary"
ATTRIBUTION_STEM = "compact_overhead_attribution"


def output_path(stem):
    for suffix in range(1, 10000):
        tag = "" if suffix == 1 else f"_{suffix}"
        path = RESULT_DIR / f"{stem}{tag}.csv"
        if not path.exists():
            return path
    raise RuntimeError(f"No unused result filename available for {stem}")


def pressure_events(users, seed):
    """Accumulate stale records while keeping many instances active.

    Initial active matches stay open. Each churn wave creates and completes
    another group. Global time only advances by one per wave, within the 30s
    window of the original active cohort, so compaction thresholds are crossed
    while A remains large.
    """
    rng = random.Random(seed)
    events = [
        __import__("core.event", fromlist=["Event"]).Event(
            "LOGIN_FAIL", 0, {"user": f"Anchor{i}"}
        )
        for i in range(users)
    ]
    waves = 30
    for wave in range(1, waves + 1):
        time_value = wave
        indices = list(range(users))
        rng.shuffle(indices)
        for i in indices:
            events.append(__import__("core.event", fromlist=["Event"]).Event(
                "LOGIN_FAIL", time_value, {"user": f"Churn{wave}_{i}"}
            ))
        for i in indices:
            events.append(__import__("core.event", fromlist=["Event"]).Event(
                "PRIVILEGE_ESCALATION", time_value, {"user": f"Churn{wave}_{i}"}
            ))
    assert all(a.timestamp <= b.timestamp for a, b in zip(events, events[1:]))
    return events


def events_for(users, workload):
    if workload == "high_active_threshold_pressure":
        return pressure_events(users, SEED + users)
    return generate_events(users, workload)


def build_runtime(policy):
    config = POLICIES[policy]
    if config is None:
        # Disable compression with an unreachable minimum threshold.
        return CompactExpirationBTRuntime(
            privilege_attack_pattern, compact_min=sys.maxsize, compact_factor=0
        )
    return CompactExpirationBTRuntime(
        privilege_attack_pattern, compact_min=config[0], compact_factor=config[1]
    )


def run(policy, events):
    gc.collect()
    runtime = build_runtime(policy)
    manager = runtime.manager
    detections = []
    peak_heap = 0
    started = time.perf_counter()
    for event in events:
        detections.extend(runtime.process_event(event))
        peak_heap = max(peak_heap, len(manager.expiration_heap))
    elapsed = time.perf_counter() - started
    return {
        "detections": detections,
        "detection_count": len(detections),
        "final_active": runtime.active_instances(),
        "peak_active": runtime.peak_instances(),
        "elapsed_s": elapsed,
        "throughput_eps": len(events) / elapsed if elapsed else 0,
        "avg_event_latency_ms": elapsed * 1000 / len(events) if events else 0,
        "compaction_count": manager.compaction_count,
        "compaction_check_count": manager.compaction_check_count,
        "peak_heap_records": peak_heap,
        "final_heap_records": len(manager.expiration_heap),
        "process_peak_working_set_mb": peak_process_memory_mb(),
        "memory_scope": "whole process peak working set, not manager-only",
    }


def run_baseline(events):
    gc.collect()
    runtime = ExpirationIndexedBTRuntime(privilege_attack_pattern)
    detections = []
    peak_heap = 0
    started = time.perf_counter()
    for event in events:
        detections.extend(runtime.process_event(event))
        peak_heap = max(peak_heap, len(runtime.manager.expiration_heap))
    elapsed = time.perf_counter() - started
    return {
        "detections": detections,
        "detection_count": len(detections),
        "final_active": runtime.active_instances(),
        "peak_active": runtime.peak_instances(),
        "elapsed_s": elapsed,
        "throughput_eps": len(events) / elapsed if elapsed else 0,
        "avg_event_latency_ms": elapsed * 1000 / len(events) if events else 0,
        "compaction_count": 0,
        "compaction_check_count": 0,
        "peak_heap_records": peak_heap,
        "final_heap_records": len(runtime.manager.expiration_heap),
        "process_peak_working_set_mb": peak_process_memory_mb(),
        "memory_scope": "whole process peak working set, not manager-only",
    }


def attribute_overhead(events, repeats=20, workload_name="unspecified"):
    """Profile diagnostic overhead in separate repeated passes.

    Runs with profiling hooks enabled are not used for throughput results.
    Profile manager conditional checks and heap rebuilds separately; report
    uncategorized total-minus-instrumented time as remaining manager/runtime
    work plus timer noise rather than assigning it to compression.
    """
    result_rows = []
    for mode in ("expiration_indexed", "compact_no_rebuild", "compact_default"):
        total_samples, check_samples, rebuild_samples = [], [], []
        check_counts, rebuild_counts = [], []
        for _ in range(repeats):
            runtime = (ExpirationIndexedBTRuntime(privilege_attack_pattern)
                       if mode == "expiration_indexed"
                       else build_runtime("no_compaction" if mode == "compact_no_rebuild" else "max64_2A"))
            manager = runtime.manager
            detections = []
            check_ns = [0]
            rebuild_ns = [0]
            if mode != "expiration_indexed":
                original = manager._maybe_compact
                original_rebuild = manager._rebuild_heap
                def instrumented_rebuild():
                    started = time.perf_counter_ns()
                    original_rebuild()
                    rebuild_ns[0] += time.perf_counter_ns() - started
                manager._rebuild_heap = instrumented_rebuild
                def instrumented():
                    started = time.perf_counter_ns()
                    original()
                    check_ns[0] += time.perf_counter_ns() - started
                manager._maybe_compact = instrumented
            start = time.perf_counter_ns()
            for event in events:
                detections.extend(runtime.process_event(event))
            total_ns = time.perf_counter_ns() - start
            total_samples.append(total_ns)
            check_samples.append(check_ns[0])
            rebuild_samples.append(rebuild_ns[0])
            check_counts.append(getattr(manager, "compaction_check_count", 0))
            rebuild_counts.append(getattr(manager, "compaction_count", 0))
        result_rows.append({
            "mode": mode,
            "workload": workload_name,
            "events": len(events),
            "repeats": repeats,
            "total_path_ns_mean": statistics.mean(total_samples),
            "total_path_ns_std": statistics.stdev(total_samples),
            "threshold_check_ns_mean": statistics.mean(check_samples),
            "threshold_check_ns_std": statistics.stdev(check_samples),
            "rebuild_ns_mean": statistics.mean(rebuild_samples),
            "rebuild_ns_std": statistics.stdev(rebuild_samples),
            "threshold_check_count_mean": statistics.mean(check_counts),
            "rebuild_count_mean": statistics.mean(rebuild_counts),
            "other_path_ns_mean": statistics.mean(
                [max(0, total - checks) for total, checks in zip(total_samples, check_samples)]
            ),
            "rebuild_is_subset_of_check_time": True,
            "interpretation": "instrumented diagnostic; timer overhead included in check/rebuild buckets",
        })
    return result_rows


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def summarize(rows):
    metrics = (
        "elapsed_s", "throughput_eps", "avg_event_latency_ms", "compaction_count",
        "compaction_check_count", "final_heap_records", "peak_heap_records",
        "process_peak_working_set_mb",
    )
    output = []
    for workload in WORKLOADS:
        for users in USER_SCALES:
            for policy in POLICIES:
                selected = [r for r in rows if r["workload"] == workload
                            and r["users"] == users and r["policy"] == policy]
                item = {"workload": workload, "users": users, "policy": policy}
                for metric in metrics:
                    values = [float(row[metric]) for row in selected]
                    item[metric + "_mean"] = statistics.mean(values)
                    item[metric + "_std"] = statistics.stdev(values)
                output.append(item)
    return output


def main():
    RESULT_DIR.mkdir(exist_ok=True)
    raw_path = output_path(RAW_STEM)
    summary_path = output_path(SUMMARY_STEM)
    attribution_path = output_path(ATTRIBUTION_STEM)
    rows = []
    rng = random.Random(SEED)
    for workload in WORKLOADS:
        for users in USER_SCALES:
            events = events_for(users, workload)
            reference = None
            for repeat in range(1, REPEATS + 1):
                order = list(POLICIES)
                rng.shuffle(order)
                for policy in order:
                    result = run(policy, events)
                    if reference is None:
                        reference = result["detections"], result["final_active"]
                    assert (result["detections"], result["final_active"]) == reference
                    rows.append({k: v for k, v in result.items() if k != "detections"} | {
                        "workload": workload, "users": users, "events": len(events),
                        "repeat": repeat, "seed": SEED, "policy": policy,
                    })
            print(f"finished {workload} users={users} events={len(events)}", flush=True)

    summaries = summarize(rows)
    # Separate no-rebuild and rebuild-heavy diagnostics.
    attribution = []
    for workload in ("many_active_few_complete", "high_active_threshold_pressure"):
        attribution.extend(attribute_overhead(
            events_for(1000, workload), repeats=20, workload_name=workload
        ))
    write_csv(raw_path, rows)
    write_csv(summary_path, summaries)
    write_csv(attribution_path, attribution)
    print(f"Raw: {raw_path}\nSummary: {summary_path}\nAttribution: {attribution_path}")
    print("All policy detection sequences and final active counts matched.")


if __name__ == "__main__":
    main()
