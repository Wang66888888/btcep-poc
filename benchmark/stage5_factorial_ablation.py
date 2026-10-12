"""2x2 factorial ablation for manager-check and runtime-update optimizations."""
import csv
import gc
import random
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmark.compact_threshold_ablation import events_for, SEED
from engine.compact_expiration_manager import CompactExpirationInstanceManager
from engine.optimized_compact_expiration_manager import (
    OptimizedCompactExpirationInstanceManager,
)
from patterns.security_attack import privilege_attack_pattern


SCALES = (100, 1000, 3000)
REPEATS = 10
FACTORS = ("O", "A", "B", "AB")
FACTOR_LABELS = {
    "O": "原阈值检查+原Runtime",
    "A": "优化阈值检查+原Runtime",
    "B": "原阈值检查+优化Runtime",
    "AB": "优化阈值检查+优化Runtime",
}
WORKLOADS = (
    "many_active_few_complete",
    "rapid_completion",
    "continuous_create_expire",
    "high_active_threshold_pressure",
)
RESULT_DIR = Path(__file__).resolve().parent / "results"


class FactorialRuntime:
    """Small adapter that composes the existing manager implementations."""

    def __init__(self, factor):
        self.factor = factor
        manager_type = (
            OptimizedCompactExpirationInstanceManager
            if factor in ("A", "AB")
            else CompactExpirationInstanceManager
        )
        self.manager = manager_type(
            privilege_attack_pattern, compact_min=64, compact_factor=2.0
        )
        self.max_active_instances = 0

    def process_event(self, event):
        result = self.manager.process_event(event)
        current = self.manager.active_count()
        if self.factor in ("B", "AB"):
            if current > self.max_active_instances:
                self.max_active_instances = current
        else:
            self.max_active_instances = max(self.max_active_instances, current)
        return result

    def active_instances(self):
        return self.manager.active_count()

    def peak_instances(self):
        return self.max_active_instances


def output_path(stem):
    for i in range(1, 10000):
        suffix = "" if i == 1 else f"_{i}"
        path = RESULT_DIR / f"{stem}{suffix}.csv"
        if not path.exists():
            return path
    raise RuntimeError("No unused output filename")


def validate_semantics(events, workload):
    reference = None
    for factor in FACTORS:
        runtime = FactorialRuntime(factor)
        history = []
        detections = []
        for event in events:
            result = runtime.process_event(event)
            detections.extend(result)
            history.append((tuple(result), runtime.active_instances()))
        outcome = (detections, history, runtime.active_instances(), runtime.peak_instances())
        if reference is None:
            reference = outcome
        else:
            assert outcome == reference, f"detection or active-state mismatch: {factor}"

    if workload == "many_active_few_complete":
        # The final user's match lands exactly at t=30, the inclusive cutoff.
        boundary_user = events[-1].attributes["user"]
        assert events[-1].timestamp == 30
        assert boundary_user in reference[0]


def run_once(factor, events):
    gc.collect()
    runtime = FactorialRuntime(factor)
    manager = runtime.manager
    detections = []
    peak_heap = 0
    start = time.perf_counter()
    for event in events:
        result = runtime.process_event(event)
        if result:
            detections.extend(result)
        heap_size = len(manager.expiration_heap)
        if heap_size > peak_heap:
            peak_heap = heap_size
    elapsed = time.perf_counter() - start
    return {
        "detection_count": len(detections),
        "detections": detections,
        "final_active": runtime.active_instances(),
        "peak_active": runtime.peak_instances(),
        "elapsed_s": elapsed,
        "throughput_eps": len(events) / elapsed if elapsed else 0,
        "avg_event_latency_ms": elapsed * 1000 / len(events),
        "compaction_count": manager.compaction_count,
        "compaction_check_count": manager.compaction_check_count,
        "peak_heap_records": peak_heap,
        "final_heap_records": len(manager.expiration_heap),
    }


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def mean_std(values):
    return statistics.mean(values), statistics.stdev(values)


def summarize(rows):
    metrics = (
        "elapsed_s", "throughput_eps", "avg_event_latency_ms", "compaction_count",
        "compaction_check_count", "final_heap_records", "peak_heap_records",
    )
    summaries = []
    paired = []
    for workload in WORKLOADS:
        for users in SCALES:
            cell = {"workload": workload, "users": users}
            group_rows = [r for r in rows if r["workload"] == workload and r["users"] == users]
            for factor in FACTORS:
                selected = [r for r in group_rows if r["factor"] == factor]
                for metric in metrics:
                    avg, std = mean_std([float(r[metric]) for r in selected])
                    cell[f"{factor}_{metric}_mean"] = avg
                    cell[f"{factor}_{metric}_std"] = std
            by_repeat = {
                repeat: {r["factor"]: float(r["throughput_eps"])
                         for r in group_rows if r["repeat"] == repeat}
                for repeat in range(1, REPEATS + 1)
            }
            effects = {"A_simple_effect_pct": [], "B_simple_effect_pct": [],
                       "AB_total_effect_pct": [], "interaction_pct": [],
                       "A_average_main_effect_pct": [], "B_average_main_effect_pct": []}
            for values in by_repeat.values():
                o, a, b, ab = (values[key] for key in FACTORS)
                effects["A_simple_effect_pct"].append((a / o - 1) * 100)
                effects["B_simple_effect_pct"].append((b / o - 1) * 100)
                effects["AB_total_effect_pct"].append((ab / o - 1) * 100)
                effects["interaction_pct"].append((ab - a - b + o) / o * 100)
                effects["A_average_main_effect_pct"].append(
                    ((a - o) + (ab - b)) / (2 * o) * 100
                )
                effects["B_average_main_effect_pct"].append(
                    ((b - o) + (ab - a)) / (2 * o) * 100
                )
            for name, values in effects.items():
                avg, std = mean_std(values)
                cell[name + "_mean"] = avg
                cell[name + "_std"] = std
            summaries.append(cell)
    return summaries


def main():
    RESULT_DIR.mkdir(exist_ok=True)
    raw_path = output_path("stage5_factorial_raw")
    summary_path = output_path("stage5_factorial_summary")
    rows = []
    order_rng = random.Random(SEED)
    for workload in WORKLOADS:
        for users in SCALES:
            events = events_for(users, workload)
            validate_semantics(events, workload)
            reference = None
            for repeat in range(1, REPEATS + 1):
                order = list(FACTORS)
                order_rng.shuffle(order)
                for factor in order:
                    result = run_once(factor, events)
                    if reference is None:
                        reference = result["detections"]
                    assert result["detections"] == reference
                    rows.append({k: v for k, v in result.items() if k != "detections"} | {
                        "workload": workload, "users": users,
                        "events": len(events), "repeat": repeat,
                        "seed": SEED, "factor": factor,
                        "combination": FACTOR_LABELS[factor],
                    })
            print(f"completed {workload} users={users} events={len(events)}", flush=True)

    summaries = summarize(rows)
    write_csv(raw_path, rows)
    write_csv(summary_path, summaries)
    print(f"Raw results: {raw_path}\nSummary: {summary_path}")
    print("All four combinations matched detection sequences and active histories.")


if __name__ == "__main__":
    main()
