"""Long-run heap stability, semantic parity, and isolated memory experiment."""
import argparse
import csv
import gc
import hashlib
import json
import random
import statistics
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.event import Event
from engine.compact_expiration_runtime import CompactExpirationBTRuntime
from engine.expiration_indexed_runtime import ExpirationIndexedBTRuntime
from engine.optimized_compact_expiration_runtime import (
    OptimizedCompactExpirationBTRuntime,
)
from patterns.security_attack import privilege_attack_pattern


SCALES = (10_000, 100_000, 500_000)
REPEATS = 3
SAMPLE_EVERY = 10_000
SEED = 20261008
POLICIES = (
    "expiration_indexed",
    "compact_none",
    "compact_default",
    "compact_candidate",
    "optimized_default",
    "optimized_candidate",
)
RESULT_DIR = Path(__file__).resolve().parent / "results"


def event_stream(event_limit, seed):
    """Yield a delayed-expiry cohort that exposes long stale-record buildup.

    Nearly all events occur at t=0: users repeatedly start, receive duplicate
    starts, and complete successfully; a smaller interleaved set remains
    active. Thus stale completion records accumulate over the run without
    advancing the event-time watermark. The stream ends with a match at its
    inclusive deadline t=30 and an observer at t=31 that expires the cohort.
    The generator retains no event history.
    """
    rng = random.Random(seed)
    emitted = 0
    order = list(range(1024))
    rng.shuffle(order)
    j = 0
    while emitted < event_limit - 3:
        user = f"Match{order[j % len(order)]}"
        events = (
            Event("LOGIN_FAIL", 0, {"user": user}),
            Event("LOGIN_FAIL", 0, {"user": user}),  # duplicate start
            Event("PRIVILEGE_ESCALATION", 0, {"user": user}),
        )
        for item in events:
            if emitted >= event_limit - 3:
                break
            yield item
            emitted += 1

        if j % 16 == 0 and emitted < event_limit - 3:
            partial = f"Partial{(j // 16) % 64}"
            for _ in range(2):
                if emitted >= event_limit - 3:
                    break
                yield Event("LOGIN_FAIL", 0, {"user": partial})
                emitted += 1
        j += 1

    boundary_user = "BoundaryFinal"
    for item in (
        Event("LOGIN_FAIL", 0, {"user": boundary_user}),
        Event("PRIVILEGE_ESCALATION", 30, {"user": boundary_user}),
        Event("NORMAL_OPERATION", 31, {"user": "Observer"}),
    ):
        yield item
        emitted += 1
    assert emitted == event_limit


def make_runtime(policy):
    if policy == "expiration_indexed":
        return ExpirationIndexedBTRuntime(privilege_attack_pattern)
    if policy == "compact_none":
        return CompactExpirationBTRuntime(
            privilege_attack_pattern,
            compact_min=sys.maxsize,
            compact_factor=2.0,
        )
    if policy == "compact_default":
        return CompactExpirationBTRuntime(privilege_attack_pattern)
    if policy == "compact_candidate":
        return CompactExpirationBTRuntime(
            privilege_attack_pattern, compact_min=128, compact_factor=3.0
        )
    if policy == "optimized_default":
        return OptimizedCompactExpirationBTRuntime(privilege_attack_pattern)
    if policy == "optimized_candidate":
        return OptimizedCompactExpirationBTRuntime(
            privilege_attack_pattern, compact_min=128, compact_factor=3.0
        )
    raise ValueError(policy)


def process_memory_mb():
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        if not psapi.GetProcessMemoryInfo(
            kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return (
            counters.WorkingSetSize / (1024 * 1024),
            counters.PeakWorkingSetSize / (1024 * 1024),
        )

    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    peak_mb = peak / (1024 * 1024 if sys.platform == "darwin" else 1024)
    try:
        with open("/proc/self/statm", encoding="ascii") as statm:
            current = int(statm.read().split()[1]) * __import__("os").sysconf("SC_PAGE_SIZE")
        current_mb = current / (1024 * 1024)
    except OSError:
        current_mb = peak_mb
    return current_mb, peak_mb


def manager_state_estimate_bytes(manager):
    """Approximate bytes reachable from active-instance and heap containers."""
    roots = [manager.instances_by_user, manager.expiration_heap]
    stack = list(roots)
    seen = set()
    total = 0
    atomic = (str, bytes, int, float, bool, type(None))
    while stack:
        obj = stack.pop()
        ident = id(obj)
        if ident in seen:
            continue
        seen.add(ident)
        total += sys.getsizeof(obj)
        if isinstance(obj, atomic):
            continue
        if isinstance(obj, dict):
            stack.extend(obj.keys())
            stack.extend(obj.values())
        elif isinstance(obj, (list, tuple, set, frozenset)):
            stack.extend(obj)
        elif hasattr(obj, "__dict__"):
            stack.append(vars(obj))
    return total


def worker(event_count, policy, repeat):
    gc.collect()
    current_start_mb, peak_start_mb = process_memory_mb()
    runtime = make_runtime(policy)
    manager = runtime.manager
    compaction_time_ns = [0]
    rebuild = getattr(manager, "_rebuild_heap", None)
    if rebuild is not None:
        def timed_rebuild():
            rebuild_started = time.perf_counter_ns()
            rebuild()
            compaction_time_ns[0] += time.perf_counter_ns() - rebuild_started
        manager._rebuild_heap = timed_rebuild
    stream_hash = hashlib.sha256()
    behavior_hash = hashlib.sha256()
    samples = []
    compactions_previous = 0
    started = time.perf_counter()
    event_digest = hashlib.sha256()
    processed = 0
    detection_count = 0
    peak_heap_records = 0

    for event in event_stream(event_count, SEED):
        user = event.attributes["user"]
        event_digest.update(
            f"{event.event_type}\0{event.timestamp}\0{user}\n".encode("utf-8")
        )
        result = runtime.process_event(event)
        detection_count += len(result)
        if event.event_type == "PRIVILEGE_ESCALATION" and user.startswith("Boundary"):
            assert result == [user], (policy, event.timestamp, user, result)
        active = runtime.active_instances()
        heap_size_now = len(manager.expiration_heap)
        if heap_size_now > peak_heap_records:
            peak_heap_records = heap_size_now
        behavior_hash.update(
            f"{event.timestamp}\0{tuple(result)}\0{active}\n".encode("utf-8")
        )
        processed += 1

        if (
            processed % SAMPLE_EVERY == 0
            or processed == event_count - 3
            or processed == event_count
        ):
            hsize = len(manager.expiration_heap)
            active = manager.active_count()
            stale = hsize - active
            compactions = getattr(manager, "compaction_count", 0)
            estimate = manager_state_estimate_bytes(manager)
            current_mb, peak_mb = process_memory_mb()
            elapsed = time.perf_counter() - started
            row = {
                "processed_events": processed,
                "active_instances_A": active,
                "heap_records_H": hsize,
                "stale_records_H_minus_A": stale,
                "cumulative_compactions": compactions,
                "cumulative_compaction_time_ns": compaction_time_ns[0],
                "manager_state_estimate_bytes": estimate,
                "process_current_working_set_mb": current_mb,
                "process_peak_working_set_mb": peak_mb,
                "elapsed_s_at_sample": elapsed,
            }
            samples.append(row)

            compressed = policy in (
                "compact_default", "compact_candidate",
                "optimized_default", "optimized_candidate",
            )
            if compressed:
                min_threshold, factor = (
                    (128, 3.0) if policy.endswith("candidate") else (64, 2.0)
                )
                assert hsize <= max(min_threshold, factor * active), (
                    policy, processed, hsize, active
                )

    elapsed = time.perf_counter() - started
    current_end_mb, peak_end_mb = process_memory_mb()
    return {
        "events": processed,
        "event_stream_sha256": event_digest.hexdigest(),
        "behavior_sha256": behavior_hash.hexdigest(),
        "detection_count": detection_count,
        "final_active_instances": runtime.active_instances(),
        "peak_active_instances": runtime.peak_instances(),
        "elapsed_s": elapsed,
        "throughput_eps": processed / elapsed if elapsed else 0,
        "avg_event_latency_ms": elapsed * 1000 / processed if processed else 0,
        "compaction_count": getattr(manager, "compaction_count", 0),
        "compaction_time_ns": compaction_time_ns[0],
        "compaction_check_count": getattr(manager, "compaction_check_count", 0),
        "peak_heap_records": peak_heap_records,
        "final_heap_records": len(manager.expiration_heap),
        "manager_state_estimate_bytes": manager_state_estimate_bytes(manager),
        "process_current_start_mb": current_start_mb,
        "process_current_end_mb": current_end_mb,
        "process_peak_start_mb": peak_start_mb,
        "process_peak_end_mb": peak_end_mb,
        "process_peak_delta_from_start_mb": max(0, peak_end_mb - current_start_mb),
        "process_memory_scope": "isolated worker process whole working set; includes Python/import overhead",
        "manager_state_scope": "estimated Python object graph reachable from manager active map and heap",
        "samples": samples,
    }


def worker_entry(args):
    result = worker(args.events, args.policy, args.repeat)
    print(json.dumps(result, separators=(",", ":")))


def output_path(stem):
    for i in range(1, 10000):
        suffix = "" if i == 1 else f"_{i}"
        path = RESULT_DIR / f"{stem}{suffix}.csv"
        if not path.exists():
            return path
    raise RuntimeError("No unused output file path")


def summarize_runs(raw_rows, sample_rows):
    metrics = (
        "elapsed_s", "throughput_eps", "avg_event_latency_ms",
        "compaction_count", "compaction_check_count", "peak_heap_records",
        "compaction_time_ns",
        "final_heap_records", "manager_state_estimate_bytes",
        "process_current_end_mb", "process_peak_end_mb",
        "process_peak_delta_from_start_mb",
    )
    rows = []
    for scale in SCALES:
        for policy in POLICIES:
            selected = [r for r in raw_rows if r["requested_events"] == scale and r["policy"] == policy]
            row = {"requested_events": scale, "policy": policy, "repeats": REPEATS}
            for metric in metrics:
                values = [float(r[metric]) for r in selected]
                row[metric + "_mean"] = statistics.mean(values)
                row[metric + "_std"] = statistics.stdev(values)
            sampled_state = []
            sampled_stale = []
            for repeat in range(1, REPEATS + 1):
                group = [s for s in sample_rows if s["requested_events"] == scale
                         and s["policy"] == policy and s["repeat"] == repeat]
                sampled_state.append(max(int(s["manager_state_estimate_bytes"]) for s in group))
                sampled_stale.append(max(int(s["stale_records_H_minus_A"]) for s in group))
            row["peak_sampled_manager_state_bytes_mean"] = statistics.mean(sampled_state)
            row["peak_sampled_manager_state_bytes_std"] = statistics.stdev(sampled_state)
            row["peak_sampled_stale_records_mean"] = statistics.mean(sampled_stale)
            row["peak_sampled_stale_records_std"] = statistics.stdev(sampled_stale)
            rows.append(row)
    return rows


def parent_main():
    RESULT_DIR.mkdir(exist_ok=True)
    raw_path = output_path("long_run_heap_stability_raw")
    summary_path = output_path("long_run_heap_stability_summary")
    sample_path = output_path("long_run_heap_stability_samples")
    raw_rows = []
    sample_rows = []
    parity = {}
    for scale in SCALES:
        for repeat in range(1, REPEATS + 1):
            policies = list(POLICIES)
            random.Random(SEED + scale + repeat).shuffle(policies)
            for policy in policies:
                command = [
                    sys.executable, "-m", "benchmark.long_run_heap_stability",
                    "--worker", "--events", str(scale),
                    "--policy", policy, "--repeat", str(repeat),
                ]
                completed = subprocess.run(
                    command, check=True, capture_output=True, text=True,
                    encoding="utf-8", timeout=600,
                )
                result = json.loads(completed.stdout.strip().splitlines()[-1])
                behavior_signature = (
                    result["event_stream_sha256"], result["behavior_sha256"],
                    result["detection_count"], result["final_active_instances"],
                    result["peak_active_instances"],
                )
                parity.setdefault((scale, repeat), behavior_signature)
                assert parity[(scale, repeat)] == behavior_signature, (
                    scale, repeat, policy, parity[(scale, repeat)], behavior_signature
                )
                raw_rows.append({
                    k: v for k, v in result.items() if k != "samples"
                } | {
                    "requested_events": scale,
                    "repeat": repeat,
                    "seed": SEED,
                    "policy": policy,
                })
                for sample in result["samples"]:
                    sample_rows.append(sample | {
                        "requested_events": scale,
                        "repeat": repeat,
                        "seed": SEED,
                        "policy": policy,
                    })
            print(f"completed {scale:,} events, repeat {repeat}/{REPEATS}", flush=True)

    summary_rows = summarize_runs(raw_rows, sample_rows)

    for path, records in (
        (raw_path, raw_rows),
        (summary_path, summary_rows),
        (sample_path, sample_rows),
    ):
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(records[0]))
            writer.writeheader()
            writer.writerows(records)
    print(f"Raw: {raw_path}\nSummary: {summary_path}\nSamples: {sample_path}")
    print("Matching event-stream hashes verified across isolated policies.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--events", type=int, default=0)
    parser.add_argument("--policy", default="")
    parser.add_argument("--repeat", type=int, default=0)
    args = parser.parse_args()
    if args.worker:
        worker_entry(args)
    else:
        parent_main()


if __name__ == "__main__":
    main()
