"""Compare expiration heap policies on deterministic, monotonic workloads.

Peak memory is the process-wide peak working set reported by Windows
GetProcessMemoryInfo (or peak RSS fallback elsewhere), not manager-only memory.
"""
import csv
import gc
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.event import Event
from engine.compact_expiration_runtime import CompactExpirationBTRuntime
from engine.expiration_indexed_runtime import ExpirationIndexedBTRuntime
from patterns.security_attack import privilege_attack_pattern


USER_SCALES = [100, 1000, 3000]
REPEATS = 5
POLICIES = {
    "expiration_indexed": ExpirationIndexedBTRuntime,
    "compact_expiration": CompactExpirationBTRuntime,
}
WORKLOADS = (
    "many_active_few_complete",
    "rapid_completion",
    "continuous_create_expire",
)
RESULT_DIR = Path(__file__).resolve().parent / "results"
RAW_STEM = "compact_expiration_raw"
SUMMARY_STEM = "compact_expiration_summary"


def output_paths():
    for suffix in range(1, 10000):
        tag = "" if suffix == 1 else f"_{suffix}"
        raw = RESULT_DIR / f"{RAW_STEM}{tag}.csv"
        summary = RESULT_DIR / f"{SUMMARY_STEM}{tag}.csv"
        if not raw.exists() and not summary.exists():
            return raw, summary
    raise RuntimeError("Could not find unused benchmark output names")


def make_event(kind, timestamp, user):
    return Event(kind, timestamp, {"user": user})


def generate_events(users, workload):
    events = []
    if workload == "many_active_few_complete":
        for i in range(users):
            events.append(make_event("LOGIN_FAIL", 0, f"User{i}"))
        for i in range(max(1, users // 20)):
            events.append(make_event("PRIVILEGE_ESCALATION", 1, f"User{i}"))
        # A window-boundary event verifies that the cutoff is inclusive.
        events.append(make_event("PRIVILEGE_ESCALATION", 30, f"User{users-1}"))
    elif workload == "rapid_completion":
        for i in range(users):
            events.append(make_event("LOGIN_FAIL", 0, f"User{i}"))
        for i in range(users):
            events.append(make_event("PRIVILEGE_ESCALATION", 1, f"User{i}"))
    elif workload == "continuous_create_expire":
        # Start one fresh instance per event-time tick, then advance time past
        # its cutoff with an unrelated observer event. This interleaves starts
        # and global expiration while keeping event time non-decreasing.
        for i in range(users):
            t = i * 64
            events.append(make_event("LOGIN_FAIL", t, f"User{i}"))
            events.append(make_event("NORMAL_OPERATION", t + 31, "Observer"))
    else:
        raise ValueError(workload)

    assert all(a.timestamp <= b.timestamp for a, b in zip(events, events[1:]))
    return events


def peak_process_memory_mb():
    """Return process peak working set (Windows), or peak RSS fallback."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
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

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(counters)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wintypes.DWORD
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        handle = kernel32.GetCurrentProcess()
        ok = psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb)
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        return counters.PeakWorkingSetSize / (1024 * 1024)

    import resource

    # ru_maxrss is KiB on Linux and bytes on macOS.
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / (1024 * 1024 if sys.platform == "darwin" else 1024)


def run_once(runtime_type, events):
    gc.collect()
    runtime = runtime_type(privilege_attack_pattern)
    manager = runtime.manager
    detected_users = []
    peak_heap = 0
    start = time.perf_counter()
    for event in events:
        detected_users.extend(runtime.process_event(event))
        peak_heap = max(peak_heap, len(manager.expiration_heap))
    elapsed = time.perf_counter() - start
    return {
        "detected": len(detected_users),
        "detected_users": detected_users,
        "final_active": runtime.active_instances(),
        "peak_active": runtime.peak_instances(),
        "peak_heap_records": peak_heap,
        "final_heap_records": len(manager.expiration_heap),
        "compaction_count": getattr(manager, "compaction_count", 0),
        "elapsed_s": elapsed,
        "throughput_eps": len(events) / elapsed if elapsed else 0,
        "avg_event_latency_ms": elapsed * 1000 / len(events) if events else 0,
        "process_peak_working_set_mb": peak_process_memory_mb(),
        "memory_measurement_scope": "whole process peak working set; not manager-only",
    }


def summarize(rows):
    group_keys = ("workload", "users", "policy")
    fields = (
        "elapsed_s", "throughput_eps", "avg_event_latency_ms", "peak_active",
        "peak_heap_records", "final_heap_records", "compaction_count",
        "process_peak_working_set_mb",
    )
    summaries = []
    for workload in WORKLOADS:
        for users in USER_SCALES:
            for policy in POLICIES:
                selected = [r for r in rows if (r["workload"], r["users"], r["policy"]) == (workload, users, policy)]
                item = {"workload": workload, "users": users, "policy": policy}
                for field in fields:
                    values = [float(r[field]) for r in selected]
                    item[f"{field}_mean"] = statistics.mean(values)
                    item[f"{field}_std"] = statistics.stdev(values)
                    item[f"{field}_change_pct_vs_expiration_indexed"] = ""
                summaries.append(item)

    # Percent changes: compact relative to expiration-indexed, per workload/scale.
    for item in summaries:
        if item["policy"] != "compact_expiration":
            continue
        base = next(s for s in summaries if s["policy"] == "expiration_indexed"
                    and s["workload"] == item["workload"] and s["users"] == item["users"])
        for field in fields:
            denominator = base[f"{field}_mean"]
            item[f"{field}_change_pct_vs_expiration_indexed"] = (
                (item[f"{field}_mean"] - denominator) / denominator * 100
                if denominator else None
            )
    return summaries


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    raw_file, summary_file = output_paths()
    RESULT_DIR.mkdir(exist_ok=True)
    rows = []
    for workload in WORKLOADS:
        for users in USER_SCALES:
            events = generate_events(users, workload)
            for repeat in range(1, REPEATS + 1):
                outcomes = {}
                policy_order = list(POLICIES)
                if repeat % 2 == 0:
                    policy_order.reverse()
                for policy in policy_order:
                    result = run_once(POLICIES[policy], events)
                    outcomes[policy] = result
                    rows.append({
                        key: value for key, value in result.items()
                        if key != "detected_users"
                    } | {
                        "workload": workload, "users": users, "repeat": repeat,
                        "policy": policy, "events": len(events),
                    })
                baseline = outcomes["expiration_indexed"]
                compact = outcomes["compact_expiration"]
                assert baseline["detected_users"] == compact["detected_users"]
                assert baseline["final_active"] == compact["final_active"]
                print(
                    f"{workload:28s} users={users:4d} repeat={repeat} "
                    f"base={baseline['throughput_eps']:9.1f} eps "
                    f"compact={compact['throughput_eps']:9.1f} eps "
                    f"heap={baseline['peak_heap_records']}/{compact['peak_heap_records']} "
                    f"compact_calls={compact['compaction_count']}",
                    flush=True,
                )

    summaries = summarize(rows)
    write_csv(raw_file, rows)
    write_csv(summary_file, summaries)
    print(f"Raw results: {raw_file}")
    print(f"Summary: {summary_file}")
    print("Detection sequence and final active count matched for all runs.")


if __name__ == "__main__":
    main()
