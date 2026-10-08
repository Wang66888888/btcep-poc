import csv
import gc
import os
import statistics
import time
from pathlib import Path

import psutil

from core.event import Event
from engine.runtime import BTRuntime
from patterns.security_attack import privilege_attack_pattern
from benchmark.match_policy_benchmark import OverlappingRuntime


REPEATS = 5
USER_SCALES = [100, 1000, 10000]
REPEATED_STARTS = [1, 2, 5, 10]

RESULT_DIR = Path("results")
RAW_FILE = RESULT_DIR / "concurrent_state_raw.csv"
SUMMARY_FILE = RESULT_DIR / "concurrent_state_summary.csv"


def memory_usage_mb():
    process = psutil.Process(
        os.getpid()
    )

    return (
        process.memory_info().rss
        / 1024
        / 1024
    )


def generate_phases(
    users,
    repeated_starts,
):
    """
    Phase 1:
    create partial matches for every user.

    Phase 2:
    complete every user's pattern.

    Timestamps are deliberately kept inside
    the 30-second window per user by assigning
    equal event-time to the start phase and a
    +1 timestamp to the completion phase.

    This benchmark studies concurrent state,
    not event-time progression.
    """

    start_events = []
    completion_events = []

    for i in range(users):
        user = f"user_{i}"

        for _ in range(repeated_starts):
            start_events.append(
                Event(
                    "LOGIN_FAIL",
                    1,
                    {"user": user},
                )
            )

        completion_events.append(
            Event(
                "PRIVILEGE_ESCALATION",
                2,
                {"user": user},
            )
        )

    return (
        start_events,
        completion_events,
    )


def build_runtime(policy):
    if policy == "single-active":
        return BTRuntime(
            privilege_attack_pattern
        )

    if policy == "overlapping":
        return OverlappingRuntime(
            privilege_attack_pattern
        )

    raise ValueError(
        f"Unknown policy: {policy}"
    )


def run_once(
    policy,
    users,
    repeated_starts,
    repeat,
):
    gc.collect()

    before_mb = memory_usage_mb()

    runtime = build_runtime(policy)

    (
        start_events,
        completion_events,
    ) = generate_phases(
        users,
        repeated_starts,
    )

    detected = 0

    start_time = time.perf_counter()

    # Phase 1: accumulate concurrent partial state.
    for event in start_events:
        result = runtime.process_event(event)

        if result:
            detected += len(result)

    active_after_start = (
        runtime.active_instances()
    )

    peak_mb = memory_usage_mb()

    # Phase 2: complete all partial matches.
    for event in completion_events:
        result = runtime.process_event(event)

        if result:
            detected += len(result)

    elapsed = (
        time.perf_counter()
        - start_time
    )

    final_active = (
        runtime.active_instances()
    )

    num_events = (
        len(start_events)
        + len(completion_events)
    )

    throughput = (
        num_events / elapsed
    )

    latency_ms = (
        elapsed / num_events * 1000
    )

    memory_increase_mb = max(
        0.0,
        peak_mb - before_mb,
    )

    result = {
        "policy": policy,
        "users": users,
        "repeated_starts": repeated_starts,
        "repeat": repeat,
        "events": num_events,
        "detected": detected,
        "elapsed_sec": elapsed,
        "throughput": throughput,
        "latency_ms": latency_ms,
        "active_after_start": active_after_start,
        "peak_active_instances": runtime.peak_instances(),
        "final_active_instances": final_active,
        "memory_increase_mb": memory_increase_mb,
    }

    print(
        f"{policy:13s} "
        f"users={users:6d} "
        f"starts={repeated_starts:2d} "
        f"repeat={repeat:2d} "
        f"detected={detected:7d} "
        f"active={active_after_start:7d} "
        f"memory={memory_increase_mb:8.2f} MB "
        f"throughput={throughput:10.2f}"
    )

    return result


def save_csv(path, rows, fieldnames):
    RESULT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)


def summarize(rows):
    summary = []

    for policy in [
        "single-active",
        "overlapping",
    ]:
        for users in USER_SCALES:
            for repeated_starts in REPEATED_STARTS:
                group = [
                    row
                    for row in rows
                    if row["policy"] == policy
                    and row["users"] == users
                    and row["repeated_starts"]
                    == repeated_starts
                ]

                def values(key):
                    return [
                        row[key]
                        for row in group
                    ]

                summary.append({
                    "policy": policy,
                    "users": users,
                    "repeated_starts": repeated_starts,
                    "repeats": len(group),
                    "throughput_mean":
                        statistics.mean(
                            values("throughput")
                        ),
                    "throughput_std":
                        statistics.stdev(
                            values("throughput")
                        ),
                    "latency_mean_ms":
                        statistics.mean(
                            values("latency_ms")
                        ),
                    "latency_std_ms":
                        statistics.stdev(
                            values("latency_ms")
                        ),
                    "memory_mean_mb":
                        statistics.mean(
                            values(
                                "memory_increase_mb"
                            )
                        ),
                    "memory_std_mb":
                        statistics.stdev(
                            values(
                                "memory_increase_mb"
                            )
                        ),
                    "detected":
                        values("detected")[0],
                    "active_after_start":
                        values(
                            "active_after_start"
                        )[0],
                    "peak_active_instances":
                        max(
                            values(
                                "peak_active_instances"
                            )
                        ),
                    "final_active_instances":
                        values(
                            "final_active_instances"
                        )[0],
                })

    return summary


def main():
    policies = [
        "single-active",
        "overlapping",
    ]

    rows = []

    for users in USER_SCALES:
        for repeated_starts in REPEATED_STARTS:
            for policy in policies:
                for repeat in range(
                    1,
                    REPEATS + 1,
                ):
                    rows.append(
                        run_once(
                            policy,
                            users,
                            repeated_starts,
                            repeat,
                        )
                    )

    raw_fields = [
        "policy",
        "users",
        "repeated_starts",
        "repeat",
        "events",
        "detected",
        "elapsed_sec",
        "throughput",
        "latency_ms",
        "active_after_start",
        "peak_active_instances",
        "final_active_instances",
        "memory_increase_mb",
    ]

    save_csv(
        RAW_FILE,
        rows,
        raw_fields,
    )

    summary = summarize(rows)

    summary_fields = [
        "policy",
        "users",
        "repeated_starts",
        "repeats",
        "throughput_mean",
        "throughput_std",
        "latency_mean_ms",
        "latency_std_ms",
        "memory_mean_mb",
        "memory_std_mb",
        "detected",
        "active_after_start",
        "peak_active_instances",
        "final_active_instances",
    ]

    save_csv(
        SUMMARY_FILE,
        summary,
        summary_fields,
    )

    print()
    print("===== Summary =====")

    for row in summary:
        print(
            f'{row["policy"]:13s} '
            f'users={row["users"]:6d} '
            f'starts={row["repeated_starts"]:2d} '
            f'active={row["active_after_start"]:7d} '
            f'memory='
            f'{row["memory_mean_mb"]:.2f}'
            f' ± '
            f'{row["memory_std_mb"]:.2f} MB '
            f'throughput='
            f'{row["throughput_mean"]:.2f}'
            f' ± '
            f'{row["throughput_std"]:.2f} '
            f'detected={row["detected"]:7d} '
            f'final={row["final_active_instances"]}'
        )

    print()
    print(f"Raw results: {RAW_FILE}")
    print(f"Summary:     {SUMMARY_FILE}")


if __name__ == "__main__":
    main()
