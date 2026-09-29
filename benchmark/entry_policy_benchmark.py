import csv
import statistics
import time
from pathlib import Path

from core.event import Event
from engine.runtime import BTRuntime
from nodes.event_node import EventNode
from nodes.parallel import Parallel
from nodes.window import Window


REPEATS = 10
USER_SCALES = [100, 1000, 10000]

RESULT_DIR = Path("results")
RAW_FILE = RESULT_DIR / "entry_policy_raw.csv"
SUMMARY_FILE = RESULT_DIR / "entry_policy_summary.csv"


def build_parallel_pattern():
    parallel = Parallel([
        EventNode("LOGIN_FAIL"),
        EventNode("FILE_ACCESS"),
    ])
    return Window(parallel, 30)


def single_entry_pattern():
    return build_parallel_pattern()


single_entry_pattern.start_events = [
    "LOGIN_FAIL"
]


def multi_entry_pattern():
    return build_parallel_pattern()


multi_entry_pattern.start_events = [
    "LOGIN_FAIL",
    "FILE_ACCESS",
]


def generate_events(users):
    events = []
    timestamp = 0

    for i in range(users):
        user = f"user_{i}"

        timestamp += 1
        events.append(
            Event(
                "LOGIN_FAIL",
                timestamp,
                {"user": user},
            )
        )

        timestamp += 1
        events.append(
            Event(
                "FILE_ACCESS",
                timestamp,
                {"user": user},
            )
        )

    return events


def run_once(policy, pattern_factory, users, repeat):
    runtime = BTRuntime(pattern_factory)
    events = generate_events(users)

    detected = 0

    start = time.perf_counter()

    for event in events:
        result = runtime.process_event(event)

        if result:
            detected += len(result)

    elapsed = time.perf_counter() - start

    num_events = len(events)
    throughput = num_events / elapsed
    latency_ms = elapsed / num_events * 1000

    result = {
        "policy": policy,
        "users": users,
        "repeat": repeat,
        "events": num_events,
        "detected": detected,
        "elapsed_sec": elapsed,
        "throughput": throughput,
        "latency_ms": latency_ms,
        "peak_active_instances": runtime.peak_instances(),
        "final_active_instances": runtime.active_instances(),
    }

    print(
        f"{policy:12s} "
        f"users={users:6d} "
        f"repeat={repeat:2d} "
        f"detected={detected:6d} "
        f"throughput={throughput:12.2f} "
        f"peak={runtime.peak_instances():6d} "
        f"final={runtime.active_instances():6d}"
    )

    return result


def save_csv(path, rows, fieldnames):
    RESULT_DIR.mkdir(parents=True, exist_ok=True)

    with path.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(rows)


def summarize(rows):
    summary = []

    for policy in ["single-entry", "multi-entry"]:
        for users in USER_SCALES:
            group = [
                row
                for row in rows
                if row["policy"] == policy
                and row["users"] == users
            ]

            throughputs = [
                row["throughput"]
                for row in group
            ]

            latencies = [
                row["latency_ms"]
                for row in group
            ]

            summary.append({
                "policy": policy,
                "users": users,
                "repeats": len(group),
                "throughput_mean": statistics.mean(
                    throughputs
                ),
                "throughput_std": statistics.stdev(
                    throughputs
                ),
                "latency_mean_ms": statistics.mean(
                    latencies
                ),
                "latency_std_ms": statistics.stdev(
                    latencies
                ),
                "detected": group[0]["detected"],
                "peak_active_instances": max(
                    row["peak_active_instances"]
                    for row in group
                ),
                "final_active_instances": group[0][
                    "final_active_instances"
                ],
            })

    return summary


def main():
    experiments = [
        (
            "single-entry",
            single_entry_pattern,
        ),
        (
            "multi-entry",
            multi_entry_pattern,
        ),
    ]

    rows = []

    for users in USER_SCALES:
        for policy, pattern_factory in experiments:
            for repeat in range(1, REPEATS + 1):
                rows.append(
                    run_once(
                        policy,
                        pattern_factory,
                        users,
                        repeat,
                    )
                )

    raw_fields = [
        "policy",
        "users",
        "repeat",
        "events",
        "detected",
        "elapsed_sec",
        "throughput",
        "latency_ms",
        "peak_active_instances",
        "final_active_instances",
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
        "repeats",
        "throughput_mean",
        "throughput_std",
        "latency_mean_ms",
        "latency_std_ms",
        "detected",
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
            f'{row["policy"]:12s} '
            f'users={row["users"]:6d} '
            f'throughput='
            f'{row["throughput_mean"]:.2f}'
            f' ± '
            f'{row["throughput_std"]:.2f} '
            f'latency='
            f'{row["latency_mean_ms"]:.6f}'
            f' ± '
            f'{row["latency_std_ms"]:.6f} ms '
            f'peak='
            f'{row["peak_active_instances"]} '
            f'final='
            f'{row["final_active_instances"]}'
        )

    print()
    print(f"Raw results: {RAW_FILE}")
    print(f"Summary:     {SUMMARY_FILE}")


if __name__ == "__main__":
    main()
