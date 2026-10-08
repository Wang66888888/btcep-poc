import csv
import gc
import statistics
import time
from pathlib import Path

from core.event import Event
from engine.runtime import BTRuntime
from engine.indexed_runtime import IndexedBTRuntime
from patterns.security_attack import privilege_attack_pattern


USER_SCALES = [100, 1000, 3000]
REPEATED_STARTS = [1, 2, 5, 10]
REPEATS = 5

RESULT_DIR = Path("results")
RAW_FILE = RESULT_DIR / "indexed_manager_raw.csv"
SUMMARY_FILE = RESULT_DIR / "indexed_manager_summary.csv"


def generate_events(users, repeated_starts):
    events = []

    # Phase 1: all users create partial matches.
    for user_id in range(users):
        for _ in range(repeated_starts):
            events.append(
                Event(
                    "LOGIN_FAIL",
                    1,
                    {"user": f"User{user_id}"},
                )
            )

    # Phase 2: all users complete their matches.
    for user_id in range(users):
        events.append(
            Event(
                "PRIVILEGE_ESCALATION",
                2,
                {"user": f"User{user_id}"},
            )
        )

    return events


def run_once(policy, events, repeat):
    gc.collect()

    if policy == "baseline":
        runtime = BTRuntime(privilege_attack_pattern)
    elif policy == "indexed":
        runtime = IndexedBTRuntime(privilege_attack_pattern)
    else:
        raise ValueError(policy)

    detected = 0
    start = time.perf_counter()

    for event in events:
        detected += len(runtime.process_event(event))

    elapsed = time.perf_counter() - start

    return {
        "policy": policy,
        "repeat": repeat,
        "events": len(events),
        "detected": detected,
        "peak_instances": runtime.peak_instances(),
        "final_instances": runtime.active_instances(),
        "elapsed_s": elapsed,
        "throughput": len(events) / elapsed,
        "avg_latency_ms": elapsed * 1000 / len(events),
    }


def main():
    RESULT_DIR.mkdir(exist_ok=True)
    rows = []

    for users in USER_SCALES:
        for starts in REPEATED_STARTS:
            events = generate_events(users, starts)

            for repeat in range(1, REPEATS + 1):
                # Alternate execution order across repetitions.
                policies = (
                    ["baseline", "indexed"]
                    if repeat % 2
                    else ["indexed", "baseline"]
                )

                results = {}

                for policy in policies:
                    row = run_once(policy, events, repeat)
                    row["users"] = users
                    row["starts"] = starts
                    rows.append(row)
                    results[policy] = row

                    print(
                        f"{policy:8s} "
                        f"users={users:5d} "
                        f"starts={starts:2d} "
                        f"repeat={repeat} "
                        f"detected={row['detected']:5d} "
                        f"peak={row['peak_instances']:5d} "
                        f"throughput={row['throughput']:10.2f}"
                    )

                baseline = results["baseline"]
                indexed = results["indexed"]

                assert baseline["detected"] == indexed["detected"]
                assert baseline["peak_instances"] == indexed["peak_instances"]
                assert baseline["final_instances"] == indexed["final_instances"]
                assert baseline["detected"] == users
                assert baseline["peak_instances"] == users
                assert baseline["final_instances"] == 0

    with RAW_FILE.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    summaries = []

    for users in USER_SCALES:
        for starts in REPEATED_STARTS:
            for policy in ["baseline", "indexed"]:
                selected = [
                    row for row in rows
                    if row["users"] == users
                    and row["starts"] == starts
                    and row["policy"] == policy
                ]

                values = [row["throughput"] for row in selected]

                summaries.append({
                    "users": users,
                    "starts": starts,
                    "policy": policy,
                    "throughput_mean": statistics.mean(values),
                    "throughput_std": statistics.stdev(values),
                })

    with SUMMARY_FILE.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=summaries[0].keys(),
        )
        writer.writeheader()
        writer.writerows(summaries)

    print("\nResults saved:")
    print(RAW_FILE)
    print(SUMMARY_FILE)


if __name__ == "__main__":
    main()
