import csv
import gc
import statistics
import time
from pathlib import Path

from core.event import Event
from engine.runtime import BTRuntime
from engine.indexed_runtime import IndexedBTRuntime
from engine.expiration_indexed_runtime import ExpirationIndexedBTRuntime
from patterns.security_attack import privilege_attack_pattern


USER_SCALES = [100, 1000, 3000]
REPEATS = 5

RUNTIMES = {
    "baseline": BTRuntime,
    "indexed": IndexedBTRuntime,
    "expiration_indexed": ExpirationIndexedBTRuntime,
}

RESULT_DIR = Path("results")
RAW_FILE = RESULT_DIR / "expiration_index_raw.csv"
SUMMARY_FILE = RESULT_DIR / "expiration_index_summary.csv"


def event(event_type, timestamp, user):
    return Event(event_type, timestamp, {"user": user})


def generate_events(users, workload):
    events = []

    if workload == "no_expiration":
        # All instances remain active until completion.
        for i in range(users):
            events.append(event("LOGIN_FAIL", 1, f"User{i}"))

        for i in range(users):
            events.append(event("NORMAL_OPERATION", 2, f"User{i}"))

        for i in range(users):
            events.append(
                event("PRIVILEGE_ESCALATION", 3, f"User{i}")
            )

    elif workload == "staggered_expiration":
        # Half start at t=1, the rest at t=20.
        midpoint = users // 2

        for i in range(midpoint):
            events.append(event("LOGIN_FAIL", 1, f"User{i}"))

        for i in range(midpoint, users):
            events.append(event("LOGIN_FAIL", 20, f"User{i}"))

        # At t=32, the first group has expired.
        events.append(event("NORMAL_OPERATION", 32, "Observer"))

        # The second group is still within its window.
        for i in range(midpoint, users):
            events.append(
                event("PRIVILEGE_ESCALATION", 33, f"User{i}")
            )

    else:
        raise ValueError(workload)

    assert all(
        events[i].timestamp <= events[i + 1].timestamp
        for i in range(len(events) - 1)
    )

    return events


def run_once(policy, events):
    gc.collect()

    runtime = RUNTIMES[policy](privilege_attack_pattern)

    detected = 0
    start = time.perf_counter()

    for e in events:
        detected += len(runtime.process_event(e))

    elapsed = time.perf_counter() - start

    return {
        "policy": policy,
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
        for workload in [
            "no_expiration",
            "staggered_expiration",
        ]:
            events = generate_events(users, workload)

            for repeat in range(1, REPEATS + 1):
                policies = list(RUNTIMES)

                # Rotate order to reduce systematic ordering bias.
                shift = (repeat - 1) % len(policies)
                policies = policies[shift:] + policies[:shift]

                results = {}

                for policy in policies:
                    row = run_once(policy, events)
                    row["users"] = users
                    row["workload"] = workload
                    row["repeat"] = repeat

                    rows.append(row)
                    results[policy] = row

                    print(
                        f"{policy:18s} "
                        f"users={users:5d} "
                        f"workload={workload:22s} "
                        f"repeat={repeat} "
                        f"detected={row['detected']:5d} "
                        f"peak={row['peak_instances']:5d} "
                        f"throughput={row['throughput']:10.2f}",
                        flush=True,
                    )

                baseline = results["baseline"]

                for policy in RUNTIMES:
                    other = results[policy]

                    assert other["detected"] == baseline["detected"]
                    assert (
                        other["peak_instances"]
                        == baseline["peak_instances"]
                    )
                    assert (
                        other["final_instances"]
                        == baseline["final_instances"]
                    )

                expected_detected = (
                    users
                    if workload == "no_expiration"
                    else users - users // 2
                )

                assert baseline["detected"] == expected_detected

    with RAW_FILE.open("w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=rows[0].keys(),
        )
        writer.writeheader()
        writer.writerows(rows)

    summaries = []

    for users in USER_SCALES:
        for workload in [
            "no_expiration",
            "staggered_expiration",
        ]:
            for policy in RUNTIMES:
                selected = [
                    r for r in rows
                    if r["users"] == users
                    and r["workload"] == workload
                    and r["policy"] == policy
                ]

                values = [r["throughput"] for r in selected]

                summaries.append({
                    "users": users,
                    "workload": workload,
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
