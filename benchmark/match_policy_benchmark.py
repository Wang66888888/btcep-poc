import csv
import statistics
import time
from pathlib import Path

from core.event import Event
from engine.runtime import BTRuntime
from engine.manager import InstanceManager
from patterns.security_attack import privilege_attack_pattern


REPEATS = 10
USER_SCALES = [100, 1000, 10000]
REPEATED_STARTS = [1, 2, 5, 10]

RESULT_DIR = Path("results")
RAW_FILE = RESULT_DIR / "match_policy_raw.csv"
SUMMARY_FILE = RESULT_DIR / "match_policy_summary.csv"


class OverlappingInstanceManager(InstanceManager):
    """
    Experimental policy:
    every start event creates a new partial instance,
    even when the same context already has an active one.
    """

    def process_event(self, event):
        detected_users = []

        event_user = event.attributes["user"]

        # Keep the same global event-time expiration
        # semantics as the production manager.
        for instance in list(self.instances):
            if instance.is_expired(event.timestamp):
                self.instances.remove(instance)

        start_events = getattr(
            self.pattern_factory,
            "start_events",
            [],
        )

        # Key experimental difference:
        # always create on a start event.
        if event.event_type in start_events:
            self.create_instance(event)

        for instance in list(self.instances):
            if instance.context_key != event_user:
                continue

            result = instance.process(event)

            if result:
                detected_users.append(result)

            if instance.completed:
                self.instances.remove(instance)

        return detected_users


class OverlappingRuntime(BTRuntime):
    def __init__(self, pattern_factory):
        self.manager = OverlappingInstanceManager(
            pattern_factory
        )
        self.max_active_instances = 0


def generate_events(users, repeated_starts):
    """
    For each user:

        LOGIN_FAIL x repeated_starts
        PRIVILEGE_ESCALATION

    All start events for a user occur inside the
    30-second window.
    """

    events = []
    timestamp = 0

    for i in range(users):
        user = f"user_{i}"

        for _ in range(repeated_starts):
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
                "PRIVILEGE_ESCALATION",
                timestamp,
                {"user": user},
            )
        )

    return events


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
    runtime = build_runtime(policy)

    events = generate_events(
        users,
        repeated_starts,
    )

    detected = 0

    start = time.perf_counter()

    for event in events:
        result = runtime.process_event(event)

        if result:
            detected += len(result)

    elapsed = time.perf_counter() - start

    num_events = len(events)

    throughput = (
        num_events / elapsed
    )

    latency_ms = (
        elapsed / num_events * 1000
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
        "peak_active_instances": runtime.peak_instances(),
        "final_active_instances": runtime.active_instances(),
    }

    print(
        f"{policy:13s} "
        f"users={users:6d} "
        f"starts={repeated_starts:2d} "
        f"repeat={repeat:2d} "
        f"detected={detected:7d} "
        f"throughput={throughput:12.2f} "
        f"peak={runtime.peak_instances():4d} "
        f"final={runtime.active_instances():4d}"
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

                throughputs = [
                    row["throughput"]
                    for row in group
                ]

                latencies = [
                    row["latency_ms"]
                    for row in group
                ]

                detections = [
                    row["detected"]
                    for row in group
                ]

                peaks = [
                    row["peak_active_instances"]
                    for row in group
                ]

                finals = [
                    row["final_active_instances"]
                    for row in group
                ]

                summary.append({
                    "policy": policy,
                    "users": users,
                    "repeated_starts": repeated_starts,
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
                    "detected": detections[0],
                    "peak_active_instances": max(
                        peaks
                    ),
                    "final_active_instances": finals[0],
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
        "repeated_starts",
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
            f'{row["policy"]:13s} '
            f'users={row["users"]:6d} '
            f'starts={row["repeated_starts"]:2d} '
            f'throughput='
            f'{row["throughput_mean"]:.2f}'
            f' ± '
            f'{row["throughput_std"]:.2f} '
            f'latency='
            f'{row["latency_mean_ms"]:.6f}'
            f' ± '
            f'{row["latency_std_ms"]:.6f} ms '
            f'detected={row["detected"]:7d} '
            f'peak={row["peak_active_instances"]:4d} '
            f'final={row["final_active_instances"]:4d}'
        )

    print()
    print(f"Raw results: {RAW_FILE}")
    print(f"Summary:     {SUMMARY_FILE}")


if __name__ == "__main__":
    main()
