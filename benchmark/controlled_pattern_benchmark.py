import time

from core.event import Event
from engine.runtime import BTRuntime
from patterns.security_attack import (
    privilege_attack_pattern,
    parallel_attack_pattern,
    selector_attack_pattern,
)


def generate_sequence_events(users):
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
                "PRIVILEGE_ESCALATION",
                timestamp,
                {"user": user},
            )
        )

    return events


def generate_parallel_events(users):
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


def generate_selector_events(users):
    events = []
    timestamp = 0

    for i in range(users):
        user = f"user_{i}"

        timestamp += 1
        events.append(
            Event(
                "MALWARE_EXECUTION",
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


def run_benchmark(name, pattern_factory, generator, users=10000):
    runtime = BTRuntime(pattern_factory)
    events = generator(users)

    detected = 0

    start = time.perf_counter()

    for event in events:
        result = runtime.process_event(event)

        if result:
            detected += len(result)

    elapsed = time.perf_counter() - start

    num_events = len(events)
    throughput = num_events / elapsed
    latency = elapsed / num_events * 1000

    print("===== Controlled Pattern Benchmark =====")
    print(f"Pattern: {name}")
    print(f"Users: {users}")
    print(f"Events: {num_events}")
    print(f"Detected: {detected}")
    print(f"Throughput: {throughput:.2f} events/sec")
    print(f"Latency: {latency:.6f} ms/event")
    print(f"Peak Active Instances: {runtime.peak_instances()}")
    print(f"Final Active Instances: {runtime.active_instances()}")


if __name__ == "__main__":
    tests = [
        (
            "sequence",
            privilege_attack_pattern,
            generate_sequence_events,
        ),
        (
            "parallel",
            parallel_attack_pattern,
            generate_parallel_events,
        ),
        (
            "selector",
            selector_attack_pattern,
            generate_selector_events,
        ),
    ]

    for name, pattern, generator in tests:
        run_benchmark(
            name,
            pattern,
            generator,
        )
