import time


from benchmark.generator import generate_events
from benchmark.metrics import save_result

from engine.runtime import BTRuntime


from patterns.security_attack import (
    privilege_attack_pattern,
    parallel_attack_pattern,
    selector_attack_pattern
)



def run_pattern_benchmark(
    name,
    pattern_factory,
    num_events=100000
):


    runtime = BTRuntime(
        pattern_factory
    )


    events = generate_events(
        num_events,
        users=100,
        attack_ratio=0.05
    )


    detected = 0


    start = time.perf_counter()


    for event in events:

        result = runtime.process_event(event)

        if result:

            detected += len(result)



    end = time.perf_counter()


    elapsed = end - start


    throughput = (
        num_events / elapsed
    )


    latency = (
        elapsed /
        num_events *
        1000
    )


    print(
        "===== Pattern Benchmark ====="
    )

    print(
        f"Pattern: {name}"
    )

    print(
        f"Detected: {detected}"
    )

    print(
        f"Throughput: {throughput:.2f} events/sec"
    )

    print(
        f"Latency: {latency:.6f} ms/event"
    )

    print(
        f"Peak Active Instances: {runtime.peak_instances()}"
    )

    print(
        f"Final Active Instances: {runtime.active_instances()}"
    )


    save_result(
        "pattern.csv",
        {
            "pattern": name,
            "events": num_events,
            "detected": detected,
            "throughput": throughput,
            "latency_ms": latency
        }
    )



if __name__ == "__main__":


    tests = [

        (
            "sequence",
            privilege_attack_pattern
        ),

        (
            "parallel",
            parallel_attack_pattern
        ),

        (
            "selector",
            selector_attack_pattern
        )

    ]


    for name, pattern in tests:

        run_pattern_benchmark(
            name,
            pattern
        )
