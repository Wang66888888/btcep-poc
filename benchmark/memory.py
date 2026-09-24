import os
import psutil
import time

from benchmark.active_generator import generate_active_events
from benchmark.metrics import save_result

from engine.runtime import BTRuntime
from patterns.security_attack import selector_attack_pattern



def memory_usage_mb():

    process = psutil.Process(
        os.getpid()
    )

    return (
        process.memory_info().rss
        /
        1024
        /
        1024
    )



def run_memory_benchmark(
    num_events=100000,
    users=10000,
    attack_ratio=0.05
):

    runtime = BTRuntime(
        selector_attack_pattern
    )


    before = memory_usage_mb()


    events = generate_active_events(
        users
    )


    start = time.perf_counter()


    detected = 0


    for event in events:

        result = runtime.process_event(event)

        if result:

            detected += len(result)



    end = time.perf_counter()


    after = memory_usage_mb()


    active = runtime.peak_instances()


    increase = after - before


    print(
        "===== Memory Benchmark ====="
    )

    print(
        f"Users: {users}"
    )

    print(
        f"Memory Increase: {increase:.2f} MB"
    )

    print(
        f"Active Instances: {active}"
    )


    save_result(
        "memory.csv",
        {
            "events": num_events,
            "users": users,
            "active_instances": active,
            "detected": detected,
            "memory_mb": increase,
            "time": end-start
        }
    )



if __name__ == "__main__":

    run_memory_benchmark()
