import time


from benchmark.generator import generate_events
from benchmark.metrics import save_result

from engine.runtime import BTRuntime

from patterns.security_attack import privilege_attack_pattern



def run_benchmark(
    num_events=10000,
    users=100,
    attack_ratio=0.01,
    experiment="default"
):


    events = generate_events(
        num_events,
        users,
        attack_ratio
    )


    runtime = BTRuntime(
        privilege_attack_pattern
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

        elapsed / num_events

    ) * 1000



    print(
        "===== BT-CEP Benchmark ====="
    )


    print(
        f"Events: {num_events}"
    )


    print(
        f"Detected: {detected}"
    )


    print(
        f"Time: {elapsed:.6f}s"
    )


    print(
        f"Throughput: {throughput:.2f} events/sec"
    )


    print(
        f"Average latency: {latency:.6f} ms/event"
    )


    save_result(
        "throughput.csv",
        {
            "experiment": experiment,
            "events": num_events,
            "users": users,
            "attack_ratio": attack_ratio,
            "detected": detected,
            "time": elapsed,
            "throughput": throughput,
            "latency_ms": latency
        }
    )



if __name__ == "__main__":


    run_benchmark(

        num_events=1000,

        users=100,

        attack_ratio=0.05

    )
