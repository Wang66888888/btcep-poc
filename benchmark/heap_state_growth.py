from core.event import Event
from engine.expiration_indexed_manager import (
    ExpirationIndexedInstanceManager,
)
from patterns.security_attack import privilege_attack_pattern


def main():
    manager = ExpirationIndexedInstanceManager(
        privilege_attack_pattern
    )

    print(
        f"{'Completed':>10} "
        f"{'Active':>10} "
        f"{'Heap':>10} "
        f"{'Stale':>10}"
    )

    for i in range(1, 5001):
        user = f"User{i}"

        manager.process_event(
            Event("LOGIN_FAIL", 1, {"user": user})
        )

        manager.process_event(
            Event("PRIVILEGE_ESCALATION", 2, {"user": user})
        )

        if i % 1000 == 0:
            active = manager.active_count()
            heap_size = len(manager.expiration_heap)

            print(
                f"{i:10d} "
                f"{active:10d} "
                f"{heap_size:10d} "
                f"{heap_size - active:10d}"
            )


if __name__ == "__main__":
    main()
