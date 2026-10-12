import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.event import Event
from engine.expiration_indexed_manager import ExpirationIndexedInstanceManager
from engine.compact_expiration_manager import CompactExpirationInstanceManager
from patterns.security_attack import privilege_attack_pattern


def main():
    managers = {
        "expiration_indexed": ExpirationIndexedInstanceManager(
            privilege_attack_pattern
        ),
        "compact_expiration": CompactExpirationInstanceManager(
            privilege_attack_pattern
        ),
    }
    print(f"{'Completed':>10} {'Manager':>20} {'Active':>10} {'Heap':>10} {'Stale':>10}")
    for i in range(1, 5001):
        user = f"User{i}"
        for manager in managers.values():
            manager.process_event(Event("LOGIN_FAIL", 1, {"user": user}))
            manager.process_event(Event("PRIVILEGE_ESCALATION", 2, {"user": user}))
        if i % 1000 == 0:
            for name, manager in managers.items():
                active = manager.active_count()
                heap_size = len(manager.expiration_heap)
                print(f"{i:10d} {name:>20} {active:10d} {heap_size:10d} {heap_size-active:10d}")


if __name__ == "__main__":
    main()
