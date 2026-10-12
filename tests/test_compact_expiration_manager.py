import unittest

from core.event import Event
from engine.runtime import BTRuntime
from engine.indexed_runtime import IndexedBTRuntime
from engine.expiration_indexed_runtime import ExpirationIndexedBTRuntime
from engine.compact_expiration_runtime import CompactExpirationBTRuntime
from engine.optimized_compact_expiration_runtime import (
    OptimizedCompactExpirationBTRuntime,
)
from patterns.security_attack import privilege_attack_pattern
from nodes.event_node import EventNode
from nodes.sequence import Sequence
from nodes.window import Window


class CompactExpirationManagerTests(unittest.TestCase):
    def event(self, event_type, timestamp, user):
        return Event(event_type, timestamp, {"user": user})

    def test_matches_all_existing_runtimes(self):
        events = [
            self.event("LOGIN_FAIL", 10, "Alice"),
            self.event("LOGIN_FAIL", 11, "Bob"),
            self.event("NORMAL_OPERATION", 40, "Carol"),
            self.event("PRIVILEGE_ESCALATION", 40, "Alice"),
            self.event("LOGIN_FAIL", 41, "Alice"),
            self.event("NORMAL_OPERATION", 72, "Carol"),
            self.event("PRIVILEGE_ESCALATION", 72, "Alice"),
        ]
        runtimes = [
            BTRuntime(privilege_attack_pattern),
            IndexedBTRuntime(privilege_attack_pattern),
            ExpirationIndexedBTRuntime(privilege_attack_pattern),
            CompactExpirationBTRuntime(privilege_attack_pattern),
        ]
        histories = [[] for _ in runtimes]
        for event in events:
            for i, runtime in enumerate(runtimes):
                histories[i].append((
                    runtime.process_event(event),
                    runtime.active_instances(),
                    runtime.peak_instances(),
                ))
        self.assertTrue(all(history == histories[0] for history in histories))

    def test_inclusive_window_boundary(self):
        for end_time, expected in ((40, ["Alice"]), (41, [])):
            runtime = CompactExpirationBTRuntime(privilege_attack_pattern)
            runtime.process_event(self.event("LOGIN_FAIL", 10, "Alice"))
            self.assertEqual(
                runtime.process_event(
                    self.event("PRIVILEGE_ESCALATION", end_time, "Alice")
                ),
                expected,
            )

    def test_cross_user_expiration_and_rebuild(self):
        runtime = CompactExpirationBTRuntime(privilege_attack_pattern)
        runtime.process_event(self.event("LOGIN_FAIL", 10, "Alice"))
        runtime.process_event(self.event("NORMAL_OPERATION", 41, "Bob"))
        self.assertEqual(runtime.active_instances(), 0)
        runtime.process_event(self.event("LOGIN_FAIL", 42, "Alice"))
        self.assertEqual(
            runtime.process_event(
                self.event("PRIVILEGE_ESCALATION", 72, "Alice")
            ),
            ["Alice"],
        )

    def test_stale_record_does_not_delete_replacement(self):
        runtime = CompactExpirationBTRuntime(privilege_attack_pattern)
        manager = runtime.manager
        manager.process_event(self.event("LOGIN_FAIL", 1, "Alice"))
        old_id = manager.instances_by_user["Alice"].instance_id
        manager.instances_by_user["Alice"].completed = True
        del manager.instances_by_user["Alice"]
        manager.process_event(self.event("LOGIN_FAIL", 2, "Alice"))
        new_id = manager.instances_by_user["Alice"].instance_id
        self.assertNotEqual(old_id, new_id)
        manager.expire_instances(32)
        self.assertEqual(manager.instances_by_user["Alice"].instance_id, new_id)

    def test_heap_bound_after_completion_churn(self):
        runtime = CompactExpirationBTRuntime(privilege_attack_pattern)
        for i in range(5000):
            user = f"User{i}"
            runtime.process_event(self.event("LOGIN_FAIL", 1, user))
            runtime.process_event(self.event("PRIVILEGE_ESCALATION", 2, user))
            self.assertLessEqual(
                len(runtime.manager.expiration_heap),
                max(64, 2 * runtime.active_instances()),
            )
        self.assertEqual(runtime.active_instances(), 0)
        self.assertLessEqual(len(runtime.manager.expiration_heap), 64)

    def test_optimized_manager_matches_compact_across_thresholds(self):
        events = []
        for timestamp in range(0, 90):
            user = f"User{timestamp % 11}"
            events.append(self.event("LOGIN_FAIL", timestamp, user))
            if timestamp % 3 == 0:
                events.append(self.event(
                    "PRIVILEGE_ESCALATION", timestamp, user
                ))
            events.append(self.event("NORMAL_OPERATION", timestamp, "Observer"))

        for compact_min, compact_factor in ((64, 2.0), (128, 3.0)):
            with self.subTest(compact_min=compact_min, factor=compact_factor):
                original = CompactExpirationBTRuntime(
                    privilege_attack_pattern,
                    compact_min=compact_min,
                    compact_factor=compact_factor,
                )
                optimized = OptimizedCompactExpirationBTRuntime(
                    privilege_attack_pattern,
                    compact_min=compact_min,
                    compact_factor=compact_factor,
                )
                for event in events:
                    self.assertEqual(
                        original.process_event(event),
                        optimized.process_event(event),
                    )
                    self.assertEqual(
                        original.active_instances(), optimized.active_instances()
                    )
                    self.assertEqual(
                        len(original.manager.expiration_heap),
                        len(optimized.manager.expiration_heap),
                    )
                    self.assertEqual(
                        original.manager.compaction_count,
                        optimized.manager.compaction_count,
                    )

    def test_optimized_runtime_preserves_inclusive_boundary(self):
        runtime = OptimizedCompactExpirationBTRuntime(privilege_attack_pattern)
        runtime.process_event(self.event("LOGIN_FAIL", 10, "Alice"))
        self.assertEqual(
            runtime.process_event(
                self.event("PRIVILEGE_ESCALATION", 40, "Alice")
            ),
            ["Alice"],
        )

    def test_compaction_keeps_unstarted_instance_expiration_record(self):
        for runtime_type in (
            CompactExpirationBTRuntime,
            OptimizedCompactExpirationBTRuntime,
        ):
            with self.subTest(runtime=runtime_type.__name__):
                runtime = runtime_type(privilege_attack_pattern)
                for i in range(64):
                    user = f"Done{i}"
                    runtime.process_event(self.event("LOGIN_FAIL", 0, user))
                    runtime.process_event(
                        self.event("PRIVILEGE_ESCALATION", 0, user)
                    )

                runtime.process_event(self.event("LOGIN_FAIL", 1, "Target"))
                manager = runtime.manager
                target = manager.instances_by_user["Target"]
                self.assertIn(
                    (31, target.instance_id, "Target"),
                    manager.expiration_heap,
                )
                runtime.process_event(
                    self.event("NORMAL_OPERATION", 32, "Observer")
                )
                self.assertEqual(runtime.active_instances(), 0)

    def test_compressed_heap_bound_after_each_processed_event(self):
        for runtime_type in (
            CompactExpirationBTRuntime,
            OptimizedCompactExpirationBTRuntime,
        ):
            runtime = runtime_type(privilege_attack_pattern)
            for i in range(500):
                timestamp = (i // 100) * 32
                user = f"User{i % 73}"
                runtime.process_event(self.event("LOGIN_FAIL", timestamp, user))
                self.assertLessEqual(
                    len(runtime.manager.expiration_heap),
                    max(64, 2 * runtime.active_instances()),
                )
                if i % 2 == 0:
                    runtime.process_event(
                        self.event("PRIVILEGE_ESCALATION", timestamp, user)
                    )
                    self.assertLessEqual(
                        len(runtime.manager.expiration_heap),
                        max(64, 2 * runtime.active_instances()),
                    )

    def test_non_root_window_is_rejected_by_compressed_managers(self):
        def non_root_window_pattern():
            return Sequence([Window(EventNode("LOGIN_FAIL"), 30)])

        non_root_window_pattern.start_events = ["LOGIN_FAIL"]
        for runtime_type in (
            CompactExpirationBTRuntime,
            OptimizedCompactExpirationBTRuntime,
        ):
            with self.subTest(runtime=runtime_type.__name__):
                runtime = runtime_type(non_root_window_pattern)
                with self.assertRaisesRegex(ValueError, "Window root"):
                    runtime.process_event(self.event("LOGIN_FAIL", 1, "Alice"))
                self.assertEqual(runtime.active_instances(), 0)


if __name__ == "__main__":
    unittest.main()
