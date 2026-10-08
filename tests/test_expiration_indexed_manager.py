import unittest

from core.event import Event
from engine.runtime import BTRuntime
from engine.indexed_runtime import IndexedBTRuntime
from engine.expiration_indexed_runtime import (
    ExpirationIndexedBTRuntime,
)
from patterns.security_attack import privilege_attack_pattern


class ExpirationIndexedManagerTests(unittest.TestCase):

    def event(self, event_type, timestamp, user):
        return Event(
            event_type,
            timestamp,
            {"user": user},
        )

    def compare_runtimes(self, events):
        runtimes = [
            BTRuntime(privilege_attack_pattern),
            IndexedBTRuntime(privilege_attack_pattern),
            ExpirationIndexedBTRuntime(
                privilege_attack_pattern
            ),
        ]

        histories = [[] for _ in runtimes]

        for event in events:
            for i, runtime in enumerate(runtimes):
                result = runtime.process_event(event)

                histories[i].append((
                    result,
                    runtime.active_instances(),
                    runtime.peak_instances(),
                ))

        self.assertEqual(histories[0], histories[1])
        self.assertEqual(histories[0], histories[2])

        return histories[0]

    def test_window_boundary(self):
        for end_time, expected in [
            (39, ["Alice"]),
            (40, ["Alice"]),
            (41, []),
        ]:
            with self.subTest(end_time=end_time):
                history = self.compare_runtimes([
                    self.event("LOGIN_FAIL", 10, "Alice"),
                    self.event(
                        "PRIVILEGE_ESCALATION",
                        end_time,
                        "Alice",
                    ),
                ])

                self.assertEqual(history[-1][0], expected)

    def test_other_user_triggers_expiration(self):
        history = self.compare_runtimes([
            self.event("LOGIN_FAIL", 10, "Alice"),
            self.event("LOGIN_FAIL", 11, "Bob"),
            self.event("NORMAL_OPERATION", 50, "Carol"),
        ])

        self.assertEqual(history[-1][1], 0)

    def test_restart_after_expiration(self):
        history = self.compare_runtimes([
            self.event("LOGIN_FAIL", 10, "Alice"),
            self.event("LOGIN_FAIL", 50, "Alice"),
            self.event(
                "PRIVILEGE_ESCALATION",
                60,
                "Alice",
            ),
        ])

        self.assertEqual(history[-1][0], ["Alice"])

    def test_stale_heap_record(self):
        history = self.compare_runtimes([
            self.event("LOGIN_FAIL", 10, "Alice"),
            self.event(
                "PRIVILEGE_ESCALATION",
                11,
                "Alice",
            ),
            self.event("LOGIN_FAIL", 20, "Alice"),
            self.event("NORMAL_OPERATION", 41, "Bob"),
            self.event(
                "PRIVILEGE_ESCALATION",
                42,
                "Alice",
            ),
        ])

        self.assertEqual(history[-1][0], ["Alice"])

    def test_multiple_users(self):
        history = self.compare_runtimes([
            self.event("LOGIN_FAIL", 10, "Alice"),
            self.event("LOGIN_FAIL", 12, "Bob"),
            self.event(
                "PRIVILEGE_ESCALATION",
                20,
                "Alice",
            ),
            self.event(
                "PRIVILEGE_ESCALATION",
                30,
                "Bob",
            ),
        ])

        self.assertEqual(history[-1][0], ["Bob"])


if __name__ == "__main__":
    unittest.main()
