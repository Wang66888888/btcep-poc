import unittest

from core.event import Event
from engine.runtime import BTRuntime
from engine.indexed_runtime import IndexedBTRuntime
from patterns.security_attack import privilege_attack_pattern


class IndexedManagerTests(unittest.TestCase):

    def event(self, event_type, timestamp, user):
        return Event(
            event_type,
            timestamp,
            {"user": user},
        )

    def test_baseline_and_indexed_equivalence(self):
        events = [
            self.event("LOGIN_FAIL", 10, "Alice"),
            self.event("LOGIN_FAIL", 11, "Bob"),
            self.event("LOGIN_FAIL", 15, "Alice"),
            self.event("NORMAL_OPERATION", 16, "Alice"),
            self.event("PRIVILEGE_ESCALATION", 20, "Alice"),
            self.event("PRIVILEGE_ESCALATION", 21, "Bob"),
            self.event("LOGIN_FAIL", 50, "Alice"),
            self.event("PRIVILEGE_ESCALATION", 60, "Alice"),
        ]

        baseline = BTRuntime(
            privilege_attack_pattern
        )

        indexed = IndexedBTRuntime(
            privilege_attack_pattern
        )

        for event in events:
            baseline_result = baseline.process_event(event)
            indexed_result = indexed.process_event(event)

            self.assertEqual(
                baseline_result,
                indexed_result,
            )

            self.assertEqual(
                baseline.active_instances(),
                indexed.active_instances(),
            )

    def test_global_expiration_equivalence(self):
        events = [
            self.event("LOGIN_FAIL", 10, "Alice"),
            self.event("LOGIN_FAIL", 11, "Bob"),
            self.event("NORMAL_OPERATION", 50, "Carol"),
            self.event("LOGIN_FAIL", 51, "Alice"),
            self.event("PRIVILEGE_ESCALATION", 60, "Alice"),
        ]

        baseline = BTRuntime(
            privilege_attack_pattern
        )

        indexed = IndexedBTRuntime(
            privilege_attack_pattern
        )

        for event in events:
            self.assertEqual(
                baseline.process_event(event),
                indexed.process_event(event),
            )

            self.assertEqual(
                baseline.active_instances(),
                indexed.active_instances(),
            )


if __name__ == "__main__":
    unittest.main()
