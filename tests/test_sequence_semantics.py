import unittest

from core.event import Event
from engine.runtime import BTRuntime
from patterns.security_attack import privilege_attack_pattern


class SequenceSemanticsTests(unittest.TestCase):

    def event(self, event_type, timestamp, user="Alice"):
        return Event(
            event_type,
            timestamp,
            {"user": user},
        )

    def test_correct_order_matches(self):
        runtime = BTRuntime(privilege_attack_pattern)

        result1 = runtime.process_event(
            self.event("LOGIN_FAIL", 10)
        )
        result2 = runtime.process_event(
            self.event("PRIVILEGE_ESCALATION", 20)
        )

        self.assertEqual(result1, [])
        self.assertEqual(result2, ["Alice"])
        self.assertEqual(runtime.active_instances(), 0)

    def test_reversed_order_does_not_match(self):
        runtime = BTRuntime(privilege_attack_pattern)

        result1 = runtime.process_event(
            self.event("PRIVILEGE_ESCALATION", 10)
        )
        result2 = runtime.process_event(
            self.event("LOGIN_FAIL", 20)
        )

        self.assertEqual(result1, [])
        self.assertEqual(result2, [])
        self.assertEqual(runtime.active_instances(), 1)

    def test_partial_sequence_remains_active(self):
        runtime = BTRuntime(privilege_attack_pattern)

        result = runtime.process_event(
            self.event("LOGIN_FAIL", 10)
        )

        self.assertEqual(result, [])
        self.assertEqual(runtime.active_instances(), 1)

    def test_unrelated_event_between_sequence_steps(self):
        runtime = BTRuntime(privilege_attack_pattern)

        runtime.process_event(
            self.event("LOGIN_FAIL", 10)
        )

        runtime.process_event(
            self.event("NORMAL_OPERATION", 15)
        )

        result = runtime.process_event(
            self.event("PRIVILEGE_ESCALATION", 20)
        )

        self.assertEqual(result, ["Alice"])


    def test_repeated_start_event_does_not_duplicate_match(self):
        runtime = BTRuntime(privilege_attack_pattern)

        result1 = runtime.process_event(
            self.event("LOGIN_FAIL", 10)
        )

        result2 = runtime.process_event(
            self.event("LOGIN_FAIL", 15)
        )

        result3 = runtime.process_event(
            self.event("PRIVILEGE_ESCALATION", 20)
        )

        self.assertEqual(result1, [])
        self.assertEqual(result2, [])

        # Same user/pattern should keep one active
        # partial match rather than duplicate it.
        self.assertEqual(result3, ["Alice"])
        self.assertEqual(runtime.active_instances(), 0)


    def test_different_users_can_have_active_instances(self):
        runtime = BTRuntime(privilege_attack_pattern)

        runtime.process_event(
            self.event("LOGIN_FAIL", 10, "Alice")
        )
        runtime.process_event(
            self.event("LOGIN_FAIL", 11, "Bob")
        )

        self.assertEqual(runtime.active_instances(), 2)

    def test_new_instance_can_start_after_expiration(self):
        runtime = BTRuntime(privilege_attack_pattern)

        runtime.process_event(
            self.event("LOGIN_FAIL", 10, "Alice")
        )

        # At t=41 the old 30-second window has expired.
        # Because this is also a start event, Alice should
        # immediately be able to begin a fresh instance.
        runtime.process_event(
            self.event("LOGIN_FAIL", 41, "Alice")
        )

        self.assertEqual(runtime.active_instances(), 1)

        result = runtime.process_event(
            self.event("PRIVILEGE_ESCALATION", 50, "Alice")
        )

        self.assertEqual(result, ["Alice"])
        self.assertEqual(runtime.active_instances(), 0)


if __name__ == "__main__":
    unittest.main()
