import unittest

from core.event import Event
from engine.runtime import BTRuntime
from patterns.security_attack import privilege_attack_pattern


class TestWindowSemantics(unittest.TestCase):

    def make_event(self, event_type, timestamp, user="Alice"):
        return Event(
            event_type,
            timestamp,
            {"user": user},
        )

    def test_match_within_window(self):
        runtime = BTRuntime(privilege_attack_pattern)

        result1 = runtime.process_event(
            self.make_event("LOGIN_FAIL", 10)
        )
        result2 = runtime.process_event(
            self.make_event("PRIVILEGE_ESCALATION", 20)
        )

        self.assertEqual(result1, [])
        self.assertEqual(result2, ["Alice"])
        self.assertEqual(runtime.active_instances(), 0)

    def test_match_exactly_at_boundary(self):
        runtime = BTRuntime(privilege_attack_pattern)

        runtime.process_event(
            self.make_event("LOGIN_FAIL", 10)
        )

        result = runtime.process_event(
            self.make_event("PRIVILEGE_ESCALATION", 40)
        )

        self.assertEqual(result, ["Alice"])
        self.assertEqual(runtime.active_instances(), 0)

    def test_match_outside_window_fails(self):
        runtime = BTRuntime(privilege_attack_pattern)

        runtime.process_event(
            self.make_event("LOGIN_FAIL", 10)
        )

        result = runtime.process_event(
            self.make_event("PRIVILEGE_ESCALATION", 41)
        )

        self.assertEqual(result, [])

    def test_timed_out_instance_is_removed(self):
        runtime = BTRuntime(privilege_attack_pattern)

        runtime.process_event(
            self.make_event("LOGIN_FAIL", 10)
        )

        runtime.process_event(
            self.make_event("PRIVILEGE_ESCALATION", 41)
        )

        self.assertEqual(
            runtime.active_instances(),
            0,
            "Timed-out instance should be removed",
        )

    def test_new_match_after_previous_instance_expires(self):
        runtime = BTRuntime(privilege_attack_pattern)

        # First instance starts at t=10.
        runtime.process_event(
            self.make_event("LOGIN_FAIL", 10)
        )

        # 31 seconds later: first instance expires.
        result = runtime.process_event(
            self.make_event("PRIVILEGE_ESCALATION", 41)
        )

        self.assertEqual(result, [])
        self.assertEqual(runtime.active_instances(), 0)

        # Same user starts a completely new instance.
        result1 = runtime.process_event(
            self.make_event("LOGIN_FAIL", 50)
        )

        self.assertEqual(result1, [])
        self.assertEqual(runtime.active_instances(), 1)

        # New instance completes within its own 30-second window.
        result2 = runtime.process_event(
            self.make_event("PRIVILEGE_ESCALATION", 60)
        )

        self.assertEqual(result2, ["Alice"])
        self.assertEqual(runtime.active_instances(), 0)

if __name__ == "__main__":
    unittest.main()
