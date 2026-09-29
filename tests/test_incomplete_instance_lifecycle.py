import unittest

from core.event import Event
from engine.runtime import BTRuntime
from patterns.security_attack import parallel_attack_pattern


class IncompleteInstanceLifecycleTests(unittest.TestCase):

    def event(self, event_type, timestamp, user):
        return Event(
            event_type,
            timestamp,
            {"user": user},
        )

    def test_incomplete_instance_exists_at_end_of_stream(self):
        runtime = BTRuntime(parallel_attack_pattern)

        runtime.process_event(
            self.event(
                "LOGIN_FAIL",
                10,
                "Alice",
            )
        )

        self.assertEqual(
            runtime.active_instances(),
            1,
        )

    def test_same_user_future_event_expires_instance(self):
        runtime = BTRuntime(parallel_attack_pattern)

        runtime.process_event(
            self.event(
                "LOGIN_FAIL",
                10,
                "Alice",
            )
        )

        runtime.process_event(
            self.event(
                "NORMAL_OPERATION",
                41,
                "Alice",
            )
        )

        self.assertEqual(
            runtime.active_instances(),
            0,
        )

    def test_other_user_future_event_expires_stale_instance(self):
        runtime = BTRuntime(parallel_attack_pattern)

        runtime.process_event(
            self.event(
                "LOGIN_FAIL",
                10,
                "Alice",
            )
        )

        runtime.process_event(
            self.event(
                "NORMAL_OPERATION",
                100,
                "Bob",
            )
        )

        self.assertEqual(
            runtime.active_instances(),
            0,
            "Globally expired instance should be removed "
            "even when the triggering event belongs to another user",
        )


if __name__ == "__main__":
    unittest.main()
