import unittest

from core.event import Event
from engine.runtime import BTRuntime
from patterns.security_attack import parallel_attack_pattern


class ParallelSemanticsTests(unittest.TestCase):

    def event(self, event_type, timestamp, user="Alice"):
        return Event(
            event_type,
            timestamp,
            {"user": user},
        )

    def test_login_fail_then_file_access_matches(self):
        runtime = BTRuntime(parallel_attack_pattern)

        result1 = runtime.process_event(
            self.event("LOGIN_FAIL", 10)
        )
        result2 = runtime.process_event(
            self.event("FILE_ACCESS", 20)
        )

        self.assertEqual(result1, [])
        self.assertEqual(result2, ["Alice"])
        self.assertEqual(runtime.active_instances(), 0)

    def test_partial_parallel_remains_active(self):
        runtime = BTRuntime(parallel_attack_pattern)

        result = runtime.process_event(
            self.event("LOGIN_FAIL", 10)
        )

        self.assertEqual(result, [])
        self.assertEqual(runtime.active_instances(), 1)

    def test_unrelated_event_between_parallel_events(self):
        runtime = BTRuntime(parallel_attack_pattern)

        runtime.process_event(
            self.event("LOGIN_FAIL", 10)
        )

        runtime.process_event(
            self.event("NORMAL_OPERATION", 15)
        )

        result = runtime.process_event(
            self.event("FILE_ACCESS", 20)
        )

        self.assertEqual(result, ["Alice"])
        self.assertEqual(runtime.active_instances(), 0)

    def test_different_users_do_not_complete_parallel(self):
        runtime = BTRuntime(parallel_attack_pattern)

        runtime.process_event(
            self.event("LOGIN_FAIL", 10, "Alice")
        )

        result = runtime.process_event(
            self.event("FILE_ACCESS", 20, "Bob")
        )

        self.assertEqual(result, [])
        self.assertEqual(runtime.active_instances(), 1)

    def test_file_access_then_login_fail_does_not_start_match(self):
        runtime = BTRuntime(parallel_attack_pattern)

        result1 = runtime.process_event(
            self.event("FILE_ACCESS", 10)
        )

        result2 = runtime.process_event(
            self.event("LOGIN_FAIL", 20)
        )

        self.assertEqual(result1, [])
        self.assertEqual(result2, [])
        self.assertEqual(runtime.active_instances(), 1)


if __name__ == "__main__":
    unittest.main()
