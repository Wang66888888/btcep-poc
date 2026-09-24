import unittest

from core.event import Event
from engine.runtime import BTRuntime
from patterns.security_attack import privilege_attack_pattern


class UserContextRoutingTests(unittest.TestCase):

    def setUp(self):
        self.runtime = BTRuntime(privilege_attack_pattern)

    def test_events_from_different_users_do_not_match(self):
        self.assertEqual(
            self.runtime.process_event(
                Event("LOGIN_FAIL", 1, {"user": "Alice"})
            ),
            [],
        )
        self.assertEqual(
            self.runtime.process_event(
                Event("PRIVILEGE_ESCALATION", 2, {"user": "Bob"})
            ),
            [],
        )

    def test_events_from_same_user_match(self):
        self.assertEqual(
            self.runtime.process_event(
                Event("LOGIN_FAIL", 1, {"user": "Alice"})
            ),
            [],
        )
        self.assertEqual(
            self.runtime.process_event(
                Event("PRIVILEGE_ESCALATION", 2, {"user": "Alice"})
            ),
            ["Alice"],
        )


if __name__ == "__main__":
    unittest.main()
