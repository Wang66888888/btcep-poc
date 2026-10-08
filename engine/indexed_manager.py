from engine.instance import TreeInstance


class IndexedInstanceManager:
    """
    Context-indexed instance manager.

    Maintains the same single-active-instance policy
    as the baseline manager.
    """

    def __init__(self, pattern_factory):
        self.pattern_factory = pattern_factory
        self.instances_by_user = {}
        self.counter = 0

    def create_instance(self, event):
        user = event.attributes["user"]

        instance = TreeInstance(
            self.pattern_factory(),
            self.counter,
            user,
        )

        self.counter += 1
        self.instances_by_user[user] = instance

        return instance

    def process_event(self, event):
        detected_users = []
        event_user = event.attributes["user"]

        # Keep global event-time expiration semantics.
        expired_users = [
            user
            for user, instance in self.instances_by_user.items()
            if instance.is_expired(event.timestamp)
        ]

        for user in expired_users:
            del self.instances_by_user[user]

        start_events = getattr(
            self.pattern_factory,
            "start_events",
            [],
        )

        # Single-active-instance policy.
        if (
            event.event_type in start_events
            and event_user not in self.instances_by_user
        ):
            self.create_instance(event)

        instance = self.instances_by_user.get(
            event_user
        )

        if instance is not None:
            result = instance.process(event)

            if result:
                detected_users.append(result)

            if instance.completed:
                del self.instances_by_user[event_user]

        return detected_users

    def active_count(self):
        return len(self.instances_by_user)
