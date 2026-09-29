from engine.instance import TreeInstance


class InstanceManager:
    def __init__(self, pattern_factory):
        self.pattern_factory = pattern_factory
        self.instances = []
        self.counter = 0

    def create_instance(self, event):
        instance = TreeInstance(
            self.pattern_factory(),
            self.counter,
            event.attributes["user"]
        )

        self.counter += 1
        self.instances.append(instance)

    def has_active_instance(self, context_key):
        return any(
            instance.context_key == context_key
            and not instance.completed
            for instance in self.instances
        )

    def process_event(self, event):
        detected_users = []

        event_user = event.attributes["user"]

        # Expiration follows global event time and must be
        # processed before deciding whether a new instance
        # may be created for this context.
        for instance in list(self.instances):
            if instance.is_expired(event.timestamp):
                self.instances.remove(instance)

        start_events = getattr(
            self.pattern_factory,
            "start_events",
            []
        )

        # PoC match-selection policy:
        # keep at most one active partial match per context.
        if (
            event.event_type in start_events
            and not self.has_active_instance(event_user)
        ):
            self.create_instance(event)

        # Only advance instances belonging to the same user.
        for instance in list(self.instances):
            if instance.context_key != event_user:
                continue

            result = instance.process(event)

            # Detection result and instance lifecycle are
            # intentionally handled separately.
            if result:
                detected_users.append(result)

            # Remove successfully completed or expired instances.
            if instance.completed:
                self.instances.remove(instance)

        return detected_users

    def active_count(self):
        return len(self.instances)
