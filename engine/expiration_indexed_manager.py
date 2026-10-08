import heapq

from engine.instance import TreeInstance


class ExpirationIndexedInstanceManager:

    def __init__(self, pattern_factory):
        self.pattern_factory = pattern_factory
        self.instances_by_user = {}
        self.expiration_heap = []
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

        # Current PoC assumes a Window root.
        window = instance.tree
        if not hasattr(window, "window_size"):
            raise ValueError(
                "Expiration index requires a Window root"
            )

        # The initial event will tick immediately after
        # creation, establishing the window start time.
        expire_at = event.timestamp + window.window_size

        heapq.heappush(
            self.expiration_heap,
            (expire_at, instance.instance_id, user),
        )

        return instance

    def expire_instances(self, current_time):
        # Inclusive boundary: expire only when time > expire_at.
        while (
            self.expiration_heap
            and self.expiration_heap[0][0] < current_time
        ):
            _, instance_id, user = heapq.heappop(
                self.expiration_heap
            )

            instance = self.instances_by_user.get(user)

            # Ignore stale records from completed instances.
            if (
                instance is None
                or instance.instance_id != instance_id
            ):
                continue

            if instance.is_expired(current_time):
                del self.instances_by_user[user]

    def process_event(self, event):
        detected_users = []
        user = event.attributes["user"]

        # Global expiration before new instance creation.
        self.expire_instances(event.timestamp)

        start_events = getattr(
            self.pattern_factory,
            "start_events",
            [],
        )

        if (
            event.event_type in start_events
            and user not in self.instances_by_user
        ):
            self.create_instance(event)

        instance = self.instances_by_user.get(user)

        if instance is not None:
            result = instance.process(event)

            if result:
                detected_users.append(result)

            if instance.completed:
                del self.instances_by_user[user]

        return detected_users

    def active_count(self):
        return len(self.instances_by_user)
