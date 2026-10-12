import heapq

from engine.instance import TreeInstance


class CompactExpirationInstanceManager:
    """Expiration-indexed manager with bounded stale-heap growth."""

    def __init__(self, pattern_factory, compact_min=64, compact_factor=2.0):
        self.pattern_factory = pattern_factory
        self.compact_min = compact_min
        self.compact_factor = compact_factor
        self.instances_by_user = {}
        self.expiration_heap = []
        self.counter = 0
        self.compaction_count = 0
        self.compaction_check_count = 0

    def create_instance(self, event):
        user = event.attributes["user"]
        instance = TreeInstance(self.pattern_factory(), self.counter, user)
        self.counter += 1
        self.instances_by_user[user] = instance

        window = instance.tree
        if not hasattr(window, "window_size"):
            del self.instances_by_user[user]
            raise ValueError("Expiration index requires a Window root")

        expire_at = event.timestamp + window.window_size
        # Preserve the deadline even before the first tick initializes
        # Window.start_time; a threshold-triggered rebuild may happen here.
        instance.expire_at = expire_at
        heapq.heappush(
            self.expiration_heap,
            (expire_at, instance.instance_id, user),
        )
        self._maybe_compact()
        return instance

    def _maybe_compact(self):
        self.compaction_check_count += 1
        heap_size = len(self.expiration_heap)
        active = len(self.instances_by_user)
        if heap_size > max(self.compact_min, self.compact_factor * active):
            self._rebuild_heap()
            self.compaction_count += 1

    def _rebuild_heap(self):
        self.expiration_heap = [
            (instance.expire_at,
             instance.instance_id, user)
            for user, instance in self.instances_by_user.items()
            if not instance.completed
        ]
        heapq.heapify(self.expiration_heap)

    def expire_instances(self, current_time):
        while self.expiration_heap and self.expiration_heap[0][0] < current_time:
            _, instance_id, user = heapq.heappop(self.expiration_heap)
            instance = self.instances_by_user.get(user)
            if instance is None or instance.instance_id != instance_id:
                continue
            if instance.is_expired(current_time):
                del self.instances_by_user[user]
        self._maybe_compact()

    def process_event(self, event):
        detected_users = []
        user = event.attributes["user"]
        self.expire_instances(event.timestamp)

        start_events = getattr(self.pattern_factory, "start_events", [])
        if event.event_type in start_events and user not in self.instances_by_user:
            self.create_instance(event)

        instance = self.instances_by_user.get(user)
        if instance is not None:
            result = instance.process(event)
            if result:
                detected_users.append(result)
            if instance.completed:
                del self.instances_by_user[user]
                self._maybe_compact()

        return detected_users

    def active_count(self):
        return len(self.instances_by_user)
