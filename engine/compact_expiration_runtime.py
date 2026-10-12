from engine.compact_expiration_manager import CompactExpirationInstanceManager


class CompactExpirationBTRuntime:
    def __init__(self, pattern_factory, compact_min=64, compact_factor=2.0):
        self.manager = CompactExpirationInstanceManager(
            pattern_factory,
            compact_min=compact_min,
            compact_factor=compact_factor,
        )
        self.max_active_instances = 0

    def process_event(self, event):
        result = self.manager.process_event(event)
        self.max_active_instances = max(
            self.max_active_instances, self.manager.active_count()
        )
        return result

    def active_instances(self):
        return self.manager.active_count()

    def peak_instances(self):
        return self.max_active_instances
