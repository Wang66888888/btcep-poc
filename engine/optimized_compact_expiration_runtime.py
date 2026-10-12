from engine.optimized_compact_expiration_manager import (
    OptimizedCompactExpirationInstanceManager,
)


class OptimizedCompactExpirationBTRuntime:
    def __init__(self, pattern_factory, compact_min=64, compact_factor=2.0):
        self.manager = OptimizedCompactExpirationInstanceManager(
            pattern_factory,
            compact_min=compact_min,
            compact_factor=compact_factor,
        )
        self.max_active_instances = 0

    def process_event(self, event):
        result = self.manager.process_event(event)
        current = self.manager.active_count()
        if current > self.max_active_instances:
            self.max_active_instances = current
        return result

    def active_instances(self):
        return self.manager.active_count()

    def peak_instances(self):
        return self.max_active_instances
