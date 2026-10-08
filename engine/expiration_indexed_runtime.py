from engine.expiration_indexed_manager import (
    ExpirationIndexedInstanceManager,
)


class ExpirationIndexedBTRuntime:

    def __init__(self, pattern_factory):
        self.manager = ExpirationIndexedInstanceManager(
            pattern_factory
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
