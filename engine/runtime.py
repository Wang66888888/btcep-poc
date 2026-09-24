from engine.manager import InstanceManager


class BTRuntime:


    def __init__(self, pattern_factory):

        self.manager = InstanceManager(
            pattern_factory
        )


    def process_event(self, event):

        return self.manager.process_event(event)
