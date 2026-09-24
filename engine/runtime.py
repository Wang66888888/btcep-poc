from engine.manager import InstanceManager


class BTRuntime:


    def __init__(self, pattern_factory):

        self.manager = InstanceManager(
            pattern_factory
        )

        self.max_active_instances = 0



    def process_event(self, event):

        result = self.manager.process_event(event)


        current = len(
            self.manager.instances
        )


        if current > self.max_active_instances:

            self.max_active_instances = current


        return result



    def active_instances(self):

        return len(
            self.manager.instances
        )



    def peak_instances(self):

        return self.max_active_instances
