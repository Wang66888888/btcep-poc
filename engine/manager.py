from engine.instance import TreeInstance



class InstanceManager:


    def __init__(self, pattern_factory):

        self.pattern_factory = pattern_factory

        self.instances = []

        self.counter = 0



    def create_instance(self,event):


        print(
            f"[Manager] Create instance for {event.attributes['user']}"
        )


        tree = self.pattern_factory()


        instance = TreeInstance(
            tree,
            self.counter,
            event.attributes["user"]
        )


        self.counter += 1


        self.instances.append(instance)



    def process_event(self,event):


        detected_users = []


        key = event.attributes["user"]



        if event.event_type in self.pattern_factory.start_events:

            self.create_instance(event)



        print(
            f"[Manager] Active instances: {len(self.instances)}"
        )


        for instance in self.instances[:]:


            if instance.context_key != key:

                continue



            result = instance.process(event)


            print(
                f"[Manager] Instance {instance.instance_id} result={result}"
            )


            if result is not None:

                detected_users.append(result)

                self.instances.remove(instance)



        return detected_users
