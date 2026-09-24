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



    def process_event(self, event):


        detected_users = []



        # 创建新的匹配实例

        start_events = getattr(

            self.pattern_factory,

            "start_events",

            []

        )


        if event.event_type in start_events:


            self.create_instance(event)



        # 推进已有实例

        for instance in list(self.instances):


            result = instance.process(event)



            if result:


                detected_users.append(result)


                self.instances.remove(instance)



        return detected_users


    def active_count(self):

        return len(self.instances)
