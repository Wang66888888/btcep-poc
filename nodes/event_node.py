from nodes.node import Node
from core.status import Status


class EventNode(Node):

    def __init__(self, event_type):

        self.event_type = event_type


    def tick(self, event, context=None):


        if event.event_type != self.event_type:

            return Status.FAILURE


        if context is not None:


            event_user = event.attributes.get(
                "user"
            )


            if event_user != context:

                return Status.FAILURE


        return Status.SUCCESS



    def reset(self):

        pass
