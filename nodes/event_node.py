from nodes.node import Node
from core.status import Status



class EventNode(Node):


    def __init__(self,event_type):

        self.event_type = event_type



    def tick(self,event):


        if event.event_type == self.event_type:

            return Status.SUCCESS



        return Status.FAILURE
