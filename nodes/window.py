from nodes.node import Node
from core.status import Status



class Window(Node):


    def __init__(self,child,timeout):

        self.child = child

        self.timeout = timeout

        self.start_time = None



    def tick(self,event):


        if self.start_time is None:

            self.start_time = event.timestamp



        if event.timestamp - self.start_time > self.timeout:


            self.reset()

            return Status.FAILURE



        result = self.child.tick(event)



        return result




    def reset(self):

        self.start_time = None

        self.child.reset()
