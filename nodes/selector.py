from nodes.node import Node
from core.status import Status


class Selector(Node):


    def __init__(self, children):

        self.children = children



    def tick(self, event):


        for child in self.children:


            result = child.tick(event)


            if result == Status.SUCCESS:

                return Status.SUCCESS



            if result == Status.RUNNING:

                return Status.RUNNING



        return Status.FAILURE



    def reset(self):

        for child in self.children:

            child.reset()
