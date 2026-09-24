from nodes.node import Node
from core.status import Status


class Sequence(Node):

    def __init__(self, children):

        self.children = children

        self.current_index = 0



    def tick(self,event):


        if self.current_index >= len(self.children):

            self.reset()

            return Status.SUCCESS



        child = self.children[self.current_index]


        result = child.tick(event)



        if result == Status.SUCCESS:


            self.current_index += 1



            if self.current_index == len(self.children):

                self.reset()

                return Status.SUCCESS



            return Status.RUNNING



        elif result == Status.RUNNING:


            return Status.RUNNING



        else:


            self.reset()

            return Status.FAILURE



    def reset(self):

        self.current_index = 0
