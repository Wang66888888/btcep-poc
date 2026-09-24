from nodes.node import Node
from core.status import Status



class Sequence(Node):


    def __init__(self,children):

        self.children = children

        self.current_index = 0



    def tick(self,event):


        while self.current_index < len(self.children):


            child = self.children[self.current_index]


            result = child.tick(event)



            if result == Status.SUCCESS:


                self.current_index += 1

                continue



            elif result == Status.RUNNING:


                return Status.RUNNING



            else:


                self.reset()

                return Status.FAILURE



        self.reset()

        return Status.SUCCESS




    def reset(self):

        self.current_index = 0
