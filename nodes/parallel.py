from nodes.node import Node
from core.status import Status


class Parallel(Node):


    def __init__(self, children):

        self.children = children

        self.completed = [
            False for _ in children
        ]



    def tick(self,event):


        print(
            "[Parallel] before:",
            self.completed
        )


        for index, child in enumerate(self.children):


            if self.completed[index]:

                continue



            result = child.tick(event)


            print(
                f"[Parallel] child {index} result={result}"
            )


            if result == Status.SUCCESS:

                self.completed[index] = True



        print(
            "[Parallel] after:",
            self.completed
        )



        if all(self.completed):

            return Status.SUCCESS



        return Status.RUNNING



    def reset(self):


        self.completed = [
            False for _ in self.children
        ]


        for child in self.children:

            child.reset()
