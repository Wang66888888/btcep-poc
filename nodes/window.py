from nodes.node import Node
from core.status import Status


class Window(Node):

    def __init__(
        self,
        child,
        window_size
    ):

        self.child = child

        self.window_size = window_size

        self.start_time = None



    def tick(
        self,
        event,
        context=None
    ):


        if self.start_time is None:

            self.start_time = event.timestamp



        if (
            event.timestamp - self.start_time
            >
            self.window_size
        ):

            self.reset()

            return Status.FAILURE



        result = self.child.tick(
            event,
            context
        )


        return result



    def reset(self):

        self.start_time = None

        self.child.reset()
