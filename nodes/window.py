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
        self.expired = False

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
            self.expired = True

            # Reset only the matching state.
            # Keep expired=True so TreeInstance can observe
            # that this instance has permanently expired.
            self.start_time = None
            self.child.reset()

            return Status.FAILURE

        return self.child.tick(
            event,
            context
        )

    def is_expired(self, current_time):
        if self.start_time is None:
            return False

        return (
            current_time - self.start_time
            > self.window_size
        )

    def reset(self):
        self.start_time = None
        self.expired = False
        self.child.reset()
