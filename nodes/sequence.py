from nodes.node import Node
from core.status import Status


class Sequence(Node):
    def __init__(self, children):
        self.children = children
        self.current_index = 0

    def tick(self, event, context=None):
        if self.current_index >= len(self.children):
            self.reset()
            return Status.SUCCESS

        child = self.children[self.current_index]

        result = child.tick(
            event,
            context
        )

        if result == Status.SUCCESS:
            self.current_index += 1

            if self.current_index == len(self.children):
                self.reset()
                return Status.SUCCESS

            return Status.RUNNING

        elif result == Status.FAILURE:
            # CEP sequence semantics:
            # once a partial match exists, unrelated events
            # do not destroy the matched prefix.
            if self.current_index > 0:
                return Status.RUNNING

            self.reset()
            return Status.FAILURE

        return Status.RUNNING

    def reset(self):
        self.current_index = 0

        for child in self.children:
            child.reset()
