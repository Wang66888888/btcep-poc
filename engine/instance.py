from core.status import Status
from config import DEBUG


class TreeInstance:

    def __init__(
        self,
        tree,
        instance_id,
        context_key
    ):
        self.tree = tree
        self.instance_id = instance_id
        self.context_key = context_key
        self.completed = False

    def process(self, event):
        result = self.tree.tick(
            event,
            self.context_key
        )

        if DEBUG:
            print(
                f"[TreeInstance] "
                f"event={event.event_type}, "
                f"result={result}"
            )

        if result == Status.SUCCESS:
            self.completed = True
            return self.context_key

        if getattr(
            self.tree,
            "expired",
            False
        ):
            self.completed = True

        return None

    def reset(self):
        self.completed = False
        self.tree.reset()
