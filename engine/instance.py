from core.status import Status


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



    def process(self,event):


        result = self.tree.tick(event)


        print(
            f"[TreeInstance] event={event.event_type}, result={result}"
        )


        if result == Status.SUCCESS:

            self.completed = True

            return self.context_key


        return None



    def reset(self):

        self.tree.reset()
