class Event:


    def __init__(
        self,
        event_type,
        timestamp,
        attributes=None
    ):

        self.event_type = event_type

        self.timestamp = timestamp

        self.attributes = attributes or {}



    def __repr__(self):

        return (
            f"Event("
            f"type={self.event_type}, "
            f"time={self.timestamp}"
            f")"
        )
