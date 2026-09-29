from core.event import Event



def generate_pattern_events(
    users=1000
):

    events = []

    t = 1


    for i in range(users):

        user = f"user_{i}"


        # sequence / parallel 起始
        events.append(
            Event(
                "LOGIN_FAIL",
                t,
                {
                    "user": user
                }
            )
        )

        t += 1


        # parallel第二事件
        events.append(
            Event(
                "FILE_ACCESS",
                t,
                {
                    "user": user
                }
            )
        )

        t += 1


        # sequence第二事件
        events.append(
            Event(
                "PRIVILEGE_ESCALATION",
                t,
                {
                    "user": user
                }
            )
        )

        t += 1


    return events
