from core.event import Event


def generate_active_events(users=1000):

    events = []

    timestamp = 1


    # 只发送启动事件
    # 创建大量未完成 TreeInstance

    for i in range(users):

        user = f"user_{i}"

        events.append(
            Event(
                "LOGIN_FAIL",
                timestamp,
                {
                    "user": user
                }
            )
        )

        timestamp += 1


    return events
