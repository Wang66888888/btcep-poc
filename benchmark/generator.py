import random

from core.event import Event



NORMAL_EVENTS = [

    "LOGIN_SUCCESS",

    "FILE_ACCESS",

    "NORMAL_OPERATION"

]



ATTACK_SEQUENCE = [

    "LOGIN_FAIL",

    "PRIVILEGE_ESCALATION"

]



def generate_events(
    num_events=10000,
    users=100,
    attack_ratio=0.01,
    seed=42
):


    random.seed(seed)


    events = []


    timestamp = 0


    user_list = [

        f"user_{i}"

        for i in range(users)

    ]



    attack_count = int(
        num_events * attack_ratio
    )


    attack_positions = set(

        random.sample(

            range(
                num_events-2
            ),

            attack_count

        )

    )



    i = 0


    while i < num_events:


        user = random.choice(user_list)


        # 插入完整攻击pattern

        if i in attack_positions and i+1 < num_events:


            for attack_event in ATTACK_SEQUENCE:


                timestamp += 1


                events.append(

                    Event(

                        attack_event,

                        timestamp,

                        {

                            "user": user

                        }

                    )

                )


            i += 2


            continue



        timestamp += 1


        events.append(

            Event(

                random.choice(
                    NORMAL_EVENTS
                ),

                timestamp,

                {

                    "user": user

                }

            )

        )


        i += 1



    return events
