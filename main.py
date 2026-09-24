from core.event import Event

from patterns.security_attack import selector_attack_pattern

from engine.runtime import BTRuntime



runtime = BTRuntime(
    selector_attack_pattern
)



events = [


    Event(
        "MALWARE_EXECUTION",
        1,
        {
            "user":"Alice"
        }
    ),


    Event(
        "PRIVILEGE_ESCALATION",
        10,
        {
            "user":"Alice"
        }
    )

]



for event in events:


    print(event)


    detected_users = runtime.process_event(event)


    for user in detected_users:

        print(
            f"ALERT: Selector attack detected! User={user}"
        )
