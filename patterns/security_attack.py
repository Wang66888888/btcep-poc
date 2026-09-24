from nodes.event_node import EventNode
from nodes.sequence import Sequence
from nodes.window import Window
from nodes.parallel import Parallel
from nodes.selector import Selector



def privilege_attack_pattern():


    sequence = Sequence(
        [
            EventNode("LOGIN_FAIL"),
            EventNode("PRIVILEGE_ESCALATION")
        ]
    )


    return Window(sequence,30)





def parallel_attack_pattern():


    parallel = Parallel(
        [
            EventNode("LOGIN_FAIL"),
            EventNode("FILE_ACCESS")
        ]
    )


    return Window(parallel,30)





def selector_attack_pattern():


    entry_selector = Selector(
        [
            EventNode("LOGIN_FAIL"),
            EventNode("MALWARE_EXECUTION")
        ]
    )


    attack_pattern = Parallel(
        [
            entry_selector,
            EventNode("PRIVILEGE_ESCALATION")
        ]
    )


    return Window(
        attack_pattern,
        30
    )


# Pattern启动事件

selector_attack_pattern.start_events = [
    "LOGIN_FAIL",
    "MALWARE_EXECUTION"
]


parallel_attack_pattern.start_events = [
    "LOGIN_FAIL",
    "FILE_ACCESS"
]


privilege_attack_pattern.start_events = [
    "LOGIN_FAIL"
]
