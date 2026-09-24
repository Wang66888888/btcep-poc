# BT-CEP PoC Progress


# Overview

Project:
Behavior Tree based Complex Event Processing Prototype


Goal:

Validate whether Behavior Tree can be used as a CEP pattern execution model.


---

# v0.1 - Basic Event Sequence Detection


## Implemented

- Event abstraction
- Node abstraction
- EventNode
- SequenceNode
- Basic Runtime


## Pattern

LOGIN_FAIL

    |

PRIVILEGE_ESCALATION


## Result

Successfully detected sequential security event pattern.


---

# v0.2 - Time Window Constraint


## Added

- Window Node
- Time-aware pattern matching


## Pattern


LOGIN_FAIL

    |

PRIVILEGE_ESCALATION


Constraint:

within 30 seconds


## Result


Successfully detected:

LOGIN_FAIL at t=10

PRIVILEGE_ESCALATION at t=20


Generated:

Attack Alert


---

# Current Limitations


1. Only supports single pattern instance.


2. Cannot handle concurrent event sequences.


3. Does not support:

- AND pattern
- OR pattern
- Dynamic pattern update


---

# Next Step


Implement:

Active Tree Instance Manager


Goal:

Support multiple concurrent complex event detection instances.

Example:

Alice attack sequence

and

Bob attack sequence

running simultaneously.


---

# v0.4 - Parallel Node


## Added

- Parallel composite node
- AND pattern matching


## Pattern

LOGIN_FAIL

AND

FILE_ACCESS


## Result

Successfully detected concurrent event pattern.


---

# v0.5 - Selector Node


## Added

- Selector composite node
- OR pattern matching
- Nested Behavior Tree CEP pattern


## Pattern


(LOGIN_FAIL OR MALWARE_EXECUTION)

AND

PRIVILEGE_ESCALATION


## Validation


Test:

MALWARE_EXECUTION

+

PRIVILEGE_ESCALATION


Result:

Successfully detected:

User=Alice


---

# Current BT-CEP Capability


Supported:

- Event Node
- Sequence Node
- Parallel Node
- Selector Node
- Window Constraint
- Active Tree Instance
- Context Partition


Current Status:

BT-CEP prototype successfully supports complex event pattern execution.

