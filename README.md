Attacker
   │
   ▼
main.py
   │
   ▼
server.py
   │
   ├── accepts TCP socket
   ├── creates ConnectionHandler
   └── creates async task
            │
            ▼
connection.py
   │
   ├── sends banner
   ├── waits for attacker input
   ├── receives command
   └── passes command to engine
            │
            ▼
engine.py
   │
   ├── parses command
   ├── decides fake behavior
   ├── updates session state
   └── returns fake response
            │
            ▼
connection.py
   │
   ├── sends response back
   └── waits again
            │
            ▼
Attacker


FIRST: What To Test

You should test in layers.

Level 1 — Unit Tests (NOW)

Tests:

isolated
fast
no real networking if possible

Goal:

verify logic correctness

Level 2 — Integration Tests (NEXT)

Tests:

real TCP connections
real async flows
multi-client concurrency

Goal:

verify components work together

Level 3 — Stress / Load Tests

Tests:

100+
1000+
malformed payloads
connection floods

Goal:

verify stability

Level 4 — Realism Tests

Tests:

does shell feel believable?
does state persist?
do commands behave consistently?

Goal:

attacker deception quality

Level 5 — Security Tests

Tests:

payload isolation
memory exhaustion
injection attempts
malformed UTF-8
socket abuse

Goal:

prevent compromise of honeypot itself