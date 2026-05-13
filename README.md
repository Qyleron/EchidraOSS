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