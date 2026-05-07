import time

class SessionState:
    """
    Represents a single attacker session.
    Completely isolated per connection.
    """

    def __init__(self, peer):
        self.peer = peer
        self.start_time = time.time()
        self.commands = []
        self.last_active = time.time()

    def log_command(self, command):
        self.commands.append({
            "cmd": command,
            "timestamp": time.time()
        })
        self.last_active = time.time()