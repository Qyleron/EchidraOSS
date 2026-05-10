import time


class SessionState:
    """
    This class acts as a 'memory bank' for a single user connection.
    It stores where they are, what they've done, and what files they can see.
    """

    def __init__(self, peer):
        # 1. IDENTITY & TIMING
        self.peer = peer   # The IP address or ID of the person connecting
        self.start_time = time.time()  # When the session began (Unix timestamp)
        self.last_active = self.start_time  # Updated every time they type a command

        # 2. ACTIVITY TRACKING
        self.commands = []  # A list to store every command typed
        self.command_count = 0  # A simple counter for the total number of commands

        # 3. ENVIRONMENT STATE
        self.cwd = "/home/admin"  # 'Current Working Directory' - where the user is 'standing'
        self.mode = "unknown"     # Can be used to track if they are in 'read' or 'edit' mode

        # 4. VIRTUAL FILE SYSTEM
        # Instead of real files on your hard drive, these exist only in the code's memory.
        self.files = {
            "/home/admin/readme.txt": "Welcome to the system.\n",
            "/home/admin/notes.txt": "TODO: rotate credentials\n",
            "/etc/passwd": (
                "root:x:0:0:root:/root:/bin/bash\n"
                "admin:x:1000:1000:admin:/home/admin:/bin/bash\n"
            ),
            "/etc/hosts": "127.0.0.1 localhost\n",
            "/var/log/auth.log": "",
        }

    def log_command(self, command: str) -> None:
        """
        Records a command, timestamps it, and updates the 'last_active' timer.
        """
        # Save the command details as a dictionary inside our list
        self.commands.append({
            "cmd": command,
            "timestamp": time.time(),
        })

        # Increment the counter
        self.command_count += 1

        # Update activity so we know the user isn't idle
        self.last_active = time.time()

    def prompt(self) -> str:
        """
        Generates the text the user sees before they type (e.g., /home/admin$ )
        """
        return f"{self.cwd}$ "