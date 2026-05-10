from __future__ import annotations

import shlex

from honeypot.core.session import SessionState


class InteractionEngine:
    """
    The core logic controller for the honeypot's terminal simulation.
    
    This engine acts as a 'fake shell' that parses attacker input and generates 
    standard Linux-like responses. It maintains the illusion of a real system 
    while remaining isolated and safe.
    """

    def build_banner(self, session: SessionState) -> str:
        """
        Generates the initial SSH/Terminal login banner.
        
        Args:
            session: The current user session object containing state data.
            
        Returns:
            A string containing the OS spoofing info and the initial command prompt.
        """
        return (
            "Linux fake-host 5.15.0-91-generic x86_64\n"
            "Last login: Fri May  7 21:00:00 2026 from unknown\n"
            f"{session.prompt()}"
        )

    def process(self, raw_input: str, session: SessionState) -> str:
        """
        Main execution loop for incoming commands.
        
        Logic Flow:
        1. Cleanup input and log it for forensics.
        2. Tokenize input using shlex (handles quotes and spaces like a real shell).
        3. Match the primary command against implemented 'fake' commands.
        4. Return the simulated output + the next prompt.
        """
        command = raw_input.strip()

        # 1. Handle Empty Input: Just return a new prompt line
        if not command:
            return session.prompt()

        # 2. Forensics: Log the raw command for later analysis
        session.log_command(command)

        # 3. Parsing: Use shlex to split "ls -la 'my folder'" into tokens
        try:
            tokens = shlex.split(command)
        except ValueError:
            # Triggered if the attacker provides unbalanced quotes
            return f"bash: syntax error near unexpected token\n{session.prompt()}"

        if not tokens:
            return session.prompt()

        cmd = tokens[0] # The actual executable (e.g., 'ls')
        args = tokens[1:] # The arguments (e.g., ['-a'])

        # --- COMMAND DISPATCHER ---

        # Session termination
        if cmd in ("exit", "quit", "logout"):
            return "__CLOSE__"
        

        # Help system
        if cmd in ("help", "?"):
            return (
                "Available commands: ls, cat, pwd, whoami, id, uname -a, help, exit\n"
                f"{session.prompt()}"
            )
        

        # Identity simulation (Hardcoded to root to entice attackers)
        if cmd == "whoami":
            return f"root\n{session.prompt()}"

        # Directory simulation using SessionState's Current Working Directory (cwd)
        if cmd == "pwd":
            return f"{session.cwd}\n{session.prompt()}"

        # Permission simulation
        if cmd == "id":
            return f"uid=0(root) gid=0(root) groups=0(root)\n{session.prompt()}"

        # Specific flag handling (uname -a)
        if cmd == "uname" and args == ["-a"]:
            return (
                "Linux fake-host 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n"
                f"{session.prompt()}"
            )

        # List files logic
        if cmd == "ls":
            # Determine if user is listing current dir or a specific path
            target = self._extract_ls_target(args) or session.cwd
            return f"{self._ls(session, target)}{session.prompt()}"

        # Read file logic
        if cmd == "cat":
            if not args:
                return f"cat: missing file operand\n{session.prompt()}"

            target = args[0]
            #  Attempt to retrieve virtual file content from session
            content = session.files.get(target)
            if content is None:
                return f"cat: {target}: No such file or directory\n{session.prompt()}"

            # Ensure proper formatting of output
            if not content.endswith("\n"):
                content += "\n"
            return f"{content}{session.prompt()}"

        # Terminal control: Sends ANSI escape codes to clear the screen
        if cmd == "clear":
            return "\x1b[2J\x1b[H" + session.prompt()

        # Fallback: Standard bash error for unimplemented commands
        return f"bash: {command}: command not found\n{session.prompt()}"

    def _extract_ls_target(self, args: list[str]) -> str | None:
        """
        Helper to filter out flags (e.g., -la) and find the directory/file target.
        """
        for arg in args:
            if not arg.startswith("-"):
                return arg
        return None

    def _ls(self, session: SessionState, path: str) -> str:
        """
        Simulates a static filesystem structure.
        
        Note: In a production honeypot, this would ideally be replaced 
        by a dynamic virtual filesystem.
        """

        # Hardcoded map of directory contents

        listings = {
            "/": "bin  boot  dev  etc  home  tmp  var",
            "/home": "admin",
            "/home/admin": "notes.txt  readme.txt  .ssh",
            "/etc": "hosts  passwd  ssh",
            "/var": "log",
            "/var/log": "auth.log  syslog",
            # Ensure the current directory always has content
            session.cwd: "notes.txt  readme.txt  .ssh",
        }

        if path in listings:
            return listings[path] + "\n"

        return f"ls: cannot access '{path}': No such file or directory\n"