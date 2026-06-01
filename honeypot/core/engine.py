from __future__ import annotations

import shlex
from pathlib import PurePosixPath

from honeypot.core.session import SessionState


class InteractionEngine:
    """
    Fake shell engine for the honeypot terminal simulation.

    Parses visitor input, records commands, and returns controlled Linux-like
    responses without executing host commands or reading host files.
    """

    def build_banner(self, session: SessionState) -> str:
        """Return the initial fake login banner and prompt for a session."""

        return (
            f"{session.persona.os_banner}\n"
            "Last login: Fri May  7 21:00:00 2026 from unknown\n"
            f"{session.prompt()}"
        )


    def process(self, raw_input: str, session: SessionState) -> str:
        """
        Process one raw command string and return fake shell output plus the next prompt.

        The engine logs non-empty commands, tokenizes shell-style input with shlex,
        dispatches supported fake commands, and falls back to a bash-like error.
        """
        command = raw_input.strip()

        # Empty input returns a fresh prompt without logging a command
        if not command:
            return session.prompt()

        # Preserve the raw command for later analysis
        session.log_command(command)

        # Parse shell-style quoting and spacing
        try:
            tokens = shlex.split(command)
        except ValueError:
            # Unbalanced quotes should look like a shell syntax error, not a crash
            return f"bash: syntax error near unexpected token\n{session.prompt()}"

        if not tokens:
            return session.prompt()

        cmd = tokens[0] 
        args = tokens[1:] 

        # --- COMMAND DISPATCHER ---

        # Session termination
        if cmd in ("exit", "quit", "logout"):
            return "__CLOSE__"
        

        # Help system
        if cmd in ("help", "?"):
            return (
                "Available commands: ls, cat, pwd, whoami, id, uname -a, "
                "hostname, ps, netstat, help, exit\n"
                f"{session.prompt()}"
            )
        

        # Identity simulation
        if cmd == "whoami":
            return f"{session.persona.username}\n{session.prompt()}"

        # Directory simulation using the session's current fake directory
        if cmd == "pwd":
            return f"{session.cwd}\n{session.prompt()}"

        # Permission simulation
        if cmd == "id":
            return f"uid=0(root) gid=0(root) groups=0(root)\n{session.prompt()}"

        # Support the most common system fingerprinting form
        if cmd == "uname" and args == ["-a"]:
            return f"{session.persona.uname_output}\n{session.prompt()}"

        if cmd == "hostname":
            return f"{session.persona.hostname}\n{session.prompt()}"

        if cmd == "ps":
            return f"{self._ps(session)}{session.prompt()}"

        if cmd in ("netstat", "ss"):
            return f"{self._visible_ports(session)}{session.prompt()}"

        # Directory listing from the virtual filesystem
        if cmd == "ls":
            # Use the current directory when no explicit target is provided
            target = self._extract_ls_target(args) or session.cwd
            return f"{self._ls(session, target)}{session.prompt()}"

        # File reads are served only from persona-backed fake files
        if cmd == "cat":
            if not args:
                return f"cat: missing file operand\n{session.prompt()}"

            target = self._resolve_path(session, args[0])
            # Look up normalized paths in the session's virtual filesystem
            content = session.files.get(target)
            if content is None:
                return f"cat: {target}: No such file or directory\n{session.prompt()}"

            session.record_decoy_file_surfaced(target)

            # Match normal terminal output formatting
            if not content.endswith("\n"):
                content += "\n"
            return f"{content}{session.prompt()}"

        # ANSI clear-screen sequence
        if cmd == "clear":
            return "\x1b[2J\x1b[H" + session.prompt()

        # Bash-like fallback for unsupported commands
        return f"bash: {cmd}: command not found\n{session.prompt()}"

    def _extract_ls_target(self, args: list[str]) -> str | None:
        """Return the first non-flag ls argument, if one was provided."""

        for arg in args:
            if not arg.startswith("-"):
                return arg
        return None

    def _resolve_path(self, session: SessionState, path: str) -> str:
        if not path or path == ".":
            raw_path = session.cwd
        elif path == "~":
            raw_path = session.persona.home_dir
        elif path.startswith("~/"):
            raw_path = f"{session.persona.home_dir}/{path[2:]}"
        elif path.startswith("/"):
            raw_path = path
        else:
            raw_path = f"{session.cwd}/{path}"

        parts = []
        for part in PurePosixPath(raw_path).parts:
            if part in ("", "/", "."):
                continue
            if part == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(part)

        return "/" + "/".join(parts)

    def _ls(self, session: SessionState, path: str) -> str:
        """Return a directory listing from the session's virtual filesystem."""
        
        path = self._resolve_path(session, path)
        listings = self._build_listings(session)

        if path in listings:
            self._record_listed_decoy_files(session, path)
            return listings[path] + "\n"

        return f"ls: cannot access '{path}': No such file or directory\n"

    def _build_listings(self, session: SessionState) -> dict[str, str]:
        directories: dict[str, set[str]] = {
            "/": {"bin", "boot", "dev", "etc", "home", "tmp", "var"},
        }

        for file_path in session.files:
            parts = [part for part in file_path.strip("/").split("/") if part]
            current = "/"

            for index, part in enumerate(parts):
                is_file = index == len(parts) - 1
                directories.setdefault(current, set()).add(part)

                if not is_file:
                    current = (
                        f"/{part}"
                        if current == "/"
                        else f"{current}/{part}"
                    )
                    directories.setdefault(current, set())

        return {
            path: "  ".join(sorted(children))
            for path, children in directories.items()
        }

    def _record_listed_decoy_files(self, session: SessionState, directory: str) -> None:
        """Track direct child files whose names were exposed by a listing."""
        for file_path in session.files:
            if str(PurePosixPath(file_path).parent) == directory:
                session.record_decoy_file_surfaced(file_path)

    def _ps(self, session: SessionState) -> str:
        lines = ["PID TTY          TIME CMD"]
        for index, process in enumerate(session.persona.running_processes, start=101):
            lines.append(f"{index} ?        00:00:00 {process}")
        return "\n".join(lines) + "\n"

    def _visible_ports(self, session: SessionState) -> str:
        lines = ["Proto Local Address           State"]
        for port in session.persona.open_ports_visible:
            lines.append(f"tcp   0.0.0.0:{port:<5}          LISTEN")
        return "\n".join(lines) + "\n"
