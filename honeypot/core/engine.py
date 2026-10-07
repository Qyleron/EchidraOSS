from __future__ import annotations

import random
import shlex
import time
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from honeypot.core.session import SessionState


class InteractionEngine:
    """
    Fake shell engine for the honeypot terminal simulation.

    Parses visitor input, records commands, and returns controlled Linux-like
    responses without executing host commands or reading host files.
    """

    def build_banner(self, session: SessionState) -> str:
        """Return the initial fake login banner and prompt for a session."""

        # A fixed date or "from unknown" is identical on every connection and
        # every install -- trivially fingerprintable. Real sshd prints the
        # previous login's time and source address.
        last_login = time.strftime(
            "%a %b %e %H:%M:%S %Y",
            time.localtime(session.start_time - random.randint(3_600, 6 * 86_400)),
        )
        source = f"10.0.{random.randint(0, 3)}.{random.randint(2, 250)}"
        return (
            f"{session.persona.os_banner}\n"
            f"Last login: {last_login} from {source}\n"
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
        

        # bash's own `help` builtin. Never list what this shell supports --
        # a menu of "available commands" is an instant honeypot tell.
        if cmd == "help":
            return f"{_BASH_HELP}{session.prompt()}"


        # Identity simulation
        if cmd == "whoami":
            return f"{session.persona.username}\n{session.prompt()}"

        # Directory simulation using the session's current fake directory
        if cmd == "pwd":
            return f"{session.cwd}\n{session.prompt()}"

        # Change the session's fake working directory -- resolved and
        # validated against the same virtual filesystem `ls` already uses,
        # so `cd` only succeeds into a directory that actually shows up in a
        # listing (a bare unimplemented `cd` would otherwise be an easy
        # honeypot tell: real bash never says "command not found" for its
        # own builtin, even on a bad path).
        if cmd == "cd":
            if len(args) > 1:
                return f"bash: cd: too many arguments\n{session.prompt()}"
            target = self._resolve_path(session, args[0] if args else "~")
            if target in self._build_listings(session):
                session.cwd = target
                return session.prompt()
            # bash echoes the operand as typed, not the resolved path
            shown = args[0] if args else "~"
            if target in session.files:
                return f"bash: cd: {shown}: Not a directory\n{session.prompt()}"
            return f"bash: cd: {shown}: No such file or directory\n{session.prompt()}"

        # Must agree with whoami and the prompt's "#"/"$"
        if cmd == "id":
            return f"{self._id(session)}\n{session.prompt()}"

        if cmd == "uname":
            return f"{self._uname(session, args)}{session.prompt()}"

        # Payload download attempts: never fetch anything. Fail the way a
        # host without outbound DNS does; the URL is already in the command
        # log as evidence.
        if cmd == "wget":
            return f"{self._wget(args)}{session.prompt()}"

        if cmd == "curl":
            return f"{self._curl(args)}{session.prompt()}"

        if cmd == "hostname":
            return f"{session.persona.hostname}\n{session.prompt()}"

        if cmd == "ps":
            return f"{self._ps(session)}{session.prompt()}"

        if cmd in ("netstat", "ss"):
            return f"{self._visible_ports(session)}{session.prompt()}"

        # Directory listing from the virtual filesystem
        if cmd == "ls":
            # Use the current directory when no explicit target is provided
            target = self._extract_ls_target(args)
            return f"{self._ls(session, target or session.cwd, shown=target)}{session.prompt()}"

        # File reads are served only from persona-backed fake files
        if cmd == "cat":
            if not args:
                return f"cat: missing file operand\n{session.prompt()}"

            target = self._resolve_path(session, args[0])
            # Look up normalized paths in the session's virtual filesystem
            content = session.files.get(target)
            if content is None:
                if target in self._build_listings(session):
                    return f"cat: {args[0]}: Is a directory\n{session.prompt()}"
                return f"cat: {args[0]}: No such file or directory\n{session.prompt()}"

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

    def _ls(self, session: SessionState, path: str, shown: str | None = None) -> str:
        """Return a directory listing from the session's virtual filesystem."""

        resolved = self._resolve_path(session, path)
        listings = self._build_listings(session)

        if resolved in listings:
            self._record_listed_decoy_files(session, resolved)
            return listings[resolved] + "\n"

        if resolved in session.files:
            # ls on a file prints the operand back, like real ls
            return f"{shown or path}\n"

        return f"ls: cannot access '{shown or path}': No such file or directory\n"

    def _id(self, session: SessionState) -> str:
        username = session.persona.username
        if username == "root":
            return "uid=0(root) gid=0(root) groups=0(root)"
        return (
            f"uid=1000({username}) gid=1000({username}) "
            f"groups=1000({username}),4(adm),27(sudo)"
        )

    def _uname(self, session: SessionState, args: list[str]) -> str:
        """Answer uname's common flags from the persona's `uname -a` line."""
        parts = session.persona.uname_output.split()
        sysname = parts[0] if parts else "Linux"
        release = parts[2] if len(parts) > 2 else ""
        machine = next((p for p in parts if p in _MACHINE_NAMES), "x86_64")
        fields = {
            "s": sysname,
            "n": session.persona.hostname,
            "r": release,
            "m": machine,
            "p": machine,
            "i": machine,
            "o": "GNU/Linux",
        }
        long_flags = {
            "--kernel-name": "s", "--nodename": "n", "--kernel-release": "r",
            "--machine": "m", "--processor": "p", "--hardware-platform": "i",
            "--operating-system": "o",
        }

        wanted: set[str] = set()
        for arg in args:
            if arg in ("-a", "--all"):
                return f"{session.persona.uname_output}\n"
            if arg in long_flags:
                wanted.add(long_flags[arg])
                continue
            if arg.startswith("-") and not arg.startswith("--") and len(arg) > 1:
                for flag in arg[1:]:
                    if flag == "a":
                        return f"{session.persona.uname_output}\n"
                    if flag not in fields and flag != "v":
                        return (
                            f"uname: invalid option -- '{flag}'\n"
                            "Try 'uname --help' for more information.\n"
                        )
                    wanted.add(flag)
                continue
            if arg.startswith("--"):
                return (
                    f"uname: unrecognized option '{arg}'\n"
                    "Try 'uname --help' for more information.\n"
                )
            return (
                f"uname: extra operand '{arg}'\n"
                "Try 'uname --help' for more information.\n"
            )

        if not wanted:
            wanted = {"s"}
        if "v" in wanted:
            version = " ".join(parts[3:parts.index(machine)]) if machine in parts else ""
            fields["v"] = version
        order = "snrvmpio"
        return " ".join(fields[f] for f in order if f in wanted and fields.get(f)) + "\n"

    def _wget(self, args: list[str]) -> str:
        url = next((a for a in args if not a.startswith("-")), None)
        if url is None:
            return (
                "wget: missing URL\n"
                "Usage: wget [OPTION]... [URL]...\n\n"
                "Try `wget --help' for more options.\n"
            )
        host = _url_host(url)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        shown = url if "://" in url else f"http://{url}/"
        return (
            f"--{stamp}--  {shown}\n"
            f"Resolving {host} ({host})... failed: Temporary failure in name resolution.\n"
            f"wget: unable to resolve host address '{host}'\n"
        )

    def _curl(self, args: list[str]) -> str:
        url = next((a for a in args if not a.startswith("-")), None)
        if url is None:
            return "curl: try 'curl --help' or 'curl --manual' for more information\n"
        return f"curl: (6) Could not resolve host: {_url_host(url)}\n"

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


def _url_host(url: str) -> str:
    """Host part of a URL as wget/curl would report it."""
    host = urlsplit(url if "://" in url else f"http://{url}").hostname
    return host or url


_MACHINE_NAMES = ("x86_64", "aarch64", "armv7l", "i686", "mips", "mipsel")

# First lines of bash 5.1's real `help` output (Ubuntu 22.04).
_BASH_HELP = """GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)
These shell commands are defined internally.  Type `help' to see this list.
Type `help name' to find out more about the function `name'.
Use `info bash' to find out more about the shell in general.
Use `man -k' or `info' to find out more about commands not in this list.

A star (*) next to a name means that the command is disabled.

 job_spec [&]                            history [-c] [-d offset] [n] or hist>
 (( expression ))                        if COMMANDS; then COMMANDS; [ elif C>
 . filename [arguments]                  jobs [-lnprs] [jobspec ...] or jobs >
 :                                       kill [-s sigspec | -n signum | -sigs>
 [ arg... ]                              let arg [arg ...]
 [[ expression ]]                        local [option] name[=value] ...
 alias [-p] [name[=value] ... ]          logout [n]
 bg [job_spec ...]                       mapfile [-d delim] [-n count] [-O or>
 bind [-lpsvPSVX] [-m keymap] [-f file>  popd [-n] [+N | -N]
 break [n]                               printf [-v var] format [arguments]
 builtin [shell-builtin [arg ...]]       pushd [-n] [+N | -N | dir]
 caller [expr]                           pwd [-LP]
 case WORD in [PATTERN [| PATTERN]...)>  read [-ers] [-a array] [-d delim] [->
 cd [-L|[-P [-e]] [-@]] [dir]            readarray [-d delim] [-n count] [-O >
 command [-pVv] command [arg ...]        readonly [-aAf] [name[=value] ...] o>
 compgen [-abcdefgjksuv] [-o option] [>  return [n]
 complete [-abcdefgjksuv] [-pr] [-DEI]>  select NAME [in WORDS ... ;] do COMM>
 continue [n]                            set [-abefhkmnptuvxBCHP] [-o option->
 declare [-aAfFgiIlnrtux] [-p] [name[=>  shift [n]
 dirs [-clpv] [+N] [-N]                  shopt [-pqsu] [-o] [optname ...]
 echo [-neE] [arg ...]                   source filename [arguments]
 enable [-a] [-dnps] [-f filename] [na>  suspend [-f]
 eval [arg ...]                          test [expr]
 exec [-cl] [-a name] [command [argume>  time [-p] pipeline
 exit [n]                                times
 export [-fn] [name[=value] ...] or ex>  trap [-lp] [[arg] signal_spec ...]
 false                                   true
 fc [-e ename] [-lnr] [first] [last] o>  type [-afptP] name [name ...]
 fg [job_spec]                           typeset [-aAfFgilnrtux] [-p] name[=v>
 for NAME [in WORDS ... ] ; do COMMAND>  ulimit [-SHabcdefiklmnpqrstuvxPT] [l>
 function name { COMMANDS ; } or name >  umask [-p] [-S] [mode]
 getopts optstring name [arg ...]        unalias [-a] name [name ...]
 hash [-lr] [-p pathname] [name ...]     unset [-f] [-v] [-n] [name ...]
 help [-dms] [pattern ...]               wait [-fn] [-p var] [id ...]
"""
