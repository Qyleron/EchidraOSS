from __future__ import annotations

import random
import re
import shlex
import struct
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

        The engine logs the whole line once, splits it into commands at `;`,
        `&&` and `||` the way bash does, runs each supported fake command, and
        falls back to a bash-like error. When a command ends the session, the
        output so far is followed by CLOSE_SIGNAL instead of a prompt.
        """
        command = raw_input.strip()

        # Empty input returns a fresh prompt without logging a command
        if not command:
            return session.prompt()

        # Preserve the raw command for later analysis
        session.log_command(command)

        segments, bad_token = _split_command_list(command)
        if bad_token is not None:
            return f"bash: syntax error near unexpected token `{bad_token}'\n{session.prompt()}"

        output = []
        succeeded = True
        for operator, segment in segments:
            # `a && b` runs b only if a worked; `a || b` only if it failed
            if (operator == "&&" and not succeeded) or (operator == "||" and succeeded):
                continue
            result = self._run(segment, session)
            if result is None:
                return "".join(output) + CLOSE_SIGNAL
            text, succeeded = result
            output.append(text)
        return "".join(output) + session.prompt()

    def _run(self, command: str, session: SessionState) -> tuple[str, bool] | None:
        """Output and success of one simple command; None means close the session."""
        # Parse shell-style quoting and spacing
        try:
            tokens = shlex.split(command)
        except ValueError:
            # Unbalanced quotes should look like a shell syntax error, not a crash
            return "bash: syntax error near unexpected token\n", False

        if not tokens:
            return "", True

        cmd = tokens[0]
        args = tokens[1:]

        # A program run by its full path ("/bin/echo", "/usr/bin/uname") is
        # the same command; a path to nothing installed fails like bash.
        if "/" in cmd:
            path = self._resolve_path(session, cmd)
            if path not in self._system_programs(session):
                return f"bash: {cmd}: No such file or directory\n", False
            cmd = PurePosixPath(path).name

        # On a BusyBox device every command is an applet of one program.
        if cmd == "busybox" and args and _is_busybox(session):
            cmd, args = args[0], args[1:]
            if cmd not in _BUSYBOX_APPLETS:
                return f"{cmd}: applet not found\n", False

        # --- COMMAND DISPATCHER ---

        # Session termination
        if cmd in ("exit", "quit", "logout"):
            return None

        # bash's own `help` builtin. Never list what this shell supports --
        # a menu of "available commands" is an instant honeypot tell.
        if cmd == "help":
            return _BASH_HELP, True

        # Identity simulation
        if cmd == "whoami":
            return f"{session.persona.username}\n", True

        # Directory simulation using the session's current fake directory
        if cmd == "pwd":
            return f"{session.cwd}\n", True

        # Change the session's fake working directory -- resolved and
        # validated against the same virtual filesystem `ls` already uses,
        # so `cd` only succeeds into a directory that actually shows up in a
        # listing (a bare unimplemented `cd` would otherwise be an easy
        # honeypot tell: real bash never says "command not found" for its
        # own builtin, even on a bad path).
        if cmd == "cd":
            if len(args) > 1:
                return "bash: cd: too many arguments\n", False
            target = self._resolve_path(session, args[0] if args else "~")
            if target in self._build_listings(session):
                session.cwd = target
                return "", True
            # bash echoes the operand as typed, not the resolved path
            shown = args[0] if args else "~"
            if target in session.files or target in self._system_programs(session):
                return f"bash: cd: {shown}: Not a directory\n", False
            return f"bash: cd: {shown}: No such file or directory\n", False

        # Must agree with whoami and the prompt's "#"/"$"
        if cmd == "id":
            return f"{self._id(session)}\n", True

        if cmd == "uname":
            text = self._uname(session, args)
            return text, not text.startswith("uname: ")

        # Payload download attempts: never fetch anything. Fail the way a
        # host without outbound DNS does; the URL is already in the command
        # log as evidence.
        if cmd == "wget":
            return self._wget(args), False

        if cmd == "curl":
            return self._curl(args), False

        # Bots confirm a guessed login works with `echo OK` or
        # `echo -e "\x6F\x6B"` before doing anything else; "command not
        # found" here ends the session before the real payload is sent.
        if cmd == "echo":
            return _echo(args), True

        if cmd == "hostname":
            return f"{session.persona.hostname}\n", True

        if cmd == "ps":
            return self._ps(session), True

        if cmd in ("netstat", "ss"):
            return self._visible_ports(session), True

        # Directory listing from the virtual filesystem
        if cmd == "ls":
            # Use the current directory when no explicit target is provided
            target = self._extract_ls_target(args)
            text = self._ls(session, target or session.cwd, shown=target)
            return text, not text.startswith("ls: ")

        # File reads are served only from persona-backed fake files
        if cmd == "cat":
            if not args:
                return "cat: missing file operand\n", False

            target = self._resolve_path(session, args[0])
            # Look up normalized paths in the session's virtual filesystem
            content = session.files.get(target)
            if content is None:
                # A loader prints a program to read its header and learn
                # the CPU type, then downloads the build for that CPU.
                if target in self._system_programs(session):
                    return _elf_header(session.persona.uname_output), True
                if target in self._build_listings(session):
                    return f"cat: {args[0]}: Is a directory\n", False
                return f"cat: {args[0]}: No such file or directory\n", False

            session.record_decoy_file_surfaced(target)

            # Match normal terminal output formatting
            if not content.endswith("\n"):
                content += "\n"
            return content, True

        # ANSI clear-screen sequence
        if cmd == "clear":
            return "\x1b[2J\x1b[H", True

        # Bash-like fallback for unsupported commands
        return f"bash: {cmd}: command not found\n", False

    def _system_programs(self, session: SessionState) -> set[str]:
        """Full paths of the programs installed in /bin and /usr/bin."""
        names = _BUSYBOX_PROGRAMS if _is_busybox(session) else _SYSTEM_PROGRAMS
        return {f"{directory}/{name}" for directory in ("/bin", "/usr/bin") for name in names}

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
        programs = _BUSYBOX_PROGRAMS if _is_busybox(session) else _SYSTEM_PROGRAMS
        directories: dict[str, set[str]] = {
            "/": {"bin", "boot", "dev", "etc", "home", "tmp", "usr", "var"},
            "/bin": set(programs),
            "/usr": {"bin"},
            "/usr/bin": set(programs),
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


CLOSE_SIGNAL = "__CLOSE__"


def _split_command_list(line: str) -> tuple[list[tuple[str, str]], str | None]:
    """Split a line at `;`, `&&` and `||` outside quotes.

    Returns (operator before each command, command text) pairs, or the
    token bash would report when a separator has no command before it.
    Pipes and redirects stay inside a command.
    """
    segments: list[tuple[str, str]] = []
    current: list[str] = []
    operator = ""
    quote = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            current.append(char)
            if char == "\\" and quote == '"' and index + 1 < len(line):
                current.append(line[index + 1])
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in "'\"":
            quote = char
        elif char == "\\" and index + 1 < len(line):
            current.append(line[index:index + 2])
            index += 2
            continue

        separator = line[index:index + 2] if line.startswith(("&&", "||", ";;"), index) else None
        if separator is None and char == ";":
            separator = ";"
        if separator is None:
            current.append(char)
            index += 1
            continue

        text = "".join(current).strip()
        if not text or separator == ";;":
            return [], separator
        segments.append((operator, text))
        operator = separator
        current = []
        index += len(separator)

    text = "".join(current).strip()
    if text:
        segments.append((operator, text))
    return segments, None


def _is_busybox(session: SessionState) -> bool:
    return "BusyBox" in session.persona.os_banner


def _elf_header(uname_output: str) -> str:
    """The start of a program file built for the persona's CPU.

    Byte 4 says 32 or 64 bit, byte 5 the byte order, bytes 18-19 the CPU --
    what a loader reads to pick its download. Every value is below 0x80, so
    the bytes reach the client unchanged through the UTF-8 channel; aarch64
    (0xB7) is the one CPU id that can't.
    """
    machine = next((part for part in uname_output.split() if part in _ELF_CPUS), "x86_64")
    bits, order, cpu_id, flags = _ELF_CPUS[machine]
    ident = bytes([0x7F, 0x45, 0x4C, 0x46, 2 if bits == 64 else 1, 1 if order == "<" else 2, 1]) + bytes(9)
    if bits == 64:
        rest = struct.pack(
            f"{order}HHIQQQIHHHHHH", 3, cpu_id, 1, 0x1310, 0x40, 0x7638, flags,
            0x40, 0x38, 13, 0x40, 31, 30,
        )
    else:
        rest = struct.pack(
            f"{order}HHIIIIIHHHHHH", 2, cpu_id, 1, 0x00401350, 0x34, 0x7A20, flags,
            0x34, 0x20, 10, 0x28, 29, 28,
        )
    return (ident + rest + bytes(64)).decode("latin-1")


# uname machine name -> (bits, struct byte order, ELF e_machine, e_flags)
_ELF_CPUS = {
    "x86_64": (64, "<", 0x3E, 0),
    "aarch64": (64, "<", 0xB7, 0),
    "i686": (32, "<", 0x03, 0),
    "armv7l": (32, "<", 0x28, 0x05000400),
    "mips": (32, ">", 0x08, 0x70001007),
    "mipsel": (32, "<", 0x08, 0x70001007),
}

# What /bin and /usr/bin list: the programs this shell answers, plus the
# shells every system has.
_SYSTEM_PROGRAMS = (
    "bash", "cat", "clear", "curl", "echo", "hostname", "id", "ls",
    "netstat", "ps", "pwd", "sh", "ss", "uname", "wget", "whoami",
)
_BUSYBOX_APPLETS = (
    "cat", "clear", "echo", "hostname", "id", "ls", "netstat", "ps", "pwd",
    "sh", "uname", "wget", "whoami",
)
_BUSYBOX_PROGRAMS = ("busybox", *_BUSYBOX_APPLETS)


def _echo(args: list[str]) -> str:
    """Output of bash's `echo` builtin (xpg_echo off) for already-split words."""
    newline = True
    escapes = False
    index = 0
    # Only leading words made entirely of n/e/E flags are options; bash
    # prints anything else ("-x", "--", "-ne5") as text.
    while index < len(args) and _ECHO_OPTIONS.fullmatch(args[index]):
        for flag in args[index][1:]:
            if flag == "n":
                newline = False
            else:
                escapes = flag == "e"
        index += 1

    words = []
    rest = args[index:]
    skip_next = False
    for word in rest:
        if skip_next:
            skip_next = False
            continue
        # Output sent to a file or another program shows nothing on screen.
        if word == "|" or _STDOUT_REDIRECT.match(word):
            return ""
        # A stderr redirect doesn't change what echo prints.
        if word.startswith("2>"):
            skip_next = word in ("2>", "2>>")
            continue
        words.append(word)

    text = " ".join(words)
    if escapes:
        text, stopped = _expand_echo_escapes(text)
        if stopped:
            return text
    return text + ("\n" if newline else "")


def _expand_echo_escapes(text: str) -> tuple[str, bool]:
    """Apply `echo -e` backslash escapes. True means `\\c` cut the output short."""
    out = []
    index = 0
    while index < len(text):
        char = text[index]
        if char != "\\" or index + 1 >= len(text):
            out.append(char)
            index += 1
            continue

        code = text[index + 1]
        if code in _ECHO_SIMPLE_ESCAPES:
            out.append(_ECHO_SIMPLE_ESCAPES[code])
            index += 2
        elif code == "c":
            return "".join(out), True
        elif code == "0":
            digits = _leading(text[index + 2:], "01234567", 3)
            out.append(chr(int(digits or "0", 8) & 0xFF))
            index += 2 + len(digits)
        elif code in _ECHO_HEX_WIDTH:
            digits = _leading(text[index + 2:], "0123456789abcdefABCDEF", _ECHO_HEX_WIDTH[code])
            value = int(digits, 16) if digits else None
            if value is None or value > 0x10FFFF or 0xD800 <= value <= 0xDFFF:
                # bash prints "\x" as typed when no valid digits follow
                out.append("\\" + code + digits)
            else:
                out.append(chr(value))
            index += 2 + len(digits)
        else:
            out.append("\\" + code)
            index += 2
    return "".join(out), False


def _leading(text: str, allowed: str, limit: int) -> str:
    count = 0
    while count < limit and count < len(text) and text[count] in allowed:
        count += 1
    return text[:count]


_ECHO_OPTIONS = re.compile(r"-[neE]+")
_STDOUT_REDIRECT = re.compile(r"(?:1|&)?>")
_ECHO_SIMPLE_ESCAPES = {
    "\\": "\\", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b",
    "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v",
}
_ECHO_HEX_WIDTH = {"x": 2, "u": 4, "U": 8}

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
