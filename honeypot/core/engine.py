from __future__ import annotations

import base64
import binascii
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
        `&&` and `||` and into pipelines at `|` the way a shell does, runs
        each supported fake command, and falls back to the shell's own error.
        Output sent to a file with `>` or `>>` is kept in the session's
        files, never written to the host.
        When a command ends the session, the output so far is followed by
        CLOSE_SIGNAL instead of a prompt.
        """
        command = raw_input.strip()

        # Empty input returns a fresh prompt without logging a command
        if not command:
            return session.prompt()

        # Preserve the raw command for later analysis
        session.log_command(command)

        output, _, closed = self._execute(command, session, depth=0)
        if closed:
            return output + CLOSE_SIGNAL
        return output + session.prompt()

    def _execute(self, line: str, session: SessionState, depth: int) -> tuple[str, bool, bool]:
        """Run one line of shell input: (output, last command worked, exit was run)."""
        segments, bad_token = _split_unquoted(line, _LIST_SEPARATORS)
        pipelines = []
        for operator, segment in segments:
            stages, pipe_error = _split_unquoted(segment, ("|",))
            bad_token = bad_token or pipe_error
            pipelines.append((operator, [stage for _, stage in stages]))
        # The shell checks the whole line before running any of it
        if bad_token is not None:
            return self._syntax_error(session, bad_token), False, False

        output = []
        succeeded = True
        for operator, stages in pipelines:
            # `a && b` runs b only if a worked; `a || b` only if it failed
            if (operator == "&&" and not succeeded) or (operator == "||" and succeeded):
                continue
            text, succeeded, closed = self._run_pipeline(stages, session, depth)
            output.append(text)
            if closed:
                return "".join(output), succeeded, True
        return "".join(output), succeeded, False

    def _run_pipeline(
        self, stages: list[str], session: SessionState, depth: int,
    ) -> tuple[str, bool, bool]:
        """Run `a | b | c`, feeding each command's output to the next."""
        if len(stages) == 1:
            result = self._run(stages[0], session, None, depth)
            if result is None:
                return "", True, True
            return result[0], result[1], False

        screen = []
        piped: str | None = None
        succeeded = True
        for position, stage in enumerate(stages):
            # Each part of a pipeline runs in a subshell, so `exit` there
            # ends only that part, not the login.
            text, succeeded = self._run(stage, session, piped, depth) or ("", True)
            # A failed command's text is its error message, which goes to
            # the screen, not down the pipe.
            if position == len(stages) - 1 or not succeeded:
                screen.append(text)
                piped = ""
            else:
                piped = text
        return "".join(screen), succeeded, False

    def _run(
        self, command: str, session: SessionState, stdin: str | None, depth: int,
    ) -> tuple[str, bool] | None:
        """Output and success of one simple command; None means close the session.

        `stdin` is the previous command's output inside a pipeline, None
        when nothing is piped in. Redirects are handled here: the files are
        opened first, as the shell does, so `>.d` alone makes an empty file
        and a redirect into a missing directory stops the command.
        """
        split = _split_redirects(command)
        if split is None:
            if _is_busybox(session):
                return f"{_shell_name(session)}: syntax error: unexpected newline\n", False
            return "bash: syntax error near unexpected token `newline'\n", False
        command, redirects = split
        if not redirects:
            return self._run_command(command, session, stdin, depth)

        # Where stdout ("1") and stderr ("2") go: None is the screen
        targets: dict[str, str | None] = {"1": None, "2": None}
        for fd, append, target in redirects:
            if target.startswith("&"):
                # `2>&1` sends stderr wherever stdout goes at this point
                if fd in targets and target[1:] in targets:
                    targets[fd] = targets[target[1:]]
                continue
            path = self._resolve_path(session, target)
            if path != "/dev/null":
                error = self._open_for_writing(session, target, path, append)
                if error:
                    return error, False
            for stream in (("1", "2") if fd == "&" else (fd,)):
                if stream in targets:
                    targets[stream] = path

        result = self._run_command(command, session, stdin, depth)
        if result is None:
            return None
        text, succeeded = result
        # A failed command's text is its error message
        streams = {"1": text if succeeded else "", "2": "" if succeeded else text}
        screen = []
        for stream, data in streams.items():
            path = targets[stream]
            if path is None:
                screen.append(data)
            elif data and path != "/dev/null" and not self._store(session, path, data, append=True):
                name = command.split()[0] if command.split() else ""
                prefix = f"{_shell_name(session)}: " if name == "echo" else ""
                screen.append(f"{prefix}{name}: write error: No space left on device\n")
                succeeded = False
        return "".join(screen), succeeded

    def _run_command(
        self, command: str, session: SessionState, stdin: str | None, depth: int,
    ) -> tuple[str, bool] | None:
        """Output and success of one simple command with its redirects taken out."""
        shell = _shell_name(session)
        # Parse shell-style quoting and spacing
        try:
            tokens = shlex.split(command)
        except ValueError:
            # Unbalanced quotes should look like a shell syntax error, not a crash
            if _is_busybox(session):
                return f"{shell}: syntax error: unterminated quoted string\n", False
            return "bash: syntax error near unexpected token\n", False

        if not tokens:
            return "", True

        cmd = tokens[0]
        args = tokens[1:]

        # A program run by its full path ("/bin/echo", "/usr/bin/uname") is
        # the same command; any other path is a file the visitor runs.
        if "/" in cmd:
            path = self._resolve_path(session, cmd)
            if path not in self._system_programs(session) or path in session.files:
                return self._run_file(session, cmd, path, depth)
            cmd = PurePosixPath(path).name

        # On a BusyBox device every command is an applet of one program.
        if cmd == "busybox" and _is_busybox(session):
            if not args:
                version = session.persona.os_banner.replace(
                    "built-in shell (ash)", "multi-call binary."
                )
                return f"{version}\n\nUsage: busybox [function [arguments]...]\n", True
            cmd, args = args[0], args[1:]
            if cmd not in _BUSYBOX_APPLETS:
                return f"{cmd}: applet not found\n", False

        # A BusyBox device only has its applets and the shell's builtins
        # (no curl, no bash, no ss).
        if (
            _is_busybox(session)
            and cmd not in _BUSYBOX_APPLETS
            and cmd not in _ASH_BUILTINS
        ):
            return f"{shell}: {cmd}: not found\n", False

        # --- COMMAND DISPATCHER ---

        # Session termination
        if cmd in ("exit", "quit", "logout"):
            return None

        # bash's own `help` builtin. Never list what this shell supports --
        # a menu of "available commands" is an instant honeypot tell.
        if cmd == "help":
            return (_ASH_HELP if _is_busybox(session) else _BASH_HELP), True

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
                return f"{shell}: cd: too many arguments\n", False
            target = self._resolve_path(session, args[0] if args else "~")
            if target in self._build_listings(session):
                session.cwd = target
                return "", True
            # The shell echoes the operand as typed, not the resolved path
            shown = args[0] if args else "~"
            if target in session.files or target in self._system_programs(session):
                reason = "Not a directory"
            else:
                reason = "No such file or directory"
            if _is_busybox(session):
                return f"{shell}: cd: can't cd to {shown}: {reason}\n", False
            return f"bash: cd: {shown}: {reason}\n", False

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
            return self._wget(session, args), False

        if cmd == "curl":
            return self._curl(args), False

        # Bots confirm a guessed login works with `echo OK` or
        # `echo -e "\x6F\x6B"` before doing anything else; "command not
        # found" here ends the session before the real payload is sent.
        if cmd == "echo":
            return _echo(args), True

        # Text filters, mostly seen at the end of a pipeline
        # (`cat /proc/cpuinfo | grep name | head -n 1`, `... | wc -l`).
        if cmd == "grep":
            return self._grep(session, args, stdin)

        if cmd in ("head", "tail"):
            return self._head_tail(session, cmd, args, stdin)

        if cmd == "wc":
            return self._wc(session, args, stdin)

        if cmd == "base64":
            return self._base64(session, args, stdin)

        # `echo <base64> | base64 -d | sh` and `sh -c "..."`: run the text
        # through this same fake shell. Nothing reaches the host.
        if cmd in ("sh", "bash"):
            return self._subshell(session, cmd, args, stdin, depth)

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
            show_all = any(
                arg in ("--all", "--almost-all")
                or (arg.startswith("-") and not arg.startswith("--") and ("a" in arg or "A" in arg))
                for arg in args
            )
            text = self._ls(session, target or session.cwd, shown=target, show_all=show_all)
            return text, not text.startswith("ls: ")

        # Download scripts run `chmod 777 x; ./x; rm -rf x`. A shell that
        # says "chmod: not found" is no real server; these change only the
        # session's own files.
        if cmd == "chmod":
            return self._chmod(session, args)

        if cmd == "mkdir":
            return self._mkdir(session, args)

        if cmd == "touch":
            return self._touch(session, args)

        if cmd == "rm":
            return self._rm(session, args)

        if cmd == "cp":
            return self._cp(session, args)

        # File reads are served only from persona-backed fake files
        if cmd == "cat":
            files = [arg for arg in args if arg == "-" or not arg.startswith("-")]
            if not files:
                if stdin is not None:
                    return stdin, True
                return "cat: missing file operand\n", False
            return self._read_files(session, "cat", files, stdin)

        # ANSI clear-screen sequence
        if cmd == "clear":
            return "\x1b[2J\x1b[H", True

        # The shell's own fallback for unsupported commands
        if _is_busybox(session):
            return f"{shell}: {cmd}: not found\n", False
        return f"bash: {cmd}: command not found\n", False

    def _system_programs(self, session: SessionState) -> set[str]:
        """Full paths of the programs installed in /bin and /usr/bin."""
        names = _BUSYBOX_PROGRAMS if _is_busybox(session) else _SYSTEM_PROGRAMS
        return {f"{directory}/{name}" for directory in ("/bin", "/usr/bin") for name in names}

    def _syntax_error(self, session: SessionState, token: str) -> str:
        if _is_busybox(session):
            return f'{_shell_name(session)}: syntax error: unexpected "{token}"\n'
        return f"bash: syntax error near unexpected token `{token}'\n"

    def _read_one(self, session: SessionState, cmd: str, operand: str) -> tuple[str | None, str]:
        """Contents of one file operand, or None and the program's error."""
        target = self._resolve_path(session, operand)
        content = session.files.get(target)
        if content is not None:
            if target not in session.written_files:
                session.record_decoy_file_surfaced(target)
            # Match normal terminal output formatting
            return (content if content.endswith("\n") else content + "\n"), ""
        # A loader prints a program to read its header and learn the CPU
        # type, then downloads the build for that CPU.
        if target in self._system_programs(session):
            return _elf_header(session.persona.uname_output), ""
        busybox = _is_busybox(session)
        if target in self._build_listings(session):
            if busybox:
                return None, f"{cmd}: read error: Is a directory\n"
            return None, f"{cmd}: {operand}: Is a directory\n"
        if busybox and cmd in ("cat", "head", "tail"):
            return None, f"{cmd}: can't open '{operand}': No such file or directory\n"
        return None, f"{cmd}: {operand}: No such file or directory\n"

    def _read_files(
        self, session: SessionState, cmd: str, operands: list[str], stdin: str | None,
    ) -> tuple[str, bool]:
        """Concatenated contents of the operands ("-" is the piped input)."""
        parts = []
        succeeded = True
        for operand in operands:
            if operand == "-":
                parts.append(stdin or "")
                continue
            content, error = self._read_one(session, cmd, operand)
            if content is None:
                parts.append(error)
                succeeded = False
            else:
                parts.append(content)
        return "".join(parts), succeeded

    def _input_for(
        self, session: SessionState, cmd: str, operands: list[str], stdin: str | None,
    ) -> tuple[str, str]:
        """(text a filter reads, error messages) from its files or the pipe."""
        if not operands:
            return stdin or "", ""
        text = []
        errors = []
        for operand in operands:
            if operand == "-":
                text.append(stdin or "")
                continue
            content, error = self._read_one(session, cmd, operand)
            if content is None:
                errors.append(error)
            else:
                text.append(content)
        return "".join(text), "".join(errors)

    def _grep(self, session: SessionState, args: list[str], stdin: str | None) -> tuple[str, bool]:
        flags: set[str] = set()
        pattern = None
        files = []
        for arg in args:
            if pattern is None and arg.startswith("--"):
                continue
            if pattern is None and arg.startswith("-") and len(arg) > 1:
                flags.update(arg[1:])
                continue
            if pattern is None:
                pattern = arg
            else:
                files.append(arg)
        if pattern is None:
            return (
                "Usage: grep [OPTION]... PATTERNS [FILE]...\n"
                "Try 'grep --help' for more information.\n"
            ), False

        text, errors = self._input_for(session, "grep", files, stdin)
        if "F" in flags:
            expression = re.escape(pattern)
        elif "E" in flags:
            expression = pattern
        else:
            expression = _basic_regex(pattern)
        try:
            matcher = re.compile(expression, re.IGNORECASE if "i" in flags else 0)
        except re.error:
            matcher = re.compile(re.escape(pattern), re.IGNORECASE if "i" in flags else 0)

        invert = "v" in flags
        matched = [line for line in text.splitlines() if bool(matcher.search(line)) != invert]
        if "q" in flags:
            output = ""
        elif "c" in flags:
            output = f"{len(matched)}\n"
        else:
            output = "".join(f"{line}\n" for line in matched)
        return output + errors, bool(matched) and not errors

    def _head_tail(
        self, session: SessionState, cmd: str, args: list[str], stdin: str | None,
    ) -> tuple[str, bool]:
        mode = "n"
        value = "10"
        files = []
        index = 0
        while index < len(args):
            arg = args[index]
            if arg in ("-n", "-c") and index + 1 < len(args):
                mode, value = arg[1], args[index + 1]
                index += 2
                continue
            if re.fullmatch(r"-[nc][+-]?\d+", arg):
                mode, value = arg[1], arg[2:]
            elif re.fullmatch(r"-\d+", arg):
                value = arg[1:]
            elif not arg.startswith("-") or arg == "-":
                files.append(arg)
            index += 1

        from_start = cmd == "tail" and value.startswith("+")
        try:
            count = abs(int(value.lstrip("+")))
        except ValueError:
            unit = "lines" if mode == "n" else "bytes"
            return f"{cmd}: invalid number of {unit}: '{value}'\n", False

        text, errors = self._input_for(session, cmd, files, stdin)
        if mode == "c":
            data = text.encode("utf-8", "surrogateescape")
            if cmd == "head":
                chunk = data[:count]
            elif from_start:
                chunk = data[max(count - 1, 0):]
            else:
                chunk = data[-count:] if count else b""
            output = chunk.decode("utf-8", "surrogateescape")
        else:
            lines = text.splitlines(keepends=True)
            if cmd == "head":
                chosen = lines[:count]
            elif from_start:
                chosen = lines[max(count - 1, 0):]
            else:
                chosen = lines[-count:] if count else []
            output = "".join(chosen)
        return output + errors, not errors

    def _wc(self, session: SessionState, args: list[str], stdin: str | None) -> tuple[str, bool]:
        flags = "".join(arg[1:] for arg in args if arg.startswith("-") and arg != "-")
        files = [arg for arg in args if arg == "-" or not arg.startswith("-")]
        text, errors = self._input_for(session, "wc", files, stdin)
        counts = {
            "l": text.count("\n"),
            "w": len(text.split()),
            "c": len(text.encode("utf-8", "surrogateescape")),
        }
        wanted = [flag for flag in "lwc" if flag in flags] or ["l", "w", "c"]
        if len(wanted) == 1:
            numbers = str(counts[wanted[0]])
        else:
            numbers = " ".join(f"{counts[flag]:>7}" for flag in wanted)
        name = f" {files[0]}" if len(files) == 1 and files[0] != "-" else ""
        return f"{numbers}{name}\n{errors}", not errors

    def _base64(self, session: SessionState, args: list[str], stdin: str | None) -> tuple[str, bool]:
        decode = any(
            arg == "--decode" or (arg.startswith("-") and not arg.startswith("--") and "d" in arg)
            for arg in args
        )
        files = [arg for arg in args if arg == "-" or not arg.startswith("-")]
        text, errors = self._input_for(session, "base64", files, stdin)
        if errors:
            return errors, False
        data = text.encode("utf-8", "surrogateescape")
        if decode:
            compact = b"".join(data.split())
            try:
                decoded = base64.b64decode(compact + b"=" * (-len(compact) % 4), validate=True)
            except (binascii.Error, ValueError):
                return "base64: invalid input\n", False
            return decoded.decode("utf-8", "surrogateescape"), True
        encoded = base64.b64encode(data).decode("ascii")
        lines = [encoded[start:start + 76] for start in range(0, len(encoded), 76)]
        return "".join(f"{line}\n" for line in lines), True

    def _subshell(
        self, session: SessionState, cmd: str, args: list[str], stdin: str | None, depth: int,
    ) -> tuple[str, bool]:
        """`sh -c "..."`, `sh script`, or a script piped into `sh`."""
        if depth >= _MAX_SUBSHELL_DEPTH:
            return "", True
        if args and args[0] == "-c":
            if len(args) < 2:
                return f"{cmd}: -c: option requires an argument\n", False
            output, succeeded, _ = self._execute(args[1], session, depth + 1)
            return output, succeeded
        if args:
            script, error = self._read_one(session, cmd, args[0])
            if script is None:
                return error, False
            if script.startswith("\x7fELF"):
                return f"{cmd}: {args[0]}: cannot execute binary file\n", False
        elif stdin is not None:
            script = stdin
        else:
            # An interactive subshell would just show another prompt
            return "", True
        return self._run_script(session, script, depth)

    def _run_script(self, session: SessionState, script: str, depth: int) -> tuple[str, bool]:
        """Run a script's lines one by one through this same fake shell."""
        output = []
        succeeded = True
        for line in script.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            text, succeeded, closed = self._execute(line, session, depth + 1)
            output.append(text)
            if closed:
                break
        return "".join(output), succeeded

    def _run_file(
        self, session: SessionState, cmd: str, path: str, depth: int,
    ) -> tuple[str, bool]:
        """`./x` or `/tmp/x`: a file from this session, never anything on the host."""
        shell = _shell_name(session)
        busybox = _is_busybox(session)
        content = session.files.get(path)
        if content is not None:
            if path not in session.executable_files:
                return f"{shell}: {cmd}: Permission denied\n", False
            # A program starts and goes on in the background, as bots'
            # programs do, so it prints nothing.
            if content.startswith("\x7fELF"):
                return "", True
            if depth >= _MAX_SUBSHELL_DEPTH:
                return "", True
            return self._run_script(session, content, depth)
        if path in self._build_listings(session):
            if busybox:
                return f"{shell}: {cmd}: Permission denied\n", False
            return f"bash: {cmd}: Is a directory\n", False
        if busybox:
            return f"{shell}: {cmd}: not found\n", False
        return f"bash: {cmd}: No such file or directory\n", False

    def _kind(self, session: SessionState, path: str) -> str | None:
        """"dir", "file", or None when nothing is at the path."""
        if path in self._build_listings(session):
            return "dir"
        if path in session.files or path in self._system_programs(session):
            return "file"
        return None

    def _open_for_writing(
        self, session: SessionState, operand: str, path: str, append: bool,
    ) -> str | None:
        """Create or empty a redirect's file; the shell's error if it can't."""
        parent = self._kind(session, str(PurePosixPath(path).parent))
        if self._kind(session, path) == "dir":
            reason = "Is a directory"
        elif parent == "file":
            reason = "Not a directory"
        elif parent is None:
            reason = "No such file or directory"
        else:
            if self._store(session, path, "", append):
                return None
            reason = "No space left on device"
        if _is_busybox(session):
            if reason == "No such file or directory":
                reason = "nonexistent directory"
            return f"{_shell_name(session)}: can't create {operand}: {reason}\n"
        return f"bash: {operand}: {reason}\n"

    def _store(self, session: SessionState, path: str, text: str, append: bool) -> bool:
        """Write text to a session file; False once the session's files are full."""
        content = (session.files.get(path, "") if append else "") + text
        used = sum(
            len(session.files[written])
            for written in session.written_files
            if written != path and written in session.files
        )
        if used + len(content) > _MAX_WRITTEN_CHARS:
            return False
        session.files[path] = content
        session.written_files.add(path)
        return True

    def _remove(self, session: SessionState, path: str) -> None:
        """Delete a file or a whole directory from the session."""
        inside = "/" if path == "/" else f"{path}/"
        for collection in (session.files, session.dirs, session.written_files, session.executable_files):
            for item in [item for item in collection if item == path or item.startswith(inside)]:
                if isinstance(collection, dict):
                    del collection[item]
                else:
                    collection.discard(item)

    def _chmod(self, session: SessionState, args: list[str]) -> tuple[str, bool]:
        busybox = _is_busybox(session)
        recursive = False
        words = []
        for arg in args:
            # "-x" and "-w" are modes, not options
            if not words and re.fullmatch(r"-[Rcfv]+|--recursive|--changes|--silent|--quiet|--verbose", arg):
                recursive = recursive or "R" in arg or arg == "--recursive"
                continue
            words.append(arg)
        if not words:
            return _missing_operand(session, "chmod", "chmod: missing operand"), False
        mode, operands = words[0], words[1:]
        if not operands:
            return _missing_operand(session, "chmod", f"chmod: missing operand after '{mode}'"), False
        if _chmod_executable(mode, False) is None:
            if busybox:
                return f"chmod: invalid mode '{mode}'\n", False
            return f"chmod: invalid mode: '{mode}'\nTry 'chmod --help' for more information.\n", False

        errors = []
        for operand in operands:
            path = self._resolve_path(session, operand)
            kind = self._kind(session, path)
            if kind is None:
                if busybox:
                    errors.append(f"chmod: {operand}: No such file or directory\n")
                else:
                    errors.append(f"chmod: cannot access '{operand}': No such file or directory\n")
                continue
            inside = "/" if path == "/" else f"{path}/"
            paths = [path] if kind == "file" else []
            if kind == "dir" and recursive:
                paths = [item for item in session.files if item.startswith(inside)]
            for item in paths:
                if _chmod_executable(mode, item in session.executable_files):
                    session.executable_files.add(item)
                else:
                    session.executable_files.discard(item)
        return "".join(errors), not errors

    def _mkdir(self, session: SessionState, args: list[str]) -> tuple[str, bool]:
        busybox = _is_busybox(session)
        flags, operands = _options(args, {"--parents": "p"}, takes_value="m")
        if not operands:
            return _missing_operand(session, "mkdir", "mkdir: missing operand"), False

        errors = []
        for operand in operands:
            path = self._resolve_path(session, operand)
            reason = None
            if "p" in flags:
                current = ""
                for part in path.strip("/").split("/") if path != "/" else []:
                    current = f"{current}/{part}"
                    kind = self._kind(session, current)
                    if kind == "file":
                        reason = "File exists" if current == path else "Not a directory"
                        break
                    if kind is None:
                        session.dirs.add(current)
            else:
                parent = self._kind(session, str(PurePosixPath(path).parent))
                if self._kind(session, path) is not None:
                    reason = "File exists"
                elif parent == "file":
                    reason = "Not a directory"
                elif parent is None:
                    reason = "No such file or directory"
                else:
                    session.dirs.add(path)
            if reason:
                verb = "can't" if busybox else "cannot"
                errors.append(f"mkdir: {verb} create directory '{operand}': {reason}\n")
        return "".join(errors), not errors

    def _touch(self, session: SessionState, args: list[str]) -> tuple[str, bool]:
        busybox = _is_busybox(session)
        flags, operands = _options(args, {"--no-create": "c"}, takes_value="dtr")
        if not operands:
            return _missing_operand(session, "touch", "touch: missing file operand"), False

        errors = []
        for operand in operands:
            path = self._resolve_path(session, operand)
            if self._kind(session, path) is not None or "c" in flags:
                continue
            parent = self._kind(session, str(PurePosixPath(path).parent))
            if parent == "dir":
                if self._store(session, path, "", append=False):
                    continue
                reason = "No space left on device"
            elif parent == "file":
                reason = "Not a directory"
            else:
                reason = "No such file or directory"
            if busybox:
                errors.append(f"touch: {operand}: {reason}\n")
            else:
                errors.append(f"touch: cannot touch '{operand}': {reason}\n")
        return "".join(errors), not errors

    def _rm(self, session: SessionState, args: list[str]) -> tuple[str, bool]:
        busybox = _is_busybox(session)
        flags, operands = _options(args, {"--recursive": "r", "--force": "f"})
        force = "f" in flags
        recursive = "r" in flags or "R" in flags
        if not operands:
            if force:
                return "", True
            return _missing_operand(session, "rm", "rm: missing operand"), False

        errors = []
        for operand in operands:
            path = self._resolve_path(session, operand)
            if path == "/" and recursive and not busybox:
                errors.append(
                    "rm: it is dangerous to operate recursively on '/'\n"
                    "rm: use --no-preserve-root to override this failsafe\n"
                )
                continue
            kind = self._kind(session, path)
            if kind is None:
                if not force:
                    verb = "can't" if busybox else "cannot"
                    errors.append(f"rm: {verb} remove '{operand}': No such file or directory\n")
                continue
            if kind == "dir" and not recursive:
                if busybox:
                    errors.append(f"rm: '{operand}' is a directory\n")
                else:
                    errors.append(f"rm: cannot remove '{operand}': Is a directory\n")
                continue
            self._remove(session, path)
        return "".join(errors), not errors

    def _cp(self, session: SessionState, args: list[str]) -> tuple[str, bool]:
        busybox = _is_busybox(session)
        flags, operands = _options(args, {"--recursive": "r", "--archive": "a"})
        recursive = bool(flags & {"r", "R", "a"})
        if not operands:
            return _missing_operand(session, "cp", "cp: missing file operand"), False
        if len(operands) == 1:
            return _missing_operand(
                session, "cp", f"cp: missing destination file operand after '{operands[0]}'"
            ), False

        *sources, destination = operands
        dest_path = self._resolve_path(session, destination)
        dest_is_dir = self._kind(session, dest_path) == "dir"
        if len(sources) > 1 and not dest_is_dir:
            if busybox:
                return f"cp: '{destination}' is not a directory\n", False
            return f"cp: target '{destination}' is not a directory\n", False

        errors = []
        for source in sources:
            path = self._resolve_path(session, source)
            kind = self._kind(session, path)
            if kind is None:
                verb = "can't" if busybox else "cannot"
                errors.append(f"cp: {verb} stat '{source}': No such file or directory\n")
                continue
            name = PurePosixPath(path).name
            target = (f"{dest_path.rstrip('/')}/{name}") if dest_is_dir else dest_path
            shown = f"{destination.rstrip('/')}/{name}" if dest_is_dir else destination
            if kind == "dir":
                if not recursive:
                    if busybox:
                        errors.append(f"cp: omitting directory '{source}'\n")
                    else:
                        errors.append(f"cp: -r not specified; omitting directory '{source}'\n")
                    continue
                session.dirs.add(target)
                inside = "/" if path == "/" else f"{path}/"
                for item in [item for item in session.dirs if item.startswith(inside)]:
                    session.dirs.add(target + item[len(path):])
                copies = [(item, target + item[len(path):]) for item in session.files if item.startswith(inside)]
            else:
                if self._kind(session, str(PurePosixPath(target).parent)) != "dir":
                    if busybox:
                        errors.append(f"cp: can't create '{shown}': No such file or directory\n")
                    else:
                        errors.append(
                            f"cp: cannot create regular file '{shown}': No such file or directory\n"
                        )
                    continue
                copies = [(path, target)]
            for origin, copy in copies:
                # `cp /bin/busybox .x` gives a bot a runnable file to overwrite
                if origin in session.files:
                    content = session.files[origin]
                else:
                    content = _elf_header(session.persona.uname_output)
                if not self._store(session, copy, content, append=False):
                    errors.append(f"cp: error writing '{shown}': No space left on device\n")
                    break
                if origin in session.executable_files or origin not in session.files:
                    session.executable_files.add(copy)
        return "".join(errors), not errors

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

    def _ls(
        self, session: SessionState, path: str, shown: str | None = None, show_all: bool = False,
    ) -> str:
        """Return a directory listing from the session's virtual filesystem."""

        resolved = self._resolve_path(session, path)
        listings = self._build_listings(session)

        if resolved in listings:
            # Names starting with "." show only with -a
            names = sorted(
                name for name in listings[resolved] if show_all or not name.startswith(".")
            )
            if show_all:
                names = [".", "..", *names]
            self._record_listed_decoy_files(session, resolved, names)
            return "  ".join(names) + "\n" if names else ""

        if resolved in session.files:
            # ls on a file prints the operand back, like real ls
            return f"{shown or path}\n"

        if _is_busybox(session):
            return f"ls: {shown or path}: No such file or directory\n"
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

    def _wget(self, session: SessionState, args: list[str]) -> str:
        url = _first_operand(args, _WGET_VALUE_OPTIONS)
        if url is None:
            return (
                "wget: missing URL\n"
                "Usage: wget [OPTION]... [URL]...\n\n"
                "Try `wget --help' for more options.\n"
            )
        host = _url_host(url)
        if _is_busybox(session):
            return f"wget: bad address '{host}'\n"
        # -q (often inside "-qO-") turns off all of wget's messages
        if any(_short_flag(arg, "q") or arg == "--quiet" for arg in args):
            return ""
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        shown = url if "://" in url else f"http://{url}/"
        return (
            f"--{stamp}--  {shown}\n"
            f"Resolving {host} ({host})... failed: Temporary failure in name resolution.\n"
            f"wget: unable to resolve host address '{host}'\n"
        )

    def _curl(self, args: list[str]) -> str:
        url = _first_operand(args, _CURL_VALUE_OPTIONS)
        if url is None:
            return "curl: try 'curl --help' or 'curl --manual' for more information\n"
        # -s hides the error unless -S asks to show it again ("-fsSL")
        silent = any(_short_flag(arg, "s") or arg == "--silent" for arg in args)
        show_error = any(_short_flag(arg, "S") or arg == "--show-error" for arg in args)
        if silent and not show_error:
            return ""
        return f"curl: (6) Could not resolve host: {_url_host(url)}\n"

    def _build_listings(self, session: SessionState) -> dict[str, set[str]]:
        """Each directory and the names in it."""
        programs = _BUSYBOX_PROGRAMS if _is_busybox(session) else _SYSTEM_PROGRAMS
        directories: dict[str, set[str]] = {
            "/": {"bin", "boot", "dev", "etc", "home", "tmp", "usr", "var"},
            "/bin": set(programs),
            "/usr": {"bin"},
            "/usr/bin": set(programs),
        }

        # A file's path makes its directories; so does each directory made
        # with mkdir, even while it's empty.
        for file_path, is_file in [
            *((file_path, True) for file_path in session.files),
            *((directory, False) for directory in session.dirs),
        ]:
            parts = [part for part in file_path.strip("/").split("/") if part]
            current = "/"

            for index, part in enumerate(parts):
                last = index == len(parts) - 1
                directories.setdefault(current, set()).add(part)

                if not (last and is_file):
                    current = (
                        f"/{part}"
                        if current == "/"
                        else f"{current}/{part}"
                    )
                    directories.setdefault(current, set())

        return directories

    def _record_listed_decoy_files(
        self, session: SessionState, directory: str, names: list[str],
    ) -> None:
        """Track direct child files whose names were exposed by a listing."""
        for file_path in session.files:
            path = PurePosixPath(file_path)
            if (
                str(path.parent) == directory
                and path.name in names
                and file_path not in session.written_files
            ):
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


_LIST_SEPARATORS = ("&&", "||", ";;", ";")
_MAX_SUBSHELL_DEPTH = 3
# Everything one session writes together, so a bot can't fill the memory
_MAX_WRITTEN_CHARS = 1_000_000


def _split_redirects(command: str) -> tuple[str, list[tuple[str, bool, str]]] | None:
    """Take `>`, `>>`, `2>`, `&>` and `2>&1` out of one simple command.

    Returns the command without them and, in order, (stream, append,
    target) for each: stream is "1", "2", another descriptor's number, or
    "&" for both; a target "&1" means "where stream 1 goes". None when a
    redirect has no target, which the shell reports as a syntax error.
    """
    rest: list[str] = []
    redirects = []
    quote = None
    index = 0
    while index < len(command):
        char = command[index]
        if quote:
            rest.append(char)
            if char == "\\" and quote == '"' and index + 1 < len(command):
                rest.append(command[index + 1])
                index += 2
                continue
            if char == quote:
                quote = None
            index += 1
            continue
        if char in "'\"":
            quote = char
        elif char == "\\" and index + 1 < len(command):
            rest.append(command[index:index + 2])
            index += 2
            continue
        if char != ">":
            rest.append(char)
            index += 1
            continue

        # "2>" names a stream only when the number is a word of its own
        start = len(rest)
        while start and not rest[start - 1].isspace():
            start -= 1
        word = "".join(rest[start:])
        stream = "1"
        if word.isdigit() or word == "&":
            stream = word
            del rest[start:]
        index += 1
        append = command.startswith(">", index)
        duplicate = not append and command.startswith("&", index)
        if append or duplicate or command.startswith("|", index):
            index += 1
        while index < len(command) and command[index] in " \t":
            index += 1

        # The target is the next word, quotes and all
        begin = index
        target_quote = None
        while index < len(command):
            char = command[index]
            if target_quote:
                if char == "\\" and target_quote == '"':
                    index += 1
                elif char == target_quote:
                    target_quote = None
            elif char in "'\"":
                target_quote = char
            elif char == "\\":
                index += 1
            elif char.isspace() or char in "<>":
                break
            index += 1
        raw = command[begin:index]
        if not raw:
            return None
        try:
            words = shlex.split(raw)
        except ValueError:
            words = [raw]
        target = words[0] if len(words) == 1 else raw
        if duplicate:
            if target.isdigit() or target == "-":
                target = "&" + target
            else:
                # `>& file` is `&> file`
                stream = "&"
        redirects.append((stream, append, target))
    return "".join(rest).strip(), redirects


def _options(
    args: list[str], long_names: dict[str, str], takes_value: str = "",
) -> tuple[set[str], list[str]]:
    """The option letters given and the operands; "--" ends the options.

    A letter in takes_value uses the rest of its word or the next word as
    its value (`mkdir -m 755 dir`).
    """
    flags: set[str] = set()
    operands = []
    index = 0
    while index < len(args):
        arg = args[index]
        index += 1
        if arg == "--":
            operands.extend(args[index:])
            break
        if arg == "-" or not arg.startswith("-"):
            operands.append(arg)
            continue
        if arg.startswith("--"):
            flags.add(long_names.get(arg.split("=", 1)[0], arg))
            continue
        for position, letter in enumerate(arg[1:], start=1):
            flags.add(letter)
            if letter in takes_value:
                if position == len(arg) - 1:
                    index += 1
                break
    return flags, operands


# BusyBox prints its usage line when an operand is missing
_BUSYBOX_USAGE = {
    "chmod": "chmod [-Rcvf] MODE[,MODE]... FILE...",
    "cp": "cp [-arPLHpfinlsTu] SOURCE... DEST",
    "mkdir": "mkdir [-m MODE] [-p] DIRECTORY...",
    "rm": "rm [-irf] FILE...",
    "touch": "touch [-c] [-d DATE] [-t DATE] [-r FILE] FILE...",
}


def _missing_operand(session: SessionState, cmd: str, message: str) -> str:
    """The error a coreutils program, or BusyBox, gives for a missing operand."""
    if _is_busybox(session):
        version = session.persona.os_banner.replace(
            "built-in shell (ash)", "multi-call binary."
        )
        return f"{version}\n\nUsage: {_BUSYBOX_USAGE[cmd]}\n"
    return f"{message}\nTry '{cmd} --help' for more information.\n"


def _chmod_executable(mode: str, executable: bool) -> bool | None:
    """Whether a file can be run after `chmod mode`; None for a bad mode."""
    if re.fullmatch(r"[0-7]{1,4}", mode):
        return any(int(digit) & 1 for digit in mode[-3:])
    for clause in mode.split(","):
        if not re.fullmatch(r"[ugoa]*(?:[-+=][rwxXstugo]*)+", clause):
            return None
        for operator, permissions in re.findall(r"([-+=])([rwxXstugo]*)", clause):
            has_x = "x" in permissions or "X" in permissions
            if operator == "=":
                executable = has_x
            elif has_x:
                executable = operator == "+"
    return executable


def _split_unquoted(
    line: str, separators: tuple[str, ...],
) -> tuple[list[tuple[str, str]], str | None]:
    """Split a line at the given separators where they're outside quotes.

    Returns (separator before each part, part text) pairs, or the token the
    shell reports when a separator has nothing before it. Separators are
    tried in order, so list "&&" before "&" and "||" before "|". Splitting
    with _LIST_SEPARATORS leaves pipes inside a part; ("|",) then splits a
    part into the commands of its pipeline.
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

        separator = next((sep for sep in separators if line.startswith(sep, index)), None)
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


def _shell_name(session: SessionState) -> str:
    """How the login shell names itself in its errors: bash, or BusyBox ash."""
    return "-sh" if _is_busybox(session) else "bash"


def _short_flag(arg: str, flag: str) -> bool:
    """True if a short-option word such as "-qO-" or "-fsSL" contains flag."""
    if not arg.startswith("-") or arg.startswith("--"):
        return False
    letters = arg[1:]
    # Letters after a value-taking O (as in "-qO-") are its value
    if "O" in letters:
        letters = letters[:letters.index("O") + 1]
    return flag in letters


def _first_operand(args: list[str], value_options: set[str]) -> str | None:
    """First word that isn't an option or an option's value."""
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in value_options:
            skip = True
            continue
        if arg.startswith("-") and arg != "-":
            continue
        return arg
    return None


_WGET_VALUE_OPTIONS = {"-O", "-o", "-a", "-P", "-t", "-T", "-U", "-e", "--output-document"}
_CURL_VALUE_OPTIONS = {
    "-o", "-H", "-A", "-d", "-X", "-u", "-e", "-m", "-x", "-b", "-c", "-F",
    "--output", "--header", "--user-agent", "--data", "--request", "--user",
    "--connect-timeout", "--max-time", "--proxy",
}


def _basic_regex(pattern: str) -> str:
    """grep's basic regex syntax as a Python regex.

    In basic syntax `+ ? | ( ) { }` are plain characters and the
    backslashed forms are the operators; Python is the other way round.
    """
    out = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            following = pattern[index + 1]
            out.append(following if following in "+?|(){}" else char + following)
            index += 2
            continue
        out.append("\\" + char if char in "+?|(){}" else char)
        index += 1
    return "".join(out)


def _elf_header(uname_output: str) -> str:
    """The start of a program file built for the persona's CPU.

    Byte 4 says 32 or 64 bit, byte 5 the byte order, bytes 18-19 the CPU --
    what a loader reads to pick its download. Bytes that aren't text are
    carried as surrogate escapes, which the SSH channel (errors=
    "surrogateescape") turns back into the original bytes.
    """
    machine = next((part for part in uname_output.split() if part in _ELF_CPUS), "x86_64")
    bits, order, cpu_id, flags = _ELF_CPUS[machine]
    ident = bytes([0x7F, 0x45, 0x4C, 0x46, 2 if bits == 64 else 1, 1 if order == "<" else 2, 1]) + bytes(9)
    if bits == 64:
        rest = struct.pack(
            f"{order}HHIQQQIHHHHHH", 3, cpu_id, 1, 0x2850, 0x40, 0x8A38, flags,
            0x40, 0x38, 13, 0x40, 31, 30,
        )
    else:
        rest = struct.pack(
            f"{order}HHIIIIIHHHHHH", 2, cpu_id, 1, 0x00401350, 0x34, 0x7A20, flags,
            0x34, 0x20, 10, 0x28, 29, 28,
        )
    return _from_bytes(ident + rest + bytes(64))


def _from_bytes(data: bytes) -> str:
    """Bytes as shell output: UTF-8 text stays text, other bytes survive."""
    return data.decode("utf-8", "surrogateescape")


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
    "base64", "bash", "cat", "chmod", "clear", "cp", "curl", "echo", "grep",
    "head", "hostname", "id", "ls", "mkdir", "netstat", "ps", "pwd", "rm",
    "sh", "ss", "tail", "touch", "uname", "wc", "wget", "whoami",
)
_BUSYBOX_APPLETS = (
    "base64", "cat", "chmod", "clear", "cp", "echo", "grep", "head",
    "hostname", "id", "ls", "mkdir", "netstat", "ps", "pwd", "rm", "sh",
    "tail", "touch", "uname", "wc", "wget", "whoami",
)
_BUSYBOX_PROGRAMS = ("busybox", *_BUSYBOX_APPLETS)
_ASH_BUILTINS = ("cd", "echo", "exit", "help", "logout", "pwd", "quit")


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

    # Redirects were taken out before this, so every word is text
    text = " ".join(args[index:])
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
_ECHO_SIMPLE_ESCAPES = {
    "\\": "\\", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b",
    "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v",
}
_ECHO_HEX_WIDTH = {"x": 2, "u": 4, "U": 8}

_MACHINE_NAMES = ("x86_64", "aarch64", "armv7l", "i686", "mips", "mipsel")

# BusyBox ash's `help` output.
_ASH_HELP = """
Built-in commands:
------------------
\t. : [ [[ alias bg break cd chdir command continue echo eval exec
\texit export false fg getopts hash help history jobs kill let
\tlocal printf pwd read readonly return set shift source test times
\ttrap true type ulimit umask unalias unset wait

"""

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
