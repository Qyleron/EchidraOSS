from __future__ import annotations

import re
import shlex
from urllib.parse import parse_qsl
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from classifier.schemas.session import SessionRecord


DISCOVERY_COMMANDS = {
    "hostname",
    "id",
    "ls",
    "netstat",
    "ps",
    "pwd",
    "ss",
    "uname",
    "whoami",
}
EXIT_COMMANDS = {"exit", "logout", "quit"}
SENSITIVE_PATH_MARKERS = {
    ".env",
    ".git",
    ".htaccess",
    "auth.log",
    "backup",
    "config.php",
    "credential",
    "passwd",
    "shadow",
    "wp-config",
}
# Bare "marker in path" substring matching misclassifies benign paths that
# happen to extend a marker into an unrelated name (".git" inside
# ".github/workflows", "shadow" inside "shadowsocks"). Require the marker not
# be immediately followed by another alphanumeric character -- an optional
# trailing "s" is still allowed so simple plurals (backup/backups,
# credential/credentials) keep matching, since "wp-config.php" and
# "/srv/backups/..." (an actual bundled persona decoy path) must still match.
_SENSITIVE_PATH_MARKER_PATTERN = re.compile(
    "|".join(re.escape(marker) + r"s?(?![A-Za-z0-9])" for marker in SENSITIVE_PATH_MARKERS)
)
# HttpHandler logs a request line ("GET /wp-login.php HTTP/1.1") as one
# command -- the path lands in args, so the same sensitive-path check that
# already covers `cat <path>` also applies to these HTTP verbs.
_HTTP_REQUEST_COMMANDS = {"get", "post", "head", "put", "delete"}
# HttpHandler logs a credential-bearing POST body as one command
# ("POST /wp-login.php: log=admin&pwd=hunter2") -- unlike Telnet/FTP's
# USER/PASS exchange, there's no fixed field name to match on, so this
# looks for common login-form field names in the body text instead.
_HTTP_CREDENTIAL_BODY_MARKERS = ("pwd=", "passwd=", "password=", "log=", "user=", "username=")
# Bare substring matching misclassifies benign fields whose name merely ends
# with a marker ("catalog=" containing "log=", "browser=" never actually
# containing "user=" but e.g. "poweruser=" would). Form fields are delimited
# by "&"/"?"/start-of-body, so require the marker not be immediately preceded
# by another alphanumeric character -- i.e. it must start a field name.
_HTTP_CREDENTIAL_BODY_PATTERN = re.compile(
    "|".join(r"(?<![A-Za-z0-9])" + re.escape(marker) for marker in _HTTP_CREDENTIAL_BODY_MARKERS)
)
# Login forms don't agree on field names ("log"/"pwd" is WordPress; "username"/
# "password" is generic; "email"/"pass" shows up too) -- check each known
# alias rather than assuming one fixed pair of field names.
_HTTP_USERNAME_FIELD_NAMES = ("log", "user", "username", "email", "uname")
_HTTP_PASSWORD_FIELD_NAMES = ("pwd", "pass", "passwd", "password")
# Product names of well-known vulnerability/recon scanners that identify
# themselves in their User-Agent header. Deliberately conservative (no
# "curl"/"python-requests"/etc.) -- those are used by huge amounts of benign
# automation too, so including them would make this rule fire constantly.
_SCANNER_USER_AGENT_MARKERS = (
    "masscan",
    "nikto",
    "sqlmap",
    "nmap",
    "nuclei",
    "zgrab",
    "wpscan",
    "dirbuster",
    "gobuster",
    "acunetix",
    "nessus",
)
_SCANNER_USER_AGENT_PATTERN = re.compile(
    "|".join(re.escape(marker) for marker in _SCANNER_USER_AGENT_MARKERS)
)
# Bounds for normalizing average_inter_command_interval_seconds into a 0-1
# human_timing_score. Below BOT_SPEED, commands are indistinguishable from
# automation (matches the ftp/telnet automated-credential-burst rules'
# implicit ceiling: commands_per_minute >= 120 is exactly a 0.5s interval).
# At or above HUMAN_PACING, the cadence reads as unambiguously human --
# someone reading output and deciding on a next command, not a script.
_BOT_SPEED_INTERVAL_SECONDS = 0.5
_HUMAN_PACING_INTERVAL_SECONDS = 5.0


class SessionFeatures(BaseModel):
    """Observable session measurements consumed by future classifier rules."""

    session_id: UUID
    protocol: str
    persona_id: str
    end_reason: str
    duration_seconds: float = Field(ge=0)
    command_count: int = Field(ge=0)
    commands_per_minute: float = Field(ge=0)
    unique_command_count: int = Field(ge=0)
    repeated_command_count: int = Field(ge=0)
    discovery_command_count: int = Field(ge=0)
    file_read_count: int = Field(ge=0)
    sensitive_file_read_count: int = Field(ge=0)
    decoy_files_surfaced: list[str]
    decoy_files_surfaced_count: int = Field(ge=0)
    exit_command_present: bool
    inter_command_intervals_seconds: list[float]
    average_inter_command_interval_seconds: float | None
    # Normalized 0.0-1.0 read on average_inter_command_interval_seconds: 0.0
    # is clearly bot-speed pacing, 1.0 is clearly human pacing. None when
    # there's no interval to measure at all (fewer than two commands) --
    # a single command has no cadence to score, not a bot-speed one.
    human_timing_score: float | None = Field(default=None, ge=0, le=1)
    command_names: list[str]
    auth_attempt_count: int = Field(default=0, ge=0)
    # "username:password" pairs submitted over Telnet, lowercased. Distinct
    # from auth_attempt_count (which only counts attempts) -- this is what
    # lets a rule match specific known credential wordlists (e.g. Mirai
    # defaults) instead of just detecting that *a* login was attempted.
    telnet_credentials_tried: list[str] = Field(default_factory=list)
    # Same idea, for the login/password gate on the primary "tcp_shell"
    # listener (the real SSH port -- see honeypot/network/ssh_server.py).
    ssh_credentials_tried: list[str] = Field(default_factory=list)
    # Same idea as telnet_credentials_tried, for FTP's USER/PASS exchange.
    ftp_credentials_tried: list[str] = Field(default_factory=list)
    # Same idea again, for credentials found in an HTTP POST body.
    http_credentials_tried: list[str] = Field(default_factory=list)
    # Request-line paths observed over HTTP, in the order requested (eg.
    # "/wp-login.php", "/.env") -- lets a rule or operator see what a scanner
    # actually probed for, beyond just whether one hit was "sensitive".
    http_paths_requested: list[str] = Field(default_factory=list)
    # Raw User-Agent header values observed over HTTP, as sent by the client.
    http_user_agents: list[str] = Field(default_factory=list)
    # True if any http_user_agents entry names a known scanner tool (eg.
    # masscan, nikto, sqlmap) -- a dedicated boolean rather than requiring a
    # rule to substring-match http_user_agents itself, since the rule engine's
    # contains_any operator only does exact element membership, not substring
    # matching within a list of free-form header strings.
    http_known_scanner_user_agent: bool = False
    # Cross-session feature — only populated by the store-time path when the DB
    # is available; None in the stateless /classify/session endpoint by design.
    connection_count_from_same_ip: int | None = None

    model_config = ConfigDict(extra="forbid")


def extract_session_features(
    session: SessionRecord,
    *,
    connection_count_from_same_ip: int | None = None,
) -> SessionFeatures:
    """Convert one validated session into deterministic behavioral measurements."""
    command_names = []
    discovery_command_count = 0
    file_read_count = 0
    sensitive_file_read_count = 0
    exit_command_present = False
    auth_attempt_count = 0
    telnet_credentials_tried: list[str] = []
    ssh_credentials_tried: list[str] = []
    ftp_credentials_tried: list[str] = []
    http_credentials_tried: list[str] = []
    http_paths_requested: list[str] = []
    http_user_agents: list[str] = []
    http_known_scanner_user_agent = False
    _pending_telnet_username: str | None = None
    _pending_ssh_username: str | None = None
    _pending_ftp_username: str | None = None

    for event in session.commands:
        command_name, args = _parse_command(event.cmd)
        command_names.append(command_name)

        normalized = event.cmd.strip().lower()
        if command_name in {"user", "pass"} or normalized.startswith(
            ("login:", "password:", "authorization:")
        ):
            auth_attempt_count += 1

        if session.protocol == "telnet":
            if normalized.startswith("login:"):
                _pending_telnet_username = event.cmd.split(":", 1)[1].strip().lower()
            elif normalized.startswith("password:") and _pending_telnet_username is not None:
                password = event.cmd.split(":", 1)[1].strip().lower()
                telnet_credentials_tried.append(f"{_pending_telnet_username}:{password}")
                _pending_telnet_username = None
        elif session.protocol == "tcp_shell":
            if normalized.startswith("login:"):
                _pending_ssh_username = event.cmd.split(":", 1)[1].strip().lower()
            elif normalized.startswith("password:") and _pending_ssh_username is not None:
                password = event.cmd.split(":", 1)[1].strip().lower()
                ssh_credentials_tried.append(f"{_pending_ssh_username}:{password}")
                _pending_ssh_username = None
        elif session.protocol == "ftp":
            if command_name == "user" and args:
                _pending_ftp_username = args[0].strip().lower()
            elif command_name == "pass" and args and _pending_ftp_username is not None:
                ftp_credentials_tried.append(f"{_pending_ftp_username}:{args[0].strip().lower()}")
                _pending_ftp_username = None
        elif (
            session.protocol == "http"
            and command_name == "post"
            and _HTTP_CREDENTIAL_BODY_PATTERN.search(normalized)
        ):
            auth_attempt_count += 1
            _, _, body = event.cmd.partition(": ")
            pair = _extract_http_credential_pair(body)
            if pair:
                http_credentials_tried.append(pair)

        if session.protocol == "http" and command_name in _HTTP_REQUEST_COMMANDS and args:
            http_paths_requested.append(args[0])

        if session.protocol == "http" and normalized.startswith("user-agent:"):
            user_agent = event.cmd.split(":", 1)[1].strip()
            if user_agent:
                http_user_agents.append(user_agent)
                if _SCANNER_USER_AGENT_PATTERN.search(user_agent.lower()):
                    http_known_scanner_user_agent = True

        if command_name in DISCOVERY_COMMANDS:
            discovery_command_count += 1

        if command_name == "cat":
            file_read_count += 1
            if any(_is_sensitive_path(arg) for arg in args):
                sensitive_file_read_count += 1
        elif (
            session.protocol == "http"
            and command_name in _HTTP_REQUEST_COMMANDS
            and any(_is_sensitive_path(arg) for arg in args)
        ):
            sensitive_file_read_count += 1

        if command_name in EXIT_COMMANDS:
            exit_command_present = True

    intervals = [
        current.timestamp - previous.timestamp
        for previous, current in zip(session.commands, session.commands[1:])
    ]
    average_interval = sum(intervals) / len(intervals) if intervals else None
    unique_command_count = len(set(command_names))
    human_timing_score = _human_timing_score(average_interval)

    return SessionFeatures(
        session_id=session.session_id,
        protocol=session.protocol,
        persona_id=session.persona_id,
        end_reason=session.end_reason,
        duration_seconds=session.duration_seconds,
        command_count=session.command_count,
        commands_per_minute=_commands_per_minute(
            session.command_count,
            session.duration_seconds,
        ),
        unique_command_count=unique_command_count,
        repeated_command_count=session.command_count - unique_command_count,
        discovery_command_count=discovery_command_count,
        file_read_count=file_read_count,
        sensitive_file_read_count=sensitive_file_read_count,
        decoy_files_surfaced=session.decoy_files_surfaced,
        decoy_files_surfaced_count=len(session.decoy_files_surfaced),
        exit_command_present=exit_command_present,
        inter_command_intervals_seconds=intervals,
        average_inter_command_interval_seconds=average_interval,
        human_timing_score=human_timing_score,
        command_names=command_names,
        auth_attempt_count=auth_attempt_count,
        telnet_credentials_tried=telnet_credentials_tried,
        ssh_credentials_tried=ssh_credentials_tried,
        ftp_credentials_tried=ftp_credentials_tried,
        http_credentials_tried=http_credentials_tried,
        http_paths_requested=http_paths_requested,
        http_user_agents=http_user_agents,
        http_known_scanner_user_agent=http_known_scanner_user_agent,
        connection_count_from_same_ip=connection_count_from_same_ip,
    )


def _parse_command(raw_command: str) -> tuple[str, list[str]]:
    """Return a normalized command name and arguments, even for malformed input."""
    try:
        tokens = shlex.split(raw_command)
    except ValueError:
        tokens = raw_command.split()

    if not tokens:
        return "", []

    return tokens[0].lower(), tokens[1:]


def _extract_http_credential_pair(body: str) -> str | None:
    """Pull a lowercased "user:pass" pair out of a POST body, if one is present.

    Returns None rather than fabricating a pair when either field is absent
    or blank -- mirrors how Telnet/FTP never pair up an incomplete exchange.
    """
    fields = {key.lower(): value for key, value in parse_qsl(body, keep_blank_values=True)}
    user = next((fields[name] for name in _HTTP_USERNAME_FIELD_NAMES if fields.get(name)), None)
    password = next((fields[name] for name in _HTTP_PASSWORD_FIELD_NAMES if fields.get(name)), None)
    if not user or not password:
        return None
    return f"{user.lower()}:{password.lower()}"


def _is_sensitive_path(path: str) -> bool:
    """Identify reads of paths likely to contain credentials or useful secrets."""
    return _SENSITIVE_PATH_MARKER_PATTERN.search(path.lower()) is not None


def _human_timing_score(average_interval: float | None) -> float | None:
    """Normalize average_inter_command_interval_seconds to a 0.0-1.0 score.

    0.0 reads as clearly bot-speed pacing, 1.0 as clearly human pacing,
    linearly interpolated between the two bounds. None in, None out --
    a session with fewer than two commands has no cadence to score at all,
    which is a different fact than "scored as bot-speed".
    """
    if average_interval is None:
        return None

    span = _HUMAN_PACING_INTERVAL_SECONDS - _BOT_SPEED_INTERVAL_SECONDS
    score = (average_interval - _BOT_SPEED_INTERVAL_SECONDS) / span
    return round(min(max(score, 0.0), 1.0), 2)


def _commands_per_minute(command_count: int, duration_seconds: float) -> float:
    """Calculate a stable command rate for sessions of any duration.

    A session with commands but a measured duration of exactly zero (e.g.
    several commands landing on the same timestamp in a fast automated
    burst) is maximally fast activity, not idle -- returning 0.0 let it
    evade any rate-based rule entirely. There's no true instantaneous rate
    to report (and +inf isn't JSON-safe, since it isn't valid JSON and
    JS's JSON.parse rejects it), so treat duration as a 1-second floor
    here: a large, finite, clearly-elevated rate instead of a wrong zero.
    """
    if duration_seconds > 0:
        return command_count * 60 / duration_seconds
    return command_count * 60.0
