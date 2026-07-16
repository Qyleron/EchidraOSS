"""HTTP honeypot handler — captures scanner requests and credential submissions."""

from __future__ import annotations

import asyncio
import base64
import logging

from honeypot.logging.session_logger import SessionLogger, finalize_and_schedule
from honeypot.network.config import READ_TIMEOUT, SESSION_LOG_PATH, get_active_persona
from honeypot.network.protocol_session import ProtocolSession

logger = logging.getLogger(__name__)

_APACHE_DEFAULT = """\
<!DOCTYPE html>
<html><head><title>Apache2 Ubuntu Default Page: It works</title></head>
<body>
<div style="width:640px;margin:0 auto">
<h1>Apache2 Ubuntu Default Page</h1>
<p>It works!</p>
<p>The Apache2 server is running. If you can read this page, the site is
running normally. Further configuration is required.</p>
</div>
</body></html>"""

_WP_LOGIN = """\
<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8"/>
<title>Log In &#8212; WordPress</title>
</head>
<body class="login wp-core-ui">
<div id="login">
<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address<br/>
<input type="text" name="log" id="user_login" class="input" size="20"/></label></p>
<p><label for="user_pass">Password<br/>
<input type="password" name="pwd" id="user_pass" class="input" size="20"/></label></p>
<p class="submit">
<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In"/>
</p>
<input type="hidden" name="redirect_to" value="/wp-admin/"/>
<input type="hidden" name="testcookie" value="1"/>
</form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
</div>
</body></html>"""

_WP_HOME = """\
<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8"/>
<title>WordPress &#8211; Just another WordPress site</title>
<meta name="generator" content="WordPress 6.4.3"/>
</head>
<body class="home blog">
<header id="masthead">
<div class="site-branding">
<p class="site-title"><a href="/">WordPress</a></p>
<p class="site-description">Just another WordPress site</p>
</div>
</header>
<main id="primary">
<p>Welcome to WordPress. This is your first post. Edit or delete it, then start writing!</p>
</main>
</body></html>"""

_PHPMYADMIN = """\
<!DOCTYPE html>
<html><head><title>phpMyAdmin 5.2.1</title>
<meta name="robots" content="noindex,nofollow"/>
</head>
<body>
<div id="pma_navigation">
<form method="post" action="index.php" name="login_form" id="login_form">
<fieldset id="fieldset_userpass">
<legend>phpMyAdmin 5.2.1</legend>
<table>
<tr><td><label for="input_username">Username:</label></td>
<td><input type="text" name="pma_username" id="input_username" value="" size="24" autocomplete="username"/></td></tr>
<tr><td><label for="input_password">Password:</label></td>
<td><input type="password" name="pma_password" id="input_password" value="" size="24" autocomplete="current-password"/></td></tr>
</table>
</fieldset>
<fieldset id="fieldset_userpass_footer">
<input value="Go" type="submit" id="input_go"/>
<input type="hidden" name="server" value="1"/>
<input type="hidden" name="target" value="index.php"/>
</fieldset>
</form>
</div>
</body></html>"""

_FORBIDDEN = """\
<!DOCTYPE html>
<html><head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body></html>"""

_NOT_FOUND = """\
<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.18.0</center>
</body></html>"""

_ROBOTS_TXT = "User-agent: *\nDisallow: /wp-admin/\nDisallow: /admin/\n"

# A minimal, structurally valid 16x16 32bpp ICO -- scanners and browsers
# alike request /favicon.ico on nearly every visit; a 404 there (while every
# other real server on the internet returns 200) is a small but free tell.
_FAVICON_ICO = base64.b64decode(
    "AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAQAQAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAzLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf"
    "/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf"
    "/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf"
    "/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf"
    "/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf"
    "/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf"
    "/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf"
    "/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf"
    "/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf"
    "/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf"
    "/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf"
    "/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf"
    "/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf"
    "/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf"
    "/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf/zMsH/8zLB//Mywf"
    "/zMsH/8zLB//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)


class HttpHandler:
    """Handle one HTTP connection, log the request, return a convincing fake page."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session_logger: SessionLogger | None = None,
    ):
        self.reader = reader
        self.writer = writer
        self.peer = writer.get_extra_info("peername")
        self.session = ProtocolSession(self.peer, "http", get_active_persona())
        self.session_logger = session_logger or SessionLogger(SESSION_LOG_PATH)

    async def handle(self) -> None:
        """Read one HTTP request, log it, and respond with a fake page."""
        end_reason = "disconnect"
        try:
            raw = await asyncio.wait_for(self._read_headers(), timeout=READ_TIMEOUT)
            if not raw:
                return

            text = raw.decode(errors="ignore")
            lines = text.replace("\r\n", "\n").split("\n")
            request_line = lines[0] if lines else ""

            if request_line:
                self.session.log_command(request_line)

            header_map: dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    key, _, val = line.partition(":")
                    header_map[key.strip().lower()] = val.strip()
                    # Capture headers that reveal attacker tools and identity
                    if key.strip().lower() in ("user-agent", "x-forwarded-for", "authorization"):
                        self.session.log_command(line.strip())

            parts = request_line.split(" ", 2)
            method = parts[0].upper() if parts else "GET"
            path = parts[1] if len(parts) > 1 else "/"

            if method == "POST":
                body = await asyncio.wait_for(
                    self._read_body(header_map),
                    timeout=10,
                )
                if body:
                    body_str = body.decode(errors="ignore")[:1024]
                    if body_str.strip():
                        self.session.log_command(f"POST {path}: {body_str}")

            response = self._build_response(method, path)
            self.writer.write(response)
            await self.writer.drain()
            end_reason = "disconnect"

        except asyncio.TimeoutError:
            end_reason = "timeout"
        except asyncio.CancelledError:
            end_reason = "shutdown"
        except Exception:
            logger.exception("HTTP handler error from %s", self.peer)
            end_reason = "error"
        finally:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
            self.session.finalize(end_reason)
            finalize_and_schedule(self.session_logger, self.session, "HTTP", logger)

    async def _read_headers(self) -> bytes:
        data = b""
        while len(data) < 16384:
            line = await self.reader.readline()
            if not line:
                break
            data += line
            if line in (b"\r\n", b"\n"):
                break
        return data

    async def _read_body(self, header_map: dict[str, str]) -> bytes:
        try:
            content_length = int(header_map.get("content-length", "0"))
        except (ValueError, TypeError):
            content_length = 0
        if content_length <= 0:
            return b""
        # A single reader.read(n) call may return fewer than n bytes if the
        # body arrives split across TCP segments (e.g. credentials in a
        # slow/chunked POST) -- it returns whatever's buffered at that
        # instant rather than waiting for the rest. readexactly() blocks
        # until the full declared length has arrived (or EOF); a client
        # that closes early having sent less than it declared still gets
        # its partial body captured via IncompleteReadError.partial instead
        # of losing everything.
        try:
            return await self.reader.readexactly(min(content_length, 65536))
        except asyncio.IncompleteReadError as exc:
            return exc.partial

    def _build_response(self, method: str, path: str) -> bytes:
        persona = self.session.persona
        status, content_type, body_bytes = self._pick_body(persona, path)

        if "nginx" in persona.running_processes:
            server_header = "nginx/1.18.0 (Ubuntu)"
        else:
            server_header = "Apache/2.4.54 (Debian)"
        headers = (
            f"HTTP/1.1 {status}\r\n"
            f"Server: {server_header}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        # A HEAD response reports the same Content-Length a GET would return
        # but never sends the body itself -- sending one anyway is a
        # protocol-level tell real servers don't make.
        if method == "HEAD":
            return headers.encode()
        return headers.encode() + body_bytes

    def _pick_body(self, persona, path: str) -> tuple[str, str, bytes]:
        p = path.lower().split("?")[0].rstrip("/") or "/"

        if p == "/favicon.ico":
            return "200 OK", "image/x-icon", _FAVICON_ICO

        if p == "/robots.txt":
            return "200 OK", "text/plain; charset=UTF-8", _ROBOTS_TXT.encode()

        # Sensitive probe paths — 403 to confirm existence without exposing content
        if any(x in p for x in ("/.env", "/wp-config", "/.git", "/config.php", "/.htaccess")):
            return "403 Forbidden", "text/html; charset=UTF-8", _FORBIDDEN.encode()

        # WordPress credential capture paths
        if any(x in p for x in ("/wp-login", "/wp-admin", "/wp-content", "/wp-includes")):
            return "200 OK", "text/html; charset=UTF-8", _WP_LOGIN.encode()

        # phpMyAdmin credential capture paths
        if any(x in p for x in ("/phpmyadmin", "/pma", "/mysqladmin", "/dbadmin", "/myadmin")):
            return "200 OK", "text/html; charset=UTF-8", _PHPMYADMIN.encode()

        # Root and index variants
        if p in ("/", "/index.html", "/index.php"):
            if "nginx" in persona.running_processes:
                return "200 OK", "text/html; charset=UTF-8", _WP_HOME.encode()
            if persona.persona_id == "centos_database":
                return "200 OK", "text/html; charset=UTF-8", _PHPMYADMIN.encode()
            return "200 OK", "text/html; charset=UTF-8", _APACHE_DEFAULT.encode()

        return "404 Not Found", "text/html; charset=UTF-8", _NOT_FOUND.encode()
