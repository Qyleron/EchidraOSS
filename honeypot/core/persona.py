from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath


"""
Persona configuration for the fake machine shown to visitors.

A persona groups the details that make the honeypot feel specific:
hostname, OS banner, fake files, visible services, users, ports, and decoy
credentials. These presets are hardcoded today, but the same Persona shape can
later be filled from the HTML/UI for customer-specific deployments.
"""


@dataclass(frozen=True)
class FakeFile:
    """One fake file path and the content returned by cat."""
    path: str
    content: str


@dataclass(frozen=True)
class FakeCredential:
    """A decoy credential that looks useful but must not grant real access."""
    username: str
    password: str


@dataclass(frozen=True)
class Persona:
    """All fake identity and environment data for one honeypot personality."""
    persona_id: str
    os_banner: str
    ssh_banner: str
    hostname: str
    uname_output: str
    timezone: str
    username: str
    home_dir: str
    fake_filesystem: tuple[FakeFile, ...] = field(default_factory=tuple)
    running_processes: tuple[str, ...] = field(default_factory=tuple)
    fake_users: tuple[str, ...] = field(default_factory=tuple)
    suid_binaries: tuple[str, ...] = field(default_factory=tuple)
    open_ports_visible: tuple[int, ...] = field(default_factory=tuple)
    fake_credentials: tuple[FakeCredential, ...] = field(default_factory=tuple)

    def file_map(self) -> dict[str, str]:
        """Return fake files in the dictionary format SessionState uses."""
        return {fake_file.path: fake_file.content for fake_file in self.fake_filesystem}


def _file(path: str, content: str) -> FakeFile:
    """Small helper to keep preset definitions readable."""
    return FakeFile(path=path, content=content)


def _credential(username: str, password: str) -> FakeCredential:
    """Small helper to keep preset definitions readable."""
    return FakeCredential(username=username, password=password)


# The five preset personas available in the OSS backend.
# Later, paid/custom deployments can build the same Persona object from UI data.
PRESET_PERSONAS: dict[str, Persona] = {
    "generic_linux": Persona(
        persona_id="generic_linux",
        os_banner="Linux fake-host 5.15.0-91-generic x86_64",
        ssh_banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        hostname="fake-host",
        uname_output=(
            "Linux fake-host 5.15.0-91-generic #101-Ubuntu SMP "
            "x86_64 GNU/Linux"
        ),
        timezone="UTC",
        # Generic Linux starts in an admin-looking home while exposing root
        # identity, a common honeypot lure for post-compromise exploration.
        username="root",
        home_dir="/home/admin",
        fake_filesystem=(
            _file("/home/admin/readme.txt", "Welcome to the system.\n"),
            _file("/home/admin/notes.txt", "TODO: rotate credentials\n"),
            _file(
                "/etc/passwd",
                "root:x:0:0:root:/root:/bin/bash\n"
                "admin:x:1000:1000:admin:/home/admin:/bin/bash\n",
            ),
            _file("/etc/hosts", "127.0.0.1 localhost\n"),
            _file("/var/log/auth.log", ""),
        ),
        running_processes=("sshd", "cron", "rsyslogd"),
        fake_users=("root", "admin"),
        suid_binaries=("/usr/bin/sudo", "/bin/su"),
        open_ports_visible=(22,),
        fake_credentials=(_credential("admin", "admin123"),),
    ),
    "ubuntu_web_server": Persona(
        persona_id="ubuntu_web_server",
        os_banner="Ubuntu 20.04.6 LTS web-prod-01 tty1",
        ssh_banner="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        hostname="web-prod-01",
        uname_output="Linux web-prod-01 5.4.0-162-generic x86_64 GNU/Linux",
        timezone="America/New_York",
        username="ubuntu",
        home_dir="/home/ubuntu",
        fake_filesystem=(
            _file("/home/ubuntu/readme.txt", "Production web node. Do not reboot.\n"),
            _file("/var/www/html/index.php", "<?php echo 'Hello World'; ?>\n"),
            _file(
                "/var/www/html/wp-config.php",
                "define('DB_NAME', 'wordpress');\n"
                "define('DB_USER', 'wp_prod');\n"
                "define('DB_PASSWORD', 'prod_pass_2024');\n",
            ),
            _file("/etc/nginx/nginx.conf", "worker_processes auto;\n"),
            _file("/var/log/nginx/access.log", "192.168.1.1 - GET /admin 200\n"),
            _file(
                "/etc/passwd",
                "root:x:0:0:root:/root:/bin/bash\n"
                "ubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash\n"
                "deploy:x:1001:1001:deploy:/home/deploy:/bin/bash\n",
            ),
        ),
        running_processes=("nginx", "php-fpm", "mysql", "sshd"),
        fake_users=("www-data", "ubuntu", "deploy"),
        suid_binaries=("/usr/bin/sudo", "/bin/su"),
        open_ports_visible=(80, 443, 3306),
        fake_credentials=(
            _credential("admin", "admin123"),
            _credential("deploy", "Deploy@2024"),
        ),
    ),
    "centos_database": Persona(
        persona_id="centos_database",
        os_banner="CentOS Linux 7 db-primary-01 tty1",
        ssh_banner="SSH-2.0-OpenSSH_7.4",
        hostname="db-primary-01",
        uname_output="Linux db-primary-01 3.10.0-1160.el7.x86_64 GNU/Linux",
        timezone="America/Chicago",
        username="centos",
        home_dir="/home/centos",
        fake_filesystem=(
            _file("/home/centos/README", "Database maintenance host.\n"),
            _file("/var/lib/mysql/app/users.frm", "table format placeholder\n"),
            _file("/srv/backups/customer_dump.sql", "-- customer export\n"),
            _file("/etc/my.cnf", "[mysqld]\nbind-address=0.0.0.0\n"),
            _file("/var/log/mysqld.log", "ready for connections\n"),
            _file(
                "/etc/passwd",
                "root:x:0:0:root:/root:/bin/bash\n"
                "centos:x:1000:1000:centos:/home/centos:/bin/bash\n"
                "postgres:x:26:26:PostgreSQL Server:/var/lib/pgsql:/bin/bash\n",
            ),
        ),
        running_processes=("mysqld", "postgres", "sshd", "crond"),
        fake_users=("mysql", "postgres", "centos"),
        suid_binaries=("/usr/bin/sudo", "/bin/su"),
        open_ports_visible=(3306, 5432),
        fake_credentials=(_credential("reporting", "Report2024!"),),
    ),
    "debian_mail_server": Persona(
        persona_id="debian_mail_server",
        os_banner="Debian GNU/Linux 12 mail-gw-01 tty1",
        ssh_banner="SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2",
        hostname="mail-gw-01",
        uname_output="Linux mail-gw-01 6.1.0-18-amd64 x86_64 GNU/Linux",
        timezone="Europe/London",
        username="admin",
        home_dir="/home/admin",
        fake_filesystem=(
            _file("/home/admin/postfix-notes.txt", "Check deferred queue on Mondays.\n"),
            _file("/etc/postfix/main.cf", "myhostname = mail-gw-01\ninet_interfaces = all\n"),
            _file("/etc/dovecot/dovecot.conf", "protocols = imap pop3 lmtp\n"),
            _file("/var/log/mail.log", "postfix/smtpd: connect from unknown\n"),
            _file(
                "/etc/passwd",
                "root:x:0:0:root:/root:/bin/bash\n"
                "admin:x:1000:1000:admin:/home/admin:/bin/bash\n"
                "vmail:x:5000:5000:Virtual Mail:/var/mail:/usr/sbin/nologin\n",
            ),
        ),
        running_processes=("postfix", "dovecot", "rsyslogd", "sshd"),
        fake_users=("postfix", "dovecot", "vmail", "admin"),
        suid_binaries=("/usr/bin/sudo", "/bin/su"),
        open_ports_visible=(25, 110, 143, 587, 993),
        fake_credentials=(_credential("mailadmin", "MailAdmin2024!"),),
    ),
    # Linux host exposing Windows-style file shares through Samba.
    "samba_file_server": Persona(
        persona_id="samba_file_server",
        os_banner="Linux filesrv-01 5.15.0-91-generic x86_64",
        ssh_banner="SSH-2.0-OpenSSH_for_Windows_8.1",
        hostname="filesrv-01",
        uname_output="Linux filesrv-01 5.15.0-91-generic x86_64 GNU/Linux",
        timezone="America/Los_Angeles",
        username="svc_backup",
        home_dir="/home/svc_backup",
        fake_filesystem=(
            _file("/home/svc_backup/readme.txt", "SMB maintenance shell.\n"),
            _file("/srv/samba/Finance/Q4.xlsx", "binary workbook placeholder\n"),
            _file("/srv/samba/HR/onboarding.docx", "binary document placeholder\n"),
            _file("/var/log/samba/log.smbd", "smbd version 4.15 started.\n"),
            _file("/var/log/windows/Security.evtx", "event log placeholder\n"),
            _file(
                "/etc/passwd",
                "root:x:0:0:root:/root:/bin/bash\n"
                "svc_backup:x:1000:1000:svc_backup:/home/svc_backup:/bin/bash\n",
            ),
        ),
        running_processes=("smbd", "nmbd", "winbindd", "sshd"),
        fake_users=("svc_backup", "administrator", "guest"),
        suid_binaries=("/usr/bin/sudo", "/bin/su"),
        open_ports_visible=(139, 445, 3389),
        fake_credentials=(_credential("svc_backup", "BackupSvc2024!"),),
    ),
}


PERSONA_ALIASES: dict[str, str] = {
    "windows_smb_server": "samba_file_server",
}


def get_persona(persona_id: str = "generic_linux") -> Persona:
    """Look up a preset persona by ID and raise a clear error if it is unknown."""
    persona_id = PERSONA_ALIASES.get(persona_id, persona_id)
    try:
        return PRESET_PERSONAS[persona_id]
    except KeyError as exc:
        valid = ", ".join(sorted(PRESET_PERSONAS))
        raise ValueError(f"Unknown persona '{persona_id}'. Valid personas: {valid}") from exc


def validate_persona(persona: Persona) -> None:
    """
    Validate config before the honeypot uses it.

    This is intentionally small for now. It protects the backend from broken
    hardcoded configs today and will protect future UI-submitted configs later.
    """
    required = (
        persona.persona_id,
        persona.os_banner,
        persona.ssh_banner,
        persona.hostname,
        persona.uname_output,
        persona.timezone,
        persona.username,
        persona.home_dir,
    )
    if any(not value for value in required):
        raise ValueError("Persona identity fields cannot be empty")

    if not persona.home_dir.startswith("/"):
        raise ValueError("Persona home_dir must be an absolute Linux path")

    seen_paths = set()
    home_path = PurePosixPath(persona.home_dir)
    has_home_content = False

    for fake_file in persona.fake_filesystem:
        path = PurePosixPath(fake_file.path)
        if not fake_file.path.startswith("/") or ".." in path.parts:
            raise ValueError(f"Invalid fake filesystem path: {fake_file.path}")
        if fake_file.path in seen_paths:
            raise ValueError(f"Duplicate fake filesystem path: {fake_file.path}")

        seen_paths.add(fake_file.path)

        try:
            path.relative_to(home_path)
            has_home_content = True
        except ValueError:
            pass

    if not has_home_content:
        raise ValueError("Persona home_dir must contain at least one fake file")

    for credential in persona.fake_credentials:
        if not credential.username or not credential.password:
            raise ValueError("Fake credential username and password cannot be empty")

    for port in persona.open_ports_visible:
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid visible port: {port}")
