"""Configuration: one mailbox from environment variables, or several from a JSON accounts file.

Everything is read on use, so that tests and both transports see the same values. Secrets (passwords, OAuth
client secrets, refresh tokens) only live in files, read when a connection needs them, never logged.
"""

import functools
import json
import os
import re
import stat
from dataclasses import dataclass
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from fastmcp.exceptions import ToolError

DEFAULT_PORT = 993
SMTP_PORTS = {"ssl": 465, "starttls": 587}  # default port of each SMTP security mode
GMAIL_SMTP_HOST = "smtp.gmail.com"
SEND_LIMIT_PER_HOUR = 20  # default of MAIL_SEND_LIMIT_PER_HOUR
DEFAULT_PASSWORD_FILE = "~/.config/mailroom-mcp/password"
DEFAULT_TIMEZONE = "UTC"
GMAIL_HOST = "imap.gmail.com"
DEFAULT_ACCOUNT = "default"  # name of the account configured through MAIL_IMAP_HOST and MAIL_USER
ACCOUNT_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
EMAIL = re.compile(r"[^\s@<>()\[\],;:\"]+@[^\s@<>()\[\],;:\"]+\.[^\s@<>()\[\],;:\"]+")


class ConfigError(ToolError):
    """Missing or invalid configuration: reported at startup, by --check and by every tool call."""


# Single-account settings that the accounts file replaces (per-account keys there).
SINGLE_ONLY = ("MAIL_ALIASES", "MAIL_SEND_ENABLED", "MAIL_SMTP_HOST", "MAIL_SMTP_PORT", "MAIL_SMTP_SECURITY")
REQUIRED = {"MAIL_IMAP_HOST": "IMAP server host name, e.g. imap.example.org",
            "MAIL_USER": "mailbox login, e.g. me@example.org"}


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, "").strip() or default


@functools.lru_cache(maxsize=8)
def _zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise ConfigError(f"MAIL_TIMEZONE: unknown time zone {name!r} (expected an IANA name such as UTC "
                          "or America/New_York)") from None


def zone() -> ZoneInfo:
    """Time zone of the dates returned by the tools and of "today" (MAIL_TIMEZONE, UTC by default)."""
    return _zone(env("MAIL_TIMEZONE", DEFAULT_TIMEZONE))


def settings() -> dict:
    """Single-account settings from the environment; ConfigError names every missing variable or the invalid one."""
    missing = [f"{name} ({hint})" for name, hint in REQUIRED.items() if not env(name)]
    if missing:
        raise ConfigError("Missing configuration: set " + " and ".join(missing) + ".")
    port = env("MAIL_IMAP_PORT", str(DEFAULT_PORT))
    if not port.isdecimal() or not 0 < int(port) < 65536:
        raise ConfigError(f"MAIL_IMAP_PORT: expected a port number, got {port!r}")
    aliases = [a for a in env("MAIL_ALIASES").split(",") if a.strip()]
    smtp = {}
    if env("MAIL_SMTP_HOST"):
        smtp["host"] = env("MAIL_SMTP_HOST")
    if env("MAIL_SMTP_PORT"):
        smtp_port = env("MAIL_SMTP_PORT")
        if not smtp_port.isdecimal() or not 0 < int(smtp_port) < 65536:
            raise ConfigError(f"MAIL_SMTP_PORT: expected a port number, got {smtp_port!r}")
        smtp["port"] = int(smtp_port)
    if env("MAIL_SMTP_SECURITY"):
        smtp["security"] = env("MAIL_SMTP_SECURITY").lower()
        if smtp["security"] not in SMTP_PORTS:
            raise ConfigError(f"MAIL_SMTP_SECURITY: expected ssl or starttls (TLS is required), "
                              f"got {env('MAIL_SMTP_SECURITY')!r}")
    return {"host": env("MAIL_IMAP_HOST"), "port": int(port), "user": env("MAIL_USER"),
            "password_file": os.path.expanduser(env("MAIL_PASSWORD_FILE", DEFAULT_PASSWORD_FILE)),
            "aliases": parse_aliases("MAIL_ALIASES", aliases, env("MAIL_USER")), "timezone": zone(),
            "send": parse_switch("MAIL_SEND_ENABLED", env("MAIL_SEND_ENABLED"), False),
            "smtp": parse_smtp("MAIL_SMTP_*", smtp, env("MAIL_IMAP_HOST"), "password")}


_TRUE, _FALSE = {"1", "true", "yes", "on"}, {"0", "false", "no", "off"}


def parse_switch(where: str, value: str, default: bool) -> bool:
    """true/false (also 1/0, yes/no, on/off, any case); empty: the default."""
    if not value.strip():
        return default
    if value.strip().lower() in _TRUE | _FALSE:
        return value.strip().lower() in _TRUE
    raise ConfigError(f"{where}: expected true or false, got {value!r}")


def smtp_default_host(imap_host: str, auth: str) -> str:
    """Gmail (OAuth, or a password on imap.gmail.com): smtp.gmail.com; otherwise the IMAP host."""
    return GMAIL_SMTP_HOST if auth == "google-oauth" or imap_host.lower() == GMAIL_HOST else imap_host


def parse_smtp(where: str, value, imap_host: str, auth: str) -> tuple[str, int, str]:
    """(host, port, security) of the SMTP server. Every key is optional: the host defaults to
    smtp_default_host, the security to starttls on port 587 and ssl otherwise, the port to the security's."""
    if not isinstance(value, dict):
        raise ConfigError(f"{where}: smtp must be an object with host, port and security (all optional)")
    _keys(where, value, {"host", "port", "security"}, set())
    host = _text(where, value["host"], "smtp host") if "host" in value else smtp_default_host(imap_host, auth)
    port = value.get("port")
    if port is not None and (isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536):
        raise ConfigError(f"{where}: smtp port must be a number between 1 and 65535, got {port!r}")
    security = value.get("security", "starttls" if port == SMTP_PORTS["starttls"] else "ssl")
    if security not in SMTP_PORTS:
        raise ConfigError(f"{where}: smtp security must be \"ssl\" or \"starttls\" (TLS is required), "
                          f"got {security!r}")
    return host, port or SMTP_PORTS[security], security


def send_limit_per_hour() -> int:
    """Most mails sent per hour by this process (MAIL_SEND_LIMIT_PER_HOUR, 20 by default; 0 disables sending)."""
    value = env("MAIL_SEND_LIMIT_PER_HOUR", str(SEND_LIMIT_PER_HOUR))
    if not value.isdecimal():
        raise ConfigError(f"MAIL_SEND_LIMIT_PER_HOUR: expected a number of mails (0 disables sending), got {value!r}")
    return int(value)


def parse_aliases(where: str, value, user: str) -> tuple[str, ...]:
    """Validated aliases: email addresses, without duplicates or the user itself (ignoring case)."""
    if not isinstance(value, list):
        raise ConfigError(f"{where}: expected a list of email addresses")
    out, seen = [], {user.strip().lower()}
    for item in value:
        address = item.strip() if isinstance(item, str) else item
        if not isinstance(address, str) or not EMAIL.fullmatch(address):
            raise ConfigError(f"{where}: expected email addresses, got {address!r}")
        if address.lower() not in seen:
            seen.add(address.lower())
            out.append(address)
    return tuple(out)


@dataclass(frozen=True)
class Account:
    name: str
    host: str
    port: int
    user: str
    auth: str  # "password" or "google-oauth"
    password_file: str | None = None
    client_secret_file: str | None = None
    refresh_token_file: str | None = None
    aliases: tuple[str, ...] = ()  # other addresses of the user: mail delivered here through them, or sent from them
    send: bool = False  # send_draft allowed (opt-in: "send": true, or MAIL_SEND_ENABLED for the single account)
    smtp_host: str = ""
    smtp_port: int = SMTP_PORTS["ssl"]
    smtp_security: str = "ssl"  # "ssl" (implicit TLS) or "starttls"

    @property
    def addresses(self) -> tuple[str, ...]:
        """The account's own addresses: its user, then its aliases."""
        return (self.user, *self.aliases)

    def secret_files(self) -> dict[str, str]:
        """{setting: path} of the files this account reads on connection."""
        keys = ("password_file",) if self.auth == "password" else ("client_secret_file", "refresh_token_file")
        return {key: getattr(self, key) for key in keys}


AUTH_KEYS = {"password": {"password_file"}, "google-oauth": {"client_secret_file", "refresh_token_file"}}
ACCOUNT_KEYS = {"name", "host", "port", "user", "auth", "aliases", "send", "smtp"}


def _keys(where: str, entry: dict, allowed: set[str], required: set[str]):
    unknown = sorted(set(entry) - allowed)
    if unknown:
        raise ConfigError(f"{where}: unknown key {', '.join(map(repr, unknown))} (allowed: {', '.join(sorted(allowed))})")
    missing = sorted(required - set(entry))
    if missing:
        raise ConfigError(f"{where}: missing {', '.join(map(repr, missing))}")


def _text(where: str, value, key: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{where}: {key} must be a non-empty string")
    if re.search(r"[\r\n\x00]", value):
        raise ConfigError(f"{where}: {key} contains a line break or a null character")
    return value.strip()


def _path(where: str, value, key: str, base: str) -> str:
    """Absolute path; a relative one is relative to the accounts file's directory."""
    path = os.path.expanduser(_text(where, value, key))
    return os.path.normpath(os.path.join(base, path))


def parse_accounts(data, source: str, base: str) -> list[Account]:
    """Validated accounts from the decoded JSON of an accounts file."""
    if not isinstance(data, list) or not data:
        raise ConfigError(f"{source}: expected a non-empty JSON list of accounts")
    out, names = [], set()
    for index, entry in enumerate(data, 1):
        where = f"{source}: account {index}"
        if not isinstance(entry, dict):
            raise ConfigError(f"{where}: expected an object")
        if isinstance(entry.get("name"), str):
            where += f" ({entry['name']!r})"
        _keys(where, entry, ACCOUNT_KEYS, {"name", "user", "auth"})
        name = entry["name"]
        if not isinstance(name, str) or not ACCOUNT_NAME.fullmatch(name):
            raise ConfigError(f"{where}: name must be a short slug (lowercase letters, digits and dashes, "
                              f"at most 32 characters, e.g. \"work\"), got {name!r}")
        if name in names:
            raise ConfigError(f"{where}: duplicate account name {name!r}")
        names.add(name)
        auth = entry["auth"]
        if not isinstance(auth, dict) or auth.get("type") not in AUTH_KEYS:
            raise ConfigError(f"{where}: auth must be an object with type \"password\" or \"google-oauth\"")
        kind = auth["type"]
        _keys(f"{where}: auth", auth, AUTH_KEYS[kind] | {"type"}, AUTH_KEYS[kind])
        user = _text(where, entry["user"], "user")
        if kind == "google-oauth" and "@" not in user:
            raise ConfigError(f"{where}: user must be the Google account's email address")
        if "host" in entry:
            host = _text(where, entry["host"], "host")
        elif kind == "google-oauth":
            host = GMAIL_HOST
        else:
            raise ConfigError(f"{where}: missing 'host' (IMAP server host name)")
        port = entry.get("port", DEFAULT_PORT)
        if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
            raise ConfigError(f"{where}: port must be a number between 1 and 65535, got {port!r}")
        files = {key: _path(f"{where}: auth", auth[key], key, base) for key in AUTH_KEYS[kind]}
        aliases = parse_aliases(f"{where}: aliases", entry.get("aliases", []), user)
        send = entry.get("send", False)
        if not isinstance(send, bool):
            raise ConfigError(f"{where}: send must be true or false, got {send!r}")
        smtp_host, smtp_port, smtp_security = parse_smtp(where, entry.get("smtp", {}), host, kind)
        out.append(Account(name=name, host=host, port=port, user=user, auth=kind, aliases=aliases, send=send,
                           smtp_host=smtp_host, smtp_port=smtp_port, smtp_security=smtp_security, **files))
    return out


def load_accounts(path: str) -> list[Account]:
    source = f"MAIL_ACCOUNTS_FILE ({path})"
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise ConfigError(f"{source}: file not found") from None
    except (OSError, UnicodeDecodeError) as e:
        raise ConfigError(f"{source}: cannot read the file ({type(e).__name__})") from None
    except json.JSONDecodeError as e:
        raise ConfigError(f"{source}: invalid JSON at line {e.lineno}, column {e.colno}: {e.msg}") from None
    return parse_accounts(data, source, os.path.dirname(os.path.abspath(path)))


def accounts() -> list[Account]:
    """Configured accounts: the MAIL_ACCOUNTS_FILE list, else one account from MAIL_IMAP_HOST and MAIL_USER."""
    path = env("MAIL_ACCOUNTS_FILE")
    if not path:
        cfg = settings()
        smtp_host, smtp_port, smtp_security = cfg["smtp"]
        return [Account(name=DEFAULT_ACCOUNT, host=cfg["host"], port=cfg["port"], user=cfg["user"],
                        auth="password", password_file=cfg["password_file"], aliases=cfg["aliases"],
                        send=cfg["send"], smtp_host=smtp_host, smtp_port=smtp_port, smtp_security=smtp_security)]
    conflicting = [name for name in (*REQUIRED, *SINGLE_ONLY) if env(name)]
    if conflicting:
        raise ConfigError(f"MAIL_ACCOUNTS_FILE is set: remove {' and '.join(conflicting)}, the accounts file "
                          "replaces them.")
    zone()
    return load_accounts(os.path.expanduser(path))


def file_problems(account: Account) -> tuple[list[str], list[str]]:
    """(errors, warnings) about the secret files of an account, for --check: missing or unreadable files are
    errors, files readable by other users are warnings."""
    errors, warnings = [], []
    for key, path in account.secret_files().items():
        try:
            mode = os.stat(path).st_mode
        except FileNotFoundError:
            errors.append(f"{key}: file not found: {path}")
            continue
        except OSError as e:
            errors.append(f"{key}: cannot read {path} ({type(e).__name__})")
            continue
        if not os.access(path, os.R_OK):
            errors.append(f"{key}: file not readable: {path}")
        elif mode & (stat.S_IRWXG | stat.S_IRWXO):
            warnings.append(f"{key}: {path} is accessible to other users: chmod 600 it")
    return errors, warnings


def account_password(account: Account) -> str:
    """Password of a password account, read from its file on use (IMAP and SMTP)."""
    if env("MAIL_ACCOUNTS_FILE"):
        return read_secret(account.password_file, f"Password of account '{account.name}'",
                           "password_file in MAIL_ACCOUNTS_FILE")
    return read_secret(account.password_file, "Password", "or set MAIL_PASSWORD_FILE")


def read_secret(path: str, what: str, hint: str) -> str:
    """Content of a secret file without its final line breaks; ToolError naming the file (never the content)."""
    try:
        with open(path, encoding="utf-8") as f:
            value = f.read().rstrip("\r\n")
    except FileNotFoundError:
        raise ToolError(f"{what} not found: create the file {path} ({hint})") from None
    except (OSError, UnicodeDecodeError) as e:
        raise ToolError(f"{what}: cannot read {path} ({type(e).__name__})") from None
    if not value.strip():
        raise ToolError(f"{what}: the file {path} is empty")
    return value
