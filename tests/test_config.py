"""Accounts file (MAIL_ACCOUNTS_FILE): strict validation with readable errors, and --check."""

import json
import os
import subprocess
import sys

import pytest
from test_accounts import PERSO, WORK, write_accounts
from test_server import FakeIMAP, install, mail_env, mailbox_fixture  # noqa: F401  (autouse fixture)

from mailroom_mcp import config, server


@pytest.fixture
def accounts_file(monkeypatch, tmp_path):
    """Writes a list of accounts and points MAIL_ACCOUNTS_FILE at it."""
    monkeypatch.delenv("MAIL_IMAP_HOST")
    monkeypatch.delenv("MAIL_USER")

    def write(entries):
        path = write_accounts(tmp_path, entries)
        monkeypatch.setenv("MAIL_ACCOUNTS_FILE", str(path))
        return path
    return write


def test_valid_file_with_defaults_and_relative_paths(accounts_file, tmp_path):
    accounts_file([PERSO, {**WORK, "port": 993}])
    perso, work = config.accounts()
    assert (perso.name, perso.host, perso.port, perso.user, perso.auth) == (
        "perso", "imap.example.org", 993, "me@example.org", "password")
    assert perso.password_file == str(tmp_path / "perso.password")  # relative to the accounts file
    assert (work.host, work.auth, work.refresh_token_file) == ("imap.gmail.com", "google-oauth", str(tmp_path / "work.token"))
    assert work.secret_files() == {"client_secret_file": str(tmp_path / "client.json"),
                                   "refresh_token_file": str(tmp_path / "work.token")}


@pytest.mark.parametrize("entries,message", [
    ({}, "expected a non-empty JSON list of accounts"),
    ([], "expected a non-empty JSON list of accounts"),
    (["perso"], "account 1: expected an object"),
    ([{**PERSO, "pasword": "x"}], "account 1 ('perso'): unknown key 'pasword' (allowed: aliases, auth, host, name, port, send, smtp, user)"),
    ([{k: v for k, v in PERSO.items() if k != "user"}], "account 1 ('perso'): missing 'user'"),
    ([{**PERSO, "name": "Perso Mail"}], "name must be a short slug (lowercase letters, digits and dashes"),
    ([{**PERSO, "name": "*"}], "name must be a short slug"),
    ([{**PERSO, "name": "x" * 33}], "name must be a short slug"),
    ([PERSO, {**WORK, "name": "perso"}], "account 2 ('perso'): duplicate account name 'perso'"),
    ([{**PERSO, "auth": {"type": "oauth"}}], 'auth must be an object with type "password" or "google-oauth"'),
    ([{**PERSO, "auth": "secret"}], 'auth must be an object with type "password" or "google-oauth"'),
    ([{**PERSO, "auth": {"type": "password", "password": "hunter2"}}],
     "account 1 ('perso'): auth: unknown key 'password' (allowed: password_file, type)"),
    ([{**WORK, "auth": {"type": "google-oauth", "client_secret_file": "client.json"}}],
     "account 1 ('work'): auth: missing 'refresh_token_file'"),
    ([{k: v for k, v in PERSO.items() if k != "host"}], "account 1 ('perso'): missing 'host'"),
    ([{**PERSO, "port": "993"}], "port must be a number between 1 and 65535, got '993'"),
    ([{**PERSO, "port": True}], "port must be a number between 1 and 65535, got True"),
    ([{**PERSO, "port": 70000}], "port must be a number between 1 and 65535"),
    ([{**PERSO, "user": " "}], "user must be a non-empty string"),
    ([{**PERSO, "user": "me@example.org\r\nA1 DELETE INBOX"}], "user contains a line break"),
    ([{**WORK, "user": "me"}], "user must be the Google account's email address"),
    ([{**PERSO, "aliases": "me@work.example"}], "account 1 ('perso'): aliases: expected a list of email addresses"),
    ([{**PERSO, "aliases": ["me"]}], "account 1 ('perso'): aliases: expected email addresses, got 'me'"),
    ([{**PERSO, "aliases": ["Me <me@work.example>"]}], "aliases: expected email addresses, got 'Me <me@work.example>'"),
    ([{**PERSO, "aliases": ["me@work.example\r\nA1 DELETE INBOX"]}], "aliases: expected email addresses"),
    ([{**PERSO, "aliases": [42]}], "aliases: expected email addresses, got 42"),
])
def test_invalid_files_are_clear_errors(accounts_file, entries, message):
    path = accounts_file(entries)
    with pytest.raises(config.ConfigError) as error:
        config.accounts()
    assert str(error.value).startswith(f"MAIL_ACCOUNTS_FILE ({path}): ")
    assert message in str(error.value)


def test_unreadable_files_are_clear_errors(accounts_file, monkeypatch, tmp_path):
    path = accounts_file([PERSO])
    path.write_text('[{"name": "perso",\n "user": }]')
    with pytest.raises(config.ConfigError, match=r"invalid JSON at line 2, column 10"):
        config.accounts()
    monkeypatch.setenv("MAIL_ACCOUNTS_FILE", str(tmp_path / "missing.json"))
    with pytest.raises(config.ConfigError, match=r"missing.json\): file not found$"):
        config.accounts()


def test_accounts_file_conflicts_with_the_single_account_variables(accounts_file, monkeypatch):
    accounts_file([PERSO])
    monkeypatch.setenv("MAIL_USER", "me@example.org")
    with pytest.raises(config.ConfigError, match="^MAIL_ACCOUNTS_FILE is set: remove MAIL_USER, the accounts file"):
        config.accounts()


def test_aliases_are_deduplicated_ignoring_case_and_without_the_user(accounts_file):
    accounts_file([{**PERSO, "aliases": [" Me@Work.example ", "me@work.example", "ME@example.org", "me@shop.example"]},
                   WORK])
    perso, work = config.accounts()
    assert perso.aliases == ("Me@Work.example", "me@shop.example")
    assert perso.addresses == ("me@example.org", "Me@Work.example", "me@shop.example")
    assert work.aliases == () and work.addresses == ("me@company.com",)


def test_mail_aliases_for_the_single_account(monkeypatch):
    monkeypatch.setenv("MAIL_ALIASES", "me@work.example, ME@WORK.example,,me@shop.example")
    (account,) = config.accounts()
    assert account.aliases == ("me@work.example", "me@shop.example")
    monkeypatch.setenv("MAIL_ALIASES", "me@work.example, nobody")
    with pytest.raises(config.ConfigError, match="^MAIL_ALIASES: expected email addresses, got 'nobody'"):
        config.accounts()


def test_mail_aliases_conflicts_with_the_accounts_file(accounts_file, monkeypatch):
    accounts_file([PERSO])
    monkeypatch.setenv("MAIL_ALIASES", "me@work.example")
    with pytest.raises(config.ConfigError, match="^MAIL_ACCOUNTS_FILE is set: remove MAIL_ALIASES"):
        config.accounts()


def test_without_accounts_file_the_environment_gives_one_default_account():
    (account,) = config.accounts()
    assert (account.name, account.host, account.user, account.auth) == ("default", "imap.example.org", "me@example.org", "password")
    assert account.password_file == os.path.expanduser("~/.config/mailroom-mcp/password")


def test_file_problems_reports_missing_files_and_loose_modes(accounts_file, tmp_path):
    accounts_file([PERSO, WORK])
    perso, work = config.accounts()
    assert config.file_problems(perso) == ([], [])
    (tmp_path / "work.token").unlink()
    (tmp_path / "client.json").chmod(0o644)
    errors, warnings = config.file_problems(work)
    assert errors == [f"refresh_token_file: file not found: {tmp_path / 'work.token'}"]
    assert warnings == [f"client_secret_file: {tmp_path / 'client.json'} is accessible to other users: chmod 600 it"]


def test_check_reports_each_account_and_fails_on_missing_files(accounts_file, monkeypatch, tmp_path, capsys):
    accounts_file([{**PERSO, "aliases": ["me@work.example"]}, WORK])
    (tmp_path / "work.token").unlink()
    install(monkeypatch, {"perso": FakeIMAP(mailbox_fixture())})
    assert server.check(config.accounts()) == 1
    out = capsys.readouterr().out
    assert "[perso] me@example.org at imap.example.org:993 (password, 1 alias)" in out
    assert "{'name': 'INBOX', 'messages': 3, 'unseen': 1}" in out
    assert "{'total': 2, 'has_more': True, 'folders_excluded': {'perso':" in out
    assert "[work] me@company.com at imap.gmail.com:993 (google-oauth, 0 aliases)" in out
    assert f"error: refresh_token_file: file not found: {tmp_path / 'work.token'}" in out
    assert "test-only-not-a-real-secret" not in out


def test_check_with_the_environment_prints_as_before(monkeypatch, capsys, tmp_path):
    password = tmp_path / "password"
    password.write_text("x")
    password.chmod(0o600)
    monkeypatch.setenv("MAIL_PASSWORD_FILE", str(password))
    install(monkeypatch, FakeIMAP(mailbox_fixture()))
    assert server.check(config.accounts()) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "{'name': 'INBOX', 'messages': 3, 'unseen': 1}"
    assert lines[-1].startswith("{'total': 2, 'has_more': True, 'folders_excluded': ['INBOX.Sent'")
    monkeypatch.setenv("MAIL_ALIASES", "me@work.example,me@shop.example")
    assert server.check(config.accounts()) == 0
    assert capsys.readouterr().out.splitlines()[0] == "me@example.org: 2 aliases"


def test_startup_with_an_invalid_accounts_file_exits_with_the_message(tmp_path):
    path = tmp_path / "accounts.json"
    path.write_text(json.dumps([{**PERSO, "name": "Perso"}]))
    env = {k: v for k, v in os.environ.items() if not k.startswith("MAIL_")}
    env["MAIL_ACCOUNTS_FILE"] = str(path)
    result = subprocess.run([sys.executable, "-m", "mailroom_mcp", "--check"], env=env,
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 1 and "name must be a short slug" in result.stderr, result.stderr


# --- Sending: opt-in and SMTP settings ---

def test_sending_is_off_by_default_and_smtp_defaults_follow_the_imap_server(accounts_file):
    accounts_file([PERSO, WORK, {**PERSO, "name": "gmail-pw", "host": "imap.gmail.com"}])
    perso, work, gmail = config.accounts()
    assert not perso.send and not work.send and not gmail.send
    assert (perso.smtp_host, perso.smtp_port, perso.smtp_security) == ("imap.example.org", 465, "ssl")
    assert (work.smtp_host, work.smtp_port, work.smtp_security) == ("smtp.gmail.com", 465, "ssl")
    assert (gmail.smtp_host, gmail.smtp_port, gmail.smtp_security) == ("smtp.gmail.com", 465, "ssl")


@pytest.mark.parametrize("smtp,expected", [
    ({"host": "smtp.example.org"}, ("smtp.example.org", 465, "ssl")),
    ({"port": 587}, ("imap.example.org", 587, "starttls")),
    ({"security": "starttls"}, ("imap.example.org", 587, "starttls")),
    ({"host": "mail.example.org", "port": 2525, "security": "starttls"}, ("mail.example.org", 2525, "starttls")),
    ({"port": 465, "security": "ssl"}, ("imap.example.org", 465, "ssl")),
])
def test_smtp_settings_per_account(accounts_file, smtp, expected):
    accounts_file([{**PERSO, "send": True, "smtp": smtp}])
    (perso,) = config.accounts()
    assert perso.send and (perso.smtp_host, perso.smtp_port, perso.smtp_security) == expected


@pytest.mark.parametrize("entry,message", [
    ({**PERSO, "send": "yes"}, "send must be true or false, got 'yes'"),
    ({**PERSO, "smtp": "smtp.example.org"}, "smtp must be an object with host, port and security"),
    ({**PERSO, "smtp": {"server": "x"}}, "unknown key 'server' (allowed: host, port, security)"),
    ({**PERSO, "smtp": {"port": "465"}}, "smtp port must be a number between 1 and 65535, got '465'"),
    ({**PERSO, "smtp": {"security": "none"}}, 'smtp security must be "ssl" or "starttls" (TLS is required)'),
    ({**PERSO, "smtp": {"host": "smtp.example.org\r\nX"}}, "smtp host contains a line break"),
])
def test_invalid_smtp_settings_are_clear_errors(accounts_file, entry, message):
    accounts_file([entry])
    with pytest.raises(config.ConfigError, match="account 1 \\('perso'\\): " + message.replace("(", "\\(").replace(")", "\\)")):
        config.accounts()


def test_single_account_sending_comes_from_the_environment(monkeypatch):
    (account,) = config.accounts()
    assert not account.send and (account.smtp_host, account.smtp_port, account.smtp_security) == ("imap.example.org", 465, "ssl")
    monkeypatch.setenv("MAIL_SEND_ENABLED", "TRUE")
    monkeypatch.setenv("MAIL_SMTP_HOST", "smtp.example.org")
    monkeypatch.setenv("MAIL_SMTP_PORT", "587")
    (account,) = config.accounts()
    assert account.send and (account.smtp_host, account.smtp_port, account.smtp_security) == ("smtp.example.org", 587, "starttls")
    monkeypatch.setenv("MAIL_IMAP_HOST", "imap.gmail.com")
    monkeypatch.delenv("MAIL_SMTP_HOST")
    monkeypatch.delenv("MAIL_SMTP_PORT")
    assert config.accounts()[0].smtp_host == "smtp.gmail.com"


@pytest.mark.parametrize("name,value,message", [
    ("MAIL_SEND_ENABLED", "sure", "MAIL_SEND_ENABLED: expected true or false, got 'sure'"),
    ("MAIL_SMTP_PORT", "x", "MAIL_SMTP_PORT: expected a port number, got 'x'"),
    ("MAIL_SMTP_SECURITY", "plain", "MAIL_SMTP_SECURITY: expected ssl or starttls (TLS is required), got 'plain'"),
])
def test_invalid_single_account_send_settings(monkeypatch, name, value, message):
    monkeypatch.setenv(name, value)
    with pytest.raises(config.ConfigError) as error:
        config.accounts()
    assert str(error.value) == message


@pytest.mark.parametrize("name", ["MAIL_SEND_ENABLED", "MAIL_SMTP_HOST", "MAIL_SMTP_PORT", "MAIL_SMTP_SECURITY"])
def test_single_account_send_settings_conflict_with_the_accounts_file(accounts_file, monkeypatch, name):
    accounts_file([PERSO])
    monkeypatch.setenv(name, "1")
    with pytest.raises(config.ConfigError, match=f"^MAIL_ACCOUNTS_FILE is set: remove {name}"):
        config.accounts()


def test_send_limit_per_hour(monkeypatch):
    assert config.send_limit_per_hour() == 20
    monkeypatch.setenv("MAIL_SEND_LIMIT_PER_HOUR", "0")
    assert config.send_limit_per_hour() == 0
    monkeypatch.setenv("MAIL_SEND_LIMIT_PER_HOUR", "-1")
    with pytest.raises(config.ConfigError, match="MAIL_SEND_LIMIT_PER_HOUR: expected a number of mails"):
        config.send_limit_per_hour()
