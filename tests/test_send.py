"""send_draft: a draft leaves only after a human approved that exact mail (confirmation code or dialog).

Fake IMAP and a fake SMTP server (smtplib.SMTP_SSL / SMTP replaced): no network, no real mailbox."""

import asyncio
import email
import json
import smtplib
import ssl
from email import policy
from email.message import EmailMessage

import pytest
from fastmcp import Client
from fastmcp.client.elicitation import ElicitResult
from test_accounts import ALL, GMAIL_CAPS, PERSO, SENT, WORK, gmail_fixture, write_accounts
from test_server import FakeIMAP, install, mail_env, mailbox_fixture  # noqa: F401  (autouse fixture)

from mailroom_mcp import google_oauth, server, smtp


class SMTPServer:
    """What the fake SMTP server received, and the failures it is told to produce."""

    def __init__(self):
        self.connections = []  # (kind, host, port, context)
        self.logins = []       # ("password", user, password) or ("xoauth2", user, token)
        self.received = []     # (sender, recipients, data, options)
        self.fail = {}         # step -> exception to raise, or (code, reply) to answer
        self.refuse = {}       # recipient -> (code, reply)
        self.features = {"auth", "starttls", "8bitmime", "smtputf8", "size"}
        self.tokens = None     # XOAUTH2 tokens accepted (None: any)
        self.starttls = []

    def answer(self, step, default):
        failure = self.fail.get(step)
        if isinstance(failure, BaseException):
            raise failure
        return failure or default


class FakeSMTP:
    def __init__(self, srv, kind, host, port, timeout=None, context=None):
        self.srv, self.tls = srv, kind == "ssl"
        srv.connections.append((kind, host, port, context))
        srv.answer("connect", None)
        assert timeout

    def ehlo(self):
        return 250, b"fake.example.org"

    def has_extn(self, name):
        return name.lower() in self.srv.features

    def starttls(self, context=None):
        self.srv.starttls.append(context)
        self.tls = True
        return 220, b"ready"

    def login(self, user, password):
        assert self.tls, "credentials sent before TLS"
        self.srv.answer("login", None)
        self.srv.logins.append(("password", user, password))
        return 235, b"ok"

    def auth(self, mechanism, authobject, initial_response_ok=True):
        assert self.tls and mechanism == "XOAUTH2" and initial_response_ok
        user, token = [p.split("=", 1)[1].removeprefix("Bearer ") for p in authobject().split("\x01") if p]
        if self.srv.tokens is not None and token not in self.srv.tokens:
            assert authobject(b'{"status":"401"}') == ""
            raise smtplib.SMTPAuthenticationError(535, b"5.7.8 Username and Password not accepted")
        self.srv.logins.append(("xoauth2", user, token))
        return 235, b"ok"

    def mail(self, sender, options=()):
        self.sender, self.options, self.rcpts = sender, list(options), []
        return self.srv.answer("mail", (250, b"ok"))

    def rcpt(self, recipient, options=()):
        if recipient in self.srv.refuse:
            return self.srv.refuse[recipient]
        self.rcpts.append(recipient)
        return 250, b"ok"

    def data(self, msg):
        reply = self.srv.answer("data", (250, b"2.0.0 queued"))
        if reply[0] == 250:
            self.srv.received.append((self.sender, self.rcpts, msg, self.options))
        return reply

    def rset(self):
        return 250, b"ok"

    def quit(self):
        return 221, b"bye"

    def close(self):
        pass


@pytest.fixture
def smtp_server(monkeypatch):
    srv = SMTPServer()
    monkeypatch.setattr(smtp.smtplib, "SMTP_SSL", lambda host, port, timeout=None, context=None:
                        FakeSMTP(srv, "ssl", host, port, timeout, context))
    monkeypatch.setattr(smtp.smtplib, "SMTP", lambda host, port, timeout=None: FakeSMTP(srv, "starttls", host, port, timeout))
    return srv


@pytest.fixture
def sending(monkeypatch, tmp_path, smtp_server):
    """Single account (Dovecot-like fake) with sending enabled."""
    password = tmp_path / "password"
    password.write_text("test-only-not-a-real-password\n")
    monkeypatch.setenv("MAIL_PASSWORD_FILE", str(password))
    monkeypatch.setenv("MAIL_SEND_ENABLED", "true")
    return install(monkeypatch, FakeIMAP(mailbox_fixture()))


def send(**kwargs):
    return asyncio.run(server.send_draft(**kwargs))


def new_draft(**kwargs):
    fields = {"to": "Bob <bob@example.org>", "subject": "Devis", "body": "Bonjour Bob,\n\nVoici le devis.", **kwargs}
    return server.save_draft(**fields)["uid"]


def put_draft(fake, folder="INBOX.Drafts", flags=("\\Draft", "\\Seen"), **headers):
    """A draft written by another mail client (Bcc, attachment…)."""
    msg = EmailMessage()
    for name, value in {"From": "me@example.org", "To": "bob@example.org", "Subject": "Rapport", **headers}.items():
        msg[name] = value
    msg.set_content("Le rapport est en pièce jointe.")
    msg.add_attachment(b"%PDF-1.4 fake", maintype="application", subtype="pdf", filename="rapport.pdf")
    uid = fake._next_uid(folder)
    fake.folders[folder]["messages"].append({"uid": uid, "flags": set(flags), "internal": "20-Oct-2026 12:00:00 +0200",
                                             "raw": msg.as_bytes(), "structure": None})
    return uid


def uids(fake, folder):
    return [m["uid"] for m in fake.folders[folder]["messages"]]


def transmitted(srv):
    sender, recipients, data, options = srv.received[-1]
    return sender, recipients, email.message_from_bytes(data, policy=policy.default), data


# --- Two steps: preview, then the code ---

def test_preview_sends_nothing_and_returns_a_code(sending, smtp_server):
    uid = new_draft(cc="Carol <carol@example.org>", body="x" * 400)
    preview = send(uid=uid)
    assert preview["sent"] is False and preview["uid"] == uid and preview["folder"] == "INBOX.Drafts"
    assert (preview["from"], preview["to"], preview["cc"], preview["subject"]) == (
        "me@example.org", "Bob <bob@example.org>", "Carol <carol@example.org>", "Devis")
    assert preview["body"] == "x" * 300 + "…" and "attachments" not in preview and "reply" not in preview
    assert len(preview["confirmation"]) >= 12 and preview["expires"].startswith("20")
    assert "explicitly approve" in preview["next"] and "Never approve it yourself" in preview["next"]
    assert smtp_server.connections == [] and uid in uids(sending, "INBOX.Drafts")


def test_confirmed_send_strips_bcc_keeps_a_copy_in_sent_and_trashes_the_draft(sending, smtp_server):
    uid = put_draft(sending, To="Bob <bob@example.org>", Cc="carol@example.org",
                    Bcc="Dan <dan@example.org>, erin@example.org", Date="Mon, 19 Oct 2026 09:00:00 +0000")
    preview = send(uid=uid)
    assert preview["bcc"] == 2 and preview["attachments"] == ["rapport.pdf"] and "Dan" not in json.dumps(preview)
    result = send(uid=uid, confirmation=preview["confirmation"])
    sender, recipients, msg, data = transmitted(smtp_server)
    assert sender == "me@example.org"
    assert recipients == ["bob@example.org", "carol@example.org", "dan@example.org", "erin@example.org"]
    assert msg["Bcc"] is None and b"dan@example.org" not in data and b"\r\n" in data
    assert msg["Message-ID"] and "19 Oct 2026" not in msg["Date"]  # dated when sent
    assert smtp_server.connections[0][:3] == ("ssl", "imap.example.org", 465)
    assert smtp_server.logins == [("password", "me@example.org", "test-only-not-a-real-password")]
    appended = [args for cmd, args in sending.log if cmd == "APPEND"]
    assert appended == [("INBOX.Sent", "(\\Seen)")]
    copy = email.message_from_bytes(sending.folders["INBOX.Sent"]["messages"][-1]["raw"], policy=policy.default)
    assert "dan@example.org" in copy["Bcc"] and copy["Message-ID"] == msg["Message-ID"]  # the copy keeps Bcc
    assert uid not in uids(sending, "INBOX.Drafts") and len(sending.folders["INBOX.Trash"]["messages"]) == 2
    assert result == {"sent": True, "to": "Bob <bob@example.org>", "subject": "Rapport",
                      "message_id": msg["Message-ID"], "saved_to": "INBOX.Sent", "draft_removed": True}


def test_a_code_is_used_once(sending, smtp_server):
    uid = new_draft()
    code = send(uid=uid)["confirmation"]
    assert send(uid=uid, confirmation=code)["sent"] is True
    with pytest.raises(server.ToolError, match="^Unknown confirmation: nothing was sent"):
        send(uid=uid, confirmation=code)
    assert len(smtp_server.received) == 1


def test_a_changed_draft_needs_a_new_preview(sending, smtp_server):
    uid = new_draft()
    code = send(uid=uid)["confirmation"]
    draft = next(m for m in sending.folders["INBOX.Drafts"]["messages"] if m["uid"] == uid)
    draft["raw"] = draft["raw"].replace(b"bob@example.org", b"mallory@example.org")
    with pytest.raises(server.ToolError, match="^The draft changed since the preview: nothing was sent"):
        send(uid=uid, confirmation=code)
    with pytest.raises(server.ToolError, match="^Unknown confirmation"):  # the code is gone with the old content
        send(uid=uid, confirmation=code)
    assert smtp_server.received == []


def test_an_expired_code_is_refused(sending, smtp_server, monkeypatch):
    uid = new_draft()
    monkeypatch.setattr(server, "CONFIRM_TTL", -1)
    code = send(uid=uid)["confirmation"]
    with pytest.raises(server.ToolError, match=r"^This confirmation expired .*nothing was sent"):
        send(uid=uid, confirmation=code)
    assert smtp_server.received == []


def test_a_code_only_approves_its_own_draft(sending, smtp_server):
    first, second = new_draft(), new_draft(subject="Autre")
    code = send(uid=first)["confirmation"]
    with pytest.raises(server.ToolError, match=f"^This confirmation is for draft {first} of account default"):
        send(uid=second, confirmation=code)
    assert send(uid=first, confirmation=code)["sent"] is True  # still valid for the draft it approves
    assert transmitted(smtp_server)[2]["Subject"] == "Devis"


def test_a_dialog_confirmation_is_not_a_code(sending, smtp_server):
    uid = new_draft()
    code, _ = server.CONFIRMATIONS.issue("default", "INBOX.Drafts", uid, "x", dialog=True)
    with pytest.raises(server.ToolError, match="^Unknown confirmation"):
        send(uid=uid, confirmation=code)


def test_only_drafts_are_sent(sending, smtp_server):
    with pytest.raises(server.ToolError, match=r"^Message 1 in INBOX is not a draft: send_draft only sends drafts"):
        send(uid=1, folder="INBOX")
    with pytest.raises(server.ToolError, match="^Draft 99 not found in INBOX.Drafts: nothing was sent"):
        send(uid=99)
    uid = put_draft(sending, folder="INBOX", flags=("\\Draft",))  # a draft filed elsewhere, flagged \Draft
    assert send(uid=uid, folder="INBOX")["sent"] is False


def test_the_from_must_be_an_address_of_the_account(sending, smtp_server, monkeypatch):
    uid = put_draft(sending, From="Boss <boss@example.org>")
    with pytest.raises(server.ToolError, match=r"^The draft's From \(Boss <boss@example.org>\) is not an address"):
        send(uid=uid)
    monkeypatch.setenv("MAIL_ALIASES", "boss@example.org")
    assert send(uid=uid)["from"] == "Boss <boss@example.org>"


def test_a_reply_says_to_what(sending, smtp_server):
    original = next(m for m in sending.folders["INBOX"]["messages"] if m["uid"] == 3)
    original["raw"] = b"Message-ID: <contrat-3@example.org>\n" + original["raw"]
    uid = server.save_draft(to="bob@example.org", subject="Re: Contrat", body="Merci", reply_to_folder="INBOX",
                            reply_to_uid=3)["uid"]
    preview = send(uid=uid)
    assert preview["reply"] is True and preview["reply_subject"] == "Contrat"


# --- Opt-in and limits ---

def test_sending_is_off_unless_enabled(smtp_server, monkeypatch):
    fake = install(monkeypatch, FakeIMAP(mailbox_fixture()))
    uid = new_draft()
    with pytest.raises(server.ToolError, match=r"^Sending is disabled for me@example.org: nothing was sent\. .*"
                                               "MAIL_SEND_ENABLED=true"):
        send(uid=uid)
    assert not [c for c, _ in fake.log if c == "FETCH"] and smtp_server.connections == []


def test_a_limit_of_zero_disables_sending(sending, monkeypatch):
    monkeypatch.setenv("MAIL_SEND_LIMIT_PER_HOUR", "0")
    with pytest.raises(server.ToolError, match=r"^Sending is disabled on this server \(MAIL_SEND_LIMIT_PER_HOUR=0\)"):
        send(uid=new_draft())


def test_sends_per_hour_are_limited(sending, smtp_server, monkeypatch):
    monkeypatch.setenv("MAIL_SEND_LIMIT_PER_HOUR", "1")
    first, second = new_draft(), new_draft()
    code = send(uid=second)["confirmation"]
    send(uid=first, confirmation=send(uid=first)["confirmation"])
    with pytest.raises(server.ToolError, match=r"^Sending limit reached: 1 mails in the last hour"):
        send(uid=second)
    with pytest.raises(server.ToolError, match=r"^Sending limit reached"):
        send(uid=second, confirmation=code)
    assert len(smtp_server.received) == 1
    monkeypatch.setenv("MAIL_SEND_LIMIT_PER_HOUR", "2")
    assert send(uid=second, confirmation=code)["sent"] is True  # the refused call did not use the code


def test_a_failed_send_does_not_count(sending, smtp_server, monkeypatch):
    monkeypatch.setenv("MAIL_SEND_LIMIT_PER_HOUR", "1")
    uid = new_draft()
    code = send(uid=uid)["confirmation"]
    smtp_server.fail["connect"] = ConnectionRefusedError(111, "Connection refused")
    with pytest.raises(server.ToolError):
        send(uid=uid, confirmation=code)
    del smtp_server.fail["connect"]
    assert send(uid=uid, confirmation=code)["sent"] is True


# --- SMTP: TLS, authentication, errors ---

def test_tls_is_verified_with_the_default_context(sending, smtp_server):
    uid = new_draft()
    send(uid=uid, confirmation=send(uid=uid)["confirmation"])
    context = smtp_server.connections[0][3]
    assert isinstance(context, ssl.SSLContext) and context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname


def test_starttls_comes_before_the_login(sending, smtp_server, monkeypatch):
    monkeypatch.setenv("MAIL_SMTP_HOST", "smtp.example.org")
    monkeypatch.setenv("MAIL_SMTP_PORT", "587")
    uid = new_draft()
    assert send(uid=uid, confirmation=send(uid=uid)["confirmation"])["sent"] is True
    assert smtp_server.connections[0][:3] == ("starttls", "smtp.example.org", 587)
    assert smtp_server.starttls[0].verify_mode == ssl.CERT_REQUIRED and smtp_server.logins


def test_a_server_without_starttls_gets_no_credentials(sending, smtp_server, monkeypatch):
    monkeypatch.setenv("MAIL_SMTP_SECURITY", "starttls")
    smtp_server.features.discard("starttls")
    uid = new_draft()
    with pytest.raises(server.ToolError, match="^The mail was not sent: the SMTP server imap.example.org:587 does not "
                                               "offer STARTTLS"):
        send(uid=uid, confirmation=send(uid=uid)["confirmation"])
    assert smtp_server.logins == []


@pytest.mark.parametrize("step,failure,message,retryable", [
    ("connect", ConnectionRefusedError(111, "Connection refused"),
     "The mail was not sent: cannot connect to the SMTP server imap.example.org:465", True),
    ("connect", TimeoutError("timed out"), "cannot connect to the SMTP server", True),
    ("login", smtplib.SMTPAuthenticationError(535, b"5.7.8 Authentication failed"),
     "The mail was not sent: SMTP authentication failed for me@example.org (535 5.7.8 Authentication failed)", False),
    ("mail", (451, b"4.3.0 Try later"), "the SMTP server refused the sender me@example.org (451 4.3.0 Try later)", True),
    ("mail", (553, b"5.7.1 Sender not allowed"), "refused the sender me@example.org (553 5.7.1 Sender not allowed)", False),
    ("data", smtplib.SMTPDataError(554, b"5.5.1 No valid recipients"),
     "the SMTP server refused the message (554 5.5.1 No valid recipients)", False),
    ("data", (552, b"5.3.4 Message too big"), "refused the message (552 5.3.4 Message too big)", False),
    ("data", (451, b"4.7.1 Greylisted"), "refused the message (451 4.7.1 Greylisted)", True),
])
def test_smtp_errors_are_readable_and_say_nothing_was_sent(sending, smtp_server, step, failure, message, retryable):
    uid = new_draft()
    code = send(uid=uid)["confirmation"]
    smtp_server.fail[step] = failure
    with pytest.raises(server.ToolError) as error:
        send(uid=uid, confirmation=code)
    text = str(error.value)
    assert message in text and "Nothing left the mailbox." in text and "Unexpected" not in text, text
    assert ("temporary" in text) is retryable and ("Retrying as is will fail" in text) is (not retryable)
    assert text.endswith("."), text
    assert "The confirmation stays valid until" in text and uid in uids(sending, "INBOX.Drafts")
    assert smtp_server.received == [] and len(sending.folders["INBOX.Sent"]["messages"]) == 1


@pytest.mark.parametrize("failure", [smtplib.SMTPServerDisconnected("Connection unexpectedly closed"),
                                     TimeoutError("The read operation timed out"), ConnectionResetError(104, "reset")])
def test_a_connection_lost_during_data_may_have_sent_the_mail(sending, smtp_server, failure):
    uid = new_draft()
    code = send(uid=uid)["confirmation"]
    smtp_server.fail["data"] = failure
    with pytest.raises(server.ToolError) as error:
        send(uid=uid, confirmation=code)
    text = str(error.value)
    assert text.startswith("The mail may have been sent: the connection to the SMTP server failed while the message "
                           "was being transmitted") and "Check the Sent folder" in text and "do not send it again" in text
    assert "stays valid" not in text
    del smtp_server.fail["data"]
    with pytest.raises(server.ToolError, match="^Unknown confirmation"):  # no blind retry with the same code
        send(uid=uid, confirmation=code)


def test_refused_recipients(sending, smtp_server):
    uid = new_draft(to="bob@example.org, nobody@example.org")
    smtp_server.refuse["nobody@example.org"] = (550, b"5.1.1 User unknown")
    result = send(uid=uid, confirmation=send(uid=uid)["confirmation"])
    assert result["sent"] is True and transmitted(smtp_server)[1] == ["bob@example.org"]
    assert result["warnings"] == ["The SMTP server refused some recipients, who will not get the mail: "
                                  "nobody@example.org (550 5.1.1 User unknown). The others got it."]
    uid = new_draft(to="nobody@example.org")
    with pytest.raises(server.ToolError, match=r"^The mail was not sent: the SMTP server refused every recipient "
                                               r"\(nobody@example.org: 550 5.1.1 User unknown\)"):
        send(uid=uid, confirmation=send(uid=uid)["confirmation"])


def test_filing_failures_after_sending_are_warnings(sending, smtp_server):
    uid = new_draft()
    code = send(uid=uid)["confirmation"]
    del sending.folders["INBOX.Sent"]  # no Sent folder at all
    result = send(uid=uid, confirmation=code)
    assert result["sent"] is True and result["draft_removed"] is True and "saved_to" not in result
    assert result["warnings"] == ["The mail WAS sent: do not send it again. No Sent folder was found, so no copy was kept."]


def test_a_lost_imap_connection_after_sending_is_a_warning(sending, smtp_server, monkeypatch):
    uid = new_draft()
    code = send(uid=uid)["confirmation"]
    calls = []
    real = server.imap

    def flaky(account=None):
        calls.append(1)
        if len(calls) == 2:  # the session after the SMTP transaction
            raise server.ConnectionTrouble("IMAP connection lost", "EOF")
        return real(account)
    monkeypatch.setattr(server, "imap", flaky)
    result = send(uid=uid, confirmation=code)
    assert result["sent"] is True and result["draft_removed"] is False
    assert result["warnings"] == [
        "The mail WAS sent: do not send it again. Afterwards the IMAP server failed (IMAP connection lost: EOF): "
        f"no copy was saved in Sent and the draft stays in INBOX.Drafts (uid {uid})."]


# --- Gmail: OAuth on SMTP, no copy appended ---

@pytest.fixture
def gmail(monkeypatch, tmp_path, smtp_server):
    monkeypatch.delenv("MAIL_IMAP_HOST")
    monkeypatch.delenv("MAIL_USER")
    monkeypatch.setenv("MAIL_ACCOUNTS_FILE", str(write_accounts(tmp_path, [PERSO, {**WORK, "send": True}])))
    tokens = []

    def access_token(account, fresh=False):
        tokens.append(fresh)
        return ("access-2" if fresh else "access-1"), not fresh
    monkeypatch.setattr(google_oauth, "access_token", access_token)
    monkeypatch.setattr(google_oauth, "forget", lambda account, token: tokens.append(f"forget {token}"))
    fakes = install(monkeypatch, {"perso": FakeIMAP(mailbox_fixture()),
                                  "work": FakeIMAP(gmail_fixture(), caps=GMAIL_CAPS, delimiter="/")})
    return fakes["work"], tokens


def test_gmail_sends_with_xoauth2_and_files_nothing_itself(gmail, smtp_server):
    work, tokens = gmail
    uid = new_draft(account="work", to="alice@example.org")
    preview = send(uid=uid, account="work")
    assert preview["account"] == "work" and preview["folder"] == "[Gmail]/Brouillons"
    result = send(uid=uid, account="work", confirmation=preview["confirmation"])
    assert smtp_server.connections[0][:3] == ("ssl", "smtp.gmail.com", 465)
    assert smtp_server.logins == [("xoauth2", "me@company.com", "access-1")]
    assert [args for cmd, args in work.log if cmd == "APPEND"] == [("[Gmail]/Brouillons", "(\\Draft \\Seen)")]
    assert result["account"] == "work" and result["saved_to"] == SENT and result["draft_removed"] is True
    assert uid not in uids(work, "[Gmail]/Brouillons") and len(work.folders["[Gmail]/Corbeille"]["messages"]) == 2
    assert len(work.folders[server.utf7_encode(ALL)]["messages"]) == 6  # nothing appended anywhere


def test_gmail_renews_a_refused_cached_token_once(gmail, smtp_server):
    _, tokens = gmail
    smtp_server.tokens = {"access-2"}
    uid = new_draft(account="work")
    assert send(uid=uid, account="work", confirmation=send(uid=uid, account="work")["confirmation"])["sent"] is True
    assert tokens == [False, "forget access-1", True] and smtp_server.logins == [("xoauth2", "me@company.com", "access-2")]


def test_sending_is_per_account(gmail, smtp_server):
    uid = new_draft(account="perso")
    with pytest.raises(server.ToolError, match=r'^Sending is disabled for me@example.org: .*"send": true for this account'):
        send(uid=uid, account="perso")
    with pytest.raises(server.ToolError, match="^Several accounts are configured: give account"):
        send(uid=uid)


# --- Confirmation dialog (elicitation) ---

def client_send(arguments, handler=None, mode="auto"):
    async def run():
        async with Client(server.mcp, elicitation_handler=handler, mode=mode) as client:
            result = await client.call_tool("send_draft", arguments, raise_on_error=False)
            return result.is_error, result.content[0].text
    return asyncio.run(run())


def answering(answer, seen):
    async def handler(message, response_type, params, context):
        seen.append(message)
        if isinstance(answer, BaseException):
            raise answer
        return answer
    return handler


@pytest.mark.parametrize("mode", ["auto", "legacy"])  # 2026-07-28 (InputRequiredResult) and handshake-era clients
def test_dialog_accepted_sends_without_a_code(sending, smtp_server, mode):
    uid = new_draft(cc="carol@example.org")
    seen = []
    is_error, text = client_send({"uid": uid}, answering({"value": True}, seen), mode)
    result = json.loads(text)
    assert not is_error and result["sent"] is True and "confirmation" not in result, text
    assert seen[0].startswith("Send this mail now? It cannot be undone.\nFrom: me@example.org\nTo: Bob <bob@example.org>"
                              "\nCc: carol@example.org\nSubject: Devis\n\nBonjour Bob, Voici le devis.")
    assert len(smtp_server.received) == 1


@pytest.mark.parametrize("mode", ["auto", "legacy"])
@pytest.mark.parametrize("answer,legacy_note", [
    ({"value": False}, "declined sending in the confirmation dialog"),
    (ElicitResult(action="decline"), "declined sending in the confirmation dialog"),
    (ElicitResult(action="cancel"), "closed the confirmation dialog without approving"),
])
def test_dialog_declined_or_dismissed_sends_nothing_and_gives_no_code(sending, smtp_server, mode, answer, legacy_note):
    uid = new_draft()
    is_error, text = client_send({"uid": uid}, answering(answer, []), mode)
    result = json.loads(text)
    assert not is_error and result["sent"] is False and result["declined"] is True and "confirmation" not in result
    note = legacy_note if mode == "legacy" else "did not approve sending in the confirmation dialog"
    assert f"{note}: nothing was sent." in result["note"], result["note"]
    assert smtp_server.connections == [] and uid in uids(sending, "INBOX.Drafts")


@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_without_dialog_support_the_code_flow_is_used(sending, smtp_server, mode):
    uid = new_draft()
    is_error, text = client_send({"uid": uid}, None, mode)
    preview = json.loads(text)
    assert not is_error and preview["sent"] is False and preview["confirmation"]
    is_error, text = client_send({"uid": uid, "confirmation": preview["confirmation"]}, None, mode)
    assert not is_error and json.loads(text)["sent"] is True


def test_a_dialog_the_client_fails_to_show_falls_back_to_the_code(sending, smtp_server):
    uid = new_draft()
    is_error, text = client_send({"uid": uid}, answering(RuntimeError("no UI"), []), "legacy")
    preview = json.loads(text)
    assert not is_error and preview["sent"] is False and preview["confirmation"] and smtp_server.connections == []


def test_a_draft_changed_while_the_dialog_was_open_is_not_sent(sending, smtp_server):
    uid = new_draft()

    async def handler(message, response_type, params, context):
        draft = next(m for m in sending.folders["INBOX.Drafts"]["messages"] if m["uid"] == uid)
        draft["raw"] = draft["raw"].replace(b"Voici", b"Voila")
        return {"value": True}
    is_error, text = client_send({"uid": uid}, handler)
    assert is_error and text.startswith("The draft changed since the preview: nothing was sent"), text
    assert smtp_server.received == []
