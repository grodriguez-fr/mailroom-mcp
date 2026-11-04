"""Tests of server.py against a fake IMAP server (no network access, no real mailbox).

Mail subjects and bodies are partly in French on purpose: they exercise accent-insensitive search
and the French quote and disclaimer patterns."""

import email
import os
import re
import subprocess
import sys
from contextlib import contextmanager
from email import policy
from email.message import EmailMessage
from email.utils import parsedate_to_datetime

import pytest

from mailroom_mcp import server

CAPS = b"IMAP4rev1 SORT PREVIEW UIDPLUS MOVE"

TEXT_STRUCTURE = '("text" "plain" ("charset" "utf-8") NIL NIL "7bit" 5 1 NIL NIL NIL)'
ATTACHMENT_STRUCTURE = (
    '(("text" "plain" ("charset" "utf-8") NIL NIL "7bit" 5 1)("application" "pdf" ("name" "devis.pdf") '
    'NIL NIL "base64" 20 NIL ("attachment" ("filename" "devis.pdf")) NIL) "mixed" ("boundary" "x") NIL NIL)')


def mk(uid, subject, sender="Alice <alice@example.org>", date="Tue, 20 Oct 2026 10:00:00 +0000", body="Bonjour",
       flags=(), internal=None, attachment=False, structure=None, to="me@example.org", html=None,
       message_id=None):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, to, subject
    if date:
        msg["Date"] = date
    if message_id:
        msg["Message-ID"] = message_id
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")
    if attachment:
        content = attachment if isinstance(attachment, bytes) else b"%PDF-1.4 fake"
        msg.add_attachment(content, maintype="application", subtype="pdf", filename="devis.pdf")
    # Without a forced structure, the fake server computes BODYSTRUCTURE from the real message.
    return {"uid": uid, "flags": set(flags), "internal": internal or "20-Oct-2026 12:00:00 +0200",
            "raw": msg.as_bytes(), "structure": structure}


def parsed(m):
    cached = m.get("_parsed")
    if cached is None or cached[0] is not m["raw"]:
        cached = m["_parsed"] = (m["raw"], email.message_from_bytes(m["raw"], policy=policy.default))
    return cached[1]


def imap_string(value):
    return "NIL" if value is None else '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def imap_params(pairs):
    pairs = [(k, v) for k, v in pairs if isinstance(v, str)]
    return "(" + " ".join(f"{imap_string(k)} {imap_string(v)}" for k, v in pairs) + ")" if pairs else "NIL"


def encoded_payload(part) -> bytes:
    return part.get_payload().encode("utf-8", "surrogateescape")


def bodystructure(part) -> str:
    """BODYSTRUCTURE of a Python message, in RFC 3501 format (with extension fields, like Dovecot)."""
    disposition = part.get_content_disposition()
    disp = "NIL"
    if disposition:
        filename = part.get_filename()
        disp = f"({imap_string(disposition)} {imap_params([('filename', filename)] if filename else [])})"
    params = (part.get_params() or [])[1:]
    if part.is_multipart():
        children = "".join(bodystructure(p) for p in part.get_payload())
        return f"({children} {imap_string(part.get_content_subtype())} {imap_params(params)} {disp} NIL NIL)"
    payload = encoded_payload(part)
    fields = (f"{imap_string(part.get_content_maintype())} {imap_string(part.get_content_subtype())} "
              f"{imap_params(params)} {imap_string(part.get('Content-ID'))} NIL {imap_string(str(part.get('Content-Transfer-Encoding', '7bit')))} {len(payload)}")
    if part.get_content_maintype() == "text":
        lines = payload.count(b"\n")
        fields += f" {lines}"
    return f"({fields} NIL {disp} NIL NIL)"


def section_content(m, section) -> bytes:
    """Encoded content of a section (BODY[1.2]), without its MIME headers."""
    if section == "TEXT":
        return m["raw"].split(b"\n\n", 1)[-1]
    part = parsed(m)
    for index in section.split("."):
        part = part.get_payload()[int(index) - 1] if part.is_multipart() else part
    return encoded_payload(part)


def uid_numbers(spec):
    numbers = set()
    for part in spec.split(","):
        lo, _, hi = part.partition(":")
        numbers |= set(range(int(lo), int(hi or lo) + 1))
    return numbers


class FakeIMAP:
    """Mimics imaplib.IMAP4_SSL for the commands used by server.py.

    Like a real server, it ignores case but does not fold accents.
    """

    def __init__(self, folders, caps=CAPS, delimiter="."):
        self.folders = folders  # name (modified UTF-7) -> {"flags": str, "messages": [mk(...)]}
        self.caps = caps
        self.delimiter = delimiter
        self.current = None
        self.literal = None
        self.log = []      # (command, arguments)
        self.selects = []  # (folder, read-only)
        self.sent_bytes = 0          # literal bytes returned by FETCH
        self.subscribe_reply = ("OK", [b"Subscribe completed."])
        self.subscribed = []

    def capability(self):
        return "OK", [self.caps]

    def list(self):
        return "OK", [f'({v["flags"]}) "{self.delimiter}" "{name}"'.encode() for name, v in self.folders.items()]

    def status(self, mailbox, items):
        name = mailbox.strip('"')
        msgs = self.folders[name]["messages"]
        unseen = sum("\\Seen" not in m["flags"] for m in msgs)
        return "OK", [f'"{name}" (MESSAGES {len(msgs)} UNSEEN {unseen})'.encode()]

    def select(self, mailbox, readonly=False):
        name = mailbox.strip('"')
        self.selects.append((name, readonly))
        if name not in self.folders:
            return "NO", [b"unknown"]
        self.current = name
        return "OK", [b"1"]

    def logout(self):
        pass

    def _next_uid(self, name):
        return max((m["uid"] for m in self.folders[name]["messages"]), default=0) + 1

    def append(self, mailbox, flags, date_time, message):
        name = mailbox.strip('"')
        self.log.append(("APPEND", (name, flags)))
        if name not in self.folders:
            return "NO", [b"[TRYCREATE] Mailbox doesn't exist: " + name.encode()]
        uid = self._next_uid(name)
        self.folders[name]["messages"].append({"uid": uid, "flags": set(flags.strip("()").split()),
                                               "internal": "20-Oct-2026 12:00:00 +0200", "raw": message, "structure": None})
        if b"UIDPLUS" in self.caps:
            return "OK", [f"[APPENDUID 1 {uid}] Append completed.".encode()]
        return "OK", [b"Append completed."]

    def create(self, mailbox):
        name = mailbox.strip('"')
        self.log.append(("CREATE", (name,)))
        if name in self.folders:
            return "NO", [b"[ALREADYEXISTS] Mailbox already exists"]
        self.folders[name] = {"flags": "\\HasNoChildren", "messages": []}
        return "OK", [b"Create completed."]

    def subscribe(self, mailbox):
        self.log.append(("SUBSCRIBE", (mailbox.strip('"'),)))
        if self.subscribe_reply[0] == "OK":
            self.subscribed.append(mailbox.strip('"'))
        return self.subscribe_reply

    def _msgs(self):
        return self.folders[self.current]["messages"]

    @staticmethod
    def _sent_ts(m):
        date = parsed(m).get("Date")
        return parsedate_to_datetime(str(date)).timestamp() if date else server.parse_internaldate(m["internal"])

    def _search(self, args):
        args = list(args)
        if args[:2] == ["CHARSET", "UTF-8"]:
            args = args[2:]
        out, i = list(self._msgs()), 0
        while i < len(args):
            match, i = self._criterion(args, i)
            out = [m for m in out if match(m)]
        return out

    def _criterion(self, args, i):
        """(predicate, next position) of the search key at args[i]: NOT and OR take keys, as in RFC 3501."""
        key = args[i]
        if key == "NOT":
            inner, j = self._criterion(args, i + 1)
            return (lambda m: not inner(m)), j
        if key == "OR":
            left, j = self._criterion(args, i + 1)
            right, k = self._criterion(args, j)
            return (lambda m: left(m) or right(m)), k
        if key in ("FROM", "TO", "SUBJECT", "TEXT", "BODY"):
            if i + 1 < len(args):
                val, j = args[i + 1].strip('"'), i + 2
            else:  # term sent as a literal
                val, self.literal, j = self.literal.decode(), None, i + 1
            needle = val.casefold()
            if key == "TEXT":
                return (lambda m: needle in m["raw"].decode("utf-8", errors="replace").casefold()), j
            if key == "BODY":
                return (lambda m: needle in m["raw"].split(b"\n\n", 1)[-1].decode("utf-8", errors="replace").casefold()), j
            return (lambda m: needle in str(parsed(m).get(key.title()) or "").casefold()), j
        if key == "HEADER":
            field, val = args[i + 1], args[i + 2].strip('"').casefold()
            return (lambda m: val in str(parsed(m).get(field) or "").casefold()), i + 3
        if key in ("SENTSINCE", "SENTBEFORE"):
            day = server.parse_internaldate(f"{args[i + 1]} 00:00:00 +0000")
            sent = lambda m: self._sent_ts(m) // 86400 * 86400
            return (lambda m: sent(m) >= day if key == "SENTSINCE" else sent(m) < day), i + 2
        if key == "X-GM-THRID":
            return (lambda m: str(self._thrid(m)) == args[i + 1]), i + 2
        if key == "UID":
            wanted = uid_numbers(args[i + 1])
            return (lambda m: m["uid"] in wanted), i + 2
        flags = {"UNSEEN": lambda m: "\\Seen" not in m["flags"], "FLAGGED": lambda m: "\\Flagged" in m["flags"],
                 "ANSWERED": lambda m: "\\Answered" in m["flags"], "UNANSWERED": lambda m: "\\Answered" not in m["flags"],
                 "UNDRAFT": lambda m: "\\Draft" not in m["flags"], "ALL": lambda m: True}
        if key not in flags:
            raise AssertionError(f"search key not handled by the fake server: {key}")
        return flags[key], i + 1

    def uid(self, command, *args):
        self.log.append((command, args))
        if command == "SEARCH":
            return "OK", [" ".join(str(m["uid"]) for m in self._search(args)).encode()]
        if command == "SORT":
            assert args[0] == "(REVERSE DATE)"
            found = sorted(self._search(args[2:]), key=lambda m: (-self._sent_ts(m), -m["uid"]))
            return "OK", [" ".join(str(m["uid"]) for m in found).encode()]
        if command == "FETCH":
            return "OK", self._fetch(args[0], args[1])
        if command in ("MOVE", "COPY", "STORE", "EXPUNGE"):  # missing UIDs: OK without doing anything, like Dovecot
            wanted = uid_numbers(args[0])
            hit = [m for m in self._msgs() if m["uid"] in wanted]
            hit_ids = {id(m) for m in hit}
            if command in ("MOVE", "COPY"):
                target = args[1].strip('"')
                for m in hit:
                    self.folders[target]["messages"].append({**m, "uid": self._next_uid(target), "flags": set(m["flags"])})
                if command == "MOVE":
                    self.folders[self.current]["messages"] = [m for m in self._msgs() if id(m) not in hit_ids]
            elif command == "STORE" and "X-GM-LABELS" in args[1]:  # Gmail: dropping the Inbox label leaves INBOX
                assert args[1] == "-X-GM-LABELS" and args[2] == "(\\Inbox)"
                ids = {m.get("gmid") for m in hit}
                self.folders["INBOX"]["messages"] = [m for m in self.folders["INBOX"]["messages"] if m.get("gmid") not in ids]
            elif command == "STORE":
                flags = set(args[2].strip("()").split())
                for m in hit:
                    m["flags"] = m["flags"] | flags if args[1].startswith("+") else m["flags"] - flags
            else:
                self.folders[self.current]["messages"] = [
                    m for m in self._msgs() if not (id(m) in hit_ids and "\\Deleted" in m["flags"])]
            return "OK", []
        raise AssertionError(f"command not handled: {command}")

    @staticmethod
    def _thrid(m):
        """Gmail conversation id: explicit ("thrid"), else one conversation per message."""
        return m.get("thrid") or 1786000000000000000 + (m.get("gmid") or m["uid"])

    def _labels(self, m):
        """Gmail labels: explicit ("labels"), else \\Inbox while a copy (same gmid) is in INBOX; a message without
        gmid, added by a test, is in the inbox."""
        if "labels" in m:
            return m["labels"]
        inbox = {x.get("gmid") for x in self.folders.get("INBOX", {}).get("messages", [])}
        return ["\\Inbox"] if m.get("gmid") is None or m["gmid"] in inbox else []

    def _fetch(self, uidset, spec):
        wanted, data = uid_numbers(uidset), []
        for m in self._msgs():
            if m["uid"] not in wanted:
                continue
            pieces = []  # (text, literal content or None)
            if "FLAGS" in spec:
                pieces.append((" FLAGS (%s)" % " ".join(sorted(m["flags"])), None))
            if "INTERNALDATE" in spec:
                pieces.append((f' INTERNALDATE "{m["internal"]}"', None))
            if "X-GM-THRID" in spec and b"X-GM-EXT-1" in self.caps:
                pieces.append((f" X-GM-THRID {self._thrid(m)}", None))
            if "X-GM-LABELS" in spec and b"X-GM-EXT-1" in self.caps:
                labels = " ".join(imap_string(label) for label in self._labels(m))
                pieces.append((f" X-GM-LABELS ({labels})", None))
            if "RFC822.SIZE" in spec:
                pieces.append((f" RFC822.SIZE {len(m['raw'])}", None))
            if "BODYSTRUCTURE" in spec:
                pieces.append((" BODYSTRUCTURE " + (m["structure"] or bodystructure(parsed(m))), None))
            if "PREVIEW" in spec and b"PREVIEW" in self.caps:
                preview = m.get("preview") or " ".join(parsed(m).get_body(("plain", "html")).get_content().split())[:200].encode()
                pieces.append((" PREVIEW", preview))
            fields = re.search(r"BODY\.PEEK\[HEADER\.FIELDS \(([^)]*)\)\]", spec)
            if fields:
                headers = parsed(m)
                block = b"".join(f"{n}: {headers[n]}\r\n".encode() for n in fields.group(1).split() if headers[n] is not None)
                pieces.append((f" BODY[HEADER.FIELDS ({fields.group(1)})]", block + b"\r\n"))
            if "BODY.PEEK[HEADER]" in spec:
                pieces.append((" BODY[HEADER]", m["raw"].split(b"\n\n", 1)[0] + b"\n\n"))
            section = re.search(r"BODY\.PEEK\[(TEXT|\d+(?:\.\d+)*)\](?:<0\.(\d+)>)?", spec)
            if section:
                content = section_content(m, section.group(1))
                if section.group(2):
                    pieces.append((f" BODY[{section.group(1)}]<0>", content[: int(section.group(2))]))
                else:
                    pieces.append((f" BODY[{section.group(1)}]", content))
            if "BODY.PEEK[]" in spec:
                pieces.append((" BODY[]", m["raw"]))
            current = f"{m['uid']} (UID {m['uid']}"
            for text, literal in pieces:
                if literal is None:
                    current += text
                else:
                    data.append((f"{current}{text} {{{len(literal)}}}".encode(), literal))
                    self.sent_bytes += len(literal)
                    current = ""
            data.append((current + ")").encode() if current else b")")
        return data


def mailbox_fixture():
    return {
        "INBOX": {"flags": "\\HasChildren", "messages": [
            mk(1, "Facture d'octobre", date="Mon, 19 Oct 2026 09:00:00 +0000", flags=["\\Seen"]),
            mk(2, "État des lieux", sender="René Dupont <rene@example.org>", date="Wed, 21 Oct 2026 08:00:00 +0200"),
            mk(3, "Contrat", sender="Bob <bob@example.org>", date="Tue, 20 Oct 2026 12:00:00 -0500",
               attachment=True, flags=["\\Seen", "\\Answered"]),
        ]},
        "INBOX.Banque": {"flags": "\\HasNoChildren", "messages": [
            mk(10, "Relevé", date="Thu, 22 Oct 2026 07:00:00 +0000"),
            mk(11, "Etat du compte", date="Sun, 18 Oct 2026 07:00:00 +0000", flags=["\\Seen"]),
        ]},
        "INBOX.Sent": {"flags": "\\HasNoChildren \\Sent", "messages": [
            mk(20, "RE: Contrat", sender="me@example.org", date="Tue, 20 Oct 2026 20:00:00 +0000", flags=["\\Seen"]),
        ]},
        "INBOX.Drafts": {"flags": "\\HasNoChildren \\Drafts", "messages": [mk(30, "Brouillon", flags=["\\Seen"])]},
        "INBOX.spam": {"flags": "\\HasNoChildren \\Junk", "messages": [mk(40, "Gagnez des millions")]},
        "INBOX.Trash": {"flags": "\\HasNoChildren \\Trash", "messages": [mk(50, "Vieux état des lieux", flags=["\\Seen"])]},
        "INBOX.dovecot": {"flags": "\\Noselect \\HasChildren", "messages": []},
        "INBOX.dovecot.sieve": {"flags": "\\HasNoChildren", "messages": []},
    }


@pytest.fixture(autouse=True)
def mail_env(monkeypatch):
    """Test mailbox; dates are checked in Paris time (DST changes on 29 March and 25 October 2026)."""
    monkeypatch.setenv("MAIL_IMAP_HOST", "imap.example.org")
    monkeypatch.setenv("MAIL_USER", "me@example.org")
    monkeypatch.setenv("MAIL_TIMEZONE", "Europe/Paris")
    for name in ("MAIL_IMAP_PORT", "MAIL_PASSWORD_FILE", "MAIL_ALIASES", "MAIL_SEND_ENABLED", "MAIL_SMTP_HOST",
                 "MAIL_SMTP_PORT", "MAIL_SMTP_SECURITY", "MAIL_SEND_LIMIT_PER_HOUR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(server, "CONFIRMATIONS", server.Confirmations())  # send_draft state, per test
    monkeypatch.setattr(server, "SENDS", server.SendLog())


def install(monkeypatch, fk):
    """Replaces the IMAP connection with a fake: one FakeIMAP for any account, or {account name: FakeIMAP}."""
    @contextmanager
    def fake_imap(account=None):
        if isinstance(fk, dict):
            if account is None or account.name not in fk:
                raise server.ToolError(f"Cannot connect to {account.host if account else '?'}:993: refused")
            yield fk[account.name]
        else:
            yield fk
    monkeypatch.setattr(server, "imap", fake_imap)
    return fk


@pytest.fixture
def fake(monkeypatch):
    return install(monkeypatch, FakeIMAP(mailbox_fixture()))


def ids(result):
    return [(m["folder"], m["uid"]) for m in result["messages"]]


# --- normalization, dates ---

def test_fold_ignores_accents_case_and_ligatures():
    assert server.fold("  État des  LIEUX ") == "etat des lieux"
    assert server.fold("Cœur de Noël") == "coeur de noel"
    assert server.fold(None) == ""


@pytest.mark.parametrize("raw,expected", [
    ("Wed, 21 Oct 2026 08:00:00 +0200", "2026-10-21T08:00:00+02:00"),
    ("Tue, 20 Oct 2026 12:00:00 -0500", "2026-10-20T19:00:00+02:00"),
    ("Tue, 20 Oct 2026 12:00:00 -0000", "2026-10-20T14:00:00+02:00"),
    ("Tue, 20 Oct 2026 12:00:00 GMT", "2026-10-20T14:00:00+02:00"),
    ("Mon, 26 Oct 2026 12:00:00 +0000", "2026-10-26T13:00:00+01:00"),  # after the switch to winter time (25 October)
    ("Sun, 29 Mar 2026 00:59:00 +0000", "2026-03-29T01:59:00+01:00"),
    ("Sun, 29 Mar 2026 01:00:00 +0000", "2026-03-29T03:00:00+02:00"),
])
def test_dates_are_iso_in_mail_timezone(raw, expected):
    assert server.iso(server.date_key(raw, None)) == expected


def test_dates_default_to_utc_and_follow_mail_timezone(monkeypatch):
    raw = "Wed, 21 Oct 2026 08:00:00 +0200"
    monkeypatch.delenv("MAIL_TIMEZONE")
    assert server.iso(server.date_key(raw, None)) == "2026-10-21T06:00:00+00:00"
    monkeypatch.setenv("MAIL_TIMEZONE", "America/New_York")
    assert server.iso(server.date_key(raw, None)) == "2026-10-21T02:00:00-04:00"


def test_unknown_timezone_is_a_clear_error(fake, monkeypatch):
    monkeypatch.setenv("MAIL_TIMEZONE", "Mars/Olympus")
    with pytest.raises(server.ConfigError, match="MAIL_TIMEZONE: unknown time zone 'Mars/Olympus'"):
        server.settings()
    with pytest.raises(server.ConfigError, match="MAIL_TIMEZONE"):
        server.search_messages("INBOX", days=2)


@pytest.mark.parametrize("missing", ["MAIL_IMAP_HOST", "MAIL_USER"])
def test_missing_host_or_user_is_a_clear_error_before_any_connection(monkeypatch, missing):
    monkeypatch.setenv(missing, " ")
    with pytest.raises(server.ConfigError, match=f"^Missing configuration: set {missing} \\("):
        server.settings()
    with pytest.raises(server.ConfigError, match=missing):
        server.connect()


def test_settings_defaults_and_port_validation(monkeypatch):
    cfg = server.settings()
    assert (cfg["host"], cfg["port"], cfg["user"]) == ("imap.example.org", 993, "me@example.org")
    assert cfg["password_file"] == os.path.expanduser("~/.config/mailroom-mcp/password")
    monkeypatch.setenv("MAIL_IMAP_PORT", "imaps")
    with pytest.raises(server.ConfigError, match="MAIL_IMAP_PORT"):
        server.settings()


def test_startup_without_configuration_exits_with_the_message():
    env = {k: v for k, v in os.environ.items() if not k.startswith("MAIL_")}
    result = subprocess.run([sys.executable, "-m", "mailroom_mcp", "--check"], env=env,
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 1, result.stderr
    assert "Missing configuration: set MAIL_IMAP_HOST" in result.stderr and "MAIL_USER" in result.stderr


def test_invalid_date_header_falls_back_to_internaldate():
    key = server.date_key("pas une date", "20-Oct-2026 12:00:00 +0200")
    assert server.iso(key) == "2026-10-20T12:00:00+02:00"
    assert server.date_key(None, None) == 0.0 and server.iso(0.0) is None


def test_uid_ranges():
    assert server.uid_ranges([9, 1, 2, 3, 5, 4, 12, 13]) == "1:5,9,12:13"
    assert server.uid_ranges([7]) == "7"


# --- validation ---

@pytest.mark.parametrize("kwargs,message", [
    ({"limit": 0}, "limit"), ({"limit": -1}, "limit"), ({"limit": 1000}, "limit"), ({"limit": 101}, "limit"),
    ({"offset": -1}, "offset"),
    ({"since": "yesterday"}, "Invalid date for since"), ({"before": "2026-13-40"}, "Invalid date for before"),
    ({"since": "2026-10-20", "before": "2026-10-01"}, "earlier than"),
    ({"since": "2026-10-20", "before": "2026-10-20"}, "earlier than"),
    ({"folder": "Nope"}, "not found"), ({"folder": []}, "empty list"),
])
def test_search_rejects_bad_arguments_with_explicit_message(fake, kwargs, message):
    with pytest.raises(server.ToolError, match=message):
        server.search_messages(**kwargs)
    assert fake.log == []  # nothing was sent to the IMAP server


@pytest.mark.parametrize("field", ["text", "subject", "sender", "recipient"])
@pytest.mark.parametrize("value", ["x\r\nA1 DELETE INBOX.Archive", "x\nA1 LOGOUT", "x\x00", "été\r\nA1 LOGOUT"])
def test_search_terms_cannot_inject_imap_commands(fake, monkeypatch, field, value):
    monkeypatch.setattr(server, "LOCAL_FILTER_MAX", 0)  # also forces the fallback to the server search
    with pytest.raises(server.ToolError, match="forbidden"):
        server.search_messages(**{field: value})
    sent = [str(a) for _, args in fake.log for a in args]
    assert not any("\n" in a or "\r" in a for a in sent)


def test_limit_bounds_are_accepted(fake):
    assert server.search_messages(limit=1)["returned"] == 1
    assert server.search_messages(limit=100)["returned"] == 3


# --- folders ---

def searched(fake):
    return list(dict.fromkeys(name for name, _ in fake.selects))


def test_star_excludes_trash_junk_drafts_sent_and_technical(fake):
    result = server.search_messages("*")
    assert searched(fake) == ["INBOX", "INBOX.Banque"]
    assert set(result["folders_excluded"]) == {"INBOX.Drafts", "INBOX.spam", "INBOX.Trash", "INBOX.Sent"}
    assert {f for f, _ in ids(result)} == {"INBOX", "INBOX.Banque"}
    assert "folders_searched" not in result


def test_star_can_include_excluded_folders_but_never_technical_ones(fake):
    result = server.search_messages("*", include_excluded_folders=True)
    assert {"INBOX.Trash", "INBOX.spam", "INBOX.Sent", "INBOX.Drafts"} <= set(searched(fake))
    assert "INBOX.dovecot.sieve" not in searched(fake) and "folders_excluded" not in result


def test_folder_list_and_case_insensitive_name(fake):
    result = server.search_messages(["inbox", "INBOX.Banque", "INBOX"])
    assert searched(fake) == ["INBOX", "INBOX.Banque"] and result["total"] == 5
    assert server.search_messages("INBOX.Trash")["total"] == 1  # a folder asked for by name is not excluded


def test_unread_across_all_folders_is_one_call(fake):
    result = server.search_messages("*", unread_only=True)
    assert ids(result) == [("INBOX.Banque", 10), ("INBOX", 2)]
    assert all(m["unread"] and m["folder"] for m in result["messages"])


def test_list_folders_hides_technical_folders(fake):
    names = [f["name"] for f in server.list_folders()["items"]]
    assert "INBOX.dovecot" not in names and "INBOX.dovecot.sieve" not in names
    assert "INBOX.Trash" in names
    assert "INBOX.dovecot.sieve" in [f["name"] for f in server.list_folders(include_technical=True)["items"]]


# --- sorting and pagination ---

def test_sorted_by_message_date_not_by_uid_across_folders(fake):
    result = server.search_messages("*")
    assert [m["subject"] for m in result["messages"]] == [
        "Relevé", "État des lieux", "Contrat", "Facture d'octobre", "Etat du compte"]
    dates = [m["date"] for m in result["messages"]]
    assert dates == sorted(dates, reverse=True)
    assert result["messages"][1]["date"] == "2026-10-21T08:00:00+02:00"


def test_single_folder_sorted_by_date_even_if_uid_order_differs(fake):
    fake.folders["INBOX"]["messages"][0]["raw"] = mk(1, "Très récent", date="Thu, 22 Oct 2026 23:00:00 +0000")["raw"]
    assert [m["uid"] for m in server.search_messages("INBOX")["messages"]] == [1, 2, 3]


def test_pagination_covers_everything_without_duplicates(fake):
    full = ids(server.search_messages("*", limit=100))
    pages, offset = [], 0
    while True:
        page = server.search_messages("*", limit=2, offset=offset)
        assert page["total"] == len(full) and page["returned"] == len(page["messages"])
        assert "offset" not in page and "limit" not in page and "capped" not in page
        pages += ids(page)
        if not page["has_more"]:
            assert page["next_offset"] is None
            break
        assert page["next_offset"] == offset + page["returned"]
        offset = page["next_offset"]
    assert pages == full and len(set(pages)) == len(pages)


def test_offset_beyond_total_is_an_empty_page_with_a_warning(fake):
    late = server.search_messages("*", offset=500)
    assert (late["total"], late["returned"], late["has_more"], late["next_offset"], late["messages"]) == (5, 0, False, None, [])
    assert late["warnings"] == ["offset 500 is past the end (5 messages): the whole list has already been read."]
    groups = server.search_messages("*", group_by="sender", offset=3)
    assert groups["groups"] == [] and "past the end (3 groups)" in groups["warnings"][0]
    empty = server.search_messages("INBOX", unread_only=True, subject="nonexistent")  # offset 0: empty list, no warning
    assert empty["total"] == 0 and "warnings" not in empty
    assert "warnings" not in server.search_messages("*", offset=4)  # last position: a real page


# --- accents ---

@pytest.mark.parametrize("query", ["etat des lieux", "ETAT DES LIEUX", "état des lieux", "État des Lieux"])
def test_subject_search_ignores_accents_and_case(fake, query):
    assert ids(server.search_messages("INBOX", subject=query)) == [("INBOX", 2)]


def test_sender_search_ignores_accents(fake):
    assert ids(server.search_messages("*", sender="rene")) == [("INBOX", 2)]
    assert ids(server.search_messages("*", sender="René")) == [("INBOX", 2)]


def test_text_search_matches_accented_subject_and_server_body_hits(fake):
    fake.folders["INBOX.Banque"]["messages"][0]["raw"] = mk(
        10, "Relevé", body="Votre etat de compte", date="Thu, 22 Oct 2026 07:00:00 +0000")["raw"]
    result = server.search_messages("*", text="etat")
    assert {("INBOX", 2), ("INBOX.Banque", 10), ("INBOX.Banque", 11)} <= set(ids(result))
    assert any("accents" in w for w in result["warnings"])


def recipients_fixture(fake):
    fake.folders["INBOX"]["messages"] = [
        mk(1, "Bonjour", to="me@acme.example", body="Rien à voir"),
        mk(2, "Point acme", to="me@acme.example", date="Wed, 21 Oct 2026 08:00:00 +0000"),
        mk(3, "Réunion", to="me@acme.example", body="Le projet Acme avance", date="Thu, 22 Oct 2026 08:00:00 +0000"),
        mk(4, "Facture", sender="Compta <compta@acme.example>", to="me@acme.example"),
        mk(5, "Copie", to="bob@example.org", body="Salut", date="Mon, 19 Oct 2026 08:00:00 +0000"),
    ]
    fake.folders["INBOX"]["messages"][4]["raw"] = fake.folders["INBOX"]["messages"][4]["raw"].replace(
        b"To: bob@example.org", b"To: bob@example.org\nCc: me@acme.example")


@pytest.mark.parametrize("local", [True, False])
def test_text_searches_subject_sender_and_body_but_not_recipients(fake, monkeypatch, local):
    recipients_fixture(fake)
    if not local:
        monkeypatch.setattr(server, "LOCAL_FILTER_MAX", 1)  # server-side search: OR BODY / SUBJECT / FROM
    assert {uid for _, uid in ids(server.search_messages("INBOX", text="acme"))} == {2, 3, 4}
    searches = [args for command, args in fake.log if command in ("SEARCH", "SORT")]
    assert not any("TEXT" in args for args in searches)


@pytest.mark.parametrize("local", [True, False])
def test_text_list_matches_any_term(fake, monkeypatch, local):
    recipients_fixture(fake)
    if not local:
        monkeypatch.setattr(server, "LOCAL_FILTER_MAX", 1)
    result = server.search_messages("INBOX", text=["facture", "invoice", "réunion", "salut"])
    assert {uid for _, uid in ids(result)} == {3, 4, 5}
    assert server.search_messages("INBOX", text=["", "  "])["total"] == 5  # blank terms: no text filter
    with pytest.raises(server.ToolError, match="Line breaks"):
        server.search_messages("INBOX", text=["ok", "x\r\nDELETE INBOX"])


@pytest.mark.parametrize("local", [True, False])
def test_subject_list_matches_any_subject(fake, monkeypatch, local):
    if not local:
        monkeypatch.setattr(server, "LOCAL_FILTER_MAX", 1)  # server search: one per subject, united
    result = server.search_messages("*", subject=["contrat", "État des lieux", "nothing"])
    assert set(ids(result)) == {("INBOX", 2), ("INBOX", 3)}
    unaccented = set(ids(server.search_messages("*", subject=["etat"])))
    assert unaccented == ({("INBOX", 2), ("INBOX.Banque", 11)} if local else {("INBOX.Banque", 11)})  # server: as typed
    both = server.search_messages("*", subject=["etat", "Relevé"], sender="alice")  # sender still required
    assert set(ids(both)) == {("INBOX.Banque", 10), ("INBOX.Banque", 11)}
    assert server.search_messages("INBOX", subject=["", " "])["total"] == 3  # blank terms: no subject filter
    with pytest.raises(server.ToolError, match="Line breaks"):
        server.search_messages("INBOX", subject=["ok", "x\r\nDELETE INBOX"])


def test_subject_list_is_limited_like_text():
    with pytest.raises(server.ToolError, match="subject: a string or a list of at most 10 strings"):
        server.search_messages("INBOX", subject=[str(i) for i in range(11)])
    with pytest.raises(server.ToolError, match="^sender: a string$"):
        server.search_messages("INBOX", sender=["a", "b"])


def test_accent_filter_composes_with_other_criteria(fake):
    assert ids(server.search_messages("*", subject="etat", unread_only=True)) == [("INBOX", 2)]


def test_big_folder_falls_back_to_server_search_with_warning(fake, monkeypatch):
    monkeypatch.setattr(server, "LOCAL_FILTER_MAX", 2)
    result = server.search_messages("INBOX", subject="Contrat")
    assert ids(result) == [("INBOX", 3)]
    assert "accent-insensitive search not applied" in result["warnings"][0]
    with pytest.raises(server.ToolError, match="filter by attachment"):
        server.search_messages("INBOX", has_attachments=True)


# --- filters and enriched fields ---

def test_answered_and_attachment_filters(fake):
    assert ids(server.search_messages("INBOX", answered=True)) == [("INBOX", 3)]
    assert ids(server.search_messages("INBOX", answered=False)) == [("INBOX", 2), ("INBOX", 1)]
    assert ids(server.search_messages("INBOX", has_attachments=True)) == [("INBOX", 3)]
    assert ids(server.search_messages("INBOX", has_attachments=False)) == [("INBOX", 2), ("INBOX", 1)]


def test_sent_folder_is_out_of_star_but_reachable_by_name_or_role(fake):
    assert "INBOX.Sent" in server.search_messages("*", answered=False)["folders_excluded"]
    assert ids(server.search_messages("Sent")) == [("INBOX.Sent", 20)]
    assert ids(server.search_messages("INBOX.Sent", subject="contrat")) == [("INBOX.Sent", 20)]  # named: not excluded
    own = server.search_messages("INBOX.Sent", answered=False)  # but your own mail awaits no reply from you
    assert own["total"] == 0 and own["excluded_from_me"] == 1


def test_date_filters_use_message_date(fake):
    result = server.search_messages("*", since="2026-10-20", before="2026-10-22")
    assert {m["subject"] for m in result["messages"]} == {"État des lieux", "Contrat"}


def test_rows_are_enriched(fake):
    rows = {m["uid"]: m for m in server.search_messages("INBOX")["messages"]}
    contract = rows[3]
    assert contract["has_attachments"] is True and contract["answered"] is True and "unread" not in contract
    assert "size" not in contract and contract["folder"] == "INBOX"
    assert "has_attachments" not in rows[2] and rows[2]["unread"] is True
    assert rows[1]["snippet"] == "Bonjour"


def test_inline_image_and_signature_are_not_attachments(fake):
    inline = ('(("text" "plain" ("charset" "utf-8") NIL NIL "7bit" 5 1)("image" "png" ("name" "a.png") "<cid>" NIL "base64" 9 '
              'NIL ("inline" ("filename" "a.png")) NIL) "related" ("boundary" "x") NIL NIL)')
    signed = ('(("text" "plain" NIL NIL NIL "7bit" 5 1)("application" "pkcs7-signature" ("name" "smime.p7s") NIL NIL "base64" 9)'
              ' "signed" NIL)')
    fake.folders["INBOX"]["messages"][0]["structure"] = inline
    fake.folders["INBOX"]["messages"][1]["structure"] = signed
    rows = {m["uid"]: m for m in server.search_messages("INBOX")["messages"]}
    assert "has_attachments" not in rows[1] and "has_attachments" not in rows[2]


def test_snippet_is_truncated_to_150_characters_and_cleaned(fake):
    fake.folders["INBOX"]["messages"][0]["preview"] = ("[cid:image001.png@01D] " + "mot " * 80).encode()
    snippet = next(m for m in server.search_messages("INBOX")["messages"] if m["uid"] == 1)["snippet"]
    assert len(snippet) <= server.SNIPPET_CHARS and snippet.endswith("…") and "cid:" not in snippet


@pytest.mark.parametrize("raw,expected", [
    # Style sheet left by an HTML preview, at-rules included.
    ("body{margin:0;padding:0} .wrapper td{color:#333;font-family:Arial} @media only screen and (max-width:600px)"
     "{.col{width:100% !important}} Bonjour Guillaume, voici votre relevé.", "Bonjour Guillaume, voici votre relevé."),
    # A style sheet or a tag cut short by the end of the preview.
    ("Votre facture 96 <styl", "Votre facture 96"),
    ("Bonjour <style type=\"text/css\">p { margin: 0; } .x { color", "Bonjour"),
    # Invisible characters of marketing preheaders.
    ("Votre commande\u200b\u034f \u00ad\u200c\ufeff\u2060 est prête\u00a0!", "Votre commande est prête !"),
    # Bare URLs, alone or in brackets (Outlook's plain text), and separator lines.
    ("Voir le document https://example.com/a?b=c&d=1 ou <https://x.example> [https://y.example/z] ____ ==== fin",
     "Voir le document ou fin"),
    # Outlook forward or reply header block, French and English: the subject stays.
    ("________________________________ De : Alice Dupont <alice@example.org> Envoyé : lundi 2 novembre 2026 10:12 "
     "À : Guillaume <me@example.org> Cc : Bob <bob@example.org> Objet : RE: Devis Bonjour Guillaume,",
     "RE: Devis Bonjour Guillaume,"),
    ("-----Original Message----- From: Bob <bob@example.org> Sent: Monday, November 2, 2026 9:00 AM To: Me "
     "<me@example.org> Subject: Contract Hello", "Contract Hello"),
    # "View in your browser" placeholders.
    ("View this email in your browser Bonjour", "Bonjour"),
    ("Si vous ne parvenez pas à lire ce message, cliquez ici. Nouveautés d'octobre", "Nouveautés d'octobre"),
    ("This is a multi-part message in MIME format. Hello", "Hello"),
    # A real person's mail stays as it is.
    ("Salut, on se voit demain à 10 h ? Alice <alice@example.org> 06 12 34 56 78",
     "Salut, on se voit demain à 10 h ? Alice <alice@example.org> 06 12 34 56 78"),
    ("De rien ! Je t'envoie le devis demain.", "De rien ! Je t'envoie le devis demain."),
    ("Prix : {total: 12 €} et {à voir}", "Prix : {total: 12 €} et {à voir}"),
    ("a:hover{text-decoration:none} .x{} Bonjour", "Bonjour"),
])
def test_snippets_are_cleaned_of_markup_urls_and_boilerplate(raw, expected):
    assert server.snippet(raw, 300) == expected


def test_cleaned_preview_reaches_search_rows(fake):
    fake.folders["INBOX"]["messages"][0]["preview"] = "\u200b\u034f ____ View in browser https://x.example Bonjour".encode()
    row = next(m for m in server.search_messages("INBOX")["messages"] if m["uid"] == 1)
    assert row["snippet"] == "Bonjour"


def test_partial_html_body_cut_inside_a_style_sheet(monkeypatch):
    html = "<html><head><style>body{margin:0} " + ".a{color:red} " * 400 + "</style></head><body>Bonjour</body></html>"
    install(monkeypatch, FakeIMAP({"INBOX": {"flags": "\\HasNoChildren", "messages": [
        mk(1, "Html", body="x", html=html)]}}, caps=b"IMAP4rev1 SORT"))
    fk_msg = server.search_messages("INBOX")["messages"][0]
    assert "{" not in fk_msg.get("snippet", "") and "color" not in fk_msg.get("snippet", "")


def test_snippet_falls_back_to_partial_body_without_preview(monkeypatch):
    fk = install(monkeypatch, FakeIMAP({"INBOX": {"flags": "\\HasNoChildren", "messages": [
        mk(1, "Texte", body="Bonjour,\n\nVoici un texte assez long pour le fallback.", flags=["\\Seen"]),
        mk(2, "Html", body="x", html="<html><head><style>p{}</style></head><body><p>Contenu <b>HTML</b> utile</p></body></html>"),
    ]}}, caps=b"IMAP4rev1 SORT"))
    rows = {m["uid"]: m for m in server.search_messages("INBOX")["messages"]}
    assert rows[1]["snippet"] == "Bonjour, Voici un texte assez long pour le fallback."
    assert "x" in rows[2]["snippet"]
    assert not any("PREVIEW" in str(args) for _, args in fk.log)


def test_works_without_sort_capability(monkeypatch):
    fk = install(monkeypatch, FakeIMAP({"INBOX": {"flags": "\\HasNoChildren", "messages": [
        mk(1, "Ancien", date="Mon, 19 Oct 2026 09:00:00 +0000"),
        mk(2, "Récent", date="Thu, 22 Oct 2026 09:00:00 +0000"),
        mk(3, "Milieu", date="Tue, 20 Oct 2026 09:00:00 +0000"),
    ]}}, caps=b"IMAP4rev1 PREVIEW"))
    assert [m["subject"] for m in server.search_messages("INBOX")["messages"]] == ["Récent", "Milieu", "Ancien"]
    assert not any(command == "SORT" for command, _ in fk.log)


# --- read-only ---

def test_search_and_read_never_write_or_mark_read(fake):
    server.search_messages("*", subject="etat", has_attachments=False)
    server.search_messages("*", unread_only=True)
    server.read_message("INBOX", 2)
    assert fake.selects and all(readonly for _, readonly in fake.selects)
    assert {command for command, _ in fake.log} <= {"SEARCH", "SORT", "FETCH"}
    for command, args in fake.log:
        if command == "FETCH":
            assert not re.search(r"BODY\[|RFC822(?!\.SIZE)", args[1].replace("BODY.PEEK[", "")), args[1]
    assert "\\Seen" not in fake.folders["INBOX"]["messages"][1]["flags"]


def test_group_by_segment_role_and_paging_never_write(fake):
    server.search_messages("*", group_by="sender")
    server.search_messages("*", group_by="folder", unread_only=True)
    server.search_messages(["Banque", "Trash"], limit=1, offset=1)
    server.read_message("corbeille", 50, max_chars=10)
    server.list_folders()
    assert fake.selects and all(readonly for _, readonly in fake.selects)
    assert {command for command, _ in fake.log} <= {"SEARCH", "SORT", "FETCH"}
    assert all("BODY[" not in args[1].replace("BODY.PEEK[", "") for command, args in fake.log if command == "FETCH")


def test_imap_wildcards_in_terms_are_plain_quoted_strings(fake):
    assert server.search_messages("INBOX", subject="*")["total"] == 0
    assert server.search_messages("INBOX", sender="%")["total"] == 0
    with pytest.raises(server.ToolError, match="not found"):
        server.read_message("%", 1)  # a wildcard is never a folder name


def test_message_expunged_between_search_and_fetch_is_not_repeated_on_next_page(fake, monkeypatch):
    real = server.fetch_rows

    def without_uid_3(M, caps, uids, *rest):
        return {u: row for u, row in real(M, caps, uids, *rest).items() if u != 3}
    monkeypatch.setattr(server, "fetch_rows", without_uid_3)
    first = server.search_messages("INBOX", limit=2)  # order: 2, 3, 1; 3 is gone
    assert [m["uid"] for m in first["messages"]] == [2] and first["returned"] == 1
    assert first["next_offset"] == 2 and "capped" not in first
    second = server.search_messages("INBOX", limit=2, offset=first["next_offset"])
    assert [m["uid"] for m in second["messages"]] == [1] and second["has_more"] is False


# --- read_message ---

REPLY = """Merci, c'est noté pour jeudi.

Le mardi 20 octobre 2026 à 10:00, Alice <alice@example.org> a écrit :
> Peux-tu confirmer ?
> Merci
"""


def put(fake, body, subject="Re: sujet", date="Tue, 20 Oct 2026 12:00:00 -0500"):
    fake.folders["INBOX"]["messages"].append(mk(99, subject, body=body, date=date, flags=["\\Seen", "\\Answered"]))


def test_read_message_strips_quotes_and_cid_and_dates_iso(fake):
    put(fake, "[cid:image001.png@01DD5FEB.933D8A20]\n" + REPLY)
    result = server.read_message("INBOX", 99)
    assert result["body"].startswith("Merci, c'est noté pour jeudi.")
    assert "Peux-tu confirmer" not in result["body"] and "cid:" not in result["body"]
    assert result["quotes_stripped"] is True and result["answered"] is True
    assert result["date"] == "2026-10-20T19:00:00+02:00"
    assert "date_original" not in result and "message_id" not in result
    full = server.read_message("INBOX", 99, strip_quotes=False)
    assert "Peux-tu confirmer" in full["body"] and "cid:" not in full["body"] and "quotes_stripped" not in full


def test_read_message_max_chars_default_and_validation(fake):
    put(fake, "mot " * 5000)
    result = server.read_message("INBOX", 99)
    assert len(result["body"]) == server.MAX_CHARS_DEFAULT == 8000
    assert result["next_offset"] == len(result["body"]) and result["body_chars"] > 8000 and "body_truncated" not in result
    for bad in (0, -5, 10 ** 6):
        with pytest.raises(server.ToolError, match="max_chars"):
            server.read_message("INBOX", 99, max_chars=bad)
    with pytest.raises(server.ToolError, match="uid"):
        server.read_message("INBOX", 0)


# --- text cleanup ---

@pytest.mark.parametrize("body", [
    "Ok pour moi.\n\nOn Tue, Oct 20, 2026 at 10:00 AM Alice <alice@example.org> wrote:\n> Can you confirm?\n",
    "Ok pour moi.\n\n-----Message d'origine-----\nDe : Alice\nEnvoyé : mardi\nÀ : moi\nObjet : x\n\nTexte cité",
    "Ok pour moi.\n\n________________________________\nDe : Alice <a@b.fr>\nEnvoyé : mardi 20 octobre 2026 10:00\n"
    "À : moi\nObjet : Test\n\nTexte cité",
    "Ok pour moi.\n\nLe mar. 20 oct. 2026 à 10:00, Alice Très Longue Adresse\n<alice@example.org> a écrit :\n\nTexte cité",
])
def test_clean_body_cuts_quoted_thread(body):
    cleaned, changed = server.clean_body(body)
    assert changed and cleaned.startswith("Ok pour moi.") and "Texte cité" not in cleaned and "Can you confirm" not in cleaned


def test_clean_body_keeps_interleaved_answers_and_removes_quote_blocks():
    cleaned, changed = server.clean_body("> Question 1\n> suite\nRéponse 1\n> Question 2\nRéponse 2")
    assert changed and "Réponse 1" in cleaned and "Réponse 2" in cleaned and "Question" not in cleaned


def test_clean_body_removes_long_disclaimer_but_not_signature():
    disclaimer = ("Ce message et ses pièces jointes sont confidentiels et établis à l'intention exclusive de ses "
                  "destinataires. Si vous l'avez reçu par erreur, merci de le détruire et d'en informer l'expéditeur.")
    cleaned, changed = server.clean_body(
        f"Bonjour, voici le dossier.\n\nCordialement,\nMarie 06 12 34 56 78\n\n{disclaimer}\n\n"
        "Avant d'imprimer, pensez à l'environnement")
    assert changed and "Marie 06 12 34 56 78" in cleaned
    assert "confidentiels" not in cleaned and "imprimer" not in cleaned


def test_clean_body_never_empties_a_message_and_keeps_forwards():
    only_quote = "Le mardi 20 octobre 2026, Alice a écrit :\n> Tout le contenu est ici\n"
    cleaned, changed = server.clean_body(only_quote)
    assert "Tout le contenu est ici" in cleaned and changed is False
    forwarded = "FYI\n\nDe : Alice <a@b.fr>\nEnvoyé : mardi\nÀ : moi\nObjet : Devis\n\nMontant 1200 euros"
    assert "Montant 1200 euros" in server.clean_body(forwarded, forwarded=True)[0]


def test_clean_body_plain_text_is_untouched():
    text = "Bonjour,\n\nRendez-vous jeudi 10h.\n\nBien à vous"
    assert server.clean_body(text) == (text, False)


@pytest.mark.parametrize("body", [
    "Bonjour,\n\nLe processus est décrit :\n- étape 1\n- étape 2\n\nBien à vous",
    "Bonjour,\n\nLe texte ci-dessous est écrit :\nligne utile\n\nBien à vous",
    "Bonjour,\n\nOn Monday we reviewed what John wrote\net il reste des points à traiter.\n\nBien à vous",
    "Votre voyage\n\nDe : Paris Gare de Lyon\nÀ : Lyon Part-Dieu\nDate : 12 novembre 2026\nPlace 42\n\nBon voyage",
])
def test_clean_body_does_not_cut_useful_content(body):
    assert server.clean_body(body) == (body, False)


def test_clean_body_still_cuts_gmail_header_block_and_attribution_without_colon():
    gmail = "Ok pour moi.\n\nDe : Alice <a@b.fr>\nDate : mar. 20 oct. 2026\nObjet : Devis\nÀ : moi\n\nTexte cité"
    assert "Texte cité" not in server.clean_body(gmail)[0]
    bare = "Ok pour moi.\n\nLe 20/10/2026 à 10:00, Alice <a@b.fr> a écrit\nTexte cité"
    assert "Texte cité" not in server.clean_body(bare)[0]


def test_clean_body_keeps_long_legit_paragraph_mentioning_error_before_the_end():
    middle = ("Nous avons constaté un prélèvement effectué par erreur sur votre compte le 12 octobre ; "
              "le montant de 45,90 euros vous sera remboursé sous cinq jours ouvrés.")
    body = f"Bonjour,\n\n{middle}\n\nNous restons à votre disposition.\n\nLe service client\n\nCordialement"
    assert server.clean_body(body) == (body, False)


# --- days (in MAIL_TIMEZONE) ---

def test_days_counts_today_in_mail_timezone(fake, monkeypatch):
    monkeypatch.setattr(server, "today", lambda: server.dt.date(2026, 10, 22))
    result = server.search_messages("*", days=2)
    assert [m["subject"] for m in result["messages"]] == ["Relevé", "État des lieux"]
    assert any("SENTSINCE" in args and "21-Oct-2026" in args for _, args in fake.log)


@pytest.mark.parametrize("kwargs,message", [
    ({"days": 7, "since": "2026-10-01"}, "mutually exclusive"), ({"days": 0}, "days"), ({"days": "7"}, "days"),
    ({"days": True}, "days"), ({"group_by": "subject"}, "group_by"), ({"days": 3, "before": "2000-01-01"}, "earlier than"),
])
def test_days_and_group_by_are_validated_before_any_imap_command(fake, kwargs, message):
    with pytest.raises(server.ToolError, match=message):
        server.search_messages(**kwargs)
    assert fake.log == []


# --- compact rows and size budget ---

def test_rows_omit_owner_recipient_and_false_flags(fake):
    fake.folders["INBOX"]["messages"].append(mk(4, "Réunion", to="Bob <bob@example.org>, Me <ME@example.org>",
                                                date="Tue, 20 Oct 2026 08:00:00 +0000", flags=["\\Seen"]))
    rows = {m["uid"]: m for m in server.search_messages("INBOX")["messages"]}
    assert "to" not in rows[1] and rows[4]["to"].startswith("Bob")
    assert set(rows[1]) == {"uid", "folder", "date", "from", "subject", "snippet"}
    assert set(rows[2]) == {"uid", "folder", "date", "from", "subject", "unread", "snippet"}


@pytest.mark.parametrize("to,shown", [
    ("me@example.org", False),
    ("'me@example.org' <me@example.org>", False),  # Outlook: the parser keeps the quotes and drops the <…> part
    ('"Me, Myself" <ME@Example.org>', False),
    ("me+lists@example.org", False),
    ("Me <me@example.org>, Bob <bob@example.org>", True),
    ("other@example.org", True),
    ("undisclosed-recipients:;", True),
])
def test_to_is_omitted_only_when_it_is_the_mailbox_itself(fake, to, shown):
    fake.folders["INBOX"]["messages"] = [mk(1, "Direct", to=to)]
    row = server.search_messages("INBOX")["messages"][0]
    assert ("to" in row) is shown, row
    assert ("to" in server.read_message("INBOX", 1)) is shown


def test_gmail_addresses_ignore_dots_and_googlemail():
    assert server.is_me("First.Last@googlemail.com", "firstlast@gmail.com")
    assert server.is_me("firstlast+shop@gmail.com", "first.last@gmail.com")
    assert not server.is_me("first.last@example.org", "firstlast@example.org")  # dots only matter outside Gmail
    assert server.addressed_to("Team: a@x.org, 'Me' <me@example.org>;", "me@example.org")
    assert not server.addressed_to("a@x.org", "me@example.org") and not server.addressed_to(None, "me@example.org")


def test_size_budget_shortens_the_page_with_an_explicit_signal_and_resumes_exactly(monkeypatch):
    messages = [mk(i, f"Objet {i} " + "x" * 250, date=f"Tue, {1 + i % 28:02d} Sep 2026 {i % 24:02d}:00:00 +0000")
                for i in range(1, 61)]
    install(monkeypatch, FakeIMAP({"INBOX": {"flags": "\\HasNoChildren", "messages": messages}}))
    first = server.search_messages("INBOX", limit=100)
    assert first["returned"] < 60 and first["has_more"] is True and first["next_offset"] == first["returned"]
    assert first["capped"] == {"reason": "size", "returned": first["returned"], "requested": 100, "resumable": True}
    assert len(server.json.dumps(first["messages"], ensure_ascii=False, separators=(",", ":"))) <= server.RESPONSE_BUDGET
    seen, offset = [], 0
    while True:
        page = server.search_messages("INBOX", limit=100, offset=offset)
        seen += [m["uid"] for m in page["messages"]]
        if not page["has_more"]:
            break
        offset = page["next_offset"]
    assert sorted(seen) == list(range(1, 61)) and len(set(seen)) == 60


def test_page_within_budget_has_no_capped(fake):
    assert "capped" not in server.search_messages("*", limit=3)


# --- group_by ---

def test_group_by_sender_counts_the_whole_filter_not_the_page(fake):
    result = server.search_messages("*", group_by="sender", limit=2)
    assert (result["total"], result["grouped"], result["groups_total"], result["returned"]) == (5, 5, 3, 2)
    assert result["has_more"] is True and result["next_offset"] == 2 and "messages" not in result
    alice, rene = result["groups"]
    assert alice == {"sender": "Alice <alice@example.org>", "folder": "INBOX.Banque", "count": 3, "unread": 1,
                     "latest_date": "2026-10-22T09:00:00+02:00", "latest_subject": "Relevé", "latest_uid": 10}
    assert rene["count"] == 1 and rene["sender"].startswith("René")
    rest = server.search_messages("*", group_by="sender", limit=2, offset=2)
    assert [g["sender"] for g in rest["groups"]] == ["Bob <bob@example.org>"] and rest["next_offset"] is None


def test_group_by_unread_and_by_folder(fake):
    unread = server.search_messages("*", unread_only=True, group_by="sender")
    assert {g["sender"]: (g["count"], g["unread"]) for g in unread["groups"]} == {
        "Alice <alice@example.org>": (1, 1), "René Dupont <rene@example.org>": (1, 1)}
    by_folder = server.search_messages("*", group_by="folder")
    assert [(g["folder"], g["count"]) for g in by_folder["groups"]] == [("INBOX", 3), ("INBOX.Banque", 2)]
    assert list(by_folder["groups"][0])[0] == "folder"


def test_group_by_signals_the_message_cap(fake, monkeypatch):
    monkeypatch.setattr(server, "GROUP_MAX", 2)
    result = server.search_messages("*", group_by="sender")
    assert result["grouped"] == 2 and result["total"] == 5
    assert result["capped"] == {"reason": "limit", "returned": 2, "total": 5, "resumable": False}
    assert any("most recent" in w for w in result["warnings"])


# --- folders: last segment, roles, injection ---

def test_folder_resolves_by_last_segment_and_role(fake):
    assert {f for f, _ in ids(server.search_messages("Banque"))} == {"INBOX.Banque"}
    assert {f for f, _ in ids(server.search_messages("banque"))} == {"INBOX.Banque"}
    assert ids(server.search_messages("Trash")) == [("INBOX.Trash", 50)]
    assert ids(server.search_messages("corbeille")) == [("INBOX.Trash", 50)]
    assert ids(server.search_messages("Junk")) == [("INBOX.spam", 40)]
    assert server.read_message("Banque", 10)["folder"] == "INBOX.Banque"


def test_ambiguous_or_unknown_folder_lists_candidates(fake):
    fake.folders["INBOX.Pro"] = {"flags": "\\HasNoChildren", "messages": []}
    fake.folders["Archives.Pro"] = {"flags": "\\HasNoChildren", "messages": []}
    with pytest.raises(server.ToolError, match="Ambiguous.*INBOX.Pro, Archives.Pro"):
        server.search_messages("Pro")
    with pytest.raises(server.ToolError, match="No Archive folder"):
        server.move_messages("INBOX", [1], "Archive")
    with pytest.raises(server.ToolError, match="not found.*Available folders: INBOX"):
        server.read_message("Nope", 1)


def test_move_to_role_uses_special_use_folder(fake):
    assert server.move_messages("INBOX", [1, 2], "Trash") == {
        "folder": "INBOX", "destination": "INBOX.Trash", "moved": [1, 2], "not_found": []}
    assert ("MOVE", ("1,2", '"INBOX.Trash"')) in fake.log
    assert fake.selects[-1] == ("INBOX", False)
    with pytest.raises(server.ToolError, match="already in"):
        server.move_messages("INBOX.Trash", [50], "corbeille")


@pytest.mark.parametrize("call", [
    lambda: server.search_messages("INBOX\r\nA1 DELETE INBOX"),
    lambda: server.search_messages(["INBOX", "x\nA1 LOGOUT"]),
    lambda: server.read_message("INBOX\r\nA1 DELETE INBOX", 1),
    lambda: server.move_messages("INBOX", [1], "Trash\r\nA1 DELETE INBOX"),
    lambda: server.set_flags("INBOX\x00", [1], read=True),
    lambda: server.create_folder("x\r\nA1 LOGOUT"),
])
def test_folder_names_cannot_inject_imap_commands(fake, call):
    with pytest.raises(server.ToolError, match="forbidden"):
        call()
    sent = [str(a) for _, args in fake.log for a in args] + [name for name, _ in fake.selects]
    assert not any("\n" in a or "\r" in a or "\x00" in a for a in sent)


@pytest.mark.parametrize("name", ["*", "INBOX.%", "  "])
def test_create_folder_rejects_wildcards_and_empty_names(fake, name):
    with pytest.raises(server.ToolError, match="Invalid folder name"):
        server.create_folder(name)


def test_set_flags_requires_a_change(fake):
    with pytest.raises(server.ToolError, match="nothing to change"):
        server.set_flags("INBOX", [1])
    assert server.set_flags("Banque", [10], read=True) == {"folder": "INBOX.Banque", "updated": [10], "not_found": []}


def test_list_folders_root_delimiter_and_order(fake):
    result = server.list_folders()
    assert result["delimiter"] == "."
    assert [f["name"] for f in result["items"]] == [
        "INBOX", "INBOX.Drafts", "INBOX.Sent", "INBOX.spam", "INBOX.Trash", "INBOX.Banque"]
    assert all("delimiter" not in f for f in result["items"])
    assert result["items"][3]["special_use"] == "Junk" and "special_use" not in result["items"][-1]


# --- read_message: offset and next_offset ---

def test_read_message_pages_rebuild_the_whole_text(fake):
    put(fake, "\n\n".join(f"Paragraphe {i} : " + "texte " * 30 for i in range(12)))
    full = server.read_message("INBOX", 99, max_chars=MAX)["body"]
    rebuilt, offset, pages = "", 0, 0
    while True:
        page = server.read_message("INBOX", 99, offset=offset, max_chars=500)
        assert len(page["body"]) <= 500 and page["body_chars"] == len(full)
        rebuilt += page["body"]
        pages += 1
        if page["next_offset"] is None:
            break
        assert page["body"].endswith("\n\n") or page["body"].endswith(" ")
        offset = page["next_offset"]
    assert rebuilt == full and pages > 1


MAX = server.MAX_CHARS_LIMIT


def test_read_message_offset_beyond_end_is_an_empty_body_with_a_warning(fake):
    put(fake, "Court message.")
    late = server.read_message("INBOX", 99, offset=5000)
    assert (late["body"], late["body_chars"], late["next_offset"]) == ("", 14, None)
    assert late["warnings"] == ["offset 5000 is past the end of the text (14 characters): the whole text has already been read."]
    assert "warnings" not in server.read_message("INBOX", 99, offset=13)
    with pytest.raises(server.ToolError, match="offset"):
        server.read_message("INBOX", 99, offset=-1)


# --- answered=false: automated mail left out ---

def mk_auto(uid, subject, sender="Alice <alice@example.org>", **headers):
    m = mk(uid, subject, sender=sender, date="Wed, 21 Oct 2026 09:00:00 +0000")
    msg = parsed(m)
    for name, value in headers.items():
        msg[name.replace("_", "-")] = value
    return {**m, "raw": msg.as_bytes()}


def automated_fixture(fake):
    fake.folders["INBOX"]["messages"] += [
        mk_auto(60, "Lettre d'info", List_Unsubscribe="<mailto:unsub@example.org>"),
        mk_auto(61, "Liste", List_Id="<dev.example.org>"),
        mk_auto(62, "Absent", Auto_Submitted="auto-replied"),
        mk_auto(63, "Promo", Precedence="bulk"),
        mk_auto(64, "Commande expédiée", sender="Boutique <no-reply@shop.example>"),
        mk_auto(65, "Nouvelle connexion", sender="GitHub <notifications@github.example>"),
        mk_auto(66, "Question", sender="Carole <carole@example.org>", Auto_Submitted="no"),
    ]


def test_unanswered_excludes_automated_mail_by_default(fake):
    automated_fixture(fake)
    result = server.search_messages("INBOX", answered=False)
    assert {uid for _, uid in ids(result)} == {1, 2, 66}
    assert result["excluded_automated"] == 6 and result["total"] == 3
    grouped = server.search_messages("INBOX", answered=False, group_by="sender")
    assert grouped["total"] == 3 and grouped["excluded_automated"] == 6
    assert fake.selects and all(readonly for _, readonly in fake.selects)
    assert all("BODY[" not in args[1].replace("BODY.PEEK[", "") for command, args in fake.log if command == "FETCH")


def test_automated_mail_kept_on_request_or_without_answered_false(fake):
    automated_fixture(fake)
    everything = server.search_messages("INBOX", answered=False, automated="include")
    assert everything["total"] == 9 and "excluded_automated" not in everything
    assert server.search_messages("INBOX")["total"] == 10 and "excluded_automated" not in server.search_messages("INBOX")
    assert server.search_messages("INBOX", answered=True)["total"] == 1


def test_automated_filter_skipped_with_a_warning_on_too_many_messages(fake, monkeypatch):
    automated_fixture(fake)
    monkeypatch.setattr(server, "LOCAL_FILTER_MAX", 3)
    result = server.search_messages("INBOX", answered=False)
    assert result["total"] == 9 and "excluded_automated" not in result
    assert any("too many to leave out automated mail, invitations, your own mail and mail not addressed to you" in w for w in result["warnings"])


def test_is_automated_sender_patterns():
    msg = lambda sender: parsed(mk(1, "x", sender=sender))
    for sender in ("ne-pas-repondre@banque.example", "Noreply <noreply@x.example>", "newsletter@x.example",
                   "bounce+abc@x.example", "MAILER-DAEMON@x.example"):
        assert server.is_automated(msg(sender)), sender
    for sender in ("Alice <alice@example.org>", "replies@x.example", "noemie@x.example", "notif-team-lead@x.example"):
        assert not server.is_automated(msg(sender)), sender


def headers_of(text: str):
    return email.message_from_bytes(text.strip().replace("\n", "\r\n").encode() + b"\r\n\r\nBody\r\n", policy=policy.default)


HUMAN_OUTLOOK = """
Return-Path: <alice.martin@corp.example>
From: Alice Martin <alice.martin@corp.example>
To: "'me@example.org'" <me@example.org>
Subject: RE: Devis
Thread-Topic: Devis
Thread-Index: AQHZ1234abcd
Content-Language: fr-FR
X-MS-Has-Attach: yes
X-MS-Exchange-Organization-SCL: 1
X-Auto-Response-Suppress: All
"""
HUMAN_GMAIL = """
Return-Path: <bob.durand@gmail.com>
From: Bob Durand <bob.durand@gmail.com>
To: me@example.org
Subject: Dîner samedi
DKIM-Signature: v=1; a=rsa-sha256; d=gmail.com; s=20230601
"""
INVITE_FROM_A_PERSON = """
From: Carole <carole@example.org>
Sender: Google Calendar <calendar-notification@google.com>
To: me@example.org
Subject: Invitation: Point projet
"""
INFO_WITHOUT_LIST = """
From: Cabinet Durand <info@cabinet-durand.example>
To: me@example.org
Subject: Votre rendez-vous
"""
LIST_FROM_A_PERSON = """
From: Dan <dan@example.com>
To: dev@lists.example.org
List-Id: Dev discussions <dev.lists.example.org>
List-Post: <mailto:dev@lists.example.org>
Precedence: list
Subject: Re: [dev] Release
"""
NEWSLETTER = """
From: Boutique <info@shop.example>
To: me@example.org
List-Unsubscribe: <https://shop.example/u/123>, <mailto:unsub@shop.example>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
Subject: -20 % ce week-end
"""
AUTO_REPLY = """
From: Eve <eve@example.org>
To: me@example.org
Auto-Submitted: auto-replied
X-Autoreply: yes
Subject: Absence du bureau
"""
BOUNCE = """
Return-Path: <>
From: Mail Delivery System <MAILER-DAEMON@mx.example>
To: me@example.org
Subject: Undelivered Mail Returned to Sender
"""
PROJECT_BOT = """
From: Plane <noreply@tracker.example>
To: me@example.org
Subject: OLX-12 Fermeture du ticket
"""
BANK_NOTICE = """
From: La Banque <notification@messagerie.banque.example>
To: me@example.org
Subject: Prise en compte de votre virement
"""

STRIPE_RECEIPT = """
Return-Path: <bounces+123456-abcd-me=example.org@stripe.example>
From: Example SaaS <receipts+acct_1AbCdEfGh@stripe.example>
Reply-To: billing@saas.example
To: me@example.org
Subject: Your receipt from Example SaaS #1234-5678
Feedback-ID: 1.eu-west-1.AbCdEf123=:AmazonSES
X-SES-Outgoing: 2026.10.21-54.240.1.1
"""
AMAZON_ORDER = """
Return-Path: <2026102109000012ab-34cd@eu-west-1.amazonses.example>
From: "Amazon.fr" <auto-confirm@amazon.example>
To: me@example.org
Subject: Votre commande Amazon.fr de "Câble USB-C"
Feedback-ID: 1.eu-west-1.XyZ987=:AmazonSES
"""
AMAZON_SHIPMENT = """
From: "Amazon.fr" <shipment-tracking@amazon.example>
To: me@example.org
Subject: Votre colis est en route
"""
HETZNER_BILLING = """
Return-Path: <billing@hetzner.example>
From: Hetzner Online GmbH <billing@hetzner.example>
To: me@example.org
Subject: Hetzner Online GmbH - Invoice 080000123456
"""
CLOUDFLARE_NOTICE = """
From: Cloudflare <noreply@notify.cloudflare.example>
To: me@example.org
Subject: Your SSL certificate is about to expire
X-SG-EID: =?us-ascii?Q?abc123?=
X-SG-ID: =?us-ascii?Q?def456?=
"""
INSURER_PASSWORD_RESET = """
From: Mon Assurance <security@assurance.example>
To: me@example.org
Subject: Réinitialisation de votre mot de passe
"""
INVOICE_TAGGED = """
From: Example Telecom <invoice+statements@telecom.example>
To: me@example.org
Subject: Your statement is available
"""
MAILGUN_TRANSACTIONAL = """
From: Example App <hello@app.example>
To: me@example.org
Subject: Welcome aboard
X-Mailgun-Sid: WyJhYmMiLCAibWVAZXhhbXBsZS5vcmciXQ==
"""
HETZNER_SUPPORT_REPLY = """
Return-Path: <support@hetzner.example>
From: Hetzner Online GmbH - Support <support@hetzner.example>
To: me@example.org
Subject: Re: [Ticket#2026102103001234] Server reachability
X-OTRS-Loop: no
"""
SUPPORT_REPLY_THROUGH_SES = """
From: Example Support <support@helpdesk.example>
To: me@example.org
Subject: Re: [#4512] Export not working
Feedback-ID: 1.us-east-1.Q1w2E3=:AmazonSES
"""
PERSON_RELAYED_BY_A_PLATFORM = """
From: Grace via Example Market <no-reply@market.example>
Reply-To: Grace <reply+abc123@market.example>
To: me@example.org
Subject: Question about your listing
"""
GOOGLE_INVITE_FROM_A_PERSON = """
Reply-To: Hugo Martin <hugo.martin@gmail.com>
Sender: Google Calendar <calendar-notification@google.com>
From: Hugo Martin <hugo.martin@gmail.com>
To: me@example.org
Subject: Invitation: Point budget @ jeu. 22 oct. 2026 10:00 - 11:00 (CEST) (me@example.org)
Content-Type: multipart/mixed; boundary="0000000000001234"
"""
PERSON_NAMED_ACCOUNT_MANAGER = """
From: Ines <account.manager@agency.example>
To: me@example.org
Subject: Notre rendez-vous de jeudi
"""


@pytest.mark.parametrize("text,automated", [
    (HUMAN_OUTLOOK, False), (HUMAN_GMAIL, False), (INVITE_FROM_A_PERSON, False), (INFO_WITHOUT_LIST, False),
    (LIST_FROM_A_PERSON, True), (NEWSLETTER, True), (AUTO_REPLY, True), (BOUNCE, True), (PROJECT_BOT, True),
    (BANK_NOTICE, True), (STRIPE_RECEIPT, True), (AMAZON_ORDER, True), (AMAZON_SHIPMENT, True),
    (HETZNER_BILLING, True), (CLOUDFLARE_NOTICE, True), (INSURER_PASSWORD_RESET, True), (INVOICE_TAGGED, True),
    (MAILGUN_TRANSACTIONAL, True), (HETZNER_SUPPORT_REPLY, False), (GOOGLE_INVITE_FROM_A_PERSON, False),
    (PERSON_NAMED_ACCOUNT_MANAGER, False),
    # Known limits, documented: a support agent's reply sent through a bulk platform, and a person's message
    # relayed by a platform from a no-reply address, are automated.
    (SUPPORT_REPLY_THROUGH_SES, True), (PERSON_RELAYED_BY_A_PLATFORM, True),
])
def test_is_automated_on_realistic_headers(text, automated):
    assert server.is_automated(headers_of(text)) is automated


def test_is_automated_sender_tokens():
    msg = lambda sender: parsed(mk(1, "x", sender=sender))
    for sender in ("no_reply@x.example", "DoNotReply@x.example", "alerts@bank.example", "alerte@x.example",
                   "news@journal.example", "notify@app.example", "postmaster@x.example", "noreply+abc@x.example"):
        assert server.is_automated(msg(sender)), sender
    for sender in ("newsom@x.example", "alerting.team.lead@x.example", "andrews@x.example", "info@x.example",
                   "contact@x.example", "nora.reply@x.example"):
        assert not server.is_automated(msg(sender)), sender


def test_is_automated_transactional_local_parts():
    msg = lambda sender: parsed(mk(1, "x", sender=sender))
    for sender in ("billing@x.example", "Invoices@x.example", "receipts+acct_123@x.example", "payments@x.example",
                   "order-update@x.example", "orders@x.example", "shipping@x.example", "auto-confirm@x.example",
                   "confirmation@x.example", "account-security@x.example", "security@x.example",
                   "invoice+statements@x.example", "account@x.example"):
        assert server.is_automated(msg(sender)), sender
    for sender in ("support@x.example", "accounts@x.example", "account.manager@x.example", "security-team@x.example",
                   "billing.jane@x.example", "orderly@x.example", "jane.order@x.example", "sales@x.example"):
        assert not server.is_automated(msg(sender)), sender


def test_automated_headers_are_fetched_with_the_row_headers(fake):
    fake.folders["INBOX"]["messages"].append(mk_auto(70, "Reçu", sender="Shop <hello@shop.example>",
                                                     Feedback_ID="1.eu-west-1.abc=:AmazonSES"))
    rows = {m["uid"]: m for m in server.search_messages("INBOX", limit=50)["messages"]}
    assert rows[70]["auto"] is True and "auto" not in rows[2]
    result = server.search_messages("INBOX", answered=False, snippet_chars=0)
    assert 70 not in {uid for _, uid in ids(result)} and result["excluded_automated"] == 1
    assert all("FEEDBACK-ID" in args[1] for command, args in fake.log if command == "FETCH" and "HEADER.FIELDS" in args[1])


def test_automated_works_with_every_filter_and_group_by(fake):
    automated_fixture(fake)
    only = server.search_messages("INBOX", automated="only")
    assert {uid for _, uid in ids(only)} == {60, 61, 62, 63, 64, 65} and all(m["auto"] for m in only["messages"])
    assert "excluded_automated" not in only
    human = server.search_messages("INBOX", automated="exclude", unread_only=True)
    assert {uid for _, uid in ids(human)} == {2, 66} and human["excluded_automated"] == 6
    assert all("auto" not in m for m in human["messages"])
    assert ids(server.search_messages("INBOX", automated="only", subject="promo")) == [("INBOX", 63)]
    groups = server.search_messages("INBOX", group_by="sender")["groups"]
    alice = next(g for g in groups if g["sender"].startswith("Alice"))
    assert alice["count"] == 5 and "auto" not in alice  # Alice: one human mail and four automated ones
    shop = next(g for g in groups if "shop.example" in g["sender"])
    assert shop["auto"] is True
    only_groups = server.search_messages("INBOX", group_by="sender", automated="only")
    assert only_groups["total"] == 6 and all(g["auto"] for g in only_groups["groups"])


def test_rows_mark_automated_mail_by_default(fake):
    automated_fixture(fake)
    rows = {m["uid"]: m for m in server.search_messages("INBOX", limit=50)["messages"]}
    assert rows[64]["auto"] is True and rows[61]["auto"] is True
    assert "auto" not in rows[2] and "auto" not in rows[66]


def test_explicit_automated_wins_over_the_answered_false_default(fake):
    automated_fixture(fake)
    assert server.search_messages("INBOX", answered=False, automated="include")["total"] == 9
    only = server.search_messages("INBOX", answered=False, automated="only")
    assert only["total"] == 6 and "excluded_automated" not in only


def test_screening_fetches_headers_in_chunks_not_per_message(fake):
    automated_fixture(fake)
    server.search_messages("INBOX", automated="exclude", snippet_chars=0)
    fetches = [args for command, args in fake.log if command == "FETCH"]
    assert len(fetches) == 2  # the screening headers, then the rows


def test_only_automated_on_too_many_messages_is_an_error(fake, monkeypatch):
    automated_fixture(fake)
    monkeypatch.setattr(server, "LOCAL_FILTER_MAX", 3)
    with pytest.raises(server.ToolError, match=r"Too many messages to examine \(10\) to filter automated mail"):
        server.search_messages("INBOX", automated="only")
    with pytest.raises(server.ToolError, match="mail not addressed to you"):
        server.search_messages("INBOX", to_me=True)


ICS = "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nSUMMARY:Point budget\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"


def mk_invite(uid, subject, kind="google", sender="Hugo <hugo@example.org>"):
    """Calendar mail as clients send it: Google (text/calendar with a method in the alternative, plus an
    invite.ics attachment), Outlook (text/calendar with a method, no attachment), or a .ics file attached by
    hand (no method, attachment disposition)."""
    m = mk(uid, subject, sender=sender, date="Wed, 21 Oct 2026 09:00:00 +0000")
    msg = parsed(m)
    if kind in ("google", "outlook"):
        msg.add_alternative(ICS, subtype="calendar", params={"method": "REQUEST"})
    if kind == "google":
        msg.add_attachment(ICS.encode(), maintype="application", subtype="ics", filename="invite.ics")
    if kind == "file":
        msg.add_attachment(ICS.encode(), maintype="text", subtype="calendar", filename="event.ics")
    return {**m, "raw": msg.as_bytes()}


def invites_fixture(fake):
    fake.folders["INBOX"]["messages"] += [
        mk_invite(80, "Invitation: Point budget"), mk_invite(81, "Réunion", kind="outlook"),
        mk_invite(82, "Le programme du salon", kind="file"),
        {**mk_invite(83, "Updated invitation", sender="Google Calendar <calendar-notification@google.com>"),
         "flags": set()}]
    m = fake.folders["INBOX"]["messages"][-1]
    m["raw"] = m["raw"].replace(b"Subject:", b"Auto-Submitted: auto-generated\nSubject:", 1)


def test_rows_mark_calendar_invitations(fake):
    invites_fixture(fake)
    rows = {m["uid"]: m for m in server.search_messages("INBOX", limit=50)["messages"]}
    assert rows[80]["invite"] is True and rows[81]["invite"] is True and rows[83]["invite"] is True
    assert "invite" not in rows[82] and "invite" not in rows[2]  # a .ics file attached by hand
    assert "auto" not in rows[80] and rows[83]["auto"] is True
    assert "invite.ics" in [a["filename"] for a in server.read_message("INBOX", 80)["attachments"]]
    assert [a["filename"] for a in server.read_message("INBOX", 82)["attachments"]] == ["event.ics"]


def test_awaiting_my_reply_leaves_invitations_out(fake):
    invites_fixture(fake)
    result = server.search_messages("INBOX", answered=False)
    assert {uid for _, uid in ids(result)} == {1, 2, 82}
    assert result["excluded_invites"] == 2 and result["excluded_automated"] == 1  # 83 counted once, as automated
    grouped = server.search_messages("INBOX", answered=False, group_by="sender")
    assert grouped["total"] == 3 and grouped["excluded_invites"] == 2
    everything = server.search_messages("INBOX", unread_only=True)
    assert {80, 81, 83} <= {uid for _, uid in ids(everything)} and "excluded_invites" not in everything
    screening = [args[1] for command, args in fake.log if command == "FETCH" and "CC" in args[1]]
    assert screening and all(spec.startswith("(UID BODYSTRUCTURE ") and "BODY.PEEK[HEADER.FIELDS" in spec
                             for spec in screening)


def test_invite_detection_without_a_readable_structure():
    item = {"text": '1 (UID 1 BODYSTRUCTURE (("text" "plain" NIL NIL NIL "7bit" 5 1)("text" "calendar" '
                    '("charset" "utf-8" "method" "REQUEST") NIL NIL "7bit" 9 1) "alternative" ("boundary" "b")', "lits": []}
    assert server.item_is_invite(item)
    assert not server.item_is_invite({"text": '1 (UID 1 BODYSTRUCTURE ("text" "plain" NIL', "lits": []})


def test_awaiting_my_reply_leaves_my_own_mail_out(fake):
    fake.folders["INBOX"]["messages"] += [
        mk(90, "Fwd: Devis", sender='"ME@Example.org" <ME+fwd@example.org>', date="Wed, 21 Oct 2026 09:00:00 +0000"),
        mk(91, "Note to self", sender="me@example.org", date="Wed, 21 Oct 2026 09:00:00 +0000")]
    result = server.search_messages("INBOX", answered=False)
    assert {uid for _, uid in ids(result)} == {1, 2} and result["excluded_from_me"] == 2
    assert server.search_messages("INBOX", unread_only=True)["total"] == 3  # 2, 90 and 91: kept without answered


def recipients_mix(fake):
    fake.folders["INBOX"]["messages"] = [
        mk(1, "Direct", to="Me <me@example.org>", date="Mon, 19 Oct 2026 09:00:00 +0000"),
        mk(2, "Avec d'autres", to="bob@example.org, 'me@example.org' <me@example.org>", date="Tue, 20 Oct 2026 09:00:00 +0000"),
        mk(3, "En copie", to="bob@example.org", date="Wed, 21 Oct 2026 09:00:00 +0000"),
        mk(4, "Liste", to="equipe@example.org", date="Thu, 22 Oct 2026 09:00:00 +0000"),
        mk(5, "Déjà répondu", to="me@example.org", flags=["\\Answered"], date="Thu, 22 Oct 2026 10:00:00 +0000"),
    ]
    m = fake.folders["INBOX"]["messages"][2]
    m["raw"] = m["raw"].replace(b"To: bob@example.org", b"To: bob@example.org\nCc: Me <me@example.org>")


def test_awaiting_my_reply_keeps_mail_addressed_to_me_in_to(fake):
    recipients_mix(fake)
    result = server.search_messages("INBOX", answered=False)
    assert {uid for _, uid in ids(result)} == {1, 2} and result["excluded_not_to_me"] == 2
    assert "excluded_automated" not in result
    widened = server.search_messages("INBOX", answered=False, to_me=True)  # To or Cc
    assert {uid for _, uid in ids(widened)} == {1, 2, 3} and widened["excluded_not_to_me"] == 1
    unchecked = server.search_messages("INBOX", answered=False, to_me=False)
    assert unchecked["total"] == 4 and "excluded_not_to_me" not in unchecked
    grouped = server.search_messages("INBOX", answered=False, group_by="sender")
    assert grouped["total"] == 2 and grouped["excluded_not_to_me"] == 2


def test_aliases_are_me_for_to_me_answered_false_and_own_mail(fake, monkeypatch):
    """MAIL_ALIASES: mail delivered here through a work address that forwards to this mailbox is addressed to me;
    mail sent from that address is my own."""
    fake.folders["INBOX"]["messages"] = [
        mk(1, "Direct", to="Me <me@example.org>", date="Mon, 19 Oct 2026 09:00:00 +0000"),
        mk(2, "Via work", sender="Client <client@example.net>", to="Me <Me@Work.example>",
           date="Tue, 20 Oct 2026 09:00:00 +0000"),
        mk(3, "Both", to="me@example.org, me+tag@work.example", date="Tue, 20 Oct 2026 10:00:00 +0000"),
        mk(4, "Fwd: Devis", sender="Me <me@work.example>", to="me@example.org", date="Wed, 21 Oct 2026 09:00:00 +0000"),
        mk(5, "Other", to="bob@example.org", date="Wed, 21 Oct 2026 10:00:00 +0000"),
    ]
    m = fake.folders["INBOX"]["messages"][4]
    m["raw"] = m["raw"].replace(b"To: bob@example.org", b"To: bob@example.org\nCc: me@work.example")
    before = server.search_messages("INBOX", answered=False)
    assert {uid for _, uid in ids(before)} == {1, 3, 4} and before["excluded_not_to_me"] == 2
    assert "excluded_from_me" not in before

    monkeypatch.setenv("MAIL_ALIASES", "me@work.example")
    result = server.search_messages("INBOX", answered=False)
    assert {uid for _, uid in ids(result)} == {1, 2, 3}
    assert result["excluded_from_me"] == 1 and result["excluded_not_to_me"] == 1
    rows = {m["uid"]: m for m in server.search_messages("INBOX")["messages"]}
    assert "to" not in rows[2] and "to" not in rows[3] and rows[5]["to"] == "bob@example.org"
    assert {uid for _, uid in ids(server.search_messages("INBOX", to_me=True))} == {1, 2, 3, 4, 5}
    assert "to" not in server.read_message("INBOX", 2)


def test_rows_show_the_first_two_recipients_and_count_the_others(fake):
    many = "Ann <ann@x.org>, bob@x.org, \"Dupont, Jean\" <jean@x.org>, me@example.org, eve@x.org"
    fake.folders["INBOX"]["messages"] = [
        mk(1, "Many", to=many, date="Mon, 19 Oct 2026 09:00:00 +0000"),
        mk(2, "Two", to="Ann <ann@x.org>, me@example.org", date="Tue, 20 Oct 2026 09:00:00 +0000"),
        mk(3, "Names", to='"Dupont, Jean" <jean@x.org>, Ann <ann@x.org>, bob@x.org', date="Wed, 21 Oct 2026 09:00:00 +0000"),
        mk(4, "Me", to="Me <me@example.org>", date="Thu, 22 Oct 2026 09:00:00 +0000")]
    rows = {m["uid"]: m for m in server.search_messages("INBOX")["messages"]}
    assert rows[1]["to"] == "Ann <ann@x.org>, bob@x.org +3"
    assert rows[2]["to"] == "Ann <ann@x.org>, me@example.org"  # two recipients: the header as is
    assert rows[3]["to"] == '"Dupont, Jean" <jean@x.org>, Ann <ann@x.org> +1'
    assert "to" not in rows[4]
    assert server.read_message("INBOX", 1)["to"] == many  # read_message keeps every recipient
    assert server.short_recipients("Team: a@x.org, b@x.org, c@x.org;") == "a@x.org, b@x.org +1"


def test_long_recipient_lists_no_longer_cap_the_page(fake):
    crowd = ", ".join(f"Person {i} <person{i}@example.net>" for i in range(60))
    fake.folders["INBOX"]["messages"] = [
        mk(i, f"Annonce {i}", to=crowd, date=f"Mon, 19 Oct 2026 {i % 24:02d}:00:00 +0000") for i in range(1, 31)]
    result = server.search_messages("INBOX", limit=30, snippet_chars=0)
    assert result["returned"] == 30 and "capped" not in result and result["next_offset"] is None
    assert all(m["to"] == "Person 0 <person0@example.net>, Person 1 <person1@example.net> +58" for m in result["messages"])
    assert server.json_size(result["messages"]) <= server.RESPONSE_BUDGET


def test_to_me_filter_without_answered(fake):
    recipients_mix(fake)
    assert {uid for _, uid in ids(server.search_messages("INBOX", to_me=True))} == {1, 2, 3, 5}
    assert server.search_messages("INBOX")["total"] == 5  # no check by default


def test_group_by_signals_both_caps(fake, monkeypatch):
    monkeypatch.setattr(server, "GROUP_MAX", 4)
    fit = server.fit
    monkeypatch.setattr(server, "fit", lambda items: fit(items, 300))
    result = server.search_messages("*", group_by="sender")
    capped = result["capped"]
    assert (capped["reason"], capped["returned"], capped["total"], capped["resumable"]) == ("limit", 4, 5, False)
    assert capped["size"] == {"returned": result["returned"], "requested": 20, "resumable": True}
    assert result["has_more"] is True


# --- move_messages and set_flags: missing UIDs ---

def test_move_reports_moved_and_missing_uids(fake):
    result = server.move_messages("INBOX", [1, 999, 2], "Trash")
    assert result["moved"] == [1, 2] and result["not_found"] == [999]
    assert "999" in result["warnings"][0] and "not found" in result["warnings"][0]
    assert ("MOVE", ("1,2", '"INBOX.Trash"')) in fake.log  # only the present UIDs are moved
    assert [m["uid"] for m in fake.folders["INBOX"]["messages"]] == [3]


def test_move_of_absent_uids_is_an_error_and_sends_no_move(fake):
    server.move_messages("INBOX", [1], "Trash")
    fake.log.clear()
    with pytest.raises(server.ToolError, match=r"None of the requested UIDs exists in INBOX \(1, 4242\): nothing was moved"):
        server.move_messages("INBOX", [1, 4242], "Junk")
    assert [command for command, _ in fake.log] == ["SEARCH"]


def test_move_without_move_capability_checks_uids_too(monkeypatch):
    fk = install(monkeypatch, FakeIMAP(mailbox_fixture(), caps=b"IMAP4rev1 UIDPLUS"))
    result = server.move_messages("INBOX", [3, 77], "Trash")
    assert result["moved"] == [3] and result["not_found"] == [77]
    assert [c for c, _ in fk.log] == ["SEARCH", "COPY", "STORE", "EXPUNGE"]
    assert all(args[0] == "3" for c, args in fk.log if c != "SEARCH")


def test_set_flags_reports_updated_and_missing_uids(fake):
    result = server.set_flags("INBOX", [2, 50], read=True)
    assert (result["updated"], result["not_found"]) == ([2], [50])  # 50 is in the trash, not in INBOX
    assert "\\Seen" in fake.folders["INBOX"]["messages"][1]["flags"]
    with pytest.raises(server.ToolError, match="nothing was changed"):
        server.set_flags("INBOX", [50, 51], flagged=True)
    assert not any(c == "STORE" and args[0].startswith("50") for c, args in fake.log)


# --- save_draft: headers, thread, UID ---

def drafts(fake):
    return fake.folders["INBOX.Drafts"]["messages"]


@pytest.mark.parametrize("kwargs,field", [
    ({"subject": "Devis\r\nBcc: spy@example.org"}, "subject"),
    ({"subject": "Devis\nX-Injected: 1"}, "subject"),
    ({"to": "a@example.org\r\nBcc: spy@example.org"}, "to"),
    ({"cc": "b@example.org\nBcc: spy@example.org"}, "cc"),
    ({"subject": "nul\x00"}, "subject"),
])
def test_save_draft_refuses_line_breaks_in_headers(fake, kwargs, field):
    arguments = {"to": "a@example.org", "subject": "Devis", "body": "Bonjour", **kwargs}
    with pytest.raises(server.ToolError, match=f"^{field}: line breaks and null characters are forbidden"):
        server.save_draft(**arguments)
    assert len(drafts(fake)) == 1 and not any(c == "APPEND" for c, _ in fake.log)


@pytest.mark.parametrize("to", ["Alice", "a@", "", "  "])
def test_save_draft_refuses_invalid_recipients(fake, to):
    with pytest.raises(server.ToolError, match="^to: "):
        server.save_draft(to=to, subject="x", body="y")
    assert len(drafts(fake)) == 1


def test_save_draft_returns_folder_uid_and_threads_the_reply(fake):
    fake.folders["INBOX"]["messages"].append(mk(5, "Devis", message_id="<orig@example.org>"))
    result = server.save_draft(to="Alice <alice@example.org>", subject="Re: Devis", body="Merci, c'est noté.",
                               reply_to_folder="INBOX", reply_to_uid=5)
    assert result == {"folder": "INBOX.Drafts", "uid": 31, "threaded": True}
    saved = parsed(drafts(fake)[-1])
    assert saved["In-Reply-To"] == "<orig@example.org>" and saved["References"] == "<orig@example.org>"
    assert saved.get_content().strip() == "Merci, c'est noté." and "\\Draft" in drafts(fake)[-1]["flags"]


def test_save_draft_without_uidplus_has_a_null_uid(monkeypatch):
    install(monkeypatch, FakeIMAP(mailbox_fixture(), caps=b"IMAP4rev1 SORT"))
    assert server.save_draft(to="a@example.org", subject="x", body="y") == {
        "folder": "INBOX.Drafts", "uid": None, "threaded": False}


@pytest.mark.parametrize("kwargs,message", [
    ({"reply_to_folder": "Nope", "reply_to_uid": 1}, "Folder not found: 'Nope'"),
    ({"reply_to_folder": "INBOX", "reply_to_uid": 4242}, "Original message 4242 not found in INBOX: draft not saved"),
    ({"reply_to_folder": "INBOX"}, "go together"),
    ({"reply_to_uid": 1}, "go together"),
])
def test_save_draft_with_unknown_origin_saves_nothing(fake, kwargs, message):
    with pytest.raises(server.ToolError, match=re.escape(message)):
        server.save_draft(to="a@example.org", subject="Re: x", body="y", **kwargs)
    assert len(drafts(fake)) == 1 and not any(c == "APPEND" for c, _ in fake.log)


def test_save_draft_origin_without_message_id_warns(fake):
    raw = parsed(fake.folders["INBOX"]["messages"][0])
    assert raw["Message-ID"] is None
    result = server.save_draft(to="a@example.org", subject="Re: x", body="y", reply_to_folder="INBOX", reply_to_uid=1)
    assert result["threaded"] is False and "outside the thread" in result["warnings"][0]


def test_save_draft_never_sends(fake):
    server.save_draft(to="a@example.org", subject="x", body="y")
    assert {c for c, _ in fake.log} <= {"APPEND", "FETCH", "SEARCH"}
    assert not hasattr(server, "smtplib")


# --- read_message: structure first, then the text part only ---

def test_read_message_of_20_mb_fetches_only_the_text_part(fake):
    attachment = bytes(range(256)) * (20 * 1024 * 1024 // 256)
    m = mk(77, "Plans", body="Voici les plans, à valider avant jeudi.", attachment=attachment)
    assert len(m["raw"]) > 20_000_000
    fake.folders["INBOX"]["messages"].append(m)
    result = server.read_message("INBOX", 77)
    assert result["body"] == "Voici les plans, à valider avant jeudi."
    (pdf,) = result["attachments"]
    assert pdf["filename"] == "devis.pdf" and pdf["content_type"] == "application/pdf"
    # Size read from the structure (base64 estimated on CRLF lines; the fake server writes LF: 1.3% off)
    assert abs(pdf["size"] - len(attachment)) / len(attachment) < 0.02
    specs = [args[1] for c, args in fake.log if c == "FETCH"]
    assert not any("BODY.PEEK[]" in spec or "BODY.PEEK[2]" in spec for spec in specs), specs
    assert fake.sent_bytes < 10_000  # headers and text, never the attachment


def test_read_message_prefers_plain_text_in_nested_alternative(fake):
    m = mk(78, "Newsletter", body="Version texte : été 2026, 50 € de remise.", html="<p>Version <b>HTML</b></p>",
           attachment=True)
    fake.folders["INBOX"]["messages"].append(m)
    result = server.read_message("INBOX", 78)
    assert result["body"] == "Version texte : été 2026, 50 € de remise."
    assert [a["filename"] for a in result["attachments"]] == ["devis.pdf"]  # the HTML version is not an attachment
    assert any(args[1] == "(UID BODY.PEEK[1.1])" for c, args in fake.log if c == "FETCH")


def test_read_message_html_only_and_latin1_quoted_printable(fake):
    msg = EmailMessage()
    msg["From"], msg["Subject"], msg["Date"] = "Banque <b@example.org>", "Relevé", "Tue, 20 Oct 2026 10:00:00 +0000"
    msg.set_content("<html><body><p>Solde : 1 200 € ; réglé.</p>" + "<p>ligne</p>" * 30 + "</body></html>",
                    subtype="html", charset="iso-8859-15", cte="quoted-printable")
    fake.folders["INBOX"]["messages"].append({"uid": 79, "flags": set(), "internal": "20-Oct-2026 12:00:00 +0200",
                                              "raw": msg.as_bytes(), "structure": None})
    result = server.read_message("INBOX", 79)
    assert result["body"].startswith("Solde : 1 200 € ; réglé.") and "<p>" not in result["body"]
    assert result["attachments"] == [] and result["unread"] is True
    assert any(args[1] == "(UID BODY.PEEK[TEXT])" for c, args in fake.log if c == "FETCH")


def test_read_message_unknown_uid_is_a_clear_error(fake):
    with pytest.raises(server.ToolError, match="Message 4242 not found in INBOX"):
        server.read_message("INBOX", 4242)


def test_read_message_falls_back_to_full_fetch_when_structure_is_unreadable(fake):
    fake.folders["INBOX"]["messages"][0]["structure"] = '("text" "plain" ((('  # truncated structure
    assert server.read_message("INBOX", 1)["body"] == "Bonjour"
    assert any("BODY.PEEK[]" in args[1] for c, args in fake.log if c == "FETCH")


def test_read_message_tolerates_a_malformed_multipart_disposition(fake):
    # Invalid multipart disposition (a list instead of a string): ignored, the text is still read.
    fake.folders["INBOX"]["messages"][0]["structure"] = (
        '(("text" "plain" NIL NIL NIL "7bit" 7 1 NIL NIL NIL NIL) "mixed" ("boundary" "x") (("inline")) NIL NIL)')
    assert server.read_message("INBOX", 1)["body"] == "Bonjour"


OUTLOOK_IMAGE = ('("image" "png" ("name" "image00{n}.png") "<image00{n}.png@01DB2A3F.5C1D2E40>" "image00{n}.png" '
                 '"base64" 412 NIL ("inline" ("filename" "image00{n}.png" "size" "301")) NIL NIL)')
OUTLOOK_SIGNATURE = (
    '((("text" "plain" ("charset" "utf-8") NIL NIL "base64" 1200 16 NIL NIL ("fr-FR") NIL)'
    '("text" "html" ("charset" "utf-8") NIL NIL "base64" 9000 116 NIL NIL ("fr-FR") NIL) "alternative" '
    '("boundary" "_000_") NIL NIL NIL)' + "".join(OUTLOOK_IMAGE.format(n=n) for n in range(1, 6))
    + ' "related" ("boundary" "_004_" "type" "multipart/alternative") NIL ("fr-FR") NIL)')
GMAIL_INLINE_AND_PDF = (
    '(((("text" "plain" ("charset" "UTF-8") NIL NIL "quoted-printable" 300 10 NIL NIL NIL NIL)'
    '("text" "html" ("charset" "UTF-8") NIL NIL "quoted-printable" 900 20 NIL NIL NIL NIL) "alternative" '
    '("boundary" "a") NIL NIL NIL)("image" "png" ("name" "image.png") "<ii_m1x2y3z40>" NIL "base64" 50000 NIL '
    '("inline" ("filename" "image.png")) NIL NIL) "related" ("boundary" "b") NIL NIL NIL)'
    '("application" "pdf" ("name" "Facture-2026-10.pdf") "<f_m1x2y3z41>" NIL "base64" 120000 NIL '
    '("attachment" ("filename" "Facture-2026-10.pdf")) NIL NIL) "mixed" ("boundary" "c") NIL NIL NIL)')


REAL_STRUCTURES = {
    # Apple Mail: mixed(alternative(plain, related(html, embedded image)), pdf), upper case.
    "apple": ('((("TEXT" "PLAIN" ("CHARSET" "us-ascii") NIL NIL "QUOTED-PRINTABLE" 120 4 NIL NIL NIL NIL)'
              '(("TEXT" "HTML" ("CHARSET" "us-ascii") NIL NIL "QUOTED-PRINTABLE" 900 20 NIL NIL NIL NIL)'
              '("IMAGE" "PNG" ("NAME" "a.png") "<cid1>" NIL "BASE64" 7800 NIL ("INLINE" ("FILENAME" "a.png")) NIL NIL)'
              ' "RELATED" ("TYPE" "text/html" "BOUNDARY" "b2") NIL NIL NIL) "ALTERNATIVE" ("BOUNDARY" "b1") NIL NIL NIL)'
              '("APPLICATION" "PDF" ("NAME" "x.pdf") NIL NIL "BASE64" 7800 NIL ("ATTACHMENT" ("FILENAME" "x.pdf")) NIL NIL)'
              ' "MIXED" ("BOUNDARY" "b0") NIL NIL NIL)',
              ("1.1", "plain"), [("x.pdf", "application/pdf")], 1),
    # Single part without charset or parameters.
    "no charset": ('("TEXT" "PLAIN" NIL NIL NIL "7BIT" 25 2 NIL NIL NIL NIL)', ("TEXT", "plain"), [], 0),
    # Without extension fields (BODY form).
    "no extension": ('(("TEXT" "PLAIN" ("CHARSET" "utf-8") NIL NIL "8BIT" 25 2)("TEXT" "HTML" ("CHARSET" "utf-8") NIL NIL '
                       '"8BIT" 25 2) "ALTERNATIVE")', ("1", "plain"), [], 0),
    # Non-delivery report: the returned message (message/rfc822 with its own multipart) is not the body.
    "report": ('(("text" "plain" ("charset" "us-ascii") NIL NIL "7bit" 300 8 NIL NIL NIL NIL)'
               '("message" "delivery-status" NIL NIL NIL "7bit" 400 NIL NIL NIL NIL)'
               '("message" "rfc822" NIL NIL NIL "7bit" 900 ("Mon, 1 Jan 2026 00:00:00 +0000" "Hi" (("A" NIL "a" "x.org")) '
               'NIL NIL NIL NIL NIL NIL "<m@x>") (("text" "plain" ("charset" "utf-8") NIL NIL "7bit" 10 1 NIL NIL NIL NIL)'
               '("text" "html" ("charset" "utf-8") NIL NIL "7bit" 10 1 NIL NIL NIL NIL) "alternative" ("boundary" "q") NIL NIL NIL)'
               ' 30 NIL NIL NIL NIL) "report" ("report-type" "delivery-status" "boundary" "r") NIL NIL NIL)',
               ("1", "plain"), [(None, "message/delivery-status"), (None, "message/rfc822")], 0),
    # HTML only, unknown charset and encoding.
    "unknown": ('("text" "html" ("charset" "x-unknown-cs") NIL NIL "x-weird" 300 8 NIL NIL NIL NIL)', ("TEXT", "html"), [], 0),
    # Outlook: five signature logos (image00N.png, ~300 bytes) referred to by Content-ID in a multipart/related.
    "outlook signature": (OUTLOOK_SIGNATURE, ("1.1", "plain"), [], 5),
    # Gmail: a pasted picture (inline, ii_…) and a PDF attached (attachment, with a Content-ID f_… too).
    "gmail": (GMAIL_INLINE_AND_PDF, ("1.1.1", "plain"), [("Facture-2026-10.pdf", "application/pdf")], 1),
    # Gmail: an attached photo keeps its attachment disposition and Content-ID: a file.
    "gmail photo": ('(("text" "plain" ("charset" "UTF-8") NIL NIL "7bit" 20 1 NIL NIL NIL NIL)("image" "jpeg" '
                    '("name" "IMG_1234.jpg") "<f_m1abc>" NIL "base64" 2000000 NIL ("attachment" ("filename" "IMG_1234.jpg"))'
                    ' NIL NIL) "mixed" ("boundary" "c") NIL NIL NIL)', ("1", "plain"), [("IMG_1234.jpg", "image/jpeg")], 0),
    # Apple Mail: an attached photo is an inline image of the multipart/mixed, without Content-ID: a file.
    "apple photo": ('(("text" "plain" ("charset" "us-ascii") NIL NIL "7bit" 20 1 NIL NIL NIL NIL)("image" "jpeg" '
                    '("name" "IMG_0042.jpeg") NIL NIL "base64" 900000 NIL ("inline" ("filename" "IMG_0042.jpeg")) NIL NIL)'
                    ' "mixed" ("boundary" "a") NIL NIL NIL)', ("1", "plain"), [("IMG_0042.jpeg", "image/jpeg")], 0),
    # S/MIME signed: the signature is not an attachment.
    "smime": ('(("text" "plain" ("charset" "utf-8") NIL NIL "7bit" 20 1 NIL NIL NIL NIL)("application" "pkcs7-signature" '
              '("name" "smime.p7s") NIL NIL "base64" 4000 NIL ("attachment" ("filename" "smime.p7s")) NIL NIL) "signed" '
              '("protocol" "application/pkcs7-signature" "boundary" "s") NIL NIL NIL)', ("1", "plain"), [], 0),
}


@pytest.mark.parametrize("name", list(REAL_STRUCTURES))
def test_real_bodystructures_give_the_text_part_and_attachments(name):
    text, (section, subtype), attachments, inline = REAL_STRUCTURES[name]
    item = {"text": f"1 (UID 5 BODYSTRUCTURE {text})", "lits": []}
    root = server.mime_tree(server.item_structure(item))
    body = server.find_body(root)
    assert (body["section"], body["subtype"]) == (section, subtype)
    files, images = server.attachment_list(root, body)
    assert [(a["filename"], a["content_type"]) for a in files] == attachments and images == inline
    assert server.item_has_attachments(item) is bool(attachments)  # search rows follow the same rule
    assert isinstance(server.decode_part(b"caf\xe9 =C3=A9\r\n", body), str)  # unknown charset or encoding: no exception


def test_signature_images_are_counted_not_listed_in_search_and_read(fake):
    fake.folders["INBOX"]["messages"][0]["structure"] = OUTLOOK_SIGNATURE
    fake.folders["INBOX"]["messages"][1]["structure"] = GMAIL_INLINE_AND_PDF
    rows = {m["uid"]: m for m in server.search_messages("INBOX")["messages"]}
    assert "has_attachments" not in rows[1] and rows[2]["has_attachments"] is True
    assert ids(server.search_messages("INBOX", has_attachments=True)) == [("INBOX", 2), ("INBOX", 3)]
    outlook = server.read_message("INBOX", 1)
    assert outlook["attachments"] == [] and outlook["inline_images"] == 5
    gmail = server.read_message("INBOX", 2)
    assert [a["filename"] for a in gmail["attachments"]] == ["Facture-2026-10.pdf"] and gmail["inline_images"] == 1
    assert "inline_images" not in server.read_message("INBOX", 3)


def test_full_fetch_fallback_applies_the_same_attachment_rule(fake):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = "Alice <alice@example.org>", "me@example.org", "Logo"
    msg.set_content("Bonjour")
    msg.add_alternative("<p>Bonjour <img src='cid:logo'></p>", subtype="html")
    msg.get_payload()[1].add_related(b"\x89PNG fake", maintype="image", subtype="png", cid="<logo>",
                                     filename="image001.png", disposition="inline")
    msg.add_attachment(b"%PDF-1.4 fake", maintype="application", subtype="pdf", filename="devis.pdf")
    fake.folders["INBOX"]["messages"][0].update(raw=msg.as_bytes(), structure='("text" "plain" (((')
    read = server.read_message("INBOX", 1)
    assert [a["filename"] for a in read["attachments"]] == ["devis.pdf"] and read["inline_images"] == 1


def test_body_section_accepts_quoted_strings_and_nil():
    assert server.body_section({"text": '1 (UID 5 BODY[1] \x000\x00)', "lits": [b"Salut"]}) == b"Salut"
    assert server.body_section({"text": '1 (UID 5 BODY[1] "dit \\"oui\\"")', "lits": []}) == b'dit "oui"'
    assert server.body_section({"text": '1 (UID 5 BODY[TEXT]<0> NIL)', "lits": []}) == b""
    assert server.body_section({"text": '1 (UID 5 FLAGS ())', "lits": []}) is None


def test_bodystructure_parser_handles_literals_rfc2231_and_attached_messages():
    text = ('1 (UID 4 BODYSTRUCTURE (("text" "plain" ("charset" "utf-8") NIL NIL "8bit" 12 1 NIL NIL NIL NIL)'
            '("application" "pdf" ("name" \x000\x00) NIL NIL "base64" 780 NIL ("attachment" ("filename*" "utf-8\'\'%C3%A9t%C3%A9.pdf")) NIL NIL)'
            '("message" "rfc822" NIL NIL NIL "7bit" 300 ("date" "subject" NIL NIL NIL NIL NIL NIL NIL "<id>") '
            '("text" "plain" NIL NIL NIL "7bit" 10 1) 12 NIL ("attachment" ("filename" "=?utf-8?q?R=C3=A9ponse?=.eml")) NIL NIL)'
            ' "mixed" ("boundary" "x") NIL NIL NIL))')
    item = {"text": text, "lits": [b'nom "bizarre".pdf']}
    root = server.mime_parts(server.item_structure(item))[0]
    body = server.find_body(root)
    assert body["section"] == "1" and body["encoding"] == "8bit"
    assert server.attachment_list(root, body) == ([
        {"filename": "été.pdf", "content_type": "application/pdf", "size": 570},
        {"filename": "Réponse.eml", "content_type": "message/rfc822", "size": 300}], 0)


# --- IMAP server errors as readable messages ---

def test_server_refusals_are_decoded_messages():
    with pytest.raises(server.ToolError) as error:
        server.ok(("NO", [b"[OVERQUOTA] Quota exceeded (mailbox for user is full)"]), "Save draft")
    assert str(error.value) == ("The IMAP server refused 'Save draft': "
                                "[OVERQUOTA] Quota exceeded (mailbox for user is full)")
    assert "b'" not in str(error.value)
    assert server.server_text([]) == "no details"


def test_imap_exceptions_become_readable_errors(monkeypatch):
    class Broken:
        def logout(self):
            pass
    monkeypatch.setattr(server, "connect", lambda account=None: Broken())
    with pytest.raises(server.ToolError, match=r"^Command refused by the IMAP server: UID command error: BAD Error in IMAP command$"):
        with server.imap():
            raise server.imaplib.IMAP4.error("UID command error: BAD [b'Error in IMAP command']")
    with pytest.raises(server.ToolError, match="^IMAP connection lost: socket error: EOF. Try again."):
        with server.imap():
            raise server.imaplib.IMAP4.abort("socket error: EOF")


def test_timeouts_and_lost_connections_are_retryable_errors(monkeypatch):
    class Slow:
        def logout(self):
            pass
    monkeypatch.setattr(server, "connect", lambda account=None: Slow())
    with pytest.raises(server.ConnectionTrouble) as error:
        with server.imap():
            raise TimeoutError("The read operation timed out")
    assert str(error.value) == "The IMAP server did not answer in time: try again."
    assert error.value.for_write() == ("The IMAP server did not answer in time. "
                                       "The action may have partly happened: check before trying again.")
    work = server.Account(name="work", host="imap.example.org", port=993, user="me@company.com", auth="password")
    with pytest.raises(server.ConnectionTrouble, match=r"^IMAP connection lost \(account work\): \[Errno 104\] reset. Try again.$"):
        with server.imap(work):
            raise ConnectionResetError(104, "reset")


@pytest.mark.parametrize("failure", [TimeoutError("The read operation timed out"), server.imaplib.IMAP4.abort("EOF")])
def test_login_timeout_is_a_retryable_error_not_an_authentication_failure(monkeypatch, tmp_path, failure):
    secret = tmp_path / "password"
    secret.write_text("test-only\n")
    secret.chmod(0o600)
    monkeypatch.setenv("MAIL_PASSWORD_FILE", str(secret))

    class SlowLogin:
        def __init__(self, *args, **kwargs):
            pass

        def login(self, user, password):
            raise failure

        def shutdown(self):
            pass
    monkeypatch.setattr(server.imaplib, "IMAP4_SSL", SlowLogin)
    with pytest.raises(server.ConnectionTrouble) as error:
        server.connect()
    assert str(error.value).endswith("Try again.") or str(error.value).endswith("try again.")
    assert "Authentication failed" not in str(error.value)


# --- create_folder: existing folder, subscription ---

def test_create_folder_subscribes_and_reports_it(fake):
    assert server.create_folder("INBOX.Factures") == {"folder": "INBOX.Factures", "subscribed": True}
    assert fake.subscribed == ["INBOX.Factures"]


def test_create_folder_warns_when_subscription_is_refused(fake):
    fake.subscribe_reply = ("NO", [b"Subscriptions not supported"])
    result = server.create_folder("INBOX.Factures")
    assert result["subscribed"] is False and "INBOX.Factures" in fake.folders
    assert "the server refused the subscription (Subscriptions not supported)" in result["warnings"][0]


def test_create_existing_folder_is_a_clear_error(fake):
    with pytest.raises(server.ToolError, match="The folder INBOX.Banque already exists"):
        server.create_folder("INBOX.Banque")
    assert not any(c == "CREATE" for c, _ in fake.log)


# --- snippet_chars ---

LONG_PREVIEW = ("Bonjour Marie, " + "voici le compte rendu détaillé de la réunion de chantier " * 6).encode()


def test_snippet_chars_bounds_the_snippets(fake):
    for m in fake.folders["INBOX"]["messages"]:
        m["preview"] = LONG_PREVIEW
    default = server.search_messages("INBOX")["messages"]
    assert all(len(m["snippet"]) == server.SNIPPET_CHARS == 100 for m in default)
    short = server.search_messages("INBOX", snippet_chars=40)["messages"]
    assert all(len(m["snippet"]) <= 40 and m["snippet"].endswith("…") for m in short)
    long = server.search_messages("INBOX", snippet_chars=300)["messages"]
    assert all(len(m["snippet"]) > 150 for m in long)


def test_snippet_chars_zero_reads_no_body(fake):
    fake.log.clear()
    rows = server.search_messages("INBOX", snippet_chars=0)["messages"]
    assert rows and all("snippet" not in m for m in rows)
    assert not any("PREVIEW" in args[1] or "TEXT" in args[1] for c, args in fake.log if c == "FETCH")


def test_snippet_chars_without_preview_capability(monkeypatch):
    install(monkeypatch, FakeIMAP({"INBOX": {"flags": "\\HasNoChildren", "messages": [
        mk(1, "Texte", body=LONG_PREVIEW.decode())]}}, caps=b"IMAP4rev1 SORT"))
    assert len(server.search_messages("INBOX", snippet_chars=60)["messages"][0]["snippet"]) == 60


@pytest.mark.parametrize("value", [-1, 301, True, "100"])
def test_snippet_chars_is_validated_before_any_imap_command(fake, value):
    with pytest.raises(server.ToolError, match="snippet_chars"):
        server.search_messages(snippet_chars=value)
    assert fake.log == []


# --- latest_before ---

def test_empty_window_gives_the_latest_message_before_it(fake):
    result = server.search_messages("*", sender="alice", since="2026-10-23")
    assert result["total"] == 0 and result["messages"] == []
    assert result["latest_before"] == {"date": "2026-10-22T09:00:00+02:00", "folder": "INBOX.Banque", "uid": 10,
                                       "from": "Alice <alice@example.org>", "subject": "Relevé"}


def test_latest_before_respects_the_other_filters_and_is_absent_otherwise(fake, monkeypatch):
    unread = server.search_messages("INBOX", unread_only=True, since="2026-10-22")
    assert unread["latest_before"]["uid"] == 2  # 1 is read, so is 3
    assert "latest_before" not in server.search_messages("*", sender="alice")  # no window
    assert "latest_before" not in server.search_messages("*", since="2026-10-20")  # window not empty
    assert "latest_before" not in server.search_messages("*", sender="personne", since="2026-10-23")
    monkeypatch.setattr(server, "today", lambda: server.dt.date(2026, 11, 2))
    assert server.search_messages("Banque", days=2)["latest_before"]["uid"] == 10


# --- answered=false: archived mail ---

def archive_fixture(fake, flags="\\HasChildren \\Archive", name="INBOX.Archive"):
    """Dovecot with an Archive folder (SPECIAL-USE, or by name only) and a yearly subfolder: mail filed there
    after reading it, never answered."""
    fake.folders[name] = {"flags": flags, "messages": [
        mk(60, "Compte rendu", sender="Paul <paul@example.net>", date="Mon, 19 Oct 2026 15:00:00 +0000",
           flags=["\\Seen"]),
        mk(61, "Newsletter", sender="news@example.net", date="Mon, 19 Oct 2026 16:00:00 +0000")]}
    fake.folders[name + ".2025"] = {"flags": "\\HasNoChildren", "messages": [
        mk(70, "Ancien devis", sender="Lea <lea@example.net>", date="Tue, 20 Oct 2026 08:00:00 +0000",
           flags=["\\Seen"])]}


@pytest.mark.parametrize("flags,name", [("\\HasChildren \\Archive", "INBOX.Archive"), ("\\HasChildren", "INBOX.Archives")])
def test_awaiting_my_reply_leaves_archived_mail_out(fake, flags, name):
    archive_fixture(fake, flags, name)
    result = server.search_messages("*", answered=False)
    assert {f for f, _ in ids(result)} == {"INBOX", "INBOX.Banque"}
    assert result["excluded_archived"] == 3  # counted first: the newsletter is archived, not automated
    assert "excluded_automated" not in result
    assert server.search_messages(["*"], answered=False, group_by="folder")["excluded_archived"] == 3
    explicit = server.search_messages("Archive", answered=False)  # named by its role: searched as asked
    assert ids(explicit) == [(name, 60)] and "excluded_archived" not in explicit
    assert ids(server.search_messages(f"{name}.2025", answered=False)) == [(f"{name}.2025", 70)]
    both = server.search_messages(["*", "Archive"], answered=False)
    assert (name, 60) in ids(both) and both["excluded_archived"] == 1  # only the subfolder left out
    everything = server.search_messages("*", unread_only=True)  # other searches keep the archive
    assert (name, 61) in ids(everything) and "excluded_archived" not in everything


# --- answered=false: one row per conversation ---

def with_headers(m, **headers):
    msg = parsed(m)
    for name, value in headers.items():
        msg[name.replace("_", "-")] = value
    return {**m, "raw": msg.as_bytes()}


def outlook_reply(uid, n, sender, date):
    """Reply number n of an Outlook thread started by message 1: RE: subject, In-Reply-To the previous
    message, References from the first one, Thread-Index."""
    ids = [f"<AM9PR02MB{k:04d}C3D1E2F4A5B6C7D8@AM9PR02MB7764.eurprd02.prod.outlook.com>" for k in range(1, n + 1)]
    return with_headers(mk(uid, "RE: Devis toiture - chantier Lyon", sender=sender, date=date), Message_ID=ids[-1],
                        In_Reply_To=ids[-2], References=" ".join(ids[:-1]), Thread_Index="AQHbTXo4c3pQkYQ2ZEqU1w==")


def threads_fixture(fake):
    """Five replies of one Outlook thread (one filed in INBOX.Pro), an unrelated mail with the same subject,
    and a short chain without any Message-ID (subject fallback)."""
    fake.folders["INBOX.Pro"] = {"flags": "\\HasNoChildren", "messages": []}
    replies = [outlook_reply(100 + k, k + 1, sender, f"Tue, 20 Oct 2026 {9 + k:02d}:00:00 +0000")
               for k, sender in enumerate(["Marc <marc@toitures.example>", "Julie <julie@client.example>",
                                           "Marc <marc@toitures.example>", "Paul <paul@client.example>"], 1)]
    filed = outlook_reply(200, 6, "Julie <julie@client.example>", "Tue, 20 Oct 2026 15:30:00 +0000")
    other = with_headers(mk(105, "RE: Devis toiture - chantier Lyon", sender="Nina <nina@ailleurs.example>",
                            date="Mon, 19 Oct 2026 08:00:00 +0000"),
                         Message_ID="<CAF7x1@mail.ailleurs.example>", In_Reply_To="<CAF7x0@mail.ailleurs.example>",
                         References="<CAF7x0@mail.ailleurs.example>")
    bare = [mk(110, "Facture mars", date="Mon, 19 Oct 2026 07:00:00 +0000"),
            mk(111, "TR : facture  MARS", date="Mon, 19 Oct 2026 07:30:00 +0000"),
            mk(112, "Re: Re: Facturé mars", date="Mon, 19 Oct 2026 07:45:00 +0000")]
    fake.folders["INBOX"]["messages"] = replies + [other] + bare
    fake.folders["INBOX.Pro"]["messages"] = [filed]
    fake.folders["INBOX.Banque"]["messages"] = []


def test_awaiting_my_reply_gives_one_row_per_conversation(fake):
    threads_fixture(fake)
    assert server.search_messages("*", limit=50)["total"] == 9  # without answered=false: every message
    result = server.search_messages("*", answered=False)
    rows = [(m["folder"], m["uid"], m.get("in_thread")) for m in result["messages"]]
    assert rows == [("INBOX.Pro", 200, 5), ("INBOX", 105, None), ("INBOX", 112, 3)]
    assert result["total"] == 3 and result["has_more"] is False
    newest = result["messages"][0]
    assert newest["from"] == "Julie <julie@client.example>" and list(newest)[-2:] == ["in_thread", "snippet"]
    inbox = server.search_messages("INBOX", answered=False)  # the thread's newest message in INBOX
    assert [(m["uid"], m.get("in_thread")) for m in inbox["messages"]] == [(104, 4), (105, None), (112, 3)]
    grouped = server.search_messages("*", answered=False, group_by="sender")  # conversations, by newest sender
    assert grouped["total"] == 3 and {g["sender"]: g["count"] for g in grouped["groups"]} == {
        "Julie <julie@client.example>": 1, "Nina <nina@ailleurs.example>": 1, "Alice <alice@example.org>": 1}


def test_conversation_key_and_subject_normalization():
    msg = email.message_from_bytes(b"Subject: AW: WG: Fwd: Re[2]: Bestellung\r\nIn-Reply-To: <b@x> (Bob)\r\n\r\n",
                                   policy=policy.default)
    assert server.thread_key(msg, {"text": "1 (UID 1)", "lits": []}) == ("id", "b@x")
    assert server.thread_key(msg, {"text": "1 (UID 1 X-GM-THRID 1786)", "lits": []}) == ("gmail", "1786")
    assert server.subject_key("AW: WG: Fwd: Re[2]: Bestellung") == server.subject_key("bestellung")
    assert server.subject_key("Re : Écran  cassé") == "ecran casse" and server.subject_key("Return") == "return"


def test_pagination_is_exact_over_conversations(fake):
    threads_fixture(fake)
    fake.folders["INBOX"]["messages"] += [
        mk(120 + k, f"Question {k}", sender=f"P{k} <p{k}@example.net>", date=f"Wed, 21 Oct 2026 {8 + k:02d}:00:00 +0000",
           message_id=f"<q{k}@example.net>") for k in range(4)]
    full = server.search_messages("*", answered=False, limit=100)
    assert full["total"] == 7
    pages, offset = [], 0
    while True:
        page = server.search_messages("*", answered=False, limit=2, offset=offset)
        assert page["total"] == 7 and page["returned"] == len(page["messages"])
        pages += [(m["folder"], m["uid"], m.get("in_thread")) for m in page["messages"]]
        if not page["has_more"]:
            assert page["next_offset"] is None
            break
        offset = page["next_offset"]
    assert pages == [(m["folder"], m["uid"], m.get("in_thread")) for m in full["messages"]]
    last = server.search_messages("*", answered=False, limit=2, offset=6)
    assert last["returned"] == 1 and last["has_more"] is False
