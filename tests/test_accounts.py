"""Several accounts in one server: a Dovecot-like mailbox ("perso", password) and a Gmail-like one ("work",
Google OAuth, labels as folders, French folder names under [Gmail]/). Fake IMAP only, no network."""

import io
import json

import pytest
from test_server import CAPS, FakeIMAP, install, mail_env, mailbox_fixture, mk  # noqa: F401  (autouse fixture)

from mailroom_mcp import google_oauth, server

GMAIL_CAPS = (b"IMAP4rev1 UNSELECT IDLE NAMESPACE QUOTA ID XLIST CHILDREN X-GM-EXT-1 UIDPLUS COMPRESS=DEFLATE "
              b"ENABLE MOVE CONDSTORE ESEARCH UTF8=ACCEPT LIST-EXTENDED LIST-STATUS LITERAL- SPECIAL-USE")
ALL = "[Gmail]/Tous les messages"
SENT = "[Gmail]/Messages envoyés"


def gmail_fixture():
    """Gmail exposes each label as a folder: one message appears in INBOX, in its labels and in All Mail,
    with a different UID in each. `gmid` ties the copies together."""
    def msg(gmid, uid, *args, **kwargs):
        return {**mk(uid, *args, to="me@company.com", **kwargs), "gmid": gmid}

    invite = ("Invitation", "Carol <carol@example.com>", "Wed, 21 Oct 2026 09:30:00 +0000")
    meeting = ("Réunion projet", "Dan <dan@example.com>", "Thu, 22 Oct 2026 06:00:00 +0000")
    alice = ("Devis", "Alice <alice@example.org>", "Mon, 19 Oct 2026 12:00:00 +0000")
    reply = ("Re: Invitation", "Me <me@company.com>", "Wed, 21 Oct 2026 10:00:00 +0000")
    draft = ("Brouillon", "me@company.com", "Wed, 21 Oct 2026 11:00:00 +0000")
    old = ("Ancien", "Erin <erin@example.com>", "Fri, 16 Oct 2026 08:00:00 +0000")
    return {
        "INBOX": {"flags": "\\HasNoChildren", "messages": [
            msg(1, 1, *invite), msg(2, 2, *meeting), msg(3, 3, *alice)]},
        "Pro": {"flags": "\\HasNoChildren", "messages": [msg(2, 7, *meeting)]},
        "[Gmail]": {"flags": "\\HasChildren \\Noselect", "messages": []},
        server.utf7_encode(ALL): {"flags": "\\All \\HasNoChildren", "messages": [
            msg(1, 101, *invite), msg(2, 102, *meeting), msg(3, 103, *alice), msg(4, 104, *reply, flags=["\\Seen"]),
            msg(5, 105, *draft, flags=["\\Seen", "\\Draft"]), msg(6, 106, *old, flags=["\\Seen"])]},
        server.utf7_encode(SENT): {"flags": "\\HasNoChildren \\Sent", "messages": [msg(4, 4, *reply, flags=["\\Seen"])]},
        "[Gmail]/Brouillons": {"flags": "\\Drafts \\HasNoChildren", "messages": [
            msg(5, 5, *draft, flags=["\\Seen", "\\Draft"])]},
        "[Gmail]/Corbeille": {"flags": "\\HasNoChildren \\Trash", "messages": [
            msg(8, 8, "Supprimé", "Frank <frank@example.com>", "Tue, 20 Oct 2026 08:00:00 +0000")]},
        "[Gmail]/Spam": {"flags": "\\HasNoChildren \\Junk", "messages": [
            msg(9, 9, "Gagnez", "spam@example.net", "Tue, 20 Oct 2026 09:00:00 +0000")]},
        "[Gmail]/Suivis": {"flags": "\\Flagged \\HasNoChildren", "messages": []},
    }


def write_accounts(tmp_path, entries):
    for name in ("perso.password", "client.json", "work.token"):
        path = tmp_path / name
        path.write_text("test-only-not-a-real-secret\n")
        path.chmod(0o600)
    path = tmp_path / "accounts.json"
    path.write_text(json.dumps(entries))
    return path


PERSO = {"name": "perso", "host": "imap.example.org", "user": "me@example.org",
         "auth": {"type": "password", "password_file": "perso.password"}}
WORK = {"name": "work", "user": "me@company.com",
        "auth": {"type": "google-oauth", "client_secret_file": "client.json", "refresh_token_file": "work.token"}}


@pytest.fixture
def accounts_env(monkeypatch, tmp_path):
    monkeypatch.delenv("MAIL_IMAP_HOST")
    monkeypatch.delenv("MAIL_USER")
    monkeypatch.setenv("MAIL_ACCOUNTS_FILE", str(write_accounts(tmp_path, [PERSO, WORK])))


@pytest.fixture
def boxes(accounts_env, monkeypatch):
    return install(monkeypatch, {"perso": FakeIMAP(mailbox_fixture()),
                                 "work": FakeIMAP(gmail_fixture(), caps=GMAIL_CAPS, delimiter="/")})


def keys(result):
    return [(m["account"], m["folder"], m["uid"]) for m in result["messages"]]


# --- Folders ---

def test_list_folders_covers_every_account_with_gmail_roles(boxes):
    result = server.list_folders()
    assert [a["account"] for a in result["accounts"]] == ["perso", "work"]
    perso, work = result["accounts"]
    assert perso["delimiter"] == "." and perso["items"][0]["name"] == "INBOX"
    assert work["delimiter"] == "/"
    roles = {i["name"]: i.get("special_use") for i in work["items"]}
    assert roles[ALL] == "All" and roles[SENT] == "Sent" and roles["[Gmail]/Corbeille"] == "Trash"
    assert roles["[Gmail]/Spam"] == "Junk" and roles["[Gmail]/Brouillons"] == "Drafts" and roles["Pro"] is None
    assert "[Gmail]" not in roles  # \Noselect parent
    one = server.list_folders(account="work")
    assert one["account"] == "work" and one["items"] == work["items"]


def test_list_folders_reports_an_unreachable_account_without_hiding_the_others(boxes, monkeypatch):
    install(monkeypatch, {"perso": boxes["perso"]})
    perso, work = server.list_folders()["accounts"]
    assert perso["items"] and work == {"account": "work", "error": "Cannot connect to imap.gmail.com:993: refused"}


# --- Search across accounts ---

def test_star_searches_every_account_sorted_by_date_with_account_on_rows(boxes):
    result = server.search_messages("*", unread_only=True)
    assert keys(result) == [("perso", "INBOX.Banque", 10), ("work", ALL, 102), ("work", ALL, 101),
                            ("perso", "INBOX", 2), ("work", ALL, 103)]
    assert result["total"] == 5 and result["has_more"] is False
    assert all(list(m)[0] == "account" for m in result["messages"])
    assert "to" not in result["messages"][1]  # me@company.com is the work account itself
    assert result["folders_excluded"] == {
        "perso": ["INBOX.Sent", "INBOX.Drafts", "INBOX.spam", "INBOX.Trash"],
        "work": [SENT, "[Gmail]/Brouillons", "[Gmail]/Corbeille", "[Gmail]/Spam"]}


def test_gmail_star_searches_all_mail_once_without_sent_and_drafts(boxes):
    result = server.search_messages("*", account="work")
    assert keys(result) == [("work", ALL, 102), ("work", ALL, 101), ("work", ALL, 103), ("work", ALL, 106)]
    work = boxes["work"]
    assert {name for name, _ in work.selects} == {server.utf7_encode(ALL)}  # INBOX and labels never searched
    search = [args for cmd, args in work.log if cmd == "SEARCH"][0]
    assert search[:4] == ("UNDRAFT", "NOT", "FROM", '"me@company.com"')
    assert result["folders_excluded"] == {"work": [SENT, "[Gmail]/Brouillons", "[Gmail]/Corbeille", "[Gmail]/Spam"]}


def test_gmail_star_with_excluded_folders_adds_trash_and_spam_and_keeps_sent_and_drafts(boxes):
    result = server.search_messages("*", account="work", include_excluded_folders=True, limit=100)
    folders = {(m["folder"], m["uid"]) for m in result["messages"]}
    assert {(ALL, 104), (ALL, 105), ("[Gmail]/Corbeille", 8), ("[Gmail]/Spam", 9)} <= folders
    assert result["total"] == 8 and "folders_excluded" not in result


def test_gmail_label_and_inbox_are_reachable_by_name(boxes):
    assert keys(server.search_messages("Pro", account="work")) == [("work", "Pro", 7)]
    assert [m["uid"] for m in server.search_messages("INBOX", account="work")["messages"]] == [2, 1, 3]
    sent = server.search_messages("Sent", account="work")
    assert keys(sent) == [("work", SENT, 4)]


def test_gmail_filters_compose_with_the_received_only_criteria(boxes):
    result = server.search_messages("*", account="work", sender="reunion", subject="réunion")
    assert result["total"] == 0
    result = server.search_messages("*", account="work", subject="reunion")  # accent-insensitive local filter
    assert keys(result) == [("work", ALL, 102)]
    assert server.search_messages("*", account="work", subject="invitation")["total"] == 1  # not the reply


def test_cross_account_pagination_is_exact(boxes):
    full = keys(server.search_messages("*", limit=100))
    assert len(full) == len(set(full)) == 9
    pages, offset = [], 0
    while offset is not None:
        page = server.search_messages("*", limit=2, offset=offset)
        assert page["total"] == 9
        pages += keys(page)
        offset = page["next_offset"]
    assert pages == full
    dates = [m["date"] for m in server.search_messages("*", limit=100)["messages"]]
    assert dates == sorted(dates, reverse=True)


def test_cross_account_size_cap_resumes_exactly(boxes, monkeypatch):
    full = keys(server.search_messages("*", limit=100))
    fit = server.fit
    monkeypatch.setattr(server, "fit", lambda items: fit(items, 700))
    first = server.search_messages("*", limit=5)
    assert first["capped"]["resumable"] is True and first["returned"] < 5
    pages, offset = [], 0
    while offset is not None:
        page = server.search_messages("*", limit=5, offset=offset)
        pages += keys(page)
        offset = page["next_offset"]
    assert pages == full


def test_group_by_sender_keeps_accounts_apart(boxes):
    result = server.search_messages("*", group_by="sender", limit=100)
    alice = [g for g in result["groups"] if "alice" in g["sender"]]
    assert {(g["account"], g["count"]) for g in alice} == {("perso", 3), ("work", 1)}
    assert result["total"] == sum(g["count"] for g in result["groups"]) == 9
    assert all(list(g)[0] == "account" for g in result["groups"])


def test_group_by_folder_names_account_and_folder(boxes):
    result = server.search_messages("*", group_by="folder")
    assert [(g["account"], g["folder"], g["count"]) for g in result["groups"]] == [
        ("work", ALL, 4), ("perso", "INBOX", 3), ("perso", "INBOX.Banque", 2)]
    assert list(result["groups"][0])[:2] == ["account", "folder"]


def test_latest_before_names_the_account(boxes):
    result = server.search_messages("*", sender="dan", since="2026-10-23")
    assert result["total"] == 0
    assert result["latest_before"] == {"account": "work", "date": "2026-10-22T08:00:00+02:00", "folder": ALL,
                                       "uid": 102, "from": "Dan <dan@example.com>", "subject": "Réunion projet"}


def test_unreachable_account_is_skipped_with_a_warning(boxes, monkeypatch):
    install(monkeypatch, {"perso": boxes["perso"]})
    result = server.search_messages("*", unread_only=True)
    assert {m["account"] for m in result["messages"]} == {"perso"}
    assert result["warnings"] == ["work skipped: Cannot connect to imap.gmail.com:993: refused"]
    with pytest.raises(server.ToolError, match="^Cannot connect"):
        server.search_messages("*", account="work")


def test_folder_missing_in_one_account_is_a_short_warning(boxes):
    result = server.search_messages("Banque")
    assert {m["account"] for m in result["messages"]} == {"perso"}
    assert result["warnings"] == ["work: no folder matches 'Banque'."]
    with pytest.raises(server.ToolError, match="perso: Folder not found: 'Nope'.*work: Folder not found"):
        server.search_messages("Nope")


def test_answered_false_leaves_automated_mail_out_in_every_account(boxes):
    boxes["work"].folders[server.utf7_encode(ALL)]["messages"].append(
        mk(120, "Notification", sender="no-reply@example.com", date="Thu, 22 Oct 2026 10:00:00 +0000"))
    result = server.search_messages("*", answered=False)
    assert ("work", ALL, 120) not in keys(result) and result["excluded_automated"] >= 1


def test_to_is_compared_with_the_row_own_account(boxes):
    """Each row's `to` is compared with the address of its own account, not with another one's."""
    boxes["work"].folders["INBOX"]["messages"] = [
        mk(1, "Direct", to="'me@company.com' <me@company.com>", date="Thu, 22 Oct 2026 10:00:00 +0000"),
        mk(2, "Elsewhere", to="me@example.org", date="Thu, 22 Oct 2026 11:00:00 +0000")]
    boxes["perso"].folders["INBOX"]["messages"] = [
        mk(3, "Perso", to="Me <me@example.org>", date="Thu, 22 Oct 2026 12:00:00 +0000"),
        mk(4, "To work", to="me@company.com", date="Thu, 22 Oct 2026 13:00:00 +0000")]
    rows = {(m["account"], m["uid"]): m for m in server.search_messages("INBOX")["messages"]}
    assert "to" not in rows[("work", 1)] and "to" not in rows[("perso", 3)]
    assert rows[("work", 2)]["to"] == "me@example.org" and rows[("perso", 4)]["to"] == "me@company.com"
    assert "to" not in server.read_message("INBOX", 1, account="work")
    assert server.read_message("INBOX", 4, account="perso")["to"] == "me@company.com"


def test_awaiting_reply_compares_to_with_each_row_own_account(boxes):
    """A mail to the work address found in the perso mailbox (a forward) is not addressed to perso."""
    boxes["work"].folders["INBOX"]["messages"] = [mk(1, "Work direct", to="me@company.com")]
    boxes["perso"].folders["INBOX"]["messages"] = [
        mk(3, "Perso direct", to="Me <me@example.org>"), mk(4, "Forwarded from work", to="me@company.com")]
    result = server.search_messages("INBOX", answered=False)
    assert sorted((m["account"], m["uid"]) for m in result["messages"]) == [("perso", 3), ("work", 1)]
    assert result["excluded_not_to_me"] == 1



def test_awaiting_reply_leaves_out_mail_from_any_configured_account(boxes):
    """A work mail forwarded to the perso mailbox comes from the work address: it awaits no reply."""
    boxes["perso"].folders["INBOX"]["messages"] = [
        mk(3, "Perso direct", to="Me <me@example.org>"),
        mk(4, "Fwd: Contrat", sender="Me <ME+fwd@Company.com>", to="me@example.org"),
        mk(5, "Fwd: Devis", sender="'me@company.com' <me@company.com>", to="me@example.org")]
    boxes["work"].folders["INBOX"]["messages"] = [mk(1, "From perso", sender="me@example.org", to="me@company.com")]
    result = server.search_messages("INBOX", answered=False)
    assert keys(result) == [("perso", "INBOX", 3)] and result["excluded_from_me"] == 3
    assert "excluded_not_to_me" not in result
    one = server.search_messages("INBOX", answered=False, account="perso")
    assert one["total"] == 1 and one["excluded_from_me"] == 2
    assert server.search_messages("INBOX", account="perso")["total"] == 3

def test_aliases_are_per_account_for_to_and_shared_for_own_mail(boxes, monkeypatch, tmp_path):
    """The work address forwards to the Gmail account, where it is an alias: a forward it delivers awaits a reply
    there; a mail the user sent from it is their own mail in every account; it is not perso's address."""
    path = write_accounts(tmp_path, [PERSO, {**WORK, "aliases": ["pro@example.net"]}])
    monkeypatch.setenv("MAIL_ACCOUNTS_FILE", str(path))
    boxes["work"].folders[server.utf7_encode(ALL)]["messages"] = [
        mk(120, "Devis client", sender="Client <client@example.net>", to="Pro <PRO@example.net>",
           date="Thu, 22 Oct 2026 10:00:00 +0000"),
        mk(121, "Fwd: Contrat", sender="Me <pro@example.net>", to="me@company.com", date="Thu, 22 Oct 2026 11:00:00 +0000")]
    boxes["perso"].folders["INBOX"]["messages"] = [
        mk(3, "Perso direct", to="Me <me@example.org>"),
        mk(4, "To the work alias", to="pro@example.net"),
        mk(5, "Fwd: Facture", sender="pro@example.net", to="me@example.org")]
    boxes["perso"].folders["INBOX.Banque"]["messages"] = []
    result = server.search_messages("*", answered=False)
    assert sorted((m["account"], m["uid"]) for m in result["messages"]) == [("perso", 3), ("work", 120)]
    assert result["excluded_from_me"] == 2 and result["excluded_not_to_me"] == 1
    rows = {(m["account"], m["uid"]): m for m in server.search_messages("*")["messages"]}
    assert "to" not in rows[("work", 120)] and rows[("perso", 4)]["to"] == "pro@example.net"


# --- Tools on one account ---

@pytest.mark.parametrize("call", [
    lambda: server.read_message("INBOX", 1),
    lambda: server.move_messages("INBOX", [1], "Trash"),
    lambda: server.set_flags("INBOX", [1], read=True),
    lambda: server.create_folder("Factures"),
    lambda: server.save_draft("a@example.org", "Objet", "Texte"),
])
def test_single_mailbox_tools_require_an_account(boxes, call):
    with pytest.raises(server.ToolError, match=r"^Several accounts are configured: give account, one of "
                                               r"perso \(me@example.org\), work \(me@company.com\)\.$"):
        call()


def test_account_errors_list_the_names(boxes):
    with pytest.raises(server.ToolError, match=r"^Unknown account 'gmail': give one of perso \(me@example.org\), work"):
        server.read_message("INBOX", 1, account="gmail")
    with pytest.raises(server.ToolError, match=r'^account="\*" is only accepted by list_folders and search_messages'):
        server.read_message("INBOX", 1, account="*")
    with pytest.raises(server.ToolError, match="Unknown account 'nope'"):
        server.search_messages("*", account="nope")


def test_account_by_address_and_results_carry_it(boxes):
    read = server.read_message(ALL, 102, account="Me@Company.com")
    assert read["account"] == "work" and read["subject"] == "Réunion projet" and "to" not in read
    assert server.read_message("INBOX", 2, account="perso")["account"] == "perso"
    assert server.set_flags("INBOX", [2], flagged=True, account="perso") == {
        "account": "perso", "folder": "INBOX", "updated": [2], "not_found": []}
    assert server.create_folder("Clients", account="work") == {"account": "work", "folder": "Clients", "subscribed": True}


def test_uids_are_per_account(boxes):
    assert server.read_message("INBOX", 1, account="perso")["subject"] == "Facture d'octobre"
    assert server.read_message("INBOX", 1, account="work")["subject"] == "Invitation"


def test_gmail_archive_from_inbox_moves_to_all_mail(boxes):
    result = server.move_messages("INBOX", [1], "Archive", account="work")
    assert result == {"account": "work", "folder": "INBOX", "destination": ALL, "moved": [1], "not_found": []}
    assert ("MOVE", ("1", f'"{server.utf7_encode(ALL)}"')) in boxes["work"].log
    assert [m["uid"] for m in boxes["work"].folders["INBOX"]["messages"]] == [2, 3]


def test_gmail_archive_from_all_mail_removes_the_inbox_label(boxes):
    result = server.move_messages(ALL, [102], "Archive", account="work")
    assert result["moved"] == [102] and result["destination"] == ALL
    assert ("STORE", ("102", "-X-GM-LABELS", "(\\Inbox)")) in boxes["work"].log
    assert [m["uid"] for m in boxes["work"].folders["INBOX"]["messages"]] == [1, 3]
    assert not any(cmd == "MOVE" for cmd, _ in boxes["work"].log)


def test_gmail_roles_resolve_through_special_use(boxes):
    assert server.move_messages(ALL, [103], "Corbeille", account="work")["destination"] == "[Gmail]/Corbeille"
    assert server.move_messages("INBOX", [2], "Junk", account="work")["destination"] == "[Gmail]/Spam"
    assert server.move_messages("Pro", [7], "Trash", account="work")["destination"] == "[Gmail]/Corbeille"


def test_archive_on_a_dovecot_account_is_unchanged(boxes):
    with pytest.raises(server.ToolError, match="No Archive folder"):
        server.move_messages("INBOX", [1], "Archive", account="perso")


def test_draft_goes_to_the_account_drafts_folder_from_its_address(boxes):
    result = server.save_draft("carol@example.com", "Re: Invitation", "Oui", reply_to_folder="INBOX",
                               reply_to_uid=1, account="work")
    assert result["account"] == "work" and result["folder"] == "[Gmail]/Brouillons"
    saved = boxes["work"].folders["[Gmail]/Brouillons"]["messages"][-1]["raw"]
    assert b"From: me@company.com" in saved and b"company.com>" in saved  # Message-ID domain
    assert len(boxes["perso"].folders["INBOX.Drafts"]["messages"]) == 1


def test_no_server_sort_fetches_dates_of_the_most_recent_only(boxes, monkeypatch):
    monkeypatch.setattr(server, "SORT_FALLBACK_MAX", 2)
    result = server.search_messages("*", account="work")
    assert result["total"] == 4 and any("no server-side sort" in w for w in result["warnings"])
    assert [uid for _, _, uid in keys(result)] == [103, 106, 102, 101]  # 2 highest UIDs by date, then by arrival


# --- One account in the accounts file: output as before ---

def test_a_single_account_file_keeps_the_single_account_output(monkeypatch, tmp_path):
    monkeypatch.delenv("MAIL_IMAP_HOST")
    monkeypatch.delenv("MAIL_USER")
    monkeypatch.setenv("MAIL_ACCOUNTS_FILE", str(write_accounts(tmp_path, [WORK])))
    install(monkeypatch, FakeIMAP(gmail_fixture(), caps=GMAIL_CAPS, delimiter="/"))
    result = server.search_messages("*", unread_only=True)
    assert "account" not in result["messages"][0] and isinstance(result["folders_excluded"], list)
    assert "account" not in server.list_folders()
    assert server.read_message("INBOX", 1, account="work")["subject"] == "Invitation"
    with pytest.raises(server.ToolError, match=r"^Unknown account 'perso': the only account is work \(me@company.com\)\.$"):
        server.read_message("INBOX", 1, account="perso")


def test_env_account_accepts_its_name_or_address(monkeypatch):
    install(monkeypatch, FakeIMAP(mailbox_fixture()))
    assert server.set_flags("INBOX", [2], read=True, account="me@example.org")["updated"] == [2]
    assert server.set_flags("INBOX", [2], read=False, account="default")["updated"] == [2]


def test_instructions_name_every_account(accounts_env):
    text = server.instructions()
    assert "IMAP access to several mailboxes." in text
    assert "perso (me@example.org), work (me@company.com)" in text
    assert "All Mail once" in text and "rows carry account" in text
    assert "the mailbox" not in text


# --- Connections: password and XOAUTH2 (imaplib and the token endpoint are replaced) ---

class Connection:
    accepted_tokens: set = set()

    def __init__(self, host, port, ssl_context=None, timeout=None):
        self.host, self.port, self.calls = host, port, []
        Connection.last = self

    def login(self, user, password):
        self.calls.append(("LOGIN", user))
        if password != "test-only-not-a-real-secret":
            raise server.imaplib.IMAP4.error("[AUTHENTICATIONFAILED] Authentication failed.")
        return "OK", []

    def authenticate(self, mechanism, authobject):
        answer = authobject(b"").decode()
        user, token = answer.split("\x01")[0][5:], answer.split("\x01")[1][12:]
        self.calls.append(("AUTHENTICATE", mechanism, user, token))
        assert answer == f"user={user}\x01auth=Bearer {token}\x01\x01"
        if token not in self.accepted_tokens:
            assert authobject(b'{"status":"400","schemes":"Bearer","scope":"https://mail.google.com/"}') == b""
            raise server.imaplib.IMAP4.error("[AUTHENTICATIONFAILED] Invalid credentials (Failure)")
        return "OK", []

    def shutdown(self):
        self.calls.append(("SHUTDOWN",))

    def logout(self):
        pass


class TokenEndpoint:
    """Stands in for urllib.request.urlopen: answers refresh requests in turn."""

    def __init__(self, *answers):
        self.answers, self.requests = list(answers), []

    def __call__(self, request, timeout=None):
        self.requests.append((request.full_url, dict(google_oauth.urllib.parse.parse_qsl(request.data.decode()))))
        status, body = self.answers.pop(0)
        if status != 200:
            raise google_oauth.urllib.error.HTTPError(request.full_url, status, "error", {},
                                                      io.BytesIO(json.dumps(body).encode()))
        return io.BytesIO(json.dumps(body).encode())


@pytest.fixture
def oauth(accounts_env, monkeypatch, tmp_path):
    (tmp_path / "client.json").write_text(json.dumps({"installed": {
        "client_id": "test.apps.googleusercontent.com", "client_secret": "test-client-secret"}}))
    (tmp_path / "work.token").write_text("test-refresh-token\n")
    monkeypatch.setattr(server.imaplib, "IMAP4_SSL", Connection)
    monkeypatch.setattr(google_oauth, "_cache", {})
    Connection.accepted_tokens = {"access-1", "access-2"}


def work():
    return server.pick_account("work")


def test_password_account_reads_its_own_file(oauth):
    server.connect(server.pick_account("perso"))
    assert Connection.last.host == "imap.example.org" and Connection.last.calls == [("LOGIN", "me@example.org")]


def test_xoauth2_exchanges_the_refresh_token_once_and_caches_the_access_token(oauth, monkeypatch):
    endpoint = TokenEndpoint((200, {"access_token": "access-1", "expires_in": 3599, "token_type": "Bearer"}))
    monkeypatch.setattr(google_oauth.urllib.request, "urlopen", endpoint)
    server.connect(work())
    server.connect(work())
    assert Connection.last.host == "imap.gmail.com" and Connection.last.port == 993
    assert Connection.last.calls == [("AUTHENTICATE", "XOAUTH2", "me@company.com", "access-1")]
    assert endpoint.requests == [(google_oauth.TOKEN_URL, {
        "grant_type": "refresh_token", "refresh_token": "test-refresh-token",
        "client_id": "test.apps.googleusercontent.com", "client_secret": "test-client-secret"})]


def test_xoauth2_renews_an_expired_access_token(oauth, monkeypatch):
    endpoint = TokenEndpoint((200, {"access_token": "access-1", "expires_in": 60}),
                             (200, {"access_token": "access-2", "expires_in": 3600}))
    monkeypatch.setattr(google_oauth.urllib.request, "urlopen", endpoint)
    server.connect(work())  # 60 s is inside the renewal margin: not reused
    server.connect(work())
    assert len(endpoint.requests) == 2 and Connection.last.calls[-1][-1] == "access-2"


def test_xoauth2_refreshes_once_when_imap_refuses_a_cached_token(oauth, monkeypatch):
    endpoint = TokenEndpoint((200, {"access_token": "access-0", "expires_in": 3600}),
                             (200, {"access_token": "access-1", "expires_in": 3600}))
    monkeypatch.setattr(google_oauth.urllib.request, "urlopen", endpoint)
    Connection.accepted_tokens = {"access-0"}
    server.connect(work())
    Connection.accepted_tokens = {"access-1"}  # access-0 revoked early
    server.connect(work())
    assert [c[-1] for c in Connection.last.calls] == ["access-0", "access-1"]


def test_xoauth2_refused_fresh_token_is_an_authentication_error(oauth, monkeypatch):
    monkeypatch.setattr(google_oauth.urllib.request, "urlopen", TokenEndpoint((200, {"access_token": "bad"})))
    with pytest.raises(server.ToolError) as error:
        server.connect(work())
    assert str(error.value).startswith("Authentication failed for me@company.com: [AUTHENTICATIONFAILED] Invalid "
                                       "credentials (Failure) (is IMAP enabled")
    assert "bad" not in str(error.value).replace("Bearer", "") and Connection.last.calls[-1] == ("SHUTDOWN",)


def test_revoked_refresh_token_says_how_to_authorize_again(oauth, monkeypatch, tmp_path):
    endpoint = TokenEndpoint((400, {"error": "invalid_grant", "error_description": "Token has been expired or revoked."}))
    monkeypatch.setattr(google_oauth.urllib.request, "urlopen", endpoint)
    with pytest.raises(server.ToolError) as error:
        server.search_messages("*", account="work")
    text = str(error.value)
    assert text.startswith("Google refused the refresh token of account 'work' (invalid_grant: Token has been "
                           "expired or revoked.)")
    assert f"mailroom-mcp-auth google --client-secret-file {tmp_path / 'client.json'} " \
           f"--refresh-token-file {tmp_path / 'work.token'} --login-hint me@company.com --force" in text
    assert "test-refresh-token" not in text and "test-client-secret" not in text


def test_unreachable_token_endpoint_and_bad_client_file(oauth, monkeypatch, tmp_path):
    def offline(request, timeout=None):
        raise google_oauth.urllib.error.URLError("Name or service not known")
    monkeypatch.setattr(google_oauth.urllib.request, "urlopen", offline)
    with pytest.raises(server.ToolError, match="^Cannot reach Google's token endpoint for account 'work': Name or"):
        server.connect(work())
    (tmp_path / "client.json").write_text(json.dumps({"web": {"client_id": "x", "client_secret": "y"}}))
    with pytest.raises(server.ToolError, match=r"expected a Desktop app client \(this is a Web application client\)"):
        server.connect(work())


def test_missing_refresh_token_file_names_the_auth_command(oauth, tmp_path):
    (tmp_path / "work.token").unlink()
    with pytest.raises(server.ToolError, match=r"^Refresh token of account 'work' not found: create the file .*"
                                               r"\(run: mailroom-mcp-auth google"):
        server.connect(work())


# --- UIDs from the wrong folder on Gmail ---

HINT = f'Rows from folder "*" on this account point to {ALL}: pass that folder with'


def test_read_message_hints_at_all_mail_for_a_uid_missing_from_a_gmail_label(boxes):
    with pytest.raises(server.ToolError) as error:
        server.read_message("INBOX", 103, account="work")  # 103 is Alice's mail in All Mail; 3 in INBOX
    assert str(error.value) == f"Message 103 not found in INBOX. {HINT} the uid."
    with pytest.raises(server.ToolError) as error:
        server.read_message(ALL, 999, account="work")  # already All Mail: no hint
    assert str(error.value) == f"Message 999 not found in {ALL}"
    with pytest.raises(server.ToolError) as error:
        server.read_message("INBOX", 999, account="perso")  # no \All folder: unchanged
    assert str(error.value) == "Message 999 not found in INBOX"


def test_write_tools_hint_at_all_mail_for_uids_missing_from_a_gmail_label(boxes):
    with pytest.raises(server.ToolError) as error:
        server.move_messages("INBOX", [103], "Trash", account="work")
    assert "nothing was moved" in str(error.value) and str(error.value).endswith(f"{HINT} the uids.")
    with pytest.raises(server.ToolError, match=r"nothing was changed.*pass that folder with the uids\.$"):
        server.set_flags("Pro", [102], read=True, account="work")
    partial = server.set_flags("INBOX", [1, 103], flagged=True, account="work")
    assert partial["not_found"] == [103] and partial["warnings"][0].endswith(f"{HINT} the uids.")
    with pytest.raises(server.ToolError, match=r"draft not saved.*pass that folder with reply_to_uid\.$"):
        server.save_draft("a@example.org", "Re: Devis", "Bonjour", reply_to_folder="INBOX", reply_to_uid=103,
                          account="work")
    with pytest.raises(server.ToolError) as error:
        server.set_flags("INBOX", [999], read=True, account="perso")
    assert "Rows from folder" not in str(error.value)


# --- Gmail: answered=false over "*" keeps the inbox ---

def test_gmail_awaiting_reply_keeps_only_mail_still_in_the_inbox(boxes):
    """Archived in Gmail is leaving the inbox: 106 (Erin) is only in All Mail, without the \\Inbox label."""
    everything = boxes["work"].folders[server.utf7_encode(ALL)]["messages"]
    everything[5]["flags"] = set()  # unread, unanswered, addressed to me: only being archived leaves it out
    result = server.search_messages("*", answered=False, account="work")
    assert keys(result) == [("work", ALL, 102), ("work", ALL, 101), ("work", ALL, 103)]
    assert result["excluded_archived"] == 1
    fetches = [args[1] for cmd, args in boxes["work"].log if cmd == "FETCH" and "X-GM-LABELS" in args[1]]
    assert fetches and all("BODY.PEEK[HEADER.FIELDS" in spec for spec in fetches)  # in the screening FETCH
    assert (ALL, 106) in {(m["folder"], m["uid"]) for m in server.search_messages(
        "*", account="work", unread_only=True)["messages"]}
    archived = server.search_messages("Archive", answered=False, account="work")  # All Mail named: as asked
    assert ("work", ALL, 106) in keys(archived) and "excluded_archived" not in archived
    server.move_messages(ALL, [103], "Archive", account="work")  # removes the Inbox label
    after = server.search_messages("*", answered=False, account="work")
    assert after["total"] == 2 and after["excluded_archived"] == 2


def test_gmail_inbox_filter_is_skipped_without_the_gmail_extension(boxes):
    boxes["work"].caps = GMAIL_CAPS.replace(b" X-GM-EXT-1", b"")
    boxes["work"].folders[server.utf7_encode(ALL)]["messages"][5]["flags"] = set()
    result = server.search_messages("*", answered=False, account="work")
    assert ("work", ALL, 106) in keys(result) and "excluded_archived" not in result and "warnings" not in result
    assert not any("X-GM-LABELS" in args[1] for cmd, args in boxes["work"].log if cmd == "FETCH")


# --- answered=false: one row per conversation ---

def test_gmail_conversations_collapse_by_thread_id(boxes):
    """Gmail's X-GM-THRID wins over headers: a reply whose subject changed stays in its conversation."""
    everything = boxes["work"].folders[server.utf7_encode(ALL)]["messages"]
    thread = 1786543210987654321
    everything[1]["thrid"] = thread  # 102, Dan: "Réunion projet"
    everything.append({**mk(107, "Ordre du jour", sender="Eve <eve@example.com>", to="me@company.com",
                            date="Thu, 22 Oct 2026 08:00:00 +0000"), "gmid": 7, "thrid": thread})
    boxes["work"].folders["INBOX"]["messages"].append({**everything[-1], "uid": 4})
    result = server.search_messages("*", answered=False, account="work")
    assert [(m["uid"], m.get("in_thread")) for m in result["messages"]] == [(107, 2), (101, None), (103, None)]
    assert result["total"] == 3
    screening = [args[1] for cmd, args in boxes["work"].log if cmd == "FETCH" and "X-GM-THRID" in args[1]]
    assert len(screening) == 1 and "X-GM-LABELS" in screening[0]  # one FETCH for labels, threads and headers


def test_conversations_never_collapse_across_accounts(boxes):
    root = "<CAOx9Yq1@mail.example.org>"
    for name, uid in (("perso", 1), ("work", 1)):
        boxes[name].folders["INBOX"]["messages"] = [{**mk(uid, "Re: Planning", to="me@example.org, me@company.com",
                                                          sender="Bob <bob@example.net>", message_id=f"<r{name}@x>"),
                                                     "gmid": 50}]
        m = boxes[name].folders["INBOX"]["messages"][0]
        m["raw"] = m["raw"].replace(b"Message-ID:", f"References: {root}\nMessage-ID:".encode(), 1)
    boxes["perso"].folders["INBOX"]["messages"].append(
        mk(2, "Re: Planning", to="me@example.org", sender="Ann <ann@example.net>", message_id="<r2@x>",
           date="Tue, 20 Oct 2026 11:00:00 +0000"))
    m = boxes["perso"].folders["INBOX"]["messages"][-1]
    m["raw"] = m["raw"].replace(b"Message-ID:", f"References: {root}\nMessage-ID:".encode(), 1)
    result = server.search_messages("INBOX", answered=False)
    assert sorted((m["account"], m["uid"], m.get("in_thread")) for m in result["messages"]) == [
        ("perso", 2, 2), ("work", 1, None)]


def test_gmail_conversation_where_you_wrote_last_awaits_no_reply(boxes, monkeypatch, tmp_path):
    """Gmail's web interface may not set \\Answered: 101 (Carol's invitation) is unanswered, but the thread's
    latest message is your reply 104, in All Mail. 102 got a reply from you, then a newer message: still awaiting.
    103 has a later message from jaime@company.com, which contains your address but is not you."""
    monkeypatch.setenv("MAIL_ACCOUNTS_FILE", str(write_accounts(tmp_path, [PERSO, {**WORK, "aliases": ["pro@example.net"]}])))
    everything = boxes["work"].folders[server.utf7_encode(ALL)]["messages"]
    threads = {1: 1786000000000000101, 4: 1786000000000000101, 2: 1786000000000000102, 3: 1786000000000000103}
    for folder in boxes["work"].folders.values():  # gmid: the same message in INBOX, its labels and All Mail
        for m in folder["messages"]:
            if m.get("gmid") in threads:
                m["thrid"] = threads[m["gmid"]]  # 101 and your reply 104; 102; 103
    everything += [
        {**mk(108, "Re: Réunion projet", sender="Pro <pro@example.net>", to="dan@example.com",
              date="Wed, 21 Oct 2026 18:00:00 +0000", flags=["\\Seen"]), "gmid": 18, "thrid": 1786000000000000102},
        {**mk(109, "Re: Devis", sender="Jaime <jaime@company.com>", to="alice@example.org",
              date="Tue, 20 Oct 2026 08:00:00 +0000", flags=["\\Seen"]), "gmid": 19, "thrid": 1786000000000000103}]
    result = server.search_messages("*", answered=False, account="work")
    assert keys(result) == [("work", ALL, 102), ("work", ALL, 103)]
    assert result["total"] == 2 and result["excluded_replied"] == 1
    work = boxes["work"]
    searches = [args for cmd, args in work.log if cmd == "SEARCH" and "X-GM-THRID" in args]
    assert len(searches) == 1  # one SEARCH for every conversation, not one per conversation
    assert searches[0][:9] == ("UNDRAFT", "OR", "FROM", '"me@example.org"', "OR", "FROM", '"me@company.com"', "FROM",
                               '"pro@example.net"')  # any configured address or alias
    assert searches[0].count("X-GM-THRID") == 3
    inbox = server.search_messages("INBOX", answered=False, account="work")  # INBOX rows: same check in All Mail
    assert [m["uid"] for m in inbox["messages"]] == [2, 3] and inbox["excluded_replied"] == 1
    assert "excluded_replied" not in server.search_messages("*", answered=False, account="perso")
