"""Contract of both transports (stdio: server.mcp; HTTP: remote.create_server): same tools, annotations,
strict schemas, short descriptions with a valid example, readable parameter errors."""

import asyncio
import json
import re

import pytest
from fastmcp import Client
from fastmcp.server.auth import AccessToken
from fastmcp.server.auth.providers.google import GoogleProvider
from starlette.testclient import TestClient
from test_remote import configured  # noqa: F401  (fixture)
from test_send import smtp_server  # noqa: F401  (fixture)
from test_server import FakeIMAP, install, mail_env, mailbox_fixture  # noqa: F401  (autouse fixture)

from mailroom_mcp import remote, server

# Raw pydantic/FastMCP wording that must never reach the client.
RAW_PYDANTIC = re.compile(r"validation error|Input should|Field required|Unexpected keyword|type=|pydantic", re.I)
EXAMPLE = re.compile(r"Example: (\{.*\})$")
EXPECTED_ANNOTATIONS = {
    "list_folders": {"readOnlyHint": True, "openWorldHint": True},
    "search_messages": {"readOnlyHint": True, "openWorldHint": True},
    "read_message": {"readOnlyHint": True, "openWorldHint": True},
    "move_messages": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True},
    "set_flags": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
    "create_folder": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True},
    "save_draft": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True},
    "send_draft": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True},
}
LIMITS = {"search_messages": 900, "send_draft": 560}

# (tool, arguments, expected part of the error message)
BAD_CALLS = [
    ("search_messages", {"zz": 1}, "Invalid parameters for search_messages: unknown parameter 'zz'."),
    ("search_messages", {"unread": True}, "unknown parameter 'unread' (did you mean unread_only?)"),
    ("search_messages", {"limit": 0}, "Invalid parameters for search_messages: limit: at least 1 (got 0)."),
    ("search_messages", {"limit": 101}, "limit: at most 100 (got 101)"),
    ("search_messages", {"limit": "x"}, "limit: integer expected (got string 'x')"),
    ("search_messages", {"folder": 3}, "folder: string or list expected (got number 3)"),
    ("search_messages", {"group_by": "subject"}, "group_by: one of sender, folder (got 'subject')"),
    ("search_messages", {"days": 0}, "days: at least 1 (got 0)"),
    ("search_messages", {"unread_only": "maybe"}, "unread_only: boolean expected"),
    ("read_message", {"folder": "INBOX"}, "Invalid parameters for read_message: uid: required."),
    ("move_messages", {"folder": "INBOX", "uids": [], "destination": "Trash"}, "uids: at least 1 item(s)"),
    ("set_flags", {"folder": "INBOX", "uids": ["a"], "read": True}, "uids[0]: integer expected"),
    ("search_messages", {"snippet_chars": 301}, "snippet_chars: at most 300 (got 301)"),
    ("search_messages", {"snippet_chars": -1}, "snippet_chars: at least 0 (got -1)"),
    ("search_messages", {"text": ["a"] * 11}, "text: at most 10 item(s)"),
    ("search_messages", {"text": 3}, "text: string or list expected (got number 3)"),
    ("search_messages", {"automated": "skip"}, "automated: one of include, exclude, only (got 'skip')"),
    ("search_messages", {"to_me": "maybe"}, "to_me: boolean expected"),
    ("send_draft", {}, "Invalid parameters for send_draft: uid: required."),
    ("send_draft", {"uid": 0}, "uid: at least 1 (got 0)"),
]


def tools_of(listed):
    return {t["name"]: t for t in listed}


def stdio_tools():
    async def run():
        async with Client(server.mcp) as client:
            return [t.model_dump(by_alias=True, exclude_none=True, mode="json") for t in await client.list_tools()]
    return tools_of(asyncio.run(run()))


def stdio_call(name, arguments):
    async def run():
        async with Client(server.mcp) as client:
            result = await client.call_tool(name, arguments, raise_on_error=False)
            return result.is_error, result.content[0].text
    return asyncio.run(run())


@pytest.fixture
def http(configured, monkeypatch):  # noqa: F811
    async def validated(self, bearer):
        return AccessToken(token=bearer, client_id="client", scopes=["openid", "https://www.googleapis.com/auth/userinfo.email"],
                           subject="123456", claims={"sub": "123456", "email_verified": True})
    monkeypatch.setattr(GoogleProvider, "load_access_token", validated)
    app = remote.create_server().http_app(stateless_http=True, json_response=True)
    headers = {"Authorization": "Bearer owner", "Accept": "application/json, text/event-stream"}
    with TestClient(app, base_url="https://mail.example.com") as client:
        def rpc(method, params):
            return client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, headers=headers).json()
        yield rpc


def http_tools(rpc):
    return tools_of(rpc("tools/list", {})["result"]["tools"])


def http_call(rpc, name, arguments):
    result = rpc("tools/call", {"name": name, "arguments": arguments})["result"]
    return result.get("isError", False), result["content"][0]["text"]


def check_surface(tools):
    assert set(tools) == set(EXPECTED_ANNOTATIONS)
    for name, tool in tools.items():
        hints = {k: v for k, v in tool["annotations"].items() if k.endswith("Hint")}
        assert hints == EXPECTED_ANNOTATIONS[name], name
        schema = tool["inputSchema"]
        assert schema.get("additionalProperties") is False, name
        description = tool["description"]
        assert len(description) <= LIMITS.get(name, 600), (name, len(description))
        assert "AAAA" not in description and "\n" not in description, name
        example = EXAMPLE.search(description)
        assert example, f"{name}: final example missing"
        arguments = json.loads(example.group(1))
        assert set(arguments) <= set(schema["properties"]), name
        assert set(schema.get("required", [])) <= set(arguments), name


def test_stdio_surface():
    tools = stdio_tools()
    check_surface(tools)
    assert all("outputSchema" not in t for t in tools.values())  # answers are text only
    assert tools["search_messages"]["inputSchema"]["properties"]["limit"]["maximum"] == server.LIMIT_MAX
    properties = tools["search_messages"]["inputSchema"]["properties"]
    assert properties["group_by"]["enum"] == ["sender", "folder"]
    assert properties["sender"] == {"type": "string", "description": "Name or address."}  # optional: no anyOf, no null published
    assert "anyOf" not in json.dumps({k: v for k, v in properties.items() if k not in ("folder", "text", "subject")})
    for name in ("text", "subject"):
        assert properties[name]["anyOf"] == [{"type": "string"}, {"type": "array", "items": {"type": "string"}, "maxItems": 10}]


def test_http_surface_matches_stdio(http):
    tools = http_tools(http)
    check_surface(tools)
    stdio = stdio_tools()
    for name, tool in tools.items():
        assert tool["inputSchema"] == stdio[name]["inputSchema"] and tool["description"] == stdio[name]["description"]
        assert tool["_meta"]["securitySchemes"][0]["type"] == "oauth2"
        assert "outputSchema" not in tool, name


def test_instructions_name_the_mailbox_and_timezone_and_cover_answered(monkeypatch):
    for text in (server.instructions(), server.instructions(remote=True)):
        assert "the mailbox me@example.org" in text and "in the Europe/Paris time zone" in text
        assert "answered=false: mail awaiting your reply, addressed to you in To" in text and "excluded_not_to_me" in text
    monkeypatch.delenv("MAIL_USER")
    monkeypatch.delenv("MAIL_TIMEZONE")
    assert "IMAP access to a mailbox." in server.instructions() and "in the UTC time zone" in server.instructions()


@pytest.mark.parametrize("name,arguments,expected", BAD_CALLS)
def test_stdio_errors_are_readable(name, arguments, expected):
    is_error, text = stdio_call(name, arguments)
    assert is_error and expected in text and not RAW_PYDANTIC.search(text), text
    if "unknown parameter" in expected:
        assert "Accepted parameters: " in text and all(p in text for p in ("folder", "limit", "offset", "group_by"))
    else:
        assert "Accepted parameters" not in text


@pytest.mark.parametrize("name,arguments,expected", BAD_CALLS)
def test_http_errors_are_readable(http, name, arguments, expected):
    is_error, text = http_call(http, name, arguments)
    assert is_error and expected in text and not RAW_PYDANTIC.search(text), text


def test_tool_errors_raised_by_the_body_reach_both_transports(http, monkeypatch):
    install(monkeypatch, FakeIMAP(mailbox_fixture()))
    for call in (stdio_call, lambda n, a: http_call(http, n, a)):
        is_error, text = call("search_messages", {"days": 3, "since": "2026-10-01"})
        assert is_error and "days and since are mutually exclusive" in text
        is_error, text = call("search_messages", {"folder": "Nope"})
        assert is_error and "Folder not found" in text


def test_results_are_compact_json_on_both_transports(http, monkeypatch):
    install(monkeypatch, FakeIMAP(mailbox_fixture()))
    for call in (stdio_call, lambda n, a: http_call(http, n, a)):
        is_error, text = call("search_messages", {"folder": "*", "unread_only": True, "sender": None})  # null accepted
        assert not is_error and "\n" not in text and ", " not in text.split('"snippet"')[0]
        data = json.loads(text)
        assert data["total"] == 2 and data["returned"] == 2 and "count" not in data


def test_results_are_sent_once_as_text_on_both_transports(http, monkeypatch):
    """No structuredContent next to the text: clients would hand the same JSON to the model twice."""
    install(monkeypatch, FakeIMAP(mailbox_fixture()))

    async def stdio_raw():
        async with Client(server.mcp) as client:
            return await client.call_tool_mcp("search_messages", {"folder": "*", "unread_only": True})
    raw = asyncio.run(stdio_raw())
    assert raw.structured_content is None and len(raw.content) == 1 and json.loads(raw.content[0].text)["total"] == 2
    result = http("tools/call", {"name": "search_messages", "arguments": {"folder": "*", "unread_only": True}})["result"]
    assert "structuredContent" not in result and len(result["content"]) == 1
    assert json.loads(result["content"][0]["text"])["total"] == 2
    error = http("tools/call", {"name": "search_messages", "arguments": {"unread": True}})["result"]
    assert error["isError"] and "structuredContent" not in error and len(error["content"]) == 1


def test_unexpected_errors_are_readable_on_both_transports(http, monkeypatch):
    """An unexpected exception is no longer reduced to "Error calling tool" (masked over HTTP)."""
    from contextlib import contextmanager

    class Broken:
        def list(self):
            raise RuntimeError("boom secret")

    @contextmanager
    def broken_imap(account=None):
        yield Broken()
    monkeypatch.setattr(server, "imap", broken_imap)
    is_error, text = stdio_call("list_folders", {})
    assert is_error and text == "Unexpected error in list_folders (RuntimeError: boom secret)."
    is_error, text = http_call(http, "list_folders", {})
    assert is_error and text == "Unexpected error in list_folders (RuntimeError)."  # HTTP: no internal detail
    is_error, text = http_call(http, "move_messages", {"folder": "INBOX", "uids": [1], "destination": "Trash"})
    assert is_error and text.startswith("Unexpected error in move_messages") and "check before trying again" in text


def test_imap_timeouts_are_readable_and_retryable_on_both_transports(http, monkeypatch):
    """A timeout is not an "Unexpected error": reads say to try again, writes to check first."""
    from contextlib import contextmanager

    class Slow:
        def list(self):
            raise TimeoutError("The read operation timed out")

    @contextmanager
    def slow_imap(account=None):  # the timeout escapes the IMAP session: the middleware still words it
        yield Slow()
    monkeypatch.setattr(server, "imap", slow_imap)
    for call in (stdio_call, lambda n, a: http_call(http, n, a)):
        is_error, text = call("read_message", {"folder": "INBOX", "uid": 1})
        assert is_error and text == "The IMAP server did not answer in time: try again.", text
        is_error, text = call("move_messages", {"folder": "INBOX", "uids": [1], "destination": "Trash"})
        assert is_error and text == ("The IMAP server did not answer in time. "
                                     "The action may have partly happened: check before trying again."), text


def test_timeouts_inside_the_imap_session_are_retryable_on_both_transports(http, monkeypatch):
    class Slow:
        def list(self):
            raise TimeoutError("The read operation timed out")

        def logout(self):
            pass
    monkeypatch.setattr(server, "connect", lambda account=None: Slow())
    for call in (stdio_call, lambda n, a: http_call(http, n, a)):
        is_error, text = call("list_folders", {})
        assert is_error and text == "The IMAP server did not answer in time: try again.", text
        is_error, text = call("create_folder", {"name": "X"})
        assert is_error and text.startswith("The IMAP server did not answer in time.") and "check before" in text


def test_header_injection_and_missing_uids_are_reported_on_both_transports(http, monkeypatch):
    fake = install(monkeypatch, FakeIMAP(mailbox_fixture()))
    for call in (stdio_call, lambda n, a: http_call(http, n, a)):
        is_error, text = call("save_draft", {"to": "a@example.org", "subject": "x\r\nBcc: spy@example.org", "body": "y"})
        assert is_error and text.startswith("subject: line breaks and null characters are forbidden"), text
        is_error, text = call("set_flags", {"folder": "INBOX", "uids": [4242], "read": True})
        assert is_error and "None of the requested UIDs exists in INBOX (4242)" in text, text
    assert len(fake.folders["INBOX.Drafts"]["messages"]) == 1


# --- Several accounts ---

@pytest.fixture
def several(configured, monkeypatch, tmp_path):  # noqa: F811
    from test_accounts import GMAIL_CAPS, PERSO, WORK, gmail_fixture, write_accounts
    monkeypatch.delenv("MAIL_IMAP_HOST")
    monkeypatch.delenv("MAIL_USER")
    monkeypatch.setenv("MAIL_ACCOUNTS_FILE", str(write_accounts(tmp_path, [PERSO, WORK])))
    return install(monkeypatch, {"perso": FakeIMAP(mailbox_fixture()),
                                 "work": FakeIMAP(gmail_fixture(), caps=GMAIL_CAPS, delimiter="/")})


def test_every_tool_takes_an_optional_account():
    for name, tool in stdio_tools().items():
        schema = tool["inputSchema"]
        assert schema["properties"]["account"]["type"] == "string", name
        assert "account" not in schema.get("required", []), name


def test_several_accounts_on_both_transports(several, http):
    for call in (stdio_call, lambda n, a: http_call(http, n, a)):
        is_error, text = call("search_messages", {"folder": "*", "unread_only": True})
        data = json.loads(text)
        assert not is_error and data["total"] == 5 and {m["account"] for m in data["messages"]} == {"perso", "work"}
        assert set(data["folders_excluded"]) == {"perso", "work"}
        is_error, text = call("read_message", {"folder": "INBOX", "uid": 1})
        assert is_error and text == ("Several accounts are configured: give account, one of perso (me@example.org), "
                                     "work (me@company.com).")
        is_error, text = call("read_message", {"folder": "INBOX", "uid": 1, "account": "work"})
        assert not is_error and json.loads(text)["account"] == "work"
        is_error, text = call("list_folders", {})
        assert not is_error and [a["account"] for a in json.loads(text)["accounts"]] == ["perso", "work"]
        is_error, text = call("move_messages", {"folder": "INBOX", "uids": [1], "destination": "Trash", "account": "x"})
        assert is_error and text.startswith("Unknown account 'x': give one of perso")


def test_remote_instructions_name_the_accounts(several):
    text = remote.create_server().instructions
    assert "perso (me@example.org), work (me@company.com)" in text and text.endswith("creating a draft.")


# --- send_draft: two steps on both transports ---

@pytest.fixture
def sending(monkeypatch, tmp_path, smtp_server):  # noqa: F811
    password = tmp_path / "password"
    password.write_text("test-only-not-a-real-password")
    monkeypatch.setenv("MAIL_PASSWORD_FILE", str(password))
    monkeypatch.setenv("MAIL_SEND_ENABLED", "true")
    return install(monkeypatch, FakeIMAP(mailbox_fixture())), smtp_server


def test_send_draft_parameter_errors_list_its_parameters(http):
    for call in (stdio_call, lambda n, a: http_call(http, n, a)):
        is_error, text = call("send_draft", {"uid": 1, "confirm": "x"})
        assert is_error and text == ("Invalid parameters for send_draft: unknown parameter 'confirm' (did you mean "
                                     "confirmation?). Accepted parameters: uid, folder, confirmation, account."), text


def test_send_draft_description_says_the_user_must_approve():
    description = stdio_tools()["send_draft"]["description"]
    assert "ONLY after the user explicitly approved sending this exact mail" in description
    assert "never resend" in description


def test_send_draft_takes_two_steps_over_http(http, sending):
    fake, srv = sending
    uid = server.save_draft(to="bob@example.org", subject="Devis", body="Bonjour")["uid"]
    is_error, text = http_call(http, "send_draft", {"uid": uid})
    preview = json.loads(text)
    assert not is_error and preview["sent"] is False and preview["to"] == "bob@example.org" and srv.received == []
    code = preview["confirmation"]
    is_error, text = http_call(http, "send_draft", {"uid": uid, "confirmation": code})
    assert not is_error and json.loads(text)["sent"] is True and len(srv.received) == 1
    is_error, text = http_call(http, "send_draft", {"uid": uid, "confirmation": code})  # reused
    assert is_error and text.startswith("Unknown confirmation: nothing was sent"), text
    assert len(srv.received) == 1


def test_send_draft_refuses_a_changed_draft_or_an_expired_code_over_http(http, sending, monkeypatch):
    fake, srv = sending
    uid = server.save_draft(to="bob@example.org", subject="Devis", body="Bonjour")["uid"]
    code = json.loads(http_call(http, "send_draft", {"uid": uid})[1])["confirmation"]
    draft = next(m for m in fake.folders["INBOX.Drafts"]["messages"] if m["uid"] == uid)
    draft["raw"] = draft["raw"].replace(b"Bonjour", b"Bonsoir")
    is_error, text = http_call(http, "send_draft", {"uid": uid, "confirmation": code})
    assert is_error and text.startswith("The draft changed since the preview: nothing was sent"), text
    monkeypatch.setattr(server, "CONFIRM_TTL", -1)
    code = json.loads(http_call(http, "send_draft", {"uid": uid})[1])["confirmation"]
    is_error, text = http_call(http, "send_draft", {"uid": uid, "confirmation": code})
    assert is_error and text.startswith("This confirmation expired"), text
    assert srv.received == []


def test_send_draft_errors_are_readable_on_both_transports(http, sending, monkeypatch):
    fake, srv = sending
    uid = server.save_draft(to="bob@example.org", subject="Devis", body="Bonjour")["uid"]
    srv.fail["data"] = TimeoutError("The read operation timed out")
    for call in (stdio_call, lambda n, a: http_call(http, n, a)):
        code = json.loads(call("send_draft", {"uid": uid})[1])["confirmation"]
        is_error, text = call("send_draft", {"uid": uid, "confirmation": code})
        assert is_error and text.startswith("The mail may have been sent") and "Unexpected" not in text, text
    monkeypatch.delenv("MAIL_SEND_ENABLED")
    for call in (stdio_call, lambda n, a: http_call(http, n, a)):
        is_error, text = call("send_draft", {"uid": uid})
        assert is_error and text.startswith("Sending is disabled for me@example.org: nothing was sent."), text


def test_instructions_mention_sending_only_when_enabled(monkeypatch):
    assert "Nothing can be sent" in server.instructions() and "send_draft" not in server.instructions()
    monkeypatch.setenv("MAIL_SEND_ENABLED", "true")
    text = server.instructions(remote=True)
    assert "drafts can be sent with send_draft only after the user's explicit approval (two steps)" in text
    assert "Nothing can be sent" not in text
