import asyncio
from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest
from fastmcp.server.auth import AccessToken
from fastmcp.server.auth.providers.google import GoogleProvider
from starlette.testclient import TestClient

from mailroom_mcp import remote, server


@pytest.fixture
def configured(monkeypatch, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("test-only-secret-not-a-real-credential")
    monkeypatch.setenv("MAIL_PUBLIC_URL", "https://mail.example.com")
    monkeypatch.setenv("MAIL_GOOGLE_CLIENT_ID", "test.apps.googleusercontent.com")
    monkeypatch.setenv("MAIL_GOOGLE_CLIENT_SECRET_FILE", str(secret))
    monkeypatch.setenv("MAIL_GOOGLE_SUB", "123456")
    monkeypatch.setenv("MAIL_IMAP_HOST", "imap.example.org")
    monkeypatch.setenv("MAIL_USER", "me@example.org")


@pytest.mark.parametrize("sub,subject,verified,allowed", [
    ("123456", "123456", True, True),
    ("123456", "123456", "true", True),
    ("999999", "999999", True, False),
    ("123456", "999999", True, False),
    ("123456", "123456", False, False),
    ("123456", "123456", None, False),
])
def test_owner_enforced_after_oauth_validation(configured, monkeypatch, sub, subject, verified, allowed):
    token = AccessToken(token="fake", client_id="client", scopes=["openid"],
                        subject=subject, claims={"sub": sub, "email_verified": verified})
    async def validated(self, bearer):
        return token
    monkeypatch.setattr(GoogleProvider, "load_access_token", validated)
    provider = remote.create_server().auth
    assert (asyncio.run(provider.load_access_token("fake")) is not None) is allowed


def test_invalid_token_rejected(configured, monkeypatch):
    async def rejected(self, bearer):
        return None
    monkeypatch.setattr(GoogleProvider, "load_access_token", rejected)
    assert asyncio.run(remote.create_server().auth.load_access_token("bad")) is None


def test_missing_identity_prevents_start(configured, monkeypatch):
    monkeypatch.delenv("MAIL_GOOGLE_SUB")
    with pytest.raises(KeyError):
        remote.create_server()


@pytest.mark.parametrize("name", ["MAIL_IMAP_HOST", "MAIL_USER"])
def test_missing_mail_settings_prevent_start(configured, monkeypatch, name):
    monkeypatch.delenv(name)
    with pytest.raises(server.ConfigError, match=name):
        remote.create_server()


def test_http_requires_auth_and_advertises_discovery(configured):
    app = remote.create_server().http_app(stateless_http=True)
    with TestClient(app, base_url="https://mail.example.com") as client:
        for headers in ({}, {"Authorization": "Bearer invalid"}):
            response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, headers=headers)
            assert response.status_code == 401
            assert "resource_metadata" in response.headers["www-authenticate"]
        metadata = client.get("/.well-known/oauth-authorization-server").json()
        assert "S256" in metadata["code_challenge_methods_supported"]
        assert client.get("/healthz").json() == {"status": "ok"}


def test_owner_check_precedes_real_tool_execution(configured, monkeypatch):
    calls = []
    def folders() -> dict:
        calls.append(True)
        return {"delimiter": ".", "items": [{"name": "INBOX"}]}
    monkeypatch.setattr(server, "list_folders", folders)
    async def validated(self, bearer):
        sub = "123456" if bearer == "owner" else "999999"
        return AccessToken(token=bearer, client_id="client", scopes=["openid", "https://www.googleapis.com/auth/userinfo.email"],
                           subject=sub, claims={"sub": sub, "email_verified": True})
    monkeypatch.setattr(GoogleProvider, "load_access_token", validated)
    app = remote.create_server().http_app(stateless_http=True, json_response=True)
    with TestClient(app, base_url="https://mail.example.com") as client:
        def call(bearer):
            return client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_folders", "arguments": {}}},
                               headers={"Authorization": f"Bearer {bearer}", "Accept": "application/json, text/event-stream"})
        assert call("other").status_code == 401
        assert calls == []
        response = call("owner")
        assert response.status_code == 200
        assert "INBOX" in response.text
        assert calls == [True]


@pytest.mark.parametrize("capabilities,expected", [
    ((b"MOVE",), ["SEARCH", "MOVE"]),  # SEARCH: do the UIDs still exist in the folder?
    ((b"UIDPLUS",), ["SEARCH", "COPY", "STORE", "EXPUNGE"]),
    ((b"IMAP4rev1",), []),
])
def test_move_never_globally_expunges(configured, monkeypatch, capabilities, expected):
    connection = MagicMock(capabilities=capabilities)
    connection.capabilities = (b"IMAP4rev1",)  # stale pre-login cache
    connection.capability.return_value = ("OK", [b" ".join(capabilities)])
    connection.uid.side_effect = lambda command, *args: ("OK", [b"3 8"] if command == "SEARCH" else [])
    connection.list.return_value = ("OK", [b'(\\HasNoChildren) "." "INBOX"', b'(\\HasNoChildren \\Archive) "." "Archives"'])
    connection.select.return_value = ("OK", [b"2"])
    @contextmanager
    def fake_imap(*args, **kwargs):
        yield connection
    monkeypatch.setattr(server, "imap", fake_imap)
    if expected:
        server.move_messages("INBOX", [3, 8], "Archive")
    else:
        with pytest.raises(server.ToolError):
            server.move_messages("INBOX", [3, 8], "Archive")
    assert [call.args[0] for call in connection.uid.call_args_list] == expected
    if expected:
        assert connection.uid.call_args_list[1].args[2] == '"Archives"'  # Archive role resolved through SPECIAL-USE
    connection.expunge.assert_not_called()
    connection.capability.assert_called_once_with()
    if "EXPUNGE" in expected:
        assert connection.uid.call_args_list[-1].args == ("EXPUNGE", "3,8")


def test_tool_errors_reach_the_http_client_with_their_message(configured, monkeypatch):
    """Without rewriting, mask_error_details would reduce "invalid limit" to "Error calling tool"."""
    async def validated(self, bearer):
        return AccessToken(token=bearer, client_id="client", scopes=["openid", "https://www.googleapis.com/auth/userinfo.email"],
                           subject="123456", claims={"sub": "123456", "email_verified": True})
    monkeypatch.setattr(GoogleProvider, "load_access_token", validated)
    app = remote.create_server().http_app(stateless_http=True, json_response=True)
    headers = {"Authorization": "Bearer owner", "Accept": "application/json, text/event-stream"}
    with TestClient(app, base_url="https://mail.example.com") as client:
        def rpc(method, params):
            return client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, headers=headers)
        tools = {t["name"]: t for t in rpc("tools/list", {}).json()["result"]["tools"]}
        assert {"search_messages", "read_message", "list_folders"} <= set(tools)
        assert "offset" in tools["search_messages"]["inputSchema"]["properties"]
        assert "*" in tools["search_messages"]["description"]
        for arguments, message in (({"limit": 0}, "Invalid parameters for search_messages: limit: at least 1 (got 0)."),
                                   ({"since": "2026-13-40"}, "Invalid date for since")):
            response = rpc("tools/call", {"name": "search_messages", "arguments": arguments})
            assert response.status_code == 200
            result = response.json()["result"]
            assert result["isError"] is True
            assert message in result["content"][0]["text"]
