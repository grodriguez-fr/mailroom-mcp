"""mailroom-mcp-auth google: PKCE, authorization URL, loopback redirect, code exchange, token file.
Google's endpoints are replaced; only a local listener on 127.0.0.1 is used."""

import base64
import hashlib
import io
import json
import stat
import threading
import urllib.error
import urllib.parse
import urllib.request

import pytest

from mailroom_mcp import auth, google_oauth

CLIENT = {"installed": {"client_id": "test.apps.googleusercontent.com", "client_secret": "test-client-secret",
                        "redirect_uris": ["http://localhost"]}}


class Google:
    """Stands in for urllib.request.urlopen: token endpoint and Gmail profile."""

    def __init__(self, token_status=200, token_body=None, profile=None):
        self.token_status = token_status
        self.token_body = token_body if token_body is not None else {
            "access_token": "test-access", "refresh_token": "test-refresh", "expires_in": 3599,
            "scope": google_oauth.SCOPE, "token_type": "Bearer"}
        self.profile = profile
        self.requests = []

    def __call__(self, request, timeout=None):
        data = dict(urllib.parse.parse_qsl(request.data.decode())) if request.data else None
        self.requests.append((request.full_url, data, request.headers.get("Authorization")))
        if request.full_url == google_oauth.TOKEN_URL:
            body = json.dumps(self.token_body).encode()
            if self.token_status != 200:
                raise urllib.error.HTTPError(request.full_url, self.token_status, "error", {}, io.BytesIO(body))
            return io.BytesIO(body)
        assert request.full_url == google_oauth.PROFILE_URL
        if self.profile is None:
            raise urllib.error.HTTPError(request.full_url, 403, "Gmail API has not been used", {}, io.BytesIO(b"{}"))
        return io.BytesIO(json.dumps({"emailAddress": self.profile}).encode())


@pytest.fixture
def client_file(tmp_path):
    path = tmp_path / "client.json"
    path.write_text(json.dumps(CLIENT))
    return path


def test_pkce_pair_is_s256():
    verifier, challenge = google_oauth.pkce_pair()
    assert 43 <= len(verifier) <= 128 and set(verifier) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    assert challenge == base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert google_oauth.pkce_pair()[0] != verifier


def test_authorization_url_asks_for_offline_mail_access_with_pkce():
    url = google_oauth.authorization_url("cid", "http://127.0.0.1:8765/", "st4te", "ch4llenge", "me@company.com")
    base, _, query = url.partition("?")
    assert base == "https://accounts.google.com/o/oauth2/v2/auth"
    assert dict(urllib.parse.parse_qsl(query)) == {
        "client_id": "cid", "redirect_uri": "http://127.0.0.1:8765/", "response_type": "code",
        "scope": "https://mail.google.com/", "access_type": "offline", "prompt": "consent", "state": "st4te",
        "code_challenge": "ch4llenge", "code_challenge_method": "S256", "login_hint": "me@company.com"}
    assert "login_hint" not in google_oauth.authorization_url("cid", "http://127.0.0.1:1/", "s", "c")


def test_client_file_must_be_a_desktop_client(tmp_path, client_file):
    assert google_oauth.load_client(str(client_file)) == ("test.apps.googleusercontent.com", "test-client-secret")
    web = tmp_path / "web.json"
    web.write_text(json.dumps({"web": CLIENT["installed"]}))
    with pytest.raises(google_oauth.ToolError, match=r"expected a Desktop app client \(this is a Web application"):
        google_oauth.load_client(str(web))
    web.write_text("{not json")
    with pytest.raises(google_oauth.ToolError, match="invalid JSON"):
        google_oauth.load_client(str(web))


@pytest.mark.parametrize("path,error", [
    ("/?state=good&code=4%2Fabc", None),
    ("/?state=bad&code=4%2Fabc", "state does not match"),
    ("/?code=4%2Fabc", "state does not match"),
    ("/?state=good&error=access_denied", "Google refused the authorization: access_denied"),
    ("/?state=good", "no authorization code"),
])
def test_parse_redirect_checks_the_state(path, error):
    if error is None:
        assert auth.parse_redirect(path, "good") == "4/abc"
    else:
        with pytest.raises(auth.AuthError, match=error):
            auth.parse_redirect(path, "good")


def test_loopback_listener_ignores_strays_and_returns_the_code():
    server = auth.listener(0)
    port = server.server_address[1]
    statuses = []

    def browser():
        for path in ("/favicon.ico", "/?state=forged&code=evil", "/?state=good&code=4%2Freal"):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as response:
                    statuses.append((response.status, response.read().decode()))
            except urllib.error.HTTPError as e:
                statuses.append((e.code, e.read().decode()))
    thread = threading.Thread(target=browser)
    thread.start()
    try:
        assert auth.wait_for_code(server, "good", timeout=10) == "4/real"
    finally:
        thread.join()
        server.server_close()
    assert [s for s, _ in statuses] == [404, 400, 200]
    assert "state does not match" in statuses[1][1] and "you can close this tab" in statuses[2][1]


def test_loopback_listener_reports_a_refusal():
    server = auth.listener(0)
    port = server.server_address[1]
    thread = threading.Thread(target=lambda: _get(f"http://127.0.0.1:{port}/?state=good&error=access_denied"))
    thread.start()
    try:
        with pytest.raises(auth.AuthError, match="access_denied"):
            auth.wait_for_code(server, "good", timeout=10)
    finally:
        thread.join()
        server.server_close()


def _get(url):
    try:
        urllib.request.urlopen(url, timeout=5).read()
    except urllib.error.HTTPError:
        pass


def test_code_exchange_sends_the_verifier_and_requires_a_refresh_token(monkeypatch):
    google = Google()
    monkeypatch.setattr(google_oauth.urllib.request, "urlopen", google)
    answer = google_oauth.exchange_code("cid", "secret", "4/abc", "verifier", "http://127.0.0.1:9/")
    assert answer["refresh_token"] == "test-refresh"
    assert google.requests == [(google_oauth.TOKEN_URL, {
        "grant_type": "authorization_code", "code": "4/abc", "code_verifier": "verifier", "client_id": "cid",
        "client_secret": "secret", "redirect_uri": "http://127.0.0.1:9/"}, None)]
    monkeypatch.setattr(google_oauth.urllib.request, "urlopen", Google(token_body={"access_token": "a", "scope": google_oauth.SCOPE}))
    with pytest.raises(google_oauth.OAuthError, match="no_refresh_token"):
        google_oauth.exchange_code("cid", "secret", "4/abc", "verifier", "http://127.0.0.1:9/")
    monkeypatch.setattr(google_oauth.urllib.request, "urlopen", Google(token_body={
        "access_token": "a", "refresh_token": "r", "scope": "openid"}))
    with pytest.raises(google_oauth.OAuthError, match="insufficient_scope"):
        google_oauth.exchange_code("cid", "secret", "4/abc", "verifier", "http://127.0.0.1:9/")
    monkeypatch.setattr(google_oauth.urllib.request, "urlopen", Google(400, {"error": "invalid_grant", "error_description": "Bad code"}))
    with pytest.raises(google_oauth.OAuthError, match="^invalid_grant: Bad code$"):
        google_oauth.exchange_code("cid", "secret", "4/abc", "verifier", "http://127.0.0.1:9/")


def test_token_file_is_600_and_never_overwritten_without_force(tmp_path):
    path = tmp_path / "work.token"
    auth.write_token(str(path), "first")
    assert path.read_text() == "first\n" and stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(auth.AuthError, match="already exists: add --force"):
        auth.write_token(str(path), "second")
    path.chmod(0o644)
    auth.write_token(str(path), "second", force=True)
    assert path.read_text() == "second\n" and stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["work.token"]  # no temporary file left
    with pytest.raises(auth.AuthError, match="Directory not found"):
        auth.write_token(str(tmp_path / "nope" / "t"), "x")


def test_google_command_end_to_end(monkeypatch, client_file, tmp_path, capsys):
    google = Google(profile="me@company.com")
    monkeypatch.setattr(google_oauth.urllib.request, "urlopen", google)
    seen = {}

    def browser(server, state, timeout=auth.WAIT_SECONDS):
        seen["state"], seen["port"] = state, server.server_address[1]
        return "4/code"
    monkeypatch.setattr(auth, "wait_for_code", browser)
    target = tmp_path / "work.token"
    status = auth.main(["google", "--client-secret-file", str(client_file), "--refresh-token-file", str(target),
                        "--login-hint", "me@company.com", "--port", "0"])
    out = capsys.readouterr().out
    assert status == 0
    url = next(line for line in out.splitlines() if line.startswith("https://"))
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    assert query["state"] == seen["state"] and query["redirect_uri"] == f"http://127.0.0.1:{seen['port']}/"
    exchange = google.requests[0][1]
    assert exchange["redirect_uri"] == query["redirect_uri"] and exchange["code"] == "4/code"
    assert base64.urlsafe_b64encode(hashlib.sha256(exchange["code_verifier"].encode()).digest()).rstrip(b"=").decode() \
        == query["code_challenge"]
    assert google.requests[1][2] == "Bearer test-access"
    assert target.read_text() == "test-refresh\n" and stat.S_IMODE(target.stat().st_mode) == 0o600
    assert f"Authorized me@company.com with scope https://mail.google.com/; refresh token written to {target}" in out
    assert "test-refresh" not in out and "test-access" not in out and "test-client-secret" not in out


def test_google_command_refuses_to_overwrite_and_reports_errors(monkeypatch, client_file, tmp_path, capsys):
    target = tmp_path / "work.token"
    target.write_text("old\n")
    assert auth.main(["google", "--client-secret-file", str(client_file), "--refresh-token-file", str(target)]) == 1
    assert "already exists: add --force to replace it" in capsys.readouterr().err
    assert target.read_text() == "old\n"
    monkeypatch.setattr(google_oauth.urllib.request, "urlopen", Google(400, {"error": "invalid_grant"}))
    monkeypatch.setattr(auth, "wait_for_code", lambda server, state, timeout=0: "4/code")
    assert auth.main(["google", "--client-secret-file", str(client_file), "--refresh-token-file", str(target),
                      "--force"]) == 1
    assert "Code exchange refused: invalid_grant" in capsys.readouterr().err
    assert target.read_text() == "old\n"


def test_google_command_without_gmail_api_still_writes_the_token(monkeypatch, client_file, tmp_path, capsys):
    monkeypatch.setattr(google_oauth.urllib.request, "urlopen", Google(profile=None))
    monkeypatch.setattr(auth, "wait_for_code", lambda server, state, timeout=0: "4/code")
    target = tmp_path / "work.token"
    assert auth.main(["google", "--client-secret-file", str(client_file), "--refresh-token-file", str(target)]) == 0
    out = capsys.readouterr().out
    assert "Authorized the account with scope https://mail.google.com/" in out and "enable the Gmail API" in out
    assert target.exists()
