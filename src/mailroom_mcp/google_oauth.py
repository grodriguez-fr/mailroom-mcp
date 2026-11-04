"""Google OAuth 2.0 for IMAP (XOAUTH2): refresh-token exchange with an in-memory access token cache, and the
pieces of the loopback authorization flow used by `mailroom-mcp-auth google` (Desktop app clients, PKCE S256).

Standard library only. Tokens are never logged, printed or returned to a client.
"""

import base64
import hashlib
import json
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from fastmcp.exceptions import ToolError

from mailroom_mcp.config import Account, read_secret

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
PROFILE_URL = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
SCOPE = "https://mail.google.com/"
EXPIRY_MARGIN = 120  # seconds: an access token is renewed this long before it expires
HTTP_TIMEOUT = 30


class OAuthError(Exception):
    """Refusal from Google's OAuth endpoints: `error` is the OAuth error code (invalid_grant…)."""

    def __init__(self, error: str, description: str = ""):
        self.error, self.description = error, description
        super().__init__(f"{error}: {description}" if description else error)


def post_form(url: str, fields: dict) -> dict:
    """POST application/x-www-form-urlencoded, JSON answer. An OAuth refusal raises OAuthError, a network
    failure OSError."""
    request = urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode(), method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded",
                                              "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError, OSError):
            body = {}
        if not isinstance(body, dict):
            body = {}
        raise OAuthError(str(body.get("error") or f"HTTP {e.code}"), str(body.get("error_description") or "")) from None
    except ValueError:
        raise OAuthError("invalid_response", "the answer is not JSON") from None


def load_client(path: str) -> tuple[str, str]:
    """(client_id, client_secret) from the JSON downloaded from Google Cloud Console for a Desktop app client."""
    raw = read_secret(path, "Google OAuth client file", "the JSON of a Desktop app OAuth client from Google Cloud Console")
    try:
        data = json.loads(raw)
    except ValueError:
        raise ToolError(f"Google OAuth client file {path}: invalid JSON") from None
    if not isinstance(data, dict):
        raise ToolError(f"Google OAuth client file {path}: expected a JSON object")
    if "installed" not in data:
        kind = " (this is a Web application client)" if "web" in data else ""
        raise ToolError(f"Google OAuth client file {path}: expected a Desktop app client{kind}. In Google Cloud "
                        "Console, create an OAuth client of type Desktop app and download its JSON.")
    client = data["installed"]
    client_id, secret = (client.get(k) if isinstance(client, dict) else None for k in ("client_id", "client_secret"))
    if not isinstance(client_id, str) or not client_id or not isinstance(secret, str) or not secret:
        raise ToolError(f"Google OAuth client file {path}: client_id or client_secret missing")
    return client_id, secret


def auth_command(account: Account) -> str:
    return (f"mailroom-mcp-auth google --client-secret-file {account.client_secret_file} "
            f"--refresh-token-file {account.refresh_token_file} --login-hint {account.user} --force")


# --- Access tokens (refresh token exchange, cached in memory) ---

_cache: dict[tuple[str, str], tuple[str, float]] = {}  # (client file, refresh token digest) -> (token, expiry)
_lock = threading.Lock()


def _cache_key(account: Account, refresh_token: str) -> tuple[str, str]:
    return account.client_secret_file, hashlib.sha256(refresh_token.encode()).hexdigest()


def access_token(account: Account, fresh: bool = False) -> tuple[str, bool]:
    """(access token, came from the cache). The refresh token file is read on every call, so a new token
    written by mailroom-mcp-auth is picked up without a restart."""
    refresh_token = read_secret(account.refresh_token_file, f"Refresh token of account '{account.name}'",
                                f"run: {auth_command(account)}")
    key = _cache_key(account, refresh_token)
    with _lock:
        cached = _cache.get(key)
        if cached and not fresh and cached[1] > time.time():
            return cached[0], True
    client_id, client_secret = load_client(account.client_secret_file)
    try:
        answer = post_form(TOKEN_URL, {"grant_type": "refresh_token", "refresh_token": refresh_token,
                                       "client_id": client_id, "client_secret": client_secret})
    except OAuthError as e:
        if e.error in ("invalid_grant", "unauthorized_client"):
            raise ToolError(f"Google refused the refresh token of account '{account.name}' ({e}): it was revoked, "
                            f"expired or issued for another client. Authorize again: {auth_command(account)}") from None
        if e.error == "invalid_client":
            raise ToolError(f"Google refused the OAuth client of account '{account.name}' ({e}): check "
                            f"{account.client_secret_file}") from None
        raise ToolError(f"Google token endpoint refused the refresh for account '{account.name}': {e}") from None
    except OSError as e:
        raise ToolError(f"Cannot reach Google's token endpoint for account '{account.name}': "
                        f"{getattr(e, 'reason', None) or type(e).__name__}. Try again.") from None
    token, lifetime = answer.get("access_token"), answer.get("expires_in", 3600)
    if not isinstance(token, str) or not token:
        raise ToolError(f"Google token endpoint gave no access token for account '{account.name}'")
    if isinstance(lifetime, bool) or not isinstance(lifetime, (int, float)):
        lifetime = 3600
    with _lock:
        _cache[key] = (token, time.time() + max(0, lifetime - EXPIRY_MARGIN))
    return token, False


def forget(account: Account, token: str):
    """Drops a cached access token the IMAP server refused."""
    with _lock:
        for key, (value, _) in list(_cache.items()):
            if value == token:
                del _cache[key]


def xoauth2(user: str, token: str):
    """imaplib authobject for AUTHENTICATE XOAUTH2. On a failure the server sends a JSON challenge: answering
    it with an empty line lets the server end the exchange with NO."""
    def respond(challenge: bytes):
        return b"" if challenge else f"user={user}\x01auth=Bearer {token}\x01\x01".encode()
    return respond


def xoauth2_smtp(user: str, token: str):
    """smtplib authobject for AUTH XOAUTH2: called without a challenge for the initial response; a failure
    challenge (JSON) gets an empty answer, so the server ends the exchange with 535."""
    def respond(challenge: bytes | None = None) -> str:
        return "" if challenge else f"user={user}\x01auth=Bearer {token}\x01\x01"
    return respond


# --- Authorization flow pieces (mailroom-mcp-auth google) ---

def pkce_pair() -> tuple[str, str]:
    """(code_verifier, S256 code_challenge), RFC 7636."""
    verifier = secrets.token_urlsafe(64)  # 86 characters from the unreserved set
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
    return verifier, challenge


def authorization_url(client_id: str, redirect_uri: str, state: str, challenge: str, login_hint: str | None = None) -> str:
    params = {"client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code", "scope": SCOPE,
              "access_type": "offline", "prompt": "consent", "state": state, "code_challenge": challenge,
              "code_challenge_method": "S256"}
    if login_hint:
        params["login_hint"] = login_hint
    return f"{AUTH_URL}?{urllib.parse.urlencode(params)}"


def exchange_code(client_id: str, client_secret: str, code: str, verifier: str, redirect_uri: str) -> dict:
    """Token answer for an authorization code; it must grant a refresh token and the mail scope."""
    answer = post_form(TOKEN_URL, {"grant_type": "authorization_code", "code": code, "code_verifier": verifier,
                                   "client_id": client_id, "client_secret": client_secret,
                                   "redirect_uri": redirect_uri})
    if not answer.get("refresh_token"):
        raise OAuthError("no_refresh_token", "Google gave no refresh token; revoke the app's access in the Google "
                                             "account and try again")
    if SCOPE not in str(answer.get("scope", "")).split():
        raise OAuthError("insufficient_scope", f"the scope {SCOPE} was not granted (got {answer.get('scope')!r})")
    return answer


def granted_email(token: str) -> str | None:
    """Address of the authorized account (Gmail API profile), or None when it cannot be read."""
    request = urllib.request.Request(PROFILE_URL, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            value = json.loads(response.read().decode("utf-8")).get("emailAddress")
    except (OSError, ValueError, AttributeError):
        return None
    return value if isinstance(value, str) else None
