"""`mailroom-mcp-auth`: authorizes a mailbox and stores its refresh token in a file (mode 600).

    mailroom-mcp-auth google --client-secret-file client.json --refresh-token-file gmail.token \
        [--login-hint me@example.com] [--port 8765] [--force]

Loopback flow for a Google "Desktop app" OAuth client: a one-shot HTTP listener on 127.0.0.1 receives the
redirect, the state is checked, the code is exchanged with PKCE (S256). Only the granted address and scope are
printed, never a token.
"""

import argparse
import hmac
import http.server
import os
import secrets
import sys
import tempfile
import time
import urllib.parse

from fastmcp.exceptions import ToolError

from mailroom_mcp import google_oauth

WAIT_SECONDS = 600
PAGE = ("<!doctype html><meta charset=utf-8><title>mailroom-mcp</title>"
        "<p style='font-family:sans-serif'>{}</p>")


class AuthError(Exception):
    """Failure of the authorization flow, printed as is."""


def write_token(path: str, token: str, force: bool = False):
    """Writes the refresh token with mode 600: refuses to overwrite an existing file unless force is set.
    With force, the new file replaces the old one atomically."""
    path = os.path.abspath(os.path.expanduser(path))
    directory = os.path.dirname(path)
    if not os.path.isdir(directory):
        raise AuthError(f"Directory not found: {directory}")
    if os.path.lexists(path) and not force:
        raise AuthError(f"{path} already exists: add --force to replace it")
    if not force:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(token + "\n")
        return
    fd, temporary = tempfile.mkstemp(dir=directory, prefix=".mailroom-token-")  # mode 600
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(token + "\n")
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def parse_redirect(path: str, state: str) -> str:
    """Authorization code from the redirect's path and query, after checking the state."""
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
    received = query.get("state", [""])[0]
    if not hmac.compare_digest(received.encode(), state.encode()):
        raise AuthError("The redirect's state does not match this authorization request: ignored. "
                        "Open the URL printed by this command, in the same session.")
    if "error" in query:
        raise AuthError(f"Google refused the authorization: {query['error'][0]}")
    code = query.get("code", [""])[0]
    if not code:
        raise AuthError("The redirect carries no authorization code")
    return code


def listener(port: int) -> http.server.HTTPServer:
    try:
        return http.server.HTTPServer(("127.0.0.1", port), http.server.BaseHTTPRequestHandler)
    except OSError as e:
        raise AuthError(f"Cannot listen on 127.0.0.1:{port}: {e.strerror or e}") from None


def wait_for_code(server: http.server.HTTPServer, state: str, timeout: float = WAIT_SECONDS) -> str:
    """Serves requests on the loopback listener until one carries the authorization answer. Other requests
    (favicon…) get a 404; a redirect with a wrong state is refused and waiting goes on."""
    outcome: dict = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            if "state" not in query:
                self.answer(404, "Not found.")
                return
            try:
                outcome["code"] = parse_redirect(self.path, state)
                self.answer(200, "Authorization received: you can close this tab and go back to the terminal.")
            except AuthError as e:
                if hmac.compare_digest(query["state"][0].encode(), state.encode()):
                    outcome["error"] = e
                self.answer(400, str(e))

        def answer(self, status, text):
            body = PAGE.format(text).encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # the query string holds the code: never logged
            pass

    server.RequestHandlerClass = Handler
    server.timeout = 1
    deadline = time.monotonic() + timeout
    while not outcome:
        if time.monotonic() > deadline:
            raise AuthError(f"No authorization received within {int(timeout)} seconds")
        server.handle_request()
    if "error" in outcome:
        raise outcome["error"]
    return outcome["code"]


def google(args) -> int:
    try:
        client_id, client_secret = google_oauth.load_client(os.path.expanduser(args.client_secret_file))
    except ToolError as e:
        raise AuthError(str(e)) from None
    target = os.path.abspath(os.path.expanduser(args.refresh_token_file))
    if os.path.lexists(target) and not args.force:
        raise AuthError(f"{target} already exists: add --force to replace it")
    if not os.path.isdir(os.path.dirname(target)):
        raise AuthError(f"Directory not found: {os.path.dirname(target)}")
    server = listener(args.port)
    try:
        redirect_uri = f"http://127.0.0.1:{server.server_address[1]}/"
        state = secrets.token_urlsafe(32)
        verifier, challenge = google_oauth.pkce_pair()
        url = google_oauth.authorization_url(client_id, redirect_uri, state, challenge, args.login_hint)
        print("Open this URL in a browser and sign in with the mailbox's Google account:\n")
        print(url + "\n")
        print(f"Waiting for the redirect on {redirect_uri} … (Ctrl-C to cancel)", flush=True)
        code = wait_for_code(server, state)
    finally:
        server.server_close()
    try:
        answer = google_oauth.exchange_code(client_id, client_secret, code, verifier, redirect_uri)
    except google_oauth.OAuthError as e:
        raise AuthError(f"Code exchange refused: {e}") from None
    except OSError as e:
        raise AuthError(f"Cannot reach Google's token endpoint: {getattr(e, 'reason', None) or e}") from None
    write_token(target, answer["refresh_token"], args.force)
    email = google_oauth.granted_email(answer.get("access_token", ""))
    print(f"Authorized {email or 'the account'} with scope {answer.get('scope')}; refresh token written to {target} (mode 600).")
    if email is None:
        print("(Could not read the address: enable the Gmail API in the Cloud project to see it here. IMAP works without it.)")
    elif args.login_hint and email.lower() != args.login_hint.lower():
        print(f"Warning: you signed in as {email}, not {args.login_hint}: the account's \"user\" must be {email}.")
    return 0


def port(value: str) -> int:
    number = int(value)
    if not 0 <= number < 65536:
        raise argparse.ArgumentTypeError("expected a port number (0 for a random free port)")
    return number


def parser() -> argparse.ArgumentParser:
    main = argparse.ArgumentParser(prog="mailroom-mcp-auth", description="Authorize a mailbox for mailroom-mcp.")
    providers = main.add_subparsers(dest="provider", required=True)
    g = providers.add_parser("google", help="Gmail / Google Workspace (OAuth 2.0, IMAP XOAUTH2)",
                             description="Loopback OAuth flow for a Google Desktop app client, scope "
                                         f"{google_oauth.SCOPE}. Writes the refresh token with mode 600.")
    g.add_argument("--client-secret-file", required=True, help="JSON of the Desktop app OAuth client (Cloud Console)")
    g.add_argument("--refresh-token-file", required=True, help="where to write the refresh token")
    g.add_argument("--login-hint", help="email address of the account to authorize")
    g.add_argument("--port", type=port, default=0, help="loopback port (default: a random free port)")
    g.add_argument("--force", action="store_true", help="replace an existing refresh token file")
    return main


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        return google(args)
    except AuthError as e:
        print(f"mailroom-mcp-auth: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nmailroom-mcp-auth: cancelled", file=sys.stderr)
        return 130
    except OSError as e:
        print(f"mailroom-mcp-auth: {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
