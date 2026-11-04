"""Personal HTTP MCP server: Google OAuth handled by FastMCP, access closed by default (one owner only)."""

import os
from pathlib import Path
from urllib.parse import urlparse

from fastmcp import FastMCP
from fastmcp.server.auth.providers.google import GoogleProvider
from starlette.responses import JSONResponse

from mailroom_mcp import server as mail


class OwnerGoogleProvider(GoogleProvider):
    """Only allows the configured Google subject, never the first account that signs in."""

    def __init__(self, *, owner_sub: str, **kwargs):
        if not owner_sub or not owner_sub.isdecimal():
            raise ValueError("MAIL_GOOGLE_SUB must be the owner's permanent Google account ID (numeric 'sub')")
        self.owner_sub = owner_sub
        super().__init__(**kwargs)

    async def load_access_token(self, token):
        validated = await super().load_access_token(token)
        if validated is None:
            return None
        if validated.claims.get("sub") != self.owner_sub:
            return None
        if validated.subject != self.owner_sub:
            return None
        if validated.claims.get("email_verified") not in (True, "true"):
            return None
        return validated


def create_server():
    mail.accounts()  # MAIL_ACCOUNTS_FILE, or MAIL_IMAP_HOST and MAIL_USER: refuse to start without them
    base_url = os.environ["MAIL_PUBLIC_URL"].rstrip("/")
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username:
        raise ValueError("MAIL_PUBLIC_URL must be an HTTPS origin without a path")
    secret = Path(os.environ["MAIL_GOOGLE_CLIENT_SECRET_FILE"]).read_text().strip()
    if not secret:
        raise ValueError("Empty Google OAuth client secret")
    auth = OwnerGoogleProvider(
        owner_sub=os.environ["MAIL_GOOGLE_SUB"],
        client_id=os.environ["MAIL_GOOGLE_CLIENT_ID"],
        client_secret=secret,
        base_url=base_url,
        required_scopes=["openid", "email"],
        valid_scopes=["openid", "email"],
        allowed_client_redirect_uris=[
            "https://chatgpt.com/connector_platform_oauth_redirect",
            "https://chatgpt.com/aip/*/oauth/callback",
        ],
        forward_resource=False,
        require_authorization_consent=True,
        fastmcp_access_token_expiry_seconds=900,
    )
    # Same tools, annotations and readable errors as the stdio transport (server.build). server.py raises
    # FastMCP's ToolError: its messages get through mask_error_details, other exceptions stay masked.
    mcp = FastMCP("mail", auth=auth, mask_error_details=True, instructions=mail.instructions(remote=True))
    mail.build(mcp, meta={"securitySchemes": [{"type": "oauth2", "scopes": ["openid", "https://www.googleapis.com/auth/userinfo.email"]}]})

    @mcp.custom_route("/healthz", methods=["GET"])
    async def health(request):
        return JSONResponse({"status": "ok"})

    return mcp


def main():
    """`mailroom-mcp-http`: Streamable HTTP on port 8000, endpoint /mcp, behind an HTTPS proxy."""
    create_server().run(transport="http", host="0.0.0.0", port=8000,
                        path="/mcp", stateless_http=True, show_banner=False,
                        log_level="warning", allowed_hosts=[urlparse(os.environ["MAIL_PUBLIC_URL"]).netloc, "localhost", "127.0.0.1:8000"],
                        uvicorn_config={"access_log": False})


if __name__ == "__main__":
    main()
