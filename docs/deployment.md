# Remote deployment (HTTP + OAuth)

The stdio transport (`mailroom-mcp`) is enough for clients running on the same machine. To use the server from a
web or mobile client such as ChatGPT, run the HTTP transport (`mailroom-mcp-http`): Streamable HTTP on port 8000, endpoint `/mcp`, health
check `/healthz`, behind HTTPS.

## How access is protected

FastMCP's OAuth proxy handles the MCP side (authorization code, PKCE S256, consent, discovery, tokens). Google
only provides identity (`openid`, `email` scopes): the server never asks Google for mail or Drive access.

Every authenticated request checks the MCP token and the Google token bound to it: Google audience equal to
your OAuth client, Google subject equal to `MAIL_GOOGLE_SUB`, verified identity. Any other Google account is
refused, even if it completes the OAuth flow. The owner is never "whoever connects first", and no setting
allows anonymous access.

MCP client redirect URIs are restricted to ChatGPT's (`allowed_client_redirect_uris` in
`src/mailroom_mcp/remote.py`). Making this list configurable, for Claude custom connectors among others, is on the roadmap.

## Setup

1. **Google OAuth client.** In a Google Cloud project, create an OAuth client of type *Web application* with
   the redirect URI `https://<your-host>/auth/callback`. Only the `openid` and `email` scopes are used.
2. **Your Google subject.** `MAIL_GOOGLE_SUB` is the permanent `sub` claim of your Google account (a long
   number), not your email address. One way to get it: sign in on the
   [OAuth 2.0 Playground](https://developers.google.com/oauthplayground) with the `openid` scope and read
   `sub` from the decoded ID token.
3. **Secrets**, in `deploy/` next to `compose.yaml` (or wherever you copy it), directory 700 and files 600:
   - `secrets/mail-password`: the IMAP password;
   - `secrets/google-client-secret`: the OAuth client secret.

   `secrets/` is mounted read-only at `/run/secrets`. For several mailboxes, put the accounts file there too
   (`secrets/accounts.json`, with paths relative to it, see the [README](../README.md#several-mailboxes)) with
   its password files, Google client JSON and refresh tokens ([google-oauth.md](google-oauth.md)), and set
   `MAIL_ACCOUNTS_FILE=/run/secrets/accounts.json` instead of `MAIL_IMAP_HOST` and `MAIL_USER`. The files must
   be readable by uid 1000. A Gmail account needs outbound HTTPS to `oauth2.googleapis.com`.
4. **`.env`** next to `compose.yaml`: copy `deploy/.env.example` and fill it in (IMAP host and login or
   accounts file, time zone, public URL, Google client ID and subject).
5. **Build and start**, from `deploy/`:
   ```sh
   docker compose config --quiet && docker compose up -d --build
   docker inspect mailroom-mcp --format '{{.State.Health.Status}}'
   ```
   To build on one machine and run on another: `docker build -t mailroom-mcp:<version> .` at the repository
   root, `docker save mailroom-mcp:<version> | ssh <host> docker load`, and set `MAIL_IMAGE` there.
   The container runs as uid 1000 with a read-only root, no capabilities and `no-new-privileges`. OAuth state
   is persisted, encrypted by FastMCP, in `oauth-data/` (key derived from the client secret: rotating the
   secret may require reconnecting clients). Back up `secrets/` and `oauth-data/`.
6. **Expose it over HTTPS.** The port is bound to `127.0.0.1` only: put a reverse proxy or a tunnel in front.
   Check: `GET /healthz` answers 200, an anonymous `POST /mcp` answers 401.

## Connect ChatGPT

In ChatGPT, add a custom MCP connector with the URL `https://<your-host>/mcp` and OAuth authentication
(automatic discovery), then sign in with the authorised Google account. Start with "list my folders".

## Updating and rolling back

Build a new image tag, update `MAIL_IMAGE`, `docker compose up -d`. Keep the previous image until the new one
is checked; rolling back is setting `MAIL_IMAGE` back. When tool outputs change, connected clients must reload
the tool schema (start a new chat).

## Limits

- The authorised owner gets every tool: there are no separate OAuth scopes for reading, sorting, drafting or sending
  (when sending is enabled).
- Moving requires MOVE or UIDPLUS on the IMAP server; without either, the move is refused before any change.
- There is no mail database: IMAP stays the source of truth, and a password rotation must be applied here too.
