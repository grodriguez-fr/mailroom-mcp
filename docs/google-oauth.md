# Gmail and Google Workspace (OAuth)

mailroom-mcp reads Gmail over IMAP with OAuth 2.0 (`XOAUTH2`, scope `https://mail.google.com/`): no app
password. You create an OAuth client once in Google Cloud, then authorize each mailbox with
`mailroom-mcp-auth`, which stores a refresh token in a file. The server exchanges it for short-lived access
tokens (kept in memory only).

This client is not the one of the HTTP transport ([deployment.md](deployment.md)): that one only identifies
you (`openid`, `email`, type *Web application*); this one reads mail (type *Desktop app*).

## Google Cloud Console (Google Workspace, Internal app)

1. **Project**: create one (or pick one) at <https://console.cloud.google.com/>, under your Workspace
   organization.
2. **Gmail API**: *APIs & Services → Library → Gmail API → Enable*. IMAP works without it; the auth command
   uses it to print the authorized address.
3. **Consent screen** (*Google Auth Platform → Branding / Audience*): app name and support email, then
   **Audience: Internal**. Only accounts of your organization can authorize, and refresh tokens do not expire
   after 7 days as they do for External apps in testing.
4. **Data access → Add scope**: `https://mail.google.com/` (a restricted scope: fine for an Internal app).
5. **Clients → Create client → Desktop app**, then **Download JSON**. Store it with mode 600, e.g.
   `~/.config/mailroom-mcp/google-client.json`.
6. IMAP must be allowed for the user (Admin console → Apps → Google Workspace → Gmail → End user access; it is
   on by default).

## Authorize a mailbox

```sh
mailroom-mcp-auth google --client-secret-file ~/.config/mailroom-mcp/google-client.json \
  --refresh-token-file ~/.config/mailroom-mcp/work.token --login-hint me@company.com
```

It prints a URL: open it, sign in with the mailbox's account and accept. Google redirects to a one-shot
listener on `127.0.0.1` (a random port, or `--port P`); the command checks the state, exchanges the code (PKCE),
writes the refresh token with mode 600 and prints only the authorized address and scope. It refuses to replace
an existing file unless `--force` is given.

On a headless server, pick a port and forward it from the machine with the browser:
`ssh -L 8765:127.0.0.1:8765 server`, then `mailroom-mcp-auth google … --port 8765` on the server.

Then add the account to `MAIL_ACCOUNTS_FILE` (`host` defaults to `imap.gmail.com`) and run
`mailroom-mcp --check`:

```json
{"name": "work", "user": "me@company.com",
 "auth": {"type": "google-oauth", "client_secret_file": "google-client.json", "refresh_token_file": "work.token"}}
```

`user` must be the address that was authorized.

## When the token stops working

If access is revoked (from the Google account's security page, by an admin, or by a password change, which
revokes tokens with Gmail scopes), tools answer `Google refused the refresh token of account '…'` with the command to run again.
Re-run it with `--force`; the server picks the new file up without a restart.

Gmail specifics (labels as folders, All Mail, archiving) are in [tools.md](tools.md#gmail).
