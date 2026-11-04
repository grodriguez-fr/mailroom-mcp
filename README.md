# mailroom-mcp

One self-hosted [MCP](https://modelcontextprotocol.io) server for your mail, shared by all your AI assistants
(Claude, ChatGPT, Codex…). Search, read, sort and draft, with compact answers.

> **Early.** Several IMAP mailboxes, Gmail / Google Workspace included (OAuth). Microsoft 365 is next.

## Why

Each AI vendor connects its own mailboxes: one inbox ends up in Claude, another in ChatGPT, and no model sees
them all. mailroom-mcp owns the mail access instead. Add a mailbox once, and every assistant can use it.

- **Safe by default**: reading never marks as read, no permanent deletion, replies are drafts. Sending is off
  unless you enable it, with a preview and confirmation tied to the exact draft. In code-based confirmation,
  your assistant must ask for your approval; the server cannot verify that the assistant actually asked you.
- **Mail is data, not instructions**: the model is told so.
- **Light on context**: compact JSON, paginated, strict parameters.

## Quick start

With [uv](https://docs.astral.sh/uv/), put your IMAP password in `~/.config/mailroom-mcp/password` (mode 600), then:

```sh
claude mcp add mail -e MAIL_IMAP_HOST=imap.example.org -e MAIL_USER=me@example.org \
  -- uvx --from git+https://github.com/grodriguez-fr/mailroom-mcp mailroom-mcp
```

For Codex:

```sh
codex mcp add mail --env MAIL_IMAP_HOST=imap.example.org --env MAIL_USER=me@example.org \
  -- uvx --from git+https://github.com/grodriguez-fr/mailroom-mcp mailroom-mcp
```

Run the server with `--check` to test the login without reading mail.
To reach it from ChatGPT or your phone, run it remotely: [docs/deployment.md](docs/deployment.md).

| Variable | Default |
|---|---|
| `MAIL_IMAP_HOST`, `MAIL_USER` | required |
| `MAIL_IMAP_PORT` | `993` |
| `MAIL_PASSWORD_FILE` | `~/.config/mailroom-mcp/password` |
| `MAIL_ALIASES` | unset: your other addresses, comma-separated |
| `MAIL_TIMEZONE` | `UTC` |
| `MAIL_SEND_ENABLED` | `false`: `true` lets `send_draft` send drafts, after your approval |
| `MAIL_SMTP_HOST`, `MAIL_SMTP_PORT`, `MAIL_SMTP_SECURITY` | the IMAP host (`smtp.gmail.com` for Gmail), `465`, `ssl` (`starttls` on 587) |
| `MAIL_SEND_LIMIT_PER_HOUR` | `20` mails per hour; `0` disables sending |
| `MAIL_ACCOUNTS_FILE` | unset: several accounts, see below |

## Several mailboxes

Point `MAIL_ACCOUNTS_FILE` at a JSON list of accounts instead of setting `MAIL_IMAP_HOST` and `MAIL_USER`.
Relative paths are relative to that file; secrets stay in their own files (mode 600), read on use.

```json
[
  {"name": "perso", "host": "imap.example.org", "user": "me@example.org",
   "aliases": ["me@old-job.example"],
   "auth": {"type": "password", "password_file": "perso.password"}},
  {"name": "work", "user": "me@company.com", "send": true,
   "auth": {"type": "google-oauth", "client_secret_file": "google-client.json",
            "refresh_token_file": "work.token"}}
]
```

`port` defaults to 993 and, for `google-oauth`, `host` to `imap.gmail.com`. Names are short slugs
(`[a-z0-9-]`). `aliases` (optional) lists your other addresses for that mailbox, the ones that forward to it or
that you send from: mail to them is addressed to you, mail from them is your own. `"send": true` (optional, off by
default) lets the account send drafts; `"smtp": {"host", "port", "security"}` (optional, `"ssl"` or `"starttls"`)
overrides the server, which defaults to `smtp.gmail.com:465` for Gmail and to the IMAP host on port 465 otherwise.
For a Gmail account, create the OAuth client and the refresh token once:
[docs/google-oauth.md](docs/google-oauth.md). `mailroom-mcp --check` then tests every account.
Every tool takes an optional `account`; searches cover all accounts by default.

## Tools

`list_folders`, `search_messages` (one folder, several or the whole mailbox; unread, awaiting your reply,
automated mail apart, by sender…),
`read_message` (clean text, attachments listed), `move_messages`, `set_flags`, `create_folder`, `save_draft`.
Drafts can be sent with `send_draft` after your explicit approval (two steps: a preview, then a confirmation).
Details: [docs/tools.md](docs/tools.md).

## Roadmap

1. Microsoft 365 over OAuth.
2. Remote access from Claude connectors, not only ChatGPT.

## Development

```sh
uv sync && uv run pytest && uv run ruff check src tests
```

Contributions welcome. Security issues: please use a private GitHub security advisory.

## License

[MIT](LICENSE)
