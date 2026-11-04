# Tool reference

Detailed behaviour of each tool. For setup, see the [README](../README.md).

## Accounts

Every tool takes an optional `account`: an account name from `MAIL_ACCOUNTS_FILE`, or its address. With a
single account it can be left out (a different name is an error). With several:

- `list_folders` and `search_messages` cover all accounts by default (`account` omitted or `"*"`), or the one
  named. `list_folders` then returns `{accounts: [{account, delimiter, items}]}` (`{account, error}` for an
  unreachable one), or `{account, delimiter, items}` for one account.
- `read_message`, `move_messages`, `set_flags`, `create_folder`, `save_draft` and `send_draft` require `account`; without it,
  the error lists the account names. Their result starts with `account`.
- Every message row, group and `latest_before` carries `account`. UIDs are per account and folder: pass back the
  `account`, `folder` and `uid` of a row. With a single account nothing changes: no `account` field.
- `aliases` (optional, per account; `MAIL_ALIASES`, comma-separated, for the single account) lists the user's
  other addresses for a mailbox: addresses that forward to it, or that the user sends from. Email addresses,
  deduplicated ignoring case. Mail to an alias is addressed to that account (`to_me`, the To check of
  `answered=false`, `to` left out of rows); mail from any account's user or alias is your own mail
  (`excluded_from_me`). `mailroom-mcp --check` prints the number of aliases of each account.
- A search over several accounts keeps the single-account contract: one date-sorted list, exact pagination,
  size capping, `group_by` over the whole filter (groups are per account: the same sender in two accounts gives
  two groups), `latest_before`. `folders_excluded` becomes `{account: [folders]}`. An unreachable account, or
  one without the requested folder, is left out with a warning instead of failing the search.

## Folders

Wherever a folder is expected (`folder`, `destination`, `reply_to_folder`) you can give its exact name, its name
ignoring case and accents, its role (`Trash`, `Archive`, `Junk`, `Sent`, `Drafts`, resolved through the
SPECIAL-USE attribute, else by name), or its last segment when unique (`Invoices` → `INBOX.Invoices`).
An ambiguous or unknown name is an error listing the candidates. Names always come from the server's `LIST`
and go through `quote()`, which rejects CR, LF and NUL: no IMAP command can be injected.

`list_folders` returns `{delimiter, items: [{name, special_use?, messages, unseen}]}`: INBOX, then special
folders, then the others by name. `special_use` is `All` for a folder holding every message (Gmail's All Mail).

## Gmail

Gmail's IMAP shows each label as a folder, so a message sits in INBOX, in each of its labels and in All Mail
(`[Gmail]/All Mail`, localized, e.g. `[Gmail]/Tous les messages`), with a different UID in each. For any account
whose server advertises the `\All` special-use folder:

- `folder="*"` searches All Mail only, so each message appears once. Trash and Spam are not in All Mail; drafts
  (`\Draft` flag) and mail sent by the account (`From` contains the account's `user`, matched by the server)
  are left out, the way Sent is elsewhere. `folders_excluded` names Sent, Drafts, Trash and Spam;
  `include_excluded_folders=true` adds Trash and Spam and keeps drafts and sent mail. Rows then have the All
  Mail folder: read, flag and move them there.
- A label or INBOX can still be searched by name: `folder="INBOX"`, `folder="Clients"`.
- A UID missing from INBOX or a label (often a row of a `"*"` search passed with `folder="INBOX"`) gets a hint
  in the error of `read_message`, `move_messages`, `set_flags` and `save_draft`, and in their warning for
  partly missing UIDs: `Message 103 not found in INBOX. Rows from folder "*" on this account point to
  [Gmail]/All Mail: pass that folder with the uid.` No other folder is searched. Accounts without a `\All`
  folder keep the plain message.
- Roles go through SPECIAL-USE, whatever the language: `Trash`, `Junk`, `Sent`, `Drafts` find the `[Gmail]/…`
  folders. `Archive` is All Mail when no folder has the Archive role (`\Archive` or by name): archiving is
  leaving the inbox. `move_messages(folder="INBOX", destination="Archive")` uses Gmail's MOVE, which removes the
  Inbox label. From All Mail, `destination="Archive"` removes the Inbox label (`X-GM-LABELS`); the message stays
  where it is.
- Gmail has no server-side SORT: dates are fetched for at most the 2,000 most recently received matching
  messages of a folder; beyond that, older ones follow in arrival order with a warning. Narrow with `days`.
- `answered=false` with `folder="*"` keeps only the messages still labelled `\Inbox`: archived mail is not
  awaiting a reply (`excluded_archived`). The labels (`X-GM-LABELS`) come with the headers already fetched to
  screen the rows; a server without `X-GM-EXT-1` skips this filter.
- Gmail may not set `\Answered` on replies sent from its web interface. So with `answered=false`, a
  conversation whose latest message in All Mail (where the mail you sent is too) is yours, from any configured
  address or alias, awaits no reply: its messages are counted in `excluded_replied`. This costs one `SEARCH` per
  100 conversations (`FROM` you and `X-GM-THRID` any of them) and one `FETCH` per 400 of your messages found,
  never one command per conversation. A forward you sent in the conversation counts as your answer.

## `search_messages`

- `folder`: one folder, a list, or `"*"` for the whole received mailbox. With `"*"`, Trash, Junk, Drafts, Sent
  and technical folders are left out (`include_excluded_folders=true` brings back the first four;
  `folders_excluded` names them). Sent is excluded because `"*"` serves questions about *received* mail
  ("my unread mail", "waiting for my answer", "grouped by sender"). To search what you sent: `folder="Sent"`.
  For Gmail, see [Gmail](#gmail).
- Unread everywhere: `folder="*", unread_only=true`. Waiting for your answer: `folder="*", answered=false`:
  mail not replied to, addressed to you in To (not only in Cc, not only through a list), with automated mail,
  calendar invitations (answered from the calendar), your own mail and archived mail left out. Your own mail is
  mail whose `From` is the address or an alias of any configured account, not only the row's own (a work mail
  you forwarded to your personal mailbox), compared like `to_me`. Archived mail, with `"*"` (alone or in a list):
  the folder `Archive` names (SPECIAL-USE, else by name, e.g. `INBOX.Archive`) and its subfolders; for Gmail,
  mail without the Inbox label. A folder named explicitly (`folder="Archive"`) is searched as asked.
  `excluded_archived`, `excluded_from_me`, `excluded_automated`, `excluded_invites`, `excluded_not_to_me` and,
  for Gmail, `excluded_replied` (see [Gmail](#gmail)) count what was left out for each reason (each message
  once, in that order: where a message is, then what its headers say, then its conversation), present when
  above 0. Archive folders are only counted (one search each, no headers read).
  Invitations and archived mail are only left out with `answered=false`: any other search keeps them.
- One row per conversation with `answered=false`: the messages left of a conversation collapse into the newest
  one, whose `in_thread` gives their number (present when above 1). The conversation is Gmail's `X-GM-THRID`
  (fetched with the headers), else the first Message-ID of `References`, else `In-Reply-To`, else the message's
  own Message-ID (the root of a thread is the first reference of its replies); without any of them, the subject
  without `Re`/`Fwd`/`Fw`/`TR`/`AW`/`WG` prefixes, case or accents. Messages of different accounts never
  collapse; folders of one account do (a reply filed in a subfolder). `total`, `has_more` and `next_offset`
  count conversations, and so does `group_by` (by the newest message's sender or folder). Beyond 2,000 messages
  nothing is examined (see below), so nothing collapses either. A reply that drops `References` and keeps only
  `In-Reply-To` starts a new conversation from its parent.
- `invite: true` marks a calendar invitation, update, reply or cancellation: a `text/calendar` part with a
  `method` parameter (iTIP, as Google, Outlook and Apple send them) or not attached as a file, read from the
  `BODYSTRUCTURE` fetched with the row. A `.ics` file a person attaches by hand is not an invitation; in
  `read_message`, `.ics` files stay in `attachments`.
- `automated`: `"include"` (default), `"exclude"` (default with `answered=false`) or `"only"`, with any filter
  and with `group_by`; an explicit value wins. Automated rows carry `auto: true`, and so does a group whose
  messages are all automated. A message is automated when it has:
  - `List-Id` or `List-Unsubscribe`, `Precedence: bulk`, `list` or `junk`, `Auto-Submitted` other than `no`,
    `X-Autoreply` or `X-Autorespond`, or an empty `Return-Path` (bounces);
  - a header added by bulk and transactional sending platforms: `Feedback-ID` (Amazon SES, Google, Mailchimp…),
    `X-SES-Outgoing`, `X-Mailgun-Sid`, `X-SG-EID` or `X-SG-ID` (SendGrid), `X-MC-User` (Mailchimp),
    `X-Mandrill-User`, `X-PM-Message-Id` (Postmark), `X-CSA-Complaints` (certified bulk senders);
  - a sender whose local part has a whole token such as `noreply`, `no-reply`, `donotreply`, `ne-pas-repondre`,
    `notification(s)`, `notify`, `alert(s)`, `news`, `newsletter`, `mailer-daemon`, `postmaster` or `bounce`;
  - or a transactional local part, made only of words such as `billing`, `invoice(s)`, `receipt(s)`,
    `payment(s)`, `order(s)`, `shipping`, `shipment(s)`, `confirm`, `confirmation`, `account`, `security`, with
    `auto`, `update(s)`, `tracking`, `status`, `notice(s)` or `statement(s)` around them: `billing@`,
    `auto-confirm@`, `shipment-tracking@`, `receipts+acct_…@` (a `+tag` is ignored). `account.manager@` or
    `security-team@` stay human.

  Precision first: `info@`, `contact@`, `support@` or `accounts@` alone is not automated (their replies are
  often written by people), and neither is a calendar invitation Google sends for a person (`Sender` is not
  looked at); a person writing to a mailing list is list mail. These headers come with the other headers of each
  row or group: no extra command per message. Known limits: a person's reply sent through a sending platform (a
  help desk relaying a support agent's answer through Amazon SES, so with `Feedback-ID`), a person's message
  relayed by a platform from a no-reply address ("Grace via Market <no-reply@…>"), and a person answering from
  a transactional address (`billing@`) are automated; a person's mail without any of these markers stays human.
- `to_me`: `true` keeps mail where your address is in To or Cc; `false` turns off the To check of
  `answered=false`. Addresses are compared with the row's own account (its user and its aliases), ignoring
  case, quotes and a `+tag` (and dots for Gmail).
- Filtering automated mail, invitations, your own mail or by recipient reads headers (and, for invitations,
  the structure) of every match in one command per 400 messages: beyond 2,000 messages it is skipped
  with a warning (`answered=false`), or refused for an explicit `automated="only"` or `to_me=true`.
- Dates: `since` (included) / `before` (excluded) as `YYYY-MM-DD`, or `days` (last N days, today included,
  in `MAIL_TIMEZONE`), exclusive with `since`. Applied to the day of the `Date` header.
- Sorted by message date (`Date` header, falling back to INTERNALDATE), across folders too.
- Pagination: `limit` 1–100 (default 20) is a maximum, `offset`. Response
  `{total, returned, has_more, next_offset, capped?, excluded_archived?, excluded_from_me?, excluded_automated?,
  excluded_invites?, excluded_not_to_me?, excluded_replied?, folders_excluded?, latest_before?, warnings?, messages}`.
  The list fits in about 7,500 characters; when shortened, `capped` `{reason: "size", returned, requested,
  resumable: true}` says so and `next_offset` resumes exactly. `snippet_chars=0` makes rows smaller, so more
  of them fit in a page.
- Each message: `uid, folder, date, from, to?, subject, unread?, flagged?, answered?, has_attachments?, auto?,
  invite?, in_thread?, snippet`.
  `to` is omitted when it is only yourself (the account's user or aliases), and keeps its first 2 recipients
  otherwise, the others counted (`Ann <a@x.org>, Bob <b@x.org> +3`; `read_message` gives them all); booleans appear only when true. `snippet_chars` (default 100, 0–300;
  0 means no preview and no body read) comes from Dovecot's PREVIEW or a partial `BODY.PEEK`. Nothing is ever
  marked as read. Previews are cleaned: no CSS or HTML leftovers (even a style sheet cut short), invisible
  characters, bare URLs, separator lines, "view in your browser" placeholders, nor the header block a forward
  or an Outlook reply starts with (its subject stays).
- Empty window: when `since` or `days` is given and nothing matches, `latest_before`
  `{date, folder, uid, from, subject}` gives the latest message matching the same filters in the year before
  ("nothing this month; the last one is from October 22nd").
- `group_by: "sender"` or `"folder"`: `{total, grouped, groups_total, returned, has_more, next_offset, groups}`,
  each group `{sender, folder, count, unread, latest_date, latest_subject, latest_uid, auto?}`, largest first, computed
  over the whole filter. Beyond 1,000 messages only the most recent are grouped (`capped`, `resumable: false`).
- `sender`, `recipient`, `subject` ignore case and accents ("etat des lieux" finds "État des lieux"), which IMAP
  servers do not do: candidate headers are filtered locally. Beyond 2,000 candidates in a folder, the server's
  own search is used instead (with a warning); narrowing with `days` or `since`/`before` restores it.
- To search subjects only, use `subject`; `text` also searches the sender and the body. Like `text`, `subject`
  takes a term or a list of at most 10 terms of which any may match (`["devis", "quote"]`); `sender` and
  `recipient` take one term. Different filters must all match.
- `text`: a term, or a list of at most 10 terms of which any may match (`["facture", "invoice", "reçu"]`, IMAP
  `OR`). Searched in the subject, the sender and the body, not in the recipients (otherwise every mail of a
  mailbox would match its own address): subject and sender are compared locally like `subject`, the server
  searches the body (`BODY`, never `TEXT`) with the term as typed and without accents. Known limit: a term typed
  without accents does not find an accented body, so give both spellings (`["reçu", "recu"]`).

## `read_message`

Only what is needed is downloaded: `BODYSTRUCTURE` and headers first, then the single chosen text part
(`text/plain` preferred, else `text/html` converted), decoded according to its transfer encoding and charset.
Attachments are never downloaded: `attachments` `[{filename, content_type, size}]` comes from the structure.
Only real files are attachments. Images shown in the body (signature logos, pasted pictures: an image in a
`multipart/related`, or with a Content-ID and no disposition) are only counted, in `inline_images` (present when
above 0); an image with an `attachment` disposition, or an inline one outside `multipart/related` (Apple Mail),
is a file. S/MIME and OpenPGP signatures and keys are neither. `has_attachments` in `search_messages` follows
the same rule, from the `BODYSTRUCTURE` of each message.
A text part over 2 MB is only read from its start (with a warning).

`strip_quotes` (default true) removes quoted replies, `>` lines, long legal disclaimers and `[cid:…]` leftovers,
leaving a `[… N quoted lines removed …]` marker; `strip_quotes=false` gives the raw text. Text comes in pages of
`max_chars` (default 8,000, max 100,000) cut on a paragraph, line or word: `body_chars` is the full length of
the cleaned text, `next_offset` the position in that text where the next page starts, to pass as `offset` (null
at the end). It counts characters of the cleaned text, not of the raw message, and pages end on a paragraph:
it can be below `max_chars` while more text follows.

## Sorting and drafts

- `move_messages`: `{folder, destination, moved, not_found, warnings?}`. UIDs are checked in the source folder
  first (`UID SEARCH`), because `UID MOVE` on missing UIDs succeeds silently. Missing UIDs are reported; if none
  exists, it is an error and nothing is attempted. Without MOVE, falls back to COPY + targeted `UID EXPUNGE`
  (UIDPLUS required: never a global expunge).
- `set_flags`: `{folder, updated, not_found, warnings?}`, same check.
- `create_folder`: `{folder, subscribed, warnings?}`. An existing folder is an error.
- `save_draft`: `{folder, uid, threaded, warnings?}`. `threaded` tells whether `In-Reply-To` and `References`
  attach the draft to its thread. Line breaks or NUL in `to`, `cc` or `subject` are rejected (they would inject
  headers such as `Bcc`), as is an address without `@`. A missing original message is an error rather than a
  draft silently detached from its thread.

## `send_draft`

Drafts can be sent with `send_draft` using a preview and confirmation tied to the exact draft.
With code-based confirmation, the assistant must obtain the user's approval: the server cannot independently
verify human consent, because the assistant receives the code and can submit it itself. No tool
sends free text: the mail is written with `save_draft` (or in a mail client) first.

- Off unless enabled: `"send": true` on the account in `MAIL_ACCOUNTS_FILE`, or `MAIL_SEND_ENABLED=true` for the
  single account. `MAIL_SEND_LIMIT_PER_HOUR` (default 20, per server process) caps sends; `0` disables sending
  for every account. A refused call says that nothing was sent.
- First call, `{uid, folder?, account?}`: nothing is sent. The draft is read from Drafts (another folder only for a
  message flagged `\Draft`); its From must be the account's address or an alias, and every To, Cc and Bcc address
  valid. Answer: `{account?, sent: false, folder, uid, from, to, cc?, bcc?, subject, body, attachments?, reply?,
  reply_subject?, confirmation, expires, next}`: `bcc` counts the hidden recipients, `body` is the first 300
  characters, `attachments` lists file names, `reply_subject` is the subject of the message replied to (found by
  Message-ID in INBOX, or All Mail on Gmail). `confirmation` is bound to the account, the uid and the SHA-256 of
  the draft's exact content; it is valid 10 minutes, used once and kept in memory only (a restart forgets it).
- Second call, with `confirmation`, only once the user approved in the conversation: the draft is read again and
  any change is refused (a new preview is needed). Answer: `{account?, sent: true, to, subject, message_id,
  saved_to?, draft_removed, warnings?}`.
- Confirmation dialog: when the client supports form elicitation, the first call asks the user directly ("Send this
  mail now?" with from, to, cc, the number of Bcc, subject, attachments and the start of the body) and sends on
  approval, without a code: a server request on handshake-era connections, an `InputRequiredResult` answered on the
  client's retry on 2026-07-28 connections. Declined or dismissed: `{sent: false, declined: true, note}` and no code.
  A client that cannot show it (no elicitation capability, stateless HTTP without a back-channel, an error) gets the
  code instead. The draft is read again before sending, as with a code.
- Sending: envelope sender the account's user, recipients To + Cc + Bcc; the Bcc header is removed from the
  transmitted message (the Sent copy keeps it); Date is the time of sending, a Message-ID is added when missing.
  SMTP over implicit TLS (`ssl`, port 465 by default) or STARTTLS, certificate verified with the default SSL context;
  password login, or XOAUTH2 with the account's Google token (the `https://mail.google.com/` scope covers SMTP).
- Afterwards: a copy is appended to the Sent folder with `\Seen`, except through Gmail's SMTP, which files sent mail
  itself (`saved_to` names the Sent folder in both cases); the draft moves to Trash. Failures there are warnings
  that start with "The mail WAS sent: do not send it again."; refused recipients are a warning too when others got
  the mail.
- Errors: `The mail was not sent: <what> (<SMTP reply>). Nothing left the mailbox.`, then "This looks temporary"
  (a 4xx reply, a connection failure) or "Retrying as is will fail the same way" (5xx, authentication,
  certificate); after a code, the confirmation stays valid for a retry. A connection lost while the message is
  transmitted reads `The mail may have been sent: …`, with the advice to check Sent first; that code is used up.

## Errors and dates

Errors are readable sentences on both transports: an IMAP refusal reads
`The IMAP server refused '<action>': <decoded answer>`. A timeout or a lost connection, at login or later,
reads `The IMAP server did not answer in time (account <name>): try again.` (or `IMAP connection lost …`); for
writes it says to check before retrying instead (`send_draft` says whether the mail was sent, see above). Other unexpected exceptions become
`Unexpected error in <tool> (<type>)` instead of a generic failure, with the same reminder for writes. Output dates are ISO 8601 in `MAIL_TIMEZONE` (`2026-10-21T08:00:00+02:00`).
