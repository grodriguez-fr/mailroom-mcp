"""SMTP submission of a message prepared by send_draft. Standard library only (smtplib), TLS always verified.

Every failure is a SendError that says whether the mail left: `maybe` is False when nothing was transmitted
(the error tells whether retrying can help), True when the connection failed while the message was being
transmitted, so it may have been delivered. The session is driven command by command (MAIL, RCPT, DATA) to
know exactly where it stopped. Secrets are read on use and never logged.
"""

import smtplib
import ssl

from fastmcp.exceptions import ToolError

from mailroom_mcp import google_oauth
from mailroom_mcp.config import Account, account_password

TIMEOUT = 30  # seconds per network operation


class SendError(ToolError):
    """The mail could not be sent (maybe=False), or may have been sent (maybe=True)."""

    def __init__(self, message: str, *, maybe: bool = False, retryable: bool = False):
        self.maybe, self.retryable = maybe, retryable
        super().__init__(message)


def reply_text(value) -> str:
    """Readable server reply, at most 200 characters."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    text = " ".join(str(value or "").split())
    return (text[:199] + "…" if len(text) > 200 else text) or "no details"


def error_text(error: BaseException) -> str:
    if isinstance(error, smtplib.SMTPResponseException):
        return f"{error.smtp_code} {reply_text(error.smtp_error)}"
    return reply_text(str(error)) if str(error) else type(error).__name__


def not_sent(what: str, detail: str, retryable: bool, fix: str = "") -> SendError:
    if retryable:
        advice = "This looks temporary: trying again in a few minutes may work."
    else:
        advice = "Retrying as is will fail the same way" + (f": {fix}." if fix else ".")
    return SendError(f"The mail was not sent: {what} ({detail}). Nothing left the mailbox. {advice}",
                     retryable=retryable)


def refused(what: str, code: int, reply, fix: str = "") -> SendError:
    """A refusal by SMTP reply code: 4xx is temporary, 5xx permanent."""
    return not_sent(what, f"{code} {reply_text(reply)}", 400 <= code < 500, fix)


def may_have_been_sent(detail: str) -> SendError:
    return SendError(f"The mail may have been sent: the connection to the SMTP server failed while the message was "
                     f"being transmitted ({detail}). Check the Sent folder, or with the recipients, before doing "
                     "anything: do not send it again blindly.", maybe=True)


def where(account: Account) -> str:
    return f"{account.smtp_host}:{account.smtp_port}"


def close(smtp):
    try:
        smtp.quit()
    except Exception:
        try:
            smtp.close()
        except Exception:
            pass


def xoauth2(smtp, account: Account, token: str, cached: bool):
    """AUTH XOAUTH2 with the account's Google access token (the IMAP one: the mail.google.com scope covers
    SMTP). A cached token the server refuses is renewed once."""
    try:
        smtp.auth("XOAUTH2", google_oauth.xoauth2_smtp(account.user, token), initial_response_ok=True)
    except smtplib.SMTPAuthenticationError:
        google_oauth.forget(account, token)
        if not cached:
            raise
        token, _ = google_oauth.access_token(account, fresh=True)
        smtp.auth("XOAUTH2", google_oauth.xoauth2_smtp(account.user, token), initial_response_ok=True)


def open_session(account: Account):
    """Authenticated SMTP session: implicit TLS (ssl) or STARTTLS, certificate verified. Raises SendError."""
    try:
        if account.auth == "password":
            password, token, cached = account_password(account), None, False
        else:
            password, (token, cached) = None, google_oauth.access_token(account)
    except ToolError as e:
        raise SendError(f"The mail was not sent: {e}") from None
    context = ssl.create_default_context()
    try:
        if account.smtp_security == "ssl":
            smtp = smtplib.SMTP_SSL(account.smtp_host, account.smtp_port, timeout=TIMEOUT, context=context)
        else:
            smtp = smtplib.SMTP(account.smtp_host, account.smtp_port, timeout=TIMEOUT)
    except ssl.SSLCertVerificationError as e:
        raise not_sent(f"the certificate of the SMTP server {where(account)} could not be verified",
                       reply_text(e.verify_message or str(e)), False, "check the smtp host") from None
    except Exception as e:
        raise not_sent(f"cannot connect to the SMTP server {where(account)}", error_text(e), True) from None
    try:
        smtp.ehlo()
        if account.smtp_security == "starttls":
            if not smtp.has_extn("starttls"):
                raise not_sent(f"the SMTP server {where(account)} does not offer STARTTLS", "no STARTTLS in EHLO",
                               False, 'use "security": "ssl" or another port')
            smtp.starttls(context=context)
            smtp.ehlo()
        if password is not None:
            smtp.login(account.user, password)
        else:
            xoauth2(smtp, account, token, cached)
    except SendError:
        close(smtp)
        raise
    except smtplib.SMTPAuthenticationError as e:
        close(smtp)
        fix = ("authorize the account again with mailroom-mcp-auth" if account.auth == "google-oauth"
               else "check the password (an app password for Gmail) and that SMTP is allowed for this mailbox")
        raise not_sent(f"SMTP authentication failed for {account.user}", error_text(e), False, fix) from None
    except smtplib.SMTPNotSupportedError as e:
        close(smtp)
        raise not_sent(f"the SMTP server {where(account)} offers no suitable authentication", error_text(e), False,
                       "check the smtp host and port (a submission server, not a relay)") from None
    except smtplib.SMTPResponseException as e:
        close(smtp)
        raise refused(f"the SMTP server {where(account)} refused the session", e.smtp_code, e.smtp_error) from None
    except ssl.SSLCertVerificationError as e:
        close(smtp)
        raise not_sent(f"the certificate of the SMTP server {where(account)} could not be verified",
                       reply_text(e.verify_message or str(e)), False, "check the smtp host") from None
    except ToolError as e:  # Google refused to renew the access token
        close(smtp)
        raise SendError(f"The mail was not sent: {e}") from None
    except Exception as e:
        close(smtp)
        raise not_sent(f"connection to the SMTP server {where(account)} lost", error_text(e), True) from None
    return smtp


def transmit(smtp, sender: str, recipients: list[str], data: bytes) -> dict[str, str]:
    """MAIL, RCPT for each recipient, DATA. Returns the recipients the server refused while accepting others
    ({address: reply}); raises SendError when nothing was sent or the outcome is unknown."""
    utf8 = any(not s.isascii() for s in (sender, *recipients))
    options = []
    try:
        if utf8:
            if not smtp.has_extn("smtputf8"):
                raise not_sent("an address is not ASCII and the SMTP server does not support SMTPUTF8",
                               ", ".join(a for a in (sender, *recipients) if not a.isascii()), False)
            options.append("SMTPUTF8")
        if any(byte > 127 for byte in data) and smtp.has_extn("8bitmime"):
            options.append("BODY=8BITMIME")
        code, reply = smtp.mail(sender, options)
        if code != 250:
            raise refused(f"the SMTP server refused the sender {sender}", code, reply,
                          "the account may not be allowed to send from this address")
        rejected = {}
        for recipient in recipients:
            code, reply = smtp.rcpt(recipient)
            if code not in (250, 251):
                rejected[recipient] = f"{code} {reply_text(reply)}"
        if len(rejected) == len(recipients):
            try:
                smtp.rset()
            except Exception:
                pass
            temporary = all(r.startswith("4") for r in rejected.values())
            detail = "; ".join(f"{a}: {r}" for a, r in rejected.items())
            raise not_sent("the SMTP server refused every recipient", detail, temporary,
                           "check the addresses of the draft")
    except SendError:
        raise
    except Exception as e:
        raise not_sent("connection to the SMTP server lost before the message was transmitted", error_text(e),
                       True) from None
    # From here on the message may leave: a failure without a final answer means it may have been delivered.
    try:
        code, reply = smtp.data(data)
    except smtplib.SMTPDataError as e:  # DATA itself refused: nothing was transmitted
        raise refused("the SMTP server refused the message", e.smtp_code, e.smtp_error) from None
    except Exception as e:
        raise may_have_been_sent(error_text(e)) from None
    if code != 250:
        raise refused("the SMTP server refused the message", code, reply, "the message may be too large or "
                      "considered spam")
    return rejected


def send(account: Account, sender: str, recipients: list[str], data: bytes) -> dict[str, str]:
    """Sends `data` (a complete message, CRLF line endings) to `recipients`; see transmit."""
    smtp = open_session(account)
    try:
        return transmit(smtp, sender, recipients, data)
    finally:
        close(smtp)
