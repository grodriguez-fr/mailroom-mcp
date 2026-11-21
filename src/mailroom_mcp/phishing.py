"""Evidence for a phishing check, read from a message already fetched: authentication headers, the real
destination of the links of its HTML body, and a suspicion score built from both. Pure functions on text:
nothing here opens a connection, and a link is never followed."""

import ipaddress
import re
from email.utils import getaddresses
from html.parser import HTMLParser
from urllib.parse import urlsplit

VALUE_MAX = 400          # characters of one header value
RECEIVED_MAX = 20        # Received lines kept (the first ones: the last hops, written by your own server)
LINK_URL_MAX = 300       # characters of a link URL (the domain is always complete)
LINK_TEXT_MAX = 80       # characters of the text shown for a link

# Headers kept as text, in this order; each one may appear several times.
HEADERS = ("From", "Reply-To", "Return-Path", "Sender", "Received", "Authentication-Results",
           "ARC-Authentication-Results", "Received-SPF", "X-Spam-Flag", "X-Spam-Status", "X-Spam-Score", "X-Spam-Bar",
           "X-Spam-Report", "Message-ID", "List-Unsubscribe")
LONG_HEADERS = {"X-Spam-Report": 300}   # verbose by nature: shortened harder than VALUE_MAX
RAW_HEADERS = {"Message-ID"}            # the parsed form stops at the first malformed character: keep the raw text


def unfold(value: str) -> str:
    return " ".join(value.split())


def header_values(msg, name: str) -> list[str]:
    """Every occurrence of a header, in message order, unfolded and decoded when possible."""
    try:
        found = msg.get_all(name) or []
        return [unfold(str(v)) for v in found]
    except Exception:  # malformed header: the raw text is still evidence
        return [unfold(str(v)) for k, v in msg.raw_items() if k.lower() == name.lower()]


def dkim_signatures(msg) -> list[dict]:
    """DKIM-Signature reduced to its signing domain (d=) and selector (s=): never the signature itself."""
    out = []
    for value in header_values(msg, "DKIM-Signature"):
        entry = {}
        for tag in ("d", "s"):
            m = re.search(rf"(?:^|;)\s*{tag}\s*=\s*([^;\s]+)", value)
            if m:
                entry[tag] = m.group(1)
        out.append(entry)
    return out


def cut(value: str, size: int) -> str:
    return value if len(value) <= size else value[:size - 1].rstrip() + "…"


def raw_headers(msg) -> dict:
    """{header: value or [values]}, whole values: the evidence the score reads. Absent headers are left out."""
    out = {}
    for name in HEADERS:
        if name in RAW_HEADERS:
            values = [unfold(str(v)) for k, v in msg.raw_items() if k.lower() == name.lower()]
        else:
            values = header_values(msg, name)
        if values:
            out[name] = values[0] if len(values) == 1 and name != "Received" else values  # Received: always a list
    return out


def auth_headers(msg, full: dict | None = None) -> tuple[dict, list[str]]:
    """({header: value or [values]}, what was shortened). A header that is absent is left out."""
    out, shortened = {}, []
    for name, value in (full if full is not None else raw_headers(msg)).items():
        values = [value] if isinstance(value, str) else list(value)
        if name == "Received" and len(values) > RECEIVED_MAX:
            shortened.append(f"Received {RECEIVED_MAX}/{len(values)}")
            values = values[:RECEIVED_MAX]
        size = LONG_HEADERS.get(name, VALUE_MAX)
        if any(len(v) > size for v in values):
            shortened.append(f"{name} (text)")
        values = [cut(v, size) for v in values]
        out[name] = values[0] if isinstance(value, str) else values
    signatures = dkim_signatures(msg)
    if signatures:
        out["DKIM-Signature"] = signatures
    return out, shortened


# --- Links ---

class _Links(HTMLParser):
    """`<a href>` of an HTML document with the text shown inside (an image's alt text counts)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._open: list | None = None
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._close()
            href = dict(attrs).get("href")
            self._open = [href, []] if href is not None else None
        elif tag == "img" and self._open is not None:
            self._open[1].append(dict(attrs).get("alt") or "")

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
        elif tag == "a":
            self._close()

    def handle_data(self, data):
        if self._open is not None and not self._skip:
            self._open[1].append(data)

    def _close(self):
        if self._open is not None:
            self.links.append((self._open[0], unfold("".join(self._open[1]))))
            self._open = None

    def close(self):
        super().close()
        self._close()


# A URL or domain written in the text of a link: with a scheme or www., or bare (domain.tld/path). Not an
# address (user@domain), not a file name.
_SHOWN = re.compile(r"(?<![\w@./-])(?:(?:https?://|www\.)[^\s<>\"']+|(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}(?::\d+)?(?:/[^\s<>\"']*)?)",
                    re.I)
_FILE_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "gif", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv",
                    "html", "htm", "php", "exe", "js", "css"}


def clean_url(href: str) -> str:
    """The URL a browser would use: no surrounding spaces, no tabs or line breaks inside."""
    return re.sub(r"[\t\r\n\x00-\x1f]", "", href).strip()


def domain_of(url: str) -> tuple[str | None, bool]:
    """(host in lowercase ASCII, written with non-ASCII or punycode labels) of an http(s) URL; (None, False) else."""
    try:
        parts = urlsplit(url if "://" in url or not url.startswith("//") else "https:" + url)
        if parts.scheme.lower() not in ("http", "https"):
            return None, False
        host = (parts.hostname or "").rstrip(".").lower()
    except ValueError:
        return None, False
    if not host:
        return None, False
    idn = not host.isascii() or any(label.startswith("xn--") for label in host.split("."))
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    return host, idn


def shown_domains(text: str) -> list[str]:
    """Domains of the URLs or domain names a link's text displays (the text a reader trusts)."""
    found = []
    for m in _SHOWN.finditer(text):
        token = m.group(0).rstrip(".,;:!?)»”'\"")
        host, _ = domain_of(token if "://" in token else "https://" + token)
        if host and "." in host and host.rsplit(".", 1)[1] not in _FILE_EXTENSIONS:
            found.append(host)
    return found


def same_site(a: str, b: str) -> bool:
    """Same domain, or one a subdomain of the other (www.example.org and click.example.org)."""
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def extract_links(markup: str) -> list[dict]:
    """The `<a href>` of an HTML body, without duplicates: {url, domain?, text?, count?, mismatch?, shown?, idn?}.

    `domain` is the real destination host (http and https only; other schemes, such as mailto: or javascript:,
    have no domain and say `scheme`). `mismatch` is true when the text displays a URL or domain that is not the
    destination's (`shown` names the first one). In-page anchors and empty targets are left out."""
    parser = _Links()
    try:
        parser.feed(markup)
        parser.close()
    except Exception:  # broken markup: keep what was read
        parser._close()
    seen: dict[tuple[str, str], dict] = {}
    for href, text in parser.links:
        url = clean_url(href)
        if not url or url.startswith("#"):
            continue
        key = (url, text)
        if key in seen:
            seen[key]["count"] = seen[key].get("count", 1) + 1
            continue
        host, idn = domain_of(url)
        entry = {"url": cut(url, LINK_URL_MAX)}
        if host:
            entry["domain"] = host
        else:
            scheme = re.match(r"([a-z][a-z0-9+.-]*):", url, re.I)
            if not scheme:
                continue  # a relative link: no destination to check
            entry["scheme"] = scheme.group(1).lower()
        if text:
            entry["text"] = cut(text, LINK_TEXT_MAX)
        if host:
            other = [d for d in shown_domains(text) if not same_site(d, host)]
            if other:
                entry["mismatch"] = True
                entry["shown"] = other[0]
        if idn:
            entry["idn"] = True
        seen[key] = entry
    return list(seen.values())


# --- Suspicion score ---
#
# phishing_score() adds up weighted signals, capped at 100. A signal is evidence, not proof: weights are chosen so
# that no single weak signal reaches "medium", and a message needs several independent ones (or one strong one with
# company) to reach "high". Newsletters and notifications sent through a mailing platform trigger the weak signals
# legitimately, so those are attenuated twice: when the destination is a known sending / tracking domain, and when the
# From domain signed the message.
#
#   code                   weight                                   what it means
#   auth_fail              dmarc 35, spf 25, dkim 20, softfail 10   topmost Authentication-Results / Received-SPF
#                          (sum, max 45)                            say the sender is not who it claims
#   spam_flag              30 (flag / status "Yes", score>=required) the host's own antispam verdict
#                          25 (score >= 5), 10 (score >= 2)
#   origin_mismatch        35 first external hop from a public IP    whatever the From looks like (not for SMTP-AUTH
#                          with helo localhost / bare IP / absent    submissions)
#                          + Return-Path / Reply-To off the From     only when the From claims a company: 25 on a free
#                          domain: 15, 5 with an aligned DKIM, 25    webmail, 15 without aligned DKIM, 5 with it
#                          for a free webmail (max 60 in all)
#   link_domain_mismatch   15 (5 if every other link is a known      no link on the From domain
#                          platform)
#   lookalike_domain       35 brand word in another domain, 30 IDN   a link imitates the sender's brand; generic
#                          only                                     words, the From domain, known sending / tracking
#                                                                   domains and, with an aligned DKIM, domains that
#                                                                   hold the whole brand name (product sites) excepted
#   display_mismatch       35 unknown destination; 10 when it is a   the text shows another URL
#                          known platform or the DKIM is aligned
#   crypto_transaction_lure 20                                        wallet / pending transaction / ETH / seed
#                                                                   phrase wording (subject, text, button) next to a
#                                                                   link off the From domain (never a known platform)
#   template_placeholder   20                                        {prenom}, {{name}}, %FIRSTNAME% unfilled
#   urgency_payment        6 per group (urgency, payment), max 12    pressure and money words, FR/EN
#
# "Aligned DKIM": a dkim=pass in the topmost Authentication-Results (and no dmarc fail) whose d= is the From's
# organisational domain. When it is aligned AND the first hop is not improvised (origin_mismatch above), link_domain_mismatch,
# display_mismatch and lookalike_domain are capped at 5 each, except a link to an IDN / punycode host, which keeps its
# weight. An improvised first hop is never excused by a signature.
#
# Levels: score < 30 "low", 30..59 "medium", >= 60 "high".
LEVEL_MEDIUM, LEVEL_HIGH = 30, 60
BODY_SCAN_MAX = 30000        # characters of the body read for placeholders and keywords

# Platforms that send and track mail for others, and large sites a newsletter links to. Never shorteners (bit.ly...):
# phishers use those too.
PLATFORMS = (
    "sendibt1.com", "sendibt2.com", "sendibt3.com", "sendibm1.com", "sendibm2.com", "sendibm3.com", "sendinblue.com",
    "brevo.com", "list-manage.com", "mailchimp.com", "mcsv.net", "mandrillapp.com", "sendgrid.net", "sendgrid.com",
    "amazonses.com", "awstrack.me", "mailjet.com", "mjt.lu", "hubspotemail.net", "hs-sites.com", "hubspot.com",
    "constantcontact.com", "rs6.net", "campaign-archive.com", "klaviyo.com", "klaviyomail.com", "sparkpostmail.com",
    "customeriomail.com", "mailgun.org", "mailgun.net", "mlsend.com", "mailerlite.com", "getresponse.com",
    "createsend.com", "emltrk.com", "cm-sender.net", "mailkit.eu", "sarbacane.com", "mailpv.net", "ymlp.com",
    "intercom-mail.com", "intercom-clicks.com", "intercom.io", "cloudflareaccess.com", "notify.cloudflare.com",
    "qualtrics.com", "qemailserver.com", "go.link", "spmta.com", "spmailtechno.com", "c.gle",
    "facebook.com", "instagram.com", "linkedin.com", "twitter.com", "x.com", "youtube.com", "apple.com", "google.com",
)
PLATFORM_PATTERN = re.compile(r"(?:^|\.)(?:cmail\d+\.com|sendib[tm]\d+\.com)$")
FREEMAIL = ("gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.fr", "live.com", "live.fr", "yahoo.com",
            "yahoo.fr", "icloud.com", "me.com", "orange.fr", "wanadoo.fr", "free.fr", "sfr.fr", "laposte.net", "proton.me",
            "protonmail.com", "gmx.com", "gmx.fr", "gmx.net", "gmx.de", "aol.com", "msn.com", "outlook.fr", "ymail.com",
            "yahoo.co.uk", "hotmail.co.uk")
# Local parts of an address a company sends from (not a person): the From claims to be an organisation.
ROLE_PREFIXES = ("noreply", "donotreply", "notif", "notification", "newsletter", "service", "support", "contact", "info", "news",
                 "alert", "mailer", "billing", "account", "security", "order", "commande", "delivery", "shipping",
                 "customer", "client", "colis", "livraison", "facture", "invoice", "hello", "team", "admin")
# Words too common in company names to prove an imitation.
GENERIC_WORDS = ("france", "online", "service", "services", "mail", "email", "group", "groupe", "shop", "store", "paris",
                 "europe", "direct", "media", "news", "web", "club", "info", "bank", "banque", "assurance", "poste",
                 "colis", "livraison", "client", "secure", "login", "account", "compte", "tracking", "suivi", "connect",
                 "mails", "notify", "notification", "support", "cloud")
# Generic only as a whole word of a domain name (go.link, my-brand, app-brand): inside a word they would eat the brand.
GENERIC_TOKENS = ("go", "my", "app", "apps", "link", "links", "click", "clicks", "track")
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}

PLACEHOLDER_WORDS = ("prenom", "prénom", "nom", "name", "firstname", "first_name", "lastname", "last_name", "fullname",
                     "full_name", "civilite", "civilité", "client", "customer", "email", "montant", "amount", "date",
                     "order", "commande", "link", "lien", "url", "company", "societe", "société")
PLACEHOLDERS = re.compile(
    r"\{\{\s*[\w .|-]{1,30}\s*\}\}"                                    # {{name}} (any identifier)
    r"|\{\s*(?:" + "|".join(PLACEHOLDER_WORDS) + r")\s*\}"             # {prenom}, {nom}
    r"|%[A-Z][A-Z_]{3,24}%"                                            # %FIRSTNAME%
    r"|\[\[\s*[\w .-]{1,30}\s*\]\]|\*\|[A-Z_]{2,20}\|\*|<<\s*[\w .-]{1,30}\s*>>|\$\{\s*\w{1,30}\s*\}", re.I)
PLACEHOLDERS_CASE = re.compile(r"%[A-Z][A-Z_]{3,24}%|\*\|[A-Z_]{2,20}\|\*")  # these two only match upper case

URGENCY = ("urgent", "immédiatement", "immediatement", "dernier rappel", "dernier avis", "dernière chance", "sous 24",
           "sous 48", "action requise", "action immédiate", "sera suspendu", "sera bloqué", "sera fermé", "sera désactivé",
           "dernier délai", "avant le blocage", "immediately", "final notice", "last reminder", "last chance",
           "within 24 hours", "within 48 hours", "action required", "will be suspended", "will be closed", "will be locked",
           "account suspended", "act now", "verify your account", "confirm your identity", "vérifiez votre compte",
           "vérifier votre compte", "confirmez votre identité")
PAYMENT = ("paiement", "payer", "régler", "règlement", "frais de livraison", "frais de port", "frais de douane",
           "facture impayée", "impayé", "remboursement", "carte bancaire", "coordonnées bancaires", "numéro de carte",
           "iban", "virement", "carte cadeau", "mettre à jour votre moyen", "payment", "pay now", "invoice", "overdue",
           "refund", "credit card", "bank details", "wire transfer", "gift card", "billing information", "customs fee",
           "delivery fee", "update your payment")


def on_platform(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in PLATFORMS) or bool(PLATFORM_PATTERN.search(host))


def org_domain(host: str) -> str:
    """Registrable domain, without a suffix list: last two labels, three for co.uk / com.au style suffixes."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _label(host: str) -> str:
    """The name part of a domain: everything left of the suffix (ml-colis-relay.com -> ml-colis-relay)."""
    suffix = org_domain(host).partition(".")[2]
    return host[:-len(suffix) - 1] if suffix and host.endswith("." + suffix) else host


def freemail(domain: str) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in FREEMAIL)


_GENERIC_BY_LENGTH = sorted(GENERIC_WORDS, key=len, reverse=True)


def _core(text: str) -> str:
    """A domain name reduced to letters and digits, with generic words turned into breaks."""
    parts = []
    for token in re.split(r"[^a-z0-9]+", text.lower()):
        if token in GENERIC_TOKENS:
            parts.append("|")
            continue
        for word in _GENERIC_BY_LENGTH:
            token = token.replace(word, "|")
        parts.append(token)
    return "".join(parts)


def _common(a: str, b: str) -> int:
    """Length of the longest common substring, with no break (|) inside."""
    best, row = 0, [0] * (len(b) + 1)
    for ca in a:
        new = [0] * (len(b) + 1)
        for j, cb in enumerate(b, 1):
            if ca == cb and ca != "|":
                new[j] = row[j - 1] + 1
                best = max(best, new[j])
        row = new
    return best


def imitates(brand: str, host: str) -> bool:
    """Does `host` borrow the brand name (at least 5 letters of it in a row, or the whole of a short brand)?"""
    brand_core, host_core = _core(brand), _core(_label(host))
    if len(brand_core.replace("|", "")) < 3:
        return False
    if len(brand_core) < 5:
        return brand_core in re.split(r"[^a-z0-9]+", _label(host).lower())
    return _common(brand_core, host_core) >= 5


def _first(headers: dict, name: str) -> str:
    value = headers.get(name)
    return (value[0] if isinstance(value, list) and value else value) or ""


def _address(value: str) -> tuple[str, str, str]:
    """(display name, local part, domain) of the first address in a header value; '' for what is missing."""
    for name, addr in getaddresses([value]):
        if "@" in addr:
            local, _, domain = addr.rpartition("@")
            return name, local.lower(), domain.strip(">").lower()
    return "", "", ""


def _claims_brand(name: str, local: str, domain: str) -> bool:
    if not domain or freemail(domain):
        return False
    plain = re.sub(r"[^a-z]", "", local)
    if plain.startswith(ROLE_PREFIXES):
        return True
    label = re.sub(r"[^a-z0-9]", "", org_domain(domain).split(".")[0])
    return len(label) >= 4 and label in re.sub(r"[^a-z0-9]", "", name.lower())


def _authentication(headers: dict) -> dict[str, list[str]]:
    """{method: [results]} from the topmost Authentication-Results (the one your own server wrote; others are written
    by the sender), else the topmost ARC one; plus the verdict word of Received-SPF."""
    line = _first(headers, "Authentication-Results") or _first(headers, "ARC-Authentication-Results")
    found: dict[str, list[str]] = {}
    for method, result in re.findall(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", line, re.I):
        found.setdefault(method.lower(), []).append(result.lower())
    spf = re.match(r"\s*(pass|fail|softfail|neutral|none|permerror|temperror)\b", _first(headers, "Received-SPF"), re.I)
    if spf and "spf" not in found:
        found["spf"] = [spf.group(1).lower()]
    return found


def _auth_fail(headers: dict):
    found = _authentication(headers)
    parts, weight = [], 0
    if "fail" in found.get("dmarc", []):
        parts, weight = parts + ["dmarc=fail"], weight + 35
    if "fail" in found.get("spf", []):
        parts, weight = parts + ["spf=fail"], weight + 25
    elif "softfail" in found.get("spf", []):
        parts, weight = parts + ["spf=softfail"], weight + 10
    if "fail" in found.get("dkim", []) and "pass" not in found["dkim"]:
        parts, weight = parts + ["dkim=fail"], weight + 20
    if parts:
        return {"code": "auth_fail", "detail": "Sender authentication failed: " + ", ".join(parts), "weight": min(weight, 45)}


def _spam_flag(headers: dict):
    flag, status = _first(headers, "X-Spam-Flag"), _first(headers, "X-Spam-Status")
    score = required = None
    if m := re.search(r"score\s*=\s*(-?\d+(?:\.\d+)?)", status):
        score = float(m.group(1))
    elif m := re.match(r"\s*(-?\d+(?:\.\d+)?)", _first(headers, "X-Spam-Score")):
        score = float(m.group(1))
    if m := re.search(r"required\s*=\s*(\d+(?:\.\d+)?)", status):
        required = float(m.group(1))
    if score is None and (m := re.search(r"\((-?\d+(?:\.\d+)?) points", _first(headers, "X-Spam-Report"))):
        score = float(m.group(1))
    if score is None and (bar := _first(headers, "X-Spam-Bar")):
        score = float(bar.count("+") - bar.count("-")) if set(bar) <= {"+", "-"} else None
    verdict = flag.strip().lower().startswith("yes") or status.strip().lower().startswith("yes")
    shown = f" (score {score:g})" if score is not None else ""
    if verdict or (score is not None and required is not None and score >= required):
        return {"code": "spam_flag", "detail": f"The mail host's antispam marked it as spam{shown}", "weight": 30}
    if score is not None and score >= 5:
        return {"code": "spam_flag", "detail": f"High antispam score {score:g}", "weight": 25}
    if score is not None and score >= 2:
        return {"code": "spam_flag", "detail": f"Raised antispam score {score:g}", "weight": 10}


def _private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (addr.is_loopback or addr.is_link_local or addr.is_unspecified or addr in ipaddress.ip_network("10.0.0.0/8")
            or addr in ipaddress.ip_network("172.16.0.0/12") or addr in ipaddress.ip_network("192.168.0.0/16")
            or addr in ipaddress.ip_network("100.64.0.0/10") or addr.version == 6 and addr.is_private)


def _first_hop(received: list[str]) -> str | None:
    """Why the oldest Received line (the first server the message went through) looks improvised, or None."""
    if not received:
        return None
    hop = received[-1]
    m = re.match(r"\s*from\s+(\S+)", hop, re.I)
    if not m:
        return None  # no "from": webmail or internal hand-over, nothing to judge
    explicit = re.search(r"helo=([^\s)]+)", hop, re.I)
    helo = (explicit.group(1) if explicit else m.group(1)).strip("[]();,").lower()
    client = re.split(r"\sby\s", hop, maxsplit=1, flags=re.I)[0]
    ips = re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", client) + re.findall(r"\[([0-9a-f:]*:[0-9a-f:]+)\]", client, re.I)
    if not ips or all(_private(ip) for ip in ips):
        return None  # no public client address: the server itself, a private network, an internal hand-over
    if re.search(r"\bwith\s+(?:E|L)?SMTPS?A\b|authenticated", hop, re.I):
        return None  # SMTP AUTH submission: a logged-in mail client, not an improvised sender
    if helo in ("localhost", "localhost.localdomain", "unknown", "") or re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", helo) \
            or ":" in helo:
        shown = f" from {ips[0]}" if ips else ""
        return f"first hop helo is {helo or 'absent'!r}{shown}"
    return None


def _aligned(headers: dict, from_domain: str) -> bool:
    """A dkim=pass (and no dmarc failure) in the topmost Authentication-Results, signed by the From's own domain."""
    auth = _authentication(headers)
    return bool(from_domain) and "pass" in auth.get("dkim", []) and "pass" in auth.get("dmarc", ["pass"]) \
        and _signed_by(headers, from_domain)


def _origin(headers: dict, from_domain: str, brand: bool, hop: str | None, aligned: bool):
    problems, weight = [], 0
    if hop:  # whatever the From looks like
        problems.append(hop)
        weight += 35
    if brand:
        worst = None
        for name in ("Return-Path", "Reply-To"):
            _, _, domain = _address(_first(headers, name))
            if not domain or same_site(org_domain(domain), org_domain(from_domain)) or on_platform(domain):
                continue
            w = 25 if freemail(domain) else 5 if aligned else 15
            if worst is None or w > worst[0]:
                worst = (w, name, domain)
        if worst:
            problems.append(f"{worst[1]} domain {worst[2]} differs from From domain {from_domain}")
            weight += worst[0]
    if problems:
        return {"code": "origin_mismatch", "detail": "; ".join(problems), "weight": min(weight, 60)}


def _signed_by(headers: dict, from_domain: str) -> bool:
    """A DKIM signature whose domain is the From domain's: only worth something next to a dkim=pass."""
    return any(sig.get("d") and same_site(org_domain(sig["d"].lower()), org_domain(from_domain))
               for sig in headers.get("DKIM-Signature") or [] if isinstance(sig, dict))


def _link_domains(links: list[dict]) -> list[str]:
    return list(dict.fromkeys(link["domain"] for link in links if link.get("domain")))


def _link_signals(links: list[dict], from_domain: str, brand_label: str, aligned: bool, attenuate: bool):
    """`aligned`: the From domain signed the mail; `attenuate`: aligned and the first hop is not improvised."""
    def capped(weight: int, idn: bool = False) -> int:
        return weight if idn or not attenuate else min(weight, 5)

    out = []
    hosts = _link_domains(links)
    if from_domain and hosts and not any(same_site(h, org_domain(from_domain)) for h in hosts) \
            and not freemail(from_domain):
        others = [h for h in hosts if not on_platform(h)]
        out.append({"code": "link_domain_mismatch", "weight": capped(15 if others else 5),
                    "detail": f"No link on {org_domain(from_domain)}; links go to " + ", ".join(hosts[:3])
                              + (" (known mailing platforms)" if not others else "")})
    lookalikes = []
    if brand_label and from_domain:
        whole = brand_label.replace("-", "")
        lookalikes = [h for h in hosts if not on_platform(h) and not same_site(h, org_domain(from_domain))
                      and imitates(brand_label, h)
                      and not (aligned and len(whole) >= 4 and whole in re.sub(r"[^a-z0-9]", "", _label(h)))]
    idn = [link["domain"] for link in links if link.get("idn") and link.get("domain")]
    if lookalikes or idn:
        out.append({"code": "lookalike_domain", "weight": capped(35, bool(idn)) if lookalikes else 30,
                    "detail": (f"Domain {lookalikes[0]} imitates the sender's name {brand_label!r}" if lookalikes
                               else f"Domain {idn[0]} uses look-alike (IDN/punycode) characters")})
    shown = []
    for link in links:
        if link.get("mismatch"):
            platform = on_platform(link.get("domain", ""))
            weight = 10 if platform or aligned else 35
            shown.append((capped(weight, bool(link.get("idn"))), platform, link))
    if shown:
        weight, platform, link = max(shown, key=lambda t: t[0])
        out.append({"code": "display_mismatch", "weight": weight,
                    "detail": f"Link text shows {link.get('shown')} but goes to {link.get('domain')}"
                              + (" (known mailing platform)" if platform else " (the sender signed the mail)" if aligned else "")})
    return out


# Wording of a crypto-wallet scam ("pending transaction, review and accept"). One strong phrase is enough; the weak words
# (wallet, ETH...) are everywhere in legitimate mail (Apple Wallet, a bank's "portefeuille"), so two different ones are needed.
CRYPTO_STRONG = re.compile(
    r"seed phrase|recovery phrase|secret phrase|phrase de r[ée]cup[ée]ration|phrase secr[èe]te|private key|cl[ée] priv[ée]e"
    r"|pending (?:crypto )?transactions?|transactions? (?:is |are )?pending|transactions? en attente|airdrop"
    r"|connect (?:your )?wallet|(?:review|accept|approve|confirm|validate|claim|examiner|valider|accepter|confirmer)\W+"
    r"(?:(?:the|your|this|a|la|votre|cette)\W+)?(?:crypto\W+)?(?:transactions?|transfers?)", re.I)
CRYPTO_WEAK = re.compile(r"\bwallets?\b|\bportefeuilles?\b|\b(?:eth|btc|usdt|usdc|xrp)\b|\bbitcoins?\b|\bethereum\b"
                         r"|\bcrypto(?:currenc(?:y|ies)|monnaies?)?\b", re.I)


def _crypto_lure(text: str, links: list[dict], from_domain: str):
    strong = CRYPTO_STRONG.search(text)
    weak = {m.group(0).lower() for m in CRYPTO_WEAK.finditer(text)}
    if not strong and len(weak) < 2:
        return None
    outside = [h for h in _link_domains(links)
               if not on_platform(h) and not (from_domain and same_site(h, org_domain(from_domain)))]
    if not outside:
        return None
    words = (strong.group(0).lower(),) if strong else tuple(sorted(weak))[:2]
    return {"code": "crypto_transaction_lure", "weight": 20,
            "detail": f"Crypto wording ({', '.join(repr(w) for w in words)}) with a link outside the sender's domain: {outside[0]}"}


def _text_signals(text: str) -> list[dict]:
    text = text[:BODY_SCAN_MAX]
    out = []
    found = [m.group(0) for m in PLACEHOLDERS.finditer(text)
             if m.group(0).startswith(("{", "[", "<", "$")) or PLACEHOLDERS_CASE.fullmatch(m.group(0))]
    if found:
        out.append({"code": "template_placeholder", "weight": 20,
                    "detail": "Unfilled template field in the text: " + ", ".join(dict.fromkeys(found[:3]))})
    lower = text.lower()
    hits = [(group, [w for w in words if w in lower]) for group, words in (("urgency", URGENCY), ("payment", PAYMENT))]
    hits = [(group, words) for group, words in hits if words]
    if hits:
        out.append({"code": "urgency_payment", "weight": 6 * len(hits),
                    "detail": "; ".join(f"{group}: {', '.join(repr(w) for w in words[:2])}" for group, words in hits)})
    return out


def phishing_score(headers: dict, links: list[dict], body_text: str, subject: str = "") -> dict:
    """Suspicion of phishing, from what the other functions of this module extract; no network access.

    `headers` is the dict of `raw_headers`/`auth_headers`, `links` the list of `extract_links`, `body_text` the
    text of the mail, `subject` its subject (read for wording only). Returns {score: 0-100, level: low|medium|high,
    reasons: [{code, detail, weight}]}, the reasons by decreasing weight. A score is a hint to look closer, never a
    verdict."""
    name, local, from_domain = _address(_first(headers, "From"))
    brand = _claims_brand(name, local, from_domain)
    brand_label = re.sub(r"[^a-z0-9-]", "", org_domain(from_domain).split(".")[0]) if brand else ""
    hop = _first_hop(headers.get("Received") or [])
    aligned = _aligned(headers, from_domain)
    reasons = [r for r in (_auth_fail(headers), _spam_flag(headers), _origin(headers, from_domain, brand, hop, aligned)) if r]
    reasons += _link_signals(links, from_domain, brand_label, aligned, aligned and not hop)
    reasons += _text_signals(body_text or "")
    shown = " ".join([subject or "", (body_text or "")[:BODY_SCAN_MAX]] + [link.get("text", "") for link in links])
    if lure := _crypto_lure(shown, links, from_domain):
        reasons.append(lure)
    reasons = sorted(({"code": r["code"], "detail": r["detail"], "weight": r["weight"]} for r in reasons),
                     key=lambda r: -r["weight"])
    score = min(sum(r["weight"] for r in reasons), 100)
    level = "high" if score >= LEVEL_HIGH else "medium" if score >= LEVEL_MEDIUM else "low"
    return {"score": score, "level": level, "reasons": reasons}
