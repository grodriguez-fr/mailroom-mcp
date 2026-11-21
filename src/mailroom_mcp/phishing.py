"""Evidence for a phishing check, read from a message already fetched: authentication headers, the real
destination of the links of its HTML body, and a suspicion score built from both. Pure functions on text:
nothing here opens a connection, and a link is never followed."""

import ipaddress
import re
import unicodedata
from email.header import decode_header, make_header
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


# Registrable "domains" that anyone can get a subdomain of: two hosts under them are not the same site.
SHARED_HOSTING = {"github.io", "gitlab.io", "blogspot.com", "herokuapp.com", "azurewebsites.net", "vercel.app", "netlify.app",
                  "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "wixsite.com", "weebly.com", "000webhostapp.com",
                  "cloudfront.net", "amazonaws.com", "s3.amazonaws.com", "onrender.com", "fly.dev", "glitch.me", "repl.co"}


def same_organisation(a: str, b: str) -> bool:
    """Same site, or two subdomains of one registrable domain (www.example.org and app.example.org), unless that
    domain is a shared host where anyone gets a subdomain."""
    if same_site(a, b):
        return True
    org = org_domain(a)
    return org == org_domain(b) and org not in SHARED_HOSTING


def extract_links(markup: str) -> list[dict]:
    """The `<a href>` of an HTML body, without duplicates: {url, domain?, text?, count?, mismatch?, shown?, idn?}.

    `domain` is the real destination host (http and https only; other schemes, such as mailto: or javascript:,
    have no domain and say `scheme`). `mismatch` is true when the text displays a URL or domain that is not the
    destination's nor on the same registrable domain (`shown` names the first one). In-page anchors and empty
    targets are left out."""
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
            other = [d for d in shown_domains(text) if not same_organisation(d, host)]
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
#   origin_mismatch        first external hop = the oldest Received   whatever the From looks like (not for SMTP-AUTH
#                          line with a public client IP:              submissions). Hops on a private / loopback IP
#                          35 helo "localhost"; 15 bare IP or no      (10/8, 172.16/12, 192.168/16, 127/8, fc00::/7,
#                          helo, 5 with an aligned DKIM               ::1) or with a container hostname as helo (12 hex)
#                          25 local hand-over (helo localhost /       are internal: never judged. The exception is a
#                          127.0.0.1) on a third-party server, not    "localhost" hand-over on a server that is not the
#                          the receiving one, when the From claims    recipient's, with no aligned DKIM, from a From that
#                          a company or a brand                       claims a company or a brand
#                          + Return-Path / Reply-To off the From      only when the From claims a company: 25 on a free
#                          domain: 15, 5 with an aligned DKIM, 25     webmail, 15 without aligned DKIM, 5 with it
#                          for a free webmail (max 60 in all)
#   link_domain_mismatch   15 (5 if every other link is a known      no link on the From domain (a link shortener or
#                          platform)                                  redirector is never a platform)
#   lookalike_domain       35 brand word in another domain, 30 IDN   a link imitates the sender's brand; generic
#                          only                                     words, the From domain, known sending / tracking
#                                                                   domains and, with an aligned DKIM, domains that
#                                                                   hold the whole brand name (product sites) excepted
#   display_mismatch       35 unknown destination; 10 when it is a   the text shows another URL
#                          known platform or the DKIM is aligned
#   display_name_brand_mismatch  30 a known brand in the display     the address domain does not hold the brand and no
#                          name ("Amazon", "PayPal", a bank...)      DKIM signature of the From domain passed
#                          15 a generic service title ("Service      the title is not backed by the address (a
#                          Client", "Support", "Sécurité"),          "support@" for a "Support") nor by the company
#                          30 next to any other signal but           name in the display name
#                          link_domain_mismatch / urgency_payment
#   crypto_transaction_lure 20                                        wallet / pending transaction / ETH / seed
#                                                                   phrase wording (subject, text, button) next to a
#                                                                   link off the From domain (never a known platform)
#   template_placeholder   20                                        {prenom}, {{name}}, %FIRSTNAME% unfilled
#   urgency_payment        6 per group (urgency, payment), max 12    pressure and money words, FR/EN
#
# "Aligned DKIM": a dkim=pass in the topmost Authentication-Results (and no dmarc fail) whose d= is the From's
# organisational domain. When it is aligned AND the first hop is not "localhost" from a public IP, link_domain_mismatch,
# display_mismatch and lookalike_domain are capped at 5 each, except a link to an IDN / punycode host, which keeps its
# weight. A "localhost" first hop from a public address is never excused by a signature.
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
# Link shorteners and redirectors: they hide the destination, so they are off-domain links and never trusted.
REDIRECTORS = ("share.google", "bit.ly", "t.co", "tinyurl.com", "lnkd.in", "goo.gl", "ow.ly", "is.gd", "buff.ly",
               "rebrand.ly", "cutt.ly", "shorturl.at", "t.ly", "rb.gy", "tiny.cc", "s.id", "urlz.fr")

# Known brands imitated in display names: {name as written (lower case, no accent): what a domain of that brand
# holds}. A key of 4 letters or less must start a label of the domain, a longer one may sit anywhere in it.
BRANDS = {
    "amazon": ("amazon", "amzn"), "paypal": ("paypal",), "apple": ("apple", "icloud"),
    "microsoft": ("microsoft", "outlook", "office", "live", "msn"), "google": ("google", "gmail", "youtube"),
    "netflix": ("netflix",), "facebook": ("facebook", "meta"), "instagram": ("instagram",), "linkedin": ("linkedin",),
    "whatsapp": ("whatsapp",), "docusign": ("docusign",),
    "mondial relay": ("mondialrelay",), "mondialrelay": ("mondialrelay",), "colissimo": ("colissimo", "laposte"),
    "chronopost": ("chronopost",), "dhl": ("dhl",), "ups": ("ups",), "fedex": ("fedex",),
    "la poste": ("laposte", "colissimo"), "laposte": ("laposte", "colissimo"),
    "ameli": ("ameli", "assurancemaladie", "cpam"), "assurance maladie": ("ameli", "assurancemaladie", "cpam"),
    "impots": ("impots", "dgfip", "gouv"), "caf": ("caf",), "edf": ("edf",), "engie": ("engie",),
    "orange": ("orange",), "sfr": ("sfr",), "free": ("free", "iliad"), "bouygues": ("bouygues",),
    "credit agricole": ("creditagricole",), "bnp paribas": ("bnpparibas",), "bnp": ("bnpparibas", "bnp"),
    "societe generale": ("societegenerale", "socgen"), "la banque postale": ("labanquepostale",),
    "caisse d epargne": ("caisse-epargne", "caisseepargne"), "credit mutuel": ("creditmutuel",), "cic": ("cic",),
    "lcl": ("lcl",), "boursorama": ("boursorama",), "hsbc": ("hsbc",), "banque populaire": ("banquepopulaire",),
    "fortuneo": ("fortuneo",), "revolut": ("revolut",), "n26": ("n26",), "qonto": ("qonto",), "lydia": ("lydia",),
    "blockchain": ("blockchain",), "coinbase": ("coinbase",), "binance": ("binance",), "kraken": ("kraken",),
    "ledger": ("ledger",), "metamask": ("metamask",),
}
BRAND_AMBIGUOUS = {"free", "orange", "ups", "caf"}   # ordinary words: only count when they start the display name
BRAND_NAME = re.compile(r"(?<![a-z0-9])(" + "|".join(sorted((re.escape(b) for b in BRANDS), key=len, reverse=True))
                        + r")(?![a-z0-9])")
# Generic service titles: {title: local parts that back it}.
GENERIC_TITLES = {
    "service client": ("service", "client", "customer"), "service clients": ("service", "client", "customer"),
    "service clientele": ("service", "client"), "customer service": ("service", "customer", "client"),
    "customer support": ("support", "customer", "help"), "customer care": ("care", "customer", "service", "support"),
    "support client": ("support", "client", "customer"), "support technique": ("support", "technique"),
    "support": ("support", "help", "aide"), "assistance": ("assistance", "support", "help", "aide"),
    "securite": ("security", "securite", "secu"), "security": ("security", "securite", "secu"),
    "security team": ("security", "securite", "secu"), "equipe securite": ("security", "securite", "secu"),
}
GENERIC_NAME = re.compile(r"(?<![a-z0-9])(" + "|".join(sorted((re.escape(t) for t in GENERIC_TITLES), key=len, reverse=True))
                          + r")(?![a-z0-9])")
LOCALHOSTS = ("localhost", "localhost.localdomain")
CONTAINER_HELO = re.compile(r"(?:[0-9a-f]{12}|[0-9a-f]{64})")   # a container's default hostname (docker short / long id)
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


def redirector(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in REDIRECTORS)


def on_platform(host: str) -> bool:
    if redirector(host):
        return False  # a shortener is never a trusted sending / tracking domain
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
            try:
                name = str(make_header(decode_header(name)))  # an encoded word (=?utf-8?q?...?=) is read as text
            except Exception:  # malformed encoded word: the raw text is still evidence
                pass
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


PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "::1/128", "fc00::/7", "fe80::/10"))


def _private(ip: str) -> bool:
    """A private, loopback or link-local address: a hop on it is the sender's own network, not the Internet."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_unspecified or any(addr in net for net in PRIVATE_NETWORKS if net.version == addr.version)


_LOOPBACK = re.compile(r"(?<![\d.])127(?:\.\d{1,3}){3}(?![\d.])|\[(?:ipv6:)?::1\]|ipv6:::1", re.I)
_IPV4 = r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"


def _hops(received: list[str]) -> list[dict]:
    """The Received lines with a "from" clause, oldest first: {helo, ips (of the client), by (host), loopback, text}.
    A line without "from" (webmail, internal hand-over) has nothing to judge."""
    out = []
    for hop in reversed(received):
        m = re.match(r"\s*from\s+(\S+)", hop, re.I)
        if not m:
            continue
        explicit = re.search(r"helo=([^\s)]+)", hop, re.I)
        helo = (explicit.group(1) if explicit else m.group(1)).strip("[]();,").lower()
        client = re.split(r"\sby\s", hop, maxsplit=1, flags=re.I)[0]
        ips = re.findall(_IPV4, client) + re.findall(r"\[(?:ipv6:)?([0-9a-f:]*:[0-9a-f:]+)\]", client, re.I)
        by = re.search(r"\sby\s+([^\s(;\[]+)", hop, re.I)
        out.append({"helo": helo, "ips": ips, "by": by.group(1).strip("[]();,").lower() if by else "", "text": hop,
                    "loopback": helo in LOCALHOSTS or bool(_LOOPBACK.search(hop.split(";")[0]))})
    return out


def _bare_ip(helo: str) -> bool:
    return bool(re.fullmatch(_IPV4, helo)) or ":" in helo


def _same_host(a: str, b: str) -> bool:
    return bool(a and b) and (a == b or org_domain(a) == org_domain(b))


def _origin_hop(received: list[str], aligned: bool, claims: bool) -> dict | None:
    """Why the way in of the message looks improvised, or None: {kind, weight, detail}.

    The first external hop is the oldest one whose client has a public IP; a hop on a private / loopback IP, or with a
    container hostname as helo, is the sender's internal plumbing and is never judged. `localhost` or a bare IP (or no
    helo) from a public address is improvised; a bare IP is attenuated by an aligned DKIM, `localhost` is not. Apart
    from that, a `localhost` hand-over on a server that is not the receiving one, from a From that claims a company or
    a brand without a DKIM of its own domain, is the local machine of a third party writing under that name."""
    hops = _hops(received)
    external = next((h for h in hops if any(not _private(ip) for ip in h["ips"])), None)
    if external:
        text, helo = external["text"], external["helo"]
        ip = next(ip for ip in external["ips"] if not _private(ip))
        if re.search(r"\bwith\s+(?:E|L)?SMTPS?A\b|authenticated", text, re.I) or CONTAINER_HELO.fullmatch(helo):
            return None  # SMTP AUTH submission: a logged-in mail client; a container: not an improvised sender
        if helo in LOCALHOSTS:
            return {"kind": "localhost", "weight": 35, "detail": f"first hop helo is {helo!r} from {ip}"}
        if helo in ("unknown", "") or _bare_ip(helo):
            what = "has no helo" if helo in ("unknown", "") else f"helo is {helo!r}, a bare IP,"
            return {"kind": "bare_ip", "weight": 5 if aligned else 15, "detail": f"first hop {what} from {ip}"}
    origin = hops[0] if hops else None
    if origin and origin["loopback"] and claims and not aligned and len(received) > 1 \
            and not _same_host(origin["by"], _by(received[0])):
        return {"kind": "local_send", "weight": 25,
                "detail": f"first hop is a local hand-over ({origin['helo']!r}) on {origin['by'] or 'another server'}, "
                          "not the receiving server, and the From domain did not sign the mail"}
    return None


def _by(line: str) -> str:
    m = re.search(r"\sby\s+([^\s(;\[]+)", " " + line, re.I)
    return m.group(1).strip("[]();,").lower() if m else ""


def _aligned(headers: dict, from_domain: str) -> bool:
    """A dkim=pass (and no dmarc failure) in the topmost Authentication-Results, signed by the From's own domain."""
    auth = _authentication(headers)
    return bool(from_domain) and "pass" in auth.get("dkim", []) and "pass" in auth.get("dmarc", ["pass"]) \
        and _signed_by(headers, from_domain)


def _origin(headers: dict, from_domain: str, brand: bool, hop: dict | None, aligned: bool):
    problems, weight = [], 0
    if hop:  # whatever the From looks like
        problems.append(hop["detail"])
        weight += hop["weight"]
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


def _plain(text: str) -> str:
    """Lower case, no accent, every run of other characters turned into one space."""
    text = unicodedata.normalize("NFKD", text.lower())
    return re.sub(r"[^a-z0-9]+", " ", "".join(c for c in text if not unicodedata.combining(c))).strip()


def _holds(domain: str, keys: tuple[str, ...]) -> bool:
    """Does the domain carry one of the brand's names? Short names must start a label (dhl, dhlparcel), long ones may
    sit anywhere (credit-agricole)."""
    labels = [t for t in re.split(r"[^a-z0-9]+", domain.lower()) if t]
    compact = "".join(labels)
    return any(key in compact if len(key) > 4 else any(t.startswith(key) for t in labels) for key in keys)


def _display_name(name: str, local: str, domain: str, aligned: bool) -> tuple[str, str] | None:
    """('brand' | 'generic', the words) when the display name claims a known brand or a generic service title that the
    address domain does not back and no DKIM signature of the From domain vouches for; None otherwise."""
    if not name or not domain or aligned:
        return None
    plain = _plain(name)
    for m in BRAND_NAME.finditer(plain):
        word = m.group(1)
        if word in BRAND_AMBIGUOUS and m.start() != 0:
            continue
        if not _holds(domain, BRANDS[word]):
            return "brand", word
    title = GENERIC_NAME.search(plain)
    if title:
        label = re.sub(r"[^a-z0-9]", "", org_domain(domain).split(".")[0])
        backed = plain.replace(" ", "")
        if (len(label) >= 4 and label in backed) or re.sub(r"[^a-z]", "", local).startswith(GENERIC_TITLES[title.group(1)]):
            return None  # "Acme Support" from acme.example, "Support" from support@: the title is the address's own
        return "generic", title.group(1)
    return None


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
    aligned = _aligned(headers, from_domain)
    named = _display_name(name, local, from_domain, aligned)
    hop = _origin_hop(headers.get("Received") or [], aligned, brand or named is not None)
    reasons = [r for r in (_auth_fail(headers), _spam_flag(headers), _origin(headers, from_domain, brand, hop, aligned)) if r]
    reasons += _link_signals(links, from_domain, brand_label, aligned, aligned and not (hop and hop["kind"] == "localhost"))
    reasons += _text_signals(body_text or "")
    shown = " ".join([subject or "", (body_text or "")[:BODY_SCAN_MAX]] + [link.get("text", "") for link in links])
    if lure := _crypto_lure(shown, links, from_domain):
        reasons.append(lure)
    if named:
        kind, words = named
        weak = {"link_domain_mismatch", "urgency_payment"}
        weight = 30 if kind == "brand" or any(r["code"] not in weak for r in reasons) else 15
        reasons.append({"code": "display_name_brand_mismatch", "weight": weight,
                        "detail": (f"Display name claims {words!r} but {from_domain} is not that brand's domain"
                                   if kind == "brand" else f"Generic service title {words!r} that the address does not back")
                                  + " and no DKIM of the From domain passed"})
    reasons = sorted(({"code": r["code"], "detail": r["detail"], "weight": r["weight"]} for r in reasons),
                     key=lambda r: -r["weight"])
    score = min(sum(r["weight"] for r in reasons), 100)
    level = "high" if score >= LEVEL_HIGH else "medium" if score >= LEVEL_MEDIUM else "low"
    return {"score": score, "level": level, "reasons": reasons}
