"""Evidence for a phishing check, read from a message already fetched: authentication headers and the real
destination of the links of its HTML body. Pure functions on text: nothing here opens a connection, and a link
is never followed."""

import re
from html.parser import HTMLParser
from urllib.parse import urlsplit

VALUE_MAX = 400          # characters of one header value
RECEIVED_MAX = 20        # Received lines kept (the first ones: the last hops, written by your own server)
LINK_URL_MAX = 300       # characters of a link URL (the domain is always complete)
LINK_TEXT_MAX = 80       # characters of the text shown for a link

# Headers kept as text, in this order; each one may appear several times.
HEADERS = ("From", "Reply-To", "Return-Path", "Sender", "Received", "Authentication-Results",
           "ARC-Authentication-Results", "Received-SPF", "Message-ID", "List-Unsubscribe")


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


def auth_headers(msg) -> tuple[dict, list[str]]:
    """({header: value or [values]}, what was shortened). A header that is absent is left out."""
    out, shortened = {}, []
    for name in HEADERS:
        values = header_values(msg, name)
        if not values:
            continue
        if name == "Received" and len(values) > RECEIVED_MAX:
            shortened.append(f"Received {RECEIVED_MAX}/{len(values)}")
            values = values[:RECEIVED_MAX]
        long = [v for v in values if len(v) > VALUE_MAX]
        if long:
            shortened.append(f"{name} (text)")
        values = [cut(v, VALUE_MAX) for v in values]
        out[name] = values[0] if len(values) == 1 and name != "Received" else values  # Received: always a list
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
