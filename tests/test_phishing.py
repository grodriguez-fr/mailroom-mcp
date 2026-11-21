"""read_message(security=true): authentication headers and real link targets, from a spoofed parcel notice.
Everything is fake (reserved .example domains); no link is ever followed."""

import json
import socket

import pytest
from test_server import FakeIMAP, install, mail_env, mk  # noqa: F401  (autouse fixture)

from mailroom_mcp import phishing, server

DKIM = ("v=1; a=rsa-sha256; c=relaxed/relaxed; d=phish-sender.example; s=sel2026; t=1761000000; "
        "h=from:to:subject:date; bh=Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFy=; "
        "b=QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB")

SPOOF_HEADERS = [
    ("Return-Path", "<bounce@mailer.phish-sender.example>"),
    ("Received", "from mx.example.org (mx.example.org [192.0.2.10]) by imap.example.org with ESMTPS; Wed, 21 Oct 2026 08:00:02 +0200"),
    ("Received", "from out.phish-sender.example (out.phish-sender.example [198.51.100.7]) by mx.example.org; Wed, 21 Oct 2026 08:00:01 +0200"),
    ("Received", "from [203.0.113.5] (unknown [203.0.113.5]) by out.phish-sender.example; Wed, 21 Oct 2026 08:00:00 +0200"),
    ("Authentication-Results", "mx.example.org; spf=fail smtp.mailfrom=mailer.phish-sender.example; "
                               "dkim=pass header.d=phish-sender.example; dmarc=fail (p=reject) header.from=mondialrelay.fr"),
    ("ARC-Authentication-Results", "i=1; mx.example.org; dmarc=fail header.from=mondialrelay.fr"),
    ("Received-SPF", "fail (mx.example.org: domain of mailer.phish-sender.example does not designate 198.51.100.7 as permitted sender)"),
    ("DKIM-Signature", DKIM),
    ("Reply-To", "Service client <support@mondial-relay-colis.example>"),
    ("Sender", "bounce@mailer.phish-sender.example"),
    ("List-Unsubscribe", "<https://track.phish-sender.example/u?id=1>"),
]

HTML = """<html><head><style>a { color: red }</style></head><body>
<p>Votre colis est en attente. <a href="https://www.mondialrelay.fr/suivi">https://www.mondialrelay.fr/suivi</a></p>
<a href="https://track.phish-sender.example/r?u=abc&amp;x=1" style="button">Suivre mon colis</a>
<a href="https://mondialrelay.fr.verify-colis.example/login">www.mondialrelay.fr</a>
<a href="https://track.phish-sender.example/r?u=abc&amp;x=1">Suivre   mon
colis</a>
<a href="https://track.phish-sender.example/r?u=abc&amp;x=1">Suivre mon colis</a>
<a href="https://aide.mondialrelay.fr/faq">Voir mondialrelay.fr</a>
<a href="https://xn--mondilrelay-n6a.example/x">Mondial Relay</a>
<a href="mailto:contact@mondialrelay.fr">contact@mondialrelay.fr</a>
<a href="javascript:void(0)">Fermer</a>
<a href="#top">Haut</a><a href="">vide</a><a>sans cible</a>
<script>var a = '<a href="https://script.example/">x</a>';</script>
</body></html>"""

TEXT = "Votre colis est en attente. Suivez-le: https://www.mondialrelay.fr/suivi"


def spoof(uid=70, html=HTML, headers=SPOOF_HEADERS):
    return mk(uid, "Votre colis est en attente", sender="Mondial Relay <noreply@mondialrelay.fr>", body=TEXT, html=html,
              message_id="<abc123@mailer.phish-sender.example>", headers=headers)


@pytest.fixture
def box(monkeypatch):
    fk = install(monkeypatch, FakeIMAP({"INBOX": {"flags": "\\HasNoChildren", "messages": [spoof()]}}))
    return fk


def by_url(links):
    return {(link["url"], link.get("text")): link for link in links}


def test_security_is_off_by_default_and_changes_nothing_else(box):
    plain = server.read_message("INBOX", 70)
    assert "security" not in plain
    assert not [c for c in box.log if "BODY.PEEK[2]" in str(c)]  # the HTML part is not even downloaded
    on = server.read_message("INBOX", 70, security=True)
    assert {k: v for k, v in on.items() if k != "security"} == plain


def test_headers_carry_the_authentication_evidence(box):
    headers = server.read_message("INBOX", 70, security=True)["security"]["headers"]
    assert headers["From"] == "Mondial Relay <noreply@mondialrelay.fr>"
    assert headers["Reply-To"] == "Service client <support@mondial-relay-colis.example>"
    assert headers["Return-Path"] == "<bounce@mailer.phish-sender.example>"
    assert headers["Sender"] == "bounce@mailer.phish-sender.example"
    assert "dmarc=fail" in headers["Authentication-Results"] and "spf=fail" in headers["Authentication-Results"]
    assert headers["ARC-Authentication-Results"].startswith("i=1;")
    assert headers["Received-SPF"].startswith("fail")
    assert headers["Message-ID"] == "<abc123@mailer.phish-sender.example>"
    assert headers["List-Unsubscribe"] == "<https://track.phish-sender.example/u?id=1>"


def test_received_keeps_every_line_in_message_order(box):
    received = server.read_message("INBOX", 70, security=True)["security"]["headers"]["Received"]
    assert [r.split()[1] for r in received] == ["mx.example.org", "out.phish-sender.example", "[203.0.113.5]"]


def test_dkim_signature_is_reduced_to_domain_and_selector(box):
    result = server.read_message("INBOX", 70, security=True)
    assert result["security"]["headers"]["DKIM-Signature"] == [{"d": "phish-sender.example", "s": "sel2026"}]
    text = json.dumps(result)
    assert "AAAA" not in text and "bh=" not in text and "QUFB" not in text  # no signature material


def test_absent_headers_are_left_out(monkeypatch):
    install(monkeypatch, FakeIMAP({"INBOX": {"flags": "", "messages": [mk(1, "Hello", html="<p>x</p>")]}}))
    headers = server.read_message("INBOX", 1, security=True)["security"]["headers"]
    assert set(headers) == {"From"}


def test_links_give_real_url_domain_and_text_without_duplicates(box):
    links = server.read_message("INBOX", 70, security=True)["security"]["links"]
    urls = by_url(links)
    button = urls[("https://track.phish-sender.example/r?u=abc&x=1", "Suivre mon colis")]
    assert button["domain"] == "track.phish-sender.example" and button["count"] == 3  # entity decoded, spaces folded, deduplicated
    assert "mismatch" not in button  # the text does not show a URL
    assert len(links) == len({(link["url"], link.get("text")) for link in links})
    assert not any("script.example" in link["url"] for link in links)  # not read from scripts
    assert not any(link["url"] in ("#top", "") for link in links) and not any(link.get("text") == "sans cible" for link in links)


def test_text_showing_another_domain_is_flagged_and_listed_first(box):
    links = server.read_message("INBOX", 70, security=True)["security"]["links"]
    urls = by_url(links)
    fake_link = urls[("https://mondialrelay.fr.verify-colis.example/login", "www.mondialrelay.fr")]
    assert fake_link["domain"] == "mondialrelay.fr.verify-colis.example"
    assert fake_link["mismatch"] is True and fake_link["shown"] == "www.mondialrelay.fr"
    flagged = [link for link in links if link.get("mismatch")]
    assert links[:len(flagged)] == flagged  # flagged links come first
    # a legitimate link shown as its own URL, or as the same site's subdomain, is not flagged
    assert "mismatch" not in urls[("https://www.mondialrelay.fr/suivi", "https://www.mondialrelay.fr/suivi")]
    assert "mismatch" not in urls[("https://aide.mondialrelay.fr/faq", "Voir mondialrelay.fr")]


def test_punycode_domains_are_marked_and_other_schemes_have_no_domain(box):
    urls = by_url(server.read_message("INBOX", 70, security=True)["security"]["links"])
    assert urls[("https://xn--mondilrelay-n6a.example/x", "Mondial Relay")]["idn"] is True
    mail = urls[("mailto:contact@mondialrelay.fr", "contact@mondialrelay.fr")]
    assert mail["scheme"] == "mailto" and "domain" not in mail and "mismatch" not in mail
    assert urls[("javascript:void(0)", "Fermer")]["scheme"] == "javascript"


def test_security_never_opens_a_network_connection(box, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    assert server.read_message("INBOX", 70, security=True)["security"]["links"]


def test_html_only_mail_reads_links_from_the_body_without_a_second_fetch(monkeypatch):
    structure = '("text" "html" ("charset" "utf-8") NIL NIL "7bit" 40 1 NIL NIL NIL)'
    m = mk(5, "Only HTML", body="x", structure=structure)
    m["raw"] = (b"From: A <a@example.org>\nTo: me@example.org\nSubject: Only HTML\nContent-Type: text/html; charset=utf-8\n\n"
                b'<p><a href="https://one.example/a">https://two.example</a></p>')
    fk = install(monkeypatch, FakeIMAP({"INBOX": {"flags": "", "messages": [m]}}))
    result = server.read_message("INBOX", 5, security=True)
    assert result["security"]["links"] == [{"url": "https://one.example/a", "domain": "one.example",
                                            "text": "https://two.example", "mismatch": True, "shown": "two.example"}]
    assert "https://two.example" in result["body"]
    assert len([c for c in fk.log if c[0] == "FETCH"]) == 2  # headers+structure, then the one text part


def test_plain_text_mail_has_no_links_and_says_why(monkeypatch):
    install(monkeypatch, FakeIMAP({"INBOX": {"flags": "", "messages": [mk(1, "Hello", body="see https://x.example")]}}))
    result = server.read_message("INBOX", 1, security=True)
    assert result["security"]["links"] == []
    assert any("No HTML part" in w for w in result["warnings"])


def test_unreadable_structure_falls_back_to_the_whole_message(monkeypatch):
    m = spoof()
    m["structure"] = "(("  # unbalanced: the structure cannot be parsed
    install(monkeypatch, FakeIMAP({"INBOX": {"flags": "", "messages": [m]}}))
    result = server.read_message("INBOX", 70, security=True)
    assert any(link.get("mismatch") for link in result["security"]["links"])
    assert result["security"]["headers"]["Authentication-Results"].startswith("mx.example.org")


def test_size_is_bounded_and_the_cut_is_signalled(monkeypatch):
    many = "".join(f'<a href="https://t{i}.example/{"p" * 120}">lien {i}</a>' for i in range(200))
    headers = [("Received", f"from h{i}.example by mx.example.org; " + "x" * 600) for i in range(30)]
    headers.append(("Authentication-Results", "mx.example.org; " + "dkim=pass " * 100))
    install(monkeypatch, FakeIMAP({"INBOX": {"flags": "", "messages": [mk(9, "Big", html=many, headers=headers)]}}))
    result = server.read_message("INBOX", 9, security=True)
    security = result["security"]
    cut = security["capped"]["cut"]
    assert security["capped"]["reason"] == "size" and security["capped"]["resumable"] is False
    assert "Received 20/30" in cut and "Authentication-Results (text)" in cut and "Received (text)" in cut
    assert len(security["headers"]["Received"]) == phishing.RECEIVED_MAX
    assert all(len(r) <= phishing.VALUE_MAX for r in security["headers"]["Received"]) and security["headers"]["Received"][0].endswith("…")
    assert 0 < len(security["links"]) < 200 and any(c.startswith("links ") and c.endswith("/200") for c in cut)
    assert server.json_size(security["links"]) <= server.RESPONSE_BUDGET + 400  # the budget, plus the one link always kept
    assert any("shortened" in w for w in result["warnings"])


def test_mismatch_detection_unit():
    def flagged(text, href="https://real.example/x"):
        return phishing.extract_links(f'<a href="{href}">{text}</a>')[0].get("mismatch", False)
    assert flagged("https://paypal.com/login") and flagged("paypal.com") and flagged("Go to www.paypal.com now")
    assert flagged("paypal.com.real.example.evil.org") and flagged("real-example.example", "https://real.example/x")
    assert not flagged("real.example") and not flagged("https://real.example/other") and not flagged("www.real.example")
    assert not flagged("Suivre mon colis") and not flagged("facture.pdf") and not flagged("write to me@paypal.com")
    assert not flagged("Version 1.2 (fr.)") and not flagged("")


def test_security_description_stays_within_the_budget_and_schema_is_strict():
    from test_contract import stdio_tools
    tool = stdio_tools()["read_message"]
    assert tool["inputSchema"]["properties"]["security"]["type"] == "boolean" and "security" not in tool["inputSchema"].get("required", [])
    assert tool["inputSchema"]["additionalProperties"] is False and len(tool["description"]) <= 600
