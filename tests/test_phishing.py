"""read_message(security=true): authentication headers and real link targets, from a spoofed parcel notice.
Everything is fake (reserved .example domains); no link is ever followed."""

import email
import json
import socket
from email import policy

import pytest
from test_contract import stdio_tools
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
    assert "Received (text)" in cut and "Authentication-Results (text)" in cut
    received = security["headers"]["Received"]
    assert any(c.startswith("Received ") and c.endswith("/30") for c in cut) and 0 < len(received) < 30
    assert all(len(r) <= phishing.VALUE_MAX for r in received) and received[0].endswith("…")
    assert any(c.startswith("links ") and c.endswith("/200") for c in cut)
    assert server.json_size(security) <= server.SECURITY_BUDGET
    assert any("shortened" in w for w in result["warnings"])


def many_hops_message(uid=9, hops=40, links=150):
    """A mail with a long Received chain and many links, in the order a real server writes them (newest first)."""
    html = "".join(f'<a href="https://t{i}.example/{"p" * 100}">lien {i}</a>' for i in range(links))
    html += '<a href="https://track.example/x">www.shop.example</a>'   # the one link whose text shows another domain
    received = [("Received", f"from relay{i}.hosting.example (relay{i}.hosting.example [10.0.{i}.1]) by relay{i + 1}.hosting.example "
                             f"with ESMTP id {i}; Fri, 21 Nov 2026 08:00:{i:02d} +0100 " + "x" * 200) for i in range(hops - 2)]
    received.append(("Received", "from out.sender.example (out.sender.example [198.51.100.7]) by relay0.hosting.example with ESMTPS; "
                                 "Fri, 21 Nov 2026 07:59:00 +0100"))
    received.append(("Received", "from [203.0.113.5] (unknown [203.0.113.5]) by out.sender.example; Fri, 21 Nov 2026 07:58:59 +0100"))
    others = [("Authentication-Results", "mx.example.org; spf=pass; dkim=pass header.d=shop.example; dmarc=pass header.from=shop.example"),
              ("ARC-Authentication-Results", "i=1; mx.example.org; spf=pass; dkim=pass header.d=shop.example"),
              ("Received-SPF", "pass (mx.example.org: domain of shop.example designates 198.51.100.7 as permitted sender)"),
              ("X-Spam-Status", "No, score=1.1 required=5.0 tests=HTML_MESSAGE"), ("X-Spam-Score", "1.1"), ("X-Spam-Flag", "NO"),
              ("DKIM-Signature", "v=1; a=rsa-sha256; d=shop.example; s=k1; h=from:to; bh=Zm9v; b=QUFB"),
              ("Return-Path", "<bounce@shop.example>"), ("Reply-To", "Shop <hello@shop.example>"),
              ("X-Spam-Report", "Content analysis details: " + "pts rule name description " * 30),
              ("List-Unsubscribe", "<https://shop.example/u/1>")]
    return mk(uid, "Big", sender="Shop <noreply@shop.example>", body="Hello", html=html, headers=received + others,
              message_id="<big@shop.example>")


def test_cut_keeps_the_priority_order(monkeypatch):
    install(monkeypatch, FakeIMAP({"INBOX": {"flags": "", "messages": [many_hops_message()]}}))
    security = server.read_message("INBOX", 9, security=True)["security"]
    headers, cut = security["headers"], security["capped"]["cut"]
    # (1) the phishing block and (2)-(3) the authentication and identity headers survive whole
    assert security["phishing"]["reasons"] is not None
    for name in ("Authentication-Results", "ARC-Authentication-Results", "Received-SPF", "X-Spam-Status", "X-Spam-Score",
                 "X-Spam-Flag", "From", "Reply-To", "Return-Path", "Message-ID"):
        assert name in headers, name
    assert headers["DKIM-Signature"] == [{"d": "shop.example", "s": "k1"}]
    assert headers["Authentication-Results"].startswith("mx.example.org; spf=pass")
    assert list(headers)[:3] == ["Authentication-Results", "ARC-Authentication-Results", "Received-SPF"]  # read first
    assert list(headers).index("Received") > list(headers).index("Message-ID")
    # (4) the flagged link comes before any other
    assert security["links"][0]["domain"] == "track.example" and security["links"][0]["mismatch"] is True
    # (5) Received: the receiving server's line and the first external hop are kept, the middle goes
    received = headers["Received"]
    assert received[0].startswith("from relay0.hosting.example") and received[-1].startswith("from [203.0.113.5]")
    assert not any(r.startswith("from relay19.hosting.example") for r in received) and 2 < len(received) < 40
    # (6)-(7): the other links, the spam report and the unsubscribe link went first
    assert "X-Spam-Report" in cut and "List-Unsubscribe" in cut and "X-Spam-Report" not in headers
    assert f"Received {len(received)}/40" in cut and any(c.startswith("links ") and c.endswith("/151") for c in cut)
    assert server.json_size(security) <= server.SECURITY_BUDGET


def test_cut_never_keeps_a_lower_priority_item_when_a_higher_one_was_dropped():
    score = {"score": 0, "level": "low", "reasons": []}
    headers = {"From": "a@b.example", "Received": [f"from h{i} by mx " + "x" * 300 for i in range(10)],
               "X-Spam-Report": "r", "List-Unsubscribe": "<u>"}
    links = [{"url": f"https://t{i}.example/", "domain": f"t{i}.example"} for i in range(5)]
    kept, kept_links, cut = phishing.trim_evidence(score, headers, links, 0, 1000)
    assert "Received" in kept and len(kept["Received"]) < 10 and kept_links == [] and "X-Spam-Report" not in kept
    assert cut[0].startswith("Received ") and "X-Spam-Report" in cut and "links 0/5" in cut
    everything, all_links, nothing = phishing.trim_evidence(score, headers, links, 0, 100000)
    assert nothing == [] and len(everything["Received"]) == 10 and all_links == links and list(everything)[0] == "From"


def test_received_priority_keeps_both_ends_and_cuts_the_middle():
    lines = [f"from relay{i} ([10.0.0.{i}]) by mx" for i in range(8)] + ["from [203.0.113.5] (unknown [203.0.113.5]) by relay7"]
    order = phishing.received_priority(lines)
    assert order[:2] == [0, 8] and sorted(order) == list(range(9))   # the receiving server's line, then the first external hop
    assert order[2:6] == [1, 7, 2, 6] and order[-1] == 4             # then inwards: the middle goes last
    assert phishing.received_priority([]) == [] and phishing.received_priority(["from a by b"]) == [0]


def test_mismatch_detection_unit():
    def flagged(text, href="https://real.example/x"):
        return phishing.extract_links(f'<a href="{href}">{text}</a>')[0].get("mismatch", False)
    assert flagged("https://paypal.com/login") and flagged("paypal.com") and flagged("Go to www.paypal.com now")
    assert flagged("paypal.com.real.example.evil.org") and flagged("real-example.example", "https://real.example/x")
    assert not flagged("real.example") and not flagged("https://real.example/other") and not flagged("www.real.example")
    assert not flagged("Suivre mon colis") and not flagged("facture.pdf") and not flagged("write to me@paypal.com")
    assert not flagged("Version 1.2 (fr.)") and not flagged("")


def test_security_description_stays_within_the_budget_and_schema_is_strict():
    tool = stdio_tools()["read_message"]
    assert tool["inputSchema"]["properties"]["security"]["type"] == "boolean" and "security" not in tool["inputSchema"].get("required", [])
    assert tool["inputSchema"]["additionalProperties"] is False and len(tool["description"]) <= 600


# --- phishing_score ---
def scored(headers, links, body_text, subject=""):
    """phishing_score for hand-built evidence: the account's receiving server is mx.example.org, and its results sit
    above every Received line (what raw_headers records for a real message)."""
    order = [name.lower() for name in ("Authentication-Results", "Received-SPF", "Received") for _ in phishing._all(headers, name)]
    return phishing.phishing_score({"_Order": order, **headers}, links, body_text, subject, ("mx.example.org",))


# Fictional hosts only (.example, documentation addresses), except the brand names being imitated.

PARCEL_HEADERS = [
    ("Return-Path", "<noreply@mondialrelay.fr>"),
    ("Received", "from host.hosting.example by host.hosting.example with LMTP id ABC123 (Exim 4.100.1); Fri, 21 Nov 2026 08:00:03 +0100"),
    ("Received", "from [203.0.113.64] (port=43738 helo=localhost) by host.hosting.example with esmtp (Exim 4.100.1) "
                 "(envelope-from <noreply@mondialrelay.fr>) id 1vMabc-000xyz-1Q; Fri, 21 Nov 2026 08:00:02 +0100"),
    ("X-Spam-Status", "No, score=1.2 required=5.0 tests=HTML_MESSAGE,MISSING_MID autolearn=no"),
    ("X-Spam-Report", "Content analysis details: (1.2 points, 5.0 required) " + "pts rule name description " * 30),
]
PARCEL_HTML = '<p>Bonjour {prenom} {nom},</p><p>Votre colis est disponible.</p><a href="https://ml-colis-relay.example/">Gérer ma livraison</a>'
PARCEL_TEXT = "Bonjour {prenom} {nom}, votre colis est disponible. Gérer ma livraison"

NEWSLETTER_HEADERS = [
    ("Return-Path", "<bounce-1234@bnc.sendibt3.com>"),
    ("Received", "from mail-out.sendibm3.com (mail-out.sendibm3.com [198.51.100.20]) by mx.example.org with ESMTPS; Fri, 21 Nov 2026 07:00:00 +0100"),
    ("Authentication-Results", "mx.example.org; spf=pass smtp.mailfrom=bnc.sendibt3.com; dkim=pass header.d=marque.fr; dmarc=pass header.from=marque.fr"),
    ("Received", "from [10.1.2.3] (unknown [10.1.2.3]) by mail-out.sendibm3.com with SMTP; Fri, 21 Nov 2026 06:59:58 +0100"),
    ("DKIM-Signature", "v=1; a=rsa-sha256; d=marque.fr; s=mail; h=from:to:subject; bh=Zm9v; b=QUFB"),
    ("Reply-To", "Marque <contact@marque.fr>"),
    ("List-Unsubscribe", "<https://r.sendibt3.com/u/abc>, <mailto:unsub@marque.fr>"),
]
NEWSLETTER_HTML = ('<p>Nos soldes: dernières heures pour en profiter.</p>'
                   '<a href="https://3a1b.r.sendibt3.com/tr/cl/aaa">www.marque.fr</a>'
                   '<a href="https://marque.us1.list-manage.com/track/click?u=1">Voir la collection</a>'
                   '<a href="https://r.sendibt3.com/u/abc">Se désinscrire</a>')


def score_of(monkeypatch, message, uid=1, folder="INBOX"):
    install(monkeypatch, FakeIMAP({folder: {"flags": "", "messages": [message]}}))
    return server.read_message(folder, uid, security=True)["security"]["phishing"]


def codes(result):
    return {r["code"]: r["weight"] for r in result["reasons"]}


def parcel(headers=PARCEL_HEADERS, html=PARCEL_HTML, body=PARCEL_TEXT, uid=1):
    return mk(uid, "Votre colis est arrivé", sender="Mondial Relay <noreply@mondialrelay.fr>", body=body, html=html,
              headers=headers)


def test_the_real_parcel_scam_scores_high(monkeypatch):
    result = score_of(monkeypatch, parcel())
    assert result["level"] == "high" and result["score"] == 100  # 105 before the cap
    assert codes(result) == {"lookalike_domain": 35, "origin_mismatch": 35, "template_placeholder": 20, "link_domain_mismatch": 15}
    assert [r["weight"] for r in result["reasons"]] == sorted((r["weight"] for r in result["reasons"]), reverse=True)
    details = " | ".join(r["detail"] for r in result["reasons"])
    assert "ml-colis-relay.example" in details and "helo is 'localhost'" in details and "203.0.113.64" in details
    assert "{prenom}" in details


def test_newsletter_through_a_mailing_platform_stays_low(monkeypatch):
    m = mk(2, "Soldes", sender="Marque <newsletter@marque.fr>", body="Soldes: dernières heures. www.marque.fr", html=NEWSLETTER_HTML,
           headers=NEWSLETTER_HEADERS)
    result = score_of(monkeypatch, m, 2)
    assert result["level"] == "low" and result["score"] == 10  # the From domain signed it: both weak signals capped at 5
    assert codes(result) == {"display_mismatch": 5, "link_domain_mismatch": 5}


def test_personal_mail_without_link_scores_zero(monkeypatch):
    m = mk(3, "Samedi", sender="Camille <camille@example.org>", body="Salut, on se voit samedi ? Tu peux me faire un virement pour le resto ?",
           headers=[("Received", "from [192.168.1.20] (unknown [203.0.113.80]) by mx.example.org with ESMTPSA; Fri, 21 Nov 2026 09:00:00 +0100")])
    result = score_of(monkeypatch, m, 3)
    assert result["level"] == "low" and result["score"] == 6 and codes(result) == {"urgency_payment": 6}


def test_plausible_medium_case(monkeypatch):
    html = '<p>Votre facture est disponible, règlement sous 48 heures.</p><a href="https://clic.offres-du-jour.example/x?id=9">Voir ma facture</a>'
    m = mk(4, "Votre facture", sender="Service client <service@bigshop.example>", body="Votre facture est disponible, règlement sous 48 heures.",
           html=html, headers=[("Reply-To", "service.bigshop@freepost.example"), ("X-Spam-Status", "No, score=2.4 required=5.0 tests=HTML_MESSAGE")])
    result = score_of(monkeypatch, m, 4)
    assert result["level"] == "medium" and 30 <= result["score"] < 60
    assert {"link_domain_mismatch", "origin_mismatch", "urgency_payment", "spam_flag"} <= set(codes(result))


# Fixtures for the tuning against real false positives: every host is fictional (.example), the brands are made up.
def aligned_auth(domain, server="mx.example.org"):
    return [("Authentication-Results", f"{server}; spf=pass; dkim=pass header.d={domain}; dmarc=pass header.from={domain}"),
            ("DKIM-Signature", f"v=1; a=rsa-sha256; d={domain}; s=k1; h=from:to:subject; bh=Zm9v; b=QUFB")]


OK_HOP = ("Received", "from out.sender-hub.example (out.sender-hub.example [198.51.100.30]) by mx.example.org with ESMTPS; "
                      "Fri, 21 Nov 2026 07:00:00 +0100")
LOCALHOST_HOP = ("Received", "from [203.0.113.77] (port=51234 helo=localhost) by host.hosting.example with esmtp (Exim 4.100.1) "
                             "id 1vMxyz-000abc-2Z; Fri, 21 Nov 2026 07:00:00 +0100")


def level_of(monkeypatch, sender, html, headers, subject="Hello", body="Hello", uid=1):
    return score_of(monkeypatch, mk(uid, subject, sender=sender, body=body, html=html, headers=headers), uid)


def test_fake_crypto_wallet_notice_scores_high(monkeypatch):
    html = ('<p>You have 13 (0.025 ETH) pending in your Wallet.</p>'
            '<a href="https://wallet-notif.example/accept?id=7">Review Transaction &amp; Accept</a>')
    result = level_of(monkeypatch, "Cryptovault <notif@cryptovault.example>", html, [LOCALHOST_HOP],
                      subject="Action Required: 13 (0.025 ETH) pending in your Wallet",
                      body="You have 13 (0.025 ETH) pending in your Wallet. Review Transaction & Accept")
    assert result["level"] == "high" and result["score"] >= 60
    assert {"origin_mismatch", "crypto_transaction_lure", "link_domain_mismatch"} <= set(codes(result))
    assert codes(result)["origin_mismatch"] == 35 and codes(result)["crypto_transaction_lure"] == 20


def test_improvised_first_hop_counts_whatever_the_from_looks_like():
    headers = {"From": "Camille <camille@example.org>", "Received": ["from mx by me", LOCALHOST_HOP[1]]}
    assert codes(scored(headers, [], "")) == {"origin_mismatch": 35}


def test_notification_sent_through_intercom_stays_low(monkeypatch):
    headers = [OK_HOP, ("Reply-To", "Studentcorp <hello@intercom-mail.com>"), *aligned_auth("studentcorp.example")]
    html = ('<p>Your landlord replied to your message.</p>'
            '<a href="https://u123.intercom-clicks.com/via/abc">studentcorp.example/messages</a>'
            '<a href="https://u123.intercom-clicks.com/via/def">Open the conversation</a>')
    result = level_of(monkeypatch, "Studentcorp <notifications@studentcorp.example>", html, headers)
    assert result["level"] == "low" and result["score"] < 30


def test_webinar_from_the_same_sender_stays_low(monkeypatch):
    headers = [OK_HOP, ("Reply-To", "Studentcorp <hello@intercom-mail.com>"), *aligned_auth("studentcorp.example")]
    html = ('<p>Join our webinar on Thursday. Register now, places are limited.</p>'
            '<a href="https://u123.intercom-clicks.com/via/xyz">https://studentcorp.example/webinar</a>')
    result = level_of(monkeypatch, "Studentcorp <hello@studentcorp.example>", html, headers, body="Join our webinar. Register now.")
    assert result["level"] == "low" and result["score"] < 30


def test_access_code_with_a_tenant_domain_stays_low(monkeypatch):
    html = '<p>Your one-time code: 123456</p><a href="https://acme.cloudflareaccess.com/cdn-cgi/access/login">Sign in</a>'
    result = level_of(monkeypatch, "Cloudflare <noreply@notify.cloudflare.com>", html, [OK_HOP])
    assert result["level"] == "low" and "lookalike_domain" not in codes(result)  # a known sending / access domain


def test_train_operator_with_a_product_domain_stays_low(monkeypatch):
    headers = [OK_HOP, *aligned_auth("connect.railco.example")]
    html = '<p>Your ticket is ready.</p><a href="https://railco-connect.example/tickets/8">See my ticket</a>'
    result = level_of(monkeypatch, "Railco <noreply@connect.railco.example>", html, headers)
    assert result["level"] == "low" and result["score"] < 30 and "lookalike_domain" not in codes(result)
    # the same link without any authentication is still a look-alike
    result = level_of(monkeypatch, "Railco <noreply@connect.railco.example>", html, [OK_HOP], uid=2)
    assert "lookalike_domain" in codes(result)


def test_bank_notice_with_a_tracking_link_stays_low(monkeypatch):
    headers = [OK_HOP, *aligned_auth("bankco.example")]
    html = ('<p>Your statement is available.</p>'
            '<a href="https://email.sparkpostmail.com/f/a/abc">https://www.bankco.example/statement</a>')
    result = level_of(monkeypatch, "Bankco <service@bankco.example>", html, headers, body="Your statement is available.")
    assert result["level"] == "low" and result["score"] < 30


def test_survey_through_a_survey_platform_stays_low(monkeypatch):
    html = '<p>Tell us what you think.</p><a href="https://lumenco.qualtrics.com/jfe/form/SV_abc">Take the survey</a>'
    result = level_of(monkeypatch, "Lumenco <noreply@lumenco.example>", html, [OK_HOP])
    assert result["level"] == "low" and "lookalike_domain" not in codes(result)


def test_official_product_domain_with_aligned_dkim_stays_low(monkeypatch):
    headers = [OK_HOP, *aligned_auth("phonebrand.example")]
    html = '<p>Meet our new model.</p><a href="https://phonebrandmimo.example/model">Discover</a>'
    result = level_of(monkeypatch, "Phonebrand <news@phonebrand.example>", html, headers)
    assert result["level"] == "low" and "lookalike_domain" not in codes(result)
    unsigned = level_of(monkeypatch, "Phonebrand <news@phonebrand.example>", html, [OK_HOP], uid=2)
    assert "lookalike_domain" in codes(unsigned)  # without the alignment the same domain is a look-alike


def test_platform_invitation_with_a_webmail_reply_to_is_at_least_medium(monkeypatch):
    headers = [OK_HOP, ("Reply-To", "Dana <dana.martin@gmail.com>")]
    html = '<p>Dana invited you to join a workspace.</p><a href="https://click.sparkpostmail.com/x">collabhub.example</a>'
    result = level_of(monkeypatch, "Collabhub <invitations@collabhub.example>", html, headers)
    assert result["level"] in ("medium", "high") and result["score"] >= 30
    assert codes(result)["origin_mismatch"] == 25 and codes(result)["display_mismatch"] == 10


def test_aligned_dkim_caps_the_weak_signals_but_not_a_bad_first_hop_or_idn():
    signed = {"Authentication-Results": "mx.example.org; dkim=pass header.d=shop.example; dmarc=pass", "DKIM-Signature": [{"d": "shop.example", "s": "k"}]}
    links = [{"url": "https://other.example/", "domain": "other.example", "mismatch": True, "shown": "shop.example"}]
    result = scored({"From": "Shop <noreply@shop.example>", **signed}, links, "")
    assert codes(result) == {"display_mismatch": 5, "link_domain_mismatch": 5}
    result = scored({"From": "Shop <noreply@shop.example>", "Received": [LOCALHOST_HOP[1]], **signed}, links, "")
    assert codes(result) == {"origin_mismatch": 35, "display_mismatch": 10, "link_domain_mismatch": 15}
    idn = [{"url": "https://xn--shp-fma.example/", "domain": "xn--shp-fma.example", "idn": True}]
    assert codes(scored({"From": "Shop <noreply@shop.example>", **signed}, idn, ""))["lookalike_domain"] == 30


def test_reply_to_weight_depends_on_alignment_and_webmail():
    signed = {"Authentication-Results": "mx.example.org; dkim=pass header.d=shop.example; dmarc=pass", "DKIM-Signature": [{"d": "shop.example", "s": "k"}]}
    base = {"From": "Shop <noreply@shop.example>"}
    assert codes(scored({**base, **signed, "Reply-To": "x@platform.example"}, [], "")) == {"origin_mismatch": 5}
    assert codes(scored({**base, "Reply-To": "x@platform.example"}, [], "")) == {"origin_mismatch": 15}
    assert codes(scored({**base, "Reply-To": "x@gmail.com"}, [], "")) == {"origin_mismatch": 25}
    assert codes(scored({**base, **signed, "Reply-To": "x@laposte.net"}, [], "")) == {"origin_mismatch": 25}


def test_lookalike_ignores_generic_words_and_known_sending_domains():
    def lookalike(host, frm):
        return "lookalike_domain" in codes(scored({"From": frm}, [{"url": f"https://{host}/", "domain": host}], ""))
    frm = "Lumenco <noreply@lumenco.example>"
    assert not lookalike("lumenco-connect.example", "Connect <noreply@connect.example>")  # the only word is generic
    assert not lookalike("acme.go.link", frm) and not lookalike("lumenco.qualtrics.com", frm) and not lookalike("lumenco.spmta.com", frm)
    assert not lookalike("t.intercom-clicks.com", frm) and not lookalike("acme.cloudflareaccess.com", "Cloudflare <noreply@cloudflare.com>")
    assert not lookalike("my-account-lumenco.example", "My Account <noreply@my-account.example>")
    assert lookalike("lumenco-login.example", frm) and lookalike("secure-lumenco.example", frm)  # the brand is left once the generic word goes


def test_crypto_lure_needs_the_vocabulary_and_a_link_off_the_sender_domain():
    off = [{"url": "https://wallet-notif.example/", "domain": "wallet-notif.example"}]
    own = [{"url": "https://www.coinco.example/", "domain": "www.coinco.example"}]
    frm = {"From": "Coinco <notif@coinco.example>"}
    def crypto(text, links=off, subject=""):
        return "crypto_transaction_lure" in codes(scored(frm, links, text, subject))
    assert crypto("Review Transaction & Accept: 0.025 ETH pending in your wallet")
    assert crypto("Votre transaction en attente sur votre portefeuille")
    assert crypto("Never share your seed phrase")
    assert crypto("hello", subject="Action Required: 0.5 BTC pending in your Wallet")
    assert not crypto("Review Transaction & Accept: 0.025 ETH pending in your wallet", own)
    assert not crypto("Add your card to Apple Wallet") and not crypto("Newsletter: methods and ethics")
    assert not crypto("Review Transaction & Accept: 0.025 ETH pending in your wallet", [])


def test_authentication_failures_and_spam_verdict():
    score = scored(
        {"From": "Bank <alerts@bank.example>", "Authentication-Results": "mx.example.org; spf=fail; dkim=fail; dmarc=fail",
         "X-Spam-Flag": "YES", "X-Spam-Score": "9.1"}, [], "")
    assert codes(score) == {"auth_fail": 45, "spam_flag": 30} and score["level"] == "high"
    # only the topmost Authentication-Results counts: a later one is written by the sender
    forged = scored({"From": "a@bank.example", "Authentication-Results": ["mx.example.org; spf=pass", "x; spf=fail dmarc=fail"]}, [], "")
    assert forged["score"] == 0
    soft = scored({"From": "a@bank.example", "Received-SPF": "softfail (domain does not designate)"}, [], "")
    assert codes(soft) == {"auth_fail": 10}
    assert scored({"X-Spam-Bar": "++++++"}, [], "")["reasons"][0]["weight"] == 25


def test_score_is_capped_at_100():
    links = [{"url": "https://bank-secure.example/", "domain": "bank-secure.example", "mismatch": True, "shown": "bank.example", "idn": True}]
    headers = {"From": "Bank <alerts@bank.example>", "Authentication-Results": "mx.example.org; spf=fail; dmarc=fail", "X-Spam-Flag": "YES",
               "Received": ["from [203.0.113.9] (helo=localhost) by mx"]}
    result = scored(headers, links, "Urgent: {{name}}, paiement sous 24 heures")
    assert result["score"] == 100 and sum(r["weight"] for r in result["reasons"]) > 100


def test_lookalike_and_alignment_rules():
    def lookalike(host, frm="Mondial Relay <noreply@mondialrelay.fr>"):
        link = {"url": f"https://{host}/", "domain": host}
        return "lookalike_domain" in codes(scored({"From": frm}, [link], ""))
    assert lookalike("ml-colis-relay.example") and lookalike("mondialetransporte.example")
    assert lookalike("mondialrelay.fr.verify-colis.example")
    assert not lookalike("www.mondialrelay.fr") and not lookalike("click.mondialrelay.fr") and not lookalike("sendibt3.com")
    assert not lookalike("france-travail.example", "France Connect <noreply@franceconnect.fr>")  # a generic word proves nothing
    assert not lookalike("ml-colis-relay.example", "Camille <camille@gmail.com>")  # not a company address
    idn = scored({"From": "a@example.org"}, [{"url": "https://xn--mondilrelay-n6a.example/", "domain": "xn--mondilrelay-n6a.example", "idn": True}], "")
    assert codes(idn)["lookalike_domain"] == 30
    aligned = scored({"From": "Shop <noreply@shop.example>", "Return-Path": "<bounce@mail.shop.example>"}, [], "")
    assert aligned["score"] == 0
    other = scored({"From": "Shop <noreply@shop.example>", "Return-Path": "<x@elsewhere.example>"}, [], "")
    assert codes(other) == {"origin_mismatch": 15}


def test_first_hop_judges_the_oldest_received_and_only_outside_clients():
    def hop(received, **extra):
        return codes(scored({"From": "Shop <noreply@shop.example>", "Received": received, **extra}, [], ""))
    assert "origin_mismatch" in hop(["from mx by me", "from [203.0.113.5] by mx with esmtp"])
    assert "origin_mismatch" in hop(["from 203.0.113.5 by mx"])
    assert "origin_mismatch" not in hop(["from localhost (localhost [127.0.0.1]) by mx"])  # internal hand-over
    assert "origin_mismatch" not in hop(["from out.shop.example (out.shop.example [203.0.113.5]) by mx"])
    assert "origin_mismatch" not in hop(["by 2002:a05:6a00 with SMTP id x; Fri"])  # no "from" clause
    signed = {"Authentication-Results": "mx.example.org; dkim=pass header.d=shop.example; dmarc=pass", "DKIM-Signature": [{"d": "shop.example", "s": "k"}]}
    assert codes(scored({"From": "Shop <noreply@shop.example>", "Received": ["from [203.0.113.5] (helo=localhost) by mx"], **signed},
                                         [], ""))["origin_mismatch"] == 35  # a signature does not excuse an improvised first hop
    assert "origin_mismatch" not in hop(["from [203.0.113.5] (helo=localhost) by mx with ESMTPSA"])  # SMTP AUTH: a mail client
    assert "origin_mismatch" not in hop(["from localhost by mx"])  # no public address at all


def test_placeholders_and_keywords_unit():
    def text_codes(text):
        return codes(scored({}, [], text))
    for text in ("Bonjour {prenom}", "Dear {{ first_name }}", "Hello %FIRSTNAME%", "Hi *|FNAME|*", "Cher [[nom]]"):
        assert text_codes(text) == {"template_placeholder": 20}, text
    for text in ("Bonjour Camille", "function() { return 1 }", "100%off", "a {b} c", "%20%2F"):
        assert "template_placeholder" not in text_codes(text), text
    assert text_codes("URGENT: régler la facture impayée") == {"urgency_payment": 12}
    assert text_codes("Final notice: update your payment") == {"urgency_payment": 12}
    assert text_codes("Bonne journée") == {}


def test_reply_to_and_message_id_come_back_whatever_their_form(monkeypatch):
    raw = ("From: Shop <noreply@shop.example>\nTo: me@example.org\nSubject: Hi\nreply-to: Société <ventes@shop.example>\n"
           "message-id: <part one@shop.example>\nContent-Type: text/plain; charset=utf-8\n\nBonjour").encode()
    m = mk(6, "Hi")
    m["raw"] = raw + b"\n"
    install(monkeypatch, FakeIMAP({"INBOX": {"flags": "", "messages": [m]}}))
    result = server.read_message("INBOX", 6, security=True)
    headers = result["security"]["headers"]
    assert headers["Reply-To"] == "Société <ventes@shop.example>" and result["reply_to"] == "Société <ventes@shop.example>"
    assert headers["Message-ID"] == "<part one@shop.example>"  # the parsed form would have stopped at "<part"
    assert "Message-ID" not in server.read_message("INBOX", 6)  # only the security view carries it
    json.dumps(result, ensure_ascii=False).encode("utf-8")


def test_spam_headers_are_returned_and_the_report_is_shortened(monkeypatch):
    install(monkeypatch, FakeIMAP({"INBOX": {"flags": "", "messages": [parcel()]}}))
    security = server.read_message("INBOX", 1, security=True)["security"]
    headers = security["headers"]
    assert headers["X-Spam-Status"].startswith("No, score=1.2") and len(headers["X-Spam-Report"]) == 300
    assert "X-Spam-Report (text)" in security["capped"]["cut"]
    assert list(security)[:3] == ["phishing", "auth", "headers"]


def test_score_reads_the_whole_evidence_even_when_output_is_cut(monkeypatch):
    headers = [("Received", "from relay.example.net (relay.example.net [198.51.100.9]) by mx.example.org with ESMTPS; Fri, 21 Nov 2026 08:00:00 +0100"),
               ("Authentication-Results", "mx.example.org; " + "dkim=pass header.d=a.example; " * 30 + "spf=fail dmarc=fail")]
    result = score_of(monkeypatch, mk(7, "Big", sender="a@bank.example", headers=headers, html="<p>x</p>"), 7)
    assert codes(result)["auth_fail"] == 45 and "spf=fail" in result["reasons"][0]["detail"]  # the failures sit past the 400-character cut


def test_score_is_pure_and_description_still_fits():
    assert len(stdio_tools()["read_message"]["description"]) <= 600
    original = socket.socket.connect
    try:
        socket.socket.connect = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network"))
        assert scored({"From": "a@example.org"}, [], "x")["level"] == "low"
    finally:
        socket.socket.connect = original


# --- Second tuning pass: origin of the first hop, internal relays, display names ---
# Fictional hosts only: .example domains and documentation addresses (192.0.2.x, 198.51.100.x, 203.0.113.x).

def hop(line):
    return ("Received", line + "; Fri, 21 Nov 2026 08:00:00 +0100")


HOSTING = {"server": "host.hosting.example"}   # the receiving server of the fixtures below: the by of their topmost Received


OWN_HOP = hop("from host.hosting.example by host.hosting.example with LMTP id ABC123")

SCENARIOS = {
    # a platform sending notifications through Mandrill: bare IP as helo, DKIM aligned on the From domain
    "platform_bare_ip_aligned": dict(
        sender="Collabhub <notifications@collabhub.example>", subject="Dana commented on your project", body="Dana commented.",
        html=('<p>Dana commented on your project.</p>'
              '<a href="https://mandrillapp.com/track/click/30001/app.collabhub.example?p=abc">app.collabhub.example/threads/9</a>'
              '<a href="https://mandrillapp.com/track/unsub/30001/abc">Unsubscribe</a>'),
        headers=[OWN_HOP, *aligned_auth("collabhub.example", **HOSTING), hop("from 198.51.100.45 (unknown [198.51.100.45]) by host.hosting.example with ESMTPS"),
                 ("Return-Path", "<bounce@mandrillapp.com>")]),
    # a bank's notification: internal hops on a private address, a container hostname as helo, DKIM aligned
    "bank_internal_hops_aligned": dict(
        sender="Bankco <noreply@bankco.example>", subject="Your transfer was executed", body="Your transfer of 120 euros was executed.",
        html=('<p>Your transfer of 120 euros was executed.</p><a href="https://mabanque.bankco.example/accounts">Open my accounts</a>'
              '<a href="https://mabanque.bankco.example/help">www.bankco.example</a>'),
        headers=[OWN_HOP, *aligned_auth("bankco.example", **HOSTING),
                 hop("from relay.bankco.example (relay.bankco.example [198.51.100.52]) by host.hosting.example with ESMTPS"),
                 hop("from 765765b0d442 ([10.225.0.128]) by relay.bankco.example (Postfix) with ESMTP id 4Xyz")]),
    # "Amazon" on an unrelated domain, sent from the third party's own machine, a link to an unknown domain
    "fake_amazon_local_send": dict(
        sender="Amazon <service@promo-abo.example>", subject="Merci pour votre abonnement",
        body="Merci pour votre abonnement. Votre paiement a été refusé: mettez à jour votre carte bancaire sous 24 heures.",
        html=('<p>Merci pour votre abonnement. Votre paiement a été refusé: mettez à jour votre carte bancaire sous 24 heures.</p>'
              '<a href="https://renouvellement-prime.example/abo?id=1">Gérer mon abonnement</a>'),
        headers=[OWN_HOP,
                 hop("from mx.promo-abo.example (mx.promo-abo.example [203.0.113.40]) by host.hosting.example with esmtps"),
                 hop("from localhost by mx.promo-abo.example ([127.0.0.1]) with ESMTP id 5")]),
    # a generic title, localhost / 127.0.0.1 on the third party's machine, one link through a redirector
    "trial_period_generic": dict(
        sender="Service Client <contact@trial-hub.example>", subject="Votre période d'essai arrive à son terme",
        body="Votre période d'essai arrive à son terme. Continuer",
        html='<p>Votre période d\'essai arrive à son terme.</p><a href="https://share.google/AbC123">Continuer</a>',
        headers=[OWN_HOP,
                 hop("from mail.trial-hub.example (mail.trial-hub.example [203.0.113.41]) by host.hosting.example with esmtp"),
                 hop("from localhost (localhost [127.0.0.1]) by mail.trial-hub.example (Postfix) with ESMTP id 7")]),
}


def unsigned_of(headers):
    """The same headers without the receiver's authentication results and the DKIM signature."""
    return [h for h in headers if h[0] not in ("Authentication-Results", "DKIM-Signature")]


def scenario(monkeypatch, name, **changes):
    spec = {**SCENARIOS[name], **changes}
    return level_of(monkeypatch, spec["sender"], spec["html"], spec["headers"], subject=spec["subject"], body=spec["body"])


def test_platform_with_a_bare_ip_helo_and_aligned_dkim_stays_low(monkeypatch):
    result = scenario(monkeypatch, "platform_bare_ip_aligned")
    assert result["level"] == "low" and result["score"] < 30
    assert codes(result)["origin_mismatch"] == 5 and "198.51.100.45" in result["reasons"][0]["detail"] + result["reasons"][-1]["detail"]
    unsigned = scenario(monkeypatch, "platform_bare_ip_aligned", headers=unsigned_of(SCENARIOS["platform_bare_ip_aligned"]["headers"]))
    assert codes(unsigned)["origin_mismatch"] == 15  # the same hop without a DKIM of the From domain


def test_bank_notice_through_internal_hops_stays_low(monkeypatch):
    result = scenario(monkeypatch, "bank_internal_hops_aligned")
    assert result["level"] == "low" and "origin_mismatch" not in codes(result)
    assert "display_mismatch" not in codes(result)  # www.bankco.example and mabanque.bankco.example are one site
    unsigned = scenario(monkeypatch, "bank_internal_hops_aligned", headers=unsigned_of(SCENARIOS["bank_internal_hops_aligned"]["headers"]))
    assert unsigned["level"] in ("low", "medium") and "origin_mismatch" not in codes(unsigned)


def test_internal_loopback_relay_of_a_signed_company_is_not_a_local_send(monkeypatch):
    headers = [OWN_HOP, *aligned_auth("bankco.example", **HOSTING),
               hop("from relay.bankco.example (relay.bankco.example [198.51.100.52]) by host.hosting.example with ESMTPS"),
               hop("from localhost (localhost [127.0.0.1]) by relay.bankco.example (Postfix) with ESMTP id 4Xyz")]
    result = level_of(monkeypatch, "Bankco <noreply@bankco.example>", "<p>Statement</p>", headers)
    assert result["level"] == "low" and "origin_mismatch" not in codes(result)
    unsigned = level_of(monkeypatch, "Bankco <noreply@bankco.example>", "<p>Statement</p>", unsigned_of(headers), uid=2)
    assert codes(unsigned) == {"origin_mismatch": 25}  # the same hand-over without the company's signature


def test_fake_amazon_sent_from_a_third_partys_machine_scores_high(monkeypatch):
    result = scenario(monkeypatch, "fake_amazon_local_send")
    assert result["level"] == "high" and result["score"] >= 60
    assert codes(result) == {"display_name_brand_mismatch": 30, "origin_mismatch": 25, "link_domain_mismatch": 15, "urgency_payment": 12}
    assert "'amazon'" in " ".join(r["detail"] for r in result["reasons"])


def test_trial_period_notice_from_a_generic_title_is_at_least_medium(monkeypatch):
    result = scenario(monkeypatch, "trial_period_generic")
    assert result["level"] in ("medium", "high") and result["score"] >= 30
    assert codes(result) == {"display_name_brand_mismatch": 30, "origin_mismatch": 25, "link_domain_mismatch": 15}  # high: 70
    assert result["level"] == "high"


def test_first_external_hop_skips_internal_hops_and_container_helos():
    def origin(*lines, **extra):
        return codes(scored({"From": "Shop <noreply@shop.example>", "Received": list(lines), **extra}, [], ""))
    own = "from mx.shop.example (mx.shop.example [198.51.100.9]) by host.example"
    for private in ("10.1.2.3", "172.16.5.4", "172.31.255.1", "192.168.0.7", "fd12:3456::1"):
        assert origin(own, f"from relay ([{private}]) by mx.shop.example") == {}, private
    # a loopback address is internal too (a hand-over on the receiving server is not judged at all)
    assert origin("from localhost ([127.0.0.1]) by host.example") == {} and origin("from x ([::1]) by host.example") == {}
    assert origin(own, "from relay ([::1]) by host.example") == {}
    # a container hostname is internal, with a private or a public address
    assert origin(own, "from 765765b0d442 ([10.225.0.128]) by mx.shop.example") == {}
    assert origin("from 765765b0d442 (unknown [203.0.113.5]) by host.example") == {}
    # the first external hop is the oldest one with a public address, whatever the internal ones before it say
    assert origin("from [203.0.113.5] by host.example", "from 765765b0d442 ([10.225.0.128]) by relay") == {"origin_mismatch": 15}
    assert origin("from localhost (helo=localhost) [203.0.113.5] by host.example",
                  "from 765765b0d442 ([10.225.0.128]) by relay") == {"origin_mismatch": 35}
    # 172.32.x.x is not private
    assert origin("from [172.32.0.1] by host.example") == {"origin_mismatch": 15}


def test_bare_ip_and_absent_helo_weigh_15_and_5_with_an_aligned_dkim():
    signed = {"Authentication-Results": "mx.example.org; dkim=pass header.d=shop.example; dmarc=pass", "DKIM-Signature": [{"d": "shop.example", "s": "k"}]}
    def origin(line, **extra):
        return codes(scored({"From": "Shop <noreply@shop.example>", "Received": [line], **extra}, [], ""))
    for line in ("from 203.0.113.5 by mx", "from [203.0.113.5] (unknown [203.0.113.5]) by mx", "from unknown (unknown [203.0.113.5]) by mx",
                 "from [2001:db8::5] by mx", "from x (helo=[203.0.113.5]) [203.0.113.5] by mx"):
        assert origin(line) == {"origin_mismatch": 15}, line
        assert origin(line, **signed) == {"origin_mismatch": 5}, line
    # localhost from a public address stays at 35, signed or not
    for line in ("from localhost ([203.0.113.5]) by mx", "from [203.0.113.5] (helo=localhost) by mx"):
        assert origin(line) == {"origin_mismatch": 35} and origin(line, **signed) == {"origin_mismatch": 35}
    assert origin("from [203.0.113.5] (helo=localhost) by mx with ESMTPSA") == {}  # SMTP AUTH is still not judged


def test_local_send_needs_a_third_party_server_a_claim_and_no_aligned_dkim():
    chain = ["from mx.shop.example (mx.shop.example [203.0.113.40]) by host.example with esmtps",
             "from localhost by mx.shop.example ([127.0.0.1]) with ESMTP"]
    signed = {"Authentication-Results": "mx.example.org; dkim=pass header.d=shop.example; dmarc=pass", "DKIM-Signature": [{"d": "shop.example", "s": "k"}]}
    def origin(sender, received=chain, **extra):
        return codes(scored({"From": sender, "Received": received, **extra}, [], ""))
    assert origin("Shop <noreply@shop.example>") == {"origin_mismatch": 25}
    assert origin("Shop <noreply@shop.example>", **signed) == {}                       # the company signed it: its own relay
    assert origin("Camille <camille@perso.example>") == {}                              # a person, no company or brand claimed
    assert origin("Shop <noreply@shop.example>", ["from localhost by host.example ([127.0.0.1])"]) == {}  # the receiving server itself
    assert origin("Shop <noreply@shop.example>", ["from x by host.example", "from localhost by host.example ([127.0.0.1])"]) == {}
    assert origin("Amazon <camille@perso.example>").get("origin_mismatch") == 25        # a brand in the display name is a claim


def test_display_name_brand_weights_and_exceptions():
    def named(sender, **extra):
        return codes(scored({"From": sender, **extra}, [], "")).get("display_name_brand_mismatch")
    signed = lambda d: {"Authentication-Results": f"mx.example.org; dkim=pass header.d={d}; dmarc=pass", "DKIM-Signature": [{"d": d, "s": "k"}]}
    assert named("Amazon <service@promo-abo.example>") == 30 and named("PayPal Support <help@secure-pay.example>") == 30
    assert named("Mondial Relay <noreply@colis-info.example>") == 30 and named("Crédit Agricole <info@notif-ca.example>") == 30
    assert named("Blockchain <hello@wallet-news.example>") == 30 and named("La Poste <contact@suivi-colis.example>") == 30
    assert named("Amazon <x@gmail.com>") == 30  # even from a free webmail
    assert named("Amazon <order-update@amazon.fr>") is None and named("Amazon <x@marketplace.amazon.co.uk>") is None
    assert named("Mondial Relay <noreply@mondialrelay.fr>") is None and named("La Poste <noreply@laposte.fr>") is None
    assert named("Assurance Maladie <noreply@ameli.fr>") is None and named("DHL Express <x@dhlparcel.example>") is None
    assert named("Amazon <service@promo-abo.example>", **signed("promo-abo.example")) is None  # signed by the From domain
    assert named("Free Mobile <contact@promo-mobile.example>") == 30 and named("Orange <x@promo.example>") == 30
    assert named("Camille Free <camille@perso.example>") is None and named("Un orange pressé <x@jus.example>") is None
    assert named("Camille <camille@perso.example>") is None and named("") is None


def test_generic_service_title_weighs_15_alone_and_30_next_to_another_signal():
    def named(sender, headers=None, links=(), text=""):
        return codes(scored({"From": sender, **(headers or {})}, list(links), text)).get("display_name_brand_mismatch")
    off = [{"url": "https://clic.offres.example/", "domain": "clic.offres.example"}]
    assert named("Service Client <contact@trial-hub.example>") == 15
    assert named("Support <hello@trial-hub.example>") == 15 and named("Sécurité <alerts@trial-hub.example>") == 15
    assert named("Customer Service <info@trial-hub.example>") == 15
    # a link off the From domain or payment wording alone are too common to raise it
    assert named("Service Client <contact@trial-hub.example>", links=off, text="Votre facture, règlement sous 48 heures") == 15
    assert named("Service Client <contact@trial-hub.example>", {"X-Spam-Flag": "YES"}) == 30
    assert named("Service Client <contact@trial-hub.example>", {"Authentication-Results": "mx.example.org; spf=fail"}) == 30
    # backed by the address or by the company's own name: not a claim
    assert named("Service Client <service@trial-hub.example>") is None and named("Support <support@trial-hub.example>") is None
    assert named("Trialhub Support <hello@trial-hub.example>") is None
    assert named("Service Client <contact@trial-hub.example>", {"Authentication-Results": "mx.example.org; dkim=pass header.d=trial-hub.example; dmarc=pass",
                                                                "DKIM-Signature": [{"d": "trial-hub.example", "s": "k"}]}) is None


def test_redirectors_are_off_domain_links_and_never_trusted():
    for host in ("share.google", "bit.ly", "t.co", "tinyurl.com", "lnkd.in", "go.bit.ly"):
        assert phishing.redirector(host) and not phishing.on_platform(host), host
    assert phishing.on_platform("www.linkedin.com") and phishing.on_platform("click.mandrillapp.com") and not phishing.redirector("x.com")
    one = [{"url": "https://share.google/abc", "domain": "share.google"}]
    result = scored({"From": "Shop <noreply@shop.example>"}, one, "")
    assert codes(result) == {"link_domain_mismatch": 15}  # not 5: a shortener is not a known platform
    crypto = scored({"From": "Coinco <notif@coinco.example>"}, one, "Never share your seed phrase")
    assert "crypto_transaction_lure" in codes(crypto)


def test_sibling_subdomains_of_one_domain_are_not_a_display_mismatch():
    def flagged(text, href):
        return phishing.extract_links(f'<a href="{href}">{text}</a>')[0].get("mismatch", False)
    assert not flagged("www.bankco.example", "https://mabanque.bankco.example/x")
    assert not flagged("app.bankco.co.uk", "https://www.bankco.co.uk/x")
    assert flagged("bankco.example", "https://bankco.example.evil.example/x") and flagged("www.bankco.example", "https://bankco-secure.example/x")
    assert flagged("paypal.github.io", "https://evil.github.io/x")  # a shared host: sibling subdomains are strangers


def test_internal_hosts_never_make_a_company_look_improvised(monkeypatch):
    """The bank notification that scored 91: internal hops, container hostname, links on the bank's own domains."""
    result = scenario(monkeypatch, "bank_internal_hops_aligned")
    assert result["score"] <= 10


def test_blockchain_impersonation_scores_high_with_the_brand_signal(monkeypatch):
    html = ('<p>You have 13 (0.025 ETH) pending in your Wallet.</p>'
            '<a href="https://wallet-notif.example/accept?id=7">Review Transaction &amp; Accept</a>')
    result = level_of(monkeypatch, "Blockchain <notif@wallet-news.example>", html, [LOCALHOST_HOP],
                      subject="Action Required: 13 (0.025 ETH) pending in your Wallet",
                      body="You have 13 (0.025 ETH) pending in your Wallet. Review Transaction & Accept")
    assert result["level"] == "high" and codes(result)["display_name_brand_mismatch"] == 30


# --- Third tuning pass: same brand under another suffix, relays, bounce services ---
# Fictional hosts only (.example / .test, documentation addresses). `dmarc=none` is what a host writes when the From domain
# publishes no policy: the DKIM signature is still the From domain's own.

def signed_auth(domain, dmarc="none", signer=None, server="mx.example.org"):
    signer = signer or domain
    return [("Authentication-Results", f"{server}; spf=pass; dkim=pass header.d={signer}; dmarc={dmarc} header.from={domain}"),
            ("DKIM-Signature", f"v=1; a=rsa-sha256; d={signer}; s=k1; h=from:to:subject; bh=Zm9v; b=QUFB")]


BANK_HOPS = [OWN_HOP, hop("from relay.finorio.example (relay.finorio.example [198.51.100.52]) by host.hosting.example with ESMTPS"),
             hop("from localhost (localhost [127.0.0.1]) by relay.finorio.example (Postfix) with ESMTP id 4Xyz")]

THIRD_PASS = {
    # a bank on .example whose links all go to its own brand on another suffix (.test)
    "bank_same_brand_other_suffix": dict(
        sender="Finorio <noreply@finorio.example>", subject="Action requise sur votre compte",
        body="Action requise: consultez votre message sécurisé.",
        html=('<p>Action requise: consultez votre message sécurisé.</p>'
              '<a href="https://mabanque.finorio.test/messages/1">Finorio</a>'
              '<a href="https://mabanque.finorio.test/help">www.finorio.test</a>'),
        headers=[OK_HOP, *signed_auth("finorio.example")]),
    # the same bank, Return-Path at a payment provider's bounce domain, no link at all
    "bank_bounce_service_no_link": dict(
        sender="Finorio <noreply@finorio.example>", subject="Votre relevé est disponible", body="Votre relevé est disponible dans votre espace.",
        html="<p>Votre relevé est disponible dans votre espace.</p>",
        headers=[BANK_HOPS[0], *signed_auth("finorio.example", **HOSTING), *BANK_HOPS[1:], ("Return-Path", "<bounce-77@bounces.worldline.com>")]),
    # a platform forwards a company's notice under "Brand via Platform": the platform's own signature passes, no link
    "brand_via_platform_no_link": dict(
        sender="EDF via Staffhub <noreply@mail-rh.example>", subject="Votre bulletin est disponible",
        body="Votre bulletin est disponible dans votre espace.", html="<p>Votre bulletin est disponible dans votre espace.</p>",
        headers=[OK_HOP, *signed_auth("mail-rh.example", dmarc="pass", signer="staffhub.example")]),
    # an internal tool's Google Group: Return-Path at the group service, the service's own signature passes, no link
    "support_via_google_groups": dict(
        sender="Support <contact@corp.example>", subject="[outil-interne] Nouveau ticket", body="Nouveau ticket ouvert par Camille.",
        html="<p>Nouveau ticket ouvert par Camille.</p>",
        headers=[OK_HOP, ("List-Id", "<outil-interne.corp.example>"), ("X-Google-Group-Id", "123456789012"),
                 ("Return-Path", "<contact+bnc123@googlegroups.com>"), *signed_auth("corp.example", dmarc="pass", signer="googlegroups.com")]),
    # a click-tracking link on a subdomain of the bank, text showing the bank's name on its other suffix
    "bank_tracking_subdomain": dict(
        sender="Finorio <noreply@finorio.example>", subject="Votre offre", body="Découvrez votre offre.",
        html='<p>Découvrez votre offre.</p><a href="https://t3.messagerie.finorio.example/c/abc">mabanque.finorio.test</a>',
        headers=[OK_HOP, *signed_auth("finorio.example")]),
}


def third(monkeypatch, name, **changes):
    spec = {**THIRD_PASS[name], **changes}
    return level_of(monkeypatch, spec["sender"], spec["html"], spec["headers"], subject=spec["subject"], body=spec["body"])


UNSIGNED = [("Authentication-Results", "mx.example.org; spf=pass; dkim=none; dmarc=none")]
UNSIGNED_HOSTING = [("Authentication-Results", "host.hosting.example; spf=pass; dkim=none; dmarc=none")]


def test_same_brand_under_another_suffix_is_internal_with_an_aligned_dkim(monkeypatch):
    result = third(monkeypatch, "bank_same_brand_other_suffix")
    assert result["level"] == "low" and codes(result) == {"urgency_payment": 6}
    # without a DKIM of the From domain (anyone can register finorio.test) the very same mail is a look-alike
    spec = THIRD_PASS["bank_same_brand_other_suffix"]
    unsigned = third(monkeypatch, "bank_same_brand_other_suffix", headers=[OK_HOP, *UNSIGNED])
    assert codes(unsigned) == {"lookalike_domain": 35, "link_domain_mismatch": 15, "urgency_payment": 6} and unsigned["level"] == "medium"
    other = third(monkeypatch, "bank_same_brand_other_suffix", headers=[OK_HOP, *signed_auth("finorio.example", signer="elsewhere.example")])
    assert {"lookalike_domain", "link_domain_mismatch"} <= set(codes(other)) and spec


def test_same_brand_rule_unit():
    same = phishing._same_brand
    assert same("www.finorio.test", "finorio.example") and same("finorio.co.uk", "finorio.example") and same("a.b.finorio.com.au", "finorio.fr")
    assert same("mabanque.finorio.co.jp", "noreply.finorio.example")
    assert not same("finorio-secure.test", "finorio.example") and not same("finorio.example.evil.test", "finorio.example")
    assert not same("finorio.github.io", "finorio.example") and not same("xn--bankc-0ta.test", "finorio.example")
    assert phishing.org_domain("www.finorio.co.uk") == "finorio.co.uk" and phishing._reg_label("www.finorio.co.uk") == "finorio"


def test_same_brand_link_is_internal_only_next_to_an_aligned_dkim_and_a_sane_first_hop():
    signed = {"Authentication-Results": "mx.example.org; dkim=pass header.d=finorio.example; dmarc=pass", "DKIM-Signature": [{"d": "finorio.example", "s": "k"}]}
    links = [{"url": "https://www.finorio.test/", "domain": "www.finorio.test", "text": "www.finorio.example", "mismatch": True,
              "shown": "www.finorio.example"}]
    base = {"From": "Finorio <noreply@finorio.example>"}
    assert scored({**base, **signed}, links, "")["score"] == 0   # not a lookalike, mismatch or display mismatch
    assert {"lookalike_domain", "link_domain_mismatch", "display_mismatch"} <= set(codes(scored(base, links, "")))
    local = {"Received": [LOCALHOST_HOP[1]]}
    # (the product-site exemption of an aligned DKIM, which holds the whole name, is older and does not look at the first hop)
    assert {"link_domain_mismatch", "display_mismatch", "origin_mismatch"} <= set(codes(scored({**base, **signed, **local}, links, "")))


def test_bank_with_a_payment_providers_return_path_and_no_link_stays_low(monkeypatch):
    result = third(monkeypatch, "bank_bounce_service_no_link")
    assert result["level"] == "low" and result["score"] == 0
    unsigned = third(monkeypatch, "bank_bounce_service_no_link", headers=[*BANK_HOPS, ("Return-Path", "<bounce-77@bounces.worldline.com>"), *UNSIGNED_HOSTING])
    assert unsigned["level"] == "medium" and codes(unsigned) == {"origin_mismatch": 40}   # 25 local hand-over + 15 Return-Path


def test_bounce_services_excuse_the_return_path_only_when_the_dkim_is_aligned_and_the_hop_sane():
    signed = {"Authentication-Results": "mx.example.org; dkim=pass header.d=finorio.example; dmarc=pass", "DKIM-Signature": [{"d": "finorio.example", "s": "k"}]}
    base = {"From": "Finorio <noreply@finorio.example>"}
    for domain in ("worldline.com", "bounces.worldline.com", "bnc.brevo.com", "em1.sparkpostmail.com", "mandrillapp.com", "amazonses.com",
                   "mg.mailgun.org", "u1.sendgrid.net", "mcsv.net", "rsgsv.net", "bounces.google.com", "googlegroups.com"):
        rp = {"Return-Path": f"<b@{domain}>"}
        assert codes(scored({**base, **signed, **rp}, [], "")) == {}, domain
    rp = {"Return-Path": "<b@bounces.worldline.com>"}
    assert codes(scored({**base, **rp}, [], "")) == {"origin_mismatch": 15}                        # not aligned
    assert codes(scored({**base, **signed, "Reply-To": "x@bounces.worldline.com"}, [], "")) == {"origin_mismatch": 5}
    assert codes(scored({**base, **signed, **rp, "Received": [LOCALHOST_HOP[1]]}, [], ""))["origin_mismatch"] == 40  # 35 + 5
    assert codes(scored({**base, **signed, "Return-Path": "<b@elsewhere.example>"}, [], "")) == {"origin_mismatch": 5}


def test_support_title_through_a_google_group_stays_low(monkeypatch):
    result = third(monkeypatch, "support_via_google_groups")
    assert result["level"] == "low" and result["score"] == 0
    returned = server.read_message("INBOX", 1, security=True)["security"]["headers"]
    assert "List-Id" not in returned and "X-Google-Group-Id" not in returned   # read by the score, not returned
    # with a link in the mail, or without any DKIM, the title and the relay still count
    linked = third(monkeypatch, "support_via_google_groups",
                   html='<p>Nouveau ticket.</p><a href="https://tickets.elsewhere.example/1">Ouvrir</a>')
    assert "display_name_brand_mismatch" in codes(linked)
    spec = THIRD_PASS["support_via_google_groups"]
    bare = third(monkeypatch, "support_via_google_groups", headers=[h for h in spec["headers"] if h[0] not in ("Authentication-Results", "DKIM-Signature")])
    assert codes(bare) == {"display_name_brand_mismatch": 30, "origin_mismatch": 15} and bare["level"] == "medium"


def test_group_relay_needs_a_passing_signature_of_the_relay_or_the_from_domain():
    base = {"From": "Support <contact@corp.example>", "List-Id": "<outil.corp.example>", "Return-Path": "<contact+x@googlegroups.com>"}
    def sig(domain, dmarc="pass"):
        return {"Authentication-Results": f"mx.example.org; dkim=pass header.d={domain}; dmarc={dmarc}", "DKIM-Signature": [{"d": domain, "s": "k"}]}
    assert codes(scored({**base, **sig("googlegroups.com")}, [], "")) == {}
    assert codes(scored({**base, **sig("corp.example")}, [], "")) == {}
    assert codes(scored({**base, **sig("random-esp.example")}, [], "")).get("origin_mismatch") == 15   # unrelated signer
    assert "origin_mismatch" in codes(scored({**base, **sig("googlegroups.com", dmarc="fail")}, [], ""))
    plain = {k: v for k, v in base.items() if k != "List-Id"}
    assert codes(scored({**plain, "Return-Path": "<contact@elsewhere.example>", **sig("googlegroups.com")}, [], "")).get("origin_mismatch") == 15
    local = {"Received": [LOCALHOST_HOP[1]]}
    assert "origin_mismatch" in codes(scored({**base, **sig("googlegroups.com"), **local}, [], ""))
    # a "Name via Platform" From is a relay too, vouched for by the platform's signature
    via = {"From": "Camille via Staffhub <contact@mail-rh.example>", "Return-Path": "<b@bnc.mail-rh.example>"}
    assert "origin_mismatch" not in codes(scored({**via, **sig("staffhub.example")}, [], ""))


def test_brand_through_a_platform_with_no_link_weighs_10_not_30(monkeypatch):
    result = third(monkeypatch, "brand_via_platform_no_link")
    assert result["level"] == "low" and codes(result) == {"display_name_brand_mismatch": 10}
    # a link, a signature that is not the platform's, or no signature: 30 as before
    linked = third(monkeypatch, "brand_via_platform_no_link", html='<p>Bulletin</p><a href="https://bulletin.elsewhere.example/1">Ouvrir</a>')
    assert codes(linked)["display_name_brand_mismatch"] == 30
    stranger = third(monkeypatch, "brand_via_platform_no_link", headers=[OK_HOP, *signed_auth("mail-rh.example", dmarc="pass", signer="other.example")])
    assert codes(stranger) == {"display_name_brand_mismatch": 30} and stranger["level"] == "medium"
    unsigned = third(monkeypatch, "brand_via_platform_no_link", headers=[OK_HOP, *UNSIGNED])
    assert codes(unsigned) == {"display_name_brand_mismatch": 30}
    assert codes(scored({"From": "EDF via Staffhub <noreply@mail-rh.example>"}, [], "see https://x.example/a"))["display_name_brand_mismatch"] == 30


def test_generic_title_is_free_when_there_is_no_link_and_a_dkim_passed():
    def named(headers, text="Votre ticket", links=()):
        return codes(scored({"From": "Service Client <contact@trial-hub.example>", **headers}, list(links), text)).get("display_name_brand_mismatch")
    passed = {"Authentication-Results": "mx.example.org; dkim=pass header.d=esp.example; dmarc=pass", "DKIM-Signature": [{"d": "esp.example", "s": "k"}]}
    assert named({}) == 15 and named(passed) is None
    assert named(passed, links=[{"url": "https://x.example/", "domain": "x.example"}]) == 15 and named(passed, text="Voir https://x.example/a") == 15
    assert named({"Authentication-Results": "mx.example.org; dkim=fail; dmarc=fail"}) == 30
    assert named({**passed, "Received": [LOCALHOST_HOP[1]]}) == 30   # an improvised first hop excuses nothing


def test_display_mismatch_is_small_for_the_senders_name_on_a_subdomain_or_a_platform(monkeypatch):
    result = third(monkeypatch, "bank_tracking_subdomain")
    assert result["level"] == "low" and result["score"] == 0 and codes(result) == {}
    esp = third(monkeypatch, "bank_tracking_subdomain",
                html='<p>Offre.</p><a href="https://email.sparkpostmail.com/f/abc">https://www.finorio.example/offre</a>')
    assert codes(esp)["display_mismatch"] == 5 and esp["level"] == "low"
    unsigned = third(monkeypatch, "bank_tracking_subdomain", headers=[OK_HOP, *UNSIGNED])
    assert codes(unsigned)["display_mismatch"] == 35
    local = third(monkeypatch, "bank_tracking_subdomain", headers=[LOCALHOST_HOP, *signed_auth("finorio.example", **HOSTING)])
    assert codes(local)["display_mismatch"] == 10 and codes(local)["origin_mismatch"] == 35


def test_same_label_on_another_suffix_without_an_aligned_dkim_stays_high(monkeypatch):
    """The counter-example: a spoofed From, a link to the same name under another suffix, no signature of the From domain."""
    html = ('<p>Action requise: confirmez votre identité sous 24 heures.</p>'
            '<a href="https://mabanque.finorio.test/login">www.finorio.example</a>')
    headers = [LOCALHOST_HOP, ("Authentication-Results", "host.hosting.example; spf=fail smtp.mailfrom=finorio.example; dkim=none; dmarc=fail header.from=finorio.example"),
               ("Received-SPF", "fail (host.hosting.example: domain of finorio.example does not designate 203.0.113.77)")]
    result = level_of(monkeypatch, "Finorio <noreply@finorio.example>", html, headers, subject="Action requise", body="Action requise: confirmez votre identité")
    assert result["level"] == "high" and {"auth_fail", "origin_mismatch", "lookalike_domain", "link_domain_mismatch"} <= set(codes(result))
    # a signature of an unrelated domain, or the From's own signature with an improvised first hop: not excused either
    other = level_of(monkeypatch, "Finorio <noreply@finorio.example>", html, [LOCALHOST_HOP, *signed_auth("finorio.example", signer="elsewhere.example", **HOSTING)], uid=2)
    assert other["level"] in ("medium", "high") and {"lookalike_domain", "display_mismatch"} <= set(codes(other))
    signed_local = level_of(monkeypatch, "Finorio <noreply@finorio.example>", html, [LOCALHOST_HOP, *signed_auth("finorio.example", **HOSTING)], uid=3)
    assert signed_local["level"] in ("medium", "high") and {"origin_mismatch", "link_domain_mismatch", "display_mismatch"} <= set(codes(signed_local))
    # no alignment at all and nothing else wrong: still a look-alike of the brand, and the displayed name still lies
    quiet = level_of(monkeypatch, "Finorio <noreply@finorio.example>", html, [OK_HOP, *UNSIGNED], uid=4)
    assert quiet["level"] in ("medium", "high") and codes(quiet)["lookalike_domain"] == 35 and codes(quiet)["display_mismatch"] == 35


def test_alignment_survives_a_dmarc_result_that_is_not_a_failure():
    base = {"From": "Shop <noreply@shop.example>", "Return-Path": "<x@elsewhere.example>", "DKIM-Signature": [{"d": "shop.example", "s": "k"}]}
    for dmarc, expected in (("pass", {"origin_mismatch": 5}), ("none", {"origin_mismatch": 5}), ("bestguesspass", {"origin_mismatch": 5}),
                            ("fail", {"auth_fail": 35, "origin_mismatch": 15})):
        headers = {**base, "Authentication-Results": f"mx.example.org; dkim=pass header.d=shop.example; dmarc={dmarc}"}
        assert codes(scored(headers, [], "")) == expected, dmarc
    no_signature = {"From": "Shop <noreply@shop.example>", "Return-Path": "<x@elsewhere.example>",
                    "Authentication-Results": "mx.example.org; dkim=pass header.d=shop.example; dmarc=pass"}   # header.d of the result is enough
    assert codes(scored(no_signature, [], "")) == {"origin_mismatch": 5}


# --- Only the receiving server's authentication results count ---
# The sender writes every header it sends: an `Authentication-Results: x; dkim=pass header.d=<bank>` that it added itself
# says nothing. Fictional hosts only; the receiving server of these fixtures is host.hosting.example, which (like a shared
# Exim / cPanel host) writes no Authentication-Results of its own.

RECEIVER = ("Received", "from out.sender-hub.example (out.sender-hub.example [198.51.100.30]) by host.hosting.example "
                         "with esmtps (Exim 4.100.1) id 1vMabc-000xyz-1Q; Fri, 21 Nov 2026 08:00:02 +0100")
SENDER_HOP = ("Received", "from [203.0.113.64] (unknown [203.0.113.64]) by out.sender-hub.example with ESMTP; "
                          "Fri, 21 Nov 2026 08:00:00 +0100")
BANK_HTML = ('<p>Votre espace est suspendu. Confirmez votre identité.</p>'
             '<a href="https://finorio-secure.example/login?id=3">www.finorio.example</a>'
             '<a href="https://tracker.mail-hub.example/u/9">Confirmer</a>')
FORGED_PASS = "dkim=pass header.d=finorio.example; spf=pass smtp.mailfrom=finorio.example; dmarc=pass header.from=finorio.example"
FINORIO_SIGNATURE = ("DKIM-Signature", "v=1; a=rsa-sha256; d=finorio.example; s=k1; h=from:to:subject; bh=Zm9v; b=QUFB")


def forged(monkeypatch, headers, uid=1):
    return level_of(monkeypatch, "Finorio <noreply@finorio.example>", BANK_HTML, headers, subject="Action requise",
                    body="Votre espace est suspendu. Confirmez votre identité.", uid=uid)


def test_an_authentication_results_with_another_authserv_id_is_the_senders_and_attenuates_nothing(monkeypatch):
    result = forged(monkeypatch, [RECEIVER, SENDER_HOP, ("Authentication-Results", f"x.attacker.example; {FORGED_PASS}"), FINORIO_SIGNATURE])
    assert result["level"] == "high" and {"lookalike_domain", "link_domain_mismatch", "display_mismatch"} <= set(codes(result))
    assert codes(result)["lookalike_domain"] == 35 and codes(result)["display_mismatch"] == 35   # not capped at 5
    security = server.read_message("INBOX", 1, security=True)["security"]
    assert security["auth"] == "unknown"   # the report says that no result was the receiver's
    # the same mail without the forged line scores the same: it is simply ignored
    plain = forged(monkeypatch, [RECEIVER, SENDER_HOP, FINORIO_SIGNATURE], uid=2)
    assert plain["score"] == result["score"] and codes(plain) == codes(result)


def test_an_authentication_results_under_an_external_received_line_is_the_senders(monkeypatch):
    # the authserv-id is the receiving server's, as an attacker would write it, but the line sits below a Received
    # line that another server wrote: the receiver's own results are written above everything it received
    headers = [RECEIVER, SENDER_HOP, ("Authentication-Results", f"host.hosting.example; {FORGED_PASS}"), FINORIO_SIGNATURE]
    result = forged(monkeypatch, headers)
    assert result["level"] == "high" and codes(result)["lookalike_domain"] == 35
    assert server.read_message("INBOX", 1, security=True)["security"]["auth"] == "unknown"
    # above that line the same text is the receiver's
    result = forged(monkeypatch, [RECEIVER, ("Authentication-Results", f"host.hosting.example; {FORGED_PASS}"), SENDER_HOP, FINORIO_SIGNATURE], uid=2)
    assert result["level"] == "low" and server.read_message("INBOX", 2, security=True)["security"]["auth"] == "receiver"


def test_a_forged_failure_from_the_sender_is_ignored_too(monkeypatch):
    headers = [RECEIVER, SENDER_HOP, ("Authentication-Results", "x; spf=fail; dmarc=fail"), ("Received-SPF", "fail (x: no)")]
    assert "auth_fail" not in codes(forged(monkeypatch, headers))


def test_a_dkim_signature_claiming_the_banks_domain_does_not_align_it(monkeypatch):
    # the trusted result vouches for the attacker's own signature; a second, unchecked one claims d=<bank>
    attacker = ("DKIM-Signature", "v=1; a=rsa-sha256; d=phish-sender.example; s=sel2026; h=from:to; bh=Zm9v; b=QUFB")
    headers = [RECEIVER, ("Authentication-Results", "host.hosting.example; dkim=pass header.d=phish-sender.example; "
                          "dmarc=none header.from=finorio.example"), SENDER_HOP, attacker, FINORIO_SIGNATURE]
    result = forged(monkeypatch, headers)
    assert result["level"] == "high" and codes(result)["lookalike_domain"] == 35 and codes(result)["display_mismatch"] == 35
    assert server.read_message("INBOX", 1, security=True)["security"]["auth"] == "receiver"
    evidence = {"DKIM-Signature": [{"d": "phish-sender.example", "s": "sel2026"}, {"d": "finorio.example", "s": "k1"}]}
    trust = {"ar": "host.hosting.example; dkim=pass header.d=phish-sender.example", "spf": ""}
    assert phishing._dkim_pass_domains(evidence, trust) == {"phish-sender.example"}


def test_a_trusted_dkim_pass_names_its_domain_by_header_d_then_header_i():
    def domains(ar, signatures=()):
        sigs = {"DKIM-Signature": [{"d": d, "s": "k"} for d in signatures]}
        return phishing._dkim_pass_domains(sigs, {"ar": ar, "spf": ""})
    signed = ["finorio.example", "phish-sender.example"]
    assert domains("mx.example.org; dkim=pass header.d=mail.finorio.example header.s=k", signed) == {"finorio.example"}
    assert domains("mx.example.org; dkim=pass header.i=@news.finorio.example header.s=k", signed) == {"finorio.example"}
    assert domains("mx.example.org; dkim=pass header.i=bounce@finorio.example", signed) == {"finorio.example"}
    assert domains("mx.example.org; dkim=pass header.d=a.example; dkim=pass header.d=b.example", signed) == {"a.example", "b.example"}
    assert domains("mx.example.org; dkim=fail header.d=finorio.example; dkim=pass header.d=a.example") == {"a.example"}
    assert domains("mx.example.org; dkim=pass header.d=finorio.example; dmarc=fail", signed) == set()
    assert domains("mx.example.org; dkim=none; spf=pass", signed) == set()


def test_a_dkim_pass_without_header_d_or_i_aligns_only_a_message_with_one_signature():
    def domains(*signatures):
        sigs = {"DKIM-Signature": [{"d": d, "s": "k"} for d in signatures]}
        return phishing._dkim_pass_domains(sigs, {"ar": "mx.example.org; dkim=pass (good signature)", "spf": ""})
    assert domains("finorio.example") == {"finorio.example"}
    assert domains("finorio.example", "phish-sender.example") == set()   # which one passed? nothing says: no alignment
    assert domains() == set()
    assert domains("") == set()   # a signature without d= names nothing


def test_receiving_server_is_the_by_of_the_topmost_received_or_a_configured_authserv_id():
    top = "from a.example ([198.51.100.1]) by mx.example.org with ESMTPS"
    old = "from b.example ([198.51.100.2]) by a.example with ESMTP"
    ar = "mx.example.org; dkim=pass header.d=finorio.example"
    headers = {"Received": [top, old], "Authentication-Results": [ar], "_Order": ["received", "authentication-results", "received"]}
    assert phishing.trusted_results(headers)["ar"] == ar
    assert phishing.trusted_results({**headers, "_Order": ["received", "received", "authentication-results"]})["ar"] == ""  # below `old`
    assert phishing.trusted_results({**headers, "Authentication-Results": ["mx.attacker.example; dkim=pass"]})["ar"] == ""
    assert phishing.trusted_results({**headers, "Authentication-Results": ["in.example.org; dkim=pass"]})["ar"] != ""   # same organisation
    assert phishing.trusted_results({**headers, "Authentication-Results": ["MX.EXAMPLE.ORG.; dkim=pass"]})["ar"] != ""   # case and dot
    assert phishing.trusted_results({**headers, "Authentication-Results": ["mx.example.org 1; dkim=pass"]})["ar"] != ""  # with a version
    assert phishing.trusted_results({**headers, "_Order": None})["ar"] == ""    # no positions: cannot tell
    # the topmost line that qualifies wins; a lower one (the sender's) never does
    both = {**headers, "Authentication-Results": ["mx.example.org; spf=pass", "mx.example.org; spf=fail"],
            "_Order": ["received", "authentication-results", "authentication-results", "received"]}
    assert phishing.trusted_results(both)["ar"] == "mx.example.org; spf=pass"
    # Gmail: the topmost line only names an internal token, so the configured server is the receiver
    gmail = {"Received": ["by 2002:a05:6a10:1 with SMTP id x; Fri", "from mail.finorio.example (mail.finorio.example. [198.51.100.60]) by mx.google.com with ESMTPS id 1",
                          "from [10.0.0.5] by mail.finorio.example; Fri"],
             "Authentication-Results": ["mx.google.com; dkim=pass header.i=@finorio.example header.s=k1"],
             "_Order": ["received", "received", "authentication-results", "received"]}
    assert phishing.trusted_results(gmail)["ar"] == ""
    assert phishing.trusted_results(gmail, ("mx.google.com",))["ar"] == gmail["Authentication-Results"][0]
    low = {**gmail, "_Order": ["received", "received", "received", "authentication-results"]}   # under the sender's own line
    assert phishing.trusted_results(low, ("mx.google.com",))["ar"] == ""
    # an IP, an IPv6 token or a bare word is not a host: an authserv-id never matches it
    assert phishing.trusted_results({"Received": ["from x by 192.0.2.1"], "Authentication-Results": ["192.0.2.1; dkim=pass"],
                                     "_Order": ["received", "authentication-results"]})["ar"] == ""


def test_received_spf_counts_only_when_the_receiver_added_it_above_the_first_external_line():
    top = "from a.example ([198.51.100.1]) by mx.example.org with ESMTPS"
    old = "from b.example ([198.51.100.2]) by a.example with ESMTP"
    spf = "fail (mx.example.org: domain of finorio.example does not designate 198.51.100.1 as permitted sender)"
    base = {"Received": [top, old], "Received-SPF": [spf]}
    assert phishing.trusted_results({**base, "_Order": ["received", "received-spf", "received"]})["spf"] == spf
    assert phishing.trusted_results({**base, "_Order": ["received", "received", "received-spf"]})["spf"] == ""
    forged_host = "pass (mx.attacker.example: domain of finorio.example designates 198.51.100.1 as permitted sender)"
    assert phishing.trusted_results({**base, "Received-SPF": [forged_host], "_Order": ["received", "received-spf", "received"]})["spf"] == ""
    bare = "pass"
    assert phishing.trusted_results({**base, "Received-SPF": [bare], "_Order": ["received", "received-spf", "received"]})["spf"] == bare
    # Gmail's own comment names google.com, the organisation of mx.google.com
    google = "pass (google.com: domain of a@finorio.example designates 198.51.100.1 as permitted sender)"
    assert phishing.trusted_results({"Received": ["by 2002:a05::1 with SMTP id x", "from m.example by mx.google.com with ESMTPS"],
                                     "Received-SPF": [google], "_Order": ["received", "received", "received-spf"]},
                                    ("mx.google.com",))["spf"] == google


def test_arc_authentication_results_is_never_trusted():
    headers = {"Received": ["from a.example ([198.51.100.1]) by mx.example.org with ESMTPS"],
               "ARC-Authentication-Results": ["i=1; mx.example.org; dkim=pass header.d=finorio.example; dmarc=pass"],
               "_Order": ["received"]}
    assert phishing.trusted_results(headers) == {"ar": "", "spf": ""} and phishing._authentication(phishing.trusted_results(headers)) == {}


def test_without_a_trusted_result_the_authentication_is_unknown_not_pass_and_not_fail(monkeypatch):
    # no Authentication-Results at all (a host that writes none) and a Received-SPF the sender wrote
    headers = [RECEIVER, SENDER_HOP, ("Received-SPF", "fail (x: forged)"), FINORIO_SIGNATURE]
    result = forged(monkeypatch, headers)
    assert "auth_fail" not in codes(result) and codes(result)["lookalike_domain"] == 35
    assert server.read_message("INBOX", 1, security=True)["security"]["auth"] == "unknown"


def test_the_receivers_failures_still_count(monkeypatch):
    headers = [RECEIVER, ("Authentication-Results", "host.hosting.example; spf=fail smtp.mailfrom=finorio.example; dmarc=fail header.from=finorio.example"),
               SENDER_HOP]
    assert codes(forged(monkeypatch, headers))["auth_fail"] == 45


def test_a_configured_authserv_id_makes_the_account_trust_that_server(monkeypatch):
    monkeypatch.setenv("MAIL_AUTH_SERVERS", "gate.example.net")
    headers = [RECEIVER, ("Authentication-Results", f"gate.example.net; {FORGED_PASS}"), SENDER_HOP, FINORIO_SIGNATURE]
    assert forged(monkeypatch, headers)["level"] == "low"
    monkeypatch.delenv("MAIL_AUTH_SERVERS")
    assert forged(monkeypatch, headers, uid=2)["level"] == "high"   # not the receiver, not configured


def test_the_trusted_servers_of_an_account_reach_the_report(monkeypatch):
    seen = {}
    real = phishing.phishing_score

    def spy(headers, links, body, subject="", trusted_servers=()):
        seen["servers"] = trusted_servers
        return real(headers, links, body, subject, trusted_servers)
    monkeypatch.setattr(phishing, "phishing_score", spy)
    monkeypatch.setenv("MAIL_AUTH_SERVERS", "gate.example.net")
    install(monkeypatch, FakeIMAP({"INBOX": {"flags": "", "messages": [mk(1, "Hi", html="<p>x</p>")]}}))
    server.read_message("INBOX", 1, security=True)
    assert seen["servers"] == ("gate.example.net",)
    monkeypatch.delenv("MAIL_AUTH_SERVERS")
    server.read_message("INBOX", 1, security=True)
    assert seen["servers"] == ()


def test_raw_headers_records_where_the_results_sit_relative_to_the_received_lines():
    raw = mk(1, "Hi", headers=[RECEIVER, ("Authentication-Results", "host.hosting.example; dkim=none"), SENDER_HOP,
                               ("Received-SPF", "none"), ("X-Other", "1")])["raw"]
    evidence = phishing.raw_headers(email.message_from_bytes(raw, policy=policy.default))
    assert evidence["_Order"] == ["received", "authentication-results", "received", "received-spf"]
    msg = email.message_from_bytes(raw, policy=policy.default)
    assert "_Order" not in phishing.auth_headers(msg, evidence)[0]   # internal: never returned to the model
