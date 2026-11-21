"""read_message(security=true): authentication headers and real link targets, from a spoofed parcel notice.
Everything is fake (reserved .example domains); no link is ever followed."""

import json
import socket

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
    tool = stdio_tools()["read_message"]
    assert tool["inputSchema"]["properties"]["security"]["type"] == "boolean" and "security" not in tool["inputSchema"].get("required", [])
    assert tool["inputSchema"]["additionalProperties"] is False and len(tool["description"]) <= 600


# --- phishing_score ---
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
    ("Received", "from [10.1.2.3] (unknown [10.1.2.3]) by mail-out.sendibm3.com with SMTP; Fri, 21 Nov 2026 06:59:58 +0100"),
    ("Authentication-Results", "mx.example.org; spf=pass smtp.mailfrom=bnc.sendibt3.com; dkim=pass header.d=marque.fr; dmarc=pass header.from=marque.fr"),
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
    assert result["level"] == "high" and result["score"] == 95
    assert codes(result) == {"lookalike_domain": 35, "origin_mismatch": 25, "template_placeholder": 20, "link_domain_mismatch": 15}
    assert [r["weight"] for r in result["reasons"]] == sorted((r["weight"] for r in result["reasons"]), reverse=True)
    details = " | ".join(r["detail"] for r in result["reasons"])
    assert "ml-colis-relay.example" in details and "helo is 'localhost'" in details and "203.0.113.64" in details
    assert "{prenom}" in details


def test_newsletter_through_a_mailing_platform_stays_low(monkeypatch):
    m = mk(2, "Soldes", sender="Marque <newsletter@marque.fr>", body="Soldes: dernières heures. www.marque.fr", html=NEWSLETTER_HTML,
           headers=NEWSLETTER_HEADERS)
    result = score_of(monkeypatch, m, 2)
    assert result["level"] == "low" and result["score"] == 15
    assert codes(result) == {"display_mismatch": 10, "link_domain_mismatch": 5}


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


def test_authentication_failures_and_spam_verdict():
    score = phishing.phishing_score(
        {"From": "Bank <alerts@bank.example>", "Authentication-Results": "mx.example.org; spf=fail; dkim=fail; dmarc=fail",
         "X-Spam-Flag": "YES", "X-Spam-Score": "9.1"}, [], "")
    assert codes(score) == {"auth_fail": 45, "spam_flag": 30} and score["level"] == "high"
    # only the topmost Authentication-Results counts: a later one is written by the sender
    forged = phishing.phishing_score({"From": "a@bank.example", "Authentication-Results": ["mx.example.org; spf=pass", "x; spf=fail dmarc=fail"]}, [], "")
    assert forged["score"] == 0
    soft = phishing.phishing_score({"From": "a@bank.example", "Received-SPF": "softfail (domain does not designate)"}, [], "")
    assert codes(soft) == {"auth_fail": 10}
    assert phishing.phishing_score({"X-Spam-Bar": "++++++"}, [], "")["reasons"][0]["weight"] == 25


def test_score_is_capped_at_100():
    links = [{"url": "https://bank-secure.example/", "domain": "bank-secure.example", "mismatch": True, "shown": "bank.example", "idn": True}]
    headers = {"From": "Bank <alerts@bank.example>", "Authentication-Results": "x; spf=fail; dmarc=fail", "X-Spam-Flag": "YES",
               "Received": ["from [203.0.113.9] (helo=localhost) by mx"]}
    result = phishing.phishing_score(headers, links, "Urgent: {{name}}, paiement sous 24 heures")
    assert result["score"] == 100 and sum(r["weight"] for r in result["reasons"]) > 100


def test_lookalike_and_alignment_rules():
    def lookalike(host, frm="Mondial Relay <noreply@mondialrelay.fr>"):
        link = {"url": f"https://{host}/", "domain": host}
        return "lookalike_domain" in codes(phishing.phishing_score({"From": frm}, [link], ""))
    assert lookalike("ml-colis-relay.example") and lookalike("mondialetransporte.example")
    assert lookalike("mondialrelay.fr.verify-colis.example")
    assert not lookalike("www.mondialrelay.fr") and not lookalike("click.mondialrelay.fr") and not lookalike("sendibt3.com")
    assert not lookalike("france-travail.example", "France Connect <noreply@franceconnect.fr>")  # a generic word proves nothing
    assert not lookalike("ml-colis-relay.example", "Camille <camille@gmail.com>")  # not a company address
    idn = phishing.phishing_score({"From": "a@example.org"}, [{"url": "https://xn--mondilrelay-n6a.example/", "domain": "xn--mondilrelay-n6a.example", "idn": True}], "")
    assert codes(idn)["lookalike_domain"] == 30
    aligned = phishing.phishing_score({"From": "Shop <noreply@shop.example>", "Return-Path": "<bounce@mail.shop.example>"}, [], "")
    assert aligned["score"] == 0
    other = phishing.phishing_score({"From": "Shop <noreply@shop.example>", "Return-Path": "<x@elsewhere.example>"}, [], "")
    assert codes(other) == {"origin_mismatch": 15}


def test_first_hop_judges_the_oldest_received_and_only_outside_clients():
    def hop(received, **extra):
        return codes(phishing.phishing_score({"From": "Shop <noreply@shop.example>", "Received": received, **extra}, [], ""))
    assert "origin_mismatch" in hop(["from mx by me", "from [203.0.113.5] by mx with esmtp"])
    assert "origin_mismatch" in hop(["from 203.0.113.5 by mx"])
    assert "origin_mismatch" not in hop(["from localhost (localhost [127.0.0.1]) by mx"])  # internal hand-over
    assert "origin_mismatch" not in hop(["from out.shop.example (out.shop.example [203.0.113.5]) by mx"])
    assert "origin_mismatch" not in hop(["by 2002:a05:6a00 with SMTP id x; Fri"])  # no "from" clause
    signed = {"Authentication-Results": "mx; dkim=pass header.d=shop.example; dmarc=pass", "DKIM-Signature": [{"d": "shop.example", "s": "k"}]}
    assert "origin_mismatch" not in hop(["from [203.0.113.5] (helo=localhost) by mx"], **signed)  # authenticated: not improvised


def test_placeholders_and_keywords_unit():
    def text_codes(text):
        return codes(phishing.phishing_score({}, [], text))
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
    assert list(security)[:2] == ["phishing", "headers"]


def test_score_reads_the_whole_evidence_even_when_output_is_cut(monkeypatch):
    headers = [("Authentication-Results", "mx.example.org; " + "dkim=pass header.d=a.example; " * 30 + "spf=fail dmarc=fail")]
    result = score_of(monkeypatch, mk(7, "Big", sender="a@bank.example", headers=headers, html="<p>x</p>"), 7)
    assert codes(result)["auth_fail"] == 45 and "spf=fail" in result["reasons"][0]["detail"]  # the failures sit past the 400-character cut


def test_score_is_pure_and_description_still_fits():
    assert len(stdio_tools()["read_message"]["description"]) <= 600
    original = socket.socket.connect
    try:
        socket.socket.connect = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network"))
        assert phishing.phishing_score({"From": "a@example.org"}, [], "x")["level"] == "low"
    finally:
        socket.socket.connect = original
