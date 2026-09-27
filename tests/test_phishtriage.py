"""Offline unit tests for PhishTriage."""

from phishtriage.analyzer import Analyzer
from phishtriage.models import RiskLevel
from phishtriage.parser import load_email_file
from phishtriage.utils import registered_domain, domain_of_addr, is_ip_host


# ---- utils ------------------------------------------------------------------

def test_registered_domain():
    assert registered_domain("mail.google.com") == "google.com"
    assert registered_domain("a.b.example.co.uk") == "example.co.uk"
    assert registered_domain("paypal-account-verify.top") == "paypal-account-verify.top"


def test_domain_of_addr():
    assert domain_of_addr("user@Example.COM") == "example.com"
    assert domain_of_addr("noaddr") == ""


def test_is_ip_host():
    assert is_ip_host("http://185.203.116.44/x") is True
    assert is_ip_host("https://paypal.com") is False


# ---- parsing ----------------------------------------------------------------

def test_parse_headers():
    email = load_email_file("samples/phishing.eml")
    assert email.meta.from_addr == "security@paypal-account-verify.top"
    assert email.meta.reply_to == "help@secure-refund-desk.top"
    assert "suspended" in (email.meta.subject or "").lower()


# ---- analysis ---------------------------------------------------------------

def _report(path):
    return Analyzer().analyze(load_email_file(path))


def test_phishing_is_high_risk():
    report = _report("samples/phishing.eml")
    assert report.verdict.level >= RiskLevel.HIGH.level
    titles = {f.title for f in report.findings}
    assert "Display-name brand impersonation" in titles
    assert any("mismatch" in t.lower() for t in titles)          # reply-to / link mismatch
    assert any(f.check == "urls" for f in report.findings)        # IP link / link mismatch
    assert any("DMARC" in t for t in titles)                      # dmarc=fail


def test_benign_is_low_risk():
    report = _report("samples/benign.eml")
    assert report.verdict is RiskLevel.LOW
    assert report.score <= 2


def test_findings_sorted_by_weight():
    report = _report("samples/phishing.eml")
    weights = [f.weight for f in report.findings]
    assert weights == sorted(weights, reverse=True)


def test_score_increases_with_indicators():
    phish = _report("samples/phishing.eml")
    benign = _report("samples/benign.eml")
    assert phish.score > benign.score
