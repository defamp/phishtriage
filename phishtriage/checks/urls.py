"""URL / link analysis."""

from __future__ import annotations

import re
from typing import List

from ..models import Finding, Weight
from ..parser import ParsedEmail
from ..utils import URL_RE, hostname, is_ip_host, registered_domain
from .base import BaseCheck

_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "cutt.ly"}
_SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "tk", "gq", "ml", "cf", "country", "click"}
_ANCHOR_RE = re.compile(r'<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.I | re.S)


class URLCheck(BaseCheck):
    name = "urls"

    def run(self, email: ParsedEmail) -> List[Finding]:
        findings: List[Finding] = []
        urls = set(URL_RE.findall(email.text_body))
        urls.update(URL_RE.findall(email.html_body))

        flagged_ip, flagged_short, flagged_tld, flagged_puny = False, False, False, False
        for url in urls:
            host = hostname(url)
            if not host:
                continue
            if is_ip_host(url) and not flagged_ip:
                findings.append(Finding(self.name, "Link uses a raw IP address", Weight.HIGH,
                                        detail="Legitimate brands rarely link to bare IPs.",
                                        evidence=[url]))
                flagged_ip = True
            if "xn--" in host and not flagged_puny:
                findings.append(Finding(self.name, "Punycode / homograph domain", Weight.HIGH,
                                        detail="Punycode (xn--) can spoof a real domain.",
                                        evidence=[url]))
                flagged_puny = True
            if registered_domain(host) in _SHORTENERS and not flagged_short:
                findings.append(Finding(self.name, "URL shortener used", Weight.MEDIUM,
                                        detail="Shorteners hide the true destination.",
                                        evidence=[url]))
                flagged_short = True
            tld = host.rsplit(".", 1)[-1]
            if tld in _SUSPICIOUS_TLDS and not flagged_tld:
                findings.append(Finding(self.name, f"Suspicious TLD .{tld}", Weight.LOW,
                                        detail="This TLD is frequently abused for phishing.",
                                        evidence=[url]))
                flagged_tld = True

        # Anchor text vs href mismatch (classic phishing tell).
        for href, text in _ANCHOR_RE.findall(email.html_body):
            text_clean = re.sub(r"<[^>]+>", "", text).strip()
            shown = hostname(text_clean)
            if shown and "." in shown:  # anchor text looks like a domain/URL
                if registered_domain(shown) and registered_domain(shown) != registered_domain(href):
                    findings.append(Finding(
                        self.name, "Link text does not match destination", Weight.HIGH,
                        detail=f"Shows '{registered_domain(shown)}' but links to "
                               f"'{registered_domain(href)}'.",
                        evidence=[f"{text_clean} -> {href}"],
                    ))
                    break

        return findings
