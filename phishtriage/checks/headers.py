"""Sender / authentication header checks."""

from __future__ import annotations

import re
from typing import List

from ..models import Finding, Weight
from ..parser import ParsedEmail
from ..utils import domain_of_addr, registered_domain
from .base import BaseCheck

# Brand names that are commonly impersonated in the display name.
_BRANDS = {
    "paypal": "paypal.com", "microsoft": "microsoft.com", "apple": "apple.com",
    "google": "google.com", "amazon": "amazon.com", "netflix": "netflix.com",
    "bank": None, "facebook": "facebook.com", "instagram": "instagram.com",
    "dhl": "dhl.com", "fedex": "fedex.com", "linkedin": "linkedin.com",
}

_AUTH_RE = {
    "spf": re.compile(r"spf=(\w+)", re.I),
    "dkim": re.compile(r"dkim=(\w+)", re.I),
    "dmarc": re.compile(r"dmarc=(\w+)", re.I),
}


class HeaderCheck(BaseCheck):
    name = "headers"

    def run(self, email: ParsedEmail) -> List[Finding]:
        findings: List[Finding] = []
        meta = email.meta
        from_domain = registered_domain(domain_of_addr(meta.from_addr or ""))

        # 1) Display-name brand impersonation.
        if meta.from_name and from_domain:
            low = meta.from_name.lower()
            for brand, brand_domain in _BRANDS.items():
                if brand in low and brand_domain and registered_domain(brand_domain) != from_domain:
                    findings.append(Finding(
                        self.name, "Display-name brand impersonation", Weight.HIGH,
                        detail=f"Name mentions '{brand}' but sender domain is '{from_domain}'.",
                        evidence=[meta.from_header or ""],
                    ))
                    break

        # 2) Reply-To domain differs from From domain.
        if meta.reply_to:
            reply_domain = registered_domain(domain_of_addr(meta.reply_to))
            if reply_domain and from_domain and reply_domain != from_domain:
                findings.append(Finding(
                    self.name, "Reply-To domain mismatch", Weight.MEDIUM,
                    detail=f"From is '{from_domain}' but replies go to '{reply_domain}'.",
                    evidence=[f"Reply-To: {meta.reply_to}"],
                ))

        # 3) Return-Path (envelope) differs from From domain.
        if meta.return_path:
            rp_domain = registered_domain(domain_of_addr(meta.return_path))
            if rp_domain and from_domain and rp_domain != from_domain:
                findings.append(Finding(
                    self.name, "Return-Path / From mismatch", Weight.LOW,
                    detail=f"Envelope sender '{rp_domain}' differs from '{from_domain}'.",
                    evidence=[f"Return-Path: {meta.return_path}"],
                ))

        # 4) SPF / DKIM / DMARC results from Authentication-Results.
        auth = " ".join(email.message.get_all("Authentication-Results", []))
        for mech, pattern in _AUTH_RE.items():
            m = pattern.search(auth)
            if m and m.group(1).lower() in ("fail", "softfail", "none", "permerror"):
                weight = Weight.HIGH if mech == "dmarc" else Weight.MEDIUM
                findings.append(Finding(
                    self.name, f"{mech.upper()} authentication {m.group(1).lower()}", weight,
                    detail=f"{mech.upper()} check returned '{m.group(1)}'.",
                    evidence=[auth[:200]],
                ))

        return findings
