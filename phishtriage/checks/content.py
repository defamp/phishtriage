"""Social-engineering content checks."""

from __future__ import annotations

import re
from typing import List

from ..models import Finding, Weight
from ..parser import ParsedEmail
from .base import BaseCheck

_URGENCY = [
    "urgent", "immediately", "action required", "within 24 hours", "act now",
    "final notice", "account suspended", "suspended", "limited", "expire",
    "verify your account", "confirm your account", "unusual activity",
    "unauthorized", "your password", "reset your password", "update your payment",
    "click here", "log in to", "sign in to verify",
]
_GENERIC_GREETINGS = ["dear customer", "dear user", "dear account holder", "dear valued customer"]


class ContentCheck(BaseCheck):
    name = "content"

    def run(self, email: ParsedEmail) -> List[Finding]:
        findings: List[Finding] = []
        body = (email.text_body + " " + re.sub(r"<[^>]+>", " ", email.html_body)).lower()
        subject = (email.meta.subject or "").lower()
        haystack = subject + " " + body

        hits = sorted({kw for kw in _URGENCY if kw in haystack})
        if len(hits) >= 2:
            findings.append(Finding(
                self.name, "Urgency / credential-harvesting language", Weight.MEDIUM,
                detail=f"{len(hits)} social-engineering phrases found.",
                evidence=hits[:6]))
        elif hits:
            findings.append(Finding(
                self.name, "Urgency language", Weight.LOW,
                detail="Contains pressure/credential phrasing.",
                evidence=hits[:4]))

        for greeting in _GENERIC_GREETINGS:
            if greeting in haystack:
                findings.append(Finding(
                    self.name, "Generic greeting", Weight.LOW,
                    detail="Impersonal greeting typical of mass phishing.",
                    evidence=[greeting]))
                break

        return findings
