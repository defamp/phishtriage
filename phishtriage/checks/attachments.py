"""Attachment risk checks."""

from __future__ import annotations

from typing import List

from ..models import Finding, Weight
from ..parser import ParsedEmail
from .base import BaseCheck

# Extensions that can execute code or are common malware carriers.
_DANGEROUS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe",
    "wsf", "hta", "jar", "ps1", "msi", "lnk", "iso", "img",
}
_MACRO_DOCS = {"docm", "xlsm", "pptm", "dotm", "xlsb"}
_ARCHIVES = {"zip", "rar", "7z", "gz", "cab"}


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


class AttachmentCheck(BaseCheck):
    name = "attachments"

    def run(self, email: ParsedEmail) -> List[Finding]:
        findings: List[Finding] = []
        for filename, ctype in email.attachments:
            ext = _ext(filename)
            parts = filename.lower().split(".")

            if ext in _DANGEROUS:
                findings.append(Finding(
                    self.name, "Executable attachment", Weight.HIGH,
                    detail=f"'{filename}' has a dangerous extension (.{ext}).",
                    evidence=[f"{filename} [{ctype}]"]))
            elif ext in _MACRO_DOCS:
                findings.append(Finding(
                    self.name, "Macro-enabled document", Weight.HIGH,
                    detail=f"'{filename}' can contain malicious macros.",
                    evidence=[f"{filename} [{ctype}]"]))
            elif ext == "html" or ctype == "text/html":
                findings.append(Finding(
                    self.name, "HTML attachment", Weight.MEDIUM,
                    detail=f"'{filename}' — HTML attachments often host credential-phishing pages.",
                    evidence=[f"{filename} [{ctype}]"]))
            elif ext in _ARCHIVES:
                findings.append(Finding(
                    self.name, "Archive attachment", Weight.LOW,
                    detail=f"'{filename}' — archives can smuggle executables past filters.",
                    evidence=[f"{filename} [{ctype}]"]))

            # Double extension, e.g. invoice.pdf.exe
            if len(parts) >= 3 and parts[-1] in _DANGEROUS and parts[-2] in {
                "pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"
            }:
                findings.append(Finding(
                    self.name, "Double extension", Weight.HIGH,
                    detail=f"'{filename}' disguises an executable as a document.",
                    evidence=[filename]))

        return findings
