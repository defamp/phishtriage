"""Attachment risk checks."""

from __future__ import annotations

import io
import zipfile
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
_DOC_EXTS = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"}

# Only the archive's directory is read — nothing is decompressed, so zip
# bombs cost nothing. Listing is capped for archives with absurd entry counts.
MAX_ARCHIVE_ENTRIES = 1000


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _is_double_extension(name: str) -> bool:
    parts = name.lower().rsplit("/", 1)[-1].split(".")
    return len(parts) >= 3 and parts[-1] in _DANGEROUS and parts[-2] in _DOC_EXTS


def _archive_findings(check: str, archive_name: str, data: bytes) -> List[Finding]:
    """Findings about what a zip attachment contains, from its listing only."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()[:MAX_ARCHIVE_ENTRIES]
    except (zipfile.BadZipFile, ValueError, OSError):
        return [Finding(
            check, "Unreadable archive", Weight.LOW,
            detail=f"'{archive_name}' is not a valid zip — malformed archives are used to dodge scanners.",
            evidence=[archive_name])]

    findings: List[Finding] = []
    members = [i.filename for i in infos if not i.is_dir()]
    executables = [m for m in members if _ext(m) in _DANGEROUS or _is_double_extension(m)]
    macros = [m for m in members if _ext(m) in _MACRO_DOCS]
    nested = [m for m in members if _ext(m) in _ARCHIVES]
    traversal = [m for m in members if m.startswith("/") or ".." in m.replace("\\", "/").split("/")]
    encrypted = any(i.flag_bits & 0x1 for i in infos)

    if executables:
        findings.append(Finding(
            check, "Executable inside archive", Weight.HIGH,
            detail=f"'{archive_name}' contains {len(executables)} executable file(s).",
            evidence=[f"{archive_name} → {m}" for m in executables[:5]]))
    if macros:
        findings.append(Finding(
            check, "Macro-enabled document inside archive", Weight.HIGH,
            detail=f"'{archive_name}' contains macro-enabled document(s).",
            evidence=[f"{archive_name} → {m}" for m in macros[:5]]))
    if encrypted:
        findings.append(Finding(
            check, "Password-protected archive", Weight.MEDIUM,
            detail=f"'{archive_name}' is encrypted, so mail filters and AV cannot inspect it.",
            evidence=[archive_name]))
    if traversal:
        findings.append(Finding(
            check, "Path traversal in archive", Weight.MEDIUM,
            detail=f"'{archive_name}' has entries that escape the extraction folder (zip-slip).",
            evidence=[f"{archive_name} → {m}" for m in traversal[:5]]))
    if nested:
        findings.append(Finding(
            check, "Nested archive", Weight.LOW,
            detail=f"'{archive_name}' contains another archive (not inspected further).",
            evidence=[f"{archive_name} → {m}" for m in nested[:5]]))
    return findings


class AttachmentCheck(BaseCheck):
    name = "attachments"

    def run(self, email: ParsedEmail) -> List[Finding]:
        findings: List[Finding] = []
        for filename, ctype in email.attachments:
            ext = _ext(filename)

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
            if _is_double_extension(filename):
                findings.append(Finding(
                    self.name, "Double extension", Weight.HIGH,
                    detail=f"'{filename}' disguises an executable as a document.",
                    evidence=[filename]))

        for archive_name, data in email.archives:
            findings.extend(_archive_findings(self.name, archive_name, data))

        return findings
