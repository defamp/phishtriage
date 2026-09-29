"""Load and normalise an .eml message."""

from __future__ import annotations

from dataclasses import dataclass, field
from email import message_from_bytes
from email.message import EmailMessage
from email.policy import default as default_policy
from email.utils import parseaddr
from typing import List, Optional, Tuple

from .models import EmailMeta

# Zip attachments up to this size are kept for a (listing-only) look inside.
MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
_ZIP_TYPES = {"application/zip", "application/x-zip-compressed", "application/x-zip"}


@dataclass
class ParsedEmail:
    message: EmailMessage
    meta: EmailMeta
    text_body: str = ""
    html_body: str = ""
    attachments: List[Tuple[str, str]] = field(default_factory=list)  # (filename, content_type)
    archives: List[Tuple[str, bytes]] = field(default_factory=list)  # (filename, zip bytes)

    @property
    def all_headers(self):
        return self.message.items()


def _addr(value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Return (display_name, email_address) from a header value."""
    if not value:
        return None, None
    name, addr = parseaddr(value)
    return (name or None), (addr or None)


def load_email(data: bytes, source: str = "<stdin>") -> ParsedEmail:
    msg: EmailMessage = message_from_bytes(data, policy=default_policy)

    from_name, from_addr = _addr(msg.get("From"))
    _, reply_to = _addr(msg.get("Reply-To"))
    _, return_path = _addr(msg.get("Return-Path"))

    meta = EmailMeta(
        from_header=msg.get("From"),
        from_addr=from_addr,
        from_name=from_name,
        reply_to=reply_to,
        return_path=return_path,
        subject=msg.get("Subject"),
        date=msg.get("Date"),
        to=msg.get("To"),
    )

    text_body, html_body = "", ""
    attachments: List[Tuple[str, str]] = []
    archives: List[Tuple[str, bytes]] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        disp = (part.get_content_disposition() or "").lower()
        ctype = part.get_content_type()
        filename = part.get_filename()
        if disp == "attachment" or filename:
            name = filename or "(unnamed)"
            attachments.append((name, ctype))
            if ctype in _ZIP_TYPES or name.lower().endswith(".zip"):
                try:
                    raw = part.get_payload(decode=True)
                except Exception:
                    raw = None
                if isinstance(raw, bytes) and 0 < len(raw) <= MAX_ARCHIVE_BYTES:
                    archives.append((name, raw))
            continue
        try:
            payload = part.get_content()
        except Exception:
            continue
        if not isinstance(payload, str):
            continue
        if ctype == "text/plain":
            text_body += payload
        elif ctype == "text/html":
            html_body += payload

    return ParsedEmail(
        message=msg,
        meta=meta,
        text_body=text_body,
        html_body=html_body,
        attachments=attachments,
        archives=archives,
    )


def load_email_file(path: str) -> ParsedEmail:
    with open(path, "rb") as fh:
        return load_email(fh.read(), source=path)
