"""Load and normalise an .eml message."""

from __future__ import annotations

from dataclasses import dataclass, field
from email import message_from_bytes
from email.message import EmailMessage
from email.policy import default as default_policy
from email.utils import parseaddr
from typing import List, Optional, Tuple

from .models import EmailMeta


@dataclass
class ParsedEmail:
    message: EmailMessage
    meta: EmailMeta
    text_body: str = ""
    html_body: str = ""
    attachments: List[Tuple[str, str]] = field(default_factory=list)  # (filename, content_type)

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

    for part in msg.walk():
        if part.is_multipart():
            continue
        disp = (part.get_content_disposition() or "").lower()
        ctype = part.get_content_type()
        filename = part.get_filename()
        if disp == "attachment" or filename:
            attachments.append((filename or "(unnamed)", ctype))
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
    )


def load_email_file(path: str) -> ParsedEmail:
    with open(path, "rb") as fh:
        return load_email(fh.read(), source=path)
