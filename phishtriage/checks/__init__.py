"""Phishing checks."""

from .attachments import AttachmentCheck
from .base import BaseCheck
from .content import ContentCheck
from .headers import HeaderCheck
from .urls import URLCheck


def default_checks():
    return [HeaderCheck(), URLCheck(), AttachmentCheck(), ContentCheck()]


__all__ = [
    "BaseCheck", "HeaderCheck", "URLCheck", "AttachmentCheck", "ContentCheck",
    "default_checks",
]
