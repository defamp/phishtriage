"""Shared helpers for domain / URL handling."""

from __future__ import annotations

import re
from urllib.parse import urlparse

# Deliberately small; a real deployment would use the Public Suffix List.
_TWO_LEVEL_TLDS = {"co.uk", "co.id", "com.au", "co.jp", "com.br", "co.nz", "go.id"}

URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def hostname(url_or_host: str) -> str:
    """Extract a lowercase hostname from a URL or bare host."""
    value = url_or_host.strip()
    if "://" in value:
        value = urlparse(value).hostname or ""
    else:
        value = value.split("/")[0]
    return value.lower().strip(".")


def registered_domain(host: str) -> str:
    """Best-effort registrable domain (e.g. mail.google.com -> google.com)."""
    host = hostname(host)
    if not host or IPV4_RE.match(host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last_two = ".".join(parts[-2:])
    if last_two in _TWO_LEVEL_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def domain_of_addr(addr: str) -> str:
    """Domain portion of an email address."""
    if not addr or "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].lower().strip(">").strip()


def is_ip_host(url_or_host: str) -> bool:
    return bool(IPV4_RE.match(hostname(url_or_host)))
