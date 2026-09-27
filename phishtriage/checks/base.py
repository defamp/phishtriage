"""Base class for phishing checks."""

from __future__ import annotations

from typing import List

from ..models import Finding
from ..parser import ParsedEmail


class BaseCheck:
    """A check inspects a parsed email and returns zero or more findings."""

    name = "base"

    def run(self, email: ParsedEmail) -> List[Finding]:
        raise NotImplementedError
