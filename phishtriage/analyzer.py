"""Runs all checks over a parsed email and builds a report."""

from __future__ import annotations

from typing import Sequence

from .checks import default_checks
from .checks.base import BaseCheck
from .models import Report
from .parser import ParsedEmail, load_email, load_email_file


class Analyzer:
    def __init__(self, checks: Sequence[BaseCheck] = None):
        self.checks = list(checks) if checks is not None else default_checks()

    def analyze(self, email: ParsedEmail) -> Report:
        report = Report(source=email.meta.from_header or "<unknown>", meta=email.meta)
        for check in self.checks:
            report.findings.extend(check.run(email))
        report.findings.sort(key=lambda f: f.weight, reverse=True)
        return report

    def analyze_bytes(self, data: bytes, source: str = "<stdin>") -> Report:
        parsed = load_email(data, source=source)
        report = self.analyze(parsed)
        report.source = source
        return report

    def analyze_file(self, path: str) -> Report:
        parsed = load_email_file(path)
        report = self.analyze(parsed)
        report.source = path
        return report
