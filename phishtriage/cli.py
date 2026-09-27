"""Command-line interface for PhishTriage."""

from __future__ import annotations

import argparse
import sys
from typing import List

from rich.console import Console

from . import __version__
from .analyzer import Analyzer
from .models import RiskLevel
from .report import print_report, to_html, to_json


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phishtriage",
        description="Triage phishing emails (.eml): score sender spoofing, auth, URLs, "
                    "attachments and content.",
    )
    p.add_argument("emails", nargs="*", help=".eml files to analyze (or pipe one via stdin)")
    p.add_argument("--json", action="store_true", help="JSON output to stdout")
    p.add_argument("--html", metavar="PATH", help="write an HTML report (single email)")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    p.add_argument("-V", "--version", action="version", version=f"phishtriage {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    console = Console(no_color=args.no_color)
    err = Console(stderr=True, no_color=args.no_color)

    analyzer = Analyzer()
    reports = []

    if args.emails:
        for path in args.emails:
            try:
                reports.append(analyzer.analyze_file(path))
            except FileNotFoundError:
                err.print(f"[red]File not found:[/] {path}")
            except Exception as exc:  # pragma: no cover
                err.print(f"[red]Failed to parse {path}:[/] {exc}")
    elif not sys.stdin.isatty():
        data = sys.stdin.buffer.read()
        if data.strip():
            reports.append(analyzer.analyze_bytes(data, source="<stdin>"))

    if not reports:
        err.print("[red]No email provided.[/] Pass one or more .eml files, or pipe one via stdin.")
        return 2

    if args.json:
        if len(reports) == 1:
            print(to_json(reports[0]))
        else:
            import json
            print(json.dumps([r.to_dict() for r in reports], indent=2))
    else:
        for i, report in enumerate(reports):
            if i:
                console.print()
            print_report(report, console)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(to_html(reports[0]))
        console.print(f"[green]HTML report written:[/] {args.html}")

    # Exit 1 if any email is HIGH or CRITICAL risk (handy for mail-gateway automation).
    risky = any(r.verdict.level >= RiskLevel.HIGH.level for r in reports)
    return 1 if risky else 0


if __name__ == "__main__":
    sys.exit(main())
