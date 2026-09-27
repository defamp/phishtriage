"""Console / JSON / HTML rendering for PhishTriage."""

from __future__ import annotations

import html
import json
from datetime import datetime
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import Report, RiskLevel

_RISK_STYLE = {
    RiskLevel.LOW: "bold green",
    RiskLevel.MEDIUM: "bold yellow",
    RiskLevel.HIGH: "bold red",
    RiskLevel.CRITICAL: "bold white on red",
}


def _weight_style(weight: int) -> str:
    if weight >= 5:
        return "red"
    if weight >= 3:
        return "yellow"
    if weight >= 1:
        return "cyan"
    return "dim"


def print_report(report: Report, console: Console) -> None:
    m = report.meta
    header = Table.grid(padding=(0, 1))
    header.add_column(style="bold", justify="right")
    header.add_column()
    header.add_row("From:", m.from_header or "-")
    header.add_row("Subject:", m.subject or "-")
    if m.reply_to:
        header.add_row("Reply-To:", m.reply_to)
    header.add_row("Date:", m.date or "-")
    console.print(Panel(header, title="Email", title_align="left", border_style="cyan"))

    if report.findings:
        table = Table(title="Phishing Indicators", header_style="bold cyan", expand=True)
        table.add_column("Pts", justify="center")
        table.add_column("Check", justify="center")
        table.add_column("Indicator")
        table.add_column("Detail", overflow="fold")
        for f in report.findings:
            table.add_row(Text(str(f.weight), style=_weight_style(f.weight)),
                          f.check, f.title, f.detail)
        console.print(table)
    else:
        console.print("[green]No phishing indicators found.[/]")

    verdict = report.verdict
    line = Text.assemble(
        ("  VERDICT: ", "bold"),
        (f" {verdict.value.upper()} ", _RISK_STYLE[verdict]),
        (f"   risk score: {report.score}", "dim"),
    )
    console.print(Panel(line, border_style=_RISK_STYLE[verdict].split()[-1]))


def to_json(report: Report) -> str:
    payload = dict(report.to_dict())
    payload["generated_at"] = datetime.now().isoformat(timespec="seconds")
    return json.dumps(payload, indent=2)


_HTML_COLOR = {
    RiskLevel.LOW: "#34d399", RiskLevel.MEDIUM: "#fbbf24",
    RiskLevel.HIGH: "#f87171", RiskLevel.CRITICAL: "#dc2626",
}


def to_html(report: Report) -> str:
    color = _HTML_COLOR[report.verdict]
    rows = "".join(
        "<tr><td class='pts' style='color:{pc}'>{w}</td><td>{chk}</td>"
        "<td class='ind'>{title}</td><td class='det'>{detail}</td></tr>".format(
            pc=("#f87171" if f.weight >= 5 else "#fbbf24" if f.weight >= 3 else "#22d3ee"),
            w=f.weight, chk=html.escape(f.check), title=html.escape(f.title),
            detail=html.escape(f.detail),
        )
        for f in report.findings
    ) or "<tr><td colspan='4'>No indicators found.</td></tr>"
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return _HTML_TEMPLATE.format(
        color=color, verdict=html.escape(report.verdict.value.upper()), score=report.score,
        frm=html.escape(report.meta.from_header or "-"),
        subject=html.escape(report.meta.subject or "-"),
        rows=rows, generated=generated,
    )


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishTriage Report</title>
<style>
  body{{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#0a0e1a;color:#e6edf7;margin:0;padding:32px}}
  h1{{margin:0 0 4px}} .top{{color:#94a3b8;font-size:.85rem;margin-bottom:20px}}
  .verdict{{display:inline-block;padding:8px 16px;border-radius:8px;font-weight:800;
           color:#04121a;background:{color};margin-bottom:20px}}
  .meta{{background:#151c2e;border:1px solid #243049;border-radius:10px;padding:14px 18px;margin-bottom:18px;font-size:.9rem}}
  .meta b{{color:#cbd5e1}}
  table{{width:100%;border-collapse:collapse;background:#151c2e;border:1px solid #243049;border-radius:10px;overflow:hidden}}
  th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #1c2438;font-size:.88rem;vertical-align:top}}
  th{{background:#0f1626;color:#22d3ee;text-transform:uppercase;font-size:.72rem;letter-spacing:.5px}}
  .pts{{font-weight:700;text-align:center}} .ind{{font-weight:600}} .det{{color:#94a3b8}}
</style></head><body>
<h1>🎣 PhishTriage Report</h1>
<div class="top">Generated {generated}</div>
<div class="verdict">{verdict} &middot; risk score {score}</div>
<div class="meta"><b>From:</b> {frm}<br><b>Subject:</b> {subject}</div>
<table><thead><tr><th>Pts</th><th>Check</th><th>Indicator</th><th>Detail</th></tr></thead>
<tbody>{rows}</tbody></table>
</body></html>
"""
