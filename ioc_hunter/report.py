"""Rendering: console (rich), JSON and standalone HTML report."""

from __future__ import annotations

import html
import json
from datetime import datetime
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import IOCReport, Verdict

_VERDICT_STYLE = {
    Verdict.CLEAN: "bold green",
    Verdict.SUSPICIOUS: "bold yellow",
    Verdict.MALICIOUS: "bold red",
    Verdict.UNKNOWN: "dim",
    Verdict.ERROR: "red",
}
_VERDICT_ICON = {
    Verdict.CLEAN: "✔",
    Verdict.SUSPICIOUS: "?",
    Verdict.MALICIOUS: "⚠",
    Verdict.UNKNOWN: "-",
    Verdict.ERROR: "x",
}


def _verdict_text(verdict: Verdict) -> Text:
    label = f"{_VERDICT_ICON[verdict]} {verdict.value.upper()}"
    return Text(label, style=_VERDICT_STYLE[verdict])


def print_reports(reports: List[IOCReport], console: Console) -> None:
    """Detailed per-indicator output (like a SOC triage note)."""
    for report in reports:
        header = Text.assemble(
            (report.ioc, "bold cyan"),
            ("  ", ""),
            (f"[{report.ioc_type.value}]", "dim"),
        )
        body = Table.grid(padding=(0, 2))
        body.add_column(style="bold")
        body.add_column()
        body.add_column()
        if not report.results:
            empty = report.note or "no supported provider for this indicator"
            body.add_row("", Text(empty, style="dim"), "")
        for r in report.results:
            if r.success:
                detail = r.summary
            else:
                detail = Text(r.error or "failed", style="red")
            body.add_row(r.provider, _verdict_text(r.verdict), detail)

        overall = _verdict_text(report.verdict)
        overall.append(f"   ({report.malicious_sources}/{report.checked_sources} sources malicious)", style="dim")
        panel = Panel(
            body,
            title=header,
            subtitle=overall,
            border_style=_VERDICT_STYLE.get(report.verdict, "dim"),
            title_align="left",
            subtitle_align="left",
        )
        console.print(panel)


def print_summary_table(reports: List[IOCReport], console: Console) -> None:
    """One-line-per-indicator overview table."""
    table = Table(title="IOC Enrichment Summary", header_style="bold cyan", expand=True)
    table.add_column("Indicator", overflow="fold")
    table.add_column("Type", justify="center")
    table.add_column("Verdict", justify="center")
    table.add_column("Sources", justify="center")
    for report in reports:
        table.add_row(
            report.ioc,
            report.ioc_type.value,
            _verdict_text(report.verdict),
            f"{report.malicious_sources}/{report.checked_sources}"
            if not report.note
            else "skipped",
        )
    console.print(table)


def to_json(reports: List[IOCReport]) -> str:
    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "count": len(reports),
        "reports": [r.to_dict() for r in reports],
    }
    return json.dumps(payload, indent=2)


_HTML_VERDICT_COLOR = {
    Verdict.CLEAN: "#34d399",
    Verdict.SUSPICIOUS: "#fbbf24",
    Verdict.MALICIOUS: "#f87171",
    Verdict.UNKNOWN: "#94a3b8",
    Verdict.ERROR: "#f87171",
}


def to_html(reports: List[IOCReport]) -> str:
    """A self-contained dark-themed HTML report."""
    rows = []
    for report in reports:
        color = _HTML_VERDICT_COLOR[report.verdict]
        provider_lines = "".join(
            "<div class='pv'><span class='pn'>{p}</span>"
            "<span class='pv-verdict' style='color:{c}'>{v}</span>"
            "<span class='ps'>{s}</span></div>".format(
                p=html.escape(r.provider),
                c=_HTML_VERDICT_COLOR[r.verdict],
                v=html.escape(r.verdict.value.upper()),
                s=html.escape(r.summary or (r.error or "")),
            )
            for r in report.results
        ) or "<div class='pv'><span class='ps'>{}</span></div>".format(
            html.escape(report.note or "no supported provider")
        )
        rows.append(
            "<div class='card'>"
            "<div class='ioc'>{ioc} <span class='type'>{t}</span></div>"
            "<div class='verdict' style='color:{c}'>{v} &middot; {m}/{n} sources malicious</div>"
            "{lines}</div>".format(
                ioc=html.escape(report.ioc), t=html.escape(report.ioc_type.value),
                c=color, v=html.escape(report.verdict.value.upper()),
                m=report.malicious_sources, n=report.checked_sources, lines=provider_lines,
            )
        )
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return _HTML_TEMPLATE.format(rows="\n".join(rows), generated=generated, count=len(reports))


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IOC Enrichment Report</title>
<style>
  body{{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#0a0e1a;color:#e6edf7;margin:0;padding:32px}}
  h1{{font-size:1.4rem;margin:0 0 4px}}
  .meta{{color:#94a3b8;font-size:.85rem;margin-bottom:24px}}
  .card{{background:#151c2e;border:1px solid #243049;border-radius:12px;padding:18px 20px;margin-bottom:14px}}
  .ioc{{font-family:ui-monospace,monospace;font-size:1.05rem;font-weight:700}}
  .type{{font-size:.72rem;color:#22d3ee;border:1px solid #243049;padding:2px 8px;border-radius:6px;margin-left:8px}}
  .verdict{{font-weight:700;margin:6px 0 12px;font-size:.95rem}}
  .pv{{display:grid;grid-template-columns:150px 110px 1fr;gap:12px;padding:5px 0;border-top:1px solid #1c2438;font-size:.9rem}}
  .pn{{color:#cbd5e1;font-weight:600}} .pv-verdict{{font-weight:700}} .ps{{color:#94a3b8}}
</style></head><body>
<h1>IOC Enrichment Report</h1>
<div class="meta">Generated {generated} &middot; {count} indicator(s) &middot; ioc-hunter</div>
{rows}
</body></html>
"""
