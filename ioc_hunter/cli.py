"""Command-line interface for IOC Hunter."""

from __future__ import annotations

import argparse
import sys
from typing import List

from dotenv import load_dotenv
from rich.console import Console

from . import __version__
from .enrich import Enricher, build_providers
from .report import print_reports, print_summary_table, to_html, to_json
from .utils import parse_iocs


def _collect_iocs(args) -> List[str]:
    raw: List[str] = list(args.iocs)
    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            raw.extend(fh.readlines())
    if not sys.stdin.isatty() and not raw:
        raw.extend(sys.stdin.read().splitlines())
    return parse_iocs(raw)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ioc-hunter",
        description="Enrich IOCs (IP/domain/URL/hash) via VirusTotal, AbuseIPDB and AlienVault OTX.",
        epilog="API keys are read from env vars or a .env file (see .env.example).",
    )
    parser.add_argument("iocs", nargs="*", help="one or more indicators to check")
    parser.add_argument("-f", "--file", help="read indicators from a file (one per line, # comments ok)")
    parser.add_argument("--providers", help="comma-separated subset: virustotal,abuseipdb,otx")
    parser.add_argument("--demo", action="store_true", help="offline demo mode (no API keys needed)")
    parser.add_argument("--summary", action="store_true", help="print compact summary table only")
    parser.add_argument("--json", action="store_true",
                        help="output JSON to stdout (redirect to a file to save)")
    parser.add_argument("--html", dest="html_out", metavar="PATH", help="write an HTML report to PATH")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    parser.add_argument("-V", "--version", action="version", version=f"ioc-hunter {__version__}")
    return parser


def main(argv=None) -> int:
    load_dotenv()
    args = build_parser().parse_args(argv)
    console = Console(no_color=args.no_color)
    err = Console(stderr=True, no_color=args.no_color)

    iocs = _collect_iocs(args)
    if not iocs:
        err.print("[red]No indicators provided.[/] Pass IOCs as arguments, --file, or via stdin.")
        return 2

    selected = [p.strip() for p in args.providers.split(",")] if args.providers else None
    providers = build_providers(selected=selected, demo=args.demo)
    enricher = Enricher(providers)

    if not args.demo and not enricher.active_providers:
        err.print(
            "[yellow]Warning:[/] no API keys configured — every provider will be skipped.\n"
            "Set VT_API_KEY / ABUSEIPDB_API_KEY / OTX_API_KEY (see .env.example), "
            "or run with [bold]--demo[/] to try it offline."
        )

    reports = enricher.enrich_many(iocs)

    # JSON is machine output; keep stdout clean so it can be piped/redirected.
    if args.json:
        print(to_json(reports))
    elif args.summary:
        print_summary_table(reports, console)
    else:
        print_reports(reports, console)

    if args.html_out:
        with open(args.html_out, "w", encoding="utf-8") as fh:
            fh.write(to_html(reports))
        console.print(f"[green]HTML report written:[/] {args.html_out}")

    # Exit code 1 if anything malicious was found (handy for automation/CI).
    malicious = any(r.verdict.value == "malicious" for r in reports)
    return 1 if malicious else 0


if __name__ == "__main__":
    sys.exit(main())
