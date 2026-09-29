#!/usr/bin/env python3
"""
main.py - CLI for the AI-Assisted Phishing Email & Header Analyzer.

Examples
--------
    python main.py sample_phish.eml                 # analyse an .eml file
    python main.py headers.txt -o case_1042.md      # raw header text file
    cat headers.txt | python main.py -              # read from stdin
    python main.py --text "$(cat headers.txt)"      # inline raw text
    python main.py sample_phish.eml --no-ai         # offline heuristics only
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ai_analyzer import AIAnalysisError, analyze_email, build_offline_report
from parser import EmailParseError, parse_email

SEVERITY_STYLE = {"Low": "green", "Medium": "yellow", "High": "dark_orange", "Critical": "bold red"}
AUTH_STYLE = {"pass": "green", "fail": "bold red", "softfail": "yellow", "none": "yellow",
              "neutral": "yellow", "not_found": "dim"}


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AI-assisted phishing e-mail & header analyzer (SOC L1 triage).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("input", nargs="?", help="Path to an .eml / raw-header file, or '-' for stdin.")
    source.add_argument("-t", "--text", help="Raw e-mail or header text passed inline.")
    parser.add_argument("-o", "--output", default="report.md", help="Markdown report path (default: report.md).")
    parser.add_argument("--model", default=None, help="Override the Gemini model (default: gemini-2.5-flash).")
    parser.add_argument("--no-ai", action="store_true", help="Skip Gemini; use the offline heuristics only.")
    return parser.parse_args(argv)


def read_input(args: argparse.Namespace) -> tuple[bytes | str, str]:
    """Return (raw_content, human_readable_source_name)."""
    if args.text:
        return args.text, "inline text"
    if args.input in (None, "-"):
        if args.input is None and sys.stdin.isatty():
            raise EmailParseError("No input given. Provide a file path, '-' for stdin, or --text.")
        return sys.stdin.read(), "stdin"
    path = Path(args.input)
    if not path.is_file():
        raise EmailParseError(f"File not found: {path}")
    return path.read_bytes(), path.name


# --------------------------------------------------------------------------- #
# Terminal rendering (rich)
# --------------------------------------------------------------------------- #
def _t(value: Any, style: str = "") -> Text:
    """Build a Text cell so e-mail-derived content is never parsed as rich markup."""
    return Text(str(value) if value not in (None, "") else "-", style=style, overflow="fold")


def render_terminal(console: Console, source: str, parsed: dict[str, Any], report: dict[str, Any]) -> None:
    h, a, n = parsed["headers"], parsed["authentication"], parsed["network"]
    severity = report["severity"]
    style = SEVERITY_STYLE.get(severity, "white")
    meta = report["meta"]

    banner = Text.assemble(
        ("PHISHING RISK SCORE  ", "bold"),
        (f"{report['risk_score']}/100", style),
        ("   Severity: ", "bold"),
        (severity.upper(), style),
    )
    banner.append(f"\n{report['score_rationale']}", style="italic")
    console.print(Panel(banner, title="L1 SOC Phishing Triage Report",
                        subtitle=f"{source} | mode: {meta['mode']} ({meta['model']})", border_style=style))

    overview = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    overview.add_column(style="bold cyan", no_wrap=True)
    overview.add_column(overflow="fold")
    for label, value in (
        ("Subject", h["subject"]), ("From", h["from_raw"]), ("Reply-To", h["reply_to"]),
        ("Return-Path", h["return_path"]), ("To", h["to"]), ("Date", h["date"]),
        ("Message-ID", h["message_id"]), ("X-Mailer", h["x_mailer"]),
        ("Originating IP", n["originating_ip"]), ("Connecting IP", n["connecting_ip"]),
    ):
        overview.add_row(label, _t(value))
    console.print(Panel(overview, title="Email Overview", border_style="cyan"))

    auth = Table(box=box.SIMPLE_HEAD)
    for column in ("SPF", "DKIM", "DMARC"):
        auth.add_column(column, justify="center")
    auth.add_row(*(_t(a[m].upper(), AUTH_STYLE.get(a[m], "white")) for m in ("spf", "dkim", "dmarc")))
    console.print(Panel(auth, title="Authentication", border_style="cyan"))

    indicators = Table(box=box.SIMPLE_HEAD, show_lines=False)
    indicators.add_column("#", justify="right", no_wrap=True)
    indicators.add_column("Category", style="magenta")
    indicators.add_column("Indicator", ratio=3, overflow="fold")
    indicators.add_column("Evidence", ratio=2, overflow="fold", style="dim")
    for i, item in enumerate(report["suspicious_indicators"], 1):
        indicators.add_row(str(i), _t(item["category"]), _t(item["indicator"]), _t(item["evidence"]))
    if not report["suspicious_indicators"]:
        indicators.add_row("-", "-", "No suspicious indicators identified.", "-")
    console.print(Panel(indicators, title="Key Suspicious Indicators", border_style="red"))

    if parsed["urls"] or parsed["attachments"]:
        artifacts = Table(box=box.SIMPLE_HEAD)
        artifacts.add_column("Type", no_wrap=True)
        artifacts.add_column("Artifact (defanged)", overflow="fold", ratio=3)
        artifacts.add_column("Flags", overflow="fold", ratio=2, style="yellow")
        for url in parsed["urls"]:
            artifacts.add_row("URL", _t(url["defanged"]), _t(", ".join(url["flags"])))
        for att in parsed["attachments"]:
            artifacts.add_row("FILE", _t(f"{att['filename']}  sha256={att['sha256']}"), _t(", ".join(att["flags"])))
        console.print(Panel(artifacts, title="Extracted Artifacts (IOCs)", border_style="yellow"))

    mitre = Table(box=box.SIMPLE_HEAD)
    mitre.add_column("Technique", style="bold", no_wrap=True)
    mitre.add_column("Name", overflow="fold")
    mitre.add_column("Justification", overflow="fold", ratio=2)
    for tech in report["mitre_mapping"]:
        mitre.add_row(_t(tech["technique_id"]), _t(tech["technique_name"]), _t(tech["justification"]))
    if not report["mitre_mapping"]:
        mitre.add_row("-", "No ATT&CK technique supported by the evidence.", "-")
    console.print(Panel(mitre, title="MITRE ATT&CK Mapping", border_style="blue"))

    steps = Text()
    for i, step in enumerate(report["analyst_checklist"], 1):
        steps.append(f"[ ] {i}. ", style="bold green")
        steps.append(step + "\n")
    console.print(Panel(steps, title="L1 Analyst Action Checklist", border_style="green"))


# --------------------------------------------------------------------------- #
# Markdown report
# --------------------------------------------------------------------------- #
def _code(value: Any) -> str:
    """Inline-code a value safely for Markdown (and for GFM table cells)."""
    text = str(value) if value not in (None, "") else "-"
    text = text.replace("`", "'").replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    return f"`{text}`" if text != "-" else "-"


def _cell(value: Any) -> str:
    """Escape plain text for a Markdown table cell."""
    text = str(value) if value not in (None, "") else "-"
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def build_markdown(source: str, parsed: dict[str, Any], report: dict[str, Any]) -> str:
    h, a, n = parsed["headers"], parsed["authentication"], parsed["network"]
    meta = report["meta"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    out: list[str] = []

    out += [
        "# Phishing Triage Report", "",
        "| Field | Value |", "|---|---|",
        f"| Generated | {now} |",
        f"| Source | {_code(source)} |",
        f"| Analysis mode | {meta['mode']} ({meta['model']}) |", "",
        "## 1. Phishing Risk Score", "",
        f"**{report['risk_score']} / 100 - {report['severity'].upper()}**", "",
        f"> {_cell(report['score_rationale'])}", "",
        "## 2. Key Suspicious Indicators", "",
    ]
    if report["suspicious_indicators"]:
        out += ["| # | Category | Indicator | Evidence |", "|---|---|---|---|"]
        for i, item in enumerate(report["suspicious_indicators"], 1):
            out.append(f"| {i} | {_cell(item['category'])} | {_cell(item['indicator'])} | {_code(item['evidence'])} |")
    else:
        out.append("_No suspicious indicators identified._")

    out += ["", "## 3. MITRE ATT&CK Mapping", ""]
    if report["mitre_mapping"]:
        out += ["| Technique | Name | Justification |", "|---|---|---|"]
        for t in report["mitre_mapping"]:
            out.append(f"| {_code(t['technique_id'])} | {_cell(t['technique_name'])} | {_cell(t['justification'])} |")
    else:
        out.append("_No ATT&CK technique is supported by the evidence._")

    out += ["", "## 4. L1 Analyst Action Checklist", ""]
    out += [f"- [ ] **Step {i}:** {_cell(step)}" for i, step in enumerate(report["analyst_checklist"], 1)]

    out += [
        "", "---", "", "## Appendix A - Extracted Metadata", "",
        "### Headers", "", "| Header | Value |", "|---|---|",
        f"| Subject | {_code(h['subject'])} |",
        f"| From | {_code(h['from_raw'])} |",
        f"| Reply-To | {_code(h['reply_to'])} |",
        f"| Return-Path | {_code(h['return_path'])} |",
        f"| To | {_code(h['to'])} |",
        f"| Date | {_code(h['date'])} |",
        f"| Message-ID | {_code(h['message_id'])} |",
        f"| X-Mailer | {_code(h['x_mailer'])} |", "",
        "### Authentication", "", "| SPF | DKIM | DMARC |", "|---|---|---|",
        f"| {a['spf']} | {a['dkim']} | {a['dmarc']} |", "",
        "### Network", "",
        f"- Originating IP (earliest external hop, lower trust): {_code(n['originating_ip'])}",
        f"- Connecting IP (recorded by our MX, higher trust): {_code(n['connecting_ip'])}",
        f"- Received hops: {n['hop_count']}", "",
        "### URLs (defanged)", "",
    ]
    if parsed["urls"]:
        out += ["| URL | Source | Flags |", "|---|---|---|"]
        for u in parsed["urls"]:
            out.append(f"| {_code(u['defanged'])} | {u['source']} | {_cell(', '.join(u['flags']))} |")
    else:
        out.append("_None found._")

    out += ["", "### Attachments", ""]
    if parsed["attachments"]:
        out += ["| File | Type | Size (B) | SHA-256 | Flags |", "|---|---|---|---|---|"]
        for att in parsed["attachments"]:
            out.append(f"| {_code(att['filename'])} | {_cell(att['content_type'])} | {att['size_bytes']} | "
                       f"{_code(att['sha256'])} | {_cell(', '.join(att['flags']))} |")
    else:
        out.append("_None found._")

    out += ["", "### Automated Heuristic Findings", "",
            f"Local rules-engine pre-score: **{parsed['heuristics']['score']} / 100**", ""]
    if parsed["heuristics"]["findings"]:
        out += ["| Rule | Weight | Description |", "|---|---|---|"]
        for f in parsed["heuristics"]["findings"]:
            out.append(f"| {f['id']} | +{f['weight']} | {_cell(f['description'])} |")
    else:
        out.append("_No rules triggered._")

    out += ["", "---", "",
            "_AI-assisted triage output. It supports, but does not replace, analyst judgement - "
            "validate indicators before taking containment action._", ""]
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    load_dotenv()  # reads GEMINI_API_KEY from .env if present
    args = parse_args(argv)
    console = Console()
    err = Console(stderr=True)

    try:
        raw, source = read_input(args)
        parsed = parse_email(raw)
    except (EmailParseError, OSError) as exc:
        err.print(Text.assemble(("Input error: ", "bold red"), str(exc)))
        return 1

    if args.no_ai:
        report = build_offline_report(parsed, reason="AI disabled with --no-ai")
    else:
        try:
            with console.status("[bold cyan]Analysing with Gemini...", spinner="dots"):
                report = analyze_email(parsed, model=args.model)
        except AIAnalysisError as exc:
            err.print(Text(f"AI analysis unavailable: {exc}", style="yellow"))
            err.print(Text("Falling back to offline heuristics.\n", style="yellow"))
            report = build_offline_report(parsed, reason="AI analysis unavailable")

    render_terminal(console, source, parsed, report)

    try:
        Path(args.output).write_text(build_markdown(source, parsed, report), encoding="utf-8")
    except OSError as exc:
        err.print(Text.assemble(("Could not write report: ", "bold red"), str(exc)))
        return 1
    console.print(f"\n[bold green]Report saved to[/bold green] {args.output}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
