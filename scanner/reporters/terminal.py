"""
Terminal reporter — color-coded console output using rich.
"""

import sys

from scanner.models import ScanResult, Severity


SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

_UNICODE = (sys.stdout.encoding or "").lower().startswith("utf")
SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}
if not _UNICODE:
    SEVERITY_ICONS = {severity: "*" for severity in SEVERITY_ICONS}


def print_terminal_report(result: ScanResult):
    if not _UNICODE:
        _plain_report(result)
        return
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text
        console = Console()
        _rich_report(console, result, Table, Panel, Text)
    except ImportError:
        _plain_report(result)


def _rich_report(console, result, Table, Panel, Text):
    summary = result.summary

    console.print()
    console.print(Panel(
        f"[bold]AI Infrastructure Security Scan Report[/bold]\n"
        f"Repository: {summary['repo']}\n"
        f"Branch: {summary['branch']}\n"
        f"Files Scanned: {summary['files_scanned']}\n"
        f"Modules: {', '.join(summary['modules_run'])}\n"
        f"Duration: {summary['scan_duration_seconds']}s",
        title=("🔍 " if _UNICODE else "") + "Theron",
        border_style="cyan",
    ))

    by_sev = summary["by_severity"]
    console.print(f"\n[bold]Findings: {summary['total_findings']}[/bold]")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        count = by_sev.get(sev.value, 0)
        if count:
            color = SEVERITY_COLORS[sev]
            console.print(f"  {SEVERITY_ICONS[sev]} [{color}]{sev.value}: {count}[/{color}]")

    if not result.findings:
        console.print("\n[green]" + ("✅ " if _UNICODE else "") + "No security findings detected![/green]")
        return

    console.print("\n[bold]Findings:[/bold]\n")
    table = Table(show_header=True, header_style="bold cyan", show_lines=True, expand=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Category", width=18)
    table.add_column("Title", ratio=3)
    table.add_column("File", ratio=2)
    table.add_column("Line", width=5)

    for i, finding in enumerate(result.findings, 1):
        table.add_row(
            str(i),
            Text(f"{SEVERITY_ICONS.get(finding.severity, '⚪')} {finding.severity.value}",
                 style=SEVERITY_COLORS.get(finding.severity, "dim")),
            finding.category.value,
            finding.title,
            finding.file_path,
            str(finding.line_number or "-"),
        )
    console.print(table)

    console.print("\n[bold]Details:[/bold]\n")
    for i, finding in enumerate(result.findings, 1):
        color = SEVERITY_COLORS.get(finding.severity, "dim").replace("bold ", "")
        console.print(Panel(
            f"[{SEVERITY_COLORS.get(finding.severity, 'dim')}]{SEVERITY_ICONS.get(finding.severity, '⚪')} {finding.severity.value}[/{SEVERITY_COLORS.get(finding.severity, 'dim')}] — {finding.title}\n\n"
            f"[dim]Category:[/dim] {finding.category.value}\n"
            f"[dim]Module:[/dim] {finding.module}\n"
            f"[dim]File:[/dim] {finding.file_path}:{finding.line_number or 'N/A'}\n"
            f"[dim]CWE:[/dim] {finding.cwe or 'N/A'}\n"
            f"[dim]Confidence:[/dim] {finding.confidence}\n"
            f"[dim]Rule ID:[/dim] {finding.rule_id or 'N/A'}\n\n"
            f"[dim]Status:[/dim] {finding.status}  [dim]Fingerprint:[/dim] {finding.fingerprint or 'N/A'}\n\n"
            f"{finding.description}\n\n"
            f"[green]Recommendation:[/green] {finding.recommendation or 'N/A'}"
            + (f"\n\n[dim]Code:[/dim]\n```{finding.code_snippet}```" if finding.code_snippet else ""),
            title=f"#{i}",
            border_style=color,
        ))


def _plain_report(result: ScanResult):
    encoding = sys.stdout.encoding or "ascii"

    def out(value):
        print(str(value).encode(encoding, errors="replace").decode(encoding))

    summary = result.summary
    out(f"\n{'='*60}")
    out("AI Infrastructure Security Scan Report")
    out(f"{'='*60}")
    out(f"Repository: {summary['repo']}")
    out(f"Branch: {summary['branch']}")
    out(f"Files Scanned: {summary['files_scanned']}")
    out(f"Modules: {', '.join(summary['modules_run'])}")
    out(f"Duration: {summary['scan_duration_seconds']}s")
    out(f"Total Findings: {summary['total_findings']}")

    by_sev = summary["by_severity"]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = by_sev.get(sev, 0)
        if count:
            out(f"  {sev}: {count}")

    if not result.findings:
        out("\n" + ("✅ " if _UNICODE else "") + "No security findings detected!")
        return

    out(f"\n{'-'*60}")
    for i, finding in enumerate(result.findings, 1):
        out(f"\n#{i} [{finding.severity.value}] {finding.title}")
        out(f"  Category: {finding.category.value}")
        out(f"  File: {finding.file_path}:{finding.line_number or 'N/A'}")
        out(f"  CWE: {finding.cwe or 'N/A'}")
        out(f"  Status: {finding.status} ({finding.fingerprint or 'N/A'})")
        out(f"  Description: {finding.description}")
        out(f"  Recommendation: {finding.recommendation or 'N/A'}")
        if finding.code_snippet:
            out(f"  Code:\n    {finding.code_snippet.replace(chr(10), chr(10) + '    ')}")
    out(f"\n{'='*60}")
