"""Terminal report renderer."""

from io import StringIO

from rich.console import Console

from repoproof.domain import AuditReport, FindingStatus

_STATUS_STYLES = {
    FindingStatus.FAIL: "bold red",
    FindingStatus.WARN: "bold yellow",
    FindingStatus.SKIP: "cyan",
    FindingStatus.PASS: "green",
}


def render_console(report: AuditReport, *, color: bool, verbose: bool) -> str:
    """Render report findings, omitting passing findings unless verbose."""
    output = StringIO()
    console = Console(
        file=output,
        force_terminal=color,
        color_system="standard" if color else None,
        highlight=False,
    )
    visible = report.findings if verbose else (
        item for item in report.findings if item.status is not FindingStatus.PASS
    )
    for item in visible:
        console.print(
            f"[{item.status.value}] {item.rule_id}: {item.message}",
            markup=False,
            style=_STATUS_STYLES[item.status] if color else "",
        )
        console.print(f"  fix: {item.remediation}", markup=False)
    if report.manual_checks:
        console.print("Manual review:", markup=False)
        for check in report.manual_checks:
            console.print(f"  - {check}", markup=False)
    console.print(f"exit: {int(report.exit_code)}", markup=False)
    return output.getvalue()
