"""Deterministic terminal renderer for the canonical report payload."""

import json
from io import StringIO
from typing import cast

from rich.console import Console

from repoproof.domain import AuditReport
from repoproof.reporting.model import normalize_console_text, report_to_dict

_STATUS_STYLES = {"FAIL": "bold red", "WARN": "bold yellow", "SKIP": "cyan", "PASS": "green"}
_CONSOLE_WIDTH = 120


def _console_safe(value: object) -> object:
    if isinstance(value, str):
        return normalize_console_text(value)
    if isinstance(value, list):
        return [_console_safe(item) for item in value]
    if isinstance(value, dict):
        return {normalize_console_text(key): _console_safe(item) for key, item in value.items()}
    return value


def _print(console: Console, text: str, *, style: str = "") -> None:
    console.print(text, markup=False, style=style, soft_wrap=True, overflow="ignore")


def render_console(report: AuditReport, *, color: bool, verbose: bool) -> str:
    """Render only the canonical payload, suppressing PASS finding details unless verbose."""
    payload = cast(dict[str, object], _console_safe(report_to_dict(report)))
    output = StringIO()
    console = Console(
        file=output,
        force_terminal=color,
        color_system="standard" if color else None,
        highlight=False,
        width=_CONSOLE_WIDTH,
    )
    repository = cast(dict[str, object], payload["repository"])
    profile = cast(dict[str, object], payload["profile"])
    summary = cast(dict[str, int], payload["summary"])
    _print(
        console,
        f"Repository: {repository['name']}; schema: {payload['report_schema']}; "
        f"tool: {payload['tool_version']}; generated: {payload['generated_at']}",
    )
    _print(
        console,
        f"Profile: {profile['name']}; schema: {profile['schema']}; sha256: {profile['sha256']}",
    )
    _print(
        console,
        "Summary: "
        + " ".join(
            f"{status}={summary[status]}" for status in ("FAIL", "WARN", "SKIP", "PASS")
        ),
    )
    findings = cast(list[dict[str, object]], payload["findings"])
    for item in findings:
        if not verbose and item["status"] == "PASS":
            continue
        status = cast(str, item["status"])
        _print(
            console,
            f"[{status}] {item['rule_id']}: {item['message']} (severity: {item['severity']})",
            style=_STATUS_STYLES[status] if color else "",
        )
        for location in cast(list[dict[str, object]], item["locations"]):
            suffix = f":{location['line']}" if "line" in location else ""
            _print(console, f"  location: {location['path']}{suffix}")
        for evidence_id in cast(list[object], item["evidence_ids"]):
            _print(console, f"  evidence: {evidence_id}")
        _print(console, f"  fix: {item['remediation']}")
    _print(console, "Manual review:")
    for check in cast(list[object], payload["manual_checks"]):
        _print(console, f"  - {check}")
    _print(console, "Diagnostics:")
    for diagnostic in cast(list[object], payload["diagnostics"]):
        _print(console, f"  - {diagnostic}")
    _print(console, "Timings (ms):")
    for name, milliseconds in cast(dict[str, int], payload["timings_ms"]).items():
        _print(console, f"  - {name}: {milliseconds}")
    _print(console, f"exit: {summary['exit_code']}")
    if verbose:
        semantic_json = json.dumps(
            payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        )
        _print(console, f"semantic-json: {semantic_json}")
    return output.getvalue()
