"""Self-contained, inert HTML renderer for the canonical report payload."""

import json
from html import escape
from typing import cast

from repoproof.domain import AuditReport
from repoproof.reporting.model import report_to_dict


def _text(value: object) -> str:
    """Escape all dynamic content, including URL delimiters in HTML source."""
    return escape(str(value), quote=True).replace(":", "&#58;")


def _locations(locations: list[dict[str, object]]) -> str:
    rendered: list[str] = []
    for item in locations:
        suffix = f":{item['line']}" if "line" in item else ""
        rendered.append(f"<code>{_text(item['path'])}{_text(suffix)}</code>")
    return "".join(rendered)


def _items(values: list[object]) -> str:
    return "".join(f"<li>{_text(value)}</li>" for value in values)


def render_html(report: AuditReport) -> str:
    """Render escaped schema-1 data only; no scripts, external resources, or active attributes."""
    payload = report_to_dict(report)
    payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    findings = cast(list[dict[str, object]], payload["findings"])
    rows = "".join(
        "<article"
        f' data-rule-id="{_text(item["rule_id"])}"'
        f' data-status="{_text(item["status"])}">'
        f"<h2>{_text(item['rule_id'])} — {_text(item['status'])} ({_text(item['severity'])})</h2>"
        f"<p>{_text(item['message'])}</p>"
        f"<p>Fix: {_text(item['remediation'])}</p>"
        f"<h3>Locations</h3>{_locations(cast(list[dict[str, object]], item['locations']))}"
        f"<h3>Evidence IDs</h3><ul>{_items(cast(list[object], item['evidence_ids']))}</ul>"
        "</article>"
        for item in findings
    )
    summary = cast(dict[str, int], payload["summary"])
    profile = cast(dict[str, object], payload["profile"])
    repository = cast(dict[str, object], payload["repository"])
    timings = cast(dict[str, int], payload["timings_ms"])
    timing_rows = "".join(
        f"<li>{_text(name)}: {_text(milliseconds)}</li>" for name, milliseconds in timings.items()
    )
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>RepoProof report</title><style>"
        "body{font:16px system-ui,sans-serif;max-width:960px;margin:auto;padding:2rem}"
        "article{border:1px solid #bbb;border-radius:.5rem;padding:1rem;margin:1rem 0}"
        "code{display:block;margin:.25rem 0;white-space:pre-wrap}"
        "</style></head>"
        f"<body data-report=\"{_text(payload_json)}\"><h1>RepoProof report</h1>"
        f"<p>Repository {_text(repository['name'])}; "
        f"report schema {_text(payload['report_schema'])}; "
        f"tool version {_text(payload['tool_version'])}; "
        f"generated {_text(payload['generated_at'])}</p>"
        f"<p>Profile {_text(profile['name'])}; schema {_text(profile['schema'])}; "
        f"sha256 {_text(profile['sha256'])}</p>"
        "<section><h2>Summary</h2><ul>"
        f"<li>FAIL: {_text(summary['FAIL'])}</li><li>WARN: {_text(summary['WARN'])}</li>"
        f"<li>SKIP: {_text(summary['SKIP'])}</li><li>PASS: {_text(summary['PASS'])}</li>"
        f"<li>Exit code: {_text(summary['exit_code'])}</li></ul></section>"
        f"<section><h2>Findings</h2>{rows}</section>"
        f"<section><h2>Manual review</h2><ul>"
        f"{_items(cast(list[object], payload['manual_checks']))}</ul></section>"
        f"<section><h2>Diagnostics</h2><ul>"
        f"{_items(cast(list[object], payload['diagnostics']))}</ul></section>"
        f"<section><h2>Timings (ms)</h2><ul>{timing_rows}</ul></section>"
        "</body></html>\n"
    )
