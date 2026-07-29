"""Self-contained, inert HTML report renderer."""

from html import escape
from typing import cast

from repoproof.domain import AuditReport
from repoproof.reporting.model import report_to_dict


def _text(value: object) -> str:
    # Encode colons as well so untrusted prose cannot form a literal URL in source.
    return escape(str(value), quote=True).replace(":", "&#58;")


def _locations(locations: list[object]) -> str:
    rendered: list[str] = []
    for location in locations:
        item = cast(dict[str, object], location)
        suffix = f":{item['line']}" if "line" in item else ""
        rendered.append(f"<code>{_text(item['path'])}{_text(suffix)}</code>")
    return "".join(rendered)


def render_html(report: AuditReport) -> str:
    """Render only escaped schema-1 data with inline CSS and no active content."""
    payload = report_to_dict(report)
    findings = cast(list[dict[str, object]], payload["findings"])
    rows = "".join(
        "<article"
        f' data-rule-id="{_text(item["rule_id"])}"'
        f' data-status="{_text(item["status"])}">'
        f"<h2>{_text(item['rule_id'])} — {_text(item['status'])}</h2>"
        f"<p>{_text(item['message'])}</p>"
        f"<p>Fix: {_text(item['remediation'])}</p>"
        f"{_locations(cast(list[object], item['locations']))}</article>"
        for item in findings
    )
    manual_checks = cast(list[object], payload["manual_checks"])
    manual = "".join(f"<li>{_text(item)}</li>" for item in manual_checks)
    profile = cast(dict[str, object], payload["profile"])
    repository = cast(dict[str, object], payload["repository"])
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>RepoProof report</title><style>"
        "body{font:16px system-ui,sans-serif;max-width:960px;margin:auto;padding:2rem}"
        "article{border:1px solid #bbb;border-radius:.5rem;padding:1rem;margin:1rem 0}"
        "code{display:block;margin:.25rem 0;white-space:pre-wrap}"
        "</style></head><body><h1>RepoProof report</h1>"
        f"<p>Repository {_text(repository['name'])}; schema {_text(payload['report_schema'])}; "
        f"tool {_text(payload['tool_version'])}; generated {_text(payload['generated_at'])}; "
        f"profile {_text(profile['name'])} ({_text(profile['sha256'])})</p>"
        f"{rows}<section><h2>Manual review</h2><ul>{manual}</ul></section>"
        "</body></html>\n"
    )
