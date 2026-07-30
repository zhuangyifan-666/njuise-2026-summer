"""Canonical JSON report renderer."""

import json

from repoproof.domain import AuditReport
from repoproof.reporting.model import report_to_dict


def render_json(report: AuditReport) -> str:
    """Render schema-1 JSON with stable key ordering and a terminal newline."""
    return json.dumps(
        report_to_dict(report), ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ) + "\n"
