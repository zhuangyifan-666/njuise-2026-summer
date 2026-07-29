import json
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path

from repoproof.domain import Finding, FindingStatus, Location, Severity
from repoproof.profile.loader import load_profile
from repoproof.reporting.html_reporter import render_html
from repoproof.reporting.json_reporter import render_json
from repoproof.reporting.model import build_report


class _DocumentInspector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.articles: list[dict[str, str | None]] = []
        self.unsafe_tags: list[str] = []
        self.unsafe_attributes: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "iframe", "object", "embed", "link"}:
            self.unsafe_tags.append(tag)
        for name, _ in attrs:
            if name.casefold().startswith("on") or name.casefold() in {"src", "href"}:
                self.unsafe_attributes.append(name)
        if tag == "article":
            self.articles.append(dict(attrs))


def _sample_report():
    findings = (
        Finding(
            "z.pass",
            FindingStatus.PASS,
            Severity.ERROR,
            "ok",
            (),
            (),
            "none",
        ),
        Finding(
            "docs.spec",
            FindingStatus.FAIL,
            Severity.ERROR,
            '<script>alert(1)</script><img src=x onerror="alert(2)"> https://evil.example',
            (Location('a&b.md" onclick="alert(3)', 3),),
            ("files.inventory",),
            "Add it.",
        ),
    )
    return build_report(
        load_profile("ai4se-b"),
        Path("repo"),
        findings,
        ("Review <img src=x>",),
        {"total": 1},
        datetime(2026, 7, 29, tzinfo=UTC),
    )


def test_json_is_canonical_and_html_shares_report_semantics() -> None:
    report = _sample_report()
    rendered_json = render_json(report)
    payload = json.loads(rendered_json)
    inspector = _DocumentInspector()
    inspector.feed(render_html(report))

    assert rendered_json == render_json(report)
    assert rendered_json.endswith("\n")
    assert [finding["rule_id"] for finding in payload["findings"]] == [
        "docs.spec",
        "z.pass",
    ]
    articles = [(item["data-rule-id"], item["data-status"]) for item in inspector.articles]
    assert articles == [
        ("docs.spec", "FAIL"),
        ("z.pass", "PASS"),
    ]
    assert payload["summary"]["exit_code"] == 1


def test_html_escapes_untrusted_text_and_has_no_active_or_external_content() -> None:
    html = render_html(_sample_report())
    inspector = _DocumentInspector()
    inspector.feed(html)

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "a&amp;b.md&quot; onclick=&quot;alert(3)" in html
    assert inspector.unsafe_tags == []
    assert inspector.unsafe_attributes == []
    assert "http://" not in html and "https://" not in html
