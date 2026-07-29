import json
import re
from pathlib import Path

from typer.testing import CliRunner

from repoproof.cli import app


def test_console_json_and_html_have_identical_finding_identity_and_summary(tmp_path: Path) -> None:
    repository = Path(__file__).parents[2] / "examples/noncompliant-repo"
    output = tmp_path / "reports"
    output.mkdir()

    result = CliRunner().invoke(
        app,
        [
            "audit",
            str(repository),
            "--offline",
            "--format",
            "console",
            "--format",
            "json",
            "--format",
            "html",
            "--output",
            str(output),
            "--verbose",
            "--no-color",
        ],
    )

    assert result.exit_code == 1
    payload = json.loads((output / "report.json").read_text(encoding="utf-8"))
    html = (output / "report.html").read_text(encoding="utf-8")
    console_match = re.search(r"semantic-json: (?P<payload>\{.*\})\n\Z", result.stdout)
    assert console_match is not None
    console_payload = json.loads(console_match.group("payload"))
    json_pairs = {(item["rule_id"], item["status"]) for item in payload["findings"]}
    html_pairs = set(re.findall(r'data-rule-id="([^"]+)" data-status="([^"]+)"', html))
    console_pairs = {(item["rule_id"], item["status"]) for item in console_payload["findings"]}
    assert console_pairs == json_pairs == html_pairs
    json_summary = {
        status: payload["summary"][status] for status in ("FAIL", "WARN", "SKIP", "PASS")
    }
    console_summary = {
        status: console_payload["summary"][status] for status in ("FAIL", "WARN", "SKIP", "PASS")
    }
    html_summary = {
        status: int(count)
        for status, count in re.findall(r"<li>(FAIL|WARN|SKIP|PASS): (\d+)</li>", html)
    }
    assert console_summary == json_summary == html_summary
