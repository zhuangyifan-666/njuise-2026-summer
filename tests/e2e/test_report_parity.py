import json
import re
from pathlib import Path

from typer.testing import CliRunner

from repoproof.cli import app


def test_json_and_html_have_identical_finding_identity(tmp_path: Path) -> None:
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
            "json",
            "--format",
            "html",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 1
    payload = json.loads((output / "report.json").read_text(encoding="utf-8"))
    html = (output / "report.html").read_text(encoding="utf-8")
    json_pairs = {(item["rule_id"], item["status"]) for item in payload["findings"]}
    html_pairs = set(re.findall(r'data-rule-id="([^"]+)" data-status="([^"]+)"', html))
    assert json_pairs == html_pairs
