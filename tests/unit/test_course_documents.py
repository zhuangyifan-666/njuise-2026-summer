import json
from pathlib import Path

from typer.testing import CliRunner

from repoproof.cli import app

ROOT = Path(__file__).parents[2]


def test_course_documents_pass_the_bundled_profile() -> None:
    result = CliRunner().invoke(
        app,
        [
            "audit",
            str(ROOT),
            "--profile",
            "ai4se-b",
            "--offline",
            "--format",
            "json",
            "--no-color",
        ],
    )

    assert result.exit_code == 0, result.stderr
    payload = json.loads(result.stdout)
    by_rule = {finding["rule_id"]: finding["status"] for finding in payload["findings"]}
    assert by_rule["docs.required"] == "PASS"
    assert by_rule["readme.sections"] == "PASS"
    assert by_rule["plan.commit-evidence"] == "PASS"
    assert by_rule["ci.gitlab-unit-test"] == "PASS"
