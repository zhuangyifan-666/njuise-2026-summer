from pathlib import Path

from typer.testing import CliRunner

from repoproof.cli import app


def test_profile_list_contains_builtin() -> None:
    result = CliRunner().invoke(app, ["profile", "list"])

    assert result.exit_code == 0
    assert result.stdout == "ai4se-b\n"


def test_profile_validate_reports_generic_fix_and_exits_two(tmp_path: Path) -> None:
    policy = tmp_path / "invalid.yml"
    policy.write_text(
        "schema: 1\nname: abc\ndescription: test\nrules:\n"
        "  - id: bad.rule\n    type: path_exists\n    severity: error\n"
        "    params: {paths: [SPEC.md], unknown: true}\n"
        "    remediation: Add it.\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["profile", "validate", str(policy)])

    assert result.exit_code == 2
    assert "profile" in result.stderr.casefold()
    assert "fix:" in result.stderr.casefold()
