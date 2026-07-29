from pathlib import Path

from typer.testing import CliRunner

from repoproof.cli import app


def test_nonexistent_repository_exits_three(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["audit", str(tmp_path / "missing")])

    assert result.exit_code == 3
    assert "repository" in result.stderr.casefold()


def test_invalid_profile_exits_two(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["audit", str(tmp_path), "--profile", "missing.yml"])

    assert result.exit_code == 2
    assert "profile" in result.stderr.casefold()


def test_passing_audit_exits_zero(tmp_path: Path) -> None:
    profile = tmp_path / "profile.yml"
    profile.write_text(
        "schema: 1\nname: test-policy\ndescription: test\nrules:\n"
        "  - id: docs.spec\n    type: path_exists\n    severity: error\n"
        "    params: {paths: [SPEC.md]}\n    remediation: Add it.\n",
        encoding="utf-8",
    )
    (tmp_path / "SPEC.md").write_text("spec", encoding="utf-8")

    result = CliRunner().invoke(
        app, ["audit", str(tmp_path), "--offline", "--profile", str(profile)]
    )

    assert result.exit_code == 0
