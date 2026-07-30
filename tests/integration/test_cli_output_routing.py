from pathlib import Path

from typer.testing import CliRunner

from repoproof.cli import app


def test_multiple_file_formats_require_directory_and_write_after_scan(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "README.md").write_text("# repo\n", encoding="utf-8")
    output = tmp_path / "reports"
    output.mkdir()
    before = {
        path.relative_to(repository): path.read_bytes()
        for path in repository.rglob("*")
        if path.is_file()
    }

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

    after = {
        path.relative_to(repository): path.read_bytes()
        for path in repository.rglob("*")
        if path.is_file()
    }
    assert result.exit_code == 1
    assert (output / "report.json").is_file()
    assert (output / "report.html").is_file()
    assert after == before
