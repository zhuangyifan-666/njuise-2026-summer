from datetime import UTC, datetime
from pathlib import Path

from repoproof.app import AppDependencies, AuditRequest, run_audit
from repoproof.domain import Evidence, EvidenceState, ExitCode


class FakeCollector:
    def __init__(self, evidence: tuple[Evidence, ...]) -> None:
        self.evidence = evidence

    def collect(self, context: object, profile: object) -> tuple[Evidence, ...]:
        return self.evidence


def test_offline_app_runs_only_required_local_collectors(tmp_path: Path) -> None:
    (tmp_path / "SPEC.md").write_text("spec", encoding="utf-8")
    evidence = Evidence(
        "files.inventory",
        "file_inventory",
        ".",
        EvidenceState.AVAILABLE,
        {"paths": ("SPEC.md",), "sizes": {}, "total_bytes": 4},
        {},
    )
    remote_factory_calls: list[str | None] = []

    def remote_factory(slug: str | None) -> FakeCollector:
        remote_factory_calls.append(slug)
        raise AssertionError("offline audit instantiated a remote dependency")

    dependencies = AppDependencies(
        collectors={
            "ci": FakeCollector(()),
            "distribution": FakeCollector(()),
            "files": FakeCollector((evidence,)),
            "git": FakeCollector(()),
            "markdown": FakeCollector(()),
            "secrets": FakeCollector(()),
        },
        clock=lambda: datetime(2026, 7, 29, tzinfo=UTC),
        monotonic_ns=iter(
            (
                0,
                1_000_000,
                2_000_000,
                3_000_000,
                4_000_000,
                5_000_000,
                6_000_000,
                7_000_000,
                8_000_000,
                9_000_000,
                10_000_000,
                11_000_000,
            )
        ).__next__,
        github_collector_factory=remote_factory,
    )

    report = run_audit(AuditRequest(tmp_path, "ai4se-b", True), dependencies)

    assert report.exit_code in (ExitCode.OK, ExitCode.FINDINGS)
    assert report.repository_name == tmp_path.name
    assert remote_factory_calls == []
