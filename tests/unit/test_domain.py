from repoproof.domain import ExitCode, FindingStatus, Severity, status_for_failure


def test_error_rule_failure_is_fail() -> None:
    assert status_for_failure(Severity.ERROR) is FindingStatus.FAIL


def test_warning_rule_failure_is_warn() -> None:
    assert status_for_failure(Severity.WARNING) is FindingStatus.WARN


def test_exit_codes_are_stable() -> None:
    assert [int(code) for code in ExitCode] == [0, 1, 2, 3]
