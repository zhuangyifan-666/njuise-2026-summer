from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from repoproof.errors import UsageFailure
from repoproof.security import resolve_under_root


@given(st.lists(st.sampled_from(["..", "child"]), min_size=1, max_size=8))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_resolved_profile_paths_never_escape(tmp_path: Path, parts: list[str]) -> None:
    root = tmp_path / "repo"
    root.mkdir(exist_ok=True)
    candidate = "/".join(parts + ["file.txt"])

    if ".." in parts:
        with pytest.raises(UsageFailure):
            resolve_under_root(root, candidate)
    else:
        assert resolve_under_root(root, candidate).is_relative_to(root.resolve())
