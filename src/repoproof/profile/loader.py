import hashlib
import json
import re
from importlib.resources import files
from pathlib import Path

import yaml
from pydantic import ValidationError
from yaml.tokens import AliasToken

from repoproof.errors import UsageFailure
from repoproof.profile.models import Profile

MAX_PROFILE_BYTES = 1024 * 1024
MAX_ALIASES = 50
_RULE_BRANCH_SEGMENTS = frozenset(
    {
        "path_exists",
        "markdown_sections",
        "ci_job_exists",
        "git_history",
        "distribution_ready",
        "secret_scan",
    }
)
_SAFE_LOCATION_SEGMENT = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_SENSITIVE_LOCATION_SEGMENT = re.compile(
    r"^(?:gh[pousr]_|github_pat_|sk-|AKIA)", re.IGNORECASE
)
_SENSITIVE_LOCATION_NAMES = frozenset(
    {"input", "input_value", "password", "secret", "token", "value"}
)
_VALIDATION_REASONS = {
    "extra_forbidden": "extra field is not permitted",
    "greater_than_equal": "value is below the supported range",
    "less_than_equal": "value is above the supported range",
    "literal_error": "value is not a supported literal",
    "missing": "required field is missing",
    "string_pattern_mismatch": "text does not match the required format",
    "string_too_long": "text exceeds the supported length",
    "string_too_short": "text is below the required length",
    "too_short": "collection has too few items",
    "union_tag_invalid": "rule type is not supported",
    "value_error": "value violates a profile constraint",
}


def _safe_location_segment(value: object) -> str | None:
    if isinstance(value, int) and value >= 0:
        return str(value)
    if not isinstance(value, str):
        return "field"
    if value in _RULE_BRANCH_SEGMENTS:
        return None
    if (
        not _SAFE_LOCATION_SEGMENT.fullmatch(value)
        or value.casefold() in _SENSITIVE_LOCATION_NAMES
        or _SENSITIVE_LOCATION_SEGMENT.match(value)
    ):
        return "field"
    return value


def _validation_failure(error: ValidationError) -> tuple[str, str]:
    details = error.errors(include_url=False, include_context=False, include_input=False)
    if not details:
        return ("Profile is invalid.", "Correct the profile YAML or schema fields.")
    first = details[0]
    location = ".".join(
        segment
        for item in first["loc"]
        if (segment := _safe_location_segment(item)) is not None
    )
    error_type = first["type"]
    if not _SAFE_LOCATION_SEGMENT.fullmatch(error_type):
        error_type = "validation_error"
    reason = _VALIDATION_REASONS.get(error_type, "field does not satisfy the profile schema")
    return (
        f"Profile is invalid at {location or 'profile'}: {error_type} ({reason}).",
        "Correct the named profile field; submitted data is omitted for safety.",
    )


def _read_profile(name_or_path: str) -> bytes:
    if name_or_path == "ai4se-b":
        data = files("repoproof.profile.builtin").joinpath("ai4se-b.yml").read_bytes()
    else:
        path = Path(name_or_path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise UsageFailure(
                "Profile could not be read.", "Check --profile path and permissions."
            ) from exc
    if len(data) > MAX_PROFILE_BYTES:
        raise UsageFailure("Profile exceeds 1 MiB.", "Reduce the YAML profile size.")
    return data


def load_profile(name_or_path: str) -> Profile:
    data = _read_profile(name_or_path)
    failure: tuple[str, str] | None = None
    profile: Profile | None = None
    try:
        text = data.decode("utf-8")
        try:
            aliases = sum(isinstance(token, AliasToken) for token in yaml.scan(text))
        except yaml.YAMLError:
            if text.count("*") > MAX_ALIASES:
                failure = (
                    "Profile exceeds 50 YAML aliases.",
                    "Remove YAML alias expansion.",
                )
            else:
                failure = ("Profile is invalid.", "Correct the profile YAML or schema fields.")
        if failure is None:
            if aliases > MAX_ALIASES:
                failure = (
                    "Profile exceeds 50 YAML aliases.",
                    "Remove YAML alias expansion.",
                )
            else:
                raw = yaml.safe_load(text)
                profile = Profile.model_validate(raw)
    except ValidationError as exc:
        failure = _validation_failure(exc)
    except (UnicodeDecodeError, yaml.YAMLError):
        failure = ("Profile is invalid.", "Correct the profile YAML or schema fields.")
    if failure is not None:
        raise UsageFailure(*failure)
    if profile is None:
        raise AssertionError("Profile validation completed without a result.")
    return profile


def profile_hash(profile: Profile) -> str:
    canonical = json.dumps(
        profile.model_dump(mode="json", by_alias=True), sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode()).hexdigest()
