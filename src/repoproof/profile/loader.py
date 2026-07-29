import hashlib
import json
from importlib.resources import files
from pathlib import Path

import yaml
from pydantic import ValidationError
from yaml.tokens import AliasToken

from repoproof.errors import UsageFailure
from repoproof.profile.models import Profile

MAX_PROFILE_BYTES = 1024 * 1024
MAX_ALIASES = 50


def _read_profile(name_or_path: str) -> bytes:
    if name_or_path == "ai4se-b":
        return files("repoproof.profile.builtin").joinpath("ai4se-b.yml").read_bytes()
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
    try:
        text = data.decode("utf-8")
        try:
            aliases = sum(isinstance(token, AliasToken) for token in yaml.scan(text))
        except yaml.YAMLError:
            if text.count("*") > MAX_ALIASES:
                raise UsageFailure(
                    "Profile exceeds 50 YAML aliases.", "Remove YAML alias expansion."
                ) from None
            raise
        if aliases > MAX_ALIASES:
            raise UsageFailure("Profile exceeds 50 YAML aliases.", "Remove YAML alias expansion.")
        raw = yaml.safe_load(text)
        return Profile.model_validate(raw)
    except UsageFailure:
        raise
    except (UnicodeDecodeError, yaml.YAMLError, ValidationError) as exc:
        raise UsageFailure(
            "Profile is invalid.", f"Correct the reported YAML/schema error: {exc}"
        ) from exc


def profile_hash(profile: Profile) -> str:
    canonical = json.dumps(
        profile.model_dump(mode="json", by_alias=True), sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode()).hexdigest()
