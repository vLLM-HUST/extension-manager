"""Persistent explicit Bundle enablement."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from platformdirs import user_config_path


@dataclass(frozen=True, slots=True)
class UserConfig:
    enabled: tuple[str, ...] = ()


def config_path() -> Path:
    override = os.environ.get("VLLM_HUST_EXT_CONFIG")
    return (
        Path(override)
        if override
        else user_config_path("vllm-hust-ext") / "config.json"
    )


def load_config(path: Path | None = None) -> UserConfig:
    target = path or config_path()
    if not target.exists():
        return UserConfig()
    payload = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("vllm-hust-ext config has an unsupported schema")
    enabled = payload.get("enabled", [])
    if not isinstance(enabled, list) or not all(
        isinstance(item, str) for item in enabled
    ):
        raise ValueError("vllm-hust-ext config enabled must be an array of strings")
    if len(enabled) != len(set(enabled)):
        raise ValueError("vllm-hust-ext config enabled contains duplicates")
    return UserConfig(tuple(enabled))


def save_config(config: UserConfig, path: Path | None = None) -> None:
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {"schema_version": 1, "enabled": list(config.enabled)}
    descriptor, temporary_name = tempfile.mkstemp(dir=target.parent, prefix=".config-")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2)
            stream.write("\n")
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, target)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
