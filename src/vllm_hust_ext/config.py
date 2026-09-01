"""Persistent extension configuration and explicit enablement state."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from platformdirs import user_config_path


@dataclass(frozen=True, slots=True)
class ExtensionConfig:
    enabled: bool = False
    configuration: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class UserConfig:
    extensions: dict[str, ExtensionConfig] = field(default_factory=dict)

    @property
    def enabled(self) -> tuple[str, ...]:
        return tuple(
            extension_id
            for extension_id, state in self.extensions.items()
            if state.enabled
        )

    def extension(self, extension_id: str) -> ExtensionConfig:
        return self.extensions.get(extension_id, ExtensionConfig())

    def with_extension(
        self, extension_id: str, extension: ExtensionConfig
    ) -> UserConfig:
        updated = dict(self.extensions)
        updated[extension_id] = extension
        return UserConfig(updated)

    def without_extension(self, extension_id: str) -> UserConfig:
        updated = dict(self.extensions)
        updated.pop(extension_id, None)
        return UserConfig(updated)


def config_path() -> Path:
    override = os.environ.get("VLLM_HUST_EXT_CONFIG")
    return (
        Path(override)
        if override
        else user_config_path("vllm-hust-ext") / "config.json"
    )


def _extension_config(extension_id: str, value: Any) -> ExtensionConfig:
    if not isinstance(value, dict):
        raise ValueError(f"extension {extension_id!r} config must be an object")
    unknown = value.keys() - {"enabled", "configuration"}
    if unknown:
        raise ValueError(
            f"extension {extension_id!r} config has unknown keys: {sorted(unknown)}"
        )
    enabled = value.get("enabled", False)
    configuration = value.get("configuration", {})
    if not isinstance(enabled, bool):
        raise ValueError(f"extension {extension_id!r} enabled must be boolean")
    if not isinstance(configuration, dict):
        raise ValueError(f"extension {extension_id!r} configuration must be an object")
    return ExtensionConfig(enabled, configuration)


def load_config(path: Path | None = None) -> UserConfig:
    target = path or config_path()
    if not target.exists():
        return UserConfig()
    payload = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("vllm-hust-ext config must be an object")
    if payload.get("schema_version") == 1:
        enabled = payload.get("enabled", [])
        if not isinstance(enabled, list) or not all(
            isinstance(item, str) for item in enabled
        ):
            raise ValueError("legacy enabled must be an array of strings")
        return UserConfig({item: ExtensionConfig(enabled=True) for item in enabled})
    if payload.get("schema_version") != 2:
        raise ValueError("vllm-hust-ext config has an unsupported schema")
    raw_extensions = payload.get("extensions", {})
    if not isinstance(raw_extensions, dict) or not all(
        isinstance(key, str) for key in raw_extensions
    ):
        raise ValueError("vllm-hust-ext extensions must be an object")
    return UserConfig(
        {
            extension_id: _extension_config(extension_id, value)
            for extension_id, value in raw_extensions.items()
        }
    )


def save_config(config: UserConfig, path: Path | None = None) -> None:
    target = path or config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 2,
        "extensions": {
            extension_id: {
                "enabled": state.enabled,
                "configuration": state.configuration,
            }
            for extension_id, state in sorted(config.extensions.items())
        },
    }
    descriptor, temporary_name = tempfile.mkstemp(dir=target.parent, prefix=".config-")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, target)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)
