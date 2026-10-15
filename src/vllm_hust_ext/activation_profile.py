"""Explicit current selected-KV baseline target; no semantic/formal admission.

The owner independently freezes this file/hash and the calibration/source pins.
This profile never supplies a Manager identity, Plan receipt or recovery service.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = "ecpa-selected-kv-activation-profile/v1"
PATH_ENV = "ECPA_ACTIVATION_PROFILE_PATH"
SHA_ENV = "ECPA_ACTIVATION_PROFILE_SHA256"
ENABLE_ENV = "VLLM_ASCEND_KVCOMPRESS_ENABLED"
CONFIG_ENV = "VLLM_ASCEND_KVCOMPRESS_CONFIG"
DISTRIBUTION = "vllm-ascend-kvcompress-hust"
EXTENSION_ID = "org.vllm-hust.ascend-kvcompress"
GROUP = "vllm.general_plugins"
NAME = "ascend_kvcompress"
VALUE = "vllm_ascend_kvcompress.plugin:register"
SOURCES = {
    "plugin": "vllm_ascend_kvcompress/plugin.py",
    "configuration": "vllm_ascend_kvcompress/config.py",
}
HEX = re.compile(r"[0-9a-f]{64}\Z")


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        _require(key not in value, "activation profile duplicates a JSON field")
        value[key] = item
    return value


def _json(raw: bytes) -> dict[str, Any]:
    value: Any = json.loads(raw, object_pairs_hook=_object)
    _require(isinstance(value, dict), "activation profile/config must be an object")
    canonical(value)  # Reject nonfinite values at any depth.
    result: dict[str, Any] = value
    return result


def _path(value: str | Path) -> Path:
    path = Path(value)
    _require(
        path.is_absolute() and path.resolve() == path and not path.is_symlink(),
        "activation source path must be canonical",
    )
    return path


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _source(reference: dict[str, Any], expected_path: Path | None = None) -> Path:
    _require(
        set(reference) == {"path", "sha256"}, "activation source reference differs"
    )
    path = _path(reference["path"])
    _require(
        expected_path is None or path == expected_path,
        "activation installed source path differs",
    )
    _require(
        isinstance(reference["sha256"], str)
        and HEX.fullmatch(reference["sha256"]) is not None
        and _hash(path) == reference["sha256"],
        "activation source bytes differ",
    )
    return path


def _configuration(value: dict[str, Any]) -> None:
    _require(
        set(value) == {"schema_version", "provider", "method", "method_config"}
        and type(value["schema_version"]) is int
        and value["schema_version"] == 1
        and value["provider"] == "ascend_kvcompress"
        and value["method"] == "triattention",
        "selected-KV activation requires explicit current provider/method",
    )
    options = value["method_config"]
    _require(isinstance(options, dict), "selected-KV method_config must be an object")
    _require(
        all(
            isinstance(key, str)
            and (item is None or isinstance(item, (str, int, float, bool)))
            for key, item in options.items()
        ),
        "selected-KV method options must be scalar",
    )
    _require(
        all(
            not isinstance(item, float) or math.isfinite(item)
            for item in options.values()
        ),
        "selected-KV method options must be finite",
    )
    _require(
        options.get("auto_calibrate") is False
        and isinstance(options.get("stats_path"), str),
        "selected-KV activation requires frozen calibration, not auto-calibration",
    )


@dataclass(frozen=True)
class ActivationProfile:
    path: Path
    sha256: str
    raw: bytes

    def value(self) -> dict[str, Any]:
        return _json(self.raw)

    @property
    def marker(self) -> str:
        return "v2:selected-kv:" + self.sha256

    @property
    def configuration(self) -> dict[str, Any]:
        result: dict[str, Any] = self.value()["configuration"]
        return result

    def validate_installed(self) -> None:
        _require(
            _path(self.path).read_bytes() == self.raw
            and hashlib.sha256(self.raw).hexdigest() == self.sha256,
            "activation profile bytes changed",
        )
        value = self.value()
        _require(
            set(value)
            == {
                "schema",
                "distribution",
                "extension_id",
                "entry_point",
                "sources",
                "configuration",
                "calibration",
            }
            and value["schema"] == SCHEMA
            and value["extension_id"] == EXTENSION_ID,
            "selected-KV activation profile fields differ",
        )
        distribution = value["distribution"]
        _require(
            set(distribution) == {"name", "version", "entry_points_sha256"}
            and distribution["name"] == DISTRIBUTION
            and isinstance(distribution["version"], str)
            and bool(distribution["version"]),
            "selected-KV distribution identity differs",
        )
        _require(
            value["entry_point"] == {"group": GROUP, "name": NAME, "value": VALUE},
            "selected-KV entry point differs",
        )
        dist = importlib.metadata.distribution(DISTRIBUTION)
        _require(
            dist.version == distribution["version"],
            "installed selected-KV version differs",
        )
        entrypoints = dist.read_text("entry_points.txt")
        _require(
            entrypoints is not None
            and hashlib.sha256(entrypoints.encode()).hexdigest()
            == distribution["entry_points_sha256"],
            "installed entry-point metadata differs",
        )
        matches = [
            item
            for item in dist.entry_points
            if item.group == GROUP and item.name == NAME
        ]
        global_matches = [
            item
            for item in importlib.metadata.entry_points(group=GROUP)
            if item.name == NAME
        ]
        _require(
            len(matches) == len(global_matches) == 1
            and matches[0].value == global_matches[0].value == VALUE,
            "installed selected-KV entry point is absent or ambiguous",
        )
        _require(
            set(value["sources"]) == set(SOURCES), "selected-KV source roles differ"
        )
        for role, relative in SOURCES.items():
            _source(value["sources"][role], _path(str(dist.locate_file(relative))))
        _configuration(value["configuration"])
        calibration = _source(value["calibration"])
        _require(
            str(calibration) == value["configuration"]["method_config"]["stats_path"],
            "provider configuration and calibration identity differ",
        )

    def bind_environment(self) -> None:
        """Enable the actual MOD identically in both Manager-disabled baselines."""
        self.validate_installed()
        existing = (os.getenv(PATH_ENV), os.getenv(SHA_ENV))
        _require(
            existing in {(None, None), (str(self.path), self.sha256)},
            "inherited activation profile binding differs",
        )
        enabled = os.getenv(ENABLE_ENV)
        _require(
            enabled is None or enabled.strip().lower() in {"1", "true", "yes", "on"},
            "inherited selected-KV enable conflicts with profile",
        )
        configured = os.getenv(CONFIG_ENV)
        if configured is not None:
            # The plugin supports either a JSON object or a JSON-file path.
            if configured.lstrip().startswith("{"):
                raw = configured.encode()
            else:
                raw = _path(configured).read_bytes()
            _require(
                canonical(_json(raw)) == canonical(self.configuration),
                "inherited selected-KV provider configuration differs",
            )
        os.environ[PATH_ENV], os.environ[SHA_ENV] = str(self.path), self.sha256
        os.environ[ENABLE_ENV] = "1"
        os.environ[CONFIG_ENV] = canonical(self.configuration).decode()

    def receipt(self) -> dict[str, Any]:
        self.validate_installed()
        return {
            "profile_sha256": self.sha256,
            "entry_point": self.value()["entry_point"],
            "configuration_sha256": hashlib.sha256(
                canonical(self.configuration)
            ).hexdigest(),
            "distribution": self.value()["distribution"],
            "formal_result": False,
            "semantic_qualification": None,
        }


def load_activation_profile(path: Path, expected_sha256: str) -> ActivationProfile:
    path = _path(path)
    _require(
        HEX.fullmatch(expected_sha256) is not None, "activation profile digest invalid"
    )
    raw = path.read_bytes()
    _require(
        hashlib.sha256(raw).hexdigest() == expected_sha256,
        "activation profile digest differs",
    )
    profile = ActivationProfile(path, expected_sha256, raw)
    profile.validate_installed()
    return profile


def profile_from_environment() -> ActivationProfile | None:
    path, digest = os.getenv(PATH_ENV), os.getenv(SHA_ENV)
    if path is None and digest is None:
        return None
    _require(
        path is not None and digest is not None,
        "activation profile path/hash must both be bound",
    )
    assert path is not None and digest is not None
    return load_activation_profile(Path(path), digest)
