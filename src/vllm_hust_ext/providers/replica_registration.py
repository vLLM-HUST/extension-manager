"""Source-bound H2 static registration; no controller or cluster operation.

The independent reviewer supplies a frozen oracle receipt through a separate
trusted CLI argument. This module cannot establish independence of its author.
It never creates an oracle or uses its verdict to compute a prediction.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import os
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from vllm_hust_ext.providers.replica_writers import PINNED_SOURCE_SHA256

MODE = "registered-source-derived-replica-writers/v1"
SOURCE_IDENTITIES = {
    "chart": {
        "repository": "vllm-project/production-stack",
        "commit": "4e076e8de3698a3729b575e3a5ade65ffbb929cf",
        "tree": "f1851241361ef53a5d2b64a1d726f81b5a245e28",
    },
    "keda": {
        "repository": "kedacore/keda",
        "commit": "59815e11667a0b8bb83453ab9ce5ebffcdf5b9da",
        "tree": "6087ec6f0683582c48aad7b77dc123bde9c03b4f",
    },
    "provider_manifest": {
        "repository": "vLLM-HUST/extension-manager",
        "commit": "9a1369d23ee32f3bb84583fb1695b2ff7cf4eb43",
        "blob": "f7c4502f77b697266069d7c4cc3f28d8b42fdc63",
    },
}
_CURRENT: contextvars.ContextVar[_RegisteredCase | None] = contextvars.ContextVar(
    "registered_H2_replica_case", default=None
)
_OWNED: dict[int, _RegisteredCase] = {}


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def read_ref(ref: dict[str, str]) -> bytes:
    if not isinstance(ref, dict) or set(ref) != {"path", "sha256"}:
        raise ValueError("exact path/digest reference required")
    path = Path(ref["path"])
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("absolute non-symlink file required")
    if path.stat().st_size > 524288:
        raise ValueError("small input size bound exceeded")
    raw = path.read_bytes()
    if len(raw) > 524288 or digest(raw) != ref["sha256"]:
        raise ValueError("small input bytes/digest mismatch")
    return raw


def ref(path: Path | str) -> dict[str, str]:
    path = Path(path).resolve()
    return {"path": str(path), "sha256": digest(path.read_bytes())}


def _sources(source_root: Path | str) -> dict[str, dict[str, str]]:
    result = {}
    for name, sha in PINNED_SOURCE_SHA256.items():
        value = {
            "path": str(Path(source_root).resolve() / name),
            "sha256": "sha256:" + sha,
        }
        read_ref(value)
        result[name] = value
    return result


def _protocol_sources() -> dict[str, dict[str, str]]:
    import importlib.util

    from vllm_hust_ext import core, providers
    from vllm_hust_ext.providers import production_stack, replica_writers

    collector = importlib.util.find_spec(
        "experiments.real_mod_composition.h2_external_writer_case"
    )
    if collector is None or collector.origin is None:
        raise ValueError("registered H2 collector source is missing")
    paths = {
        "registration": __file__,
        "provider_factory": providers.__file__,
        "production_provider": production_stack.__file__,
        "detector": replica_writers.__file__,
        "core": core.__file__,
        "H2_collector": collector.origin,
    }
    result = {}
    for name, path in paths.items():
        if path is None:
            raise ValueError("registered protocol source path missing")
        result[name] = ref(path)
    return result


def _validate_request(
    request: dict[str, Any], source_root: Path | str
) -> dict[str, dict[str, str]]:
    if set(request) != {
        "schema",
        "case_id",
        "configuration",
        "provider_manifest",
        "autoscaler_manifest",
        "prediction_path",
    }:
        raise ValueError("registration request fields differ")
    if request["schema"] != "ecpa-H2-replica-writer-registration-request/v1":
        raise ValueError("wrong registration request schema")
    if not isinstance(request["case_id"], str) or not request["case_id"]:
        raise ValueError("case identity missing")
    sources = _sources(source_root)
    manifest = read_ref(request["provider_manifest"])
    scaler = read_ref(request["autoscaler_manifest"])
    if digest(manifest) != sources["production-stack-provider-manifest.json"]["sha256"]:
        raise ValueError("provider manifest differs from exact registered source")
    if digest(scaler) != sources["vllm-keda-scaled-object.yaml"]["sha256"]:
        raise ValueError("autoscaler differs from exact registered source")
    configuration = json.loads(read_ref(request["configuration"]))
    if not isinstance(configuration, dict) or "ownership_conflicts" in configuration:
        raise ValueError(
            "independent mode forbids the legacy diagnosis input, even empty"
        )
    output = Path(request["prediction_path"])
    if not output.is_absolute() or output.is_symlink():
        raise ValueError("prediction destination must be an absolute fresh path")
    return sources


def _validate_freeze(
    freeze_ref: dict[str, str], request_ref: dict[str, str], request: dict[str, Any]
) -> dict[str, Any]:
    freeze = json.loads(read_ref(freeze_ref))
    if (
        freeze.get("schema") != "ecpa-H2-independent-oracle-freeze/v1"
        or freeze.get("case_id") != request["case_id"]
        or freeze.get("registration_request_sha256") != request_ref["sha256"]
        or freeze.get("manager_prediction_present_at_freeze") is not False
        or freeze.get("independence", {}).get("manager_output_used") is not False
    ):
        raise ValueError("separate independent oracle freeze does not bind this case")
    # Hash the externally supplied reviewer source and oracle. Do not read the
    # oracle's verdict here; the future independent scorer alone uses it.
    read_ref(freeze["reviewer_source"])
    read_ref(freeze["oracle"])
    if not isinstance(freeze, dict):
        raise ValueError("freeze must be an object")
    return freeze


def write_exclusive(path: Path | str, document: Mapping[str, Any]) -> None:
    raw = json.dumps(document, sort_keys=True, indent=2).encode() + b"\n"
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        # Preserve any failed/partial original for diagnosis; never overwrite it.
        raise


def issue_registration(
    request_ref: dict[str, str],
    oracle_freeze_ref: dict[str, str],
    source_root: Path | str,
    output: Path | str,
) -> dict[str, str]:
    request = json.loads(read_ref(request_ref))
    sources = _validate_request(request, source_root)
    freeze = _validate_freeze(oracle_freeze_ref, request_ref, request)
    if Path(request["prediction_path"]).exists():
        raise ValueError("prediction already exists before registration")
    receipt = {
        "schema": "ecpa-H2-replica-writer-registration/v1",
        "mode": MODE,
        "request": request_ref,
        "oracle_freeze": oracle_freeze_ref,
        "oracle": freeze["oracle"],
        "source_root": str(Path(source_root).resolve()),
        "sources": sources,
        "source_identities": SOURCE_IDENTITIES,
        "protocol_sources": _protocol_sources(),
        "registered_clock_ns": time.monotonic_ns(),
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "prediction_absent_at_registration": True,
        "runtime_claim": False,
        "formal_hypothesis_result": False,
    }
    write_exclusive(output, receipt)
    return ref(output)


class _RegisteredCase:
    def __init__(self, receipt_ref: dict[str, str]) -> None:
        self.receipt_ref = dict(receipt_ref)
        self.validate_current()
        _OWNED[id(self)] = self

    def validate_current(self) -> _RegisteredCase:
        receipt = json.loads(read_ref(self.receipt_ref))
        if (
            receipt.get("schema") != "ecpa-H2-replica-writer-registration/v1"
            or receipt.get("mode") != MODE
        ):
            raise ValueError("wrong registered detector domain")
        request = json.loads(read_ref(receipt["request"]))
        sources = _validate_request(request, receipt["source_root"])
        freeze = _validate_freeze(receipt["oracle_freeze"], receipt["request"], request)
        if (
            receipt["sources"] != sources
            or receipt["source_identities"] != SOURCE_IDENTITIES
            or receipt["oracle"] != freeze["oracle"]
            or receipt["protocol_sources"] != _protocol_sources()
            or receipt["prediction_absent_at_registration"] is not True
            or type(receipt["registered_clock_ns"]) is not int
            or not 0 < receipt["registered_clock_ns"] <= time.monotonic_ns()
            or receipt["boot_id"]
            != Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        ):
            raise ValueError("registered source/protocol/clock binding changed")
        self.receipt, self.request = receipt, request
        self.configuration = json.loads(read_ref(request["configuration"]))
        return self

    def objects(self) -> list[dict[str, Any]]:
        self.validate_current()
        # Lossless relevant projection of ONE exact SHA-pinned YAML specimen.
        # Its apiVersion/kind defaults are derived from KEDA's pinned Go source.
        # This is no general YAML parser and accepts no other YAML bytes.
        return [
            {
                "apiVersion": "keda.sh/v1alpha1",
                "kind": "ScaledObject",
                "metadata": {"name": "vllm-scaledobject", "namespace": "default"},
                "spec": {
                    "scaleTargetRef": {"name": "vllm-llama3-deployment-vllm"},
                    "triggers": [{"type": "prometheus"}],
                },
            }
        ]


def load_registered_case(receipt_ref: dict[str, str]) -> _RegisteredCase:
    return _RegisteredCase(receipt_ref)


def require_owned_case(case: object) -> _RegisteredCase:
    if not isinstance(case, _RegisteredCase) or _OWNED.get(id(case)) is not case:
        raise ValueError("caller object is not an owned registered case")
    return case.validate_current()


def current_case() -> _RegisteredCase | None:
    case = _CURRENT.get()
    return None if case is None else require_owned_case(case)


@contextmanager
def registered_scope(case: _RegisteredCase) -> Iterator[_RegisteredCase]:
    token = _CURRENT.set(require_owned_case(case))
    try:
        yield case
    finally:
        _CURRENT.reset(token)
