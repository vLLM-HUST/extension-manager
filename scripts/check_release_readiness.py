"""Validate the machine-readable ECPA release decision and version sources."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from packaging.version import InvalidVersion, Version

ROOT = Path(__file__).resolve().parents[1]
READINESS = ROOT / "docs/release-readiness.json"
SCHEMA = ROOT / "docs/release-readiness.schema.json"


def _project_version(path: Path) -> str:
    match = re.search(
        r'^version\s*=\s*"([^"]+)"\s*$', path.read_text(encoding="utf-8"), re.M
    )
    if match is None:
        raise ValueError(f"cannot find project version in {path.relative_to(ROOT)}")
    return match.group(1)


def _module_version(path: Path) -> str:
    match = re.search(
        r'^__version__\s*=\s*"([^"]+)"\s*$',
        path.read_text(encoding="utf-8"),
        re.M,
    )
    if match is None:
        raise ValueError(f"cannot find __version__ in {path.relative_to(ROOT)}")
    return match.group(1)


def validate_readiness(root: Path, payload: dict[str, Any]) -> list[str]:
    """Return semantic errors not expressible in the JSON Schema."""

    errors: list[str] = []
    package_version = payload["package_version"]
    versions = {
        "pyproject.toml": _project_version(root / "pyproject.toml"),
        "src/vllm_hust_ext/__init__.py": _module_version(
            root / "src/vllm_hust_ext/__init__.py"
        ),
    }
    for source, value in versions.items():
        if value != package_version:
            errors.append(f"{source} has version {value}, expected {package_version}")

    try:
        parsed_version = Version(package_version)
    except InvalidVersion:
        errors.append(f"package_version is not PEP 440: {package_version}")
        parsed_version = None

    gates = payload["gates"]
    gate_ids = [gate["id"] for gate in gates]
    if len(gate_ids) != len(set(gate_ids)):
        errors.append("gate ids must be unique")
    required_blockers = [
        gate for gate in gates if gate["required"] and gate["status"] != "passed"
    ]
    authorized = payload["publication_authorized"]
    decision = payload["decision"]
    if authorized != (decision == "go"):
        errors.append("publication_authorized must be true exactly when decision is go")
    if authorized and required_blockers:
        errors.append(
            "publication cannot be authorized while required gates are blocked"
        )
    if authorized and parsed_version is not None and parsed_version.is_devrelease:
        errors.append("an authorized publication cannot use a development version")
    if not authorized and not required_blockers:
        errors.append("a no-go decision must identify at least one required blocker")
    if not authorized and not package_version.endswith(".dev0"):
        errors.append("a frozen development line must retain a .dev0 package version")

    inventory = payload["inventory"]
    if (
        inventory["activation_intent"] + inventory["inspect_only"]
        != inventory["registrations"]
    ):
        errors.append("activation_intent plus inspect_only must equal registrations")
    if inventory["distributions"] > inventory["registrations"]:
        errors.append("distributions cannot exceed registrations")

    for gate in gates:
        for evidence in gate["evidence"]:
            candidate = Path(evidence)
            if candidate.is_absolute() or ".." in candidate.parts:
                errors.append(f"gate {gate['id']} has unsafe evidence path {evidence}")
                continue
            if not (root / candidate).is_file():
                errors.append(f"gate {gate['id']} evidence does not exist: {evidence}")

    if not authorized:
        readme = (root / "README.md").read_text(encoding="utf-8")
        if "Compatibility freeze" not in readme:
            errors.append("README must retain the compatibility freeze for a no-go")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-authorized",
        action="store_true",
        help="fail unless every required gate passes and publication is authorized",
    )
    args = parser.parse_args(argv)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    payload = json.loads(READINESS.read_text(encoding="utf-8"))
    schema_errors = sorted(
        Draft202012Validator(schema).iter_errors(payload),
        key=lambda error: list(error.absolute_path),
    )
    errors = [error.message for error in schema_errors]
    if not schema_errors:
        errors.extend(validate_readiness(ROOT, payload))
    if args.require_authorized and not payload.get("publication_authorized", False):
        errors.append("publication is not authorized by docs/release-readiness.json")
    if errors:
        for error in errors:
            print(f"release-readiness: {error}")
        return 1
    blocked = sum(gate["status"] == "blocked" for gate in payload["gates"])
    print(
        f"release-readiness: {payload['decision']} "
        f"({len(payload['gates']) - blocked} passed, {blocked} blocked)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
