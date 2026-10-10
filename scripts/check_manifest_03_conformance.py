"""Check stable Manifest 0.3 schema, parser, and migration vectors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from vllm_hust_ext.manifest import ManifestError, parse_manifest

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec/manifest-0.3"
SCHEMA = SPEC / "manifest.schema.json"
CONFORMANCE = SPEC / "conformance-vectors.json"
MIGRATION = SPEC / "migration-vectors.json"
_MIGRATION_INVARIANTS = {
    "extension_id",
    "extension_version",
    "kind",
    "host",
    "runtime",
    "lifecycle_owner",
    "protocols",
    "implementation",
    "requires_services",
    "components",
    "activation",
}


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_vectors(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    spec = root / "spec/manifest-0.3"
    validator = Draft202012Validator(_load(spec / "manifest.schema.json"))
    conformance = _load(spec / "conformance-vectors.json")
    names: set[str] = set()
    for vector in conformance["vectors"]:
        name = vector["name"]
        if name in names:
            errors.append(f"duplicate conformance vector {name}")
        names.add(name)
        manifest = vector["manifest"]
        schema_errors = list(validator.iter_errors(manifest))
        try:
            parse_manifest(manifest)
            parser_error = None
        except ManifestError as error:
            parser_error = str(error)
        if vector["valid"]:
            if schema_errors:
                errors.append(f"{name}: stable schema rejected a valid vector")
            if parser_error is not None:
                errors.append(f"{name}: parser rejected a valid vector: {parser_error}")
        else:
            if not schema_errors:
                errors.append(f"{name}: stable schema accepted an invalid vector")
            if parser_error is None:
                errors.append(f"{name}: parser accepted an invalid vector")
            elif vector.get("error_contains") not in parser_error:
                errors.append(f"{name}: unexpected parser error: {parser_error}")

    migrations = _load(spec / "migration-vectors.json")
    migration_names: set[str] = set()
    for vector in migrations["vectors"]:
        name = vector["name"]
        if name in migration_names:
            errors.append(f"duplicate migration vector {name}")
        migration_names.add(name)
        source = vector["source"]
        target = vector["target"]
        rollback = vector["rollback"]
        try:
            parse_manifest(source)
            parse_manifest(target)
            parse_manifest(rollback)
        except ManifestError as error:
            errors.append(f"{name}: migration stage is invalid: {error}")
            continue
        if list(validator.iter_errors(target)):
            errors.append(f"{name}: migration target violates stable schema")
        if rollback != source:
            errors.append(f"{name}: rollback must reproduce the exact source manifest")
        for field in _MIGRATION_INVARIANTS:
            if source.get(field) != target.get(field):
                errors.append(f"{name}: migration changed invariant field {field}")
        if not target.get("resource_claims"):
            errors.append(f"{name}: migration must declare audited resource claims")
        if not target.get("requires_extensions"):
            errors.append(f"{name}: vector must exercise an explicit dependency")
    return errors


def main() -> int:
    errors = validate_vectors()
    if errors:
        for error in errors:
            print(f"manifest-0.3-conformance: {error}")
        return 1
    conformance = _load(CONFORMANCE)
    migrations = _load(MIGRATION)
    print(
        "manifest-0.3-conformance: "
        f"{len(conformance['vectors'])} conformance vectors, "
        f"{len(migrations['vectors'])} migration vector"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
