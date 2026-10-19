"""Explicit research declarations, not automatic constraint discovery or admission."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import replace
from pathlib import Path

from vllm_hust_ext.config import ExtensionConfig
from vllm_hust_ext.core import plan_for, reject_conflicting_plans
from vllm_hust_ext.discovery import InstalledBundle
from vllm_hust_ext.manifest import load_manifest
from vllm_hust_ext.providers.base import ConfigurationRequirement, ProviderPlan


def checked_file(root: Path, reference: dict) -> Path:
    relative = Path(reference["path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("source reference must stay beneath source root")
    path = root.resolve() / relative
    if path.is_symlink() or path.resolve() != path or not path.is_file():
        raise ValueError("canonical regular source required")
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, k) != getattr(after, k) for k in fields):
        raise ValueError("source changed while reading")
    if hashlib.sha256(raw).hexdigest() != reference["sha256"]:
        raise ValueError("source SHA mismatch")
    return path


def source_plans(root: Path, profiles: list[dict]) -> tuple[ProviderPlan, ...]:
    plans = []
    for row in profiles:
        checked_file(root, row["source"])
        manifest_path = checked_file(root, row["manifest"])
        manifest = load_manifest(manifest_path)
        if (manifest.bundle_id, manifest.bundle_version) != (
            row["owner"],
            row["version"],
        ):
            raise ValueError("declaration differs from source manifest owner/version")
        bundle = InstalledBundle(
            manifest.bundle_id,
            "source-inspection-not-installed:" + manifest.bundle_id,
            manifest.bundle_version,
            manifest_path,
            manifest,
            (),
        )
        plan = plan_for(
            bundle, ExtensionConfig(True, {}), include_external_providers=False
        )
        requirements = tuple(
            ConfigurationRequirement(
                tuple(item["path"]), item["minimum"], item["maximum"]
            )
            for item in row["configuration_requirements"]
        )
        plans.append(replace(plan, configuration_requirements=requirements))
    if len({plan.extension_id for plan in plans}) != len(plans):
        raise ValueError("duplicate declaration owner")
    return tuple(plans)


def declared_topology(argv: list[str]) -> dict[tuple[str, ...], int]:
    result = {}
    for name in ("pipeline", "tensor"):
        option = f"--{name}-parallel-size"
        values = []
        for index, token in enumerate(argv):
            if token == option:
                if index + 1 == len(argv):
                    raise ValueError("topology flag missing value")
                values.append(argv[index + 1])
            elif token.startswith(option + "="):
                values.append(token.split("=", 1)[1])
        if len(values) != 1 or not values[0].isdigit() or int(values[0]) < 1:
            raise ValueError("one explicit positive topology flag required: " + option)
        result[("vllm", "parallel_config", name + "_parallel_size")] = int(values[0])
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--profiles", type=Path, required=True)
    parser.add_argument("--launch-argv", type=Path, required=True)
    args = parser.parse_args()
    payload = json.loads(args.profiles.read_bytes())
    if payload["schema"] != "ecpa-explicit-source-read-predicates/v1":
        raise ValueError("unsupported research declaration schema")
    command = json.loads(args.launch_argv.read_bytes())
    if (
        not isinstance(command, list)
        or not command
        or any(type(x) is not str for x in command)
    ):
        raise ValueError("Host argv must be a nonempty string array")
    plans = source_plans(args.source_root, payload["profiles"])
    try:
        reject_conflicting_plans(plans, configuration_values=declared_topology(command))
    except ValueError as exc:
        print(
            json.dumps(
                {
                    "source_prelaunch": "rejected",
                    "reason": str(exc),
                    "native_qualification": False,
                    "Host_started": False,
                }
            )
        )
        return 2
    print(
        json.dumps(
            {
                "source_prelaunch": "declared-predicates-satisfied-only",
                "native_qualification": False,
                "Host_started": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
