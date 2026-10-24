#!/usr/bin/env python3
"""Verify and install exact H2 wheels without claiming host execution.

The probe creates a fresh environment per installation order and observes only
wheel metadata. It never imports either plugin and cannot produce an H2 label.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, cast
from zipfile import ZipFile

_CHECKOUT = Path(__file__).resolve().parents[2]
if (_CHECKOUT / "BENCHMARK_ORIGINALS.json").is_file():
    sys.path.insert(0, str(_CHECKOUT))
    from scripts.benchmark_inputs import resolve_original
else:

    def resolve_original(path: Path) -> Path:
        return path


HERE = Path(__file__).resolve().parent
DEFAULT_CAMPAIGN = HERE / "runtime_campaign.json"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(resolve_original(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return cast(dict[str, Any], value)


def _sha256(path: Path) -> str:
    return hashlib.sha256(resolve_original(path).read_bytes()).hexdigest()


def validate_campaign(campaign: dict[str, Any]) -> None:
    if (
        campaign.get("schema") != "ecpa-h2-real-mod-runtime-campaign/0.1"
        or campaign.get("classification")
        != "pre-admission-install-order-campaign-not-oracle-or-host-runtime"
        or campaign.get("status") != "pre-admission"
        or campaign.get("score_eligible") is not False
    ):
        raise ValueError("campaign must remain a non-scoreable pre-admission input")
    members = campaign.get("members")
    if not isinstance(members, list) or len(members) < 2:
        raise ValueError("campaign requires at least two members")
    by_id = {member.get("id"): member for member in members}
    if len(by_id) != len(members) or None in by_id:
        raise ValueError("campaign member ids must be unique strings")
    orders = campaign.get("installation_orders")
    expected_orders = {tuple(by_id), tuple(reversed(tuple(by_id)))}
    observed_orders = {tuple(order.get("members", [])) for order in orders or []}
    if len(by_id) == 2 and observed_orders != expected_orders:
        raise ValueError("both installation orders are required")
    if len({order.get("order_id") for order in orders or []}) != len(orders or []):
        raise ValueError("installation order ids must be unique")
    sources = {
        source["id"]: source for source in _load(HERE / "sources.json")["sources"]
    }
    for member_id, member in by_id.items():
        source = sources.get(member_id)
        if source is None or any(
            member.get(field) != source[field] for field in ("commit", "tree")
        ):
            raise ValueError(f"campaign source identity mismatch: {member_id}")
    cases = {case["id"]: case for case in _load(HERE / "cases.json")["cases"]}
    case = cases.get(campaign.get("case_id"))
    if (
        case is None
        or case["members"] != list(by_id)
        or case["host"]["provider"] != campaign["host"]["provider"]
        or case["host"]["versions"] != campaign["host"]["components"]
    ):
        raise ValueError("campaign does not match the frozen source case")
    observations = _load(HERE / "ownership_observations.json")["observations"]
    observation = next(
        (item for item in observations if item["case_id"] == campaign["case_id"]),
        None,
    )
    if observation is None or observation["installation_orders_required"] != [
        order["members"] for order in orders
    ]:
        raise ValueError("campaign does not match required ownership review orders")
    oracle = campaign.get("oracle", {})
    if (
        oracle.get("status") != "unreviewed"
        or oracle.get("label") is not None
        or oracle.get("reviewed_artifact_sha256") is not None
        or oracle.get("review_commit") is not None
    ):
        raise ValueError("pre-admission campaign cannot contain an oracle label")
    state = campaign.get("measurement_state", {})
    if set(state.values()) != {"unmeasured"}:
        raise ValueError("pre-admission measurements must remain unmeasured")


def _wheel_metadata(wheel: Path, member: dict[str, Any]) -> None:
    if (
        not resolve_original(wheel).is_file()
        or _sha256(wheel) != member["wheel_sha256"]
    ):
        raise ValueError(f"wheel digest mismatch: {member['id']}")
    entry_point = member["entry_point"]
    expected_line = f"{entry_point['name']} = {entry_point['value']}"
    with ZipFile(wheel) as archive:
        entries = [
            name for name in archive.namelist() if name.endswith("entry_points.txt")
        ]
        manifests = [
            name
            for name in archive.namelist()
            if name.endswith("vllm-hust-extension-v0.3.json")
        ]
        if len(entries) != 1 or len(manifests) != 1:
            raise ValueError(f"wheel metadata is ambiguous: {member['id']}")
        text = archive.read(entries[0]).decode()
        if f"[{entry_point['group']}]" not in text or expected_line not in text:
            raise ValueError(f"entry point mismatch: {member['id']}")
        expected_manifest = (
            resolve_original(HERE / "source_manifests" / f"{member['id']}.json")
        ).read_bytes()
        if archive.read(manifests[0]) != expected_manifest:
            raise ValueError(f"embedded manifest mismatch: {member['id']}")


_INSPECT = r"""
import importlib.metadata as m, json
members = json.loads(__import__('os').environ['ECPA_MEMBERS'])
names = {item['distribution'] for item in members}
eps = sorted(
    (
        {'group': ep.group, 'name': ep.name, 'value': ep.value}
        for ep in m.entry_points(group='vllm.general_plugins')
        if ep.dist and ep.dist.metadata['Name'] in names
    ),
    key=lambda item: (item['group'], item['name'], item['value']),
)
versions = {name: m.version(name) for name in sorted(names)}
print(json.dumps({'entry_points': eps, 'versions': versions}, sort_keys=True))
"""


def run_probe(campaign_path: Path, wheel_dir: Path) -> dict[str, Any]:
    campaign = _load(campaign_path)
    validate_campaign(campaign)
    members = {member["id"]: member for member in campaign["members"]}
    wheels = {key: wheel_dir / member["wheel"] for key, member in members.items()}
    for key, wheel in wheels.items():
        _wheel_metadata(wheel, members[key])
    receipts = []
    with tempfile.TemporaryDirectory(prefix="ecpa-h2-install-") as parent:
        for order in campaign["installation_orders"]:
            environment = Path(parent) / order["order_id"]
            subprocess.run(["python", "-m", "venv", str(environment)], check=True)
            python = environment / "bin" / "python"
            for member_id in order["members"]:
                subprocess.run(
                    [
                        str(python),
                        "-m",
                        "pip",
                        "install",
                        "--no-deps",
                        "--disable-pip-version-check",
                        str(wheels[member_id]),
                    ],
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
            env = {
                "ECPA_MEMBERS": json.dumps(list(members.values())),
                "PATH": str(environment / "bin"),
            }
            completed = subprocess.run(
                [str(python), "-c", _INSPECT],
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )
            observed = json.loads(completed.stdout)
            expected_entries = sorted(
                (member["entry_point"] for member in members.values()),
                key=lambda item: (item["group"], item["name"], item["value"]),
            )
            expected_versions = {
                member["distribution"]: member["version"] for member in members.values()
            }
            if observed["entry_points"] != expected_entries:
                raise ValueError(f"installed entry point mismatch: {order['order_id']}")
            if observed["versions"] != expected_versions:
                raise ValueError(f"installed version mismatch: {order['order_id']}")
            receipts.append(
                {
                    "order_id": order["order_id"],
                    "members": order["members"],
                    **observed,
                    "plugin_imported": False,
                    "host_started": False,
                }
            )
    return {
        "schema": "ecpa-h2-install-order-preflight-result/0.1",
        "classification": (
            "isolated-wheel-install-order-preflight-not-host-execution-or-oracle"
        ),
        "case_id": campaign["case_id"],
        "campaign_sha256": _sha256(campaign_path),
        "wheel_sha256": {key: members[key]["wheel_sha256"] for key in sorted(members)},
        "orders": receipts,
        "runtime_effective": "unmeasured",
        "performance_benefit": "unmeasured",
        "score_eligible": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign", type=Path, default=DEFAULT_CAMPAIGN)
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.output:
        from scripts.benchmark_inputs import new_output

        args.output = new_output(args.output)
    result = run_probe(args.campaign, args.wheel_dir)
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(payload)
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
