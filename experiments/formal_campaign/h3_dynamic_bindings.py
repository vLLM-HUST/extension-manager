"""Derive obligation ownership from actual installed bundles and contracts.

A policy's bare plugin_id/entrypoint association is never authoritative. The
issuer and authority both recompute this artifact from actual distribution
payloads, declared activation metadata and the admitted contract compiler.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, replace
from pathlib import Path

from vllm_hust_ext.contract_compiler import compile_contracts, parse_contract
from vllm_hust_ext.discovery import discover_bundles
from vllm_hust_ext.ecpa_model import (
    EvidenceObligation,
    HostCompatibility,
    Plan,
    PluginIdentity,
    PredecessorSnapshot,
    ResourceClaim,
    content_id,
)
from vllm_hust_ext.plan_artifact import (
    parse_plan_artifact,
    plan_artifact_bytes,
    read_plan_artifact,
)
from vllm_hust_ext.semantic_runtime_binding import installed_plugin_identities

SCHEMA = "ecpa-h3-installed-obligation-bindings/v1"


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def require(value, why):
    if not value:
        raise ValueError(why)


def checked(ref):
    path = Path(ref["path"])
    require(
        path.is_absolute() and path.is_file() and not path.is_symlink(),
        "binding source artifact is absent or noncanonical",
    )
    raw = path.read_bytes()
    require(digest(raw) == ref["sha256"], "binding source artifact bytes differ")
    return path


def read_base_template(ref):
    value = json.loads(checked(ref).read_bytes())
    require(
        set(value) == {"schema", "deployment"}
        and value["schema"] == "ecpa-h3-uncompiled-deployment/v1",
        (
            "base is an explicit uncompiled intent, never an old execution "
            "Plan with obligations removed"
        ),
    )
    body = value["deployment"]
    require(
        set(body)
        == {
            "plugins",
            "host",
            "claims",
            "obligations",
            "predecessor",
            "fallback_proven",
        }
        and body["obligations"] == [],
        "uncompiled intent cannot discard existing required obligations",
    )
    return Plan(
        tuple(PluginIdentity(**p) for p in body["plugins"]),
        HostCompatibility(**body["host"]),
        tuple(ResourceClaim(**c) for c in body["claims"]),
        (),
        PredecessorSnapshot(**body["predecessor"]),
        body["fallback_proven"],
    )


def derive_owned_plan(base, bundles, contract_values, worker_ordinals=(0, 1)):
    require(
        not base.obligations,
        (
            "new binding compilation requires an obligation-empty base; "
            "existing obligations cannot be dropped"
        ),
    )
    require(
        worker_ordinals == (0, 1), "current actual worker binding scope is explicit TP2"
    )
    plugins, snapshots = installed_plugin_identities(bundles)
    require(
        set(plugins) == set(base.plugins) and len(plugins) == len(base.plugins),
        "actual installed PluginIdentity artifacts differ from Plan",
    )
    contracts = tuple(parse_contract(value) for value in contract_values)
    require(
        {c.extension_id for c in contracts} == {b.bundle_id for b in bundles}
        and len(contracts) == len(bundles),
        "every actual MOD needs its admitted contract; no silent single-MOD reduction",
    )
    compiled = compile_contracts(
        contracts, host_runtime=base.host.runtime, host_version=base.host.version
    )
    owner = {}
    for bundle, plugin, snapshot in zip(
        sorted(bundles, key=lambda b: b.bundle_id), plugins, snapshots, strict=True
    ):
        contract = next(c for c in contracts if c.extension_id == bundle.bundle_id)
        require(
            contract.version == bundle.distribution_version == plugin.version,
            "contract and actual distribution versions differ",
        )
        declared = {(e.group, e.name) for e in bundle.manifest.activation.entry_points}
        candidates = [e for e in bundle.entry_points if (e.group, e.name) in declared]
        require(
            len(candidates) == 1,
            "binding needs one unambiguous actual declared entrypoint per MOD",
        )
        ep = candidates[0]
        require(
            ep.dist is not None
            and ep.dist.metadata["Name"] == bundle.distribution_name
            and ep.dist.version == bundle.distribution_version,
            "entrypoint belongs to another installed artifact",
        )
        owner[bundle.bundle_id] = (
            plugin,
            {"group": ep.group, "name": ep.name, "value": ep.value},
            snapshot,
        )
    bindings, obligations = [], []
    for compiled_binding in compiled.obligation_bindings:
        require(
            compiled_binding.event == "invoked",
            (
                "semantic/non-invoked contract requires its own producer; cannot "
                "be downscoped"
            ),
        )
        require(
            compiled_binding.capability_direction == "provides"
            and compiled_binding.capability_provider == compiled_binding.extension_id,
            "runtime invocation must bind its actual owning MOD's provided capability",
        )
        require(
            compiled_binding.completion == "all" and compiled_binding.quorum is None,
            "current source-owned binding requires all declared processes",
        )
        require(
            compiled_binding.role in {"api-server", "worker"},
            "contract role is unsupported; do not relabel API/engine roles",
        )
        plugin, entry, snapshot = owner[compiled_binding.extension_id]
        ordinals = worker_ordinals if compiled_binding.role == "worker" else (0,)
        material = {
            "compiled_contract_plan_id": compiled.plan_id,
            "compiled_binding": asdict(compiled_binding),
            "plugin_id": plugin.id,
            "entry_point": entry,
            "installed_snapshot_sha256": digest(canonical(snapshot)),
            "required_ordinals": list(ordinals),
        }
        obligation_id = content_id("h3-owned-invocation-obligation", material)
        obligations.append(
            EvidenceObligation(
                obligation_id, compiled_binding.role, compiled_binding.event, ordinals
            )
        )
        bindings.append(
            {
                "obligation_id": obligation_id,
                "plugin_id": plugin.id,
                "entry_point": entry,
            }
        )
    require(
        len({b["obligation_id"] for b in bindings}) == len(bindings),
        "duplicate obligation owner",
    )
    require(
        len({canonical(b["entry_point"]) for b in bindings}) == len(bindings),
        "duplicate actual entrypoint cannot discharge multiple MOD obligations",
    )
    require(
        {b["plugin_id"] for b in bindings} == {p.id for p in plugins},
        "actual MOD missing its independently derived obligation",
    )
    plan = replace(base, obligations=tuple(obligations))
    parse_plan_artifact(plan_artifact_bytes(plan))
    return (
        plan,
        bindings,
        {
            b.bundle_id: digest(canonical(s))
            for b, s in zip(
                sorted(bundles, key=lambda b: b.bundle_id), snapshots, strict=True
            )
        },
    )


def verify_binding_artifact(ref):
    artifact = json.loads(checked(ref).read_bytes())
    require(
        set(artifact)
        == {
            "schema",
            "base_template",
            "plan",
            "contracts",
            "bundle_ids",
            "worker_ordinals",
            "bindings",
            "installed_snapshots",
        }
        and artifact["schema"] == SCHEMA,
        "installed binding artifact schema differs",
    )
    require(
        len(set(artifact["bundle_ids"])) == len(artifact["bundle_ids"]),
        "duplicate installed bundle",
    )
    bundles = discover_bundles(artifact["bundle_ids"])
    base = read_base_template(artifact["base_template"])
    declared = read_plan_artifact(checked(artifact["plan"])).plan
    values = [json.loads(checked(r).read_bytes()) for r in artifact["contracts"]]
    plan, bindings, snapshots = derive_owned_plan(
        base, bundles, values, tuple(artifact["worker_ordinals"])
    )
    require(
        plan == declared
        and bindings == artifact["bindings"]
        and snapshots == artifact["installed_snapshots"],
        "caller binding differs from installed artifact/contract-derived ownership",
    )
    return plan, bindings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-template", type=Path, required=True)
    parser.add_argument("--bundle-id", action="append", required=True)
    parser.add_argument("--contract", type=Path, action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    base = read_base_template(
        {
            "path": str(args.base_template.resolve()),
            "sha256": digest(args.base_template.read_bytes()),
        }
    )
    plan, bindings, snapshots = derive_owned_plan(
        base,
        discover_bundles(args.bundle_id),
        [json.loads(p.read_bytes()) for p in args.contract],
    )
    args.output_dir.mkdir(mode=0o700, exist_ok=False)
    plan_path = args.output_dir / "plan.json"
    plan_path.write_bytes(plan_artifact_bytes(plan))
    plan_path.chmod(0o400)

    def ref(p):
        return {"path": str(p.resolve()), "sha256": digest(p.read_bytes())}

    artifact = {
        "schema": SCHEMA,
        "base_template": ref(args.base_template),
        "plan": ref(plan_path),
        "contracts": [ref(p) for p in args.contract],
        "bundle_ids": args.bundle_id,
        "worker_ordinals": [0, 1],
        "bindings": bindings,
        "installed_snapshots": snapshots,
    }
    path = args.output_dir / "bindings.json"
    path.write_bytes(canonical(artifact) + b"\n")
    path.chmod(0o400)
    print(json.dumps(ref(path)))


if __name__ == "__main__":
    main()


class BindingGuard:
    """Keep a derived proof valid by checking all its actual input bytes.

    Compilation/discovery is pure over these installed payloads, contracts and
    metadata. Cache only the derived result, never a stat/mtime-only freshness
    assertion. Every call rehashes the complete frozen inputs and checks the
    metadata directory inventory; new distributions or modified RECORDs fail.
    """

    def __init__(self, ref):
        import sys
        from importlib import metadata

        self.plan, self.bindings = verify_binding_artifact(ref)
        artifact = json.loads(checked(ref).read_bytes())
        bundles = discover_bundles(artifact["bundle_ids"])
        _, snapshots = installed_plugin_identities(bundles)
        paths = {Path(ref["path"])}
        for item in [
            artifact["base_template"],
            artifact["plan"],
            *artifact["contracts"],
        ]:
            paths.add(checked(item))
        self.optional = {}
        for bundle, snapshot in zip(
            sorted(bundles, key=lambda b: b.bundle_id), snapshots, strict=True
        ):
            dist = metadata.distribution(bundle.distribution_name)
            for row in snapshot["files"]:
                paths.add(Path(dist.locate_file(row["path"])))
            # RECORD defines the inventory; editable metadata changes cannot be
            # hidden by omitting a payload from an updated inventory.
            for name in ("RECORD", "direct_url.json", "INSTALLER", "REQUESTED"):
                metadata_path = Path(dist._path) / name
                self.optional[metadata_path] = (
                    digest(metadata_path.read_bytes())
                    if metadata_path.exists()
                    else None
                )
        self.files = {p.resolve(): digest(p.read_bytes()) for p in paths}
        require(
            all(not p.is_symlink() and p.is_file() for p in paths),
            "binding proof input is symbolic or missing",
        )
        self.search_path = tuple(sys.path)
        self.roots = tuple(
            Path(p or ".").resolve() for p in sys.path if Path(p or ".").is_dir()
        )
        self.metadata_inventory = self._inventory()
        for root in self.roots:
            for directory in root.iterdir():
                if (
                    directory.name.endswith((".dist-info", ".egg-info"))
                    and directory.is_dir()
                ):
                    path = directory / "entry_points.txt"
                    self.optional[path] = (
                        digest(path.read_bytes()) if path.exists() else None
                    )
        require(
            verify_binding_artifact(ref) == (self.plan, self.bindings),
            "binding ownership changed during proof capture",
        )
        self.verify()

    def _inventory(self):
        return tuple(
            (
                str(root),
                tuple(
                    sorted(
                        p.name
                        for p in root.iterdir()
                        if p.name.endswith((".dist-info", ".egg-info"))
                    )
                ),
            )
            for root in self.roots
        )

    def verify(self):
        import sys

        require(
            tuple(sys.path) == self.search_path
            and self._inventory() == self.metadata_inventory,
            "installed distribution search/inventory changed",
        )
        for path, expected in self.files.items():
            require(
                not path.is_symlink()
                and path.is_file()
                and digest(path.read_bytes()) == expected,
                "installed binding proof input bytes changed",
            )
        for path, expected in self.optional.items():
            require(
                not path.is_symlink()
                and (digest(path.read_bytes()) if path.exists() else None) == expected,
                "installed binding metadata inventory changed",
            )
        return self.plan, self.bindings


def default_native_plan_binding(ref):
    """Derive the *distinct* actual Manager default lifecycle binding ID.

    Keep the raw native Plan ID exactly as emitted by the admitted Manager.
    This mapping never accepts a semantic_launch_spec or changes any event's
    plan_id. Its typed execution intent still contains all compiled obligations.
    """
    from vllm_hust_ext.runtime_evidence import launch_environment

    artifact = json.loads(checked(ref).read_bytes())
    plan, _ = verify_binding_artifact(ref)
    bundles = discover_bundles(artifact["bundle_ids"])
    environment = launch_environment(bundles)
    return {
        "runtime_plan_id": environment["VLLM_ECPA_PLAN_ID"],
        "execution_plan_id": plan.plan_id,
        "mode": "manager-default-lifecycle",
    }
