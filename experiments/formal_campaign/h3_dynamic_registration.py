"""Explicit dynamic-domain registration. Static intent never contains future PIDs.

The issuer requires the unchanged full-tuple published-source policy. Runtime
identity materialization belongs to the independently owned runner, not this
receipt. CPU test fixtures cannot issue a formal receipt.
"""

from __future__ import annotations

import argparse
import copy
import subprocess
import sys
from pathlib import Path

from experiments.formal_campaign import source_provenance
from experiments.formal_campaign.h3_cell_dispatch import cell_policy
from experiments.formal_campaign.h3_dynamic_authority import (
    canonical,
    digest,
    require,
    validate_policy,
)
from experiments.formal_campaign.h3_owned_worker_carrier import (
    checked_reference,
    load,
    save_new,
    validate_recipe,
)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DOMAIN = "ecpa-h3-dynamic-campaign/v1"
RECEIPT = "ecpa-h3-dynamic-deployment-receipt/v1"
ARMS = ("vanilla-vllm-entry-points", "manual-integration", "ecpa")
# Include every transitive experiment helper, including immutable legacy helpers
# reused as primitives, without rewriting or projecting their protocol domains.
PROTOCOL_FILES = (
    "h3_dynamic_registration.py",
    "h3_dynamic_runner.py",
    "h3_dynamic_intake.py",
    "h3_owned_worker_carrier.py",
    "h3_dynamic_authority.py",
    "h3_dynamic_client.py",
    "h3_dynamic_bindings.py",
    "h3_dynamic_host.py",
    "h3_runtime_source_closure.py",
    "h3-owned-worker-recipe.schema.json",
    "h3-dynamic-policy.schema.json",
    "h3-dynamic-campaign.schema.json",
    "h3-campaign.schema.json",
    "h3_worker_recovery.py",
    "h3_worker_relaunch.py",
    "h3_client_trace.py",
    "h3_cell_dispatch.py",
    "source_provenance.py",
    "protocol.json",
)


def scope_digest(original_ref, start):
    return _scope_digest(original_ref, start, DOMAIN)


def _scope_digest(original_ref, start, domain):
    policy = load(checked_reference(start["policy"]))
    body = {k: v for k, v in policy.items() if k != "registration_sha256"}
    return digest(
        canonical(
            {
                "domain": domain,
                "original_campaign": original_ref,
                "start_id": start["start_id"],
                "recipe_template": start["recipe_template"],
                "policy": body,
                "client_template": start["client_template"],
                "recovery_action": start["recovery_action"],
            }
        )
    )


def validate_campaign(spec):
    return _validate_campaign(spec)


def _validate_campaign(spec, *, profile=None, spec_path=None):
    from jsonschema import Draft7Validator

    Draft7Validator(
        load(
            HERE
            / (
                profile.CAMPAIGN_SCHEMA
                if profile
                else "h3-dynamic-campaign.schema.json"
            )
        )
    ).validate(spec)
    original = load(checked_reference(spec["original_campaign"]))
    Draft7Validator(load(HERE / "h3-campaign.schema.json")).validate(original)
    if profile is not None and hasattr(profile, "validate_original_cell"):
        profile.validate_original_cell(original)
    else:
        require(
            cell_policy(original["cell_id"]) == "worker-recovery",
            "new domain implements original worker cells only",
        )
    require(
        original["campaign_id"] == "H3-transactional-recovery-v1",
        "original H3 campaign identity differs",
    )
    source_provenance.validate_policy(spec["source_policy"], original["fixed_identity"])
    probe = original["probe"]
    require(
        original["fault"]["target_role"]
        == (
            profile.FAULT_ROLE
            if profile and hasattr(profile, "FAULT_ROLE")
            else "worker"
        ),
        "original fault must target this domain's actual role",
    )
    require(
        original["fault"]["signal"] in ("SIGKILL", "SIGTERM")
        and original["fault"]["target_exit_timeout_s"] > 0,
        "original worker fault missing",
    )
    expected = {f"{original['cell_id']}-r{r}-{a}" for r in (1, 2, 3) for a in ARMS}
    require(
        {s["start_id"] for s in spec["starts"]} == expected
        and len(spec["starts"]) == 9,
        "retain three original arms and repetitions",
    )
    fresh_paths = []
    for start in spec["starts"]:
        require(
            start["start_id"]
            == f"{original['cell_id']}-r{start['repetition']}-{start['arm']}",
            "original start identity differs",
        )
        require(
            start["arm_order"]
            == load(HERE / "protocol.json")["schedule"][start["repetition"] - 1].index(
                start["arm"]
            )
            + 1,
            "original arm order differs",
        )
        recipe = load(checked_reference(start["recipe_template"]))
        require(
            recipe["authority"]["process_identity"] is None,
            "static template cannot guess authority kernel",
        )
        validate_recipe(
            recipe,
            start["recipe_template"]["sha256"],
            Path(start["recipe_template"]["path"]),
            start["arm"],
            **({"native": True} if profile else {}),
        )
        policy = load(checked_reference(start["policy"]))
        (profile.validate_policy if profile else validate_policy)(policy)
        require(
            policy["start_id"] == start["start_id"]
            and policy["static_deployment_sha256"]
            == spec["original_campaign"]["sha256"]
            and policy["registration_sha256"]
            == _scope_digest(
                spec["original_campaign"], start, profile.DOMAIN if profile else DOMAIN
            ),
            "static policy/start/scope differs",
        )
        require(
            policy["backend_endpoint"] == recipe["authority"]["backend_endpoint"],
            "recipe/authority backend differs",
        )
        require(
            policy["model"] == probe["request_payload"]["model"],
            "authority model differs from original workload",
        )
        definition = start["authority"]
        source = checked_reference(recipe["authority"]["source"])
        require(
            source
            == HERE
            / (profile.AUTHORITY_SOURCE if profile else "h3_dynamic_authority.py"),
            "authority must execute this independently admitted new domain",
        )
        command = [
            sys.executable,
            str(source),
            "--policy",
            start["policy"]["path"],
            "--policy-sha256",
            start["policy"]["sha256"],
            "--journal",
            definition["journal"],
            "--socket",
            recipe["authority"]["socket"],
            "--public-port",
            str(definition["public_port"]),
            "--owned-stdin-lifetime",
        ]
        if profile:
            command += profile.authority_arguments(spec_path, start)
        require(
            definition["command"] == command,
            "authority command differs from exact source/policy/endpoint",
        )
        template = start["client_template"]
        from experiments.formal_campaign.h3_client_trace import validate_spec

        validate_spec(template)
        require(
            set(template)
            == {
                "schema",
                "start_id",
                "request_count",
                "concurrency",
                "interval_s",
                "timeout_s",
                "dispatch_slack_s",
                "request_url",
                "retry_policy",
                "payload",
                "response_expectation",
            },
            "static client template contains runtime identity or unknown fields",
        )
        require(
            template["start_id"] == start["start_id"]
            and template["request_url"]
            == f"http://127.0.0.1:{definition['public_port']}/v1/completions"
            and (
                template["request_count"],
                template["concurrency"],
                template["interval_s"],
                template["timeout_s"],
                template["dispatch_slack_s"],
            )
            == (60, 8, 0.2, 10, 0.5)
            and template["payload"] == probe["request_payload"]
            and template["response_expectation"] == probe["response_expectation"],
            "original finite functional workload differs",
        )
        phases = recipe["arms"][start["arm"]]["phases"]
        baseline_paths = {
            p["evidence_path"] for p in phases if p["origin"] == "host-baseline"
        }
        native_roots = {
            str(Path(p["handoff_path"]).parent)
            for p in phases
            if p["origin"] == "manager-native-handoff"
        }
        require(
            baseline_paths == set(policy["host_evidence_paths"])
            and native_roots == set(policy["host_evidence_roots"]),
            "authority must observe exact baseline paths "
            "or native Manager UUID-derived private roots",
        )
        # Every actual phase source is frozen, not just a launcher pathname.
        admitted = {(r["path"], r["sha256"]) for r in policy["source_refs"]}
        require(
            all(
                (r["path"], r["sha256"]) in admitted
                for p in phases
                for r in p["sources"]
            ),
            "phase source outside authority source policy",
        )
        require(
            start["recovery_action"] == "bounded-operator-full-relaunch",
            (
                "current adapter performs an actual bounded full relaunch; never "
                "claim automatic recovery"
            ),
        )
        if profile:
            profile.validate_start(spec, original, start, recipe, policy)
            fresh_paths += profile.extra_fresh_paths(start, recipe)
        fresh_paths += [definition["journal"], recipe["authority"]["socket"]] + [
            p["evidence_path"] for p in phases
        ]
    require(
        len(fresh_paths) == len(set(fresh_paths)),
        "starts must not reuse live journals, sockets or evidence streams",
    )
    return original


def verify_deployment_sources(spec, original):
    return _verify_deployment_sources(spec, original)


def _verify_deployment_sources(spec, original, *, profile=None, _starts=None):
    """Join actual installed MOD payloads and executable sources to pinned git.

    Pure Python wheel payloads must equal their admitted source files. Generated
    metadata is already hashed in PluginIdentity. Native build products need a
    separate reproducible-build proof and are rejected here, never guessed.
    """
    from vllm_hust_ext.discovery import discover_bundles
    from vllm_hust_ext.semantic_runtime_binding import installed_plugin_identities

    subjects = source_provenance.subjects(original["fixed_identity"])
    roots = {
        role: Path(value["path"]).resolve()
        for role, value in spec["repositories"].items()
    }

    def pinned(path, role):
        root = roots[role]
        path = Path(path)
        require(path.is_relative_to(root), "source outside its admitted repository")
        historical = subprocess.check_output(
            [
                "git",
                "-C",
                str(root),
                "show",
                f"{subjects[role]}:{path.relative_to(root)}",
            ]
        )
        require(
            path.read_bytes() == historical,
            "source differs from admitted exact commit: " + str(path),
        )

    installed = (
        profile.installed_payloads(
            spec, original, **({"_starts": _starts} if _starts is not None else {})
        )
        if profile
        else {}
    )
    bundles_by_id = {}
    for start in spec["starts"]:
        policy = load(checked_reference(start["policy"]))
        for item in policy["source_refs"]:
            path = checked_reference(item)
            owners = [role for role, root in roots.items() if path.is_relative_to(root)]
            require(
                owners or (profile and str(path) in installed),
                "phase source has no admitted repository owner: " + str(path),
            )
            if owners:
                pinned(path, max(owners, key=lambda role: len(str(roots[role]))))
            else:
                require(
                    installed.get(str(path))
                    == digest(path.read_bytes()).removeprefix("sha256:"),
                    "source is not in actual independently checked installed wheel",
                )
        artifacts = (
            profile.source_artifacts(start)
            if profile
            else [load(checked_reference(item)) for item in policy["binding_artifacts"]]
        )
        for artifact in artifacts:
            for contract in artifact["contracts"]:
                path = checked_reference(contract)
                owners = [
                    role for role, root in roots.items() if path.is_relative_to(root)
                ]
                if profile:
                    profile.verify_contract_source(spec, path, artifact["bundle_ids"])
                else:
                    require(owners, "contract is not admitted source")
                    pinned(path, max(owners, key=lambda role: len(str(roots[role]))))
            for bundle in discover_bundles(artifact["bundle_ids"]):
                bundles_by_id[bundle.bundle_id] = bundle
    require(
        set(spec["plugin_source_roles"]) == set(bundles_by_id)
        and set(spec["plugin_source_roles"].values())
        == {r for r in subjects if r.startswith("plugin:")},
        "every actual MOD needs its exact full-tuple source owner",
    )
    for bundle_id, bundle in bundles_by_id.items():
        role = spec["plugin_source_roles"][bundle_id]
        _, snapshots = installed_plugin_identities((bundle,))
        for row in snapshots[0]["files"]:
            relative = Path(row["path"])
            if any(p.endswith(".dist-info") for p in relative.parts):
                continue
            candidates = [roots[role] / relative, roots[role] / "src" / relative]
            matches = [
                path
                for path in candidates
                if path.is_file()
                and digest(path.read_bytes()).removeprefix("sha256:") == row["sha256"]
            ]
            require(
                len(matches) == 1,
                "actual MOD payload has no unique byte-identical admitted source: "
                + row["path"],
            )
            pinned(matches[0], role)


def verify_runtime_closures(spec, original, *, _starts=None):
    from experiments.formal_campaign.h3_runtime_source_closure import (
        verify_runtime_source_closure,
    )

    for start in spec["starts"] if _starts is None else _starts:
        recipe = load(checked_reference(start["recipe_template"]))
        for phase in recipe["arms"][start["arm"]]["phases"]:
            verify_runtime_source_closure(
                phase,
                original["fixed_identity"],
                spec["repositories"],
                spec["runtime_wheels"],
            )


def protocol_binding(manager_commit):
    return _protocol_binding(manager_commit, PROTOCOL_FILES)


def _protocol_binding(manager_commit, files):
    refs = {}
    for name in files:
        path = HERE / name if not name.startswith("experiments/") else ROOT / name
        raw = path.read_bytes()
        historical = subprocess.check_output(
            [
                "git",
                "-C",
                str(ROOT),
                "show",
                f"{manager_commit}:{path.relative_to(ROOT)}",
            ]
        )
        require(
            raw == historical,
            "new protocol source absent from exact admitted Manager revision: " + name,
        )
        refs[str(path.relative_to(ROOT))] = digest(raw)
    path = ROOT / "experiments/exposure_gate/loopback_traffic.py"
    raw = path.read_bytes()
    historical = subprocess.check_output(
        ["git", "-C", str(ROOT), "show", f"{manager_commit}:{path.relative_to(ROOT)}"]
    )
    require(raw == historical, "inherited socket/route primitive source differs")
    refs[str(path.relative_to(ROOT))] = digest(raw)
    # Bind the actually imported installed SDK, not just an unrelated clean
    # checkout bearing the requested commit. Core source remains untouched.
    import vllm_hust_ext

    package = Path(vllm_hust_ext.__file__).resolve().parent
    for path in sorted(package.rglob("*.py")):
        relative = Path("src/vllm_hust_ext") / path.relative_to(package)
        raw = path.read_bytes()
        historical = subprocess.check_output(
            ["git", "-C", str(ROOT), "show", f"{manager_commit}:{relative}"]
        )
        require(
            not path.is_symlink() and raw == historical,
            "actual runtime SDK source differs from admitted Manager: " + str(relative),
        )
        refs["runtime-sdk:" + str(relative)] = digest(raw)
    return refs


def issue(spec_path, output):
    return _issue(spec_path, output)


def _issue(spec_path, output, *, profile=None):
    spec_path, output = Path(spec_path).resolve(), Path(output).resolve()
    spec = load(spec_path)
    original = _validate_campaign(spec, profile=profile, spec_path=spec_path)
    if profile:
        profile.validate_receipt_destination(spec, output)
    observed = source_provenance.observe_sources(
        original["fixed_identity"], spec["source_policy"], spec["repositories"]
    )
    _verify_deployment_sources(spec, original, profile=profile)
    verify_runtime_closures(spec, original)
    binding = _protocol_binding(
        original["fixed_identity"]["manager_commit"],
        PROTOCOL_FILES
        + (profile.PROTOCOL_FILES + profile.EXTERNAL_PROTOCOL_FILES if profile else ()),
    )
    if profile:
        profile.verify_native_plans(spec, original, observed)
    receipt = {
        "schema": profile.RECEIPT if profile else RECEIPT,
        "campaign_sha256": digest(spec_path.read_bytes()),
        "original_campaign": spec["original_campaign"],
        "source_observation": observed,
        "protocol_sources": binding,
        "starts": [],
    }
    for start in spec["starts"]:
        recipe = load(checked_reference(start["recipe_template"]))
        policy = load(checked_reference(start["policy"]))
        receipt["starts"].append(
            {
                "start_id": start["start_id"],
                "authority": {
                    "registration_sha256": policy["registration_sha256"],
                    "source_sha256": recipe["authority"]["source"]["sha256"],
                    "argv_sha256": digest(
                        canonical({"argv": start["authority"]["command"]})
                    ),
                    "grant": policy["grant"],
                },
                "policy": start["policy"],
                "recipe_template": start["recipe_template"],
            }
        )
    save_new(output, receipt)
    return receipt


def validate_receipt(spec_path, receipt_path, *, check_remote=False):
    return _validate_receipt(spec_path, receipt_path, check_remote=check_remote)


def _validate_receipt(
    spec_path,
    receipt_path,
    *,
    check_remote=False,
    profile=None,
    _selected_start_id=None,
):
    spec_path, receipt_path = Path(spec_path).resolve(), Path(receipt_path).resolve()
    spec = load(spec_path)
    original = _validate_campaign(spec, profile=profile, spec_path=spec_path)
    selected = None
    if _selected_start_id is not None:
        require(profile is not None, "start scope requires explicit native profile")
        selected = tuple(
            start for start in spec["starts"] if start["start_id"] == _selected_start_id
        )
        require(len(selected) == 1, "unknown or ambiguous selected start")
    if profile:
        profile.validate_receipt_destination(spec, receipt_path)
    receipt = load(receipt_path)
    require(
        set(receipt)
        == {
            "schema",
            "campaign_sha256",
            "original_campaign",
            "source_observation",
            "protocol_sources",
            "starts",
        }
        and receipt["schema"] == (profile.RECEIPT if profile else RECEIPT)
        and receipt["campaign_sha256"] == digest(spec_path.read_bytes())
        and receipt["original_campaign"] == spec["original_campaign"],
        "explicit dynamic deployment receipt differs",
    )
    source_provenance.validate_observation(
        receipt["source_observation"], spec["source_policy"], original["fixed_identity"]
    )
    _verify_deployment_sources(
        spec,
        original,
        profile=profile,
        **({"_starts": selected} if selected is not None else {}),
    )
    require(
        receipt["protocol_sources"]
        == _protocol_binding(
            original["fixed_identity"]["manager_commit"],
            PROTOCOL_FILES
            + (
                profile.PROTOCOL_FILES + profile.EXTERNAL_PROTOCOL_FILES
                if profile
                else ()
            ),
        ),
        "protocol source inventory differs",
    )
    verify_runtime_closures(
        spec, original, **({"_starts": selected} if selected is not None else {})
    )
    if profile:
        profile.verify_native_plans(
            spec,
            original,
            receipt["source_observation"],
            **({"_starts": selected} if selected is not None else {}),
        )
    if check_remote:
        current = source_provenance.observe_sources(
            original["fixed_identity"], spec["source_policy"], spec["repositories"]
        )
        require(
            current == receipt["source_observation"],
            "full tuple source observation changed",
        )
    expected = []
    for start in spec["starts"]:
        recipe = load(checked_reference(start["recipe_template"]))
        policy = load(checked_reference(start["policy"]))
        expected.append(
            {
                "start_id": start["start_id"],
                "authority": {
                    "registration_sha256": policy["registration_sha256"],
                    "source_sha256": recipe["authority"]["source"]["sha256"],
                    "argv_sha256": digest(
                        canonical({"argv": start["authority"]["command"]})
                    ),
                    "grant": policy["grant"],
                },
                "policy": start["policy"],
                "recipe_template": start["recipe_template"],
            }
        )
    require(
        receipt["starts"] == expected,
        "per-start source/command/grant registration differs",
    )
    return spec, original, receipt


def materialize_recipe(template, actual_kernel):
    require(
        template["authority"]["process_identity"] is None,
        "preregistered recipe already contains a kernel",
    )
    result = copy.deepcopy(template)
    result["authority"]["process_identity"] = {
        k: actual_kernel[k] for k in ("pid", "start_ticks", "boot_id")
    }
    return result


def validate_materialization(spec, start, recipe):
    template = load(checked_reference(start["recipe_template"]))
    expected = materialize_recipe(template, recipe["authority"]["process_identity"])
    require(recipe == expected, "runtime materialization changed frozen intent")
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    issue(args.campaign, args.output)


if __name__ == "__main__":
    main()
