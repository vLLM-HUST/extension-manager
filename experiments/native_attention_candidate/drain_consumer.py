"""Explicit prospective full-phase drain consumer; never formal admission."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path

from . import attention_consumer as base
from . import drain_collector, drain_time_policy, phase_drain

CONTRACT = "ecpa-native-attention-source-drain-consumer/v1"
SCOPE = "full-unfiltered-phase-source-closed-final-ACK"


def expected_sources():
    return {
        str(Path(m.__file__).resolve()): base.sha(Path(m.__file__).read_bytes())
        for m in (drain_collector, drain_time_policy, phase_drain)
    } | {str(Path(__file__).resolve()): base.sha(Path(__file__).read_bytes())}


def declare_drain_recipe(recipe):
    base.require_declared_attention_recipe(recipe)
    value = copy.deepcopy(recipe)
    base.require(
        "attention_drain_contract" not in value,
        "source drain contract already declared",
    )
    sources = expected_sources()
    existing = {x["path"]: x["sha256"] for x in value["sources"]}
    base.require(
        all(p not in existing or existing[p] == d for p, d in sources.items()),
        "source drain bytes previously differ",
    )
    for path, digest in sources.items():
        if path not in existing:
            value["sources"].append(dict(path=path, sha256=digest))
    value["attention_drain_contract"] = {
        "schema": CONTRACT,
        "scope": SCOPE,
        "required_ranks": [0, 1],
        "source_sha256": sources,
        "formal_result": False,
    }
    return value


def require_declared_drain_recipe(recipe, *, source_resolver=None):
    base.require_declared_attention_recipe(recipe, source_resolver=source_resolver)
    contract = recipe.get("attention_drain_contract")
    base.require(isinstance(contract, dict), "source drain was not preregistered")
    base.require(
        {k: v for k, v in contract.items() if k != "source_sha256"}
        == {
            "schema": CONTRACT,
            "scope": SCOPE,
            "required_ranks": [0, 1],
            "formal_result": False,
        },
        "source drain scope differs",
    )
    declared, expected = contract.get("source_sha256"), expected_sources()
    base.require(
        isinstance(declared, dict) and len(declared) == len(expected),
        "source drain module inventory differs",
    )
    if source_resolver is None:
        base.require(declared == expected, "live source drain bytes/paths differ")
    else:
        for current, digest in expected.items():
            originals = [p for p in declared if Path(p).name == Path(current).name]
            base.require(len(originals) == 1, "source drain basename ambiguous")
            original = originals[0]
            resolved = Path(source_resolver(original))
            base.require(
                declared[original] == digest
                and resolved.is_absolute()
                and resolved.is_file()
                and base.sha(resolved.read_bytes()) == digest,
                "copied source drain bytes differ",
            )
    pinned = {x["path"]: x["sha256"] for x in recipe["sources"]}
    base.require(
        all(pinned.get(p) == d for p, d in declared.items()),
        "source drain bytes not bound in recipe",
    )


def verify_sealed_status(receipt, phase, drain_policy_path):
    """An authenticated source predicate, never a quiescence timeout."""
    status = receipt["status"]
    base.require(status["failed"] is False, "source drain collector failed")
    source = status.get("source_drain")
    base.require(
        isinstance(source, dict)
        and source["schema"] == drain_collector.POLICY
        and source["policy_sha256"] == base.sha(Path(drain_policy_path).read_bytes()),
        "authenticated source drain policy differs",
    )
    runtimes = source["runtimes"]
    selected = [
        v for v in runtimes.values() if v["phase"]["phase_id"] == phase["phase_id"]
    ]
    if not selected:
        return False
    base.require(len(selected) == 1, "source drain phase has multiple runtimes")
    state = selected[0]
    base.require(
        state["phase"]["external_request_id"] == phase["external_request_id"]
        and type(state["complete"]) is bool,
        "source drain phase binding differs",
    )
    if not state["complete"]:
        base.require(
            state["sealed_prefix"] is None,
            "incomplete source drain claims a sealed prefix",
        )
        return False
    base.require(
        state["ranks"] == [0, 1]
        and state["sealed_prefix"] == status["acknowledged_prefix"],
        "source drain rank/full-prefix coverage differs",
    )
    return True


def verify_observation(*args, drain_policy_path, **kwargs):
    return base.verify_observation(*args, drain_policy_path=drain_policy_path, **kwargs)


def execute_with_drain(*args, drain_policy_path, **kwargs):
    return base.execute_with_attention(
        *args, drain_policy_path=drain_policy_path, **kwargs
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "recipe",
        "output",
        "descriptor",
        "spec",
        "journal",
        "policy",
        "drain-policy",
    ):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--phase", required=True)
    parser.add_argument("--source-map", type=Path)
    args = parser.parse_args()
    source_map = json.loads(args.source_map.read_bytes()) if args.source_map else None
    observed = verify_observation(
        json.loads(args.recipe.read_bytes()),
        args.phase,
        args.output,
        descriptor=json.loads(args.descriptor.read_bytes()),
        spec_path=args.spec,
        journal_path=args.journal,
        policy_path=args.policy,
        drain_policy_path=args.drain_policy,
        source_resolver=(lambda p: Path(source_map[p]))
        if source_map is not None
        else None,
    )
    print(json.dumps(observed, sort_keys=True))


if __name__ == "__main__":
    main()
