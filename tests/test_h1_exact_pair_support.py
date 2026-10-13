from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path("experiments/false_effective")
CANDIDATE = ROOT / "deployment-candidates/h1-exact-pair-support-20261013.json"
SPEC = importlib.util.spec_from_file_location(
    "check_h1_exact_pair", ROOT / "check_h1_exact_pair.py"
)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def _candidate() -> dict:
    return json.loads(CANDIDATE.read_text())


def test_exact_pair_scope_and_current_source_status_are_bounded() -> None:
    candidate = _candidate()
    assert candidate["classification"].endswith("not-formal-h1")
    assert candidate["profile"] == {
        "model": "Qwen/Qwen2.5-7B-Instruct",
        "model_revision": "a09a35458c702b33eeacc393d103063234e8bc28",
        "accelerator": "2x Ascend 910B2",
        "topology": "single-host-tp2",
        "execution_mode": "enforce-eager",
        "extension": "kv_materialization",
        "extension_entry_point": {
            "group": "vllm.general_plugins",
            "name": "kv_materialization",
            "value": "vllm_kv_materialization.plugin:register_plugin",
        },
    }
    sources = candidate["sources"]
    assert sources["manager"]["merge_blocker"] is False
    assert sources["manager"]["artifact_source_is_ancestor_of_current_main"] is True
    assert sources["accelerator_plugin"]["pr50"]["state"] == "open"
    assert sources["accelerator_plugin"]["pr50"]["candidate_is_pr_head"] is False
    for name in ("host", "accelerator_plugin", "mod"):
        assert sources[name]["remote_reachability"]["reachable"] is False
        assert sources[name]["remote_reachability"]["matching_refs"] == []


def test_failed_full_suite_and_unregistered_preflights_remain_explicit() -> None:
    candidate = _candidate()
    full = candidate["validation"]["full_cpu_suite"]
    assert full["status"] == "failed"
    assert full["failed_count"] == 50
    assert sum(full["failed_file_counts"].values()) == 50
    assert "1985 passed, 12 skipped" in full["result"]
    preflights = candidate["validation"]["real_tp2_preflights"]
    assert preflights["formal_h1_starts"] == 0
    assert preflights["performance_result"] is False
    qualification = candidate["qualification"]
    assert qualification["formal_h1_starts"] == 0
    assert qualification["eligible_for_formal_h1"] is False
    assert len(qualification["blockers"]) == 7
    assert CHECKER.verify_invariants(candidate) == []


def test_checker_rejects_erasing_full_suite_failure() -> None:
    candidate = _candidate()
    candidate["validation"]["full_cpu_suite"]["status"] = "passed"
    errors = CHECKER.verify_invariants(candidate)
    assert "candidate must preserve the failed full-suite status" in errors


def test_checker_rejects_promoting_preflight_to_formal_h1() -> None:
    candidate = _candidate()
    candidate["qualification"]["formal_h1_starts"] = 3
    candidate["qualification"]["eligible_for_formal_h1"] = True
    errors = CHECKER.verify_invariants(candidate)
    assert "unreviewed candidate must not be formal-H1 eligible" in errors
    assert "unregistered preflights must contribute zero H1 starts" in errors
