"""CPU counterexamples for prospective pair binding, never runtime evidence."""

import copy
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_host_evidence import raw_event
from test_semantic_obligations import BASE, payload

from experiments.pair_semantic_candidate import authority, binding
from vllm_hust_ext import semantic_runtime_binding
from vllm_hust_ext.semantic_obligations import EVENT


@pytest.fixture
def pair(tmp_path, monkeypatch):
    bundles, dists = [], {}
    for extension, distribution, version in (
        (binding.KV, "kv", "1.0.0"),
        (binding.PROFILER, "profiler", "0.1.2"),
    ):
        root = tmp_path / distribution
        root.mkdir()
        (root / "manifest.json").write_text(json.dumps({"id": extension}))
        (root / "plugin.py").write_text("actual_payload = " + repr(extension))
        dist = SimpleNamespace(
            metadata={"Name": distribution},
            version=version,
            files=["manifest.json", "plugin.py"],
            locate_file=lambda name, root=root: root / name,
            read_text=lambda name: None,
        )
        dists[distribution] = dist
        bundles.append(
            SimpleNamespace(
                bundle_id=extension,
                distribution_name=distribution,
                distribution_version=version,
                manifest_path=root / "manifest.json",
            )
        )
    monkeypatch.setattr(
        semantic_runtime_binding.metadata, "distribution", lambda name: dists[name]
    )
    plugins, _ = semantic_runtime_binding.installed_plugin_identities(bundles)
    base = replace(BASE, plugins=(plugins[0],))
    contract = payload()
    contract["id"] = binding.KV
    return SimpleNamespace(bundles=bundles, base=base, contract=contract, root=tmp_path)


def compile_pair(pair):
    return binding.compile_pair_plan(
        pair.base,
        pair.bundles,
        pair.contract,
        profiler_slots={"api-server": (0,), "worker": (0, 1)},
    )


def test_both_actual_payload_identities_and_full_original_kv_obligations_retained(pair):
    before = copy.deepcopy(pair.base)
    base, plan, native, receipt = compile_pair(pair)
    assert pair.base == before
    assert len(plan.plugins) == len(base.plugins) == 2
    assert set(pair.base.obligations).issubset(plan.obligations)
    assert native["bindings"][0]["plugin_id"] == pair.base.plugins[0].id
    assert native["bindings"][0]["compiled_obligation"]["event"] == EVENT
    assert native["bindings"][0]["compiled_obligation"]["completion"] == "all"
    assert native["bindings"][0]["required_worker_ordinals"] == [0, 1]
    assert len(receipt["profiler_loader_bindings"]) == 2
    assert all(
        b["event"] == "invoked" and b["observation_kind"] == "loader_lifecycle"
        for b in receipt["profiler_loader_bindings"]
    )
    assert receipt["formal_result"] is receipt["runtime_observed"] is False


def test_changed_profiler_actual_payload_creates_distinct_plugin_and_plan(pair):
    first = compile_pair(pair)
    (pair.root / "profiler/plugin.py").write_text("changed = 1")
    second = compile_pair(pair)
    assert first[1].plan_id != second[1].plan_id
    assert (
        first[3]["plugin_identities"][binding.PROFILER]
        != second[3]["plugin_identities"][binding.PROFILER]
    )
    assert (
        first[3]["plugin_identities"][binding.KV]
        == second[3]["plugin_identities"][binding.KV]
    )


@pytest.mark.parametrize("slots", [{}, {"worker": [True]}, {"worker": [0, 0]}])
def test_invalid_profiler_rosters_rejected(pair, slots):
    with pytest.raises(ValueError):
        binding.compile_pair_plan(
            pair.base, pair.bundles, pair.contract, profiler_slots=slots
        )


def test_single_bundle_or_substituted_original_kv_artifact_rejected(pair):
    with pytest.raises(ValueError, match="exact actual"):
        binding.compile_pair_plan(
            pair.base, pair.bundles[:1], pair.contract, profiler_slots={"worker": [0]}
        )
    changed = replace(
        pair.base, plugins=(replace(pair.base.plugins[0], artifact_sha256="0" * 64),)
    )
    with pytest.raises(ValueError, match="original KV artifact"):
        binding.compile_pair_plan(
            changed, pair.bundles, pair.contract, profiler_slots={"worker": [0]}
        )


def event(extension, **changes):
    group, name, value = authority.ENTRIES[extension]
    return raw_event(entry_point=dict(group=group, name=name, value=value), **changes)


def host_args(raw):
    first = json.loads(raw.splitlines()[0])
    return dict(
        plan_id=first["plan_id"],
        launch_id=first["launch_id"],
        roster={"worker/0": first["process"]},
        required_slots={binding.KV: ["worker/0"], binding.PROFILER: ["worker/0"]},
    )


def test_loader_coverage_is_each_extension_not_union_of_entries():
    kv = event(binding.KV) + b"\n"
    with pytest.raises(ValueError, match="both MODs"):
        authority.verify_pair_host_events(kv, **host_args(kv))
    raw = kv + event(binding.PROFILER) + b"\n"
    coverage, _ = authority.verify_pair_host_events(raw, **host_args(raw))
    assert set(coverage) == {(binding.KV, "worker/0"), (binding.PROFILER, "worker/0")}


def test_runtime_effective_callback_cannot_satisfy_loader_invoked():
    raw = (
        event(binding.KV)
        + b"\n"
        + event(
            binding.PROFILER,
            event="effective",
            observation_kind="runtime_effective",
            occurrence_id="abc",
            detail="request-lifecycle-eventbus:request_finished",
        )
        + b"\n"
    )
    with pytest.raises(ValueError, match="both MODs"):
        authority.verify_pair_host_events(raw, **host_args(raw))


def test_other_plan_and_reused_process_epoch_rejected():
    kv = event(binding.KV) + b"\n"
    with pytest.raises(ValueError, match="another Plan"):
        authority.verify_pair_host_events(
            kv + event(binding.PROFILER, launch_id="other") + b"\n", **host_args(kv)
        )
    process = json.loads(kv)["process"]
    process["process_epoch"] += 1
    with pytest.raises(ValueError, match="original kernel roster"):
        authority.verify_pair_host_events(
            kv + event(binding.PROFILER, process=process) + b"\n", **host_args(kv)
        )


def test_pair_audit_cannot_accept_only_one_source_or_wrong_original_kv_wheel():
    with pytest.raises(ValueError, match="both exact pair"):
        authority.audit_pair_inputs(
            {}, {binding.KV: {}}, plugin_commits={binding.KV: "a" * 40}, bundles=()
        )
    audit = dict(
        schema=authority.routes.SCHEMA,
        formal_result=False,
        wheel_sha256={k: "a" * 64 for k in authority.routes.DISTRIBUTIONS},
        wheel_revisions={"mod": "b" * 40},
    )
    wheels = {binding.KV: {"sha256": "c" * 64}, binding.PROFILER: {}}
    with pytest.raises(ValueError, match="KV wheel"):
        authority.audit_pair_inputs(
            audit,
            wheels,
            plugin_commits={binding.KV: "b" * 40, binding.PROFILER: "d" * 40},
            bundles=(),
        )


def test_callback_requires_authority_owned_snapshot_and_actual_native_request_id():
    checker = object.__new__(authority.PairSourceAuthority)
    request = "original-runtime-request"
    raw = (
        event(
            binding.PROFILER,
            event="effective",
            observation_kind="runtime_effective",
            occurrence_id=authority.sha(("request_finished\0" + request).encode()),
            detail="request-lifecycle-eventbus:request_finished",
        )
        + b"\n"
    )
    kwargs = host_args(raw)
    args = dict(
        runtime_request_id=request,
        plan_id=kwargs["plan_id"],
        launch_id=kwargs["launch_id"],
        roster=kwargs["roster"],
    )
    with pytest.raises(ValueError, match="authority-owned"):
        checker.verify_profiler_finished({"raw": raw}, **args)
    with pytest.raises(ValueError, match="authority-owned"):
        checker.verify_profiler_finished(
            authority._HostSnapshot(object(), raw, {}), **args
        )
    snap = authority._HostSnapshot(checker, raw, {})
    result = checker.verify_profiler_finished(snap, **args)
    assert result["event"] == "effective"
    assert result["observation_kind"] == "runtime_effective"
    assert result["public_route_authorized"] is False
    with pytest.raises(ValueError, match="no original finished"):
        checker.verify_profiler_finished(
            snap, **{**args, "runtime_request_id": "another-request"}
        )


def test_authority_cannot_be_instantiated_without_independent_trust(pair):
    with pytest.raises(ValueError, match="independent pair/source/Manager trust"):
        authority.PairSourceAuthority(
            bundles=pair.bundles,
            trusted_source_observations=(),
            trusted_pair_inputs=(),
            trusted_manager_handoffs=(),
            trusted_kv_base_plan_ids=(),
            trusted_kv_contract_sha256=(),
        )


def test_prepare_writes_both_actual_identities_and_original_h4_schedule(
    pair, tmp_path, monkeypatch
):
    from experiments.pair_semantic_candidate import prepare
    from vllm_hust_ext.plan_artifact import plan_artifact_bytes

    base_path, contract_path = tmp_path / "base.json", tmp_path / "kv.json"
    base_path.write_bytes(plan_artifact_bytes(pair.base))
    contract_path.write_text(json.dumps(pair.contract))
    output = tmp_path / "prepared"
    monkeypatch.setattr(prepare, "discover_bundles", lambda selected: pair.bundles)
    monkeypatch.setattr(
        "sys.argv",
        [
            "prepare",
            "--kv-base-plan",
            str(base_path),
            "--kv-contract",
            str(contract_path),
            "--output",
            str(output),
        ],
    )
    prepare.main()
    cohort = json.loads((output / "h4-original-cohort.json").read_bytes())
    assert len(cohort["cells"]) == 4
    assert all(len(cell["planned_starts"]) == 9 for cell in cohort["cells"])
    assert cohort["h4"]["manual_baseline"] == "manual-integration"
    assert cohort["h4"]["thresholds"]["startup_join"] == "and"
    assert cohort["formal_starts"] == 0
    pair_plan = json.loads((output / "pair-plan.json").read_bytes())
    assert len(pair_plan["plan"]["plugins"]) == 2
    assert any(o["event"] == EVENT for o in pair_plan["plan"]["obligations"])
    assert (output / "pair-launch-spec.json").stat().st_mode & 0o077 == 0
    status = json.loads((output / "qualification-status.json").read_bytes())
    assert status["runtime_observed"] is status["public_route_authorized"] is False


def test_native_guard_cannot_weaken_compiled_profiler_slot_coverage():
    checker = object.__new__(authority.PairSourceAuthority)
    with pytest.raises(ValueError, match="compiled individual obligations"):
        authority.PairEpochGuard(
            checker,
            pair_inputs={},
            source_arguments={"profiler_slots": {"engine-core-scheduler": [0]}},
            handoff={},
            roster={},
            kernels={},
            required_slots={binding.KV: ["worker/0", "worker/1"], binding.PROFILER: []},
        )
