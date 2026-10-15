"""Opaque baseline correlation; CPU activation is never semantic qualification."""

import json
from pathlib import Path

import pytest
from test_activation_profile import installation as installation
from test_baseline_host_binding import finish, launch, wait_for
from test_baseline_host_binding import real_host as real_host

from experiments.native_attention_candidate import baseline_host_binding as binding
from experiments.native_attention_candidate import baseline_native_scope as scope_api
from experiments.native_attention_candidate import (
    semantic_producer_registry as registry,
)
from experiments.native_kv_tensor_candidate import artifact_bootstrap


def reference(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)
    return {"path": str(path), "sha256": registry.sha(raw)}


def test_opaque_domains_freshness_and_private_reference(tmp_path):
    tmp_path.chmod(0o700)
    a = scope_api.create(
        "baseline-trial:" + "1" * 64, "entry-points-unmanaged", "2" * 64, "3" * 64
    )
    b = scope_api.create(
        "baseline-trial:" + "1" * 64, "entry-points-unmanaged", "2" * 64, "3" * 64
    )
    assert a.value()["native_correlation"] != b.value()["native_correlation"]
    assert a.value()["origin"] == "baseline-host-observer"
    assert a.value()["activation_only"] and a.value()["effect_qualification"] is None
    assert a.value()["formal_result"] is False
    assert not {"manager", "execution_plan_id", "native_binding"}.intersection(
        a.value()
    )
    ref = a.write(tmp_path / "scope.json")
    env = a.environment({"CPU_ONLY": "yes"}, scope_reference=ref)
    assert env["CPU_ONLY"] == "yes"
    assert env["VLLM_ECPA_PLAN_ID"] == a.value()["native_correlation"]["plan_id"]
    (tmp_path / "scope.json").write_bytes(a.raw + b" ")
    with pytest.raises(ValueError, match="reference bytes"):
        a.environment({}, scope_reference=ref)


@pytest.mark.parametrize(
    "key",
    [
        "VLLM_ECPA_PLAN_ID",
        "VLLM_ECPA_LAUNCH_ID",
        scope_api.PATH_ENV,
        scope_api.SHA_ENV,
        "ECPA_SEMANTIC_EXECUTION_PLAN_ID",
        "VLLM_HUST_EXT_EVIDENCE_PATH",
        "VLLMHUST_EXT_ENABLED_BUNDLES",
    ],
)
def test_environment_cannot_overwrite_or_inherit_Manager_bindings(tmp_path, key):
    tmp_path.chmod(0o700)
    scope = scope_api.create(
        "baseline-trial:" + "1" * 64, "explicit-manual-hooks", "2" * 64, "3" * 64
    )
    ref = scope.write(tmp_path / "scope.json")
    with pytest.raises(ValueError, match="conflict|Manager"):
        scope.environment({key: "caller"}, scope_reference=ref)


@pytest.mark.parametrize("mutation", ["origin", "alias", "formal", "arm", "trial"])
def test_scope_cannot_be_promoted_or_relabelled(mutation):
    scope = scope_api.create(
        "baseline-trial:" + "1" * 64, "entry-points-unmanaged", "2" * 64, "3" * 64
    )
    value = scope.value()
    if mutation == "origin":
        value["origin"] = "Manager"
    elif mutation == "alias":
        value["native_correlation"]["plan_id"] = "f" * 64
    elif mutation == "formal":
        value["formal_result"] = True
    elif mutation == "arm":
        value["arm"] = "manager-controlled-activation"
    else:
        value["observer_trial_id"] = "unregistered-trial"
    with pytest.raises(ValueError):
        scope_api.BaselineNativeScope(registry.canonical(value)).value()


@pytest.mark.parametrize(
    "mutation", ["same", "existing_native", "existing_tensor", "dangling", "public"]
)
def test_context_targets_reject_before_either_original_writer(
    tmp_path, monkeypatch, mutation
):
    tmp_path.chmod(0o700)
    native, tensor = tmp_path / "native.json", tmp_path / "tensor.json"
    if mutation == "same":
        tensor = native
    elif mutation == "existing_native":
        native.write_bytes(b"ORIGINAL NATIVE")
    elif mutation == "existing_tensor":
        tensor.write_bytes(b"ORIGINAL TENSOR")
    elif mutation == "dangling":
        tensor.symlink_to(tmp_path / "absent")
    else:
        tmp_path.chmod(0o755)
    calls = []
    monkeypatch.setattr(
        scope_api.native_bootstrap,
        "write_context",
        lambda *a, **k: calls.append("native"),
    )
    monkeypatch.setattr(
        scope_api.artifact_bootstrap,
        "write_context",
        lambda *a, **k: calls.append("tensor"),
    )
    with pytest.raises(ValueError, match="distinct|fresh|canonical|private"):
        scope_api.write_contexts(
            None,
            scope_reference=None,
            observer=None,
            receipt_reference=None,
            common_query_reference=None,
            peers=None,
            spec_reference=None,
            policy_reference=None,
            ready=None,
            source_files=None,
            collector_source_path=None,
            native_context_path=native,
            tensor_context_path=tensor,
        )
    assert calls == []
    if mutation == "existing_native":
        assert native.read_bytes() == b"ORIGINAL NATIVE" and not tensor.exists()
    if mutation == "existing_tensor":
        assert tensor.read_bytes() == b"ORIGINAL TENSOR" and not native.exists()


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "spec",
        "environment",
        "receipt",
        "source",
        "query",
        "post_auth_query",
        "collector",
        "observer_object",
        "journal",
    ],
)
def test_actual_Host_join_and_prewrite_guards(real_host, monkeypatch, mutation):
    """Real CPU Host callbacks/epochs; collector authentication alone is stubbed.

    This tests prewrite joins and the unchanged context writers, not semantic
    evidence, a real tensor collector, NPU execution or Manager authentication.
    """
    profile, root, sources = real_host
    observer = binding.HostObserver(
        root / "observer.sock",
        root / "ingress.jsonl",
        profile=profile,
        arm="entry-points-unmanaged",
        host_sources=sources,
    )
    query = reference(root / "common-query.json", b'{"CPU_QUERY_ONLY":true}')
    scope = scope_api.create(
        observer.trial, observer.arm, profile.sha256, query["sha256"]
    )
    scope_ref = scope.write(root / "scope.json")
    extra = scope.environment({}, scope_reference=scope_ref)
    if mutation == "environment":
        extra["VLLM_ECPA_PLAN_ID"] = "a" * 64
    child = launch(observer, root, extra=extra)
    try:
        wait_for(
            lambda: (
                len(list(root.glob("ready-*.json"))) == 3 or child.poll() is not None
            )
        )
        assert child.poll() is None
        peers = [json.loads(p.read_bytes()) for p in sorted(root.glob("ready-*.json"))]
        receipt = observer.finalize(peers)
        if mutation == "receipt":
            receipt["activation_only"] = False
        receipt_ref = reference(root / "receipt.json", registry.canonical(receipt))
        native_sources = [{"path": p, "sha256": d} for p, d in sources.items()]
        spec = {
            "native_plan_id": scope.value()["native_correlation"]["plan_id"],
            "native_launch_id": scope.value()["native_correlation"]["launch_id"],
            "senders": [
                {"process": p["process"], "source_files": native_sources} for p in peers
            ],
        }
        if mutation == "spec":
            spec["native_plan_id"] = "b" * 64
        spec_ref = reference(root / "spec.json", registry.canonical(spec))
        policy_ref = reference(
            root / "policy.json",
            registry.canonical(
                {
                    "schema": artifact_bootstrap.transport.RUNTIME_POLICY,
                    "classification": (
                        artifact_bootstrap.transport.runtime_contract.CLASSIFICATION
                    ),
                    "native_spec_sha256": spec_ref["sha256"],
                }
            ),
        )
        ready = {
            "socket_path": str(root / "CPU-collector.sock"),
            "socket_identity": [1, 2],
            "collector": {},
            "collector_source_sha256": "a" * 64,
            "archive_identity": {},
            "spec_sha256": spec_ref["sha256"],
        }
        from experiments.native_challenge_candidate import collector_client

        monkeypatch.setattr(
            collector_client,
            "authenticate",
            lambda *args, **kwargs: {"CPU_fixture": True},
        )
        if mutation == "collector":

            def rejected(*args, **kwargs):
                raise ValueError("CPU collector authentication rejected")

            monkeypatch.setattr(collector_client, "authenticate", rejected)
        if mutation == "post_auth_query":

            def changed(*args, **kwargs):
                Path(query["path"]).write_bytes(b"{}")
                return {"CPU_fixture": True}

            monkeypatch.setattr(collector_client, "authenticate", changed)
        if mutation == "source":
            native_sources[0] = {**native_sources[0], "sha256": "0" * 64}
        if mutation == "query":
            Path(query["path"]).write_bytes(b"{}")
        if mutation == "journal":
            with observer.journal_path.open("ab") as stream:
                stream.write(b'{"CPU_forged_append":true}\n')
        arguments = dict(
            scope_reference=scope_ref,
            observer=observer,
            receipt_reference=receipt_ref,
            common_query_reference=query,
            peers=peers,
            spec_reference=spec_ref,
            policy_reference=policy_ref,
            ready=ready,
            source_files=native_sources,
            collector_source_path=next(iter(sources)),
            native_context_path=root / "native-context.json",
            tensor_context_path=root / "tensor-context.json",
        )
        if mutation == "observer_object":
            arguments["observer"] = receipt
        if mutation is None:
            result = scope_api.write_contexts(scope, **arguments)
            assert (
                result["activation_only"] is True
                and result["effect_qualification"] is None
            )
            assert result["formal_result"] is False
            native = json.loads((root / "native-context.json").read_bytes())
            tensor = json.loads((root / "tensor-context.json").read_bytes())
            assert native["spec_sha256"] == tensor["spec_sha256"] == spec_ref["sha256"]
            assert not {"manager", "execution_plan_id", "native_binding"}.intersection(
                result
            )
        else:
            with pytest.raises(ValueError):
                scope_api.write_contexts(scope, **arguments)
            assert not (root / "native-context.json").exists()
            assert not (root / "tensor-context.json").exists()
    finally:
        finish(child, root, observer)
