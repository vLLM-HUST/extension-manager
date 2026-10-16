"""New request-domain declaration counterexamples; never runtime qualification."""

import copy
from pathlib import Path

import pytest
from test_native_attention_drain_unix import CPUFixtureTokenizer
from test_native_attention_drain_unix import observation as observation

from experiments.native_attention_candidate import (
    attention_consumer,
    drain_consumer,
    drain_time_policy,
    request_collector_client,
)
from experiments.native_attention_candidate import (
    request_drain_consumer as consumer,
)
from experiments.native_challenge_candidate import kv_request_runner as kv
from experiments.native_challenge_candidate import kv_time_policy
from experiments.native_kv_tensor_candidate import campaign_consumer


@pytest.fixture
def legacy_recipe():
    path = Path(campaign_consumer.__file__).resolve()
    recipe = kv.make_kv_recipe(
        [
            (f"phase-{i}", "http://127.0.0.1:1/v1/chat/completions", "CPU_FIXTURE_ONLY")
            for i in range(2)
        ],
        [{"path": str(path), "sha256": consumer.sha(path.read_bytes())}],
        CPUFixtureTokenizer(),
        [
            {
                "path": str(Path(__file__).resolve()),
                "sha256": consumer.sha(Path(__file__).read_bytes()),
            }
        ],
        materialized_row=True,
        rpc_budget_s=180,
        prompt_variant=kv.STRICT_COPY,
        ack_time_policy=kv_time_policy.FINAL_PREFIX_POLICY,
    )
    return drain_consumer.declare_drain_recipe(
        attention_consumer.declare_attention_recipe(
            campaign_consumer.declare_tensor_recipe(recipe)
        ),
        upload_tail_policy=drain_time_policy.NONWITNESS_UPLOAD_TAIL,
    )


def test_new_declaration_pins_actual_new_client_and_preserves_original(legacy_recipe):
    original = copy.deepcopy(legacy_recipe)
    recipe = consumer.declare_recipe(legacy_recipe)
    assert legacy_recipe == original
    assert recipe["schema"] == consumer.RECIPE
    assert "attention_drain_contract" not in recipe
    assert recipe["formal_result"] is False
    expected = consumer.sha(Path(request_collector_client.__file__).read_bytes())
    assert all(p["ack_client_source_sha256"] == expected for p in recipe["phases"])
    consumer.validate_recipe(recipe)
    with pytest.raises(ValueError):
        kv.validate_kv(recipe)
    with pytest.raises(ValueError):
        consumer.validate_recipe(legacy_recipe)


@pytest.mark.parametrize(
    "change", ["tokenization", "client", "source", "old-domain", "phase-replay"]
)
def test_new_domain_keeps_full_original_field_and_source_predicates(
    legacy_recipe, change
):
    recipe = consumer.declare_recipe(legacy_recipe)
    phase = recipe["phases"][0]
    if change == "tokenization":
        phase["tokenization"]["prompt_token_count"] += 1
    elif change == "client":
        phase["ack_client_source_sha256"] = "0" * 64
    elif change == "source":
        path = next(iter(recipe["request_drain_contract"]["source_sha256"]))
        recipe["request_drain_contract"]["source_sha256"][path] = "0" * 64
    elif change == "old-domain":
        recipe["attention_drain_contract"] = legacy_recipe["attention_drain_contract"]
    else:
        recipe["phases"][1]["challenge_nonce"] = phase["challenge_nonce"]
    with pytest.raises(ValueError):
        consumer.validate_recipe(recipe)


def test_compile_time_conversion_rejects_implicit_upload_tail_policy(legacy_recipe):
    legacy_recipe["attention_drain_contract"].pop("upload_tail_policy")
    with pytest.raises(ValueError):
        consumer.declare_recipe(legacy_recipe)


def test_explicit_projection_report_preserves_legacy_runtime_rejection(observation):
    """Reuse actual Unix CPU evidence; extra report rows are not archived proof."""
    import base64
    import json

    from experiments.native_kv_tensor_candidate import projection_tensor_join

    events = [
        json.loads(line) for line in observation["journal"].read_bytes().splitlines()
    ]
    tensor_events = [
        event for event in events if event["kind"] == "tensor.artifact.accepted"
    ]
    payloads = {
        event["sequence"]: json.loads(
            (observation["journal"].parent / event["artifact"]["basename"]).read_bytes()
        )
        for event in tensor_events
    }
    envelope = json.loads(base64.b64decode(tensor_events[0]["raw_base64"]))
    extra = copy.deepcopy(events[-1])
    extra["phase"]["phase_id"] = "other-phase"
    other = json.loads(base64.b64decode(extra["raw_base64"]))
    other["runtime_request_id"] = "other-runtime"
    extra["raw_base64"] = base64.b64encode(consumer.canonical(other)).decode()
    arguments = {
        "runtime_request_id": envelope["runtime_request_id"],
        "transaction_id": envelope["transaction_id"],
    }
    with pytest.raises(ValueError, match="phase joins another runtime"):
        projection_tensor_join.verify_projection_tensor_join(
            events + [extra], payloads, **arguments
        )
    selected = projection_tensor_join.verify_projection_tensor_join(
        events + [extra], payloads, phase_id="phase", **arguments
    )
    assert selected["two_rank_plan_projection_upload_join"] is True
    extra["phase"]["phase_id"] = "phase"
    with pytest.raises(ValueError, match="phase joins another runtime"):
        projection_tensor_join.verify_projection_tensor_join(
            events + [extra], payloads, phase_id="phase", **arguments
        )
