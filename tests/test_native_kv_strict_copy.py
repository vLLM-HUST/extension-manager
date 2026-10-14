"""Strict task feasibility inputs; CPU receipts do not qualify Host/NPU."""

import copy
import os
from pathlib import Path

import pytest

from experiments.native_challenge_candidate import kv_request_runner as kv
from experiments.native_challenge_candidate import request_runner as runner


class CPUFixtureTokenizer:
    def apply_chat_template(self, messages, **kwargs):
        return list(range(1201))

    def encode(self, expected, **kwargs):
        return list(range(70))


def recipe(tokenizer, assets=None):
    source = Path(kv.__file__).resolve()
    return kv.make_kv_recipe(
        [("strict-phase", "http://127.0.0.1:29501/v1/chat/completions", "model")],
        [{"path": str(source), "sha256": runner.sha(source.read_bytes())}],
        tokenizer,
        assets or [{"path": str(source), "sha256": runner.sha(source.read_bytes())}],
        materialized_row=True,
        rpc_budget_s=180,
        prompt_variant=kv.STRICT_COPY,
    )


def test_strict_variant_preserves_exact_two_nonce_oracle_and_legacy_default():
    value = recipe(CPUFixtureTokenizer())
    phase = value["phases"][0]
    assert len(phase["payload"]["messages"]) == 2
    assert (
        phase["response_oracle"]["expected"].split()
        == ["ECPA-CHALLENGE-" + phase["challenge_nonce"]] * 2
    )
    assert phase["minimum_completion_tokens"] == 32
    assert phase["payload"]["max_tokens"] == 128
    assert phase["oracle_tokenization"]["count"] == 70
    source = Path(kv.__file__).resolve()
    legacy = kv.make_kv_recipe(
        [("legacy", "http://127.0.0.1:29501/v1/chat/completions", "model")],
        value["sources"],
        CPUFixtureTokenizer(),
        [{"path": str(source), "sha256": runner.sha(source.read_bytes())}],
        materialized_row=True,
    )
    assert "prompt_variant" not in legacy["phases"][0]
    assert len(legacy["phases"][0]["payload"]["messages"]) == 1


@pytest.mark.parametrize(
    "mutation",
    ["system", "tail", "variant", "guided", "oracle", "budget", "phase-budget", "ids"],
)
def test_rehashed_prompt_or_constraint_tampering_rejected(mutation):
    value = recipe(CPUFixtureTokenizer())
    phase = value["phases"][0]
    if mutation == "system":
        phase["payload"]["messages"][0]["content"] += " Explain afterwards."
    elif mutation == "tail":
        phase["payload"]["messages"][1]["content"] += " Extra instruction."
    elif mutation == "variant":
        phase["prompt_variant"] = "unknown"
    elif mutation == "guided":
        phase["payload"]["guided_decoding"] = {"regex": ".*"}
    elif mutation == "oracle":
        phase["response_oracle"]["expected"] = "one nonce"
    elif mutation == "budget":
        phase["minimum_completion_tokens"] = 1
    elif mutation == "phase-budget":
        phase["rpc_budget_s"] = 181
    else:
        phase["oracle_tokenization"]["token_ids"] = [1] * 31
        phase["oracle_tokenization"]["count"] = 31
        phase["oracle_tokenization"]["token_ids_sha256"] = runner.sha(
            runner.canonical([1] * 31)
        )
    phase["tokenization"]["messages_sha256"] = runner.sha(
        runner.canonical(phase["payload"]["messages"])
    )
    with pytest.raises(ValueError):
        runner.validate(value)


def test_short_single_sample_is_rejected_without_resampling():
    tokenizer = CPUFixtureTokenizer()
    calls = []

    def short(expected, **kwargs):
        calls.append(expected)
        return list(range(31))

    tokenizer.encode = short
    with pytest.raises(ValueError, match="single-sampled"):
        recipe(tokenizer)
    assert len(calls) == 1


@pytest.mark.skipif(
    not os.environ.get("ECPA_REAL_TOKENIZER_MODEL"),
    reason="requires explicit local tokenizer assets",
)
def test_actual_local_tokenizer_recomputes_1201_and_strict_receipt():
    from transformers import AutoTokenizer

    directory = Path(os.environ["ECPA_REAL_TOKENIZER_MODEL"]).resolve()
    tokenizer = AutoTokenizer.from_pretrained(
        directory, local_files_only=True, trust_remote_code=False
    )
    value = recipe(tokenizer)
    phase = value["phases"][0]
    assert (
        kv.actual_chat_ids(tokenizer, phase["payload"]["messages"])
        == phase["tokenization"]["prompt_token_ids"]
    )
    assert len(phase["tokenization"]["prompt_token_ids"]) == 1201
    assert (
        tokenizer.encode(phase["response_oracle"]["expected"], add_special_tokens=False)
        == phase["oracle_tokenization"]["token_ids"]
    )
    assert (
        phase["tokenization"]["runtime_binding"]["classification"]
        == "ACTUAL_LOCAL_TOKENIZER_CPU_PREFLIGHT_ONLY"
    )
    tampered = copy.deepcopy(value)
    tampered["phases"][0]["payload"]["messages"][0]["content"] = (
        "Reply with just one string."
    )
    tampered["phases"][0]["tokenization"]["messages_sha256"] = runner.sha(
        runner.canonical(tampered["phases"][0]["payload"]["messages"])
    )
    with pytest.raises(ValueError):
        runner.validate(tampered)
