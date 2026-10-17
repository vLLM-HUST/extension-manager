"""Authored only: future CPU_UNIT_FIXTURE tests, NOT an independent real oracle.

The fixture oracle below is intentionally artificial and never scoreable data.
No candidate import/test execution occurred while preparing this source patch.
"""

import json
from pathlib import Path

import pytest

from experiments.real_mod_composition.h2_external_writer_case import predict, score
from vllm_hust_ext.providers import provider_for
from vllm_hust_ext.providers.replica_registration import (
    issue_registration,
    load_registered_case,
    ref,
    registered_scope,
)
from vllm_hust_ext.providers.replica_writers import analyze_registered_objects

SOURCES = (
    Path(__file__).resolve().parents[1]
    / "experiments"
    / "real_mod_composition"
    / "artifacts"
    / "h2-external-writer-source-adapter-20261017"
)


def write(path, value):
    path.write_text(json.dumps(value))
    return ref(path)


def request_and_freeze(tmp_path, *, legacy=False, delegated=False):
    configuration = {
        "chart": "vllm/vllm-stack",
        "release": "vllm",
        "namespace": "default",
        "values": {
            "servingEngineSpec": {
                "modelSpec": [
                    {
                        "name": "llama3",
                        "replicaCount": 1,
                        "keda": {"enabled": delegated},
                    }
                ]
            }
        },
    }
    if legacy:
        configuration["ownership_conflicts"] = []
    config_ref = write(tmp_path / "configuration.json", configuration)
    request = {
        "schema": "ecpa-H2-replica-writer-registration-request/v1",
        "case_id": "CPU_UNIT_FIXTURE_NOT_REAL_ORACLE",
        "configuration": config_ref,
        "provider_manifest": ref(SOURCES / "production-stack-provider-manifest.json"),
        "autoscaler_manifest": ref(SOURCES / "vllm-keda-scaled-object.yaml"),
        "prediction_path": str(tmp_path / "prediction.json"),
    }
    request_ref = write(tmp_path / "request.json", request)
    reviewer = tmp_path / "CPU-unit-reviewer.txt"
    reviewer.write_text("CPU_UNIT_FIXTURE_ONLY; not an independent source review")
    oracle_ref = write(
        tmp_path / "CPU-unit-oracle.json",
        {
            "case_id": request["case_id"],
            "verdict": "reject",
            "classification": "CPU_UNIT_FIXTURE_ONLY",
        },
    )
    freeze_ref = write(
        tmp_path / "CPU-unit-freeze.json",
        {
            "schema": "ecpa-H2-independent-oracle-freeze/v1",
            "case_id": request["case_id"],
            "registration_request_sha256": request_ref["sha256"],
            "manager_prediction_present_at_freeze": False,
            "independence": {"manager_output_used": False},
            "reviewer_source": ref(reviewer),
            "oracle": oracle_ref,
        },
    )
    return request_ref, freeze_ref


def register(tmp_path, **kwargs):
    request_ref, freeze_ref = request_and_freeze(tmp_path, **kwargs)
    return issue_registration(
        request_ref, freeze_ref, SOURCES, tmp_path / "receipt.json"
    )


def test_real_factory_core_status_and_plan_derived_path(tmp_path):
    receipt = register(tmp_path)
    case = load_registered_case(receipt)
    assert (
        provider_for(
            "production-stack", include_external=False
        )._registered_replica_case
        is None
    )
    with registered_scope(case):
        provider = provider_for("production-stack", include_external=False)
        assert provider._registered_replica_case is case
    document = predict(receipt)
    assert document["derived"]["prediction"] == "reject"
    assert document["derived"]["legacy_report_used"] is False
    assert "incompatible" in document["derived"]["sdk_status"]["states"]
    assert any(
        line.startswith(document["mode"] + ":")
        for line in document["derived"]["sdk_status"]["evidence"]
    )
    assert score(ref(tmp_path / "prediction.json"))["matched"] is True


def test_freeze_is_required_before_registration(tmp_path):
    request_ref, freeze_ref = request_and_freeze(tmp_path)
    Path(freeze_ref["path"]).unlink()
    with pytest.raises(ValueError):
        issue_registration(request_ref, freeze_ref, SOURCES, tmp_path / "receipt.json")


def test_legacy_diagnosis_input_rejected_even_when_empty(tmp_path):
    request_ref, freeze_ref = request_and_freeze(tmp_path, legacy=True)
    with pytest.raises(ValueError, match="legacy diagnosis"):
        issue_registration(request_ref, freeze_ref, SOURCES, tmp_path / "receipt.json")


def test_preexisting_prediction_blocks_registration(tmp_path):
    request_ref, freeze_ref = request_and_freeze(tmp_path)
    (tmp_path / "prediction.json").write_text("historical observation")
    with pytest.raises(ValueError, match="already exists"):
        issue_registration(request_ref, freeze_ref, SOURCES, tmp_path / "receipt.json")


def test_receipt_or_configuration_mutation_rejected(tmp_path):
    receipt = register(tmp_path)
    config = tmp_path / "configuration.json"
    config.write_text(config.read_text() + " ")
    with pytest.raises(ValueError, match="digest mismatch"):
        load_registered_case(receipt)


def test_oracle_mutation_rejected_after_registration(tmp_path):
    receipt = register(tmp_path)
    (tmp_path / "CPU-unit-oracle.json").write_text("{}")
    with pytest.raises(ValueError, match="digest mismatch"):
        predict(receipt)


def test_delegation_is_unknown_not_fake_admit_or_TN(tmp_path):
    receipt = register(tmp_path, delegated=True)
    document = predict(receipt)
    assert document["derived"]["prediction"] == "unknown"
    result = score(ref(tmp_path / "prediction.json"))
    assert result["score_eligible"] is False


def test_legacy_prediction_domain_cannot_score(tmp_path):
    receipt = register(tmp_path)
    document = predict(receipt)
    document["mode"] = "legacy-report-consumption"
    prediction_ref = write(tmp_path / "prediction.json", document)
    with pytest.raises(ValueError, match="domain mismatch"):
        score(prediction_ref)


def test_forged_derived_output_cannot_score(tmp_path):
    receipt = register(tmp_path)
    document = predict(receipt)
    document["derived"]["legacy_report_used"] = True
    prediction_ref = write(tmp_path / "prediction.json", document)
    with pytest.raises(ValueError, match="does not reproduce"):
        score(prediction_ref)


@pytest.mark.parametrize(
    "deployment,scalers",
    [
        ({"metadata": None}, []),
        ({"metadata": []}, []),
        ({}, [None]),
        ({}, {"not": "a sequence"}),
    ],
)
def test_malformed_objects_unknown_not_attribute_error(deployment, scalers):
    assert (
        analyze_registered_objects(
            deployment, scalers, release_namespace="default", release_name="vllm"
        ).decision
        == "unknown"
    )
