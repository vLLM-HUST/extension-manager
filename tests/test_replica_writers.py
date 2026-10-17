"""Prospective unit cases only. Written but NOT EXECUTED during H4 measurement."""

from copy import deepcopy
from pathlib import Path

from vllm_hust_ext.providers.replica_writers import inspect_pinned_configuration

SOURCES = (
    Path(__file__).resolve().parents[1]
    / "experiments"
    / "real_mod_composition"
    / "artifacts"
    / "h2-external-writer-source-adapter-20261017"
)


def config():
    # Same raw configuration surface as the historical without_report specimen;
    # no ownership_conflicts or oracle verdict is supplied.
    return {
        "chart": "vllm/vllm-stack",
        "release": "vllm",
        "namespace": "default",
        "values": {
            "servingEngineSpec": {
                "modelSpec": [
                    {"name": "llama3", "replicaCount": 1, "keda": {"enabled": False}}
                ]
            }
        },
    }


def scaler():
    # Unit fixture; target fields intentionally absent to test exact KEDA
    # 59815 Go defaults, rather than introducing a live discovery prerequisite.
    return {
        "apiVersion": "keda.sh/v1alpha1",
        "kind": "ScaledObject",
        "metadata": {
            "name": "vllm-scaledobject",
            "namespace": "default",
            "uid": "so-1",
        },
        "spec": {
            "scaleTargetRef": {"name": "vllm-llama3-deployment-vllm"},
            "triggers": [{"type": "prometheus"}],
        },
    }


def analyze(c=None, objects=None, source_root=SOURCES):
    return inspect_pinned_configuration(
        config() if c is None else c,
        [scaler()] if objects is None else objects,
        source_root=source_root,
    )[0]


def test_derived_conflict_without_diagnosis():
    result = analyze()
    assert result.decision == "conflict"
    assert set(result.owners) == {"helm:default/vllm", "keda:default/vllm-scaledobject"}


def test_delegation_has_one_writer():
    c = config()
    c["values"]["servingEngineSpec"]["modelSpec"][0]["keda"]["enabled"] = True
    assert analyze(c).decision == "no-conflict-in-declared-inventory"


def test_different_namespace_is_not_shared_target():
    obj = scaler()
    obj["metadata"]["namespace"] = "other"
    assert analyze(objects=[obj]).decision == "no-conflict-in-declared-inventory"


def test_different_name_is_not_shared_target():
    obj = scaler()
    obj["spec"]["scaleTargetRef"]["name"] = "other"
    assert analyze(objects=[obj]).decision == "no-conflict-in-declared-inventory"


def test_different_explicit_kind_stays_unknown():
    obj = scaler()
    obj["spec"]["scaleTargetRef"]["kind"] = "StatefulSet"
    assert analyze(objects=[obj]).decision == "unknown"


def test_duplicate_same_registered_provider_not_two_writers():
    obj = scaler()
    assert len(analyze(objects=[obj, deepcopy(obj)]).owners) == 2  # Helm + ONE KEDA


def test_conflicting_observation_of_same_provider_unknown():
    obj = scaler()
    changed = deepcopy(obj)
    changed["spec"]["triggers"] = [{"type": "cpu"}]
    assert analyze(objects=[obj, changed]).decision == "unknown"


def test_keda_owned_hpa_not_counted_as_second_autoscaler():
    c = config()
    c["values"]["servingEngineSpec"]["modelSpec"][0]["keda"]["enabled"] = True
    hpa = {
        "apiVersion": "autoscaling/v2",
        "kind": "HorizontalPodAutoscaler",
        "metadata": {
            "name": "child",
            "namespace": "default",
            "ownerReferences": [
                {
                    "apiVersion": "keda.sh/v1alpha1",
                    "kind": "ScaledObject",
                    "name": "vllm-scaledobject",
                    "uid": "so-1",
                    "controller": True,
                }
            ],
        },
        "spec": {
            "scaleTargetRef": {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "name": "vllm-llama3-deployment-vllm",
            }
        },
    }
    assert analyze(c, [scaler(), hpa]).decision == "no-conflict-in-declared-inventory"
    hpa["metadata"]["ownerReferences"][0]["uid"] = "wrong"
    assert analyze(c, [scaler(), hpa]).decision == "unknown"


def test_missing_configuration_is_unknown():
    assert analyze({}).decision == "unknown"


def test_missing_source_is_unknown():
    assert analyze(source_root=None).decision == "unknown"


def test_unknown_paused_semantics_is_unknown():
    obj = scaler()
    obj["metadata"]["annotations"] = {"autoscaling.keda.sh/paused": "true"}
    assert analyze(objects=[obj]).decision == "unknown"


def test_oracle_flags_do_not_drive_result():
    c = config()
    c["ownership_conflicts"] = []
    c["oracle_decision"] = "admit"
    assert analyze(c).decision == "conflict"
    c["ownership_conflicts"] = ["made up diagnosis"]
    assert analyze(c, []).decision == "no-conflict-in-declared-inventory"


def test_bool_replica_count_is_not_integer_fact():
    c = config()
    c["values"]["servingEngineSpec"]["modelSpec"][0]["replicaCount"] = True
    assert analyze(c).decision == "unknown"


def test_missing_target_name_is_unknown():
    obj = scaler()
    obj["spec"]["scaleTargetRef"] = {}
    assert analyze(objects=[obj]).decision == "unknown"
