"""Future source-only three-arm confound tests; NOT RUN."""

import copy

import pytest
from experiments.formal_campaign.conditional_registration import require_same_activation


def phase():
    return dict(
        python="/new-private/python",
        cwd="/new-manager",
        served_model="original-model",
        host_argv=["actual-host", "--max-num-seqs", "1"],
        manager_config=dict(path="/frozen-actual-config", sha256="a" * 64),
        environment=dict(
            HTTP_PROXY="unit-transport",
            PYTHONPATH="/new-sdk:/CANN/python",
            ECPA_H4_CONDITIONAL_ACTIVATION="ecpa",
            ECPA_H4_RUN_DIRECTORY="/actual/11",
            ECPA_H4_CONDITIONAL_SELECTION_CONTEXT="/actual/11/selection-context.json",
        ),
    )


def test_original_slot_route_and_owned_paths_can_differ():
    a = phase()
    b = copy.deepcopy(a)
    b["environment"].update(
        ECPA_H4_CONDITIONAL_ACTIVATION="manual-integration",
        ECPA_H4_RUN_DIRECTORY="/actual/12",
        ECPA_H4_CONDITIONAL_SELECTION_CONTEXT="/actual/12/selection-context.json",
    )
    require_same_activation(a, b)


@pytest.mark.parametrize(
    "field,value",
    [
        ("host_argv", ["actual-host", "--max-num-seqs", "2"]),
        ("manager_config", dict(path="/another-config", sha256="a" * 64)),
        ("python", "/old-runtime/python"),
        ("served_model", "other-model"),
    ],
)
def test_original_arm_semantics_cannot_change(field, value):
    a = phase()
    b = copy.deepcopy(a)
    b[field] = value
    with pytest.raises(ValueError, match="three arms"):
        require_same_activation(a, b)


@pytest.mark.parametrize(
    "field,value",
    [
        ("HTTP_PROXY", "different-transport"),
        ("PYTHONPATH", "/old-sdk:/CANN/python"),
        ("POLICY_PARAMETER", "different-value"),
    ],
)
def test_original_arm_runtime_environment_cannot_change(field, value):
    a = phase()
    b = copy.deepcopy(a)
    b["environment"][field] = value
    with pytest.raises(ValueError, match="three arms"):
        require_same_activation(a, b)
