"""Original objective bounds remain unchanged; missing duplication never passes."""

from experiments.formal_campaign.h3_dynamic_intake import assess_original_objective


def test_measured_violation_falsifies_but_unknown_never_passes():
    bounds = {
        "max_lost_requests": 0,
        "max_recovery_ms": 1000,
        "max_operator_actions": 0,
    }
    measured = {"lost_requests": 0, "coverage": "complete-finite-delivery-window"}
    result = assess_original_objective(bounds, measured, 500, 0)
    assert result["objective_met"] is None and not result["known_objective_violations"]
    measured = {"lost_requests": 2, "coverage": "recovery-outside-frozen-window"}
    result = assess_original_objective(bounds, measured, 55000, 1)
    assert result["objective_met"] is False
    assert set(result["known_objective_violations"]) == {
        "max_lost_requests",
        "max_recovery_ms",
        "max_operator_actions",
        "original_continuous_client_window",
    }
    assert bounds == {
        "max_lost_requests": 0,
        "max_recovery_ms": 1000,
        "max_operator_actions": 0,
    }


def test_incomplete_actual_window_falsifies_without_inventing_lost_count():
    measured = {"lost_requests": None, "coverage": "coverage-failed"}
    result = assess_original_objective(
        {"max_lost_requests": 0, "max_recovery_ms": 30000, "max_operator_actions": 0},
        measured,
        None,
        0,
    )
    assert result["objective_met"] is False
    assert result["known_objective_violations"] == ["original_continuous_client_window"]
    assert measured["lost_requests"] is None
    assert "backend_execution_duplication" in result["unverified_obligations"]
