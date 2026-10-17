"""Pure role-assignment joins; no kernel/model/qualification simulation."""

from copy import deepcopy

import pytest

from experiments.formal_campaign.h3_native_authority import native_host_roster
from vllm_hust_ext.exposure_gate import GateError


def row(pid, role, ordinal, assignment, time):
    return dict(
        plan_id="plan",
        launch_id="launch",
        event="discovered",
        observation_kind="loader_lifecycle",
        observed_at_ns=time,
        process=dict(
            host="actual-host",
            pid=pid,
            role=role,
            ordinal=ordinal,
            assignment_source=assignment,
            start_identity=f"pid:{pid}:start_ticks:12345",
            process_epoch=100000 + pid,
        ),
    )


def actual_shape():
    # Same source lifecycle as r10: three independent unknown/0 slots become
    # one scheduler and worker0/worker1. No process/kernel identity is rewritten.
    rows = [row(10, "api-server", 0, "host", 1)]
    rows += [row(pid, "unknown", 0, "environment", 2) for pid in (20, 30, 40)]
    rows += [
        row(20, "engine-core-scheduler", 0, "host", 3),
        row(30, "worker", 0, "host", 4),
        row(40, "worker", 1, "host", 5),
    ]
    return rows


def test_provisional_rows_join_to_exact_later_host_epoch_without_mutation():
    rows = actual_shape()
    before = deepcopy(rows)
    roster = native_host_roster(rows, "plan", "launch")
    assert set(roster) == {
        "api-server/0",
        "engine-core-scheduler/0",
        "worker/0",
        "worker/1",
    }
    assert rows == before
    assert roster["worker/1"] is rows[-1]["process"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("host", "different-host"),
        ("pid", 999),
        ("start_identity", "pid:20:start_ticks:99999"),
        ("process_epoch", 99999),
        ("process_epoch", 100020.0),
    ],
)
def test_provisional_cannot_hide_identity_change(field, value):
    rows = actual_shape()
    rows[1]["process"][field] = value
    with pytest.raises(GateError, match="lacks a later exact-epoch"):
        native_host_roster(rows, "plan", "launch")


def test_unmatched_unknown_and_wrong_launch_binding_are_rejected():
    for mutation in ("remove", "wrong-launch", "not-later"):
        rows = actual_shape()
        if mutation == "remove":
            del rows[4]
        elif mutation == "wrong-launch":
            rows[4]["launch_id"] = "other-launch"
        else:
            rows[4]["observed_at_ns"] = 2
        with pytest.raises(GateError, match="lacks a later exact-epoch"):
            native_host_roster(rows, "plan", "launch")


@pytest.mark.parametrize("change", ["assigned-role", "unknown-event", "non-loader"])
def test_environment_identity_never_grants_role_authority(change):
    rows = actual_shape()
    if change == "assigned-role":
        rows[1]["process"]["role"] = "worker"
    elif change == "unknown-event":
        rows[1]["event"] = "invoked"
    else:
        rows[1]["observation_kind"] = "native_callback"
    with pytest.raises(GateError, match="not pre-assignment discovery"):
        native_host_roster(rows, "plan", "launch")


def test_real_assigned_slot_conflict_is_not_resolved_by_last_event():
    rows = actual_shape()
    rows.append(row(41, "worker", 1, "host", 6))
    with pytest.raises(GateError, match="native Host role kernel changed"):
        native_host_roster(rows, "plan", "launch")


def test_same_exact_epoch_cannot_acquire_two_host_roles():
    rows = actual_shape()
    rows.append(row(40, "worker", 2, "host", 6))
    with pytest.raises(GateError, match="assigned multiple roles"):
        native_host_roster(rows, "plan", "launch")
