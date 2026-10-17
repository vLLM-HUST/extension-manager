"""Exact Host-seven/kernel-four to sender-ten ABI joins; not runtime evidence."""

import copy
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from test_host_evidence import raw_event

from experiments.formal_campaign import h3_native_authority as authority
from vllm_hust_ext.exposure_gate import GateError
from vllm_hust_ext.host_evidence import parse_host_event


def membership_fixture(monkeypatch):
    kernels = {}
    members = []
    peers = []
    for pid, (role, ordinal) in enumerate(
        [("api-server", 0), ("worker", 0), ("worker", 1)], start=101
    ):
        kernel = dict(pid=pid, start_ticks=pid * 10, session=99, boot_id="CPU-only")
        kernels[pid] = kernel
        process = dict(
            host="CPU-ABI-fixture",
            role=role,
            ordinal=ordinal,
            pid=pid,
            start_identity=f"pid:{pid}:start_ticks:{kernel['start_ticks']}",
            process_epoch=pid + 9000,
            assignment_source="host",
        )
        event = parse_host_event(raw_event(process=process))
        members.append(
            dict(
                role=role,
                ordinal=ordinal,
                identity={**kernel, "launch_id": event["launch_id"]},
                event=event,
            )
        )
        peers.append(dict(process={**process, **kernel}))
    monkeypatch.setattr(
        "experiments.formal_campaign.h3_worker_relaunch.identity",
        lambda pid: copy.deepcopy(kernels[pid]),
    )
    return members, peers


def verify(members, peers):
    authority.verify_native_membership(
        peers,
        members,
        members[0]["event"]["plan_id"],
        members[0]["event"]["launch_id"],
    )


def test_exact_sender_abi_preserves_original_events_and_peers(monkeypatch):
    members, peers = membership_fixture(monkeypatch)
    original = authority.canonical([members, peers])
    assert len(members[0]["event"]["process"]) == 7
    assert len(peers[0]["process"]) == 10
    verify(members, list(reversed(peers)))
    assert authority.canonical([members, peers]) == original


@pytest.mark.parametrize(
    "field,value",
    [
        ("host", "other-host"),
        ("role", "engine-core-scheduler"),
        ("ordinal", 9),
        ("pid", 999),
        ("start_identity", "pid:101:start_ticks:0"),
        ("process_epoch", 0),
        ("assignment_source", "environment"),
        ("start_ticks", 0),
        ("session", 999),
        ("boot_id", "other-boot"),
        ("pid", 101.0),
        ("extra_field", "not-in-ABI"),
    ],
)
def test_each_sender_field_must_match_exactly(monkeypatch, field, value):
    members, peers = membership_fixture(monkeypatch)
    peers[0]["process"][field] = value
    with pytest.raises(GateError):
        verify(members, peers)


@pytest.mark.parametrize("field", ["start_ticks", "session", "boot_id"])
def test_missing_sender_kernel_field_is_rejected(monkeypatch, field):
    members, peers = membership_fixture(monkeypatch)
    del peers[0]["process"][field]
    with pytest.raises(GateError):
        verify(members, peers)


@pytest.mark.parametrize("field", ["start_ticks", "session", "boot_id", "launch_id"])
def test_member_identity_conflict_or_missing_field_rejected(monkeypatch, field):
    members, peers = membership_fixture(monkeypatch)
    del members[0]["identity"][field]
    with pytest.raises(GateError):
        verify(members, peers)


@pytest.mark.parametrize("collection", ["members", "peers"])
def test_duplicate_or_missing_slot_rejected(monkeypatch, collection):
    members, peers = membership_fixture(monkeypatch)
    selected = members if collection == "members" else peers
    selected[-1] = copy.deepcopy(selected[0])
    with pytest.raises(GateError):
        verify(members, peers)
    selected.pop()
    with pytest.raises(GateError):
        verify(members, peers)


def test_stale_host_start_identity_and_cross_launch_rejected(monkeypatch):
    members, peers = membership_fixture(monkeypatch)
    members[1]["event"]["process"]["start_identity"] = "pid:102:start_ticks:0"
    with pytest.raises(GateError):
        verify(members, peers)
    members, peers = membership_fixture(monkeypatch)
    members[1]["event"]["launch_id"] = "other-launch"
    with pytest.raises(GateError):
        verify(members, peers)


@pytest.mark.parametrize("tamper", [False, True])
def test_actual_attach_path_uses_exact_join_before_binding(monkeypatch, tamper):
    members, peers = membership_fixture(monkeypatch)
    if tamper:
        peers[0]["process"]["boot_id"] = "wrong-boot"
    entered = []
    # The independent full roster includes the scheduler. The three native
    # sender join must not reduce that roster or rewrite any of its events.
    full_roster = {
        "api-server/0": {},
        "worker/0": {},
        "worker/1": {},
        "engine-core-scheduler/0": {"original": "untouched"},
    }
    full_kernels = copy.deepcopy(full_roster)

    def bind_actual(*args):
        assert args[2] is full_roster
        assert args[3] is full_kernels
        entered.append(True)
        raise RuntimeError("reached-independent-source-guard")

    instance = object.__new__(authority.NativeAuthority)
    instance.lock = nullcontext()
    instance._lease = lambda: None
    instance._observe_members = lambda supplied: None
    instance.observe_backend = lambda candidate: None
    instance.route = SimpleNamespace(generation=None)
    instance.candidate = (None, object())
    instance.enrollment = dict(
        sha256="enrollment",
        members=members,
        generation=1,
        plan_id=members[0]["event"]["plan_id"],
        launch_id=members[0]["event"]["launch_id"],
    )
    instance.native_plan_guards = [SimpleNamespace(bind_actual=bind_actual)]
    native_enrollment = dict(
        native_plan_id=instance.enrollment["plan_id"],
        native_launch_id=instance.enrollment["launch_id"],
        source_peers=peers,
    )
    error = GateError if tamper else RuntimeError
    with pytest.raises(error):
        instance.attach_actual_epoch(
            "enrollment",
            native_enrollment=native_enrollment,
            handoff=None,
            roster=full_roster,
            kernels=full_kernels,
            host_journal=None,
            descriptor=None,
            spec_path=None,
            policy_path=None,
            drain_path=None,
            socket_path=None,
            journal_path=None,
            snapshots=None,
        )
    assert entered == ([] if tamper else [True])


@pytest.mark.parametrize(
    "field,value",
    [
        ("start_ticks", 0),
        ("session", 0),
        ("boot_id", "wrong"),
        ("launch_id", "wrong"),
        ("pid", 101.0),
    ],
)
def test_conflicting_member_kernel_or_scalar_type_rejected(monkeypatch, field, value):
    members, peers = membership_fixture(monkeypatch)
    members[0]["identity"][field] = value
    with pytest.raises(GateError):
        verify(members, peers)
