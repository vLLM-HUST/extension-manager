"""Source-issued transport enrollment; original semantic revocation is permanent.

A new transport fence reuses the actual healthy Host membership, never claims a
new Host launch/semantic enrollment, and does not prove any completed request.
"""

from __future__ import annotations

import secrets
import time

from experiments.formal_campaign.h3_dynamic_authority import (
    RouteState,
    canonical,
    digest,
    require,
)
from experiments.formal_campaign.h3_observer_live_launcher import write_private

SCHEMA = "ecpa-h3-observer-transport-enrollment/v2"
DOMAIN = "original-H3-observer-loss-live-transport-only"


def verify_transport(
    value, semantic, *, receipt, descriptor, commit, observed_ns, revoked
):
    require(
        set(value)
        == {
            "schema",
            "domain",
            "semantic_enrollment",
            "successor_descriptor",
            "commit",
            "live_receipt",
            "generation",
            "nonce",
            "issued_ns",
            "sha256",
        },
        "exact transport enrollment fields required",
    )
    unsigned = {k: v for k, v in value.items() if k != "sha256"}
    require(
        value["schema"] == SCHEMA
        and value["domain"] == DOMAIN
        and value["sha256"] == digest(canonical(unsigned))
        and value["semantic_enrollment"] == semantic
        and semantic["sha256"] in revoked
        and value["live_receipt"] == receipt
        and value["successor_descriptor"] == descriptor
        and value["commit"] == commit
        and value["generation"] == semantic["generation"] + 1
        and isinstance(value["nonce"], str)
        and len(value["nonce"]) == 64
        and value["nonce"] != semantic["nonce"],
        "transport receipt/epoch/revocation binding differs",
    )
    require(
        commit["transport_commit_complete"] is True
        and commit["error"] is None
        and commit["generation"] == 1
        and len(commit["prepared"]) == len(commit["committed"]) == 3
        and commit["fault"]["triggered_ns"]
        < commit["observer_dead_ns"]
        <= commit["committed_ns"]
        <= value["issued_ns"]
        <= observed_ns
        <= commit["original_deadline_ns"]
        and commit["original_deadline_ns"]
        == commit["fault"]["triggered_ns"] + 30_000_000_000,
        "actual transport complete/original30s clocks differ",
    )
    # No summary flag replaces exact actual API+TP2 epoch/paired contexts.
    expected = [
        {k: m["identity"][k] for k in ("pid", "start_ticks", "session", "boot_id")}
        for m in semantic["members"]
    ]
    for prepared, committed, kernel in zip(
        commit["prepared"], commit["committed"], expected, strict=True
    ):
        require(
            all(
                prepared["producer"][k] == v and committed["producer"][k] == v
                for k, v in kernel.items()
            )
            and prepared["state"] == "prepared"
            and committed["state"] == "committed"
            and prepared["generation"] == 0
            and committed["generation"] == 1
            and prepared["collector"]
            == committed["collector"]
            == descriptor["collector"]
            and prepared["contexts"] == committed["contexts"]
            and prepared["transition_nonce"]
            == committed["transition_nonce"]
            == commit["transition_nonce"]
            and prepared["receipt_sha256"]
            == committed["receipt_sha256"]
            == receipt["sha256"]
            and prepared["old_client_request_ids"]
            == committed["old_client_request_ids"]
            == commit["old_client_request_ids"],
            "actual producer successor receipt/context/frontier mismatch",
        )
    return value


def routing_copy(value):
    """Private routing view, explicitly distinct from semantic membership proof."""
    return {
        **value["semantic_enrollment"],
        "sha256": value["sha256"],
        "generation": value["generation"],
        "transport_enrollment": value,
    }


def recheck_actual_route(authority):
    value = authority.live_transport_enrollment["transport_enrollment"]
    authority._lease()
    authority._source_current()
    authority.live_grants.recheck()
    require(
        value["semantic_enrollment"] == authority.enrollment
        and authority.enrollment["sha256"] in authority.revoked_enrollments,
        "original semantic enrollment must remain unchanged and permanently revoked",
    )
    require(
        value["sha256"] not in authority.revoked_enrollments,
        "closed transport enrollment cannot be admitted again",
    )
    authority._observe_members(authority.enrollment["members"])
    require(
        authority.observe_backend(authority.candidate[1])
        == authority.enrollment["backend"],
        "original actual backend listener changed",
    )
    bound = authority._epoch(authority.routing_enrollment())
    bound["guard"].validate_current(bound["native_enrollment"], bound["host_journal"])
    require(
        authority.current_observer is not None
        and not authority.observer_lost
        and authority.current_observer[1]["original_collector_identity"]
        == value["successor_descriptor"]["collector"],
        "actual successor observer epoch lost/substituted",
    )
    bound["verifier"]._current()
    return digest(
        canonical(
            {
                "transport_enrollment_sha256": value["sha256"],
                "state": "native-source-prepared-private-only",
            }
        )
    )


def open_actual_successor(authority, coordinator):
    from experiments.formal_campaign.h3_observer_live_rebind import Coordinator

    require(
        type(coordinator) is Coordinator
        and coordinator.authority is authority
        and getattr(coordinator, "attached_commit", None) is not None,
        "actual owned coordinator attachment required; caller JSON cannot enroll",
    )
    with authority.lock:
        require(
            authority.route.generation is None
            and authority.live_transport_enrollment is None
            and authority.enrollment["sha256"] in authority.revoked_enrollments
            and authority.native_epochs[authority.enrollment["sha256"]]["verifier"]
            is coordinator.attached_verifier,
            "original close/revocation/exact attached verifier required",
        )
        descriptor = coordinator.successor[1]
        value = dict(
            schema=SCHEMA,
            domain=DOMAIN,
            semantic_enrollment=authority.enrollment,
            successor_descriptor=descriptor,
            commit=coordinator.attached_commit,
            live_receipt=authority.live_scope.receipt_ref(),
            generation=authority.generation + 1,
            nonce=secrets.token_hex(32),
            issued_ns=time.monotonic_ns(),
        )
        value["sha256"] = digest(canonical(value))
        verify_transport(
            value,
            authority.enrollment,
            receipt=authority.live_scope.receipt_ref(),
            descriptor=descriptor,
            commit=coordinator.attached_commit,
            observed_ns=time.monotonic_ns(),
            revoked=authority.revoked_enrollments,
        )
        view = routing_copy(value)
        authority.native_epochs[view["sha256"]] = authority.native_epochs[
            authority.enrollment["sha256"]
        ]
        authority.live_transport_enrollment = view
        try:
            recheck_actual_route(authority)
            authority.generation = value["generation"]
            authority._record(
                "observer.transport.enrolled", authority.route, transport=value
            )
            authority.route = RouteState(
                value["generation"],
                "observer-live-transport",
                {"transport_enrollment_sha256": value["sha256"]},
            )
            authority._record(
                "observer.transport.route-open",
                authority.route,
                transport_enrollment_sha256=value["sha256"],
            )
            write_private(
                authority.output / "live-route-publication.json",
                {
                    "schema": "ecpa-h3-observer-live-route-publication/v2",
                    "transport": value,
                    "published_ns": time.monotonic_ns(),
                    "formal_result": False,
                },
            )
        except Exception:
            authority._close("live transport open failed")
            raise
        # The independent runner must observe actual successor and old Host.
        # Actual public recovery time can only come from an original request.
        return {"transport_enrollment_sha256": value["sha256"], "recovery_ns": None}
