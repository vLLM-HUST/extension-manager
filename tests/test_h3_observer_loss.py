"""Meaningful candidate tests, source only. NOT RUN in the active NPU window."""

import copy
import unittest
from unittest.mock import patch

from experiments.formal_campaign.h3_observer_loss import (
    BINDING,
    RAW,
    observe_and_fault,
    validate_raw,
)
from vllm_hust_ext.exposure_gate import GateError


class ObserverLossEvidenceTests(unittest.TestCase):
    def setUp(self):
        # Test-only symbolic epoch values; never campaign registrations/evidence.
        self.bound = {
            "schema": BINDING,
            "start_id": "test-only",
            "observer": {"test_epoch": "observer"},
            "authority": {"test_epoch": "authority"},
            "observed_ns": 10,
        }
        self.raw = {
            "schema": RAW,
            "start_id": "test-only",
            "binding": self.bound,
            "fault": {
                "target": self.bound["observer"],
                "triggered_ns": 20,
                "signal": "SIGKILL",
            },
            "pidfd_observed_dead_ns": 25,
        }
        self.events = [
            {
                "kind": "route.closed",
                "authority": self.bound["authority"],
                "monotonic_ns": 24,
                "route": {"generation": None},
                "detail": {"reason": "original observer lost"},
            },
            {
                "kind": "observer.loss.observed",
                "authority": self.bound["authority"],
                "monotonic_ns": 26,
                "route": {"generation": None},
                "detail": {"observer": self.bound["observer"]},
            },
        ]

    def assess(self, raw=None, events=None, hosts=None):
        return validate_raw(
            raw or self.raw,
            self.bound,
            authority_events=self.events if events is None else events,
            independent_host_kernels=[
                {"test_epoch": "api"},
                {"test_epoch": "worker0"},
                {"test_epoch": "worker1"},
            ]
            if hosts is None
            else hosts,
            original_host_kernels=[
                {"test_epoch": "api"},
                {"test_epoch": "worker0"},
                {"test_epoch": "worker1"},
            ],
        )

    def test_real_fault_does_not_claim_original_objective_or_formal_admission(self):
        result = self.assess()
        self.assertIs(result["objective_met"], None)
        self.assertIs(result["formal_result"], False)

    def test_worker_raw_cannot_be_relabelled(self):
        raw = copy.deepcopy(self.raw)
        raw["schema"] = "ecpa-h3-worker-raw-recovery/v1"
        with self.assertRaises(GateError):
            self.assess(raw=raw)

    def test_downstream_host_loss_is_retained_as_failure_without_relabeling_fault(self):
        result = self.assess(hosts=[None, None, None])
        self.assertIs(result["actual_observer_fault_observed"], True)
        self.assertIs(result["host_preserved_after_fault"], False)

    def test_source_owned_closed_route_is_mandatory(self):
        with self.assertRaises(GateError):
            self.assess(events=self.events[1:])

    def test_reopening_after_observer_loss_is_rejected(self):
        events = self.events + [{"kind": "route.open.applied", "monotonic_ns": 30}]
        with self.assertRaises(GateError):
            self.assess(events=events)

    def test_stale_authority_fails_before_pidfd_or_signal(self):
        bound = dict(self.bound, authority={"pid": 7})
        with (
            patch(
                "experiments.formal_campaign.h3_observer_loss.identity",
                return_value={"pid": 8},
            ),
            patch(
                "experiments.formal_campaign.h3_observer_loss.os.pidfd_open"
            ) as opened,
            patch(
                "experiments.formal_campaign.h3_observer_loss.signal.pidfd_send_signal"
            ) as sent,
        ):
            with self.assertRaises(GateError):
                observe_and_fault(
                    bound,
                    authority={"pid": 7},
                    source_ref={},
                    expected_argv=[],
                    start_id="test-only",
                    enrollment="unused",
                    timeout_s=1,
                    before_signal=lambda: self.fail("must not reach barrier"),
                )
            opened.assert_not_called()
            sent.assert_not_called()
