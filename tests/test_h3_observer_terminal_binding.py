"""Actual-epoch/terminal-clock negative tests; source only and unrun."""

import copy
import unittest

from experiments.formal_campaign.h3_observer_loss import verify_terminal_witness
from vllm_hust_ext.exposure_gate import GateError


class TerminalWitnessTests(unittest.TestCase):
    def setUp(self):
        self.hosts = [
            {"test-only-epoch": "api"},
            {"test-only-epoch": "worker0"},
            {"test-only-epoch": "worker1"},
        ]
        self.client = {"test-only-epoch": "client"}
        self.trace = [
            {
                "kind": "client.start",
                "monotonic_ns": 250,
                "client": self.client,
                "detail": {"start_id": "test-only"},
            },
            {"kind": "client.stop", "monotonic_ns": 400, "client": self.client},
        ]
        self.account = {
            "host_kernels_at_client_stop": self.hosts,
            "predecessor_alive_through_client_window": True,
            "observed_ns": 410,
            "replacement_committed": False,
        }
        self.witness = {
            "host_kernels": self.hosts,
            "host_preserved": True,
            "client_stop_ns": 400,
            "observed_ns": 420,
            "replacement_committed": False,
        }

    def assess(self, witness=None):
        return verify_terminal_witness(
            self.account,
            witness or self.witness,
            original_host_kernels=self.hosts,
            client_trace=self.trace,
            expected_client=self.client,
            start_id="test-only",
            launch_ns=200,
            dead_ns=350,
        )

    def test_missing_epochs_with_summary_true_retain_known_loss(self):
        witness = copy.deepcopy(self.witness)
        witness["host_kernels"] = [None, None, None]
        result = self.assess(witness)
        self.assertIs(result["host_preserved"], False)
        self.assertIs(result["summary_consistent"], False)

    def test_different_worker_epoch_cannot_be_hidden_by_summary_true(self):
        witness = copy.deepcopy(self.witness)
        witness["host_kernels"][1] = {"test-only-epoch": "replacement"}
        self.assertIs(self.assess(witness)["host_preserved"], False)

    def test_wrong_client_stop_clock_is_rejected(self):
        witness = copy.deepcopy(self.witness)
        witness["client_stop_ns"] = 401
        with self.assertRaises(GateError):
            self.assess(witness)

    def test_summary_flip_is_detected_even_with_correct_epoch_list(self):
        witness = copy.deepcopy(self.witness)
        witness["host_preserved"] = False
        result = self.assess(witness)
        self.assertIs(result["host_preserved"], True)
        self.assertIs(result["summary_consistent"], False)


class IndependentFailedTerminalTests(unittest.TestCase):
    def setUp(self):
        self.context = {"start_id": "test-only-partial"}
        self.epochs = {"test-only-epochs": "independently-captured-seven"}
        self.fault = {
            "target": {"test-only-epoch": "collector"},
            "signal": "SIGKILL",
            "triggered_ns": 300,
        }
        self.marker = {
            "schema": "ecpa-h3-observer-independent-runner-terminal/v1",
            "context": self.context,
            "run_epochs": self.epochs,
            "start_id": "test-only-partial",
            "fault": self.fault,
            "observed_dead_ns": 350,
            "observed_ns": 380,
            "carrier_complete": False,
        }

    def assess(self, marker=None):
        from experiments.formal_campaign.h3_observer_loss import (
            verify_independent_partial_terminal,
        )

        return verify_independent_partial_terminal(
            marker or self.marker,
            context=self.context,
            epochs=self.epochs,
            fault=self.fault,
            dead_ns=350,
            cleanup_started_ns=400,
        )

    def test_actual_failed_terminal_does_not_invent_stop_accounting_or_recovery(self):
        result = self.assess()
        self.assertEqual(result["kind"], "independent-runner-failed-start")
        self.assertIsNone(result["client_stop_ns"])
        self.assertIsNone(result["host_preserved"])
        self.assertNotIn("operator_actions", result)
        self.assertNotIn("recovery_ns", result)

    def test_partial_terminal_from_wrong_actual_epoch_is_rejected(self):
        marker = copy.deepcopy(self.marker)
        marker["run_epochs"] = {"test-only-epochs": "other-run"}
        with self.assertRaises(GateError):
            self.assess(marker)

    def test_partial_terminal_before_actual_observer_death_is_rejected(self):
        marker = copy.deepcopy(self.marker)
        marker["observed_ns"] = 340
        with self.assertRaises(GateError):
            self.assess(marker)

    def test_complete_carrier_cannot_use_partial_terminal_fallback(self):
        marker = copy.deepcopy(self.marker)
        marker["carrier_complete"] = True
        with self.assertRaises(GateError):
            self.assess(marker)
