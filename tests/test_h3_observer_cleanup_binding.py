"""Negative cross-run cleanup substitution tests. Source only; never evidence."""

import base64
import copy
import hashlib
import unittest

from experiments.formal_campaign.h3_observer_cleanup import (
    SCHEMA,
    ordered_kernels,
    verify,
)
from vllm_hust_ext.exposure_gate import GateError


def kernel(pid):
    return {
        "pid": pid,
        "start_ticks": pid * 100,
        "session": pid,
        "boot_id": "test-only-boot",
    }


class ExactCleanupBindingTests(unittest.TestCase):
    def setUp(self):
        self.epochs = {
            "authority": kernel(1),
            "carrier": kernel(2),
            "host": [kernel(3), kernel(4), kernel(5)],
            "collector": kernel(6),
            "client": kernel(7),
        }
        self.owned = ordered_kernels([kernel(n) for n in range(1, 8)])
        self.context = {
            "start_id": "test-only-slot",
            "campaign_sha256": "test-only-campaign",
            "receipt_sha256": "test-only-receipt",
            "external_references": [],
        }
        self.policy = {
            "allocated_devices": [0, 3],
            "npu_command": ["/usr/local/sbin/npu-smi", "info"],
            "external_services": [],
        }
        npu = (
            b"No running processes found in NPU 0\n"
            b"No running processes found in NPU 3\n"
        )
        self.after = {
            "schema": SCHEMA,
            "context": self.context,
            "stage": "after-cleanup",
            "run_epochs": self.epochs,
            "observed_ns": 500,
            "boot_id": "test-only-boot",
            "owned_kernels": self.owned,
            "process_samples": [
                {"expected": k, "stat_raw": None, "observed_ns": 450}
                for k in self.owned
            ],
            "owned_survivors": [],
            "external_services": [],
            "tcp_tables": {
                "tcp": base64.b64encode(b"header\n").decode(),
                "tcp6": base64.b64encode(b"header\n").decode(),
            },
            "listeners": [],
            "ports": [29611, 29621],
            "devices": [0, 3],
            "npu_argv": self.policy["npu_command"],
            "npu_exit": 0,
            "npu_stdout_base64": base64.b64encode(npu).decode(),
            "npu_stdout_sha256": hashlib.sha256(npu).hexdigest(),
        }
        self.before = copy.deepcopy(self.after)
        self.before.update(
            stage="before-product",
            run_epochs=None,
            observed_ns=100,
            owned_kernels=[],
            process_samples=[],
        )
        self.clocks = {
            "terminal_kind": "complete-client-window",
            "launch_ns": 200,
            "fault_ns": 300,
            "dead_ns": 350,
            "client_stop_ns": 400,
            "terminal_ns": 410,
            "cleanup_started_ns": 420,
            "recorded_ns": 600,
        }

    def assess(self, before=None, after=None):
        return verify(
            before or self.before,
            after or self.after,
            self.policy,
            context=self.context,
            run_epochs=self.epochs,
            owned_kernels=self.owned,
            ports=[29611, 29621],
            clocks=self.clocks,
        )

    def test_exact_complete_cleanup_is_scored_from_raw_samples(self):
        self.assertTrue(all(self.assess().values()))

    def test_another_clean_start_pair_cannot_authorize_current_start(self):
        before = copy.deepcopy(self.before)
        after = copy.deepcopy(self.after)
        before["context"]["start_id"] = after["context"]["start_id"] = (
            "another-test-only-slot"
        )
        with self.assertRaises(GateError):
            self.assess(before, after)

    def test_same_policy_but_different_actual_authority_epoch_is_rejected(self):
        after = copy.deepcopy(self.after)
        after["run_epochs"]["authority"] = kernel(99)
        with self.assertRaises(GateError):
            self.assess(after=after)

    def test_omitted_owned_epochs_cannot_turn_empty_survivors_into_cleanup(self):
        after = copy.deepcopy(self.after)
        after["owned_kernels"] = []
        after["process_samples"] = []
        with self.assertRaises(GateError):
            self.assess(after=after)

    def test_omitted_registered_ports_are_rejected(self):
        after = copy.deepcopy(self.after)
        after["ports"] = []
        with self.assertRaises(GateError):
            self.assess(after=after)

    def test_false_empty_listener_summary_is_recomputed_from_raw_tcp(self):
        after = copy.deepcopy(self.after)
        raw = b"header\n0: 0100007F:73AB 00000000:0000 0A 0:0 0:0 0 0 0 123\n"
        after["tcp_tables"]["tcp"] = base64.b64encode(raw).decode()
        with self.assertRaises(GateError):
            self.assess(after=after)

    def test_false_empty_survivors_are_recomputed_from_actual_stat(self):
        after = copy.deepcopy(self.after)
        sample = after["process_samples"][0]
        k = sample["expected"]
        fields = ["0"] * 22
        fields[0] = "S"
        fields[3] = str(k["session"])
        fields[19] = str(k["start_ticks"])
        sample["stat_raw"] = str(k["pid"]) + " (test-only) " + " ".join(fields)
        with self.assertRaises(GateError):
            self.assess(after=after)

    def test_before_terminal_witness_cannot_authorize_later_cleanup(self):
        after = copy.deepcopy(self.after)
        after["observed_ns"] = 405
        with self.assertRaises(GateError):
            self.assess(after=after)

    def test_partial_failed_start_cleanup_uses_real_runner_terminal_without_stop(self):
        self.clocks.update(
            terminal_kind="independent-runner-failed-start", client_stop_ns=None
        )
        self.assertTrue(all(self.assess().values()))

    def test_partial_wrong_actual_collector_epoch_still_rejects_cleanup(self):
        self.clocks.update(
            terminal_kind="independent-runner-failed-start", client_stop_ns=None
        )
        after = copy.deepcopy(self.after)
        after["run_epochs"]["collector"] = kernel(98)
        with self.assertRaises(GateError):
            self.assess(after=after)

    def test_partial_cannot_fabricate_client_stop_to_authorize_cleanup(self):
        self.clocks.update(
            terminal_kind="independent-runner-failed-start", client_stop_ns=400
        )
        with self.assertRaises(GateError):
            self.assess()

    def test_external_historical_epoch_is_checked_against_frozen_identity_bytes(self):
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "external-identity.json"
            path.write_text(json.dumps(kernel(99)))
            ref = {
                "path": str(path),
                "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            service = {"name": "test-only-external", "identity_reference": ref}
            self.policy["external_services"] = [service]
            self.context["external_references"] = [service]
            self.before["context"] = copy.deepcopy(self.context)
            self.after["context"] = copy.deepcopy(self.context)
            record = dict(service, kernel=kernel(99))
            self.before["external_services"] = copy.deepcopy([record])
            self.after["external_services"] = copy.deepcopy([record])
            with patch(
                "experiments.formal_campaign.h3_observer_cleanup.identity",
                side_effect=AssertionError(
                    "offline history must not require current liveness"
                ),
            ):
                self.assertTrue(all(self.assess().values()))
                self.before["external_services"][0]["kernel"] = kernel(100)
                self.after["external_services"][0]["kernel"] = kernel(100)
                with self.assertRaises(GateError):
                    self.assess()
