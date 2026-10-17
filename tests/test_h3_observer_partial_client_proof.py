"""Canonical real-chain source fixtures for a no-stop failed start. Never run here."""

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from experiments.formal_campaign.h3_observer_loss import verify_first_request_prefix
from vllm_hust_ext.exposure_gate import GateError


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


class PartialOriginalClientProofTests(unittest.TestCase):
    def setup_packet(self, root):
        client = {"pid": 111, "start_ticks": 222, "boot_id": "test-only-boot"}
        spec = {
            "start_id": "test-only",
            "initial_enrollment_sha256": "test-only-enrollment",
            "request_count": 60,
            "concurrency": 8,
            "interval_s": 0.2,
            "timeout_s": 10,
            "dispatch_slack_s": 0.5,
            "retry_policy": "single-attempt-no-retry",
            "payload": {"prompt": "test-only", "model": "test-only", "max_tokens": 1},
        }
        path = root / "runtime-client-spec.json"
        path.write_bytes(canonical(spec) + b"\n")
        first = {
            "schema": "ecpa-h3-client-window/v1",
            "sequence": 1,
            "previous_sha256": "sha256:" + "0" * 64,
            "client": client,
            "monotonic_ns": 250,
            "kind": "client.start",
            "detail": {
                "start_id": "test-only",
                "spec_sha256": "sha256:"
                + hashlib.sha256(path.read_bytes()).hexdigest(),
            },
        }
        second = {
            "schema": "ecpa-h3-client-window/v1",
            "sequence": 2,
            "previous_sha256": "sha256:" + hashlib.sha256(canonical(first)).hexdigest(),
            "client": client,
            "monotonic_ns": 270,
            "kind": "request.start",
            "detail": {
                "request_id": "test-only/request-00000",
                "body_base64": base64.b64encode(canonical(spec["payload"])).decode(),
            },
        }
        prefix = root / "runner-pre-fault-client-prefix.bin"
        prefix.write_bytes(canonical(first) + b"\n" + canonical(second) + b"\n")
        barrier = {
            "client_prefix": {
                "path": str(prefix),
                "sha256": "sha256:" + hashlib.sha256(prefix.read_bytes()).hexdigest(),
            },
            "enrollment_sha256": "test-only-enrollment",
            "client_started_ns": 250,
            "first_request_started_ns": 270,
            "observed_ns": 280,
        }
        return path, prefix, barrier, client

    def test_actual_request_start_chain_without_client_stop_remains_source_proof(self):
        with tempfile.TemporaryDirectory() as td:
            path, prefix, barrier, client = self.setup_packet(Path(td))
            self.assertTrue(
                verify_first_request_prefix(
                    prefix,
                    barrier,
                    start_id="test-only",
                    enrollment="test-only-enrollment",
                    client_spec_path=path,
                    expected_client=client,
                    fault_ns=300,
                )
            )
            self.assertNotIn(b"client.stop", prefix.read_bytes())

    def test_another_client_epoch_cannot_substitute_partial_source_proof(self):
        with tempfile.TemporaryDirectory() as td:
            path, prefix, barrier, _ = self.setup_packet(Path(td))
            with self.assertRaises(GateError):
                verify_first_request_prefix(
                    prefix,
                    barrier,
                    start_id="test-only",
                    enrollment="test-only-enrollment",
                    client_spec_path=path,
                    expected_client={"pid": 999},
                    fault_ns=300,
                )

    def test_changed_prefix_cannot_reuse_prefault_digest(self):
        with tempfile.TemporaryDirectory() as td:
            path, prefix, barrier, client = self.setup_packet(Path(td))
            prefix.write_bytes(prefix.read_bytes() + b"corruption")
            with self.assertRaises(GateError):
                verify_first_request_prefix(
                    prefix,
                    barrier,
                    start_id="test-only",
                    enrollment="test-only-enrollment",
                    client_spec_path=path,
                    expected_client=client,
                    fault_ns=300,
                )
