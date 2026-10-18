"""Real tiny payload capture and late-mutation negatives; no actual wheel reads."""

import importlib.util
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from experiments.formal_campaign import h3_observer_registration as registration
from experiments.native_attention_candidate import live_route_reader as routes
from vllm_hust_ext.exposure_gate import GateError

fixture_spec = importlib.util.spec_from_file_location(
    "capture_tiny_fixtures", Path(__file__).with_name("test_native_role_parallel.py")
)
fixtures = importlib.util.module_from_spec(fixture_spec)
fixture_spec.loader.exec_module(fixtures)


class PayloadCaptureTests(unittest.TestCase):
    def setUp(self):
        fixtures.ParallelRoleTests.setUp(self)

    def tearDown(self):
        fixtures.ParallelRoleTests.tearDown(self)

    def capture(self):
        return routes._audit_cell_inputs_with_payloads(
            self.fixture.config, self.fixture.recipe
        )

    def check(self, audit, installed):
        routes._check_captured_payloads(
            self.fixture.wheels, installed, audit["file_state"]
        )

    def test_same_actual_mapping_and_original_evidence(self):
        expected = fixtures.old.audit_cell_inputs(
            self.fixture.config, self.fixture.recipe
        )
        actual, installed = self.capture()
        self.assertEqual(actual, expected)
        self.assertEqual(
            actual["installed_payload_sha256"],
            routes.registry.sha(routes.registry.canonical(installed)),
        )
        self.check(actual, installed)

    def test_consumer_reads_each_wheel_once_without_second_payload_hash(self):
        audit = routes.audit_cell_inputs(self.fixture.config, self.fixture.recipe)
        wheel_paths = {row["path"] for row in self.fixture.wheels.values()}
        calls = []
        original = routes._hash

        def counted(path, states=None):
            if str(path) in wheel_paths:
                calls.append(str(path))
            return original(path, states)

        with patch.object(routes, "_hash", counted):
            fresh, installed = registration._native_wheel_payloads(audit)
        self.assertEqual(fresh, audit)
        self.assertEqual(len(calls), 7)
        self.assertEqual(set(calls), wheel_paths)
        self.assertTrue(installed)

    def test_late_actual_member_mutation_rejects(self):
        audit, installed = self.capture()
        path = self.fixture.site / self.fixture.modules["host"] / "data.py"
        path.write_bytes(b"AFTER_CAPTURE = 1\n")
        with self.assertRaisesRegex(ValueError, "audited input file changed"):
            self.check(audit, installed)

    def test_late_extra_source_and_extensionless_elf_reject(self):
        audit, installed = self.capture()
        for name, raw in [
            ("late.py", b"EXTRA = 1\n"),
            ("native_blob", b"\x7fELFextra"),
        ]:
            path = self.fixture.site / self.fixture.modules["host"] / name
            path.write_bytes(raw)
            try:
                with self.assertRaisesRegex(ValueError, "unrecorded installed"):
                    self.check(audit, installed)
            finally:
                path.unlink()

    def test_late_wheel_same_bytes_inode_replacement_rejects(self):
        audit, installed = self.capture()
        wheel = Path(self.fixture.wheels["host"]["path"])
        replacement = wheel.with_suffix(".new")
        replacement.write_bytes(wheel.read_bytes())
        os.replace(replacement, wheel)
        with self.assertRaisesRegex(ValueError, "audited input file changed"):
            self.check(audit, installed)

    def test_late_metadata_version_rejects(self):
        audit, installed = self.capture()
        path = self.fixture.site / "vllm-0.0.1.dist-info" / "METADATA"
        path.write_bytes(b"Name: vllm\nVersion: 9.0\n")
        with self.assertRaisesRegex(ValueError, "installed wheel version differs"):
            self.check(audit, installed)

    def test_late_equal_version_distribution_origin_rejects(self):
        audit, installed = self.capture()
        alternate = self.root / "alternate-origin/vllm-0.0.1.dist-info"
        alternate.mkdir(parents=True)
        (alternate / "METADATA").write_bytes(b"Name: vllm\nVersion: 0.0.1\n")
        actual_distribution = routes.metadata.distribution

        def replaced(distribution):
            return (
                routes.metadata.PathDistribution(alternate)
                if distribution == "vllm"
                else actual_distribution(distribution)
            )

        with (
            patch.object(routes.metadata, "distribution", replaced),
            self.assertRaisesRegex(ValueError, "distribution origin changed"),
        ):
            self.check(audit, installed)

    def test_original_skipped_noncode_asset_link_remains_accepted(self):
        module = self.fixture.modules["host"]
        wheel = Path(self.fixture.wheels["host"]["path"])
        import zipfile

        with zipfile.ZipFile(wheel, "a") as archive:
            archive.writestr(module + "/asset.txt", b"noncode")
        self.fixture.wheels["host"]["sha256"] = fixtures.digest(wheel.read_bytes())
        config = json.loads(self.fixture.config.read_text())
        config["wheel_artifacts"] = self.fixture.wheels
        self.fixture.config.write_text(json.dumps(config))
        target = self.root / "noncode-target"
        target.write_bytes(b"noncode")
        (self.fixture.site / module / "asset.txt").symlink_to(target)
        audit, installed = self.capture()
        self.check(audit, installed)

    def test_tampered_captured_mapping_cannot_authorize_consumer(self):
        audit = routes.audit_cell_inputs(self.fixture.config, self.fixture.recipe)
        actual_capture = routes._audit_cell_inputs_with_payloads

        def tamper(*args, **kwargs):
            fresh, installed = actual_capture(*args, **kwargs)
            installed["host"][next(iter(installed["host"]))] = "0" * 64
            return fresh, installed

        with (
            patch.object(routes, "_audit_cell_inputs_with_payloads", tamper),
            self.assertRaisesRegex(
                GateError, "native actual seven-wheel payload inventory changed"
            ),
        ):
            registration._native_wheel_payloads(audit)
