"""Portable CPU-only source boundaries; typed fixtures never represent live proof."""

import copy
import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1] / "experiments/formal_campaign"
SMI = b"""| 0     910B2               | OK | 0 / 0 |
| 0 | 0000:C1:00.0 | 0 | 0 / 0 60918/ 65536 |
| 3     910B2               | OK | 0 / 0 |
| 0 | 0000:82:00.0 | 0 | 0 / 0 60843/ 65536 |
"""


def module(name):
    spec = importlib.util.spec_from_file_location(name, BASE / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


pair = module("h4_pair_activation")
npu = module("h4_npu_observation")


class PairBoundaries(unittest.TestCase):
    def setUp(self):
        self.host = {
            "pid": 100,
            "start_ticks": 20,
            "session": 100,
            "boot_id": "CPU-FIXTURE-ONLY",
        }
        self.launch = {
            "VLLM_ECPA_PLAN_ID": "a" * 64,
            "VLLM_ECPA_LAUNCH_ID": "00000000-0000-4000-8000-000000000000",
        }
        self.kernels = {}
        events = []
        for role, ordinal, pid in [
            ("api-server", 0, 100),
            ("engine-core-scheduler", 0, 101),
            ("worker", 0, 102),
            ("worker", 1, 103),
        ]:
            self.kernels[pid] = {**self.host, "pid": pid}
            for name, value in pair.EPS.items():
                process = {
                    "host": "CPU-FIXTURE",
                    "role": role,
                    "ordinal": ordinal,
                    "pid": pid,
                    "start_identity": f"pid:{pid}:start_ticks:20",
                    "process_epoch": pid,
                    "assignment_source": "host",
                }
                ep = {"group": "vllm.general_plugins", "name": name, "value": value}
                event = {
                    "schema": "vllm-hust-plugin-evidence/0.1",
                    "event": "invoked",
                    "observation_kind": "loader_lifecycle",
                    "entry_point": ep,
                    "process": process,
                    "observed_at_ns": 100,
                    "delivery_attempt": 1,
                    "plan_id": self.launch["VLLM_ECPA_PLAN_ID"],
                    "launch_id": self.launch["VLLM_ECPA_LAUNCH_ID"],
                    "binding_status": "bound",
                    "occurrence_id": None,
                    "controller_instance_id": None,
                    "invocation_seq": None,
                    "dispatch_id": None,
                    "plugin_id": None,
                    "artifact_digest": None,
                    "identity_status": "launch-bound",
                    "detail": None,
                }
                material = [
                    process["host"],
                    pid,
                    process["start_identity"],
                    pid,
                    role,
                    ordinal,
                    ep["group"],
                    name,
                    value,
                    "invoked",
                    None,
                    None,
                    event["plan_id"],
                    event["launch_id"],
                    "loader_lifecycle",
                    None,
                    1,
                    100,
                    "host",
                ]
                event["event_id"] = pair.sha(
                    json.dumps(material, separators=(",", ":")).encode()
                )
                events.append(event)
        self.raw = b"".join(pair.canonical(e) + b"\n" for e in events)

    def roster(self, raw=None):
        return pair.source_owned_roster(
            self.raw if raw is None else raw,
            self.launch,
            self.host,
            self.kernels.__getitem__,
            descendant_check=lambda pid, ancestor: True,
        )

    def test_typed_fixture_is_only_boundary_regression(self):
        r = self.roster()
        self.assertEqual(set(r), set(pair.EPS))
        self.assertTrue(
            all(
                set(x)
                == {"api-server/0", "engine-core-scheduler/0", "worker/0", "worker/1"}
                for x in r.values()
            )
        )

    def test_one_EP_cannot_fill_both(self):
        raw = (
            b"\n".join(
                line
                for line in self.raw.splitlines()
                if json.loads(line)["entry_point"]["name"]
                != "request_lifecycle_profiler"
            )
            + b"\n"
        )
        with self.assertRaisesRegex(ValueError, "coverage incomplete"):
            self.roster(raw)

    def test_profiler_scheduler_invoked_cannot_be_effective(self):
        raw = (
            b"\n".join(
                line
                for line in self.raw.splitlines()
                if not (
                    json.loads(line)["entry_point"]["name"]
                    == "request_lifecycle_profiler"
                    and json.loads(line)["process"]["role"] == "engine-core-scheduler"
                    and json.loads(line)["event"] == "invoked"
                )
            )
            + b"\n"
        )
        with self.assertRaisesRegex(ValueError, "coverage incomplete"):
            self.roster(raw)

    def test_raw_event_tamper_rejected(self):
        lines = self.raw.splitlines()
        r = json.loads(lines[0])
        r["process"]["pid"] += 1
        lines[0] = json.dumps(r).encode()
        with self.assertRaises((ValueError, KeyError)):
            self.roster(b"\n".join(lines) + b"\n")

    def test_stale_kernel_rejected(self):
        bad = copy.deepcopy(self.kernels)
        bad[self.host["pid"]]["start_ticks"] += 1
        with self.assertRaisesRegex(ValueError, "live process tree"):
            pair.source_owned_roster(
                self.raw,
                self.launch,
                self.host,
                bad.__getitem__,
                descendant_check=lambda pid, ancestor: True,
            )

    def test_partial_original_line_rejected(self):
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.roster(self.raw[:-1])

    def test_source_path_byte_change_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "source"
            p.write_bytes(b"original")
            ref = pair.reference(p)
            p.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "changed"):
                pair.checked(ref)

    def test_no_existing_receipt_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "receipt"
            pair.save(p, b"original")
            with self.assertRaises(FileExistsError):
                pair.save(p, b"replacement")
            self.assertEqual(p.read_bytes(), b"original")

    def test_fake_CPU_host_is_not_admitted(self):
        spec = {
            "python": sys.executable,
            "manager_repository_root": str(BASE.parents[1]),
            "health_url": "http://127.0.0.1:29712/health",
            "host_commands": {"ecpa": [sys.executable, "-c", 'print("fake")']},
        }
        with self.assertRaisesRegex(ValueError, "real installed vLLM"):
            pair.validate_registered_commands(spec)

    def test_wrong_selected_interpreter_rejected(self):
        with self.assertRaisesRegex(ValueError, "selected interpreter"):
            pair.validate_registered_commands({"python": "/usr/bin/false"})

    def test_actual_old_hbm_shape_not_performance(self):
        raw = SMI
        self.assertEqual(npu.hbm_bytes(raw), (60918 + 60843) * 1024 * 1024)

    def test_missing_device_is_not_zero(self):
        raw = SMI
        raw = re.sub(rb"(?m)^\|\s*3\s+910B2.*\n\|\s*0\s*\|.*\n", b"", raw)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            npu.hbm_bytes(raw)

    def test_invalid_memory_total_rejected(self):
        raw = SMI.replace(b"60918/ 65536", b"70000/ 65536")
        with self.assertRaisesRegex(ValueError, "invalid"):
            npu.hbm_bytes(raw)


if __name__ == "__main__":
    unittest.main()
