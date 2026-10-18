"""Real tiny anonymous-pipe/Popen tests; no source qualification or Host facts."""

import ast
import copy
import hashlib
import io
import json
import os
import secrets
import select
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "experiments/formal_campaign/h3_observer_live_operator.py"
TREE = ast.parse(SOURCE.read_bytes())
NAMES = {
    "_send",
    "_receive",
    "_reference",
    "_fault_evidence",
    "PreparedOperator",
    "prepare",
}
MODULE = types.ModuleType("original_operator_transport_under_test")


def require(value, message):
    if not value:
        raise ValueError(message)


def write_private(path, value):
    with Path(path).open("xb") as stream:
        stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
    Path(path).chmod(0o600)
    return MODULE._reference(path)


MODULE.__dict__.update(
    globals(),
    secrets=secrets,
    select=select,
    stat=stat,
    subprocess=subprocess,
    require=require,
    write_private=write_private,
)
exec(
    compile(
        ast.Module(
            body=[
                n
                for n in TREE.body
                if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in NAMES
            ],
            type_ignores=[],
        ),
        str(SOURCE),
        "exec",
    ),
    MODULE.__dict__,
)

FIXTURE = r"""import hashlib, json, os, sys, time
from pathlib import Path


def kernel(pid):
    f = Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()
    return dict(
        pid=pid,
        start_ticks=int(f[19]),
        session=int(f[3]),
        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    )


def ref(path):
    return dict(
        path=str(path), sha256="sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    )


challenge = json.loads(sys.stdin.buffer.readline())
if sys.argv[1] == "no-ready":
    sys.stdin.buffer.readline()
    raise SystemExit(0)
root = Path(sys.argv[2])
parent = kernel(os.getppid())
value = dict(
    schema="ecpa-h3-original-operator-qualified-ready/v1",
    start_id="tiny-nonformal",
    operator=kernel(os.getpid()),
    parent=parent,
    nonce=challenge["nonce"],
    live_receipt=dict(path="/tiny-fixture", sha256="sha256:fixture"),
    recipe=ref(root / "runtime-recipe.json"),
    source=ref(Path(__file__)),
    authority=parent,
    qualification_completed_ns=time.monotonic_ns(),
)
if sys.argv[1] == "wrong-nonce":
    value["nonce"] = "wrong"
if sys.argv[1] == "wrong-source":
    value["source"]["sha256"] = "sha256:wrong"
if sys.argv[1] == "wrong-receipt":
    value["live_receipt"]["path"] = "/another"
if sys.argv[1] == "wrong-kernel":
    value["operator"]["start_ticks"] += 1
if sys.argv[1] == "replace-source":
    content = Path(__file__).read_text()
    Path(__file__).write_text(content + "\n# replaced source bytes\n")
sys.stdout.buffer.write(
    json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
)
sys.stdout.buffer.flush()
sys.stdin.buffer.readline()
"""


class TinyTransportTests(unittest.TestCase):
    def test_real_pipe_roundtrip(self):
        r, w = os.pipe()
        try:
            with os.fdopen(w, "wb") as stream:
                MODULE._send(stream, {"nonce": "actual-anonymous-pipe"})
            self.assertEqual(
                MODULE._receive(r, time.monotonic_ns() + 1_000_000_000),
                {"nonce": "actual-anonymous-pipe"},
            )
        finally:
            os.close(r)

    def test_pipe_eof_rejects(self):
        r, w = os.pipe()
        os.close(w)
        try:
            with self.assertRaises(ValueError):
                MODULE._receive(r, time.monotonic_ns() + 1_000_000_000)
        finally:
            os.close(r)

    def test_absolute_deadline_not_extended_by_wait(self):
        r, w = os.pipe()
        try:
            with self.assertRaises(ValueError):
                MODULE._receive(r, time.monotonic_ns() + 10_000_000)
        finally:
            os.close(r)
            os.close(w)

    def test_noncanonical_and_trailing_frames_reject(self):
        for raw in (b'{"x": 1}\n', b'{"x":1}\n{"x":2}\n'):
            with self.subTest(raw=raw):
                r, w = os.pipe()
                os.write(w, raw)
                os.close(w)
                try:
                    with self.assertRaises(ValueError):
                        MODULE._receive(r, time.monotonic_ns() + 1_000_000_000)
                finally:
                    os.close(r)

    def test_control_frame_bound_unchanged(self):
        with self.assertRaises(ValueError):
            MODULE._send(io.BytesIO(), {"large": "x" * 65536})

    def test_real_reference_handles_large_recipe_but_rejects_mode_and_link(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "recipe.json"
            path.write_bytes(b"x" * 70000)
            path.chmod(0o600)
            self.assertEqual(
                MODULE._reference(path)["sha256"],
                "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
            )
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                MODULE._reference(path)
            link = Path(temp) / "link"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                MODULE._reference(link, 0o644)

    def test_real_prearm_child_and_pidfd_reclaimed(self):
        self.run_child("valid")

    def test_real_prearm_source_mode0600_accepts(self):
        self.run_child("valid-private-source")

    def test_source_reference_allows0600_and0644_but_rejects_writable(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source.py"
            source.write_text("VALUE = 1\n")
            for mode in (0o600, 0o644):
                source.chmod(mode)
                self.assertEqual(
                    MODULE._reference(source, None)["sha256"],
                    "sha256:" + hashlib.sha256(source.read_bytes()).hexdigest(),
                )
            for mode in (0o620, 0o602, 0o666):
                source.chmod(mode)
                with self.assertRaises(ValueError):
                    MODULE._reference(source, None)

    def test_ready_substitutions_reject_and_child_is_reaped(self):
        for mode in (
            "wrong-nonce",
            "wrong-source",
            "wrong-receipt",
            "wrong-kernel",
            "replace-source",
        ):
            with self.subTest(mode=mode):
                self.run_child(mode)

    def test_ready_timeout_reclaims_only_own_child(self):
        self.run_child("no-ready")

    def run_child(self, mode):
        from experiments.formal_campaign.h3_worker_relaunch import identity

        before = len(list(Path("/proc/self/fd").iterdir()))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "tiny_child.py"
            source.write_text(FIXTURE)
            source.chmod(0o600 if mode == "valid-private-source" else 0o644)
            recipe = root / "runtime-recipe.json"
            recipe.write_text("{}")
            recipe.chmod(0o600)
            scope = types.SimpleNamespace(
                value=lambda: dict(
                    declaration=dict(
                        operator=dict(
                            command=[sys.executable, str(source), mode, str(root)]
                        )
                    ),
                    start=dict(start_id="tiny-nonformal"),
                ),
                receipt_ref=lambda: dict(path="/tiny-fixture", sha256="sha256:fixture"),
            )
            children = []

            def cleanup(process, owner, timeout, captured):
                self.assertEqual(owner, identity(process.pid))
                self.assertEqual(captured, [owner])
                process.wait(timeout=2)
                children.append(process)

            actor = None
            try:
                if mode in {"valid", "valid-private-source"}:
                    actor = MODULE.prepare(
                        scope,
                        dict(authority=dict(process_identity=identity(os.getpid()))),
                        root,
                        timeout_s=2,
                        cleanup=cleanup,
                    )
                    self.assertIsNone(actor.process.poll())
                    self.assertLessEqual(
                        actor.ready["qualification_completed_ns"], time.monotonic_ns()
                    )
                else:
                    with self.assertRaises(ValueError):
                        MODULE.prepare(
                            scope,
                            dict(
                                authority=dict(process_identity=identity(os.getpid()))
                            ),
                            root,
                            timeout_s=0.15 if mode == "no-ready" else 2,
                            cleanup=cleanup,
                        )
                    self.assertFalse((root / "live-operator-action.json").exists())
            finally:
                if actor is not None:
                    actor.close(cleanup)
            self.assertTrue(children)
            self.assertTrue(all(c.poll() is not None for c in children))
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())), before)

    def test_actual_fault_pidfd_record_crossjoins(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            owner = dict(pid=10, start_ticks=20, session=10, boot_id="boot")
            target = dict(pid=11, start_ticks=21, session=11, boot_id="boot")
            fault = dict(target=target, signal="SIGKILL", triggered_ns=200)
            raw = dict(
                schema="ecpa-h3-observer-loss-raw/v1",
                start_id="original",
                binding=dict(start_id="original", authority=owner, observer=target),
                fault=fault,
                pidfd_observed_dead_ns=201,
            )

            def save(raw_value, fault_value, dead_value):
                for name, value in (
                    ("observer-fault-raw.json", raw_value),
                    ("runner-fault.json", fault_value),
                    ("runner-observer-dead.json", dead_value),
                ):
                    p = root / name
                    p.write_text(json.dumps(value))
                    p.chmod(0o600)

            save(raw, fault, dict(observed_dead_ns=201))
            self.assertEqual(
                MODULE._fault_evidence(root, "original", owner, 100)[0], fault
            )
            for mutation in (
                "start",
                "authority",
                "target",
                "death",
                "qualification-after-fault",
            ):
                changed = copy.deepcopy(raw)
                dead = dict(observed_dead_ns=201)
                qualified = 100
                if mutation == "start":
                    changed["start_id"] = "other"
                if mutation == "authority":
                    changed["binding"]["authority"]["start_ticks"] += 1
                if mutation == "target":
                    changed["binding"]["observer"]["start_ticks"] += 1
                if mutation == "death":
                    dead["observed_dead_ns"] = 202
                if mutation == "qualification-after-fault":
                    qualified = 201
                save(changed, fault, dead)
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    MODULE._fault_evidence(root, "original", owner, qualified)

    def test_full_qualification_remains_before_ready_then_real_fault_before_restart(
        self,
    ):
        main = next(
            n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == "main"
        )
        calls = [
            (n.lineno, ast.unparse(n.func))
            for n in ast.walk(main)
            if isinstance(n, ast.Call)
        ]
        ready_line = next(line for line, name in calls if name == "_send")
        restart_line = next(
            line for line, name in calls if name == "authority.restart_live_observer"
        )
        self.assertTrue(
            all(
                line < ready_line
                for line, name in calls
                if name
                in {
                    "validate_for_start",
                    "validate_receipt_for_start",
                    "authority.preflight",
                }
            )
        )
        self.assertTrue(
            any(
                ready_line < line < restart_line and name == "_fault_evidence"
                for line, name in calls
            )
        )
        self.assertTrue(
            any(
                ready_line < line < restart_line and name == "scope.native_admission"
                for line, name in calls
            )
        )
        self.assertTrue(
            any(
                isinstance(n, ast.Constant) and n.value == 30_000_000_000
                for n in ast.walk(main)
            )
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
