"""Tiny real ZIP/current metadata checks. No actual product/model qualification."""

import ast
import copy
import hashlib
import importlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

SDK = Path(__file__).resolve().parents[1]

# Frozen pre-parallel entry functions: original guard/model/source helpers below
# are loaded from the same checkout and are separately AST-proved unchanged.
ORIGINAL_AUDIT = r'''
def audit_cell_inputs(config_path, recipe_path, *, _model_call=None):
    """Expensive prelaunch audit, run in the actual pinned runtime interpreter.

    Returns observed bytes, not a producer claim.  It proves files and installed
    code at audit time, not model quality or which bytes an accelerator executed.
    The issuer must pin/trust the resulting manifest independently.  No NPU runs.
    """
    if _model_call is not None:
        _active_model_audit_call(_model_call)
    config_path, recipe_path = _path(config_path), _path(recipe_path)
    states = {}
    config_raw, recipe_raw = config_path.read_bytes(), recipe_path.read_bytes()
    registry.require(
        _hash(config_path, states) == registry.sha(config_raw)
        and _hash(recipe_path, states) == registry.sha(recipe_raw),
        "input documents changed during audit",
    )
    config, recipe = json.loads(config_raw), json.loads(recipe_raw)
    registry.require(
        Path(sys.executable) == Path(config["python"])
        and Path(sys.prefix) == Path(config["python"]).parent.parent,
        "input audit must run in actual runtime interpreter",
    )
    registry.require(
        str(recipe_path) == config["recipe"]
        and registry.sha(recipe_raw) == config["recipe_sha256"],
        "frozen recipe bytes differ",
    )
    registry.require(
        len(recipe["phases"]) == 1, "only one request-scoped cell supported"
    )
    phase = recipe["phases"][0]
    wheels = config["wheel_artifacts"]
    registry.require(
        set(wheels) == set(DISTRIBUTIONS), "exact seven wheel roles required"
    )
    installed = {}
    for role, wheel in wheels.items():
        registry.require(
            _hash(wheel["path"], states) == wheel["sha256"],
            "genuine wheel bytes differ",
        )
        installed[role] = _installed_payload(wheel, DISTRIBUTIONS[role], states)
    models = _model_inventory_in_call(
        config["model_files"],
        states,
        _model_call,
        {
            "config": {"path": str(config_path), "sha256": registry.sha(config_raw)},
            "recipe": {"path": str(recipe_path), "sha256": registry.sha(recipe_raw)},
        },
    )
    # This adapter intentionally supports the current single 7B cell only.
    registry.require(
        len(models) == 14, "single-cell model inventory must contain 14 files"
    )
    tokenization = phase["tokenization"]
    assets = _inventory(tokenization["assets"], states)
    registry.require(
        all(models.get(path) == digest for path, digest in assets.items()),
        "tokenizer assets are outside the exact model inventory",
    )
    binding = tokenization["runtime_binding"]
    host_sources = _inventory(binding["host_sources"], states)
    implementation = _inventory([binding["implementation_source"]], states)
    registry.require(
        all(installed["host"].get(p) == digest for p, digest in host_sources.items())
        and binding["host_version"] == wheels["host"]["version"]
        and binding["host_revision"] == wheels["host"]["revision"]
        and metadata.version("transformers") == binding["transformers_version"],
        "tokenizer runtime binding differs",
    )
    calibration = config["calibration_artifact"]
    registry.require(
        _hash(calibration["path"], states) == calibration["sha256"],
        "calibration bytes differ",
    )
    frozen_sources = {}
    for source in config["sources"]:
        path, digest = source["path"], source["sha256"]
        registry.require(
            path not in frozen_sources or frozen_sources[path] == digest,
            "frozen source inventory conflicts",
        )
        frozen_sources[path] = digest
    sources = _inventory(
        [{"path": p, "sha256": d} for p, d in frozen_sources.items()], states
    )
    result = {
        "schema": SCHEMA,
        "source_files": sources,
        "config": {"path": str(config_path), "sha256": registry.sha(config_raw)},
        "recipe": {"path": str(recipe_path), "sha256": registry.sha(recipe_raw)},
        "profile_id": registry.recipe_profile_id(recipe),
        "request_sha256": registry.sha(registry.canonical(phase["payload"])),
        "wheel_sha256": {r: w["sha256"] for r, w in wheels.items()},
        "wheel_revisions": {r: w["revision"] for r, w in wheels.items()},
        "installed_payload_sha256": registry.sha(registry.canonical(installed)),
        "model_sha256": registry.sha(registry.canonical(models)),
        "tokenizer_sha256": registry.sha(
            registry.canonical(
                {
                    "tokenization": tokenization,
                    "host_sources": host_sources,
                    "implementation": implementation,
                }
            )
        ),
        "calibration_sha256": calibration["sha256"],
        "file_state": states,
        "formal_result": False,
    }
    registry.require(
        all(_state(_path(path).stat()) == state for path, state in states.items()),
        "input files changed during audit",
    )
    # Reject a concurrent replacement of the binding documents during the audit.
    registry.require(
        config_path.read_bytes() == config_raw
        and recipe_path.read_bytes() == recipe_raw,
        "input documents changed during audit",
    )
    if _model_call is not None:
        _active_model_audit_call(_model_call)
    return result
'''
ORIGINAL_PROBE = r'''
def _probe(items):
    """Run under the exact child interpreter/environment, without importing Host."""
    result = {}
    for role, item in items.items():
        dist = metadata.distribution(item["distribution"])
        wheel = item["wheel"]
        require(dist.version == wheel["version"], "actual runtime version differs")
        payload, roots = {}, set()
        wheel_raw = checked(wheel)
        with zipfile.ZipFile(io.BytesIO(wheel_raw)) as archive:
            names = archive.namelist()
            require(len(names) == len(set(names)), "wheel has repeated members")
            for name in names:
                parts = PurePosixPath(name).parts
                require(
                    parts and not name.startswith("/") and ".." not in parts,
                    "unsafe wheel member",
                )
                if name.endswith("/") or name.endswith(".dist-info/RECORD"):
                    continue
                relative = name
                if parts[0].endswith(".data"):
                    require(
                        len(parts) > 2 and parts[1] in {"purelib", "platlib"},
                        "unsupported wheel relocation",
                    )
                    relative = str(PurePosixPath(*parts[2:]))
                path = Path(dist.locate_file(relative))
                require(
                    path.is_file() and not path.is_symlink() and path.resolve() == path,
                    "actual installed wheel payload path differs: " + name,
                )
                installed_raw = path.read_bytes()
                require(
                    installed_raw == archive.read(name),
                    "actual installed wheel payload differs: " + name,
                )
                payload[str(path)] = sha(installed_raw)
                if not parts[0].endswith(".dist-info"):
                    roots.add(Path(dist.locate_file(PurePosixPath(relative).parts[0])))
        for root in roots:
            if root.is_dir():
                for path in root.rglob("*"):
                    if path.is_file() and (
                        path.suffix in {".py", ".so", ".o", ".a"}
                        or path.read_bytes()[:4] == b"\x7fELF"
                    ):
                        require(str(path) in payload, "unrecorded runtime payload")
        module = item["module"]
        require(module.isidentifier(), "probe module must be a top-level package")
        found = importlib.util.find_spec(module)
        require(
            found is not None and found.origin in payload,
            "actual import origin shadows the admitted installed wheel",
        )
        result[role] = {"origin": found.origin, "payload": payload}
    return {
        "python": sys.executable,
        "real_python": str(Path(sys.executable).resolve()),
        "python_sha256": sha(Path(sys.executable).read_bytes()),
        "cwd": os.getcwd(),
        "sys_path": sys.path,
        "distributions": result,
    }
'''


def load_source(relative, name, original=None):
    path = SDK / relative
    source = path.read_text()
    if original is not None:
        tree = ast.parse(source)
        reference = ast.parse(original).body[0]
        node = next(
            n
            for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name == reference.name
        )
        lines = source.splitlines(keepends=True)
        source = (
            "".join(lines[: node.lineno - 1])
            + original
            + "\n"
            + "".join(lines[node.end_lineno :])
        )
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


old = load_source(
    "experiments/native_attention_candidate/live_route_reader.py",
    "tiny_original_route",
    ORIGINAL_AUDIT,
)
new = load_source(
    "experiments/native_attention_candidate/live_route_reader.py",
    "tiny_candidate_route",
)
old_closure = load_source(
    "experiments/formal_campaign/h3_runtime_source_closure.py",
    "tiny_original_closure",
    ORIGINAL_PROBE,
)
new_closure = load_source(
    "experiments/formal_campaign/h3_runtime_source_closure.py", "tiny_candidate_closure"
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class TinyFixture:
    def __init__(self, root):
        self.root = root
        self.site = root / "site"
        self.site.mkdir()
        self.wheels = {}
        self.modules = {}
        self.items = {}
        for index, (role, distribution) in enumerate(old.DISTRIBUTIONS.items()):
            module = "ecpa_tiny_role_" + str(index)
            self.modules[role] = module
            dist = distribution.replace("-", "_") + "-0.0.1.dist-info"
            payload = {
                module + "/__init__.py": b"# tiny real source\n",
                module + "/data.py": b"VALUE = 1\n",
                dist + "/METADATA": (
                    "Metadata-Version: 2.1\n"
                    + f"Name: {distribution}\n"
                    + "Version: 0.0.1\n\n"
                ).encode(),
            }
            wheel = root / (role + ".whl")
            with zipfile.ZipFile(
                wheel, "w", compression=zipfile.ZIP_DEFLATED
            ) as archive:
                for relative, raw in payload.items():
                    archive.writestr(relative, raw)
                    path = self.site / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(raw)
            row = dict(
                path=str(wheel),
                sha256=digest(wheel.read_bytes()),
                version="0.0.1",
                revision="a" * 40,
            )
            self.wheels[role] = row
            self.items[role] = dict(distribution=distribution, module=module, wheel=row)
        d = self.site / "transformers-0.0.1.dist-info"
        d.mkdir()
        (d / "METADATA").write_bytes(b"Name: transformers\nVersion: 0.0.1\n")
        self.model_rows = []
        for i in range(14):
            path = root / ("tiny-model-" + str(i))
            path.write_bytes(("tiny CPU fixture " + str(i)).encode())
            self.model_rows.append(
                dict(path=str(path), sha256=digest(path.read_bytes()))
            )
        implementation = root / "tiny_tokenizer.py"
        implementation.write_bytes(b"# source only; never executed\n")
        host_source = self.site / self.modules["host"] / "__init__.py"
        binding = dict(
            host_sources=[
                dict(path=str(host_source), sha256=digest(host_source.read_bytes()))
            ],
            implementation_source=dict(
                path=str(implementation), sha256=digest(implementation.read_bytes())
            ),
            host_version="0.0.1",
            host_revision="a" * 40,
            transformers_version="0.0.1",
        )
        recipe = dict(
            tensor_consumer_contract="tiny",
            attention_consumer_contract="tiny",
            attention_drain_contract="tiny",
            phases=[
                dict(
                    payload=dict(prompt="tiny"),
                    ack_time_policy="tiny",
                    tokenization=dict(
                        assets=[self.model_rows[0]], runtime_binding=binding
                    ),
                )
            ],
        )
        self.recipe = root / "recipe.json"
        self.recipe.write_text(json.dumps(recipe))
        calibration = root / "tiny-calibration"
        calibration.write_bytes(b"not a real calibration or model\n")
        config = dict(
            python=sys.executable,
            recipe=str(self.recipe),
            recipe_sha256=digest(self.recipe.read_bytes()),
            wheel_artifacts=self.wheels,
            model_files=self.model_rows,
            calibration_artifact=dict(
                path=str(calibration), sha256=digest(calibration.read_bytes())
            ),
            sources=[binding["implementation_source"]],
        )
        self.config = root / "config.json"
        self.config.write_text(json.dumps(config))


class ParallelRoleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ecpa-role-tiny-")
        self.root = Path(self.tmp.name)
        self.fixture = TinyFixture(self.root)
        sys.path.insert(0, str(self.fixture.site))
        importlib.invalidate_caches()

    def tearDown(self):
        sys.path.remove(str(self.fixture.site))
        self.tmp.cleanup()

    def audit(self, module):
        return module.audit_cell_inputs(self.fixture.config, self.fixture.recipe)

    def test_exact_original_full_audit_and_deterministic_role_order(self):
        baseline = self.audit(old)
        original_worker = new._audit_wheel_role
        completed = []
        roles = list(self.fixture.wheels)

        def delayed(role, wheel):
            value = original_worker(role, wheel)
            time.sleep((len(roles) - roles.index(role)) * 0.001)
            completed.append(role)
            return value

        with patch.object(new, "_audit_wheel_role", delayed):
            actual = self.audit(new)
        self.assertEqual(
            old.registry.canonical(baseline), new.registry.canonical(actual)
        )
        self.assertEqual(list(actual["wheel_sha256"]), roles)
        self.assertEqual(set(completed), set(roles))
        self.assertFalse(actual["formal_result"])

    def test_corrupt_installed_member_rejected_by_both(self):
        (self.fixture.site / self.fixture.modules["torch"] / "data.py").write_bytes(
            b"CORRUPTED = True\n"
        )
        for module in (old, new):
            with self.assertRaisesRegex(ValueError, "installed wheel payload differs"):
                self.audit(module)

    def test_extra_installed_code_rejected_by_both(self):
        (
            self.fixture.site / self.fixture.modules["torch_npu"] / "unrecorded.py"
        ).write_bytes(b"EXTRA = True\n")
        for module in (old, new):
            with self.assertRaisesRegex(
                ValueError, "unrecorded installed runtime payload"
            ):
                self.audit(module)

    def test_real_metadata_version_corruption_rejected(self):
        metadata = self.fixture.site / "vllm_ascend-0.0.1.dist-info/METADATA"
        metadata.write_bytes(b"Name: vllm-ascend\nVersion: 9.0\n")
        for module in (old, new):
            with self.assertRaisesRegex(ValueError, "installed wheel version differs"):
                self.audit(module)

    def test_real_file_state_conflict_does_not_partially_merge(self):
        path = self.fixture.site / "vllm-0.0.1.dist-info/METADATA"
        original = old._state(path.stat())
        states = {str(path): original}
        os.utime(
            path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1_000_000)
        )
        with self.assertRaisesRegex(ValueError, "input file state conflicts"):
            new._audit_wheel_roles(self.fixture.wheels, states)
        self.assertEqual(states, {str(path): original})

    def test_worker_exception_joins_all_workers_and_keeps_parent_states(self):
        original_worker = new._audit_wheel_role
        finished = []
        lock = threading.Lock()

        def fail_one(role, wheel):
            try:
                if role == "host":
                    raise RuntimeError("actual worker exception fixture")
                return original_worker(role, wheel)
            finally:
                with lock:
                    finished.append(role)

        states = {}
        with (
            patch.object(new, "_audit_wheel_role", fail_one),
            self.assertRaisesRegex(RuntimeError, "actual worker exception"),
        ):
            new._audit_wheel_roles(self.fixture.wheels, states)
        self.assertEqual(set(finished), set(self.fixture.wheels))
        self.assertEqual(states, {})

    def test_model_scope_entry_stays_owner_thread_and_all_states_fresh(self):
        owner = threading.get_ident()
        original = new._model_inventory_in_call
        observed = []

        def recording(*args):
            observed.append(threading.get_ident())
            return original(*args)

        with (
            patch.object(new, "_model_inventory_in_call", recording),
            new._fresh_model_audit_call() as token,
        ):
            actual = new.audit_cell_inputs(
                self.fixture.config, self.fixture.recipe, _model_call=token
            )
        self.assertEqual(observed, [owner])
        new._check_file_states(actual["file_state"])
        path = self.root / "tiny-model-1"
        path.write_bytes(b"changed after original audit")
        with self.assertRaises(ValueError):
            new._check_file_states(actual["file_state"])

    def test_real_cross_worker_duplicate_state_conflict(self):
        # Two distinct metadata distributions own the same real installed tiny
        # code. A real metadata-clock change between independent observations
        # must fail rather than overwrite the first worker's state.
        wheel = Path(self.fixture.wheels["ascend"]["path"])
        shared_module = self.fixture.modules["host"]
        dist = "vllm_ascend-0.0.1.dist-info"
        with zipfile.ZipFile(wheel, "w") as archive:
            for relative in (
                shared_module + "/__init__.py",
                shared_module + "/data.py",
                dist + "/METADATA",
            ):
                archive.writestr(relative, (self.fixture.site / relative).read_bytes())
        self.fixture.wheels["ascend"]["sha256"] = digest(wheel.read_bytes())
        observed = threading.Event()
        original_worker = new._audit_wheel_role

        def actual_race(role, descriptor):
            if role == "ascend":
                self.assertTrue(observed.wait(1))
                shared = self.fixture.site / shared_module / "data.py"
                info = shared.stat()
                os.utime(shared, ns=(info.st_atime_ns, info.st_mtime_ns + 1_000_000))
            result = original_worker(role, descriptor)
            if role == "host":
                observed.set()
            return result

        states = {}
        with (
            patch.object(new, "_audit_wheel_role", actual_race),
            self.assertRaisesRegex(ValueError, "input file state conflicts"),
        ):
            new._audit_wheel_roles(self.fixture.wheels, states)
        self.assertEqual(states, {})

    def test_real_workers_are_bounded_four_and_join_before_return(self):
        original_worker = new._audit_wheel_role
        lock = threading.Lock()
        active = 0
        peak = 0
        ended = []

        def measured(role, descriptor):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                result = original_worker(role, descriptor)
                time.sleep(0.01)
                return result
            finally:
                with lock:
                    active -= 1
                    ended.append(role)

        with patch.object(new, "_audit_wheel_role", measured):
            payload = new._audit_wheel_roles(self.fixture.wheels, {})
        self.assertGreater(peak, 1)
        self.assertLessEqual(peak, 4)
        self.assertEqual(active, 0)
        self.assertEqual(len(ended), 7)
        self.assertEqual(list(payload), list(self.fixture.wheels))

    def test_optional_probe_exact_original_and_order(self):
        baseline = old_closure._probe(self.fixture.items)
        actual = new_closure._probe(self.fixture.items)
        self.assertEqual(baseline, actual)
        self.assertEqual(list(actual["distributions"]), list(self.fixture.items))

    def test_optional_probe_corrupt_and_extra_member_fail(self):
        path = self.fixture.site / self.fixture.modules["host"] / "data.py"
        path.write_bytes(b"BAD = True\n")
        for module in (old_closure, new_closure):
            with self.assertRaisesRegex(
                ValueError, "actual installed wheel payload differs"
            ):
                module._probe(self.fixture.items)
        path.write_bytes(b"VALUE = 1\n")
        (path.parent / "extra.py").write_bytes(b"EXTRA = 1\n")
        for module in (old_closure, new_closure):
            with self.assertRaisesRegex(ValueError, "unrecorded runtime payload"):
                module._probe(self.fixture.items)

    def test_optional_source_members_original_git_blobs_and_order(self):
        revision = subprocess.check_output(
            ["git", "-C", str(SDK), "rev-parse", "HEAD"], text=True
        ).strip()
        relative = "src/vllm_hust_ext/__init__.py"
        body = (SDK / relative).read_bytes()
        wheel = self.root / "tiny-source.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("vllm_hust_ext/__init__.py", body)
        item = dict(
            wheel=dict(
                path=str(wheel),
                sha256=digest(wheel.read_bytes()),
                revision=revision,
            )
        )
        revisions = {
            "plugin:tiny-b": revision,
            "plugin:tiny-a": revision,
        }
        items = {r: copy.deepcopy(item) for r in revisions}
        repositories = {r: dict(path=str(SDK)) for r in revisions}
        baseline = {
            role: old_closure._source_members(items[role], SDK, revision)
            for role, revision in revisions.items()
        }
        actual = new_closure._source_roles(revisions, items, repositories, {})
        self.assertEqual(baseline, actual)
        self.assertEqual(list(actual), list(revisions))


if __name__ == "__main__":
    unittest.main(verbosity=2)
