from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from test_activation_profile import installation as installation

from experiments.native_attention_candidate import baseline_host_binding as binding
from vllm_hust_ext.runtime_phase_handoff import process_identity

HOST = Path(
    "/root/ecpa-workspace/environments/ecpa-selected-kv-attention-candidate-venv-20261014-r4/lib/python3.12/site-packages"
)
HOST_FILES = (
    "vllm/plugins/__init__.py",
    "vllm/plugins/evidence.py",
    "vllm/entrypoints/cli/main.py",
    "vllm/v1/executor/multiproc_executor.py",
    "vllm/v1/engine/core.py",
)


def wait_for(predicate):
    end = time.monotonic() + 10
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(0.01)
    raise AssertionError("bounded CPU child wait expired")


@pytest.fixture
def real_host(installation):
    profile, root, _, _ = installation
    explicit_source = os.getenv("ECPA_TEST_HOST_SOURCE_ROOT")
    source_root = Path(str(HOST) if explicit_source is None else explicit_source)
    try:
        available = all((source_root / p).is_file() for p in HOST_FILES)
    except OSError as exc:
        if explicit_source is not None:
            pytest.fail(f"explicit Host source cannot be read: {exc}")
        pytest.skip(f"default real47 Host source is unavailable: {exc}")
    if not available:
        if explicit_source is not None:
            pytest.fail("explicit Host source is missing required files")
        pytest.skip(
            "real47 Host source CPU integration needs ECPA_TEST_HOST_SOURCE_ROOT"
        )
    for relative in HOST_FILES:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((source_root / relative).read_bytes())
    (root / "vllm/__init__.py").write_text("")
    (root / "vllm/envs.py").write_text(
        "import os\n"
        "def __getattr__(name):\n"
        '    if name=="VLLM_PLUGINS":\n'
        "        value=os.getenv(name)\n"
        '        return None if value is None else value.split(",")\n'
        "    raise AttributeError(name)\n"
    )
    info = root / "vllm-0.19.1.dist-info"
    info.mkdir()
    (info / "METADATA").write_text("Name: vllm\nVersion: 0.19.1\n")
    return (
        profile,
        root,
        {str(root / p): binding.digest((root / p).read_bytes()) for p in HOST_FILES},
    )


# Execute the exact CPU-safe prefix of real47's CLI / worker_main role binding.
# No synthetic late event is emitted: real Host loader/evidence emits callbacks.
CHILD = r"""
import ast, json, os, subprocess, sys, time
from pathlib import Path
from types import SimpleNamespace
from experiments.native_attention_candidate import baseline_host_binding as b
from vllm_hust_ext import runtime_activation as a
from vllm_hust_ext.activation_profile import profile_from_environment
from vllm_hust_ext.runtime_phase_handoff import process_identity

root = Path(sys.argv[1])
role = sys.argv[2]
ordinal = int(sys.argv[3])
import vllm.plugins as p

# Real loader pre-binding callback: never acceptable as final worker role.
p.load_plugins_by_group("vllm.general_plugins")
if os.getenv("TEST_ONLY_EARLY") != "1":
    if role == "api-server":
        tree = ast.parse((root / "vllm/entrypoints/cli/main.py").read_text())
        function = next(
            n
            for n in tree.body
            if isinstance(n, ast.FunctionDef)
            and n.name == "_bind_serve_process_identity"
        )
        module = ast.Module(body=[function], type_ignores=[])
        namespace = {}
        exec(compile(module, "real47-cli-bind", "exec"), namespace)
        namespace["_bind_serve_process_identity"](["vllm", "serve"])
    else:
        tree = ast.parse((root / "vllm/v1/executor/multiproc_executor.py").read_text())
        cls = next(
            n
            for n in tree.body
            if isinstance(n, ast.ClassDef) and n.name == "WorkerProc"
        )
        function = next(
            n
            for n in cls.body
            if isinstance(n, ast.FunctionDef) and n.name == "worker_main"
        )
        prefix = []
        for statement in function.body:
            prefix.append(statement)
            if (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Call)
                and getattr(statement.value.func, "id", None) == "bind_process_identity"
            ):
                break
        function.body = prefix
        function.decorator_list = []
        namespace = {}
        exec(
            compile(
                ast.Module(body=[function], type_ignores=[]),
                "real47-worker-bind-prefix",
                "exec",
            ),
            namespace,
        )
        namespace["worker_main"](
            rank=ordinal,
            vllm_config=SimpleNamespace(
                parallel_config=SimpleNamespace(data_parallel_index=0, world_size=2)
            ),
        )
a.configure_activation(
    os.environ["ECPA_ACTIVATION_CONTRACT"], profile=profile_from_environment()
)
p.load_general_plugins()
from vllm.plugins.evidence import capture_scope

process = capture_scope()["process"]
process.update(process_identity(os.getpid()))
(root / f"ready-{role}-{ordinal}.json").write_text(json.dumps({"process": process}))
children = []
if role == "api-server" and os.getenv("TEST_SINGLE") != "1":
    for rank in range(2):
        children.append(
            subprocess.Popen(
                [sys.executable, __file__, str(root), "worker", str(rank)],
                env=dict(os.environ),
            )
        )
while not (root / "stop").exists():
    time.sleep(0.01)
for child in children:
    child.wait(timeout=5)
"""


def launch(observer, root, *, extra=None):
    script = root / "cpu_real_host.py"
    script.write_text(CHILD)
    env = dict(os.environ)
    env.update(observer.environment())
    env.update(extra or {})
    source = Path(binding.__file__).resolve().parents[2]
    env["PYTHONPATH"] = os.pathsep.join([str(root), str(source / "src"), str(source)])
    env["VLLM_PLUGINS"] = "ascend_kvcompress"
    child = subprocess.Popen(
        [sys.executable, str(script), str(root), "api-server", "0"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    observer.attach_host(process_identity(child.pid))
    return child


def finish(child, root, observer):
    (root / "stop").touch()
    try:
        _, err = child.communicate(timeout=10)
        assert child.returncode == 0 and "Traceback" not in err, (
            observer.failures,
            err,
        )
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        observer.close()


@pytest.mark.parametrize("arm", ["entry-points-unmanaged", "explicit-manual-hooks"])
def test_actual47_loader_socket_and_late_host_binding(real_host, arm):
    profile, root, sources = real_host
    observer = binding.HostObserver(
        root / "observer.sock",
        root / "ingress.jsonl",
        profile=profile,
        arm=arm,
        host_sources=sources,
    )
    child = launch(observer, root)
    try:
        wait_for(
            lambda: (
                len(list(root.glob("ready-*.json"))) == 3 or child.poll() is not None
            )
        )
        assert child.poll() is None, child.stderr.read()
        peers = [
            json.loads(path.read_text()) for path in sorted(root.glob("ready-*.json"))
        ]
        receipt = observer.finalize(peers)
        assert receipt["origin"] == "baseline-host-observer"
        assert (
            receipt["activation_only"] is True
            and receipt["effect_qualification"] is None
        )
        assert receipt["formal_result"] is False
        assert "manager" not in receipt and "execution_plan_id" not in receipt
        records = [
            json.loads(line) for line in observer.journal_path.read_bytes().splitlines()
        ]
        assert any(
            row["envelope"]["payload"]["process"]["assignment_source"] == "environment"
            for row in records
        )
        assert len(receipt["peers"]) == 3
        repeated = json.loads(json.dumps(peers))
        # Keep the complete role/ordinal set, but reuse one captured live kernel.
        role, ordinal = (
            repeated[-1]["process"]["role"],
            repeated[-1]["process"]["ordinal"],
        )
        repeated[-1]["process"] = dict(repeated[-2]["process"])
        repeated[-1]["process"].update(role=role, ordinal=ordinal)
        with pytest.raises(ValueError, match="three distinct live process identities"):
            observer.finalize(repeated)
        forged = json.loads(json.dumps(peers))
        forged[-1]["process"]["start_ticks"] += 1
        with pytest.raises(ValueError, match="kernel differs"):
            observer.finalize(forged)
        with pytest.raises(ValueError, match="source bytes"):
            next(Path(p) for p in sources if p.endswith("evidence.py")).write_text(
                "# replaced"
            )
            observer.finalize(peers)
    finally:
        finish(child, root, observer)


def test_early_environment_roles_cannot_be_promoted_by_caller_json(real_host):
    profile, root, sources = real_host
    observer = binding.HostObserver(
        root / "observer.sock",
        root / "ingress.jsonl",
        profile=profile,
        arm="entry-points-unmanaged",
        host_sources=sources,
    )
    child = launch(observer, root, extra={"TEST_ONLY_EARLY": "1"})
    try:
        wait_for(
            lambda: (
                len(list(root.glob("ready-*.json"))) == 3 or child.poll() is not None
            )
        )
        peers = []
        for path in sorted(root.glob("ready-*.json")):
            p = json.loads(path.read_text())["process"]
            p["assignment_source"] = "host"
            p["role"] = "api-server" if "api-server" in path.name else "worker"
            p["ordinal"] = int(path.stem.rsplit("-", 1)[1])
            peers.append({"process": p})
        with pytest.raises(ValueError, match="later authenticated Host assignment"):
            observer.finalize(peers)
    finally:
        finish(child, root, observer)


@pytest.mark.parametrize("bad", ["ack", "owner", "nonce"])
def test_real_sink_rejects_wrong_ack_owner_or_nonce(installation, bad):
    profile, root, _, _ = installation
    path = root / "fake-owner.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    path.chmod(0o600)
    server.listen(1)
    identity = binding._socket(path)
    errors = []

    def serve():
        try:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(3)
                binding._send(
                    connection,
                    {
                        "schema": binding.SCHEMA,
                        "trial": "trial",
                        "nonce": ("a" * 64 if bad != "nonce" else "short"),
                        "socket": identity,
                    },
                )
                envelope = binding._receive(connection)
                binding._send(
                    connection,
                    {
                        "schema": binding.SCHEMA,
                        "trial": "trial",
                        "nonce": envelope["nonce"],
                        "record_sha256": "0" * 64,
                    },
                )
        except (OSError, ValueError) as exc:
            errors.append(str(exc))

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    owner = process_identity(os.getpid())
    if bad == "owner":
        owner["start_ticks"] += 1
    env = dict(os.environ)
    env.update(
        {
            binding.SOCKET_ENV: str(path),
            binding.TRIAL_ENV: "trial",
            binding.OWNER_ENV: json.dumps(owner),
            "ECPA_ACTIVATION_PROFILE_PATH": str(profile.path),
            "ECPA_ACTIVATION_PROFILE_SHA256": profile.sha256,
        }
    )
    source = Path(binding.__file__).resolve().parents[2]
    env["PYTHONPATH"] = os.pathsep.join([str(root), str(source / "src"), str(source)])
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from experiments.native_attention_candidate.baseline_host_binding "
            "import record_event; record_event({})",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    server.close()
    thread.join(5)
    assert result.returncode != 0
    assert (
        "acknowledgement differs"
        if bad == "ack"
        else "owner epoch differs"
        if bad == "owner"
        else "challenge differs"
    ) in result.stderr


def test_owner_rejects_replayed_nonce_on_real_child_socket(real_host):
    profile, root, sources = real_host
    observer = binding.HostObserver(
        root / "observer.sock",
        root / "ingress.jsonl",
        profile=profile,
        arm="entry-points-unmanaged",
        host_sources=sources,
    )
    source = Path(binding.__file__).resolve().parents[2]
    env = dict(os.environ)
    env.update(observer.environment())
    env["PYTHONPATH"] = os.pathsep.join([str(root), str(source / "src"), str(source)])
    script = """
import os,socket
from pathlib import Path
from experiments.native_attention_candidate import baseline_host_binding as b
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as c:
    c.connect(os.environ[b.SOCKET_ENV]); challenge=b._receive(c)
    b._send(c,dict(schema=b.SCHEMA,trial=challenge['trial'],nonce='0'*64,
        profile_sha256=os.environ['ECPA_ACTIVATION_PROFILE_SHA256'],
        sender=b.process_identity(os.getpid()),payload={},
        observer_source={'path':str(Path(b.__file__).resolve()),
                         'sha256':b.digest(Path(b.__file__).read_bytes())}))
    b._receive(c)
"""
    child = subprocess.Popen(
        [sys.executable, "-c", script],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        observer.attach_host(process_identity(child.pid))
        _, error = child.communicate(timeout=10)
        assert child.returncode != 0 and "frame incomplete" in error
        assert wait_for(lambda: observer.failures)
        assert "challenge/identity differs" in observer.failures[0]
        assert observer.records == []
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        observer.close()
