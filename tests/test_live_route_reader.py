"""CPU socket/controller tests; synthetic cell data is never NPU qualification."""

import copy
import http.client
import json
import multiprocessing
import sys
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_cell_semantic_producer_registry import cell as _registry_cell

from experiments.exposure_gate import loopback_traffic as traffic
from experiments.native_attention_candidate import live_route_reader as reader
from experiments.native_attention_candidate import (
    semantic_producer_registry as registry,
)
from vllm_hust_ext.exposure_gate import LeaseGrant, RouteState
from vllm_hust_ext.runtime_phase_handoff import process_identity

registry_cell = _registry_cell


class CPUBackend(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"CPU_BACKEND_FORWARDED"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def cpu_controller(path, journal, grant, snapshot, ready):
    backend = ThreadingHTTPServer(("127.0.0.1", 0), CPUBackend)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    authority = traffic._Authority(
        RouteState(1, "gate-CPU_ONLY", snapshot),
        grant,
        ("127.0.0.1", backend.server_port),
        ("127.0.0.1", backend.server_port),
        traffic._TrafficJournal(Path(journal)),
    )
    proxy = traffic._ProxyServer(authority)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    ready.send(proxy.server_port)
    # This is the existing controller's real read/control socket implementation,
    # not a static route_reader callback or a mocked socket response.
    traffic._admin(Path(path), authority, proxy.server_port)


@pytest.fixture
def controller(tmp_path):
    tmp_path.chmod(0o700)
    scope = {
        "execution_plan_id": "plan:sha256:" + "a" * 64,
        "native_plan_id": "a" * 64,
        "native_launch_id": "00000000-0000-4000-8000-000000000001",
        "controller_instance": "controller:CPU_ONLY",
        "candidate_generation": 1,
        "membership_epoch": 0,
    }
    input_source = str(Path(__file__).resolve())
    inputs = {
        "schema": reader.SCHEMA,
        "file_state": {input_source: reader._state(Path(input_source).stat())},
    }
    cell = {
        "inputs_sha256": registry.sha(registry.canonical(inputs)),
        "schema": reader.SNAPSHOT,
        "execution_plan_id": scope["execution_plan_id"],
        "native_launch_id": scope["native_launch_id"],
        "CPU_SYNTHETIC_CELL_NOT_A_PERMIT": True,
    }
    snapshot = {
        **{
            k: scope[k]
            for k in (
                "execution_plan_id",
                "native_launch_id",
                "controller_instance",
                "membership_epoch",
            )
        },
        "semantic_cell": cell,
    }
    grant = LeaseGrant(scope["controller_instance"], 1, int(time.time()) + 20)
    socket_path = tmp_path / "ctl.sock"
    context = multiprocessing.get_context("fork")
    parent, child = context.Pipe()
    process = context.Process(
        target=cpu_controller,
        args=(str(socket_path), str(tmp_path / "journal"), grant, snapshot, child),
    )
    process.start()
    try:
        assert parent.poll(5)
        port = parent.recv()
        deadline = time.monotonic() + 5
        while not socket_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        kwargs = dict(
            socket_path=socket_path,
            authority=process_identity(process.pid),
            authority_command_sha256=reader._hash(f"/proc/{process.pid}/cmdline"),
            authority_sources={
                str(Path(traffic.__file__).resolve()): reader._hash(traffic.__file__)
            },
            inputs=inputs,
            grant=grant,
            expected_cell=cell,
            scope=scope,
        )
        yield SimpleNamespace(
            kwargs=kwargs,
            port=port,
            process=process,
            adapter=traffic.LoopbackTrafficAdapter(socket_path, grant),
        )
    finally:
        process.terminate()
        process.join(5)
        if process.is_alive():
            process.kill()
            process.join(5)
        parent.close()
        child.close()


def http_status(port):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("GET", "/CPU_ONLY")
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def test_reads_same_real_controller_state_used_by_HTTP_forwarding(controller):
    bound = reader.LiveRouteReader(**controller.kwargs)
    state = bound.read()
    assert state["generation"] == 1
    assert state["fence"] == "gate-CPU_ONLY"
    assert http_status(controller.port) == (200, b"CPU_BACKEND_FORWARDED")
    assert (
        bound.read()["lease_expires_monotonic_ns"]
        == state["lease_expires_monotonic_ns"]
    )
    controller.adapter.close_all()
    assert http_status(controller.port)[0] == 503
    with pytest.raises(ValueError, match="closed or restored"):
        bound.read()


@pytest.mark.parametrize(
    "field,value",
    [
        ("execution_plan_id", "plan:sha256:" + "b" * 64),
        ("native_launch_id", "00000000-0000-4000-8000-000000000002"),
        ("membership_epoch", 1),
        ("controller_instance", "controller:OTHER"),
    ],
)
def test_scope_cannot_be_filled_from_static_configuration(controller, field, value):
    kwargs = copy.deepcopy(controller.kwargs)
    kwargs["scope"][field] = value
    if field in kwargs["expected_cell"]:
        kwargs["expected_cell"][field] = value
    if field == "controller_instance":
        kwargs["grant"] = LeaseGrant(value, 1, kwargs["grant"].expires_at)
    bound = reader.LiveRouteReader(**kwargs)
    with pytest.raises(ValueError, match="binding|scope|lease"):
        bound.read()


def test_different_cell_and_predecessor_are_rejected(controller):
    kwargs = copy.deepcopy(controller.kwargs)
    kwargs["expected_cell"]["other_input_sha256"] = "b" * 64
    with pytest.raises(ValueError, match="exact semantic cell"):
        reader.LiveRouteReader(**kwargs).read()
    bound = reader.LiveRouteReader(**controller.kwargs)
    controller.adapter.restore(0, "fence-0", {"CPU_ONLY": True})
    with pytest.raises(ValueError, match="restored predecessor"):
        bound.read()


def test_controller_epoch_command_source_and_socket_replacement_rejected(
    controller, tmp_path
):
    for change in ("epoch", "command", "source"):
        kwargs = copy.deepcopy(controller.kwargs)
        if change == "epoch":
            kwargs["authority"]["start_ticks"] += 1
        elif change == "command":
            kwargs["authority_command_sha256"] = "0" * 64
        else:
            kwargs["authority_sources"] = {
                str(Path(traffic.__file__).resolve()): "0" * 64
            }
        with pytest.raises(ValueError, match="epoch|command|source"):
            reader.LiveRouteReader(**kwargs)
    bound = reader.LiveRouteReader(**controller.kwargs)
    path = controller.kwargs["socket_path"]
    path.rename(tmp_path / "old.sock")
    import socket

    with socket.socket(socket.AF_UNIX) as replacement:
        replacement.bind(str(path))
        with pytest.raises(ValueError, match="socket replaced"):
            bound.read()


def test_expiry_does_not_renew_on_read(controller, monkeypatch):
    bound = reader.LiveRouteReader(**controller.kwargs)
    expiration = bound.expiry
    monkeypatch.setattr(reader.time, "monotonic_ns", lambda: expiration + 1)
    with pytest.raises(ValueError, match="expired"):
        bound.read()


@pytest.fixture
def input_files(tmp_path, monkeypatch):
    wheels, distributions = {}, {}
    for index, (role, distribution) in enumerate(reader.DISTRIBUTIONS.items()):
        package = tmp_path / role
        package.mkdir()
        code = package / "module.py"
        code.write_text(f"CPU_ONLY = {index}\n")
        wheel = tmp_path / f"{role}.whl"
        metadata_path = tmp_path / f"{role}-1.CPU.dist-info/METADATA"
        metadata_path.parent.mkdir()
        metadata_path.write_text(f"Name: {distribution}\nVersion: 1.CPU\n")
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.write(code, f"{role}/module.py")
            archive.write(metadata_path, f"{role}-1.CPU.dist-info/METADATA")
        wheels[role] = {
            "path": str(wheel),
            "sha256": reader._hash(wheel),
            "version": "1.CPU",
            "revision": str(index) * 40,
        }
        distributions[distribution] = SimpleNamespace(
            version="1.CPU", locate_file=lambda relative: tmp_path / relative
        )
    monkeypatch.setattr(reader.metadata, "distribution", distributions.__getitem__)
    monkeypatch.setattr(reader.metadata, "version", lambda name: "CPU_TRANSFORMERS")
    models = []
    for i in range(14):
        p = tmp_path / f"model{i}.CPU"
        p.write_bytes(f"CPU_NOT_MODEL_{i}".encode())
        models.append({"path": str(p), "sha256": reader._hash(p)})
    implementation = tmp_path / "transformers.CPU.py"
    implementation.write_text("CPU_ONLY = True\n")
    calibration = tmp_path / "calibration.CPU"
    calibration.write_bytes(b"CPU_NOT_CALIBRATION")
    binding = {
        "host_sources": [
            {
                "path": str(tmp_path / "host/module.py"),
                "sha256": reader._hash(tmp_path / "host/module.py"),
            }
        ],
        "host_version": wheels["host"]["version"],
        "host_revision": wheels["host"]["revision"],
        "implementation_source": {
            "path": str(implementation),
            "sha256": reader._hash(implementation),
        },
        "transformers_version": "CPU_TRANSFORMERS",
    }
    recipe = {
        "phases": [
            {
                "payload": {"CPU_ONLY": True},
                "ack_time_policy": "CPU_ONLY",
                "tokenization": {"assets": models[:2], "runtime_binding": binding},
            }
        ],
        "tensor_consumer_contract": {},
        "attention_consumer_contract": {},
        "attention_drain_contract": {},
    }
    recipe_path = tmp_path / "recipe.json"
    recipe_path.write_bytes(registry.canonical(recipe))
    config = {
        "python": sys.executable,
        "recipe": str(recipe_path),
        "recipe_sha256": reader._hash(recipe_path),
        "wheel_artifacts": wheels,
        "model_files": models,
        "sources": [
            {"path": str(implementation), "sha256": reader._hash(implementation)}
        ],
        "calibration_artifact": {
            "path": str(calibration),
            "sha256": reader._hash(calibration),
        },
    }
    config_path = tmp_path / "config.json"
    config_path.write_bytes(registry.canonical(config))
    return SimpleNamespace(config=config_path, recipe=recipe_path, data=config)


def test_exact_byte_input_audit(input_files):
    result = reader.audit_cell_inputs(input_files.config, input_files.recipe)
    assert result["schema"] == reader.SCHEMA and result["formal_result"] is False
    assert len(result["wheel_sha256"]) == 7
    assert result["model_sha256"] != result["tokenizer_sha256"]


@pytest.mark.parametrize(
    "mutation",
    ["wheel", "installed", "extra_module", "model", "calibration", "tokenizer"],
)
def test_input_byte_changes_rejected(input_files, mutation):
    data = input_files.data
    if mutation == "wheel":
        path = Path(data["wheel_artifacts"]["mod"]["path"])
    elif mutation == "installed":
        path = input_files.config.parent / "mod/module.py"
    elif mutation == "extra_module":
        path = input_files.config.parent / "mod/extra.py"
    elif mutation == "model":
        path = Path(data["model_files"][3]["path"])
    elif mutation == "calibration":
        path = Path(data["calibration_artifact"]["path"])
    else:
        recipe = json.loads(input_files.recipe.read_bytes())
        path = Path(
            recipe["phases"][0]["tokenization"]["runtime_binding"][
                "implementation_source"
            ]["path"]
        )
    path.write_bytes(b"CPU_TAMPER")
    with pytest.raises(ValueError, match="bytes differ|payload"):
        reader.audit_cell_inputs(input_files.config, input_files.recipe)


@pytest.mark.parametrize(
    "mutation",
    [None, "untrusted", "wheel_revision", "calibration", "handoff", "other_permit"],
)
def test_cell_binding_requires_original_handshake_and_independent_exact_inputs(
    registry_cell,
    mutation,
):
    fixture = registry_cell
    cell = fixture["definition"]
    inputs = {
        key: copy.deepcopy(cell[key])
        for key in (
            "profile_id",
            "request_sha256",
            "model_sha256",
            "tokenizer_sha256",
            "calibration_sha256",
            "wheel_sha256",
        )
    }
    fixed = fixture["fixed"]
    inputs.update(
        schema=reader.SCHEMA,
        formal_result=False,
        recipe={"sha256": cell["recipe_sha256"]},
        wheel_revisions={
            "manager": fixed["manager_commit"],
            "host": fixed["host_commit"],
            "ascend": fixed["accelerator_commit"],
            "mod": fixed["plugin_commits"]["cpu"],
        },
    )
    handoff = copy.deepcopy(fixture["handoff"])
    if mutation == "wheel_revision":
        inputs["wheel_revisions"]["ascend"] = "f" * 40
    elif mutation == "calibration":
        inputs["calibration_sha256"] = "f" * 64
    elif mutation == "handoff":
        handoff["body"]["record"]["environment"]["VLLM_ECPA_LAUNCH_ID"] = "forged"
    elif mutation == "other_permit":
        handoff["body"]["permit_sha256"] = "f" * 64
        handoff = fixture["issuer"]._seal(handoff["body"])
    trust = (
        {registry.sha(registry.canonical(inputs))} if mutation != "untrusted" else set()
    )
    if mutation is None:
        result = reader.controller_cell_binding(
            fixture["issuer"],
            fixture["permit"],
            handoff,
            inputs,
            trusted_input_audits=trust,
        )
        assert result["manager"] == fixture["manager"]
        assert result["native_launch_id"] == fixture["scope"]["native_launch_id"]
        assert result["formal_result"] is False
    else:
        with pytest.raises(
            ValueError, match="trusted|revisions|audit|authentication|permit"
        ):
            reader.controller_cell_binding(
                fixture["issuer"],
                fixture["permit"],
                handoff,
                inputs,
                trusted_input_audits=trust,
            )


def test_audited_input_stat_change_rejects_future_route_reads(controller, tmp_path):
    path = tmp_path / "audited.CPU"
    path.write_bytes(b"CPU_ORIGINAL")
    kwargs = copy.deepcopy(controller.kwargs)
    kwargs["inputs"]["file_state"] = {str(path): reader._state(path.stat())}
    kwargs["expected_cell"]["inputs_sha256"] = registry.sha(
        registry.canonical(kwargs["inputs"])
    )
    bound = reader.LiveRouteReader(**kwargs)
    path.write_bytes(b"CPU_CHANGED")
    with pytest.raises(ValueError, match="audited input file changed"):
        bound.read()


def test_fresh_fd_walk_rejects_leaf_and_ancestor_symlinks(tmp_path):
    directory = tmp_path / "pinned"
    directory.mkdir()
    leaf = directory / "leaf"
    leaf.write_bytes(b"ORIGINAL")
    states = {str(leaf): reader._state(leaf.stat())}
    reader._check_file_states(states)
    target = directory / "original"
    leaf.rename(target)
    leaf.symlink_to(target)
    with pytest.raises(ValueError, match="input file changed"):
        reader._check_file_states(states)
    leaf.unlink()
    target.rename(leaf)
    moved = tmp_path / "moved"
    directory.rename(moved)
    directory.symlink_to(moved, target_is_directory=True)
    with pytest.raises(ValueError, match="ancestor changed"):
        reader._check_file_states(states)


@pytest.mark.parametrize("component", ["//", "/./", "/../"])
def test_fd_walk_rejects_noncanonical_manifest_paths(tmp_path, component):
    leaf = tmp_path / "leaf"
    leaf.write_bytes(b"ORIGINAL")
    path = str(tmp_path) + component + "leaf"
    with pytest.raises(ValueError, match="not canonical"):
        reader._check_file_states({path: reader._state(leaf.stat())})


@pytest.mark.parametrize("mutation", ["mode", "inode", "ctime"])
def test_fd_walk_retains_complete_leaf_state_and_fresh_checks(tmp_path, mutation):
    leaf = tmp_path / "leaf"
    leaf.write_bytes(b"ORIGINAL")
    before = leaf.stat()
    states = {str(leaf): reader._state(before)}
    reader._check_file_states(states)
    if mutation == "mode":
        leaf.chmod(0o600 if before.st_mode & 0o777 != 0o600 else 0o644)
    elif mutation == "inode":
        replacement = tmp_path / "replacement"
        replacement.write_bytes(leaf.read_bytes())
        replacement.replace(leaf)
    else:
        # Some overlay filesystems coalesce metadata writes in one clock tick.
        # Wait a bounded 100 ms for a real distinct ctime, preserving mtime/size.
        deadline = time.monotonic() + 0.1
        while time.monotonic() < deadline:
            time.sleep(0.005)
            leaf.write_bytes(b"MODIFIED")
            reader.os.utime(leaf, ns=(before.st_atime_ns, before.st_mtime_ns))
            if leaf.stat().st_ctime_ns != before.st_ctime_ns:
                break
        assert leaf.stat().st_size == before.st_size
        assert leaf.stat().st_mtime_ns == before.st_mtime_ns
        assert leaf.stat().st_ctime_ns != before.st_ctime_ns
    with pytest.raises(ValueError, match="input file changed"):
        reader._check_file_states(states)


def test_opened_ancestor_replacement_cannot_hide_unchanged_leaf_inode(
    tmp_path, monkeypatch
):
    directory = tmp_path / "pinned"
    directory.mkdir()
    leaf = directory / "leaf"
    leaf.write_bytes(b"ORIGINAL")
    states = {str(leaf): reader._state(leaf.stat())}
    original_stat = reader.os.stat
    replaced = False

    def replace_after_leaf_stat(path, *args, **kwargs):
        nonlocal replaced
        result = original_stat(path, *args, **kwargs)
        if path == "leaf" and kwargs.get("dir_fd") is not None and not replaced:
            replaced = True
            moved = tmp_path / "moved"
            directory.rename(moved)
            directory.mkdir()
            reader.os.link(moved / "leaf", leaf)
            # The leaf stat alone cannot distinguish these namespace bindings.
            assert original_stat(leaf).st_ino == result.st_ino
        return result

    monkeypatch.setattr(reader.os, "stat", replace_after_leaf_stat)
    with pytest.raises(ValueError, match="ancestor changed"):
        reader._check_file_states(states)
    assert replaced


def test_final_ancestor_rewalk_rejects_replacement_in_completed_branch(
    tmp_path, monkeypatch
):
    first, second = tmp_path / "a", tmp_path / "b"
    for directory in (first, second):
        directory.mkdir()
        (directory / "leaf").write_bytes(b"ORIGINAL")
    states = {
        str(p / "leaf"): reader._state((p / "leaf").stat()) for p in (first, second)
    }
    original_stat = reader.os.stat
    replaced = False

    def replace_completed_branch(path, *args, **kwargs):
        nonlocal replaced
        result = original_stat(path, *args, **kwargs)
        if path == "leaf" and kwargs.get("dir_fd") is not None:
            parent = reader.os.fstat(kwargs["dir_fd"])
            if parent.st_ino == original_stat(second).st_ino and not replaced:
                replaced = True
                moved = tmp_path / "old-a"
                first.rename(moved)
                first.mkdir()
                reader.os.link(moved / "leaf", first / "leaf")
        return result

    monkeypatch.setattr(reader.os, "stat", replace_completed_branch)
    with pytest.raises(ValueError, match="ancestor changed"):
        reader._check_file_states(states)
    assert replaced


def test_unrelated_cache_activity_changes_no_leaf_or_ancestor_identity(
    tmp_path, monkeypatch
):
    leaf = tmp_path / "leaf"
    leaf.write_bytes(b"ORIGINAL")
    states = {str(leaf): reader._state(leaf.stat())}
    original_stat = reader.os.stat
    created = False

    def create_cache_after_leaf_stat(path, *args, **kwargs):
        nonlocal created
        result = original_stat(path, *args, **kwargs)
        if path == "leaf" and kwargs.get("dir_fd") is not None and not created:
            created = True
            cache = tmp_path / "__pycache__"
            cache.mkdir()
            (cache / "unrelated.pyc").write_bytes(b"CPU_CACHE")
        return result

    monkeypatch.setattr(reader.os, "stat", create_cache_after_leaf_stat)
    reader._check_file_states(states)
    assert created


def test_compiled_declarations_recheck_replaced_ancestor_and_ignore_caller_edits(
    tmp_path,
):
    directory = tmp_path / "original"
    directory.mkdir()
    leaf = directory / "source.py"
    leaf.write_bytes(b"original")
    states = {str(leaf): reader._state(leaf.stat())}
    compiled = reader._CompiledFileStates(states)
    compiled.check()
    directory.rename(tmp_path / "moved")
    directory.mkdir()
    leaf.write_bytes(b"replacement")
    states[str(leaf)].update(reader._state(leaf.stat()))
    with pytest.raises(ValueError, match="file changed"):
        compiled.check()
    leaf.unlink()
    directory.rmdir()
    directory.symlink_to(tmp_path / "moved", target_is_directory=True)
    with pytest.raises(ValueError, match="file or ancestor changed"):
        compiled.check()
