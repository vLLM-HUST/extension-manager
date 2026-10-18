"""Manager issuer/launcher contract tests using actual Manager modules."""

import json
import os
import threading
from types import SimpleNamespace

import pytest

from experiments.formal_campaign import h3_observer_live_registration as registration
from experiments.formal_campaign.h3_observer_live_launcher import LiveGrants
from vllm_hust_ext.exposure_gate import GateError


def test_caller_trust_roots_or_ready_flag_cannot_enter_receipt_issuer(tmp_path):
    path = tmp_path / "caller.json"
    path.write_text(
        json.dumps(
            {
                "schema": registration.INTENT,
                "domain": registration.DOMAIN,
                "base_campaign": {},
                "base_receipt": {},
                "receipt_path": str(tmp_path / "receipt.json"),
                "starts": [],
                "ready": True,
                "trusted_roots": ["caller"],
            }
        )
    )
    with pytest.raises(GateError, match="exact independent live-continuation intent"):
        registration.issue(path, tmp_path / "receipt.json")


def test_unissued_scope_cannot_publish_launcher_grants():
    with pytest.raises(GateError, match="actual original authority"):
        LiveGrants(SimpleNamespace(), SimpleNamespace(ready=True))


def test_old_receipt_cannot_construct_new_issued_capability():
    with pytest.raises(GateError, match="independently issued"):
        registration.ValidatedLiveStart({"schema": "old-receipt", "ready": True}, {})


def test_forged_ready_file_with_wrong_actual_socket_kernel_is_rejected(tmp_path):
    import socket
    import time

    from experiments.exposure_gate import native_semantic_collector as native

    tmp_path.chmod(0o700)
    socket_path = tmp_path / "fake-ready.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    socket_path.chmod(0o600)
    server.listen(1)
    server.settimeout(2)

    def accept():
        with server.accept()[0] as peer:
            peer.recv(1)  # Real verifier closes immediately after credential mismatch.

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    actual = native.identity(os.getpid())
    wrong = {**actual, "pid": actual["pid"] + 1_000_000}
    metadata = socket_path.stat()
    ready_path = tmp_path / "ready.json"
    scope = SimpleNamespace(
        receipt_ref=lambda: {"path": "CPU-only", "sha256": "fixture-live-receipt"}
    )
    member = {
        "producer": wrong,
        "socket_path": str(socket_path),
        "ready_path": str(ready_path),
    }
    ready = dict(
        schema="ecpa-native-observer-control-ready/v2",
        producer=wrong,
        socket_identity=[metadata.st_dev, metadata.st_ino],
        socket_path=str(socket_path),
        policy_sha256="fixture-policy",
        receipt_sha256="fixture-live-receipt",
    )
    ready_path.write_bytes(native.canonical(ready))
    ready_path.chmod(0o600)
    launcher = LiveGrants.__new__(LiveGrants)
    launcher.recheck = lambda: None
    launcher.scope = scope
    launcher.endpoints = []
    launcher.group = [
        member,
        {**member, "producer": {**wrong, "pid": wrong["pid"] + 1}},
        {**member, "producer": {**wrong, "pid": wrong["pid"] + 2}},
    ]
    launcher.policies = {
        str(wrong["pid"]): (
            {
                "start_id": "observer-loss-r1-ecpa",
                "receipt_sha256": "fixture-live-receipt",
                "controller": actual,
                "control_nonce": "a" * 64,
            },
            {"sha256": "fixture-policy"},
        )
    }
    try:
        with pytest.raises(
            GateError, match="not actual source-owned original producer"
        ):
            launcher.wait_actual_endpoints(time.monotonic_ns() + 1_000_000_000)
    finally:
        thread.join(timeout=1)
        server.close()


@pytest.fixture
def runtime_sdk_sources(tmp_path, monkeypatch):
    """Tiny actual source files, explicitly no installed/NPU qualification."""
    import hashlib

    import vllm_hust_ext
    from experiments.formal_campaign import h3_observer_live_launcher as launcher

    repo = tmp_path / "repo"
    module = repo / "experiments/formal_campaign/h3_observer_live_launcher.py"
    module.parent.mkdir(parents=True)
    module.write_bytes(b"# actual tiny source fixture\n")
    package = tmp_path / "actual-runtime/site-packages/vllm_hust_ext"
    package.mkdir(parents=True)
    checkout = repo / "src/vllm_hust_ext"
    checkout.mkdir(parents=True)
    refs = {}
    for name in ("__init__.py", "runtime_evidence.py"):
        raw = ("# source fixture " + name + "\n").encode()
        (package / name).write_bytes(raw)
        (checkout / name).write_bytes(raw)
        refs["runtime-sdk:src/vllm_hust_ext/" + name] = hashlib.sha256(raw).hexdigest()
    refs["experiments/formal_campaign/h3_observer_live_launcher.py"] = hashlib.sha256(
        module.read_bytes()
    ).hexdigest()
    monkeypatch.setattr(vllm_hust_ext, "__file__", str(package / "__init__.py"))
    monkeypatch.setattr(launcher, "__file__", str(module))
    return launcher, refs, package, checkout, repo


def test_runtime_sdk_logical_refs_resolve_actual_nonempty_package(runtime_sdk_sources):
    launcher, refs, package, checkout, repo = runtime_sdk_sources
    observed = launcher._protocol_source_files(refs)
    assert {row["path"] for row in observed} == {
        str(package / "__init__.py"),
        str(package / "runtime_evidence.py"),
        str(repo / "experiments/formal_campaign/h3_observer_live_launcher.py"),
    }
    assert all("runtime-sdk:" not in row["path"] for row in observed)
    assert not (repo / "runtime-sdk:src/vllm_hust_ext/__init__.py").exists()
    assert launcher.native.source_digests(observed)


@pytest.mark.parametrize("changed", ["runtime", "checkout"])
def test_sdk_both_runtime_and_checkout_keep_original_hash_pins(
    runtime_sdk_sources, changed
):
    launcher, refs, package, checkout, _ = runtime_sdk_sources
    path = (package if changed == "runtime" else checkout) / "runtime_evidence.py"
    path.write_bytes(b"# changed after original issuance\n")
    with pytest.raises(ValueError, match="source bytes changed"):
        launcher._protocol_source_files(refs)


def test_runtime_sdk_inventory_cannot_drop_a_core_pin(runtime_sdk_sources):
    launcher, refs, _, _, _ = runtime_sdk_sources
    del refs["runtime-sdk:src/vllm_hust_ext/__init__.py"]
    with pytest.raises(GateError, match="complete package"):
        launcher._protocol_source_files(refs)


@pytest.mark.parametrize(
    "bad",
    [
        "runtime-sdk:src/vllm_hust_ext/../../outside.py",
        "runtime-sdk:/src/vllm_hust_ext/__init__.py",
        "runtime-sdk:src/vllm_hust_ext//__init__.py",
        "runtime-sdk:src/vllm_hust_ext/./__init__.py",
        "runtime-sdk:src/not_the_sdk/__init__.py",
        "runtime-sdk:src/vllm_hust_ext\\outside.py",
        "/etc/passwd",
        "../outside.py",
        "experiments/../../outside.py",
        "experiments//outside.py",
        "file:experiments/outside.py",
    ],
)
def test_logical_and_repository_path_escape_is_rejected(runtime_sdk_sources, bad):
    launcher, refs, _, _, _ = runtime_sdk_sources
    refs[bad] = "0" * 64
    with pytest.raises(GateError, match="inventory|namespace"):
        launcher._protocol_source_files(refs)


def test_repository_symlink_cannot_redirect_issued_code(runtime_sdk_sources, tmp_path):
    import hashlib

    launcher, refs, _, _, repo = runtime_sdk_sources
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "code.py").write_bytes(b"# outside fixture\n")
    (repo / "experiments/link").symlink_to(outside, target_is_directory=True)
    refs["experiments/link/code.py"] = hashlib.sha256(
        (outside / "code.py").read_bytes()
    ).hexdigest()
    with pytest.raises(GateError, match="canonical"):
        launcher._protocol_source_files(refs)
