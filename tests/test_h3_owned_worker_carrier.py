"""Actual CPU transport/process tests; no model/accelerator qualification."""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from experiments.formal_campaign.h3_owned_worker_carrier import (
    RegisteredAuthority,
    launch_phase,
    retain_failure,
    sha,
)
from vllm_hust_ext.ecpa_model import (
    EvidenceObligation,
    HostCompatibility,
    Plan,
    PluginIdentity,
    PredecessorSnapshot,
)
from vllm_hust_ext.plan_artifact import plan_artifact_bytes


def test_real_independent_unix_authority_rejects_missing_dynamic_profile(tmp_path):
    source = tmp_path / "authority.py"
    sock = tmp_path / "authority.sock"
    source.write_text("""import json,os,select,socket,sys
server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
server.bind(sys.argv[1]);os.chmod(sys.argv[1],0o600);server.listen()
print(os.getpid(),flush=True)
while True:
    ready,_,_=select.select([server,sys.stdin],[],[])
    if sys.stdin in ready: break
    c,_=server.accept()
    with c:
        raw=b''
        while not raw.endswith(b'\\n'): raw+=c.recv(4096)
        request=json.loads(raw)
        c.sendall(json.dumps({'ok':True,'profiles':[]}).encode()+b'\\n')
""")
    process = subprocess.Popen(
        [sys.executable, str(source), str(sock)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        assert int(process.stdout.readline()) == process.pid
        fields = Path(f"/proc/{process.pid}/stat").read_text().rsplit(")", 1)[1].split()
        kernel = {
            "pid": process.pid,
            "start_ticks": int(fields[19]),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        }
        source_ref = {"path": str(source), "sha256": sha(source.read_bytes())}
        recipe = {
            "authority": {
                "source": source_ref,
                "process_identity": kernel,
                "socket": str(sock),
                "backend_endpoint": "http://127.0.0.1:8188",
            }
        }
        registration = {
            "schema": "ecpa-h3-dynamic-deployment-receipt/v1",
            "starts": [
                {
                    "start_id": "cpu-only",
                    "authority": {
                        "registration_sha256": "sha256:" + "1" * 64,
                        "source_sha256": source_ref["sha256"],
                        "argv_sha256": sha(
                            json.dumps(
                                {"argv": [sys.executable, str(source), str(sock)]},
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode()
                        ),
                        "grant": {
                            "holder": "fixture",
                            "token": 1,
                            "expires_at": time.time() + 60,
                        },
                    },
                }
            ],
        }
        authority = RegisteredAuthority(recipe, registration, "cpu-only")
        with pytest.raises(ValueError, match="new-epoch enrollment"):
            authority.preflight()
    finally:
        process.stdin.close()
        assert process.wait(timeout=5) == 0


def test_actual_popen_failure_is_retained_as_launched_not_preflight(tmp_path):
    source = tmp_path / "early_exit.py"
    source.write_text("import time\ntime.sleep(.05)\n")
    plan = Plan(
        (PluginIdentity("org.cpu-fixture", "mod", "1", "a" * 64),),
        HostCompatibility("cpu-fixture", "1", "cpu", "1"),
        (),
        (EvidenceObligation("fixture-invoked", "worker", "invoked", (0,)),),
        PredecessorSnapshot(0, None, {}),
    )
    artifact = tmp_path / "plan.json"
    artifact.write_bytes(plan_artifact_bytes(plan))
    artifact.chmod(0o600)
    phase = {
        "origin": "host-baseline",
        "argv": [sys.executable, str(source)],
        "cwd": str(tmp_path),
        "environment": dict(os.environ),
        "handoff_path": None,
        "evidence_path": str(tmp_path / "events.jsonl"),
        "plan_artifact": {"path": str(artifact), "sha256": sha(artifact.read_bytes())},
        "launch_id": "cpu-only",
        "worker_ordinal": 0,
    }
    with pytest.raises((ValueError, TimeoutError)):
        launch_phase(phase, "manual-integration", tmp_path, 0, 1)
    observed = json.loads((tmp_path / "phase0.launch-observation.json").read_bytes())
    assert observed["pid"] > 0
    assert not Path(f"/proc/{observed['pid']}").exists()
    receipt, authority = (
        tmp_path / "input-receipt.json",
        tmp_path / "input-authority.json",
    )
    receipt.write_text("{}")
    authority.write_text("{}")
    args = argparse.Namespace(arm="manual-integration", repetition=1, arm_order=2)
    campaign = {
        "campaign_id": "H3-transactional-recovery-v1",
        "cell_id": "worker-crash",
        "fixed_identity": {},
    }
    retain_failure(
        tmp_path,
        campaign,
        args,
        ValueError("real early exit"),
        [observed],
        receipt,
        authority,
        {
            "processes_reclaimed": True,
            "ports_reclaimed": False,
            "devices_reclaimed": False,
        },
    )
    summary = json.loads((tmp_path / "actual-start-failure.json").read_bytes())
    record = json.loads((tmp_path / "launch-failure-provenance.json").read_bytes())
    assert summary["host_launched"] is True and summary["objective_met"] is None
    assert (
        record["evidence_class"] == "prospective-unverified"
        and record["formal_result"] is False
    )
    assert not (tmp_path / "record.json").exists()
    assert not (tmp_path / "preflight-rejection.json").exists()


def test_python_c_sourcepath_argument_is_not_registered_script_execution(tmp_path):
    from experiments.formal_campaign.h3_worker_relaunch import identity

    source = tmp_path / "authority.py"
    source.write_text("import sys;sys.stdin.read()\n")
    process = subprocess.Popen(
        [sys.executable, "-c", "import sys;sys.stdin.read()", str(source)],
        stdin=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        kernel = identity(process.pid)
        recipe = {
            "authority": {
                "source": {"path": str(source), "sha256": sha(source.read_bytes())},
                "process_identity": {
                    k: kernel[k] for k in ("pid", "start_ticks", "boot_id")
                },
                "socket": str(tmp_path / "absent.sock"),
            }
        }
        with pytest.raises(ValueError, match="exact registered script prefix"):
            RegisteredAuthority(recipe, {}, "cpu-only")
    finally:
        process.stdin.close()
        assert process.wait(timeout=5) == 0


def test_actual_rogue_unix_peer_receives_zero_grant_bytes(tmp_path, monkeypatch):
    import socket

    from experiments.formal_campaign.h3_client_trace import canonical
    from experiments.formal_campaign.h3_worker_relaunch import identity

    source = tmp_path / "authority.py"
    source.write_text("""import os, select, socket, sys

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[1])
os.chmod(sys.argv[1], 0o600)
s.listen()
print(os.getpid(), flush=True)
while True:
    ready, _, _ = select.select([s, sys.stdin], [], [])
    if sys.stdin in ready:
        break
    c, _ = s.accept()
    with c:
        raw = c.recv(65536)
        open(sys.argv[2], "ab").write(raw)
        if raw:
            c.sendall(b'{"ok":true}\\n')
""")
    path = tmp_path / "authority.sock"
    rogue_path = tmp_path / "rogue.sock"
    real_args = [
        sys.executable,
        str(source),
        str(path),
        str(tmp_path / "real.received"),
    ]
    rogue_args = [
        sys.executable,
        str(source),
        str(rogue_path),
        str(tmp_path / "rogue.received"),
    ]
    real = subprocess.Popen(
        real_args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    rogue = subprocess.Popen(
        rogue_args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        assert (
            int(real.stdout.readline()) == real.pid
            and int(rogue.stdout.readline()) == rogue.pid
        )
        kernel = identity(real.pid)
        source_ref = {"path": str(source), "sha256": sha(source.read_bytes())}
        recipe = {
            "authority": {
                "source": source_ref,
                "process_identity": {
                    k: kernel[k] for k in ("pid", "start_ticks", "boot_id")
                },
                "socket": str(path),
            }
        }
        registration = {
            "schema": "ecpa-h3-dynamic-deployment-receipt/v1",
            "starts": [
                {
                    "start_id": "cpu-only",
                    "authority": {
                        "registration_sha256": "sha256:" + "1" * 64,
                        "source_sha256": source_ref["sha256"],
                        "argv_sha256": sha(canonical({"argv": real_args})),
                        "grant": {
                            "holder": "secret-holder",
                            "token": 926,
                            "expires_at": time.time() + 60,
                        },
                    },
                }
            ],
        }
        authority = RegisteredAuthority(recipe, registration, "cpu-only")
        original = socket.socket.connect
        swapped = []

        def replace_just_before_connect(channel, address):
            if address == str(path) and not swapped:
                path.unlink()
                rogue_path.rename(path)
                swapped.append(True)
            return original(channel, address)

        monkeypatch.setattr(socket.socket, "connect", replace_just_before_connect)
        with pytest.raises(
            ValueError, match="peer is not the registered actual process; no grant sent"
        ):
            authority.call("capabilities")
        deadline = time.monotonic() + 2
        while (
            not (tmp_path / "rogue.received").exists() and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert (tmp_path / "rogue.received").read_bytes() == b""
    finally:
        for process in (real, rogue):
            process.stdin.close()
            assert process.wait(timeout=5) == 0
