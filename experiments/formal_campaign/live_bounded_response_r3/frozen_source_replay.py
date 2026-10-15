"""Frozen-stdlib consumer replay adapter reused from the published R4 verifier.

Only packaged captured sources are loaded; no current SDK or live host is read.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ISOLATED_REPLAY_BOOTSTRAP = """
import os
import runpy
import sys

def audit(event, args):
    if event in ('socket.connect', 'socket.bind', 'socket.sendto', 'subprocess.Popen'):
        raise PermissionError('offline replay attempted live I/O')
    if event in ('open', 'os.listdir', 'os.scandir') and args:
        path = args[0]
        if isinstance(path, (str, bytes)):
            if os.fsdecode(path).startswith(('/root/', '/models/', '/proc/', '/dev/')):
                raise PermissionError('offline replay consulted original host')

sys.addaudithook(audit)
sys.path.insert(0, sys.argv.pop(1))
runpy.run_module('experiments.native_attention_candidate.drain_consumer',
                 run_name='__main__')
"""


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def frozen_replay(files, cfg):
    """Run captured consumer bytes with no site packages or current OS claims."""
    names = {
        "collector": "exposure_gate/native_semantic_collector.py",
        "request-runner": "native_challenge_candidate/request_runner.py",
        "collector-client": "native_challenge_candidate/collector_client.py",
        "kv-request-runner": "native_challenge_candidate/kv_request_runner.py",
        "kv-time-policy": "native_challenge_candidate/kv_time_policy.py",
        "kv-archive": "native_challenge_candidate/kv_archive.py",
        "tensor-transport": "native_kv_tensor_candidate/artifact_transport.py",
        "tensor-witness": "native_kv_tensor_candidate/witness.py",
        "tensor-runtime": "native_kv_tensor_candidate/runtime_contract.py",
        "tensor-campaign-consumer": "native_kv_tensor_candidate/campaign_consumer.py",
        "tensor-projection-join": (
            "native_kv_tensor_candidate/projection_tensor_join.py"
        ),
        "attention-consumer": "native_attention_candidate/attention_consumer.py",
        "attention-collector": "native_attention_candidate/collector.py",
        "attention-observer": "native_attention_candidate/operator_observer.py",
        "attention-drain-collector": "native_attention_candidate/drain_collector.py",
        "attention-drain-consumer": "native_attention_candidate/drain_consumer.py",
        "attention-drain-time": "native_attention_candidate/drain_time_policy.py",
        "attention-phase-drain": "native_attention_candidate/phase_drain.py",
    }
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        sources = {item["role"]: item for item in cfg["sources"]}
        for role, name in names.items():
            source = sources[role]
            raw = files["snapshots/" + source["sha256"]]
            need(sha(raw) == source["sha256"], "captured consumer bytes differ")
            target = root / "experiments" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        for name, raw in files.items():
            if name.startswith("runtime/"):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                target.chmod(0o600)
        recipe = json.loads(files["runtime/recipe.json"])
        all_sources = list(recipe["sources"])
        for phase in recipe["phases"]:
            binding = phase["tokenization"]["runtime_binding"]
            all_sources.extend(
                phase["tokenization"]["assets"]
                + [binding["implementation_source"]]
                + binding["host_sources"]
            )
        mapping = {}
        for source in all_sources:
            target = root / ("source-" + source["sha256"])
            raw = files["snapshots/" + source["sha256"]]
            need(sha(raw) == source["sha256"], "frozen dependency bytes differ")
            target.write_bytes(raw)
            mapping[source["path"]] = str(target)
        source_map = root / "source-map.json"
        source_map.write_text(json.dumps(mapping))
        runtime = root / "runtime"
        run = runtime / "run"
        command = [
            sys.executable,
            "-I",
            "-S",
            "-c",
            ISOLATED_REPLAY_BOOTSTRAP,
            str(root),
            "--recipe",
            str(runtime / "recipe.json"),
            "--phase",
            recipe["phases"][0]["phase_id"],
            "--output",
            str(run / "probe"),
            "--descriptor",
            str(run / "collector-launcher-descriptor.json"),
            "--spec",
            str(run / "collector-spec.json"),
            "--journal",
            str(run / "native-raw.jsonl"),
            "--policy",
            str(run / "tensor-policy.json"),
            "--drain-policy",
            str(run / "drain-policy.json"),
            "--source-map",
            str(source_map),
        ]
        result = subprocess.run(
            command, check=False, cwd=root, capture_output=True, text=True, timeout=90
        )
        need(result.returncode == 0, "frozen replay failed: " + result.stderr[-1200:])
        return json.loads(result.stdout)
