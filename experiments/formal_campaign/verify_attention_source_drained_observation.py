"""Replay the frozen real R4 source-drained attention observation with stdlib."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

CONFIG_SHA256 = "e7526309a0da24d565263f8335b98d462f9ac9a9abc66899c746c2db4b2d2a73"
RECIPE_SHA256 = "df4a88eae1775d5cff9def2a3a97efa5ef544e3fe4acfa5f687657953ca3af50"
KERNEL = ("pid", "start_ticks", "session", "boot_id")
SCHEMA = "ecpa-real-attention-source-drained-observation-archive/v1"


ISOLATED_REPLAY_BOOTSTRAP = """
import os
import runpy
import sys

def audit(event, args):
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


def load_archive(manifest_path, directory):
    manifest = json.loads(Path(manifest_path).read_bytes())
    need(
        manifest["schema"] == SCHEMA
        and manifest["formal_result"] is False
        and manifest["GPU_qualification"] is None
        and manifest["full_model_quality"] is None
        and manifest["performance_result"] is None,
        "finite nonformal archive scope differs",
    )
    parts = []
    for index, item in enumerate(manifest["archive_parts"]):
        need(item["path"] == f"raw.tar.xz.part-{index:03d}", "archive part order")
        raw = (Path(directory) / item["path"]).read_bytes()
        need(len(raw) == item["bytes"] and sha(raw) == item["sha256"], "part bytes")
        parts.append(raw)
    compressed = b"".join(parts)
    need(sha(compressed) == manifest["archive_sha256"], "complete archive digest")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(compressed), mode="r:xz") as archive:
        for member in archive:
            path = Path(member.name)
            need(
                member.isfile()
                and not path.is_absolute()
                and ".." not in path.parts
                and member.name not in files
                and 0 <= member.size < 16_000_000,
                "unsafe or duplicate archive member",
            )
            files[member.name] = archive.extractfile(member).read()
    need(set(files) == set(manifest["inventory"]), "complete archive inventory")
    for name, raw in files.items():
        need(
            manifest["inventory"][name] == dict(bytes=len(raw), sha256=sha(raw)),
            "member bytes differ",
        )
    return files


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
            command, cwd=root, capture_output=True, text=True, timeout=90
        )
        need(result.returncode == 0, "frozen replay failed: " + result.stderr[-1200:])
        return json.loads(result.stdout)


def inspect(files):
    def raw(name):
        need(name in files, "missing archived evidence: " + name)
        return files[name]

    def obj(name):
        return json.loads(raw(name))

    cfg = obj("runtime/owner-config.json")
    need(
        sha(raw("runtime/owner-config.json")) == CONFIG_SHA256
        and obj("runtime/run/owner-config.json") == cfg
        and cfg["formal_result"] is False
        and sha(raw("runtime/recipe.json")) == cfg["recipe_sha256"] == RECIPE_SHA256,
        "frozen inputs differ",
    )
    need(
        sha(raw("runtime/owner.source.py")) == cfg["owner_source_sha256"]
        and sha(raw("runtime/launcher.source.py"))
        == cfg["outer_launcher_source_sha256"],
        "executed owner/launcher source differs",
    )
    for source in cfg["sources"]:
        need(
            sha(raw("snapshots/" + source["sha256"])) == source["sha256"],
            "source closure",
        )
    need(
        cfg["wheel_artifacts"]["host"]["revision"]
        == "04c0b19163aa350837bc63e11ec5b4e2a51db572"
        and cfg["wheel_artifacts"]["host"]["sha256"]
        == "adc33a1773741a0038320acb86fa64c4b79cf93f71c8dbc8d7de6649a516a29a"
        and cfg["wheel_artifacts"]["ascend"]["revision"]
        == "92c7ab31996708e0c425f991707b387c8d3de8f3"
        and len(cfg["model_files"]) == 14
        and len(cfg["wheel_artifacts"]) == 7
        and cfg["rpc_watchdog_s"] == 180
        and cfg["overall_watchdog_s"] == 1200,
        "exact runtime tuple or budgets differ",
    )
    peers = obj("runtime/run/actual-owned-source-peers.json")
    spec = obj("runtime/run/collector-spec.json")
    launcher = obj("runtime/run/launcher-kernel-identity.json")
    binding = obj("runtime/run/native-binding.json")
    handoff = raw("runtime/run/handoff-raw.json")
    need(
        binding == {**json.loads(handoff), "binding_sha256": sha(handoff)}
        and binding["publisher"] == launcher
        and binding["manager_source_sha256"] == cfg["manager_source_sha256"],
        "actual Manager publisher/source handoff differs",
    )
    environment = binding["environment"]
    journal_name = Path(environment["VLLM_HUST_EXT_EVIDENCE_PATH"]).name
    journal = [json.loads(x) for x in raw("runtime/" + journal_name).splitlines()]
    invoked = [r for r in journal if r["event"] == "invoked"]
    need(
        {r["entry_point"]["name"] for r in invoked}
        == {
            "ascend_kv_connector",
            "ascend_model",
            "ascend_model_loader",
            "ascend_kvcompress",
        },
        "ordinary Host activation source coverage differs",
    )
    need(
        spec["senders"] == peers
        and sorted(p["process"]["role"] for p in peers)
        == ["api-server", "worker", "worker"]
        and sorted(
            p["process"]["ordinal"] for p in peers if p["process"]["role"] == "worker"
        )
        == [0, 1]
        and all(p["source_files"] == cfg["native_source_files"] for p in peers),
        "actual source-assigned TP2 membership differs",
    )
    for peer in peers:
        process = peer["process"]
        matches = [
            r
            for r in invoked
            if r["entry_point"]["name"] == "ascend_kvcompress"
            and r["process"]["role"] == process["role"]
            and r["process"]["ordinal"] == process["ordinal"]
        ]
        need(
            process["assignment_source"] == "host"
            and process["boot_id"] == launcher["boot_id"]
            and process["start_identity"]
            == f"pid:{process['pid']}:start_ticks:{process['start_ticks']}"
            and len(matches) == 1
            and all(process[k] == v for k, v in matches[0]["process"].items())
            and matches[0]["plan_id"] == environment["VLLM_ECPA_PLAN_ID"]
            and matches[0]["launch_id"] == environment["VLLM_ECPA_LAUNCH_ID"],
            "actual Host process epoch or launch differs",
        )
    owner_result = obj("runtime/run/result.json")
    watchdog = obj("runtime/outer-watchdog-result.json")
    terminal = obj("runtime/run/terminal-process-audit.json")
    outer = obj("runtime/outer-independent-terminal-audit.json")
    owner = obj("runtime/actual-owner-kernel.json")["kernel"]
    api = next(p["process"] for p in peers if p["process"]["role"] == "api-server")
    api_kernel = {k: api[k] for k in KERNEL}
    descriptor = obj("runtime/run/collector-launcher-descriptor.json")
    collector_kernel = {k: descriptor["collector"][k] for k in KERNEL}
    need(
        descriptor["collector"] == descriptor["launcher_observed_identity"]
        and outer["captured_sessions"]
        == [owner, launcher, api_kernel, collector_kernel]
        and terminal["captured_sessions"] == [launcher, api_kernel]
        and all(
            audit["captured_sessions"]
            == [s["owner"] for s in audit["remaining_sessions"]]
            for audit in (terminal, outer)
        ),
        "independently captured session coverage differs",
    )
    need(
        owner_result["passed"] is True
        and not owner_result["cleanup_errors"]
        and watchdog["original_owner_exit"] == 0
        and watchdog["fired"] is False
        and not watchdog["cleanup_errors"]
        and not outer["owner_identity_still_live"]
        and not outer["cleanup_errors"]
        and all(not s["members"] for s in outer["remaining_sessions"])
        and all(not s["members"] for s in terminal["remaining_sessions"])
        and terminal["backend_port"]["open"] is False,
        "original success/watchdog/session cleanup differs",
    )
    need(
        [p["source_process"] for p in terminal["source_peers"]]
        == [p["process"] for p in peers]
        and all(
            p["expected_kernel"] == {k: p["source_process"][k] for k in KERNEL}
            and p["observed_kernel"] is None
            and p["same_identity_live"] is False
            for p in terminal["source_peers"]
        ),
        "source peer epoch cleanup differs",
    )
    npu = raw("runtime/run/terminal-npu-smi.txt").decode()
    need(
        set(re.findall(r"No running processes found in NPU (\d+)", npu)) == {"3", "6"},
        "NPU cleanup",
    )
    observed = frozen_replay(files, cfg)
    need(
        observed["observed_typed_HTTP_ACK_join"] is True
        and observed["model_task_passed"] is True
        and observed["tensor_receipt_count"] == observed["operator_receipt_count"] == 56
        and observed["formal_result"] is False,
        "finite captured consumer outcome differs",
    )
    return dict(
        schema="ecpa-real-attention-source-drained-portable-replay/v1",
        observed_typed_HTTP_ACK_join=True,
        model_task_passed=True,
        tensor_receipt_count=56,
        operator_receipt_count=56,
        frozen_consumer_replayed_isolated=True,
        original_epochs_and_cleanup_verified=True,
        formal_result=False,
        formal_H3_starts=0,
        formal_H4_starts=0,
        full_model_quality=None,
        performance_result=None,
        whole_journal_sha256=observed["whole_journal_sha256"],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive-dir", required=True, type=Path)
    args = parser.parse_args()
    files = load_archive(args.archive_dir / "manifest.json", args.archive_dir)
    print(json.dumps(inspect(files), sort_keys=True))


if __name__ == "__main__":
    main()
