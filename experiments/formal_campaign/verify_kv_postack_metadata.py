"""Replay one real TP2 metadata run under its preregistered final-prefix ACK clock."""

from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from .verify_kv_disabled_diagnostic import CORE, KERNEL, canonical, need, sha

CONFIGS = {
    "enabled": "062a2cace2bb6e444bdacb40e7884ea8670c7b2b9fdfb419704b58e29b1fb329"
}
COLLECTOR = "6b3e76d2f49e2c1360a898d06912bd745a4bf799abafe71c1f360e5a8c8fb925"
SOURCE = "7fc5f8700452bc3b3d7b94e8cc2903ff1a05d453"
POLICY = "source-fact-in-http-final-prefix-ack-v1"


def load_archive(manifest_path, archive_path):
    manifest = json.loads(Path(manifest_path).read_bytes())
    need(
        manifest["schema"] == "ecpa-real-TP2-postACK-metadata-archive/v1"
        and manifest["formal_result"] is False
        and manifest["KV_tensor_equivalence"] is None,
        "partial archive scope",
    )
    need(
        sha(Path(archive_path).read_bytes()) == manifest["archive_sha256"],
        "archive hash",
    )
    files = {}
    with tarfile.open(archive_path) as archive:
        for member in archive:
            p = Path(member.name)
            need(
                member.isfile()
                and not p.is_absolute()
                and ".." not in p.parts
                and member.name not in files
                and member.size < 16_000_000,
                "unsafe member",
            )
            files[member.name] = archive.extractfile(member).read()
    need(set(files) == set(manifest["inventory"]), "complete inventory")
    for name, raw in files.items():
        need(
            manifest["inventory"][name] == {"sha256": sha(raw), "bytes": len(raw)},
            "member hash/size",
        )
    return files


def frozen_replay(files, cfg):
    """Run exact 7fc5 pure-stdlib source in an isolated interpreter."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        package = root / "experiments"
        for p in (
            package,
            package / "exposure_gate",
            package / "native_challenge_candidate",
        ):
            p.mkdir(parents=True, exist_ok=True)
            (p / "__init__.py").write_bytes(b"")
        names = {
            "collector": "exposure_gate/native_semantic_collector.py",
            "kv-time-policy": "native_challenge_candidate/kv_time_policy.py",
            "request-runner": "native_challenge_candidate/request_runner.py",
            "collector-client": "native_challenge_candidate/collector_client.py",
            "kv-request-runner": "native_challenge_candidate/kv_request_runner.py",
            "kv-archive": "native_challenge_candidate/kv_archive.py",
        }
        sources = {x["role"]: x for x in cfg["sources"]}
        for role, name in names.items():
            raw = files["snapshots/" + sources[role]["sha256"]]
            need(sha(raw) == sources[role]["sha256"], "frozen interpreter source")
            (package / name).write_bytes(raw)
        snapshot = root / "original-archive"
        snapshot.mkdir()
        prefix = "enabled/portable-source-bound-snapshot/"
        for name, raw in files.items():
            if name.startswith(prefix):
                target = snapshot / name[len(prefix) :]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                target.chmod(0o600)
        manifest_sha = sha((snapshot / "manifest.json").read_bytes())
        script = """import sys,json,pathlib,base64
sys.path.insert(0,sys.argv[1])
from experiments.native_challenge_candidate import kv_archive,collector_client
from experiments.exposure_gate import native_semantic_collector as collector
r=pathlib.Path(sys.argv[2]);spec=json.loads((r/'spec.json').read_bytes());recipe=json.loads((r/'recipe.json').read_bytes());after=json.loads((r/'collector-after.json').read_bytes());phase=recipe['phases'][0]
proof=collector.verify_journal(r/'spec.json',r/'native.jsonl',acknowledged_prefix=after['status']['acknowledged_prefix'])
events=[json.loads(x) for x in (r/'native.jsonl').read_bytes().splitlines()]
joined=collector_client.phase_join(events,phase,proof,require_kv=True,collector_spec=spec)
try:
 result=kv_archive.verify(r,sys.argv[3],phase['phase_id']);window={'passed':True,'result':result}
except ValueError as exc:window={'passed':False,'error':str(exc)}
print(json.dumps({'proof':proof,'joined':joined,'original_window':window,'formal_result':False}))
"""
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-c",
                script,
                str(root),
                str(snapshot),
                manifest_sha,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        need(
            result.returncode == 0,
            "original source replay failed: " + result.stderr[-800:],
        )
        proof = json.loads(result.stdout)
        need(
            proof["original_window"]["passed"] is True,
            "new prospective clock replay failed",
        )
        return proof


def inspect(files):
    def raw(name):
        need(name in files, "missing raw: " + name)
        return files[name]

    def obj(name):
        return json.loads(raw(name))

    phases = {}
    outcomes = {}
    configs = {}
    for tag, expected in CONFIGS.items():
        cfg = obj(tag + "/owner-config.json")
        configs[tag] = cfg
        need(
            sha(raw(tag + "/owner-config.json")) == expected
            and obj(tag + "/run/owner-config.json") == cfg
            and cfg["formal_result"] is False
            and cfg["runner_source_commit"] == SOURCE,
            "original frozen runtime/input",
        )
        need(
            sha(raw(tag + "/owner.source.py")) == cfg["owner_source_sha256"]
            and sha(raw(tag + "/launcher.source.py"))
            == cfg["outer_launcher_source_sha256"],
            "executed source snapshots",
        )
        for source in cfg["sources"]:
            need(
                sha(raw("snapshots/" + source["sha256"])) == source["sha256"],
                "original source bytes",
            )
        need(
            len(cfg["model_files"]) == 14
            and set(cfg["wheel_artifacts"])
            == {"host", "ascend", "mod", "manager", "torch", "torch_npu", "triton"}
            and sha(raw("inputs/genuine-7b-stats.pt"))
            == cfg["calibration_artifact"]["sha256"],
            "model/wheel/calibration input closure",
        )
        recipe = obj(tag + "/recipe.json")
        need(sha(raw(tag + "/recipe.json")) == cfg["recipe_sha256"], "recipe bytes")
        phase = recipe["phases"][0]
        phases[tag] = phase
        need(
            phase["prompt_variant"] == "strict-system-copy-v1"
            and [m["role"] for m in phase["payload"]["messages"]] == ["system", "user"]
            and phase["tokenization"]["prompt_token_count"]
            == len(phase["tokenization"]["prompt_token_ids"])
            == 1201
            and phase["minimum_completion_tokens"] == 32
            and phase["rpc_budget_s"] == cfg["rpc_watchdog_s"] == 180
            and cfg["overall_watchdog_s"] == 1200,
            "frozen strict-copy task/budgets",
        )
        need(
            raw(tag + "/run/probe/request.bin") == canonical(phase["payload"])
            and obj(tag + "/run/probe/headers.json") == phase["headers"],
            "actual request bytes",
        )
        metadata = obj(tag + "/run/probe/response-metadata.json")
        rpc = obj(tag + "/run/probe/result.json")
        response_raw = raw(tag + "/run/probe/response.bin")
        response = json.loads(response_raw)
        need(
            metadata["status"] == rpc["status"] == 200
            and metadata["request_sha256"] == sha(raw(tag + "/run/probe/request.bin"))
            and metadata["response_sha256"]
            == rpc["response_sha256"]
            == sha(response_raw),
            "actual HTTP status/hash",
        )
        need(
            response["id"]
            == phase["expected_response_id"]
            == phase["external_request_id"]
            == "chatcmpl-" + phase["client_request_id"]
            and phase["payload"]["request_id"]
            == phase["headers"]["X-Request-Id"]
            == phase["client_request_id"]
            and response["model"] == phase["payload"]["model"],
            "actual external request/model identity",
        )
        need(
            response["choices"][0]["message"]["content"].strip()
            == phase["response_oracle"]["expected"]
            and response["choices"][0]["finish_reason"] == "stop"
            and response["usage"]["prompt_tokens"] == 1201
            and response["usage"]["completion_tokens"] == 77
            and rpc["rpc_task_passed"] is True,
            "actual exact task/prompt/decode evidence",
        )
        need(
            re.findall(
                r'"POST /v1/chat/completions HTTP/1.1" (\d+) ',
                raw(tag + "/run/backend.stdout").decode(),
            )
            == ["200"],
            "exactly one actual HTTP200 POST",
        )
        result = obj(tag + "/run/result.json")
        need(
            result["probe"]
            == {
                **rpc,
                "independent_phase_watchdog_fired": False,
                "independent_phase_total_elapsed_gate_passed": True,
            }
            and result["formal_result"] is False
            and not result["cleanup_errors"],
            "recorded live result binding",
        )
        watchdog = obj(tag + "/run/phase-watchdog.json")
        elapsed = obj(tag + "/run/phase-total-elapsed.json")
        need(
            watchdog["fired"] is False
            and watchdog["cancelled"] is True
            and elapsed["elapsed_gate_passed"] is True
            and 0
            <= elapsed["probe_completed_monotonic_ns"]
            - elapsed["probe_entry_monotonic_ns"]
            <= 180_000_000_000
            and 0
            <= metadata["received_monotonic_ns"] - metadata["sent_monotonic_ns"]
            <= 180_000_000_000,
            "recorded HTTP/phase budget",
        )
        outer_result = obj(tag + "/outer-watchdog-result.json")
        need(
            outer_result["fired"] is False
            and outer_result["original_owner_exit"] == 0
            and not outer_result["cleanup_errors"]
            and outer_result["overall_watchdog_s"] == 1200,
            "original overall watchdog",
        )
        launcher = obj(tag + "/run/launcher-kernel-identity.json")
        owner = obj(tag + "/actual-owner-kernel.json")["kernel"]
        peers = obj(tag + "/run/actual-owned-source-peers.json")
        need(
            {(p["process"]["role"], p["process"]["ordinal"]) for p in peers}
            == {("api-server", 0), ("worker", 0), ("worker", 1)}
            and len({p["process"]["pid"] for p in peers}) == 3,
            "actual source-assigned API and two ranks",
        )
        if tag == "disabled":
            binding = cfg["identity_binding"]
            need(
                binding["native_Manager_handoff_qualified"] is False
                and obj(tag + "/run/baseline-fixed-binding.json") == binding,
                "disabled IDs not native minted",
            )
            environment = binding["environment"]
            journal_name = "baseline-host-evidence.jsonl"
        else:
            binding = obj(tag + "/run/native-binding.json")
            handoff = raw(tag + "/run/handoff-raw.json")
            need(
                binding == {**json.loads(handoff), "binding_sha256": sha(handoff)}
                and binding["publisher"] == launcher
                and binding["manager_source_sha256"] == cfg["manager_source_sha256"],
                "actual native publisher/source/receipt bytes",
            )
            environment = binding["environment"]
            journal_name = Path(environment["VLLM_HUST_EXT_EVIDENCE_PATH"]).name
        journal = [json.loads(x) for x in raw(tag + "/" + journal_name).splitlines()]
        invoked = [r for r in journal if r["event"] == "invoked"]
        needed = CORE | ({"ascend_kvcompress"} if tag == "enabled" else set())
        need(
            {r["entry_point"]["name"] for r in invoked} == needed,
            "actual ordinary activation",
        )
        for peer in peers:
            p = peer["process"]
            need(
                peer["source_files"] == cfg["native_source_files"]
                and p["assignment_source"] == "host"
                and p["boot_id"] == launcher["boot_id"]
                and p["start_identity"]
                == f"pid:{p['pid']}:start_ticks:{p['start_ticks']}",
                "actual source/kernel identity",
            )
            name = "ascend_kvcompress" if tag == "enabled" else "ascend_model"
            matching = [
                r
                for r in invoked
                if r["entry_point"]["name"] == name
                and r["process"]["role"] == p["role"]
                and r["process"]["ordinal"] == p["ordinal"]
            ]
            need(
                len(matching) == 1
                and all(p[k] == v for k, v in matching[0]["process"].items())
                and matching[0]["plan_id"] == environment["VLLM_ECPA_PLAN_ID"]
                and matching[0]["launch_id"] == environment["VLLM_ECPA_LAUNCH_ID"],
                "native/fixed launch and exact Host peer",
            )
        terminal = obj(tag + "/run/terminal-process-audit.json")
        outer = obj(tag + "/outer-independent-terminal-audit.json")
        api = next(p["process"] for p in peers if p["process"]["role"] == "api-server")
        api_kernel = {k: api[k] for k in KERNEL}
        expected_outer = [owner, launcher, api_kernel]
        if tag == "enabled":
            descriptor = obj(tag + "/run/collector-launcher-descriptor.json")
            collector_kernel = {k: descriptor["collector"][k] for k in KERNEL}
            need(
                descriptor["launcher_observed_identity"] == descriptor["collector"],
                "actual collector observed identity",
            )
            expected_outer.append(collector_kernel)
        need(
            outer["captured_sessions"] == expected_outer
            and terminal["captured_sessions"] == [launcher, api_kernel],
            "all actual independently owned sessions retained",
        )
        for audit in (terminal, outer):
            need(
                audit["captured_sessions"]
                == [r["owner"] for r in audit["remaining_sessions"]]
                and all(not r["members"] for r in audit["remaining_sessions"]),
                "captured session terminal closure",
            )
        need(
            launcher in terminal["captured_sessions"]
            and owner in outer["captured_sessions"]
            and set(map(canonical, terminal["captured_sessions"]))
            <= set(map(canonical, outer["captured_sessions"]))
            and not outer["owner_identity_still_live"]
            and not outer["cleanup_errors"],
            "owner/Manager session cleanup",
        )
        need(
            [r["source_process"] for r in terminal["source_peers"]]
            == [p["process"] for p in peers]
            and all(
                r["expected_kernel"] == {k: r["source_process"][k] for k in KERNEL}
                and r["observed_kernel"] is None
                and r["same_identity_live"] is False
                for r in terminal["source_peers"]
            ),
            "exact peer epoch terminal closure",
        )
        need(
            terminal["wall_ns"] > max(r["observed_at_ns"] for r in journal)
            and terminal["backend_port"]["open"] is False,
            "terminal later than all Host records and port closed",
        )
        npu = raw(tag + "/run/terminal-npu-smi.txt").decode()
        need(
            set(re.findall(r"No running processes found in NPU (\d+)", npu))
            == {"3", "6"}
            and not re.search(r"^\|\s*\d+\s+\d+\s*\|\s*\d+\s*\|", npu, re.M),
            "actual two-card terminal no running",
        )
        manager = obj(tag + "/manager-config.json")
        need(
            manager["extensions"]["org.vllm-hust.ascend-kvcompress"]["enabled"]
            is (tag == "enabled"),
            "actual selected bundle configuration",
        )
        outcomes[tag] = {
            "HTTP_status": 200,
            "model_task_passed": True,
            "prompt_tokens": 1201,
            "completion_tokens": 77,
            "finish_reason": "stop",
            "response_sha256": sha(response_raw),
            "observed_HTTP_elapsed_s": (
                metadata["received_monotonic_ns"] - metadata["sent_monotonic_ns"]
            )
            / 1e9,
            "recorded_source_peers_and_terminal_cleanup_verified": True,
        }
    cfg = configs["enabled"]
    phase = phases["enabled"]
    need(phase["ack_time_policy"] == POLICY, "preregistered clock policy")
    need(
        next(s for s in cfg["sources"] if s["role"] == "collector")["sha256"]
        == COLLECTOR,
        "exact new collector",
    )
    prefix = "enabled/portable-source-bound-snapshot/"
    for name, source in {
        "recipe.json": "enabled/recipe.json",
        "spec.json": "enabled/run/collector-spec.json",
        "native.jsonl": "enabled/run/native-raw.jsonl",
        "descriptor.json": "enabled/run/collector-launcher-descriptor.json",
        **{
            n: "enabled/run/probe/" + n
            for n in (
                "request.bin",
                "headers.json",
                "response.bin",
                "response-metadata.json",
                "collector-before.json",
                "collector-after.json",
            )
        },
    }.items():
        need(raw(prefix + name) == raw(source), "exact original portable snapshot")
    spec = obj("enabled/run/collector-spec.json")
    need(
        spec["senders"] == obj("enabled/run/actual-owned-source-peers.json"),
        "native source peer preregistration",
    )
    native = [json.loads(x) for x in raw("enabled/run/native-raw.jsonl").splitlines()]
    need(
        len(native) == 160 and native[0]["collector_source_sha256"] == COLLECTOR,
        "all exact-source raw records retained",
    )
    metadata = obj("enabled/run/probe/response-metadata.json")
    phase_end = obj("enabled/run/phase-total-elapsed.json")[
        "probe_completed_monotonic_ns"
    ]
    authentication = obj("enabled/run/probe/collector-after.json")[
        "authentication_clock"
    ]
    need(
        metadata["received_monotonic_ns"]
        <= authentication["dispatch_monotonic_ns"]
        <= authentication["completed_monotonic_ns"]
        <= phase_end,
        "recorded post-HTTP authentication completes within original phase",
    )
    late = []
    for event in native[1:]:
        fact = json.loads(base64.b64decode(event["raw_base64"], validate=True))
        need(
            metadata["sent_monotonic_ns"]
            <= fact["monotonic_ns"]
            <= metadata["received_monotonic_ns"]
            and fact["monotonic_ns"] <= event["accepted_monotonic_ns"] <= phase_end,
            "source fact and bounded phase clock",
        )
        if event["accepted_monotonic_ns"] > metadata["received_monotonic_ns"]:
            late.append(
                {
                    "sequence": event["sequence"],
                    "rank": fact["process"]["ordinal"],
                    "after_HTTP_read_ns": event["accepted_monotonic_ns"]
                    - metadata["received_monotonic_ns"],
                }
            )
    need(
        late
        == [
            {"sequence": 158, "rank": 1, "after_HTTP_read_ns": 5233954},
            {"sequence": 159, "rank": 0, "after_HTTP_read_ns": 13161606},
        ],
        "two original late intakes retained",
    )
    replay = frozen_replay(files, cfg)
    result = replay["original_window"]["result"]
    need(
        replay["proof"]["native_chronology_status"] == "verified"
        and replay["proof"]["runtime_collector_source_sha256"] == COLLECTOR
        and replay["proof"]["durable_ACK_status"] == "verified-authenticated-prefix"
        and result["KV_MOD_metadata_upload_binding_observed"] is True
        and result["source_authenticated_native_upload_records"] == 156
        and result["source_authenticated_KV_projection_records"] == 2
        and result["ACK_time_contract"]["policy"] == POLICY
        and result["ACK_time_contract"]["selected_records"] == 159
        and result["ACK_time_contract"][
            "recorded_client_authentication_window_verified"
        ]
        is True,
        "finite recorded source/clock/ACK metadata proof",
    )
    for field in (
        "native_GPU_semantic_qualification",
        "KV_MOD_semantic_obligation_satisfied",
        "kv_tensor_equivalence",
        "attention_consumed_observed_tensor",
        "full_generation_quality",
        "full_objective_satisfied",
    ):
        need(result[field] is None, "metadata proof cannot promote semantic quality")
    return {
        "classification": "REAL_TP2_RECORDED_KV_METADATA_UPLOAD_BINDING_NONFORMAL",
        "actual_hardware_transport_observed": True,
        "model_task": outcomes["enabled"],
        "metadata_binding_verified": True,
        "raw_records": 160,
        "actual_GPU_uploads": 156,
        "materialized_row_projections": 2,
        "late_intakes_preserved": late,
        "ACK_time_contract": result["ACK_time_contract"],
        "formal_result": False,
        "formal_H3_starts": 0,
        "formal_H4_starts": 0,
        "KV_tensor_equivalence": None,
        "attention_consumed": None,
        "full_quality": None,
        "lost_requests": None,
        "duplicate_requests": None,
        "full_objective_satisfied": None,
        "performance_result": False,
        "fresh_OS_peer_authentication_performed": False,
        "late_observations_not_preregistration": True,
    }


def verify_archive(manifest_path, archive_path):
    return inspect(load_archive(manifest_path, archive_path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify_archive(args.manifest, args.archive), indent=2))


if __name__ == "__main__":
    main()
