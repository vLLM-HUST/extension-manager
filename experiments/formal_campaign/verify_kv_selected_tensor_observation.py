"""Replay one complete real selected-KV byte observation; no formal admission."""

from __future__ import annotations

import argparse
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

from .verify_kv_disabled_diagnostic import CORE, KERNEL, canonical, need, sha

CONFIGS = {
    "enabled": "98aefd628a2978947b084b0208b5de84118523985eb2b5cee2088aa9c30a30d1"
}
COLLECTOR = "6b3e76d2f49e2c1360a898d06912bd745a4bf799abafe71c1f360e5a8c8fb925"
SOURCE = "0666cf001db4f2a6247f6da6b2c12ad0b97e5560"
POLICY = "source-fact-in-http-final-prefix-ack-v1"


def load_archive(manifest_path, archive_directory):
    manifest = json.loads(Path(manifest_path).read_bytes())
    need(
        manifest["schema"] == "ecpa-real-selected-KV-tensor-observation-archive/v1"
        and manifest["formal_result"] is False
        and manifest["GPU_qualification"] is None
        and manifest["attention_consumption"] is None
        and manifest["full_quality"] is None,
        "finite archive scope",
    )
    directory = Path(archive_directory)
    parts = []
    for index, item in enumerate(manifest["archive_parts"]):
        need(
            item["path"] == f"raw.tar.xz.part-{index:03d}",
            "ordered complete archive parts",
        )
        raw = (directory / item["path"]).read_bytes()
        need(
            len(raw) == item["bytes"] and sha(raw) == item["sha256"],
            "archive part bytes",
        )
        parts.append(raw)
    primary = b"".join(parts)
    need(sha(primary) == manifest["archive_sha256"], "whole original XZ digest")
    need(
        manifest["source_extra_archive"] == "source-extra.tar.xz", "source archive name"
    )
    extra = (directory / "source-extra.tar.xz").read_bytes()
    need(sha(extra) == manifest["source_extra_sha256"], "complete source archive")
    files = {}
    for compressed in (primary, extra):
        with tarfile.open(fileobj=io.BytesIO(compressed), mode="r:xz") as archive:
            for member in archive:
                path = Path(member.name)
                need(
                    member.isfile()
                    and not path.is_absolute()
                    and ".." not in path.parts
                    and member.name not in files
                    and 0 <= member.size < 16_000_000,
                    "safe complete member",
                )
                files[member.name] = archive.extractfile(member).read()
    need(set(files) == set(manifest["inventory"]), "complete global inventory")
    for name, raw in files.items():
        need(
            manifest["inventory"][name] == dict(sha256=sha(raw), bytes=len(raw)),
            "member hash and size",
        )
    return files


def frozen_replay(files, cfg):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        package = root / "experiments"
        for part in (
            package,
            package / "exposure_gate",
            package / "native_challenge_candidate",
            package / "native_kv_tensor_candidate",
        ):
            part.mkdir(parents=True, exist_ok=True)
            (part / "__init__.py").write_bytes(b"")
        names = {
            "collector": "exposure_gate/native_semantic_collector.py",
            "request-runner": "native_challenge_candidate/request_runner.py",
            "collector-client": "native_challenge_candidate/collector_client.py",
            "kv-request-runner": "native_challenge_candidate/kv_request_runner.py",
            "kv-time-policy": "native_challenge_candidate/kv_time_policy.py",
            "tensor-transport": "native_kv_tensor_candidate/artifact_transport.py",
            "tensor-witness": "native_kv_tensor_candidate/witness.py",
            "tensor-runtime": "native_kv_tensor_candidate/runtime_contract.py",
            "tensor-campaign-consumer": (
                "native_kv_tensor_candidate/campaign_consumer.py"
            ),
            "tensor-projection-join": (
                "native_kv_tensor_candidate/projection_tensor_join.py"
            ),
        }
        sources = {x["role"]: x for x in cfg["sources"]}
        for role, name in names.items():
            source = sources[role]
            raw = files["snapshots/" + source["sha256"]]
            need(sha(raw) == source["sha256"], "exact frozen interpreter source")
            (package / name).write_bytes(raw)
        original = root / "runtime"
        original.mkdir()
        for name, raw in files.items():
            if name.startswith("runtime/"):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raw)
                target.chmod(0o600)
        recipe = json.loads(files["runtime/recipe.json"])
        mapping = {}
        all_sources = list(recipe["sources"])
        for phase in recipe["phases"]:
            binding = phase["tokenization"]["runtime_binding"]
            all_sources.extend(
                phase["tokenization"]["assets"]
                + [binding["implementation_source"]]
                + binding["host_sources"]
            )
        for source in all_sources:
            target = root / ("source-" + source["sha256"])
            target.write_bytes(files["snapshots/" + source["sha256"]])
            target.chmod(0o600)
            mapping[source["path"]] = str(target)
        source_map = root / "source-map.json"
        source_map.write_text(json.dumps(mapping))
        run = original / "run"
        command = [
            sys.executable,
            "-I",
            "-S",
            "-c",
            (
                "import sys,runpy;sys.path.insert(0,sys.argv.pop(1));"
                "runpy.run_module('experiments.native_kv_tensor_candidate.campaign_consumer',"
                "run_name='__main__')"
            ),
            str(root),
            "--recipe",
            str(original / "recipe.json"),
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
            "--source-map",
            str(source_map),
        ]
        process = subprocess.run(command, capture_output=True, text=True, timeout=60)
        need(
            process.returncode == 0,
            "exact mixed source replay failed: " + process.stderr[-800:],
        )
        return json.loads(process.stdout)


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
        cfg = obj("runtime/owner-config.json")
        configs[tag] = cfg
        need(
            sha(raw("runtime/owner-config.json")) == expected
            and obj("runtime/run/owner-config.json") == cfg
            and cfg["formal_result"] is False
            and cfg["runner_source_commit"] == SOURCE,
            "original frozen runtime/input",
        )
        need(
            sha(raw("runtime/owner.source.py")) == cfg["owner_source_sha256"]
            and sha(raw("runtime/launcher.source.py"))
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
        recipe = obj("runtime/recipe.json")
        need(sha(raw("runtime/recipe.json")) == cfg["recipe_sha256"], "recipe bytes")
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
            raw("runtime/run/probe/request.bin") == canonical(phase["payload"])
            and obj("runtime/run/probe/headers.json") == phase["headers"],
            "actual request bytes",
        )
        metadata = obj("runtime/run/probe/response-metadata.json")
        rpc = obj("runtime/run/probe/result.json")
        response_raw = raw("runtime/run/probe/response.bin")
        response = json.loads(response_raw)
        need(
            metadata["status"] == rpc["status"] == 200
            and metadata["request_sha256"] == sha(raw("runtime/run/probe/request.bin"))
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
            and response["usage"]["completion_tokens"] == 69
            and rpc["rpc_task_passed"] is True,
            "actual exact task/prompt/decode evidence",
        )
        need(
            re.findall(
                r'"POST /v1/chat/completions HTTP/1.1" (\d+) ',
                raw("runtime/run/backend.stdout").decode(),
            )
            == ["200"],
            "exactly one actual HTTP200 POST",
        )
        result = obj("runtime/run/result.json")
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
        watchdog = obj("runtime/run/phase-watchdog.json")
        elapsed = obj("runtime/run/phase-total-elapsed.json")
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
        outer_result = obj("runtime/outer-watchdog-result.json")
        need(
            outer_result["fired"] is False
            and outer_result["original_owner_exit"] == 0
            and not outer_result["cleanup_errors"]
            and outer_result["overall_watchdog_s"] == 1200,
            "original overall watchdog",
        )
        launcher = obj("runtime/run/launcher-kernel-identity.json")
        owner = obj("runtime/actual-owner-kernel.json")["kernel"]
        peers = obj("runtime/run/actual-owned-source-peers.json")
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
                and obj("runtime/run/baseline-fixed-binding.json") == binding,
                "disabled IDs not native minted",
            )
            environment = binding["environment"]
            journal_name = "baseline-host-evidence.jsonl"
        else:
            binding = obj("runtime/run/native-binding.json")
            handoff = raw("runtime/run/handoff-raw.json")
            need(
                binding == {**json.loads(handoff), "binding_sha256": sha(handoff)}
                and binding["publisher"] == launcher
                and binding["manager_source_sha256"] == cfg["manager_source_sha256"],
                "actual native publisher/source/receipt bytes",
            )
            environment = binding["environment"]
            journal_name = Path(environment["VLLM_HUST_EXT_EVIDENCE_PATH"]).name
        journal = [json.loads(x) for x in raw("runtime/" + journal_name).splitlines()]
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
        terminal = obj("runtime/run/terminal-process-audit.json")
        outer = obj("runtime/outer-independent-terminal-audit.json")
        api = next(p["process"] for p in peers if p["process"]["role"] == "api-server")
        api_kernel = {k: api[k] for k in KERNEL}
        expected_outer = [owner, launcher, api_kernel]
        if tag == "enabled":
            descriptor = obj("runtime/run/collector-launcher-descriptor.json")
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
        npu = raw("runtime/run/terminal-npu-smi.txt").decode()
        need(
            set(re.findall(r"No running processes found in NPU (\d+)", npu))
            == {"3", "6"}
            and not re.search(r"^\|\s*\d+\s+\d+\s*\|\s*\d+\s*\|", npu, re.M),
            "actual two-card terminal no running",
        )
        manager = obj("runtime/manager-config.json")
        need(
            manager["extensions"]["org.vllm-hust.ascend-kvcompress"]["enabled"]
            is (tag == "enabled"),
            "actual selected bundle configuration",
        )
        outcomes[tag] = {
            "HTTP_status": 200,
            "model_task_passed": True,
            "prompt_tokens": 1201,
            "completion_tokens": 69,
            "finish_reason": "stop",
            "response_sha256": sha(response_raw),
            "observed_HTTP_elapsed_s": (
                metadata["received_monotonic_ns"] - metadata["sent_monotonic_ns"]
            )
            / 1e9,
            "recorded_source_peers_and_terminal_cleanup_verified": True,
        }
    cfg = configs["enabled"]
    spec = obj("runtime/run/collector-spec.json")
    need(
        spec["senders"] == obj("runtime/run/actual-owned-source-peers.json"),
        "exact native source preregistration",
    )
    native = [json.loads(x) for x in raw("runtime/run/native-raw.jsonl").splitlines()]
    need(
        len(native) == 201
        and native[0]["collector_source_sha256"] == COLLECTOR
        and native[1]["transport_source_sha256"]
        == "0571301b98cef1569eb6010a0b5d4659b96ec7556f18a875e0ea806b26613fcb",
        "complete exact mixed journal",
    )
    by_rank = {0: [], 1: []}
    for event in native:
        if event["kind"] == "tensor.artifact.accepted":
            payload = raw("runtime/run/" + event["artifact"]["basename"])
            fact = json.loads(payload)
            binding = fact["binding"]
            need(
                binding["layer_name"]
                == f"model.layers.{binding['layer_index']}.self_attn.attn",
                "fixed Qwen layer name/index binding",
            )
            by_rank[binding["rank"]].append(fact)
    for facts in by_rank.values():
        need(
            len(facts) == 28
            and {f["binding"]["layer_index"] for f in facts} == set(range(28)),
            "all actual layers per rank",
        )
        for kind in ("K", "V"):
            need(
                len({f["cache_views"][kind]["before"]["data_ptr"] for f in facts})
                == 28,
                "same-rank fixed-corpus virtual cache pointers are distinct",
            )
    metadata = obj("runtime/run/probe/response-metadata.json")
    phase_end = obj("runtime/run/phase-total-elapsed.json")[
        "probe_completed_monotonic_ns"
    ]
    after = obj("runtime/run/probe/collector-after.json")
    clock = after["authentication_clock"]
    need(
        metadata["received_monotonic_ns"]
        <= clock["dispatch_monotonic_ns"]
        <= clock["completed_monotonic_ns"]
        <= phase_end,
        "post-HTTP authentication is inside captured phase",
    )
    result = frozen_replay(files, cfg)
    need(
        result["classification"] == "REAL_RUNTIME_UNQUALIFIED"
        and result["observed_typed_HTTP_ACK_join"] is True
        and result["model_task_passed"] is True
        and result["tensor_receipt_count"] == 56
        and result["typed_archive_provenance"]["durable_artifact_join_complete"] is True
        and result["ACK_time_contract"]["selected_records"] == 199,
        "finite complete selected observation",
    )
    for field in (
        "GPU_qualification",
        "attention_consumption",
        "full_model_quality",
        "full_objective_satisfied",
    ):
        need(
            result[field] is None, "selected logical bytes cannot promote full quality"
        )
    return {
        "classification": "REAL_RUNTIME_UNQUALIFIED",
        "actual_hardware_transport_observed": True,
        "model_task": outcomes["enabled"],
        "selected_logical_KV_byte_observation": True,
        "mixed_typed_HTTP_ACK_join": True,
        "tensor_receipts": 56,
        "all_named_Qwen_layers_per_rank": 28,
        "same_rank_observed_virtual_pointers_distinct": True,
        "whole_mixed_journal_rows": 201,
        "ACK_time_contract": result["ACK_time_contract"],
        "typed_plan_projection_upload_join": result[
            "typed_plan_projection_upload_join"
        ],
        "formal_result": False,
        "formal_H3_starts": 0,
        "formal_H4_starts": 0,
        "all_physical_storage_equivalence": None,
        "attention_consumption": None,
        "full_model_quality": None,
        "lost_requests": None,
        "duplicate_requests": None,
        "full_objective_satisfied": None,
        "performance_result": False,
        "fresh_OS_peer_authentication_performed": False,
        "late_observations_not_preregistration": True,
    }


def verify_archive(manifest_path, archive_directory):
    return inspect(load_archive(manifest_path, archive_directory))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--archive-directory", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify_archive(args.manifest, args.archive_directory), indent=2))


if __name__ == "__main__":
    main()
