"""Source-bound failed attempts and a separate CPU-only calibration input check."""

from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import importlib
import importlib.util
import json
import re
import sys
import tarfile
import tempfile
import types
from pathlib import Path

COLLECTOR = "6eba068c13bcf739317799f4df3bd9ba6437bab5e782e7ae28117106825fd4ef"
STATS = "d8cc47fbdae931785fcbed403fcc688d1b12000cee76e591622c7d70e3b254d7"
CALIBRATION_SOURCE = "c596867a7866e85a8fc5867b9b1cd4204014a19dd4a3ae00c905e1901d4dd2ee"
HOST = "f575fac91bf30059210b185bd6bcbfab32f42bb757c29a605fd3a57a06937aa3"
ASCEND = "be5a69b8dc2dd9a77144657a6d394aa7079e95054aef54dda41f260b0af6eb86"
MOD = "8f53c169e641b1f5569584ab862d3dfc47f18693272b63ca55f7d5c53b11abca"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def need(value, message):
    if not value:
        raise ValueError(message)


def load_archive(manifest_path, archive_path):
    manifest = json.loads(Path(manifest_path).read_bytes())
    need(
        manifest["schema"] == "ecpa-7b-calibration-and-KV-failures-archive/v1"
        and manifest["formal_result"] is False,
        "archive scope",
    )
    need(
        sha(Path(archive_path).read_bytes()) == manifest["archive_sha256"],
        "archive hash",
    )
    files = {}
    with tarfile.open(archive_path) as archive:
        for member in archive:
            path = Path(member.name)
            need(
                member.isfile()
                and not path.is_absolute()
                and ".." not in path.parts
                and member.name not in files,
                "unsafe or duplicate archive member",
            )
            need(member.size < 16_000_000, "unbounded member")
            files[member.name] = archive.extractfile(member).read()
    need(set(files) == set(manifest["inventory"]), "complete inventory")
    for name, raw in files.items():
        item = manifest["inventory"][name]
        need(
            sha(raw) == item["sha256"] and len(raw) == item["bytes"], "member hash/size"
        )
    return manifest, files


def inspect(files):
    def raw(name):
        need(name in files, "missing original raw: " + name)
        return files[name]

    def obj(name):
        return json.loads(raw(name))

    def npu(name):
        text = raw(name).decode()
        need(
            set(re.findall(r"No running processes found in NPU (\d+)", text))
            == {"3", "6"}
            and set(re.findall(r"^\|\s*(\d+)\s+910B2\s*\|", text, re.M)) == {"3", "6"}
            and not re.search(r"^\|\s*\d+\s+\d+\s*\|\s*\d+\s*\|", text, re.M),
            "actual two-card terminal no-running raw",
        )

    need(
        sha(raw("calibration/recipe.json"))
        == "020b42ed2b0024a161e6de594aed9e8b9986c496f82a7952aec94e3675738c0e",
        "original calibration freeze ledger",
    )
    calibration = obj("calibration/recipe.json")
    need(
        calibration["formal_result"] is False
        and calibration["TP2_calibration"] is False
        and calibration["actual_token_count"] == 4096,
        "single-device calibration scope",
    )
    need(
        sha(raw("calibration/owner.source.py")) == calibration["owner_source_sha256"]
        and obj("calibration/run/frozen-recipe.json") == calibration,
        "calibration owner/freeze",
    )
    need(
        sha(raw("calibration/builtin-multilingual-input.txt"))
        == calibration["input"]["sha256"],
        "calibration text input",
    )
    tokens = obj("calibration/actual-tokenizer-input-ids.json")
    need(
        tokens["actual_length"] == len(tokens["input_ids"][0]) == 4096
        and sha(raw("calibration/actual-tokenizer-input-ids.json"))
        == calibration["tokenizer_ids_sha256"]
        and tokens["text_sha256"] == calibration["input"]["sha256"],
        "actual calibration IDs",
    )
    for source in calibration["sources"]:
        name = "calibration/" + Path(source.get("snapshot", source["path"])).name
        # Wheels were pre-execution hashed but their large original bytes are omitted.
        if name in files:
            need(
                sha(raw(name)) == source["sha256"], "original calibration source bytes"
            )
        else:
            need(source["path"].endswith(".whl"), "missing calibration source snapshot")
    owned = obj("calibration/run/actual-owned-process.json")
    need(
        owned["argv"] == calibration["argv"]
        and owned["cmdline_sha256"]
        == sha(b"\0".join(x.encode() for x in owned["argv"]) + b"\0"),
        "actual calibration argv",
    )
    terminal = obj("calibration/run/terminal-process-audit.json")
    need(
        terminal["captured_sessions"] == [owned["kernel"]]
        and terminal["remaining_sessions"]
        == [{"owner": owned["kernel"], "members": []}],
        "actual calibration owned session terminal",
    )
    need(
        b"generated calibration artifact:" in raw("calibration/run/stdout")
        and b"FileNotFoundError: [Errno 2] No such file or directory: 'npu-smi'"
        in raw("calibration/owner-cli.stderr")
        and "calibration/run/result.json" not in files,
        "original failed wrapper/missing leaf status retained",
    )
    late = obj("calibration/late-terminal-diagnostic-audit.json")
    need(
        late["actual_tool_path"] == "/usr/local/sbin/npu-smi"
        and late["returncode"] == 0
        and late["original_wrapper_exit"] == 1
        and late["leaf_exit_status_independently_recorded"] is False
        and late["generator_pid868137_exists"] is False
        and late["frozen_recipe_modified"] is False,
        "late diagnostic cannot promote wrapper/leaf status",
    )
    npu("calibration/late-terminal-npu-smi.stdout")
    need(
        sha(raw("calibration/qwen2.5-7b-genuine-global-head-stats.pt")) == STATS,
        "exact generated artifact",
    )
    model_files = calibration["model_files"]
    need(
        len(model_files) == 14 and len({x["path"] for x in model_files}) == 14,
        "original fourteen full model hash records",
    )
    config_row = next(x for x in model_files if Path(x["path"]).name == "config.json")
    need(
        sha(raw("inputs/model-config.json")) == config_row["sha256"],
        "actual model config",
    )
    observations = {}
    for attempt in ("effect-r3", "effect-r4"):
        prefix = attempt + "/"
        cfg, recipe = obj(prefix + "owner-config.json"), obj(prefix + "recipe.json")
        need(
            cfg["formal_result"] is False
            and cfg["scope"] == "KV-host-metadata-to-later-upload-only"
            and cfg["model_files"]
            == [{k: x[k] for k in ("path", "sha256")} for x in model_files],
            "effect model/scope bound to calibration",
        )
        need(
            sha(raw(prefix + "owner.source.py")) == cfg["owner_source_sha256"]
            and sha(raw(prefix + "recipe.json")) == cfg["recipe_sha256"],
            "effect frozen source/recipe",
        )
        need(
            cfg["physical_devices"] == [3, 6]
            and cfg["runtime_devices"] == [0, 1]
            and cfg["calibration_artifact"]["sha256"] == STATS,
            "effect devices/input stats",
        )
        need(
            all(
                cfg["wheel_artifacts"][k]["sha256"] == value
                for k, value in [("host", HOST), ("ascend", ASCEND), ("mod", MOD)]
            ),
            "exact native wheel tuple",
        )
        need(
            obj(prefix + "installed-source-audit.json")["artifacts"]
            == cfg["wheel_artifacts"],
            "installed tuple provenance",
        )
        need(
            cfg["env"]["VLLM_PLUGINS"]
            == "ascend_kv_connector,ascend_model,ascend_model_loader"
            and "VLLM_ASCEND_KVCOMPRESS_CONFIG" not in cfg["env"],
            "activation input closure",
        )
        snapshots = obj(prefix + "source-snapshot-map.json")
        need(len(snapshots) == len(cfg["sources"]), "source snapshot closure")
        for snapshot, original in zip(snapshots, cfg["sources"], strict=True):
            need(
                all(snapshot[k] == value for k, value in original.items())
                and sha(raw(snapshot["archived_path"])) == original["sha256"],
                "post-run exact-source snapshot",
            )
        source_paths = {x["path"]: x["sha256"] for x in snapshots}
        need(
            all(
                source_paths.get(x["path"]) == x["sha256"]
                for x in cfg["native_source_files"]
            ),
            "native source binding",
        )
        collector = next(x for x in snapshots if x["role"] == "collector")
        need(collector["sha256"] == COLLECTOR, "exact 6eba collector source")
        manager_config = obj(prefix + "manager-config.json")
        extension = manager_config["extensions"]["org.vllm-hust.ascend-kvcompress"]
        need(
            set(manager_config["extensions"]) == {"org.vllm-hust.ascend-kvcompress"}
            and extension["enabled"] is True
            and extension["configuration"]["method_config"]["auto_calibrate"] is False,
            "only selected actual KV bundle/no inline calibration",
        )
        binding, owner = (
            obj(prefix + "run/native-binding.json"),
            obj(prefix + "run/launcher-kernel-identity.json"),
        )
        need(
            binding
            == {
                **obj(prefix + "run/handoff-raw.json"),
                "binding_sha256": sha(raw(prefix + "run/handoff-raw.json")),
            }
            and binding["publisher"] == owner
            and binding["manager_source_sha256"] == cfg["manager_source_sha256"],
            "actual native Manager source/kernel/raw handoff",
        )
        host_events = [
            json.loads(x)
            for x in raw(
                prefix
                + Path(binding["environment"]["VLLM_HUST_EXT_EVIDENCE_PATH"]).name
            ).splitlines()
        ]
        terminal = obj(prefix + "run/terminal-process-audit.json")
        processes = [x["source_process"] for x in terminal["source_peers"]]
        need(
            len(processes) == 3
            and {(p["role"], p["ordinal"]) for p in processes}
            == {("api-server", 0), ("worker", 0), ("worker", 1)},
            "actual three source role identities",
        )
        for process in processes:
            need(
                process["assignment_source"] == "host"
                and process["boot_id"] == owner["boot_id"]
                and process["start_identity"]
                == f"pid:{process['pid']}:start_ticks:{process['start_ticks']}"
                and any(
                    e.get("event") == "invoked"
                    and e.get("entry_point", {}).get("name") == "ascend_kvcompress"
                    and e.get("plan_id") == binding["environment"]["VLLM_ECPA_PLAN_ID"]
                    and e.get("launch_id")
                    == binding["environment"]["VLLM_ECPA_LAUNCH_ID"]
                    and all(
                        e.get("process", {}).get(k) == v
                        for k, v in process.items()
                        if k not in {"boot_id", "session", "start_ticks"}
                    )
                    for e in host_events
                ),
                "original Host invoked peer/kernel/native scope",
            )
        need(
            not any(
                e.get("event") == "invoked"
                and e.get("entry_point", {}).get("name")
                in {"kv_materialization", "arctic_inference"}
                for e in host_events
            ),
            "unselected MOD invoked",
        )
        api = next(p for p in processes if p["role"] == "api-server")
        expected = [
            owner,
            {k: api[k] for k in ("pid", "start_ticks", "boot_id", "session")},
        ]
        need(
            terminal["captured_sessions"] == expected
            and terminal["remaining_sessions"]
            == [{"owner": p, "members": []} for p in expected]
            and terminal["wall_ns"] > max(e["observed_at_ns"] for e in host_events),
            "actual original session terminal coverage",
        )
        for p in terminal["source_peers"]:
            need(
                p["expected_kernel"]
                == {
                    k: p["source_process"][k]
                    for k in ("pid", "start_ticks", "boot_id", "session")
                }
                and p["observed_kernel"] is None
                and p["same_identity_live"] is False
                and p["different_live_identity"] is False,
                "actual owned epoch gone",
            )
        need(
            terminal["backend_port"]
            == {"host": "127.0.0.1", "port": 29494, "open": False},
            "backend terminal port",
        )
        npu(prefix + "run/terminal-npu-smi.txt")
        result = obj(prefix + "run/result.json")
        need(
            result["passed"] is False
            and result["formal_result"] is False
            and not result["cleanup_errors"]
            and result["actual_hardware_transport_observed"] is False
            and all(
                result[k] is None
                for k in (
                    "KV_MOD_semantic_obligation_satisfied",
                    "GPU_semantic_qualification",
                    "lost_requests",
                    "duplicate_requests",
                    "full_objective_satisfied",
                )
            ),
            "failed attempt or unknown objective promoted",
        )
        source = raw(collector["archived_path"])
        if attempt == "effect-r3":
            native_paths = [x["path"] for x in cfg["native_source_files"]]
            need(
                len(native_paths) > len(set(native_paths))
                and prefix + "run/probe/result.json" not in files,
                "original pre-request duplicate failure",
            )
            diagnostic = obj(prefix + "late-duplicate-source-diagnostic.json")
            need(
                diagnostic["passed"] is False
                and diagnostic["failure"]
                == "sender source path is not immutable and unique",
                "actual duplicate guard rejection",
            )
            stopped = obj(prefix + "controlled-owned-stop.json")
            need(
                stopped["expected_kernel"] == stopped["observed_kernel"] == owner
                and stopped["signal"] == "SIGTERM"
                and stopped["frozen_inputs_modified"] is False,
                "exact controlled owned failure stop",
            )
        else:
            spec, peers = (
                obj(prefix + "run/collector-spec.json"),
                obj(prefix + "run/actual-owned-source-peers.json"),
            )
            need(
                peers == spec["senders"]
                and [x["process"] for x in peers] == processes
                and all(x["source_files"] == cfg["native_source_files"] for x in peers),
                "original registered source peers",
            )
            need(
                spec["native_plan_id"] == binding["environment"]["VLLM_ECPA_PLAN_ID"]
                and spec["native_launch_id"]
                == binding["environment"]["VLLM_ECPA_LAUNCH_ID"],
                "registered native scope",
            )
            phase = recipe["phases"][0]
            need(
                spec["phases"]
                == [
                    {
                        k: phase[k]
                        for k in (
                            "phase_id",
                            "client_request_id",
                            "challenge_nonce",
                            "external_request_id",
                            "expected_ranks",
                        )
                    }
                ]
                and spec["kv_requirements"]
                == {phase["phase_id"]: phase["kv_requirements"]},
                "frozen phase collector registration",
            )
            probe = obj(prefix + "run/probe/result.json")
            need(
                probe["status"] == 500
                and probe["formal_result"] is False
                and probe["hardware_result"] is False
                and probe["native_join_qualified"] is False
                and all(
                    probe[k] is None
                    for k in (
                        "GPU_semantic_qualification",
                        "KV_MOD_semantic_obligation_satisfied",
                        "lost_requests",
                        "duplicate_requests",
                        "full_objective_satisfied",
                    )
                )
                and probe["rpc_task_passed"] is False
                and probe["response_sha256"]
                == sha(raw(prefix + "run/probe/response.bin"))
                and probe["recipe_sha256"] == cfg["recipe_sha256"]
                and result["probe"] == probe,
                "actual original HTTP failure",
            )
            need(
                obj(prefix + "run/probe/headers.json") == phase["headers"]
                and raw(prefix + "run/probe/request.bin")
                == canonical(phase["payload"]),
                "actual frozen HTTP request",
            )
            need(
                obj(prefix + "run/probe/response.bin")["error"]["code"] == 500,
                "original raw error response",
            )
            log = raw(prefix + "run/backend.stdout").decode()
            need(
                re.findall(r'"POST /v1/chat/completions HTTP/1.1" (\d+)', log)
                == ["500"]
                and log.count("KeyError: '" + phase["external_request_id"]) >= 2
                and "native_kv_projection_observer.py" in log
                and "req_id_to_index[request_id]" in log,
                "actual sole POST500/two-rank row-absence traceback",
            )
            need(
                prefix + "run/probe/collector-after.json" not in files,
                "post-request ACK seal was absent",
            )
            descriptor = obj(prefix + "run/collector-launcher-descriptor.json")
            ready = obj(prefix + "run/collector-ready.bin")
            need(
                all(descriptor[k] == value for k, value in ready.items())
                and descriptor["launcher_observed_identity"] == ready["collector"]
                and ready["collector_source_sha256"] == COLLECTOR
                and ready["spec_sha256"]
                == sha(raw(prefix + "run/collector-spec.json")),
                "actual collector descriptor",
            )
            before = obj(prefix + "run/probe/collector-before.json")
            status_raw = base64.b64decode(before["status_raw_base64"], validate=True)
            status = before["status"]
            directory = obj(prefix + "run/collector-directory-identity.json")
            need(
                sha(status_raw) == before["status_raw_sha256"]
                and json.loads(status_raw) == status
                and before["kernel_peer"]
                == {"pid": ready["collector"]["pid"], "uid": directory["uid"]}
                and all(
                    status[k] == ready[k]
                    for k in (
                        "collector",
                        "socket_identity",
                        "socket_path",
                        "archive_identity",
                        "collector_source_sha256",
                        "spec_sha256",
                    )
                )
                and status["failed"] is False,
                "actual before-status peer/raw/source ownership",
            )
            collector_argv = obj(prefix + "run/collector-launch-argv.json")
            need(
                descriptor["launcher_observed_cmdline_sha256"]
                == sha(b"\0".join(x.encode() for x in collector_argv) + b"\0"),
                "actual collector command",
            )
            collector_terminal = obj(prefix + "late-collector-terminal-audit.json")
            need(
                collector_terminal["expected_kernel"]
                == {
                    k: ready["collector"][k]
                    for k in ("pid", "start_ticks", "boot_id", "session")
                }
                and collector_terminal["observed_kernel"] is None
                and not collector_terminal["remaining_owned_members"]
                and collector_terminal["same_identity_live"] is False
                and collector_terminal["different_live_identity"] is False
                and collector_terminal["wall_ns"] > terminal["wall_ns"],
                "late actual collector epoch terminal",
            )
            events = [
                json.loads(x) for x in raw(prefix + "run/native-raw.jsonl").splitlines()
            ]
            need(
                len(events) == 4
                and events[0]["collector_source_sha256"] == COLLECTOR
                and events[0]["collector"] == ready["collector"],
                "exact observed raw source/events",
            )
            with tempfile.TemporaryDirectory() as tmp:
                tmp = Path(tmp)
                (tmp / "source.py").write_bytes(source)
                (tmp / "spec.json").write_bytes(raw(prefix + "run/collector-spec.json"))
                (tmp / "spec.json").chmod(0o600)
                (tmp / "raw.jsonl").write_bytes(raw(prefix + "run/native-raw.jsonl"))
                module_spec = importlib.util.spec_from_file_location(
                    "_kv_failure_collector", tmp / "source.py"
                )
                module = importlib.util.module_from_spec(module_spec)
                module_spec.loader.exec_module(module)
                proof = module.verify_journal(tmp / "spec.json", tmp / "raw.jsonl")
            facts = [json.loads(base64.b64decode(e["raw_base64"])) for e in events[1:]]
            need(
                facts[0]["schema"] == "ecpa-native-request-id-mapping/v1"
                and facts[0]["external_request_id"] == phase["external_request_id"]
                and all(
                    x["schema"] == "ecpa-native-block-table-upload/v1"
                    and x["runtime_request_id"] == facts[0]["runtime_request_id"]
                    for x in facts[1:]
                )
                and {x["process"]["ordinal"] for x in facts[1:]} == {0, 1}
                and proof["complete_two_rank_transport_phases"] is None
                and proof["durable_ACK_status"] == "unverified",
                "generic raw is not a durable KV effect witness",
            )
            observations["r4_raw_facts"] = 3
    return {
        "failure_evidence_verified": True,
        "calibration_artifact_sha256": STATS,
        "calibration_wrapper_exit": 1,
        "calibration_leaf_exit_raw_status": None,
        "live_generator_independently_observed": False,
        "calibration_artifact_structure_verified": None,
        "r3": "controlled-pre-request-source-adaptation-failure",
        "r4_HTTP_status": 500,
        **observations,
        "KV_projection_facts": 0,
        "durable_KV_join": None,
        "formal_result": False,
        "KV_semantic_qualification": None,
        "full_objective_satisfied": None,
    }


def validate_stats(files):
    """Optional torch CPU weights-only load, original source shape validator.

    Frozen full-file digest records are not rehashed model bytes on this machine.
    The original local fingerprint is only a names/sizes/mtime manifest replay.
    """
    import torch

    calibration = json.loads(files["calibration/recipe.json"])
    config = json.loads(files["inputs/model-config.json"])
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        package = root / "_ecpa_calibration_snapshot"
        for source in calibration["sources"]:
            marker = "/vllm_ascend_kvcompress/"
            if marker not in source["path"]:
                continue
            rel = source["path"].split(marker, 1)[1]
            dest = package / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            body = files["calibration/" + Path(source["snapshot"]).name]
            need(sha(body) == source["sha256"], "calibration validation source")
            if rel == "calibration.py":
                need(
                    source["sha256"] == CALIBRATION_SOURCE,
                    "exact original calibration source",
                )
            dest.write_bytes(body)
        for suffix in ("", ".methods", ".methods.triattention"):
            name = "_ecpa_calibration_snapshot" + suffix
            namespace = types.ModuleType(name)
            namespace.__path__ = [
                str(package.joinpath(*suffix.strip(".").split(".")))
                if suffix
                else str(package)
            ]
            sys.modules[name] = namespace
        sys.path.insert(0, str(root))
        try:
            base = importlib.import_module("_ecpa_calibration_snapshot.methods.base")
            stats_module = importlib.import_module(
                "_ecpa_calibration_snapshot.methods.triattention.stats"
            )
            artifact_path = root / "stats.pt"
            artifact_path.write_bytes(
                files["calibration/qwen2.5-7b-genuine-global-head-stats.pt"]
            )
            need(
                sha(artifact_path.read_bytes()) == STATS,
                "exact calibration output bytes",
            )
            shape = base.ModelShape(
                model_type=config["model_type"],
                num_layers=config["num_hidden_layers"],
                num_attention_heads=config["num_attention_heads"],
                num_kv_heads=config["num_key_value_heads"],
                head_dim=config["hidden_size"] // config["num_attention_heads"],
                rope_theta=config["rope_theta"],
                has_rope_scaling=bool(config.get("rope_scaling")),
                rotary_dim=128,
                attention_layer_indices=tuple(range(28)),
            )
            artifact = stats_module.CalibrationStats.load(artifact_path)
            need(
                not artifact.validate(shape),
                "actual source shape validator rejected stats",
            )
            payload = torch.load(artifact_path, map_location="cpu", weights_only=True)
            metadata = payload["metadata"]
            patterns = ("*.safetensors", "*.bin", "*.pt", "*.index.json", "config.json")
            entries = [
                (Path(x["path"]).name, x["size"], x["mtime_ns"])
                for x in calibration["model_files"]
                if any(fnmatch.fnmatch(Path(x["path"]).name, p) for p in patterns)
            ]
            fingerprint = "local-manifest:" + sha(
                json.dumps(
                    sorted(entries), sort_keys=True, separators=(",", ":"), default=str
                ).encode()
            )
            need(
                metadata["model_source_fingerprint"] == fingerprint
                and metadata["model"] == "/models/Qwen2.5-7B-Instruct"
                and metadata["model_revision"] == "default"
                and metadata["token_count"] == calibration["actual_token_count"] == 4096
                and metadata["input_sha256"] == calibration["input"]["sha256"],
                "stats model/fingerprint/input metadata",
            )
        finally:
            sys.path.remove(str(root))
            for name in list(sys.modules):
                if name.startswith("_ecpa_calibration_snapshot"):
                    del sys.modules[name]
    return {
        "calibration_artifact_structure_verified": True,
        "stats_source_shape_validator": "original frozen source",
        "weights_only": True,
        "map_location": "cpu",
        "fingerprint_scope": "frozen names/sizes/mtime only",
        "full_model_bytes_rehashed_by_portable_verifier": False,
        "runner_success": False,
        "formal_result": False,
    }


def verify_archive(manifest, archive, *, check_stats=False):
    metadata, files = load_archive(manifest, archive)
    need(
        metadata["calibration_wrapper_exit"] == 1
        and metadata["calibration_leaf_exit_raw_recorded"] is False
        and metadata["live_generator_independently_observed"] is False,
        "manifest failure provenance",
    )
    result = inspect(files)
    if check_stats:
        result.update(validate_stats(files))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument(
        "--validate-stats",
        action="store_true",
        help="separate original-source torch CPU shape/metadata check",
    )
    args = parser.parse_args()
    print(
        json.dumps(
            verify_archive(
                args.manifest, args.archive, check_stats=args.validate_stats
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
