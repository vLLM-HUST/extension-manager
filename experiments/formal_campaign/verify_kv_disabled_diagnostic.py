"""Replay a failed original-input counterfactual, never a fresh native qualification."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
import tempfile
from pathlib import Path

from .verify_kv_materialized_partial import inspect as inspect_enabled
from .verify_kv_materialized_partial import load_archive as load_enabled

CONFIGS = {
    "r2": "965954fba528f612a19df3b7b9e2e725e8466964a681f0e5d27e8201c5f7e72e",
    "r3": "61191efdbc1f42c22756067c54e4ddf90252500d0a050da07255e266373c61a7",
    "r4": "4ceaf19b64dc2763334d0b8e15823f2c5e0a25403084b8644932a37ad33be93c",
}
ENABLED_ARCHIVE = "a201f045f3e38422c2d7b701cbedd31421b189e2a2cb535fff5ecbec61972fd2"
CORE = {"ascend_kv_connector", "ascend_model", "ascend_model_loader"}
KERNEL = ("pid", "start_ticks", "session", "boot_id")


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
        manifest["schema"] == "ecpa-KV-disabled-counterfactual-archive/v1"
        and manifest["formal_result"] is False
        and manifest["fresh_challenge_qualification"] is False
        and manifest["single_pair_causal_attribution"] is False,
        "diagnostic archive scope",
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
                "unsafe archive member",
            )
            files[member.name] = archive.extractfile(member).read()
    need(set(files) == set(manifest["inventory"]), "complete inventory")
    for name, raw in files.items():
        need(
            manifest["inventory"][name] == {"sha256": sha(raw), "bytes": len(raw)},
            "member bytes",
        )
    return files


def inspect(files):
    def raw(name):
        need(name in files, "missing raw: " + name)
        return files[name]

    def obj(name):
        return json.loads(raw(name))

    need(
        sha(raw("enabled-r3/raw.tar.gz")) == ENABLED_ARCHIVE,
        "published enabled archive source",
    )
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "archive").write_bytes(raw("enabled-r3/raw.tar.gz"))
        (root / "manifest").write_bytes(raw("enabled-r3/manifest.json"))
        original = load_enabled(
            root / "manifest", root / "archive", oracle_failure=True
        )
        enabled_result = inspect_enabled(original, oracle_failure=True)
    prior_recipe = json.loads(original["original/recipe.json"])
    prior_phase = prior_recipe["phases"][0]
    prior_config = json.loads(original["original/manager-config.json"])
    outcomes = {}
    for tag in CONFIGS:
        cfg_raw = raw(tag + "/owner-config.json")
        need(sha(cfg_raw) == CONFIGS[tag], "original frozen owner config")
        cfg = json.loads(cfg_raw)
        need(
            obj(tag + "/run/owner-config.json") == cfg
            and cfg["formal_result"] is False,
            "actual owner freeze",
        )
        need(
            sha(raw(tag + "/owner.source.py")) == cfg["owner_source_sha256"]
            and sha(raw(tag + "/launcher.source.py"))
            == cfg["outer_launcher_source_sha256"],
            "actual executed source snapshots",
        )
        need(
            obj(tag + "/CPU-preflight-exit.json")["exitcode"] == 0,
            "actual CPU preflight",
        )
        for source in cfg["sources"]:
            need(
                sha(raw("snapshots/" + source["sha256"])) == source["sha256"],
                "original source closure bytes",
            )
        need(
            sha(raw("inputs/genuine-7b-stats.pt"))
            == cfg["calibration_artifact"]["sha256"],
            "validated stats input bytes",
        )
        need(
            len(cfg["model_files"]) == 14
            and set(cfg["wheel_artifacts"])
            == {"host", "ascend", "mod", "manager", "torch", "torch_npu", "triton"},
            "original model and wheel closure",
        )
        recipe = obj(tag + "/recipe.json")
        need(sha(raw(tag + "/recipe.json")) == cfg["recipe_sha256"], "recipe freeze")
        phase = recipe["phases"][0]
        for key in (
            "challenge_nonce",
            "response_oracle",
            "tokenization",
            "minimum_completion_tokens",
            "rpc_budget_s",
        ):
            need(phase[key] == prior_phase[key], "original token/oracle policy")
        need(
            {k: v for k, v in phase["payload"].items() if k != "request_id"}
            == {k: v for k, v in prior_phase["payload"].items() if k != "request_id"},
            "original model/sampling/messages",
        )
        need(
            phase["client_request_id"] != prior_phase["client_request_id"]
            and phase["external_request_id"]
            == phase["expected_response_id"]
            == "chatcmpl-" + phase["client_request_id"]
            and phase["headers"]["X-Request-Id"]
            == phase["payload"]["request_id"]
            == phase["client_request_id"],
            "new external request identity",
        )
        diagnostic = obj(tag + "/diagnostic-manifest.json")
        need(
            sha(raw(tag + "/diagnostic-manifest.json"))
            == cfg["diagnostic_manifest_sha256"]
            and diagnostic["original_recipe_sha256"]
            == sha(original["original/recipe.json"])
            and diagnostic["original_response_sha256"]
            == sha(original["original/run/probe/response.bin"])
            and diagnostic["nonce_reuse_explicit"] is True
            and diagnostic["fresh_challenge_qualification"] is False
            and diagnostic["single_pair_causal_attribution"] is False,
            "explicit original-input counterfactual",
        )
        manager = obj(tag + "/manager-config.json")
        need(
            manager["extensions"]["org.vllm-hust.ascend-kvcompress"]["enabled"]
            is False,
            "compression disabled",
        )
        manager["extensions"]["org.vllm-hust.ascend-kvcompress"]["enabled"] = True
        need(manager == prior_config, "only Manager bundle enabled flag changed")
        result = obj(tag + "/run/result.json")
        need(
            result["passed"] is False
            and result["formal_result"] is False
            and not result["cleanup_errors"],
            "no failed-run promotion",
        )
        launcher = obj(tag + "/run/launcher-kernel-identity.json")
        owner = obj(tag + "/actual-owner-kernel.json")["kernel"]
        terminal = obj(tag + "/run/terminal-process-audit.json")
        outer = obj(tag + "/outer-independent-terminal-audit.json")
        for audit in (terminal, outer):
            need(
                audit["captured_sessions"]
                == [x["owner"] for x in audit["remaining_sessions"]]
                and all(not x["members"] for x in audit["remaining_sessions"]),
                "actual captured session cleanup",
            )
        need(
            launcher in terminal["captured_sessions"]
            and launcher in outer["captured_sessions"]
            and owner in outer["captured_sessions"]
            and not outer["owner_identity_still_live"]
            and not outer["cleanup_errors"],
            "actual owner/Manager sessions",
        )
        need(
            set(map(canonical, terminal["captured_sessions"]))
            <= set(map(canonical, outer["captured_sessions"])),
            "independent cleanup covers owner-captured sessions",
        )
        need(
            terminal["backend_port"]["open"] is False
            and terminal["backend_port"]["port"]
            == int(phase["url"].split(":")[2].split("/")[0]),
            "actual frozen backend closed",
        )
        text = raw(tag + "/run/terminal-npu-smi.txt").decode()
        need(
            set(re.findall(r"No running processes found in NPU (\d+)", text))
            == {"3", "6"}
            and set(re.findall(r"^\|\s*(\d+)\s+910B2\s*\|", text, re.M)) == {"3", "6"}
            and not re.search(r"^\|\s*\d+\s+\d+\s*\|\s*\d+\s*\|", text, re.M),
            "actual NPU terminal cleanup",
        )
        outer_result = obj(tag + "/outer-watchdog-result.json")
        need(
            outer_result["original_owner_exit"] == 1
            and outer_result["fired"] is False
            and not outer_result["cleanup_errors"]
            and outer_result["overall_watchdog_s"] == 1200,
            "original outer failure status",
        )
        if tag != "r4":
            need(
                not any(n.startswith(tag + "/run/probe/") for n in files),
                "pre-request failure cannot acquire a response",
            )
            needle = (
                "native phase handoff requires enabled bundles"
                if tag == "r2"
                else "Failed to infer device type"
            )
            need(
                needle in raw(tag + "/run/backend.stderr").decode(),
                "primary source failure cause",
            )
            if tag == "r3":
                rows = [
                    json.loads(line)
                    for line in raw(tag + "/baseline-host-evidence.jsonl").splitlines()
                ]
                need(
                    any(
                        r["event"] == "skipped"
                        and r["entry_point"]["group"] == "vllm.platform_plugins"
                        and r["entry_point"]["name"] == "ascend"
                        and r.get("detail") == "allowlist"
                        for r in rows
                    ),
                    "actual native platform filtered",
                )
                calls = [r for r in rows if r["event"] == "invoked"]
                need(
                    {r["entry_point"]["name"] for r in calls} == CORE,
                    "pre-request ordinary activation",
                )
                binding = cfg["identity_binding"]["environment"]
                for row in calls:
                    proc = row["process"]
                    need(
                        row["plan_id"] == binding["VLLM_ECPA_PLAN_ID"]
                        and row["launch_id"] == binding["VLLM_ECPA_LAUNCH_ID"]
                        and proc["role"] == "api-server"
                        and proc["assignment_source"] == "host",
                        "failed pre-request Host scope",
                    )
                    need(
                        any(
                            x["pid"] == proc["pid"]
                            and proc["start_identity"]
                            == f"pid:{x['pid']}:start_ticks:{x['start_ticks']}"
                            for x in terminal["captured_sessions"]
                        ),
                        "failed pre-request actual API cleanup",
                    )
            outcomes[tag] = {
                "pre_request_failure": needle,
                "HTTP_response": None,
                "runner_success": False,
            }
            continue
        need(
            cfg["identity_binding"]["native_Manager_handoff_qualified"] is False
            and cfg["identity_binding"]["kind"]
            == "preregistered-baseline-fixed-IDs-not-native-Manager-mint"
            and obj(tag + "/run/baseline-fixed-binding.json")
            == cfg["identity_binding"],
            "baseline is not native Manager issuer",
        )
        need(
            cfg["env"]["VLLM_PLUGINS"]
            == "ascend_kv_connector,ascend_model,ascend_model_loader,ascend"
            and "ECPA_NATIVE_SEMANTIC_BOOTSTRAP" not in cfg["env"],
            "actual platform/core-only activation",
        )
        journal = [
            json.loads(line)
            for line in raw(tag + "/baseline-host-evidence.jsonl").splitlines()
        ]
        invoked = [r for r in journal if r["event"] == "invoked"]
        need(
            {r["entry_point"]["name"] for r in invoked} == CORE,
            "only ordinary core plugins invoked",
        )
        peers = obj(tag + "/run/actual-owned-source-peers.json")
        need(
            {(p["process"]["role"], p["process"]["ordinal"]) for p in peers}
            == {("api-server", 0), ("worker", 0), ("worker", 1)}
            and len({p["process"]["pid"] for p in peers}) == 3,
            "actual API and two ranks",
        )
        need(
            len(terminal["source_peers"]) == 3,
            "actual source-peer terminal observations",
        )
        late = obj("late-independent/kernel-1791942567686030666.json")
        need(
            late["config_sha256"] == CONFIGS[tag]
            and late["preregistered_observer"] is False,
            "late observer source and scope",
        )
        need(
            {canonical(r["actual_kernel"]) for r in late["rows"]}
            == {canonical({k: p["process"][k] for k in KERNEL}) for p in peers},
            "late actual API/rank kernel coverage",
        )
        for p in peers:
            process = p["process"]
            need(
                p["source_files"] == cfg["native_source_files"],
                "actual peer source registration",
            )
            need(
                any(
                    r["expected_native"]
                    == r["actual_kernel"]
                    == {k: process[k] for k in KERNEL}
                    and r["kernel_match"] is True
                    and r["cmdline_sha256"] == p["cmdline_sha256"]
                    for r in late["rows"]
                ),
                "late actual kernel and cmdline binding",
            )
            matching = [
                r
                for r in invoked
                if r["entry_point"]["name"] == "ascend_model"
                and r["process"]["role"] == process["role"]
                and r["process"]["ordinal"] == process["ordinal"]
            ]
            need(
                len(matching) == 1
                and all(process[k] == v for k, v in matching[0]["process"].items()),
                "source-assigned actual peer identity",
            )
            row = matching[0]
            binding = cfg["identity_binding"]["environment"]
            need(
                row["plan_id"] == binding["VLLM_ECPA_PLAN_ID"]
                and row["launch_id"] == binding["VLLM_ECPA_LAUNCH_ID"]
                and process["assignment_source"] == "host"
                and process["start_identity"]
                == f"pid:{process['pid']}:start_ticks:{process['start_ticks']}",
                "fixed baseline scope and actual epoch",
            )
            need(
                any(
                    x["source_process"] == process
                    and x["expected_kernel"] == {k: process[k] for k in KERNEL}
                    and x["observed_kernel"] is None
                    and x["same_identity_live"] is False
                    for x in terminal["source_peers"]
                ),
                "source-peer exact kernel cleanup",
            )
        request = raw(tag + "/run/probe/request.bin")
        response = raw(tag + "/run/probe/response.bin")
        need(
            request == canonical(phase["payload"])
            and obj(tag + "/run/probe/headers.json") == phase["headers"],
            "actual single request source",
        )
        metadata = obj(tag + "/run/probe/response-metadata.json")
        rpc = obj(tag + "/run/probe/result.json")
        body = json.loads(response)
        need(
            metadata["status"] == rpc["status"] == 200
            and metadata["request_sha256"] == sha(request)
            and metadata["response_sha256"] == rpc["response_sha256"] == sha(response),
            "actual HTTP status and bytes",
        )
        posts = re.findall(
            r'"POST /v1/chat/completions HTTP/1.1" (\d+) ',
            raw(tag + "/run/backend.stdout").decode(),
        )
        need(posts == ["200"], "exactly one original backend HTTP200")
        need(
            body["id"] == phase["expected_response_id"]
            and body["model"] == phase["payload"]["model"]
            and body["usage"]["prompt_tokens"] == 1201
            and body["usage"]["completion_tokens"] == 119
            and body["choices"][0]["finish_reason"] == "stop",
            "actual original response identity/tokens",
        )
        need(
            body["choices"][0]["message"]["content"].strip()
            != phase["response_oracle"]["expected"]
            and rpc["rpc_task_passed"] is False
            and rpc["failure"] == "phase challenge task_oracle_failed",
            "strict two-nonce failed task",
        )
        watchdog = obj(tag + "/run/phase-watchdog.json")
        elapsed = obj(tag + "/run/phase-total-elapsed.json")
        need(
            watchdog["fired"] is False
            and watchdog["cancelled"] is True
            and elapsed["elapsed_gate_passed"] is True
            and elapsed["includes_authenticated_pre_and_post_HTTP_work"] is False
            and elapsed["includes_RPC_only_work"] is True,
            "actual RPC-only phase watchdog scope",
        )
        need(
            metadata["rpc_budget_s"] == 180
            and 0
            <= metadata["received_monotonic_ns"] - metadata["sent_monotonic_ns"]
            <= 180_000_000_000
            and 0
            <= elapsed["probe_completed_monotonic_ns"]
            - elapsed["probe_entry_monotonic_ns"]
            <= 180_000_000_000,
            "actual bounded HTTP/phase elapsed",
        )
        outcomes[tag] = {
            "HTTP_status": 200,
            "prompt_tokens": 1201,
            "completion_tokens": 119,
            "finish_reason": "stop",
            "strict_task_passed": False,
            "response_sha256": sha(response),
            "HTTP_elapsed_s": (
                metadata["received_monotonic_ns"] - metadata["sent_monotonic_ns"]
            )
            / 1e9,
            "runner_success": False,
            "native_Manager_handoff_qualified": False,
        }
    need(enabled_result["model_task_passed"] is False, "published enabled task failed")
    return {
        "scope": "original-input-single-pair-counterfactual-diagnostic-only",
        "enabled_result": enabled_result,
        "disabled_attempts": outcomes,
        "both_strict_tasks_failed": True,
        "single_pair_causal_attribution": None,
        "fresh_challenge_qualification": False,
        "formal_result": False,
        "formal_H3_starts": 0,
        "formal_H4_starts": 0,
        "KV_tensor_equivalence": None,
        "attention_consumed": None,
        "full_quality": None,
        "lost_requests": None,
        "duplicate_requests": None,
        "full_objective_satisfied": None,
        "late_audits_are_not_preregistration": True,
    }


def verify_archive(manifest, archive):
    return inspect(load_archive(manifest, archive))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify_archive(args.manifest, args.archive), indent=2))


if __name__ == "__main__":
    main()
