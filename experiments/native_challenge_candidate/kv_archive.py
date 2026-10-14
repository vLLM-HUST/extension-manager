"""Seal and replay bounded KV metadata/upload evidence without current PID reads."""

from __future__ import annotations

import argparse
import base64
import json
import shutil
from pathlib import Path

from experiments.exposure_gate import native_semantic_collector as collector

from . import request_runner
from .collector_client import phase_join
from .kv_request_runner import validate_kv
from .request_runner import canonical, require, sha

SCHEMA = "ecpa-KV-metadata-upload-archive/v1"


def seal(recipe_path, spec_path, journal_path, rpc_directory, descriptor_path, output):
    """Copy exact artifacts and source bytes; sealing alone asserts no result."""
    recipe = json.loads(recipe_path.read_bytes())
    validate_kv(recipe)
    spec = json.loads(spec_path.read_bytes())
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    output.chmod(0o700)
    files = {}
    for name, source in {
        "recipe.json": recipe_path,
        "spec.json": spec_path,
        "native.jsonl": journal_path,
        "descriptor.json": descriptor_path,
        **{
            name: rpc_directory / name
            for name in (
                "request.bin",
                "headers.json",
                "response.bin",
                "response-metadata.json",
                "collector-before.json",
                "collector-after.json",
            )
        },
    }.items():
        shutil.copyfile(source, output / name)
        (output / name).chmod(0o600)
        files[name] = sha((output / name).read_bytes())
    source_paths = {s["path"] for s in recipe["sources"]}
    source_paths.update(
        s["path"] for p in recipe["phases"] for s in p["tokenization"]["assets"]
    )
    source_paths.update(
        s["path"] for peer in spec["senders"] for s in peer["source_files"]
    )
    for phase in recipe["phases"]:
        binding = phase["tokenization"]["runtime_binding"]
        source_paths.add(binding["implementation_source"]["path"])
        source_paths.update(s["path"] for s in binding["host_sources"])

    source_paths.update(
        [
            str(Path(collector.__file__).resolve()),
            str(Path(request_runner.__file__).resolve()),
        ]
    )
    snapshots = {}
    (output / "source").mkdir()
    (output / "source").chmod(0o700)
    for original in sorted(source_paths):
        raw = Path(original).read_bytes()
        name = "source/" + sha(raw) + ".snapshot"
        (output / name).write_bytes(raw)
        (output / name).chmod(0o600)
        files[name] = sha(raw)
        snapshots[original] = name
    manifest = {
        "schema": SCHEMA,
        "formal_result": False,
        "file_sha256": files,
        "source_snapshots": snapshots,
        "collector_source_original": str(Path(collector.__file__).resolve()),
        "client_source_original": str(Path(request_runner.__file__).resolve()),
    }
    raw = canonical(manifest)
    (output / "manifest.json").write_bytes(raw)
    (output / "manifest.json").chmod(0o600)
    return {"manifest_sha256": sha(raw), "formal_result": False}


def verify(root, expected_manifest_sha256, phase_id):
    """Requires a caller-held immutable manifest digest, never a success summary."""
    manifest_raw = (root / "manifest.json").read_bytes()
    require(
        sha(manifest_raw) == expected_manifest_sha256, "KV archive manifest differs"
    )
    manifest = json.loads(manifest_raw)
    require(
        manifest["schema"] == SCHEMA and manifest["formal_result"] is False,
        "KV archive scope changed",
    )
    for name, expected in manifest["file_sha256"].items():
        path = Path(name)
        require(
            not path.is_absolute()
            and ".." not in path.parts
            and not (root / name).is_symlink(),
            "KV archive path escapes",
        )
        require(
            sha((root / name).read_bytes()) == expected, "KV archived bytes changed"
        )

    def source(original):
        name = manifest["source_snapshots"][original]
        require(name in manifest["file_sha256"], "KV source snapshot unbound")
        return root / name

    recipe = json.loads((root / "recipe.json").read_bytes())
    validate_kv(recipe, source_resolver=source)
    phase = next(p for p in recipe["phases"] if p["phase_id"] == phase_id)
    spec = json.loads((root / "spec.json").read_bytes())
    request_runner.require_phase_registration(
        phase,
        spec,
        kv_requirements=phase["kv_requirements"],
        materialized_row=recipe["schema"] == "ecpa-native-kv-challenge-campaign/v2",
    )
    descriptor = json.loads((root / "descriptor.json").read_bytes())
    before, after = [
        json.loads((root / name).read_bytes())
        for name in ["collector-before.json", "collector-after.json"]
    ]
    runtime_source = sha(source(manifest["collector_source_original"]).read_bytes())
    require(
        runtime_source == sha(Path(collector.__file__).read_bytes()),
        "unsupported KV archive collector source/version",
    )
    require(
        descriptor["collector"] == descriptor["launcher_observed_identity"],
        "KV recorded launcher identity differs",
    )
    uid = {s["peer_uid"] for s in spec["senders"]}
    for receipt in [before, after]:
        raw = base64.b64decode(receipt["status_raw_base64"], validate=True)
        status = receipt["status"]
        require(
            sha(raw) == receipt["status_raw_sha256"] and json.loads(raw) == status,
            "KV recorded status bytes differ",
        )
        require(
            receipt["kernel_peer"]["pid"] == descriptor["collector"]["pid"]
            and uid == {receipt["kernel_peer"]["uid"]}
            and status["collector"] == descriptor["collector"]
            and status["collector_source_sha256"]
            == descriptor["collector_source_sha256"]
            == runtime_source
            and status["spec_sha256"]
            == descriptor["spec_sha256"]
            == sha((root / "spec.json").read_bytes())
            and status["socket_identity"] == descriptor["socket_identity"]
            and status["archive_identity"] == descriptor["archive_identity"]
            and status["schema"] == "ecpa-native-semantic-collector-status/v1"
            and status["classification"] == "CPU_REVIEW_CANDIDATE_ONLY"
            and receipt["formal_result"] is False
            and status["failed"] is False
            and status["formal_producer_registration"] is False,
            "KV recorded peer/source/spec/ACK receipt differs",
        )
    require(
        before["status"]["acknowledged_prefix"]["next_sequence"]
        < after["status"]["acknowledged_prefix"]["next_sequence"],
        "KV request has no fresh acknowledged prefix",
    )
    for sender in spec["senders"]:
        for binding in sender["source_files"]:
            require(
                sha(source(binding["path"]).read_bytes()) == binding["sha256"],
                "KV native source snapshot differs",
            )
    verified = collector.verify_journal(
        root / "spec.json",
        root / "native.jsonl",
        acknowledged_prefix=after["status"]["acknowledged_prefix"],
    )
    events = [
        json.loads(line) for line in (root / "native.jsonl").read_bytes().splitlines()
    ]
    require(
        events[0]["collector"] == descriptor["collector"]
        and events[0]["archive_identity"] == descriptor["archive_identity"],
        "KV raw owner differs",
    )
    joined = phase_join(events, phase, verified, require_kv=True, collector_spec=spec)
    require(
        (root / "request.bin").read_bytes() == canonical(phase["payload"])
        and json.loads((root / "headers.json").read_bytes()) == phase["headers"],
        "KV archived request differs",
    )
    metadata = json.loads((root / "response-metadata.json").read_bytes())
    body = (root / "response.bin").read_bytes()
    require(
        metadata["schema"]
        == (
            "ecpa-observed-KV-HTTP-response/v2"
            if "rpc_budget_s" in phase
            else "ecpa-observed-KV-HTTP-response/v1"
        )
        and metadata["status"] == 200
        and metadata["url"] == phase["url"]
        and metadata["request_sha256"] == sha((root / "request.bin").read_bytes())
        and metadata["response_sha256"] == sha(body)
        and metadata["client_source_sha256"]
        == sha(source(manifest["client_source_original"]).read_bytes())
        and metadata["client"]["boot_id"] == descriptor["collector"]["boot_id"],
        "KV observed HTTP binding differs",
    )
    request_runner.verify_rpc_budget(phase, metadata)
    data = json.loads(body)
    require(
        data["id"] == phase["expected_response_id"]
        and data["model"] == phase["payload"]["model"]
        and data["choices"][0]["message"]["content"].strip()
        == phase["response_oracle"]["expected"]
        and data["choices"][0]["finish_reason"] == "stop"
        and data["usage"]["prompt_tokens"] == 1201
        and data["usage"]["completion_tokens"] >= 32,
        "KV raw model/nonce/prompt/decode response differs",
    )
    external = phase["external_request_id"]
    selected = [
        e
        for e in events[1:]
        if e.get("phase", {}).get("external_request_id") == external
    ]
    for event in selected:
        fact = json.loads(base64.b64decode(event["raw_base64"]))
        require(
            before["status"]["acknowledged_prefix"]["next_sequence"]
            <= event["sequence"]
            and metadata["sent_monotonic_ns"] <= fact["monotonic_ns"]
            and event["accepted_monotonic_ns"] <= metadata["received_monotonic_ns"],
            "KV source facts lie outside the observed HTTP request window",
        )
    return {
        **joined,
        "recorded_peer_and_HTTP_bindings_verified": True,
        "fresh_OS_peer_authentication_performed": False,
        "tokenization_reexecuted_from_archived_assets": False,
        "HTTP_prompt_and_decode_counts_verified": True,
        "archive_manifest_sha256": expected_manifest_sha256,
        "formal_result": False,
        "hardware_result": False,
        "KV_MOD_semantic_obligation_satisfied": None,
        "full_objective_satisfied": None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--phase", required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.root, args.expected_manifest_sha256, args.phase)))


if __name__ == "__main__":
    main()
