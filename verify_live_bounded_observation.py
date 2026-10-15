"""Stdlib replay of archived r3 bytes; no fresh peers or formal qualification.

Full producer quotes/nonces and all public response bodies were not retained.
Their hashes remain recorded evidence, not a reconstructed authentication proof.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import tarfile
from pathlib import Path, PurePosixPath

ORIGIN_SHA = "76d68e7417479e9306955447842d910d79cbe6db54607ff70ae6ad170c565360"
INVENTORY_SHA = "d2ca41e16ac781ccffc7817049761fb8f3f69740c71859ea8cff3bf38a0c868a"
CONFIG_SHA = "413521082304ec041f5b265e5710bce3540a387753f588ac7e4bba2bbc56a022"
RECIPE_SHA = "548be0216cc8028deca513dfcf36244264c94004d100228763f1c2c96aa5ee1b"
REPLAY_HELPER_SHA = "0151803464eb9e4b00469f51fbba0b3daf7fc55b332ba3e1bd0b79b978e30659"
CLASSIFICATION = "REAL_LIVE_BOUNDED_RESPONSE_RELEASE_NONFORMAL"
KERNEL = ("pid", "start_ticks", "session", "boot_id")
SCOPE = (
    "execution_plan_id",
    "native_plan_id",
    "native_launch_id",
    "controller_instance",
    "candidate_generation",
    "membership_epoch",
)


def need(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def file_sha(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1048576), b""):
            value.update(block)
    return value.hexdigest()


def kernel(value):
    return {key: value[key] for key in KERNEL}


def safe_name(value):
    path = PurePosixPath(value)
    return (
        bool(value)
        and not path.is_absolute()
        and ".." not in path.parts
        and str(path) == value
    )


def load_bundle(directory):
    manifest = json.loads((directory / "manifest.json").read_bytes())
    need(
        manifest["schema"] == "ecpa-live-bounded-response-lossless-cas/v1"
        and manifest["formal_result"] is False
        and manifest["fresh_OS_peer_authentication_performed"] is False,
        "packaged profile scope differs",
    )
    inventory_raw = (directory / "origin-inventory.json").read_bytes()
    need(
        sha(inventory_raw) == INVENTORY_SHA == manifest["origin_inventory"]["sha256"],
        "original member inventory changed",
    )
    origin = json.loads(inventory_raw)
    need(
        origin["sha256"] == ORIGIN_SHA == manifest["origin_archive"]["sha256"]
        and origin["archive_bytes"] == manifest["origin_archive"]["bytes"] == 244769640
        and origin["members"] == manifest["origin_archive"]["members"] == 1102,
        "original archive identity differs",
    )
    expected = {row["path"]: (row["size"], row["sha256"]) for row in origin["files"]}
    need(len(expected) == len(origin["files"]) == 1102, "original inventory duplicates")
    members = manifest["members"]
    actual = {row["path"]: (row["bytes"], row["sha256"]) for row in members}
    need(
        len(actual) == len(members) == 1102
        and actual == expected
        and sum(size for size, _ in actual.values())
        == origin["original_bytes"]
        == 875520077,
        "lossless member mapping differs",
    )
    need(all(safe_name(name) for name in actual), "unsafe original member path")
    objects = {digest: size for size, digest in actual.values()}
    need(
        manifest["objects"] == objects and len(objects) == 1022,
        "content-addressed object inventory differs",
    )
    container = manifest["container"]
    need(container["path"] == "objects.tar.xz", "container path differs")
    path = directory / container["path"]
    need(
        path.stat().st_size == container["bytes"]
        and file_sha(path) == container["sha256"],
        "packaged container bytes differ",
    )
    contents = {}
    with tarfile.open(path, "r|xz") as archive:
        for item in archive:
            name = PurePosixPath(item.name)
            need(
                item.isfile()
                and len(name.parts) == 2
                and name.parts[0] == "objects"
                and safe_name(item.name),
                "unsafe object member",
            )
            digest = name.name
            need(
                digest in objects
                and digest not in contents
                and item.size == objects[digest]
                and item.size < 16000000,
                "duplicate or unregistered object",
            )
            raw = archive.extractfile(item).read()
            need(len(raw) == item.size and sha(raw) == digest, "object bytes changed")
            contents[digest] = raw
    need(set(contents) == set(objects), "missing content-addressed object")
    return {name: contents[digest] for name, (_, digest) in actual.items()}, manifest


def verify(files, directory, replay=True):
    def raw(name):
        need(name in files, "missing original member: " + name)
        return files[name]

    def obj(name):
        return json.loads(raw(name))

    cfg, recipe = obj("owner-config.json"), obj("recipe.json")
    need(
        sha(raw("owner-config.json")) == CONFIG_SHA
        and obj("run/owner-config.json") == cfg
        and sha(raw("recipe.json")) == RECIPE_SHA == cfg["recipe_sha256"]
        and cfg["formal_result"] is False
        and recipe["formal_result"] is False,
        "frozen original inputs differ",
    )
    need(
        sha(raw("owner.source.py")) == cfg["owner_source_sha256"]
        and sha(raw("launcher.source.py")) == cfg["outer_launcher_source_sha256"],
        "executed source differs",
    )
    inventory, mapping = (
        obj("frozen-source-inventory.json"),
        obj("frozen-source-map.json"),
    )
    need(
        len(inventory)
        == len(mapping)
        == len({s["original"] for s in inventory})
        == 145,
        "frozen path inventory differs",
    )
    for source in inventory:
        target = "frozen-sources/" + source["sha256"]
        need(
            Path(mapping[source["original"]]).name == source["sha256"]
            and len(raw(target)) == source["size"]
            and sha(raw(target)) == source["sha256"],
            "frozen source or asset bytes differ",
        )
    for source in cfg["sources"]:
        need(
            sha(raw("frozen-sources/" + source["sha256"])) == source["sha256"],
            "declared executed source missing",
        )
    roles = {s["role"]: s for s in cfg["sources"]}
    registration = obj("run/live-registration.json")
    reg_sha = sha(canonical(registration))
    need(
        registration["schema"] == "ecpa-live-native-semantic-registration/v1"
        and registration["formal_result"] is False
        and type(registration["max_validity_ns"]) is int
        and registration["max_validity_ns"] == 30000000000,
        "live registration scope differs",
    )
    scope = {key: registration[key] for key in SCOPE}
    phase = next(
        p for p in recipe["phases"] if p["phase_id"] == registration["phase_id"]
    )
    spec, peers = (
        obj("run/collector-spec.json"),
        obj("run/actual-owned-source-peers.json"),
    )
    need(
        spec["senders"] == registration["source_peers"] == peers
        and sorted(p["process"]["role"] for p in peers)
        == ["api-server", "worker", "worker"]
        and scope["native_plan_id"] == spec["native_plan_id"]
        and scope["native_launch_id"] == spec["native_launch_id"]
        and obj("semantic-plan.json")["plan_id"] == scope["execution_plan_id"],
        "registered execution/source scope differs",
    )
    producer = obj("run/producer-ready.bin")
    authority = obj("run/authority-ready.bin")
    need(
        producer == obj("run/live-producer-descriptor.json")
        and producer["producer"] == obj("run/live-producer-owned-kernel.json")
        and authority["authority"] == obj("run/live-authority-owned-kernel.json")
        and producer["registration_sha256"]
        == authority["registration_sha256"]
        == reg_sha
        and producer["source_sha256"] == roles["live-semantic-producer"]["sha256"]
        and authority["source_sha256"] == roles["live-semantic-authority"]["sha256"]
        and producer["producer"] != authority["authority"],
        "independent process/source descriptor binding differs",
    )
    completion, observation = (
        obj("run/producer-completion.json"),
        obj("run/probe/attention-HTTP-ACK-observation.json"),
    )
    proof = completion["proof"]
    need(
        completion["schema"] == "ecpa-live-native-semantic-completion/v1"
        and completion["producer"] == producer["producer"]
        and completion["registration_sha256"] == reg_sha
        and completion["scope"] == scope
        and completion["formal_result"] is False
        and proof["tensor_receipts"] == proof["operator_receipts"] == 56
        and proof["worker_closures"] == 2
        and proof["full_prefix_records"] == 265
        and proof["expires_monotonic_ns"] - proof["issued_monotonic_ns"]
        == registration["max_validity_ns"]
        and proof["observation_sha256"] == sha(canonical(observation)),
        "completed bounded proof differs",
    )
    request, response = raw("run/probe/request.bin"), raw("run/probe/response.bin")
    need(
        request == canonical(phase["payload"])
        and sha(request) == proof["request_sha256"]
        and sha(response) == proof["response_sha256"],
        "frozen request/response bytes differ",
    )
    native_events = [
        json.loads(line) for line in raw("run/native-raw.jsonl").splitlines()
    ]
    need(len(native_events) == 265, "full native prefix count differs")
    previous, records, closed, counts = "0" * 64, {}, set(), {}
    for sequence, event in enumerate(native_events):
        need(
            event["sequence"] == sequence
            and event["previous_sha256"] == previous
            and event["event_sha256"]
            == sha(canonical({k: v for k, v in event.items() if k != "event_sha256"})),
            "full native hashchain differs",
        )
        previous = event["event_sha256"]
        if sequence < 4:
            continue
        fact_raw = base64.b64decode(event["raw_base64"], validate=True)
        fact = json.loads(fact_raw)
        need(
            sha(fact_raw) == event["raw_sha256"] and canonical(fact) == fact_raw,
            "native raw source bytes differ",
        )
        counts[event["kind"]] = counts.get(event["kind"], 0) + 1
        process = next(
            p["process"] for p in peers if p["process"]["pid"] == event["peer"]["pid"]
        )
        key = (process["pid"], event["runtime_request_id"])
        need(key not in closed, "native source fact after closure")
        if event["kind"] == "attention.worker.drained":
            prior = records.get(key, [])
            need(
                fact["process"] == process
                and prior
                and fact["source_ack_count"] == len(prior)
                and fact["source_ack_chain_sha256"] == sha(canonical(prior))
                and fact["source_last_ack"] == prior[-1],
                "complete actual source ACK chain differs",
            )
            closed.add(key)
        elif process["role"] == "worker":
            records.setdefault(key, []).append(
                {k: event[k] for k in ("sequence", "event_sha256", "raw_sha256")}
            )
    need(
        counts.get("tensor.artifact.accepted")
        == counts.get("attention.operator.accepted")
        == 56
        and counts.get("attention.worker.drained") == len(closed) == 2,
        "native receipt/source closure coverage differs",
    )
    need(
        obj("run/probe/collector-after.json")["status"]["acknowledged_prefix"]
        == {"next_sequence": 265, "last_event_sha256": previous},
        "full unfiltered final ACK differs",
    )
    journal = [
        json.loads(line) for line in raw("run/live-authority-raw.jsonl").splitlines()
    ]
    previous, clock, public = "0" * 64, 0, []
    for sequence, event in enumerate(journal, 1):
        need(
            event["sequence"] == sequence
            and event["previous_sha256"] == previous
            and event["sha256"]
            == sha(canonical({k: v for k, v in event.items() if k != "sha256"}))
            and event["schema"] == "ecpa-live-native-semantic-authority-journal/v1"
            and event["classification"] == CLASSIFICATION
            and event["formal_result"] is False
            and type(event["monotonic_ns"]) is int
            and clock <= event["monotonic_ns"],
            "complete authority hashchain differs",
        )
        previous, clock = event["sha256"], event["monotonic_ns"]
        if event["event"] == "public-request":
            public.append(event)
    need(
        len(journal) == 704
        and len(public) == 699
        and journal[0]["scope"] == scope
        and journal[0]["registration_sha256"] == reg_sha
        and journal[0]["authority"] == authority["authority"]
        and journal[0]["producer"] == producer["producer"],
        "authority scope or prefix differs",
    )
    cohort = obj("run/live-cohort-result.json")
    clients = [obj(f"run/live-client-{i:04}.json") for i in range(1, 700)]
    need(
        cohort["http_observations"] == clients
        and cohort["scope"] == scope
        and cohort["authority"] == authority["authority"]
        and cohort["producer"] == producer["producer"]
        and cohort["formal_result"] is False
        and cohort["passed"] is True,
        "complete independent client cohort differs",
    )
    for row, event in zip(clients, public):
        need(
            row["method"] == event["method"]
            and sha(row["path"].encode()) == event["path_sha256"]
            and row["status"] == event["status"]
            and row["response_sha256"] == event["response_sha256"]
            and row["request_monotonic_ns"]
            <= event["monotonic_ns"]
            <= row["response_monotonic_ns"],
            "independent client/authority status/hash/clock differs",
        )
        released = row["method"] == "POST" and row["status"] == 200
        retained_or_reconstructed_body = (
            response
            if released
            else canonical(
                {
                    "ready": event["ready"] if row["method"] == "GET" else False,
                    "quote_sha256": event["quote_sha256"],
                    "formal_result": False,
                    "classification": CLASSIFICATION,
                }
            )
        )
        need(
            sha(retained_or_reconstructed_body) == row["response_sha256"],
            "recorded HTTP hash differs from retained/reconstructed response bytes",
        )
        if event["ready"]:
            need(
                proof["issued_monotonic_ns"]
                <= event["monotonic_ns"]
                < proof["expires_monotonic_ns"],
                "recorded ready event outside original fixed lease",
            )
        if released:
            need(
                event["matched_frozen_request"] is True
                and event["ready"] is True
                and event["request_sha256"] == proof["request_sha256"],
                "public release scope differs",
            )
    posts = [
        (row, event) for row, event in zip(clients, public) if row["method"] == "POST"
    ]
    need(
        [row["status"] for row, _ in posts] == [200, 503, 503],
        "bounded public controls differ",
    )
    success, wrong, faulted = posts
    fault = obj("run/actual-worker-fault-intent.json")
    worker = next(
        p["process"]
        for p in peers
        if p["process"]["role"] == "worker" and p["process"]["ordinal"] == 1
    )
    need(
        fault["worker"] == kernel(worker)
        and fault["fault"] == "SIGTERM"
        and fault["formal_result"] is False
        and wrong[1]["matched_frozen_request"] is False
        and wrong[1]["request_sha256"] == sha(b"{}")
        and wrong[1]["ready"] is True
        and faulted[1]["matched_frozen_request"] is True
        and faulted[1]["request_sha256"] == proof["request_sha256"]
        and faulted[1]["ready"] is False
        and success[0]["response_monotonic_ns"]
        <= wrong[0]["response_monotonic_ns"]
        <= fault["at_monotonic_ns"]
        <= faulted[0]["request_monotonic_ns"]
        <= faulted[0]["response_monotonic_ns"]
        < proof["expires_monotonic_ns"],
        "actual registered fault identity/order or unexpired-lease control differs",
    )
    terminal = obj("run/terminal-process-audit.json")
    outer, watchdog = (
        obj("outer-independent-terminal-audit.json"),
        obj("outer-watchdog-result.json"),
    )
    live_terminal = obj("run/live-process-terminal.json")
    need(
        live_terminal["identities"] == [producer["producer"], authority["authority"]]
        and live_terminal["returncodes"] == [0, -15]
        and not terminal["backend_port"]["open"]
        and not terminal["public_port"]["open"]
        and all(not row["members"] for row in terminal["remaining_sessions"])
        and all(
            not row["same_identity_live"] and row["observed_kernel"] is None
            for row in terminal["source_peers"]
        )
        and not outer["owner_identity_still_live"]
        and not outer["cleanup_errors"]
        and all(not row["members"] for row in outer["remaining_sessions"])
        and watchdog["original_owner_exit"] == 0
        and watchdog["fired"] is False
        and not watchdog["cleanup_errors"]
        and obj("run/result.json")["passed"] is True,
        "recorded terminal cleanup differs",
    )
    observed = None
    if replay:
        path = directory / "frozen_source_replay.py"
        need(file_sha(path) == REPLAY_HELPER_SHA, "replay adapter source differs")
        specifier = importlib.util.spec_from_file_location(
            "frozen_replay_adapter", path
        )
        adapter = importlib.util.module_from_spec(specifier)
        specifier.loader.exec_module(adapter)
        adapted = {"runtime/" + name: value for name, value in files.items()}
        adapted.update(
            {
                "snapshots/" + name.split("/")[-1]: value
                for name, value in files.items()
                if name.startswith("frozen-sources/")
            }
        )
        # These software/tokenizer dependencies were pinned by the original
        # recipe but omitted from the raw archive. They are a separately named
        # late packaging supplement, never represented as original evidence.
        sources = list(recipe["sources"])
        for phase in recipe["phases"]:
            tokenization = phase["tokenization"]
            binding = tokenization["runtime_binding"]
            sources.extend(tokenization["assets"])
            sources.extend([binding["implementation_source"], *binding["host_sources"]])
        missing = {
            row["sha256"]: row["path"]
            for row in sources
            if "snapshots/" + row["sha256"] not in adapted
        }
        supplement = json.loads((directory / "replay-assets.json").read_bytes())
        need(
            supplement["schema"] == "ecpa-live-bounded-response-replay-supplement/v1"
            and supplement["original_archive_modified"] is False
            and supplement["original_recipe_sha256"] == RECIPE_SHA
            and {row["sha256"]: row["path"] for row in supplement["assets"]} == missing
            and len(supplement["assets"]) == len(missing) == 13,
            "late packaging dependency closure differs from original recipe pins",
        )
        container = supplement["container"]
        need(container["path"] == "replay-assets.tar.xz", "unsafe supplement path")
        source = directory / container["path"]
        need(
            source.stat().st_size == container["bytes"]
            and file_sha(source) == container["sha256"],
            "supplement container changed",
        )
        captured = set()
        with tarfile.open(source, "r|xz") as archive:
            for item in archive:
                digest = PurePosixPath(item.name).name
                need(
                    item.isfile()
                    and item.name == "objects/" + digest
                    and digest in missing
                    and digest not in captured
                    and item.size < 16000000,
                    "unexpected supplement object",
                )
                data = archive.extractfile(item).read()
                need(
                    len(data) == item.size and sha(data) == digest,
                    "supplement differs from preregistered bytes",
                )
                adapted["snapshots/" + digest] = data
                captured.add(digest)
        need(captured == set(missing), "missing preregistered replay dependency")
        observed = adapter.frozen_replay(adapted, cfg)
        need(
            sha(canonical(observed)) == proof["observation_sha256"]
            and observed == observation
            and observed["formal_result"] is False
            and observed["tensor_receipt_count"]
            == observed["operator_receipt_count"]
            == 56,
            "isolated frozen consumer output differs from original proof",
        )
    return {
        "schema": "ecpa-live-bounded-response-portable-replay/v1",
        "classification": CLASSIFICATION,
        "original_members_verified": 1102,
        "unique_content_objects_verified": 1022,
        "full_native_prefix_records": 265,
        "tensor_receipts": 56,
        "operator_receipts": 56,
        "worker_closures": 2,
        "authority_hashchain_records": 704,
        "public_client_observations": 699,
        "public_POST_statuses": [200, 503, 503],
        "fault_registered_kernel_identity_verified_from_records": True,
        "fault_response_remaining_original_lease_ns": proof["expires_monotonic_ns"]
        - faulted[0]["response_monotonic_ns"],
        "frozen_consumer_replayed_isolated": observed is not None,
        "late_packaging_preregistered_dependencies": 13,
        "original_raw_archive_dependency_closure_complete": False,
        "full_quote_nonce_transcript_replayed": False,
        "all_public_response_bodies_archived": False,
        "response_hashes_checked_against_retained_probe_or_reconstructed_controls": True,
        "fresh_OS_peer_authentication_performed": False,
        "formal_result": False,
        "formal_H3_starts": 0,
        "formal_H4_starts": 0,
        "full_model_quality": None,
        "performance_result": None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    args = parser.parse_args()
    files, _ = load_bundle(args.bundle)
    print(json.dumps(verify(files, args.bundle), sort_keys=True))


if __name__ == "__main__":
    main()
