"""Verify retained real TP2 invocation-gate qualification without formal admission."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import tarfile
import tempfile
from pathlib import Path
from typing import Any

from experiments.exposure_gate.loopback_traffic import (
    frozen_target_set_sha256,
    read_traffic_journal,
)
from vllm_hust_ext.exposure_gate import GateError
from vllm_hust_ext.host_evidence import parse_host_event
from vllm_hust_ext.host_observer import parse_linux_start_ticks
from vllm_hust_ext.plan_artifact import read_plan_artifact


class QualificationError(ValueError):
    """Retained bytes do not substantiate this limited qualification."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise QualificationError(message)


def _json(root: Path, name: str) -> Any:
    return json.loads((root / name).read_bytes())


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verify_qualification(root: Path) -> dict[str, Any]:
    """Recompute worker coverage, routing boundaries, inference, and input binding."""
    result = _json(root, "result.json")
    inputs = _json(root, "inputs.json")
    audit = _json(root, "preflight.json")
    probe = _json(root, "device-init-probe.json")
    authorization = _json(root, "authorization.json")
    plan = read_plan_artifact(root / "plan.json").plan
    _require(result.get("passed") is True, "qualification execution failed")
    _require(result.get("classification") == "QUALIFIED_NONFORMAL", "wrong class")
    for name in ("formal_result", "performance_result", "effectiveness_result"):
        _require(result.get(name) is False, "qualification overclaims " + name)
    _require(result["launch_id"] == inputs["launch_id"], "launch changed")
    _require(audit["passed"] and probe["passed"], "input or device audit failed")
    _require(probe["device_count"] == 2, "TP2 device probe missing")
    _require(
        "ASCEND_RT_VISIBLE_DEVICES" not in inputs["environment"],
        "invalid physical-to-logical visible device mapping",
    )
    _require(
        audit["manager"]["commit"] == inputs["manager_commit"]
        and not audit["manager"]["dirty"],
        "Manager source audit differs from launch",
    )
    for name, digest in inputs["frozen_input_sha256"].items():
        path = root / ("runner.snapshot" if name == "run.py" else name)
        if not path.exists() and name == "run.py":
            path = root / name
        _require(_sha(path.read_bytes()) == digest, "frozen input changed: " + name)
    _require(plan.host.version == audit["installed"]["vllm"]["version"], "Host version")
    _require(
        plan.plugins[0].artifact_sha256
        == audit["wheels"]["vllm-kv-materialization"]["sha256"],
        "plugin artifact identity differs from audited wheel",
    )
    _require(
        all(not row["mismatches"] for row in audit["wheels"].values()),
        "installed source differs from wheel",
    )
    _require(
        result["frozen_input_sha256"] == inputs["frozen_input_sha256"],
        "result input hashes changed",
    )
    _require(
        len(plan.obligations) == 1 and len(authorization["bindings"]) == 1,
        "unexpected obligation or binding",
    )
    binding = authorization["bindings"][0]
    expected_entry = {k: binding[k] for k in ("group", "name", "value")}
    _require(
        binding["obligation"] == plan.obligations[0].obligation_id
        and binding["plugin_id"] == plan.plugins[0].id,
        "obligation or plugin binding changed",
    )
    _require(
        authorization["launch_id"] == inputs["launch_id"]
        and inputs["environment"]["VLLM_ECPA_PLAN_ID"] == plan.plan_id
        and inputs["environment"]["VLLM_ECPA_LAUNCH_ID"] == inputs["launch_id"],
        "authorization launch binding changed",
    )
    _require(
        Path(authorization["plan_path"]).name == "plan.json"
        and authorization["controller_instance"] == "controller:qualification-only",
        "authorization plan or controller changed",
    )
    required = authorization["required_processes"]
    _require(
        len(required) == 2 and {p["ordinal"] for p in required} == {0, 1},
        "worker target set is incomplete",
    )
    _require(all(p["role"] == "worker" for p in required), "wrong coverage scope")
    _require(
        authorization["target_set_sha256"] == frozen_target_set_sha256(required),
        "target set binding changed",
    )
    targets = {
        (p["host"], p["role"], p["ordinal"], p["process_epoch"]) for p in required
    }

    def coverage(name: str) -> float:
        observation = _json(root, name)
        _require(
            observation["plan_id"] == plan.plan_id
            and observation["launch_id"] == inputs["launch_id"],
            "observation is from another execution",
        )
        slots, linux = set(), set()
        for obligation in observation["obligations"].values():
            for record in obligation["effect_records"]:
                raw = base64.b64decode(record["raw_base64"], validate=True)
                _require(record["raw_sha256"] == "sha256:" + _sha(raw), "raw digest")
                source = root / "events" / record["journal"]
                if not source.exists():
                    source = root / "quarantine" / record["journal"]
                lines = source.read_bytes().splitlines()
                _require(
                    lines[record["line_number"] - 1] == raw,
                    "effect bytes differ from retained Host journal",
                )
                event = parse_host_event(raw)
                _require(
                    event["entry_point"] == expected_entry,
                    "effect uses another entry point",
                )
                process = event["process"]
                slot = tuple(
                    process[k] for k in ("host", "role", "ordinal", "process_epoch")
                )
                _require(
                    slot in targets
                    and process["assignment_source"] == "host"
                    and event["event"] == "invoked"
                    and event["plan_id"] == plan.plan_id
                    and event["launch_id"] == inputs["launch_id"],
                    "context or cross-execution bytes claimed as coverage",
                )
                ticks = parse_linux_start_ticks(
                    (root / "proc" / str(process["pid"]) / "stat").read_bytes()
                )
                _require(
                    process["start_identity"]
                    == f"pid:{process['pid']}:start_ticks:{ticks}",
                    "PID reuse",
                )
                argv = [
                    part.decode(errors="surrogateescape")
                    for part in (root / "proc" / str(process["pid"]) / "cmdline")
                    .read_bytes()
                    .split(b"\0")
                    if part
                ]
                identities = obligation["effect_process_identities"]
                _require(
                    any(
                        identity["pid"] == process["pid"] and identity["argv"] == argv
                        for identity in identities
                    ),
                    "retained worker cmdline differs from observation",
                )
                slots.add(slot)
                linux.add((process["pid"], ticks))
        _require(len(linux) == len(slots), "Linux identity reused for worker coverage")
        value = len(slots) / len(targets)
        _require(observation["complete_coverage"] == (value == 1), "coverage counter")
        return value

    _require(coverage("complete-observation.json") == 1, "complete invocation missing")
    for phase in ("before-open", "after-open"):
        _require(
            coverage(phase + "-partial-observation.json") == 0.5,
            "partial worker coverage is not derived from raw bytes",
        )
        _require(
            _json(root, phase + "-blocked-http.json")["status"] == 503,
            "partial coverage exposed the candidate",
        )
        _require(
            _json(root, phase + "-backend-alive.json")["status"] == 200,
            "model process was not alive during blocking",
        )
        _require(
            (root / (phase + "-backend-before.bin")).read_bytes()
            == (root / (phase + "-backend-after.bin")).read_bytes(),
            "blocked request changed backend log",
        )
    _require(
        _json(root, "after-open-route.json")["generation"] is None,
        "coverage loss did not revoke candidate route",
    )
    completion = _json(root, "proxy-completion.json")
    body = json.loads(completion["body"])
    _require(
        completion["status"] == 200
        and body["choices"][0]["message"]["content"]
        and body["usage"]["completion_tokens"] > 0,
        "real inference missing",
    )
    _require(body["model"] == _json(root, "request.json")["model"], "wrong model")
    _require(
        "g379a0ad35-tp2" in body["system_fingerprint"], "wrong runtime fingerprint"
    )
    _require(
        _json(root, "cleanup-ports.json") == {"8187": 111, "18187": 111, "28187": 111},
        "ports not cleaned",
    )
    cleanup = (root / "cleanup-npu.txt").read_text()
    _require(
        all(
            f"No running processes found in NPU {device}" in cleanup
            for device in (3, 6)
        ),
        "NPU cleanup missing",
    )
    for phase in ("before-open", "after-open"):
        quarantine = _json(root, phase + "-quarantine.json")
        retained = root / "quarantine" / Path(quarantine["quarantine"]).name
        _require(
            _sha(retained.read_bytes()) == quarantine["raw_sha256"],
            "quarantined Host bytes changed",
        )
    with tempfile.TemporaryDirectory() as directory:
        private = Path(directory) / "authority.jsonl"
        private.write_bytes((root / "authority.jsonl").read_bytes())
        private.chmod(0o600)
        try:
            events = read_traffic_journal(private)
        except GateError as exc:
            raise QualificationError("authority trace invalid") from exc
    _require(all(e["proxy_pid"] == result["proxy_pid"] for e in events), "proxy PID")
    expected_kinds = [
        "authority.start",
        "request.admit",
        "route.open.intent",
        "route.open.applied",
        "request.admit",
        "route.close_all",
        "request.reject",
        "authority.stop",
    ]
    _require(
        [event["kind"] for event in events] == expected_kinds,
        "traffic sequence differs from retained deny/open/revoke experiment",
    )
    _require(
        [event["route"]["generation"] for event in events]
        == [0, 0, 0, 1, 1, None, None, None],
        "traffic generations changed",
    )
    candidate = {
        k: authorization[k]
        for k in (
            "launch_id",
            "controller_instance",
            "candidate_generation",
            "membership_epoch",
            "target_set_sha256",
        )
    }
    candidate["plan_id"] = plan.plan_id

    def canonical(value: Any) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    snapshot_digest = "sha256:" + _sha(canonical({"snapshot": candidate}))
    _require(
        events[3]["route"]["snapshot_sha256"] == snapshot_digest
        and events[4]["route"]["snapshot_sha256"] == snapshot_digest,
        "candidate snapshot changed",
    )
    _require(
        events[2]["detail"]["authorization"] == candidate,
        "authority opened another authorization",
    )
    observation_digest = "sha256:" + _sha(
        canonical(_json(root, "complete-observation.json"))
    )
    _require(
        events[2]["detail"]["observation_sha256"] == observation_digest
        and events[4]["detail"]["observation_sha256"] == observation_digest,
        "candidate request lacks exact independent observation binding",
    )
    before = _json(root, "before-open-blocked-http.json")["observed_ns"]
    after = _json(root, "after-open-blocked-http.json")["observed_ns"]
    _require(
        events[1]["at_ns"] < before < events[2]["at_ns"]
        and events[4]["at_ns"] < completion["observed_ns"] < events[5]["at_ns"]
        and events[6]["at_ns"] < after < events[7]["at_ns"],
        "HTTP observations are outside their authority phases",
    )
    claim = _json(root, "authorization.json.claim")
    _require(
        claim["authority_pid"] == result["proxy_pid"]
        and claim["authority_start_ticks"] == events[0]["proxy_start_ticks"]
        and claim["authorization_sha256"]
        == "sha256:" + _sha((root / "authorization.json").read_bytes()),
        "authorization claim changed",
    )
    opened = [e for e in events if e["kind"] == "route.open.applied"]
    _require(len(opened) == 1, "candidate open count")
    closed = [
        e
        for e in events
        if e["kind"] == "route.close_all"
        and e["detail"].get("reason") == "host observation lost"
    ]
    _require(
        closed and closed[0]["sequence"] > opened[0]["sequence"],
        "independent authority did not revoke coverage loss",
    )
    return {
        "classification": "QUALIFIED_NONFORMAL",
        "formal_result": False,
        "performance_result": False,
        "effective_semantics_result": False,
        "worker_invocation_coverage_complete": 1.0,
        "worker_invocation_coverage_partial": 0.5,
        "real_model_completions": 1,
        "blocked_requests": 2,
        "model": body["model"],
        "manager_commit": inputs["manager_commit"],
    }


def unpack_qualification(package: Path, target: Path) -> None:
    """Check the sealed raw archive before extracting ordinary relative files."""
    manifest = _json(package, "manifest.json")
    raw = (package / "retained.tar.gz").read_bytes()
    _require(_sha(raw) == manifest["archive_sha256"], "retained archive changed")
    expected = manifest["files"]
    seen = set()
    with tarfile.open(package / "retained.tar.gz", "r:gz") as archive:
        for member in archive.getmembers():
            path = Path(member.name)
            _require(
                member.isfile()
                and not path.is_absolute()
                and ".." not in path.parts
                and member.name in expected
                and member.name not in seen,
                "archive contains unexpected or unsafe member",
            )
            source = archive.extractfile(member)
            _require(source is not None, "archive member is unreadable")
            assert source is not None
            data = source.read()
            _require(
                len(data) == expected[member.name]["size"]
                and _sha(data) == expected[member.name]["sha256"],
                "raw member changed",
            )
            destination = target / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            destination.chmod(0o600)
            seen.add(member.name)
    _require(seen == set(expected), "retained raw file is missing")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as directory:
        target = Path(directory)
        unpack_qualification(args.package, target)
        print(json.dumps(verify_qualification(target), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
