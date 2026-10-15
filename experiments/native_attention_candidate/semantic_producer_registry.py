"""Cell-scoped permits and live bindings; no launch, route mutation or formal PASS.

An independent issuer owns the key and the trusted source-observation digests.
They must never come from a producer's registration JSON. This local MAC is an
administrative boundary, not protection against an administrator reading memory.
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import os
import re
import socket
import stat
import struct
import threading
import time
from pathlib import Path

from experiments.formal_campaign import source_provenance
from vllm_hust_ext.plan_artifact import parse_plan_artifact, plan_artifact_bytes
from vllm_hust_ext.runtime_phase_handoff import (
    accept_native_binding,
    manager_source_digests,
    process_identity,
)
from vllm_hust_ext.semantic_obligations import EVENT, SCOPE

PERMIT = "ecpa-cell-semantic-producer-permit/v1"
DEPLOYMENT = "ecpa-cell-semantic-deployment/v1"
HANDOFF = "ecpa-cell-authenticated-manager-handoff/v1"
HEX = re.compile(r"[0-9a-f]{64}\Z")
KERNEL = ("pid", "start_ticks", "session", "boot_id")
SCOPE_KEYS = (
    "execution_plan_id",
    "native_plan_id",
    "native_launch_id",
    "controller_instance",
    "candidate_generation",
    "membership_epoch",
)
CELL_FIELDS = {
    "cell_id",
    "execution_plan_id",
    "obligation_id",
    "event",
    "scope",
    "plugin_ids",
    "profile_id",
    "recipe_sha256",
    "request_sha256",
    "model_sha256",
    "tokenizer_sha256",
    "calibration_sha256",
    "wheel_sha256",
    "native_sources",
    "protocol_sources",
    "manager_handoff_sources",
}


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def recipe_profile_id(recipe):
    """Bind exact source-bearing consumer contracts, never a caller's label."""
    require(len(recipe["phases"]) == 1, "only one request-scoped cell is supported")
    phase = recipe["phases"][0]
    return "profile:sha256:" + sha(
        canonical(
            {
                "contracts": {
                    k: recipe[k]
                    for k in (
                        "tensor_consumer_contract",
                        "attention_consumer_contract",
                        "attention_drain_contract",
                    )
                },
                "ack_time_policy": phase["ack_time_policy"],
                "tokenization": phase["tokenization"]["runtime_binding"],
            }
        )
    )


def require(value, reason):
    if not value:
        raise ValueError(reason)


def _files(sources):
    require(isinstance(sources, dict) and sources, "source inventory missing")
    for path, digest in sources.items():
        p = Path(path)
        require(
            p.is_absolute()
            and p.resolve() == p
            and not p.is_symlink()
            and p.is_file()
            and HEX.fullmatch(digest)
            and sha(p.read_bytes()) == digest,
            "registered source bytes differ",
        )


def _callback(callback, reference):
    path = inspect.getsourcefile(callback)
    require(
        path is not None and str(Path(path).resolve()) == reference["path"],
        "independent callback origin differs",
    )
    require(
        callback.__qualname__ == reference["callable"],
        "independent callback function differs",
    )
    _files({reference["path"]: reference["sha256"]})


def _kernel(expected):
    require(
        set(expected) == set(KERNEL) and type(expected["pid"]) is int,
        "kernel identity fields differ",
    )
    require(
        process_identity(expected["pid"]) == expected, "actual kernel epoch differs"
    )


def _environment(pid):
    return dict(
        piece.split(b"=", 1)
        for piece in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
        if b"=" in piece
    )


def _socket(path, connection, producer):
    p = Path(path)
    require(
        p.is_absolute() and p.parent.resolve() == p.parent and not p.is_symlink(),
        "producer socket path differs",
    )
    parent, meta = p.parent.stat(), p.stat()
    require(
        stat.S_ISSOCK(meta.st_mode)
        and parent.st_uid == os.geteuid()
        and not stat.S_IMODE(parent.st_mode) & 0o077,
        "socket parent is not private",
    )
    require(
        connection.family == socket.AF_UNIX and connection.getpeername() == str(p),
        "connected producer endpoint differs",
    )
    pid, uid, _ = struct.unpack(
        "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    )
    require(
        pid == producer["pid"] and uid == os.geteuid(), "producer kernel peer differs"
    )
    return {"device": meta.st_dev, "inode": meta.st_ino, "uid": meta.st_uid}


class CellIssuer:
    """Permit issuer, with independently pinned source-admission observations."""

    def __init__(self, key: bytes, trusted_source_observations: set[str]):
        require(
            isinstance(key, bytes) and len(key) >= 32,
            "independent issuer key too short",
        )
        require(
            bool(trusted_source_observations), "independent source trust set missing"
        )
        self._key = key
        self._trusted = frozenset(trusted_source_observations)

    def _seal(self, body):
        # Copy through canonical JSON: subsequent caller mutation cannot alter it.
        raw = canonical(body)
        return {
            "body": json.loads(raw),
            "sha256": sha(raw),
            "mac": hmac.new(self._key, raw, hashlib.sha256).hexdigest(),
        }

    def _open(self, envelope, schema):
        require(set(envelope) == {"body", "sha256", "mac"}, "issuer envelope differs")
        raw = canonical(envelope["body"])
        require(
            envelope["sha256"] == sha(raw)
            and isinstance(envelope["mac"], str)
            and hmac.compare_digest(
                envelope["mac"], hmac.new(self._key, raw, hashlib.sha256).hexdigest()
            ),
            "issuer authentication failed",
        )
        body = json.loads(raw)
        require(
            body["schema"] == schema and body["formal_result"] is False,
            "registration schema/result differs",
        )
        return body

    def issue_permit(
        self, cell, *, execution_plan, recipe, fixed, policy, source_observation
    ):
        source_provenance.validate_observation(source_observation, policy, fixed)
        admission = source_provenance.digest(
            source_provenance.canonical(source_observation)
        )
        require(
            admission in self._trusted,
            "source observation is not independently trusted",
        )
        require(
            set(cell) == CELL_FIELDS
            and cell["event"] == EVENT
            and cell["scope"] == SCOPE,
            "unsupported cell or semantic effect scope",
        )
        require(
            cell["profile_id"] == recipe_profile_id(recipe)
            and cell["recipe_sha256"] == sha(canonical(recipe))
            and cell["request_sha256"]
            == sha(canonical(recipe["phases"][0]["payload"])),
            "permitted recipe/profile/request differs",
        )
        plan = parse_plan_artifact(plan_artifact_bytes(execution_plan))
        require(
            plan.plan_id == cell["execution_plan_id"]
            and {p.id for p in plan.plugins} == set(cell["plugin_ids"])
            and len(
                [
                    o
                    for o in plan.obligations
                    if o.obligation_id == cell["obligation_id"]
                    and o.event == EVENT
                    and o.role == "worker"
                    and o.required_ordinals == (0, 1)
                ]
            )
            == 1,
            "execution Plan lacks the exact bounded obligation",
        )
        require(
            len(cell["plugin_ids"]) == 1
            and len(fixed.get("plugin_commits", fixed.get("plugins", {}))) == 1,
            "only one explicit plugin cell is supported; compositions unverified",
        )
        require(
            set(cell["wheel_sha256"])
            == {"host", "ascend", "mod", "manager", "torch", "torch_npu", "triton"},
            "exact seven-wheel tuple missing",
        )
        require(
            all(HEX.fullmatch(v) for v in cell["wheel_sha256"].values()),
            "wheel digest invalid",
        )
        require(
            all(
                isinstance(cell[k], str)
                and cell[k]
                and not any(c.isspace() for c in cell[k])
                for k in ("cell_id", "execution_plan_id", "obligation_id", "profile_id")
            ),
            "cell identity invalid",
        )
        for k in (
            "request_sha256",
            "recipe_sha256",
            "model_sha256",
            "tokenizer_sha256",
            "calibration_sha256",
        ):
            require(bool(HEX.fullmatch(cell[k])), "cell input digest invalid")
        require(
            set(cell["protocol_sources"])
            == {"producer", "verifier", "route_reader", "registry"},
            "protocol source roles missing",
        )
        for role, reference in cell["protocol_sources"].items():
            require(
                set(reference)
                == (
                    {"path", "sha256", "callable"}
                    if role in {"verifier", "route_reader"}
                    else {"path", "sha256"}
                ),
                "protocol source reference differs",
            )
            _files({reference["path"]: reference["sha256"]})
        registry = cell["protocol_sources"]["registry"]
        require(
            registry["path"] == str(Path(__file__).resolve()), "registry source differs"
        )
        _files(cell["native_sources"])
        require(
            cell["manager_handoff_sources"] == manager_source_digests(),
            "actual Manager handoff source differs",
        )
        return self._seal(
            {
                "schema": PERMIT,
                "cell": cell,
                "fixed_identity": fixed,
                "source_policy": policy,
                "source_observation": source_observation,
                "source_admission_sha256": admission,
                "other_cells": "unverified",
                "formal_result": False,
            }
        )

    def _permit(self, permit):
        value = self._open(permit, PERMIT)
        require(
            value["source_admission_sha256"] in self._trusted, "source trust revoked"
        )
        source_provenance.validate_observation(
            value["source_observation"], value["source_policy"], value["fixed_identity"]
        )
        _files(value["cell"]["native_sources"])
        require(
            value["cell"]["manager_handoff_sources"] == manager_source_digests(),
            "actual Manager handoff source differs",
        )
        for ref in value["cell"]["protocol_sources"].values():
            _files({ref["path"]: ref["sha256"]})
        return value

    def accept_handoff(self, permit, *, listener, path, manager, launched_wall_ns):
        """Capture the actual SO_PEERCRED-authenticated Manager exchange once.

        This replaces the owner's original accept call, before Host startup.
        Returning a MAC witness does not issue a semantic completion proof.
        """
        value = self._permit(permit)
        record = accept_native_binding(
            listener,
            Path(path),
            manager,
            launched_wall_ns,
            value["cell"]["manager_handoff_sources"],
        )
        return self._seal(
            {
                "schema": HANDOFF,
                "permit_sha256": permit["sha256"],
                "record": record,
                "formal_result": False,
            }
        )

    def bind_deployment(
        self,
        permit,
        *,
        handoff,
        scope,
        manager,
        peers,
        producer,
        socket_path,
        connection,
        artifacts,
        route_reader,
    ):
        """Bind actual OS identities after handshake; no semantic proof is issued."""
        value = self._permit(permit)
        captured = self._open(handoff, HANDOFF)
        require(
            captured["permit_sha256"] == permit["sha256"]
            and captured["record"]["publisher"] == manager
            and captured["record"]["environment"]["VLLM_ECPA_PLAN_ID"]
            == scope["native_plan_id"]
            and captured["record"]["environment"]["VLLM_ECPA_LAUNCH_ID"]
            == scope["native_launch_id"],
            "authenticated Manager handoff belongs to another deployment",
        )
        require(set(scope) == set(SCOPE_KEYS), "live scope fields differ")
        require(
            scope["execution_plan_id"] == value["cell"]["execution_plan_id"]
            and scope["execution_plan_id"] == "plan:sha256:" + scope["native_plan_id"],
            "Plan/native identity differs",
        )
        require(
            type(scope["candidate_generation"]) is int
            and scope["candidate_generation"] > 0
            and type(scope["membership_epoch"]) is int
            and scope["membership_epoch"] >= 0,
            "generation/membership invalid",
        )
        require(
            isinstance(scope["native_launch_id"], str)
            and re.fullmatch(
                r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                scope["native_launch_id"],
            )
            and isinstance(scope["controller_instance"], str)
            and scope["controller_instance"].startswith("controller:")
            and scope["controller_instance"] != "controller:"
            and not any(c.isspace() for c in scope["controller_instance"]),
            "launch/controller identity invalid",
        )
        require(
            set(peers) == {"api-server/0", "worker/0", "worker/1"},
            "frozen membership incomplete",
        )
        require(
            len({p["pid"] for p in [manager, producer, *peers.values()]}) == 5,
            "producer/Manager/required peers must be distinct processes",
        )
        _callback(route_reader, value["cell"]["protocol_sources"]["route_reader"])
        route = route_reader()
        body = {
            "schema": DEPLOYMENT,
            "permit_sha256": permit["sha256"],
            "scope": scope,
            "handoff": handoff,
            "manager": manager,
            "peers": peers,
            "producer": producer,
            "socket_path": str(socket_path),
            "socket_identity": _socket(socket_path, connection, producer),
            "artifacts": artifacts,
            "route": route,
            "formal_result": False,
        }
        self._live(value, body, connection, route_reader)
        return self._seal(body)

    def _live(self, permit, binding, connection, route_reader):
        cell, scope = permit["cell"], binding["scope"]
        for process in [
            binding["manager"],
            binding["producer"],
            *binding["peers"].values(),
        ]:
            _kernel(process)
        require(
            _socket(binding["socket_path"], connection, binding["producer"])
            == binding["socket_identity"],
            "producer socket replaced",
        )
        _callback(route_reader, cell["protocol_sources"]["route_reader"])
        route = route_reader()
        require(
            set(route)
            == {
                "generation",
                "membership_epoch",
                "controller_instance",
                "execution_plan_id",
                "native_launch_id",
                "fence",
                "lease_expires_monotonic_ns",
            },
            "route query fields differ",
        )
        require(
            route == binding["route"]
            and route["generation"] == scope["candidate_generation"]
            and route["membership_epoch"] == scope["membership_epoch"]
            and route["controller_instance"] == scope["controller_instance"]
            and route["execution_plan_id"] == scope["execution_plan_id"]
            and route["native_launch_id"] == scope["native_launch_id"]
            and isinstance(route["fence"], str)
            and bool(route["fence"])
            and type(route["generation"]) is int
            and type(route["membership_epoch"]) is int
            and type(route["lease_expires_monotonic_ns"]) is int
            and time.monotonic_ns() < route["lease_expires_monotonic_ns"],
            "route generation/fence/lease changed",
        )
        expected = {
            "VLLM_ECPA_PLAN_ID": scope["native_plan_id"],
            "VLLM_ECPA_LAUNCH_ID": scope["native_launch_id"],
            "ECPA_SEMANTIC_EXECUTION_PLAN_ID": scope["execution_plan_id"],
            "ECPA_SEMANTIC_CONTROLLER_INSTANCE": scope["controller_instance"],
            "ECPA_SEMANTIC_CANDIDATE_GENERATION": str(scope["candidate_generation"]),
            "ECPA_SEMANTIC_MEMBERSHIP_EPOCH": str(scope["membership_epoch"]),
        }
        for p in binding["peers"].values():
            env = _environment(p["pid"])
            require(
                all(env.get(k.encode()) == v.encode() for k, v in expected.items()),
                "actual Host handshake environment differs",
            )
        require(
            set(binding["artifacts"])
            == {"recipe", "spec", "policy", "drain_policy", "registration"},
            "deployment artifact roles differ",
        )
        for ref in binding["artifacts"].values():
            _files({ref["path"]: ref["sha256"]})
        spec = json.loads(Path(binding["artifacts"]["spec"]["path"]).read_bytes())
        recipe = json.loads(Path(binding["artifacts"]["recipe"]["path"]).read_bytes())
        require(
            sha(canonical(recipe)) == cell["recipe_sha256"]
            and recipe_profile_id(recipe) == cell["profile_id"],
            "deployed recipe profile differs",
        )
        registration = json.loads(
            Path(binding["artifacts"]["registration"]["path"]).read_bytes()
        )
        require(
            {k: registration[k] for k in SCOPE_KEYS} == scope
            and registration["manager_identity"] == binding["manager"]
            and registration["spec_path"] == binding["artifacts"]["spec"]["path"]
            and registration["recipe_path"] == binding["artifacts"]["recipe"]["path"]
            and registration["producer_source_path"]
            == cell["protocol_sources"]["producer"]["path"]
            and registration["producer_source_sha256"]
            == cell["protocol_sources"]["producer"]["sha256"],
            "live producer registration/handshake differs",
        )
        require(
            spec["native_plan_id"] == scope["native_plan_id"]
            and spec["native_launch_id"] == scope["native_launch_id"],
            "collector handshake IDs differ",
        )
        senders = spec["senders"]
        require(len(senders) == 3, "source peer registration incomplete")
        for sender in senders:
            process = sender["process"]
            key = f"{process['role']}/{process['ordinal']}"
            require(
                key in binding["peers"]
                and {k: process[k] for k in KERNEL} == binding["peers"][key],
                "registered source kernel differs",
            )
            require(
                {s["path"]: s["sha256"] for s in sender["source_files"]}
                == cell["native_sources"],
                "registered source tuple differs",
            )
        require(
            {f"{s['process']['role']}/{s['process']['ordinal']}" for s in senders}
            == set(binding["peers"]),
            "registered role coverage differs",
        )


class QuoteVerifier:
    """One-use challenges plus independently executed, source-pinned verification."""

    def __init__(self, issuer: CellIssuer):
        self.issuer = issuer
        self._pending = {}
        self._spent = set()
        self._leases = {}
        self._lock = threading.Lock()

    def expect(self, nonce):
        with self._lock:
            require(
                isinstance(nonce, str)
                and HEX.fullmatch(nonce)
                and nonce not in self._spent
                and nonce not in self._pending,
                "challenge nonce reused or invalid",
            )
            self._pending[nonce] = time.monotonic_ns()

    def verify(
        self,
        permit,
        deployment,
        quote,
        *,
        connection,
        route_reader,
        observation_verifier,
        observation_arguments,
    ):
        nonce = quote.get("nonce")
        with self._lock:
            require(nonce in self._pending, "quote nonce not pending or replayed")
            challenged = self._pending.pop(nonce)
            self._spent.add(nonce)  # Failed attempts are burned too.
        value = self.issuer._permit(permit)
        bound = self.issuer._open(deployment, DEPLOYMENT)
        require(
            bound["permit_sha256"] == permit["sha256"],
            "deployment belongs to another permit",
        )
        self.issuer._live(value, bound, connection, route_reader)
        cell = value["cell"]
        require(
            set(quote)
            == {
                "schema",
                "nonce",
                "registration_sha256",
                "producer",
                "scope",
                "ready",
                "reason",
                "proof",
                "formal_result",
            }
            and quote["schema"] == "ecpa-live-native-semantic-quote/v1"
            and isinstance(quote["reason"], str)
            and quote["formal_result"] is False
            and quote["ready"] is True
            and quote["producer"] == bound["producer"]
            and quote["scope"] == bound["scope"],
            "typed quote source/scope differs",
        )
        registration = json.loads(
            Path(bound["artifacts"]["registration"]["path"]).read_bytes()
        )
        require(
            quote["registration_sha256"] == sha(canonical(registration)),
            "quote registration differs",
        )
        proof = quote["proof"]
        require(
            isinstance(proof, dict)
            and set(proof)
            == {
                "observation_sha256",
                "request_sha256",
                "response_sha256",
                "issued_monotonic_ns",
                "expires_monotonic_ns",
                "tensor_receipts",
                "operator_receipts",
                "full_prefix_records",
                "worker_closures",
            },
            "typed proof fields differ",
        )
        require(
            proof["request_sha256"] == cell["request_sha256"]
            and type(proof["issued_monotonic_ns"]) is int
            and type(proof["expires_monotonic_ns"]) is int
            and challenged
            <= proof["issued_monotonic_ns"]
            <= time.monotonic_ns()
            < proof["expires_monotonic_ns"]
            <= bound["route"]["lease_expires_monotonic_ns"]
            and 0
            < proof["expires_monotonic_ns"] - proof["issued_monotonic_ns"]
            <= 30_000_000_000,
            "typed quote request/lease invalid",
        )
        with self._lock:
            expiry = self._leases.setdefault(
                deployment["sha256"], proof["expires_monotonic_ns"]
            )
            require(
                expiry == proof["expires_monotonic_ns"], "proof lease cannot be renewed"
            )
        _callback(observation_verifier, cell["protocol_sources"]["verifier"])
        require(
            set(observation_arguments)
            == {
                "recipe",
                "phase_id",
                "output",
                "descriptor",
                "spec_path",
                "journal_path",
                "policy_path",
                "drain_policy_path",
            },
            "live verifier argument fields differ",
        )
        require(
            str(observation_arguments["output"]) == registration["probe_output"]
            and str(observation_arguments["journal_path"])
            == registration["journal_path"]
            and observation_arguments["phase_id"] == registration["phase_id"]
            and observation_arguments["descriptor"]
            == registration["collector_descriptor"],
            "live verifier observation belongs to another deployment",
        )
        recipe = json.loads(Path(bound["artifacts"]["recipe"]["path"]).read_bytes())
        require(
            observation_arguments.get("recipe") == recipe,
            "verifier recipe differs from deployment",
        )
        for argument, artifact in (
            ("spec_path", "spec"),
            ("policy_path", "policy"),
            ("drain_policy_path", "drain_policy"),
        ):
            require(
                str(observation_arguments.get(argument))
                == bound["artifacts"][artifact]["path"],
                "verifier artifact belongs to another deployment",
            )
        phase = next(
            p
            for p in recipe["phases"]
            if p["phase_id"] == observation_arguments["phase_id"]
        )
        require(
            sha(canonical(phase["payload"])) == cell["request_sha256"],
            "verifier request differs from permitted scope",
        )
        observed = observation_verifier(**observation_arguments)
        journal = Path(registration["journal_path"]).read_bytes()
        rows = [json.loads(line) for line in journal.splitlines()]
        require(
            observed["observed_typed_HTTP_ACK_join"] is True
            and observed["finite_native_argument_completion_join"] is True
            and observed["typed_archive_provenance"]["full_phase_source_drained"]
            is True
            and observed["tensor_receipt_count"]
            == observed["operator_receipt_count"]
            == 56
            and sha(canonical(observed)) == proof["observation_sha256"]
            and observed["actual_raw_response_sha256"] == proof["response_sha256"],
            "independent full semantic observation differs",
        )
        require(
            observed["whole_journal_sha256"] == sha(journal)
            and all(
                type(proof[k]) is int
                for k in (
                    "tensor_receipts",
                    "operator_receipts",
                    "worker_closures",
                    "full_prefix_records",
                )
            )
            and proof["tensor_receipts"]
            == sum(r["kind"] == "tensor.artifact.accepted" for r in rows)
            == 56
            and proof["operator_receipts"]
            == sum(r["kind"] == "attention.operator.accepted" for r in rows)
            == 56
            and proof["worker_closures"]
            == sum(r["kind"] == "attention.worker.drained" for r in rows)
            == 2
            and proof["full_prefix_records"] == len(rows),
            "typed proof counts differ from independently verified full raw chain",
        )
        # Recheck after potentially expensive verification: no stale success.
        self.issuer._live(value, bound, connection, route_reader)
        require(
            time.monotonic_ns() < proof["expires_monotonic_ns"],
            "quote expired during verification",
        )
        return {
            "status": "bounded-cell-quote-verified",
            "permit_sha256": permit["sha256"],
            "deployment_sha256": deployment["sha256"],
            "obligation_id": cell["obligation_id"],
            "observation_sha256": proof["observation_sha256"],
            "other_cells": "unverified",
            "formal_result": False,
        }
