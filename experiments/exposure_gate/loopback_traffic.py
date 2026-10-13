"""Bounded loopback HTTP traffic authority for research integration tests.

The authority runs in a process separate from the gate. It owns the only
client-facing port and answers route queries over a private Unix socket.
It is not a production reverse proxy or a general deployment controller.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import signal
import socket
import stat
import struct
import threading
import time
from contextlib import suppress
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from vllm_hust_ext.exposure_gate import (
    GateError,
    LeaseAuthority,
    LeaseGrant,
    RouteState,
)
from vllm_hust_ext.formal_proxy_membership import verify_formal_proxy_membership
from vllm_hust_ext.host_evidence import EntryPointBinding
from vllm_hust_ext.host_observer import observe_bound_invocations
from vllm_hust_ext.plan_artifact import read_plan_artifact

MAX_MESSAGE = 64 * 1024
MAX_BODY = 1024 * 1024
MAX_JOURNAL = 4 * 1024 * 1024
JOURNAL_SCHEMA = "ecpa-loopback-route-journal/v1"
SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
AUTHORIZATION_FIELDS = {
    "plan_id",
    "launch_id",
    "controller_instance",
    "candidate_generation",
    "membership_epoch",
    "target_set_sha256",
}
FORMAL_AUTHORIZATION_FIELDS = {
    *AUTHORIZATION_FIELDS,
    "process_membership_sha256",
    "registration_sha256",
}
JOURNAL_KINDS = {
    "authority.start",
    "authority.stop",
    "route.close_checked",
    "route.open.intent",
    "route.open.applied",
    "route.restore.intent",
    "route.restore.applied",
    "route.close_all",
    "request.admit",
    "request.reject",
}


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def frozen_target_set_sha256(values: list[dict[str, Any]]) -> str:
    """Digest a canonical fixed-membership process snapshot."""
    fields = {"host", "role", "ordinal", "process_epoch"}
    if not isinstance(values, list) or not values:
        raise GateError("host authorization target set is empty")
    for value in values:
        if not isinstance(value, dict) or set(value) != fields:
            raise GateError("host authorization target fields are invalid")
        if (
            not isinstance(value["host"], str)
            or not value["host"]
            or value["host"].strip() != value["host"]
            or not isinstance(value["role"], str)
            or not value["role"]
            or value["role"].strip() != value["role"]
            or isinstance(value["ordinal"], bool)
            or not isinstance(value["ordinal"], int)
            or value["ordinal"] < 0
            or isinstance(value["process_epoch"], bool)
            or not isinstance(value["process_epoch"], int)
            or value["process_epoch"] < 0
        ):
            raise GateError("host authorization target values are invalid")
    try:
        canonical_targets = sorted(
            values,
            key=lambda item: (
                item["host"],
                item["role"],
                item["ordinal"],
                item["process_epoch"],
            ),
        )
    except TypeError as exc:
        raise GateError("host authorization target values are invalid") from exc
    if values != canonical_targets:
        raise GateError("host authorization target set is not canonical")
    logical_slots = [
        (item["host"], item["role"], item["ordinal"]) for item in canonical_targets
    ]
    if len(logical_slots) != len(set(logical_slots)):
        raise GateError("host authorization target set repeats a logical slot")
    return (
        "sha256:"
        + hashlib.sha256(
            _canonical({"required_processes": canonical_targets})
        ).hexdigest()
    )


class _TrafficJournal:
    """Traffic-process-owned route/admission trace, not a host-effect receipt."""

    def __init__(self, path: Path):
        parent = path.parent.stat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid()
            or parent.st_mode & 0o077
            or os.path.lexists(path)
        ):
            raise GateError(
                "traffic journal requires a new path in a private directory"
            )
        stat_fields = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()
        self.start_ticks = int(stat_fields[19])
        self.pid = os.getpid()
        self.sequence = 0
        self.previous = "sha256:" + "0" * 64
        self.fd = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_APPEND
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600,
        )

    def record(self, kind: str, route: RouteState, **detail: Any) -> None:
        next_sequence = self.sequence + 1
        event = {
            "schema": JOURNAL_SCHEMA,
            "sequence": next_sequence,
            "previous_sha256": self.previous,
            "at_ns": time.time_ns(),
            "proxy_pid": self.pid,
            "proxy_start_ticks": self.start_ticks,
            "kind": kind,
            "route": {
                "generation": route.generation,
                "fence": route.fence,
                "snapshot_sha256": "sha256:"
                + hashlib.sha256(_canonical({"snapshot": route.snapshot})).hexdigest(),
            },
            "detail": detail,
        }
        payload = _canonical(event)
        line = payload + b"\n"
        if os.fstat(self.fd).st_size + len(line) > MAX_JOURNAL:
            raise OSError("traffic journal capacity exceeded")
        written = 0
        while written < len(line):
            count = os.write(self.fd, line[written:])
            if count <= 0:
                raise OSError("traffic journal write failed")
            written += count
        os.fsync(self.fd)
        self.sequence = next_sequence
        self.previous = "sha256:" + hashlib.sha256(payload).hexdigest()

    def close(self) -> None:
        os.close(self.fd)


def read_traffic_journal(path: Path) -> list[dict[str, Any]]:
    """Validate an integration trace without promoting it to formal evidence."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as source:
            mode = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(mode.st_mode)
                or mode.st_uid != os.getuid()
                or mode.st_mode & 0o077
                or mode.st_size > MAX_JOURNAL
            ):
                raise GateError("traffic journal owner, mode, or size invalid")
            data = source.read(MAX_JOURNAL + 1)
    except OSError as exc:
        raise GateError("traffic journal cannot be opened safely") from exc
    if not data or len(data) > MAX_JOURNAL or not data.endswith(b"\n"):
        raise GateError("traffic journal is empty, oversized, or incomplete")
    previous = "sha256:" + "0" * 64
    events: list[dict[str, Any]] = []
    identity: tuple[int, int] | None = None
    for sequence, line in enumerate(data.splitlines(), 1):
        try:
            event = json.loads(line)
            canonical = isinstance(event, dict) and _canonical(event) == line
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise GateError("traffic journal contains invalid JSON") from exc
        if (
            not canonical
            or event.get("schema") != JOURNAL_SCHEMA
            or event.get("sequence") != sequence
            or event.get("previous_sha256") != previous
        ):
            raise GateError(
                "traffic journal sequence, chain, or canonical form changed"
            )
        route = event.get("route")
        if (
            event.get("kind") not in JOURNAL_KINDS
            or not isinstance(event.get("proxy_pid"), int)
            or event["proxy_pid"] <= 0
            or not isinstance(event.get("proxy_start_ticks"), int)
            or event["proxy_start_ticks"] <= 0
            or not isinstance(event.get("at_ns"), int)
            or not isinstance(event.get("detail"), dict)
            or not isinstance(route, dict)
            or set(route) != {"generation", "fence", "snapshot_sha256"}
            or not (
                route["generation"] is None
                or (
                    not isinstance(route["generation"], bool)
                    and isinstance(route["generation"], int)
                    and route["generation"] >= 0
                )
            )
            or not isinstance(route["fence"], str)
            or not isinstance(route["snapshot_sha256"], str)
            or SHA256.fullmatch(route["snapshot_sha256"]) is None
        ):
            raise GateError("traffic journal event shape invalid")
        observed_identity = (event["proxy_pid"], event["proxy_start_ticks"])
        if identity is None:
            identity = observed_identity
        elif observed_identity != identity:
            raise GateError("traffic journal process identity changed")
        if event["kind"] == "request.admit" and route["generation"] is None:
            raise GateError("traffic journal admitted a closed route")
        if event["kind"] == "request.reject" and route["generation"] is not None:
            raise GateError("traffic journal rejected an open route")
        previous = "sha256:" + hashlib.sha256(line).hexdigest()
        events.append(event)
    if events[0]["kind"] != "authority.start":
        raise GateError("traffic journal has no authority start")
    return events


def observe_gate_transitions(path: Path) -> dict[str, Any]:
    """Derive loopback gate facts from authority-owned journal bytes.

    This deliberately reports integration facts, not runtime-effect evidence.
    The reader is independent of the SUT and Manager and only accepts applied
    opens that immediately follow their durable intent record.
    """
    events = read_traffic_journal(path)
    facts: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        if event["kind"] == "route.open.applied":
            if index == 0:
                raise GateError("applied route open has no authority intent")
            intent = events[index - 1]
            route = event["route"]
            detail = intent["detail"]
            authorization = detail.get("authorization")
            if (
                intent["kind"] != "route.open.intent"
                or detail.get("candidate_generation") != route["generation"]
                or detail.get("candidate_fence") != route["fence"]
                or not isinstance(authorization, dict)
                or frozenset(authorization)
                not in {
                    frozenset(AUTHORIZATION_FIELDS),
                    frozenset(FORMAL_AUTHORIZATION_FIELDS),
                }
                or any(
                    not isinstance(authorization[field], str)
                    or not authorization[field]
                    for field in ("plan_id", "launch_id", "controller_instance")
                )
                or authorization["candidate_generation"] != route["generation"]
                or isinstance(authorization["membership_epoch"], bool)
                or not isinstance(authorization["membership_epoch"], int)
                or authorization["membership_epoch"] < 0
                or SHA256.fullmatch(str(authorization["target_set_sha256"])) is None
                or (
                    frozenset(authorization) == frozenset(FORMAL_AUTHORIZATION_FIELDS)
                    and (
                        SHA256.fullmatch(
                            str(authorization["process_membership_sha256"])
                        )
                        is None
                        or SHA256.fullmatch(
                            str(authorization["registration_sha256"])
                        )
                        is None
                    )
                )
                or SHA256.fullmatch(str(detail.get("observation_sha256"))) is None
            ):
                raise GateError("applied route open is not authority-bound")
            facts.append(
                {
                    "event": "gate-open",
                    "sequence": event["sequence"],
                    "route": route,
                    "authorization": authorization,
                    "observation_sha256": detail["observation_sha256"],
                }
            )
        elif event["kind"] in {"route.close_all", "route.restore.applied"}:
            facts.append(
                {
                    "event": (
                        "gate-close"
                        if event["kind"] == "route.close_all"
                        else "gate-restore"
                    ),
                    "sequence": event["sequence"],
                    "route": event["route"],
                    "reason": event["detail"].get("reason"),
                }
            )
    first = events[0]
    return {
        "schema": "ecpa-loopback-gate-observation/v1",
        "classification": "real-loopback-integration-preflight",
        "formal_result": False,
        "performance_result": False,
        "authority_process": {
            "pid": first["proxy_pid"],
            "start_ticks": first["proxy_start_ticks"],
        },
        "facts": facts,
    }


class _HostAuthorization:
    """Frozen host-observer inputs read by the traffic process, not its caller."""

    def __init__(self, path: Path):
        if not path.is_absolute() or path.is_symlink():
            raise GateError("host authorization path must be absolute and real")
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            with os.fdopen(fd, "rb") as source:
                metadata = os.fstat(source.fileno())
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_size > MAX_MESSAGE
                ):
                    raise GateError("host authorization file is not private")
                raw = source.read(MAX_MESSAGE + 1)
            value = json.loads(raw)
        except (OSError, ValueError, UnicodeError) as exc:
            raise GateError("host authorization cannot be read safely") from exc
        fields = {
            "schema",
            "authorization_path",
            "plan_path",
            "journal_dir",
            "journal_device",
            "journal_inode",
            "launch_id",
            "controller_instance",
            "candidate_generation",
            "membership_epoch",
            "target_set_sha256",
            "local_host",
            "bindings",
            "required_processes",
        }
        formal = isinstance(value, dict) and value.get("schema") == (
            "ecpa-loopback-formal-host-authorization/v1"
        )
        if formal:
            fields |= {
                "process_membership",
                "process_membership_sha256",
                "registration",
                "registration_sha256",
            }
        if not isinstance(value, dict) or set(value) != fields:
            raise GateError("host authorization fields do not match schema")
        if value["schema"] not in {
            "ecpa-loopback-host-authorization/v1",
            "ecpa-loopback-formal-host-authorization/v1",
        }:
            raise GateError("unsupported host authorization schema")
        try:
            self.authorization_path = Path(value["authorization_path"])
            self.plan = read_plan_artifact(value["plan_path"]).plan
            self.root = Path(value["journal_dir"])
            self.directory_identity = (
                value["journal_device"],
                value["journal_inode"],
            )
            self.launch_id = value["launch_id"]
            self.controller_instance = value["controller_instance"]
            self.candidate_generation = value["candidate_generation"]
            self.membership_epoch = value["membership_epoch"]
            self.target_set_sha256 = value["target_set_sha256"]
            self.local_host = value["local_host"]
            self.bindings = tuple(
                EntryPointBinding(**binding) for binding in value["bindings"]
            )
            self.required_processes = tuple(value["required_processes"])
            self.process_membership = (
                tuple(value["process_membership"]) if formal else None
            )
            self.process_membership_sha256 = (
                value["process_membership_sha256"] if formal else None
            )
            self.registration = value["registration"] if formal else None
            self.registration_sha256 = value["registration_sha256"] if formal else None
        except (KeyError, TypeError, ValueError) as exc:
            raise GateError("host authorization values are invalid") from exc
        if (
            self.authorization_path != path
            or not self.authorization_path.is_absolute()
            or not isinstance(self.launch_id, str)
            or not self.launch_id
            or not isinstance(self.controller_instance, str)
            or not self.controller_instance
            or not isinstance(self.local_host, str)
            or not self.local_host
            or isinstance(self.candidate_generation, bool)
            or not isinstance(self.candidate_generation, int)
            or self.candidate_generation < 1
            or isinstance(self.membership_epoch, bool)
            or not isinstance(self.membership_epoch, int)
            or self.membership_epoch < 0
            or not isinstance(self.target_set_sha256, str)
            or SHA256.fullmatch(self.target_set_sha256) is None
            or not self.root.is_absolute()
            or self.root.is_symlink()
            or not self.required_processes
            or not self.bindings
        ):
            raise GateError("host authorization identity is incomplete")
        derived_target_set = frozen_target_set_sha256(list(self.required_processes))
        if self.target_set_sha256 != derived_target_set:
            raise GateError("host authorization target-set digest changed")
        if formal:
            assert self.process_membership is not None
            derived_membership = (
                "sha256:"
                + hashlib.sha256(
                    _canonical({"process_membership": list(self.process_membership)})
                ).hexdigest()
            )
            if self.process_membership_sha256 != derived_membership:
                raise GateError("host authorization process-membership digest changed")
            registration_fields = {
                "schema",
                "evidence_class",
                "authority",
                "proxy_command_digest",
                "proxy_source_sha256",
                "review_receipt_sha256",
                "reviewer_kind",
                "public_port",
                "backend_port",
                "predecessor_port",
                "grant_holder",
                "grant_token",
                "grant_expires_at",
            }
            if (
                not isinstance(self.registration, dict)
                or set(self.registration) != registration_fields
                or self.registration["schema"] != "ecpa-formal-proxy-registration/v1"
                or self.registration["evidence_class"] != "formal-real"
                or self.registration["authority"] != "independent-loopback-proxy"
                or self.registration["reviewer_kind"] != "automated-independent"
                or SHA256.fullmatch(str(self.registration["proxy_command_digest"]))
                is None
                or SHA256.fullmatch(str(self.registration["proxy_source_sha256"]))
                is None
                or SHA256.fullmatch(str(self.registration["review_receipt_sha256"]))
                is None
                or self.registration["public_port"] != 8187
                or any(
                    isinstance(self.registration[field], bool)
                    or not isinstance(self.registration[field], int)
                    or not 1 <= self.registration[field] <= 65535
                    for field in ("backend_port", "predecessor_port")
                )
                or len(
                    {
                        self.registration["public_port"],
                        self.registration["backend_port"],
                        self.registration["predecessor_port"],
                    }
                )
                != 3
                or not isinstance(self.registration["grant_holder"], str)
                or not self.registration["grant_holder"]
                or any(
                    isinstance(self.registration[field], bool)
                    or not isinstance(self.registration[field], int)
                    or self.registration[field] < 1
                    for field in ("grant_token", "grant_expires_at")
                )
            ):
                raise GateError("formal proxy registration is invalid")
            derived_registration = (
                "sha256:" + hashlib.sha256(_canonical(self.registration)).hexdigest()
            )
            if self.registration_sha256 != derived_registration:
                raise GateError("formal proxy registration digest changed")
        self._claim_once(raw, metadata)

    def _claim_once(self, raw: bytes, metadata: os.stat_result) -> None:
        """Atomically consume this path-bound authorization for one authority."""
        parent = self.authorization_path.parent.stat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid()
            or parent.st_mode & 0o077
        ):
            raise GateError("host authorization directory is not private")
        claim_path = self.authorization_path.with_name(
            self.authorization_path.name + ".claim"
        )
        stat_fields = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()
        claim = {
            "schema": "ecpa-loopback-authorization-claim/v1",
            "authorization_path": str(self.authorization_path),
            "authorization_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
            "authorization_device": metadata.st_dev,
            "authorization_inode": metadata.st_ino,
            "authority_pid": os.getpid(),
            "authority_start_ticks": int(stat_fields[19]),
        }
        try:
            descriptor = os.open(
                claim_path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o600,
            )
        except FileExistsError as exc:
            raise GateError("host authorization was already claimed") from exc
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(_canonical(claim) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            directory = os.open(
                self.authorization_path.parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            os.close(descriptor)

    def binding(self) -> dict[str, Any]:
        value = {
            "plan_id": self.plan.plan_id,
            "launch_id": self.launch_id,
            "controller_instance": self.controller_instance,
            "candidate_generation": self.candidate_generation,
            "membership_epoch": self.membership_epoch,
            "target_set_sha256": self.target_set_sha256,
        }
        if self.process_membership_sha256 is not None:
            value["process_membership_sha256"] = self.process_membership_sha256
            value["registration_sha256"] = self.registration_sha256
        return value

    def authorize(self, snapshot: dict[str, Any]) -> str:
        if any(snapshot.get(key) != value for key, value in self.binding().items()):
            raise GateError("candidate route is not bound to host authorization")
        try:
            if self.process_membership is not None:
                verify_formal_proxy_membership(
                    self.root,
                    expected_directory_identity=self.directory_identity,
                    execution_identity={
                        "plan_id": self.plan.plan_id,
                        "launch_id": self.launch_id,
                        "controller_instance": self.controller_instance,
                    },
                    members=list(self.process_membership),
                )
            observation = observe_bound_invocations(
                self.root,
                expected_directory_identity=self.directory_identity,
                plan=self.plan,
                launch_id=self.launch_id,
                controller_instance=self.controller_instance,
                bindings=self.bindings,
                required_processes=self.required_processes,
                local_host=self.local_host,
            )
        except Exception as exc:
            raise GateError(
                "host observation is unavailable for frozen membership"
            ) from exc
        if not observation["complete_coverage"]:
            raise GateError("host observation does not cover frozen membership")
        return "sha256:" + hashlib.sha256(_canonical(observation)).hexdigest()


class LoopbackTrafficAdapter:
    """Control client for a separately running traffic-authority process."""

    behavioral_restore = False

    def __init__(self, socket_path: Path, grant: LeaseGrant):
        self.socket_path = socket_path
        self.authority = LeaseAuthority(grant)

    def _call(self, operation: str, **fields: Any) -> dict[str, Any]:
        payload = json.dumps(
            {"operation": operation, **fields}, sort_keys=True, separators=(",", ":")
        ).encode()
        if len(payload) > MAX_MESSAGE:
            raise GateError("traffic control request too large")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(str(self.socket_path))
            client.sendall(payload + b"\n")
            response = bytearray()
            while not response.endswith(b"\n"):
                chunk = client.recv(4096)
                if not chunk or len(response) + len(chunk) > MAX_MESSAGE:
                    raise GateError(
                        "traffic authority response incomplete or oversized"
                    )
                response.extend(chunk)
        value = json.loads(response)
        if not isinstance(value, dict):
            raise GateError("traffic authority returned a non-object response")
        if value.get("ok") is not True:
            raise GateError(
                str(value.get("error", "traffic authority rejected request"))
            )
        return value

    def close(self, generation: int) -> None:
        self._call("close", generation=generation)

    def open(
        self,
        generation: int,
        fence: str,
        snapshot: dict[str, Any],
        grant: LeaseGrant,
        now: int,
    ) -> None:
        self._call(
            "open",
            generation=generation,
            fence=fence,
            snapshot=snapshot,
            grant=asdict(grant),
            now=now,
        )

    def close_all(self) -> None:
        self._call("close_all")

    def restore(
        self, generation: int, fence: str, snapshot: dict[str, Any]
    ) -> RouteState:
        self._call("restore", generation=generation, fence=fence, snapshot=snapshot)
        return self.query_route()

    def lease_valid(self, grant: LeaseGrant, now: int) -> bool:
        return self._call("lease_valid", grant=asdict(grant), now=now)["valid"] is True

    def query_route(self) -> RouteState:
        value = self._call("query")["route"]
        return RouteState(value["generation"], value["fence"], value["snapshot"])


class _Authority:
    def __init__(
        self,
        route: RouteState,
        grant: LeaseGrant,
        predecessor: tuple[str, int],
        candidate: tuple[str, int],
        journal: _TrafficJournal,
        observer: _HostAuthorization | None = None,
    ):
        self.route = route
        self.grant = grant
        self.predecessor = predecessor
        self.candidate = candidate
        self.journal = journal
        self.observer = observer
        self.lock = threading.Lock()
        self.journal.record("authority.start", route)

    def _record(self, kind: str, route: RouteState, **detail: Any) -> None:
        try:
            self.journal.record(kind, route, **detail)
        except (OSError, TypeError, ValueError) as exc:
            self.route = RouteState(None, "closed", None)
            raise GateError(
                "traffic journal unavailable; routing failed closed"
            ) from exc

    def _refresh_candidate(self) -> str | None:
        if (
            self.observer is None
            or self.route.generation is None
            or not self.route.fence.startswith("gate-")
        ):
            return None
        try:
            if self.grant.expires_at < int(time.time()):
                raise GateError("traffic lease expired")
            if not isinstance(self.route.snapshot, dict):
                raise GateError("candidate route snapshot is unavailable")
            return self.observer.authorize(self.route.snapshot)
        except Exception:
            self.route = RouteState(None, "closed", None)
            self._record("route.close_all", self.route, reason="host observation lost")
            return None

    def _authorize_candidate(
        self, generation: int, snapshot: dict[str, Any]
    ) -> str | None:
        if self.observer is None:
            return None
        try:
            if self.observer.binding()["candidate_generation"] != generation:
                raise GateError("candidate generation differs from authorization")
            return self.observer.authorize(snapshot)
        except GateError:
            raise
        except Exception as exc:
            raise GateError("host observation is unavailable") from exc

    def apply(self, value: dict[str, Any]) -> dict[str, Any]:
        operation = value.get("operation")
        with self.lock:
            if operation == "query":
                self._refresh_candidate()
                return {"route": asdict(self.route)}
            if operation == "lease_valid":
                return {"valid": self._valid(value)}
            if operation == "close":
                if (
                    self.route.generation is None
                    or value.get("generation") != self.route.generation + 1
                ):
                    raise GateError("candidate generation does not follow predecessor")
                self._record(
                    "route.close_checked",
                    self.route,
                    candidate_generation=value["generation"],
                )
                return {}
            if operation == "open":
                if not self._valid(value):
                    raise GateError("traffic lease changed or expired")
                generation = value.get("generation")
                fence = value.get("fence")
                snapshot = value.get("snapshot")
                if (
                    self.route.generation is None
                    or generation != self.route.generation + 1
                    or not isinstance(fence, str)
                    or not fence.startswith("gate-")
                    or not isinstance(snapshot, dict)
                ):
                    raise GateError("invalid candidate route transition")
                observation_sha256 = self._authorize_candidate(generation, snapshot)
                candidate_route = RouteState(generation, fence, snapshot)
                self._record(
                    "route.open.intent",
                    self.route,
                    candidate_generation=generation,
                    candidate_fence=fence,
                    observation_sha256=observation_sha256,
                    authorization=(
                        self.observer.binding() if self.observer is not None else None
                    ),
                )
                self.route = candidate_route
                self._record("route.open.applied", self.route)
                return {}
            if operation == "close_all":
                self.route = RouteState(None, "closed", None)
                self._record("route.close_all", self.route)
                return {}
            if operation == "restore":
                generation = value.get("generation")
                fence = value.get("fence")
                snapshot = value.get("snapshot")
                if (
                    generation is None
                    or fence != f"fence-{generation}"
                    or not isinstance(snapshot, dict)
                ):
                    raise GateError("invalid predecessor restoration")
                predecessor_route = RouteState(generation, fence, snapshot)
                self._record("route.restore.intent", self.route, generation=generation)
                self.route = predecessor_route
                self._record("route.restore.applied", self.route)
                return {"route": asdict(self.route)}
        raise GateError("unknown traffic control operation")

    def _valid(self, value: dict[str, Any]) -> bool:
        try:
            supplied = LeaseGrant(**value["grant"])
            now = int(value["now"])
        except (KeyError, TypeError, ValueError):
            return False
        return (
            supplied == self.grant
            and self.grant.expires_at >= now
            and self.grant.expires_at >= int(time.time())
        )


class _ProxyHandler(BaseHTTPRequestHandler):
    server: _ProxyServer

    def do_GET(self) -> None:
        self._forward()

    def do_POST(self) -> None:
        self._forward()

    def _forward(self) -> None:
        if self.headers.get("Transfer-Encoding") is not None:
            self.send_error(400, "chunked requests unsupported")
            return
        try:
            body_size = int(self.headers.get("Content-Length", "0"))
            if body_size < 0 or body_size > MAX_BODY:
                raise ValueError
        except ValueError:
            self.send_error(413, "request body too large")
            return
        journal_failed = False
        with self.server.authority.lock:
            try:
                observation_sha256 = self.server.authority._refresh_candidate()
                route = self.server.authority.route
                self.server.authority._record(
                    "request.reject" if route.generation is None else "request.admit",
                    route,
                    method=self.command,
                    observation_sha256=observation_sha256,
                )
            except GateError:
                journal_failed = True
        if journal_failed:
            self.send_error(503, "traffic journal unavailable")
            return
        if route.generation is None:
            self.send_error(503, "traffic gate closed")
            return
        backend = (
            self.server.authority.predecessor
            if route.fence.startswith("fence-")
            else self.server.authority.candidate
        )
        body = self.rfile.read(body_size)
        try:
            connection = http.client.HTTPConnection(*backend, timeout=5)
            try:
                connection.request(
                    self.command,
                    self.path,
                    body=body,
                    headers={"Content-Type": self.headers.get("Content-Type", "")},
                )
                response = connection.getresponse()
                payload = response.read(MAX_BODY + 1)
                if len(payload) > MAX_BODY:
                    raise GateError("backend response too large")
                self.send_response(response.status)
                self.send_header("Content-Type", response.getheader("Content-Type", ""))
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            finally:
                connection.close()
        except (OSError, GateError):
            self.send_error(502, "backend unavailable")

    def log_message(self, _format: str, *_args: Any) -> None:
        pass


class _ProxyServer(ThreadingHTTPServer):
    def __init__(self, authority: _Authority, listen_port: int = 0):
        super().__init__(("127.0.0.1", listen_port), _ProxyHandler)
        self.authority = authority


def _admin(socket_path: Path, authority: _Authority, port: int) -> None:
    parent = socket_path.parent.stat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or parent.st_mode & 0o077
    ):
        raise GateError("traffic control directory must be private and owned")
    if os.path.lexists(socket_path):
        raise GateError("traffic control socket already exists")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        listener.listen(8)
        print(json.dumps({"port": port}), flush=True)
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(5)
                peer = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                _pid, uid, _gid = struct.unpack("3i", peer)
                if uid != os.getuid():
                    continue
                request = bytearray()
                while not request.endswith(b"\n") and len(request) <= MAX_MESSAGE:
                    try:
                        chunk = connection.recv(4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    request.extend(chunk)
                try:
                    if len(request) > MAX_MESSAGE or not request.endswith(b"\n"):
                        raise GateError("invalid traffic control message")
                    value = json.loads(request)
                    if not isinstance(value, dict):
                        raise GateError("traffic control request must be an object")
                    result = {"ok": True, **authority.apply(value)}
                except (GateError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    result = {"ok": False, "error": str(exc)}
                with suppress(OSError):
                    connection.sendall(
                        json.dumps(result, separators=(",", ":")).encode() + b"\n"
                    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--predecessor-port", type=int, required=True)
    parser.add_argument("--candidate-port", type=int, required=True)
    parser.add_argument("--listen-port", type=int, default=0)
    parser.add_argument("--predecessor-snapshot", required=True)
    parser.add_argument("--grant-holder", required=True)
    parser.add_argument("--grant-token", type=int, required=True)
    parser.add_argument("--grant-expires-at", type=int, required=True)
    parser.add_argument("--observer-config", type=Path)
    args = parser.parse_args()
    predecessor = json.loads(args.predecessor_snapshot)
    if not isinstance(predecessor, dict) or not isinstance(
        predecessor.get("generation"), int
    ):
        raise GateError("predecessor snapshot requires generation")
    observer = (
        _HostAuthorization(args.observer_config)
        if args.observer_config is not None
        else None
    )
    journal = _TrafficJournal(args.journal)
    try:
        authority = _Authority(
            RouteState(
                predecessor["generation"],
                f"fence-{predecessor['generation']}",
                predecessor,
            ),
            LeaseGrant(args.grant_holder, args.grant_token, args.grant_expires_at),
            ("127.0.0.1", args.predecessor_port),
            ("127.0.0.1", args.candidate_port),
            journal,
            observer,
        )
        if not 0 <= args.listen_port <= 65535:
            raise GateError("proxy listen port is invalid")
        if args.listen_port and args.listen_port in {
            args.predecessor_port,
            args.candidate_port,
        }:
            raise GateError("proxy listen port must be independent of backends")
        server = _ProxyServer(authority, args.listen_port)
    except Exception:
        journal.close()
        raise
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def stop(_signal: int, _frame: Any) -> None:
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        _admin(args.socket, authority, server.server_port)
    finally:
        with authority.lock:
            authority.route = RouteState(None, "closed", None)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        with authority.lock, suppress(GateError):
            authority._record("authority.stop", authority.route)
        journal.close()
        args.socket.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
