#!/usr/bin/env python3
"""Actual owned Host launch/relaunch adapter for the registered H3 handshake.

This is a new source candidate. It does not retrofit archived qualifications or
change the frozen runner. Dynamic authority support must be registered before
execution; a missing capability rejects before any Host process is launched.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

from jsonschema import Draft7Validator

from experiments.formal_campaign import h3_client_trace as client
from experiments.formal_campaign.h3_worker_recovery import (
    capture_parent_worker_ancestry,
    require,
)
from experiments.formal_campaign.h3_worker_relaunch import (
    cleanup as _owned_cleanup,
)
from experiments.formal_campaign.h3_worker_relaunch import (
    identity,
    owned_sessions,
    worker,
)
from vllm_hust_ext.host_evidence import parse_host_event
from vllm_hust_ext.plan_artifact import read_plan_artifact
from vllm_hust_ext.runtime_phase_handoff import (
    accept_native_binding,
    bind_receiver,
    manager_source_digests,
)

PROTOCOL = "ecpa-h3-owned-observer-handshake/v1"
DYNAMIC_AUTHORITY = "ecpa-source-owned-dynamic-backend-enrollment/v1"
HERE = Path(__file__).resolve().parent


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def load(path):
    return json.loads(Path(path).read_bytes())


def reference(path):
    return {"path": str(path), "sha256": sha(Path(path).read_bytes())}


def save_new(path, value):
    raw = (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        + b"\n"
    )
    with Path(path).open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"path": Path(path).name, "sha256": sha(raw)}


def checked_reference(value):
    path = Path(value["path"])
    require(
        path.is_absolute() and path.is_file() and not path.is_symlink(),
        "source input requires an actual canonical file",
    )
    raw = path.read_bytes()
    require(sha(raw) == value["sha256"], "source input bytes differ")
    return path


class RegisteredAuthority:
    receipt_schema = "ecpa-h3-dynamic-deployment-receipt/v1"
    profile = DYNAMIC_AUTHORITY

    """Talk only to the source/argv/epoch bound independent authority process."""

    def __init__(self, recipe, registration, start_id):
        self.spec = recipe["authority"]
        self.expected = self.spec["process_identity"]
        self.process = identity(self.expected["pid"])
        require(
            all(self.process[k] == self.expected[k] for k in self.expected),
            "authority kernel differs",
        )
        require(
            self.process["pid"] != os.getpid(), "authority must be independently owned"
        )
        source = checked_reference(self.spec["source"])
        self.source = source
        self.argv = [
            p.decode()
            for p in Path(f"/proc/{self.process['pid']}/cmdline")
            .read_bytes()
            .split(b"\0")
            if p
        ]
        require(
            len(self.argv) >= 2
            and Path(self.argv[0]).resolve() == Path(sys.executable).resolve()
            and self.argv[1] == str(source),
            "authority did not execute the exact registered script prefix",
        )
        self.start = self._registered_start(registration, start_id)
        binding = self.start["authority"]
        self.registration_sha = binding["registration_sha256"]
        require(
            binding["source_sha256"] == sha(source.read_bytes()),
            "authority source is not the registered source",
        )
        require(
            binding["argv_sha256"] == sha(client.canonical({"argv": self.argv})),
            "authority complete argv differs from independently registered command",
        )
        self.socket = self.spec["socket"]
        status = Path(f"/proc/{self.process['pid']}/status").read_text().splitlines()
        self.uid = int(
            next(line for line in status if line.startswith("Uid:")).split()[2]
        )
        self.gid = int(
            next(line for line in status if line.startswith("Gid:")).split()[2]
        )
        self.socket_fence = self._socket_identity()
        self.grant = {
            "grant_holder": binding["grant"]["holder"],
            "grant_token": binding["grant"]["token"],
            "grant_expires_at": binding["grant"]["expires_at"],
        }
        require(
            self.grant["grant_expires_at"] > time.time(),
            "authority registration lease expired",
        )

    def _socket_identity(self):
        path = Path(self.socket)
        require(
            path.is_absolute() and path.resolve() == path,
            "authority socket must be canonical and nonsymlink",
        )
        info, parent = path.lstat(), path.parent.stat()
        require(
            stat.S_ISSOCK(info.st_mode)
            and info.st_uid == self.uid
            and info.st_gid == self.gid
            and not info.st_mode & 0o077
            and parent.st_uid == self.uid
            and not parent.st_mode & 0o077,
            "authority socket/directory is not private and source owned",
        )
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_gid,
            parent.st_dev,
            parent.st_ino,
            parent.st_mode,
            parent.st_uid,
            parent.st_gid,
        )

    @classmethod
    def _registered_start(cls, registration, start_id):
        start = next(
            (r for r in registration["starts"] if r["start_id"] == start_id), None
        )
        require(start is not None, "authority registration lacks this original start")
        require(
            registration.get("schema") == cls.receipt_schema,
            "explicit dynamic registration required",
        )
        return start

    def _verify_authority(self):
        require(
            identity(self.process["pid"]) == self.process,
            "registered authority epoch changed",
        )
        checked_reference(self.spec["source"])
        argv = [
            p.decode()
            for p in Path(f"/proc/{self.process['pid']}/cmdline")
            .read_bytes()
            .split(b"\0")
            if p
        ]
        require(
            argv == self.argv and self._socket_identity() == self.socket_fence,
            "authority source argv or private socket inode changed",
        )

    def call(self, operation, **fields):
        return self._call(operation, fields)

    def _call(self, operation, fields, *, response_deadline_ns=None):
        # Only native pre-admission preparation may use its original ready bound.
        require(
            response_deadline_ns is None
            or (
                isinstance(self, NativeRegisteredAuthority)
                and (
                    operation == "prepare_native_epoch"
                    or (
                        operation == "restart_live_observer"
                        and getattr(self, "live_scope", None) is not None
                    )
                )
                and type(response_deadline_ns) is int
            ),
            "extended control response bound is native preparation only",
        )
        stage = "authority-verification"
        try:
            self._verify_authority()
            request = {
                "operation": operation,
                "registration_sha256": self.registration_sha,
                "holder": self.grant["grant_holder"],
                "token": self.grant["grant_token"],
                **fields,
            }
            raw = client.canonical(request)
            require(len(raw) <= 64 * 1024, "authority command exceeds protocol bound")
            stage = "connect"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
                channel.settimeout(5)
                channel.connect(self.socket)
                peer = struct.unpack(
                    "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                )
                require(
                    peer == (self.process["pid"], self.uid, self.gid),
                    (
                        "connected authority peer is not the registered "
                        "actual process; "
                        "no grant sent"
                    ),
                )
                self._verify_authority()
                stage = "send"
                if (
                    response_deadline_ns is not None
                    and time.monotonic_ns() >= response_deadline_ns
                ):
                    raise TimeoutError(
                        "original readiness deadline expired before send"
                    )
                channel.sendall(raw + b"\n")
                stage = "response"
                data = b""
                while not data.endswith(b"\n"):
                    if response_deadline_ns is not None:
                        remaining_ns = response_deadline_ns - time.monotonic_ns()
                        if remaining_ns <= 0:
                            raise TimeoutError("original readiness deadline expired")
                        channel.settimeout(remaining_ns / 1e9)
                    piece = channel.recv(4096)
                    require(
                        piece and len(data) + len(piece) <= 64 * 1024,
                        "authority response is truncated/oversize",
                    )
                    data += piece
                self._verify_authority()
                if (
                    response_deadline_ns is not None
                    and time.monotonic_ns() > response_deadline_ns
                ):
                    raise TimeoutError(
                        "original readiness deadline expired after response"
                    )
            result = json.loads(data)
            require(
                result.get("ok") is True,
                "registered authority rejected "
                + operation
                + ": "
                + str(result.get("error")),
            )
            if (
                response_deadline_ns is not None
                and time.monotonic_ns() > response_deadline_ns
            ):
                raise TimeoutError(
                    "original readiness deadline expired before acceptance"
                )
            return result
        except TimeoutError as exc:
            raise TimeoutError(
                "authority control " + operation + " timed out during " + stage
            ) from exc

    def preflight(self):
        result = self.call("capabilities")
        require(
            self.profile in result.get("profiles", []),
            (
                "authority lacks actual new-epoch enrollment; no future PID or "
                "dead-instance reuse allowed"
            ),
        )
        require(
            result.get("registration_sha256") == self.registration_sha,
            "authority capability profile is not registered for this start",
        )
        return result

    def enroll(self, phase, membership, source_refs, expected_generation):
        # Authority must independently re-read /proc, endpoint ownership and
        # source/Plan obligation facts. These client fields are join inputs,
        # never authority evidence or permission to bypass required predicates.
        result = self.call(
            "enroll_generation",
            expected_generation=expected_generation,
            plan_id=phase["parent_event"]["plan_id"],
            launch_id=phase["parent"]["launch_id"],
            actual_membership=membership,
        )
        require(
            result.get("admission") == "closed-pending-obligations",
            "new generation was exposed during enrollment",
        )
        require(
            result.get("generation", -1) > expected_generation,
            "authority reused a dead serving generation",
        )
        return result


class NativeRegisteredAuthority(RegisteredAuthority):
    receipt_schema = "ecpa-h3-observer-loss-deployment-receipt/v1"
    profile = "ecpa-h3-source-owned-observer-private-route/v1"

    def prepare_native_epoch(self, *, phase_index, handoff, ready_deadline_ns):
        require(
            type(ready_deadline_ns) is int and ready_deadline_ns > time.monotonic_ns(),
            "native preparation exceeds original Host readiness deadline",
        )
        return self._call(
            "prepare_native_epoch",
            {"phase_index": phase_index, "handoff": handoff},
            response_deadline_ns=ready_deadline_ns,
        )

    def restart_live_observer(self, *, original_fault_ns):
        from experiments.formal_campaign.h3_observer_live_registration import (
            ValidatedLiveStart,
        )

        require(
            type(getattr(self, "live_scope", None)) is ValidatedLiveStart,
            "independently issued original live start scope required",
        )
        return self._call(
            "restart_live_observer",
            {"live_receipt": self.live_scope.receipt_ref()},
            response_deadline_ns=original_fault_ns + 30_000_000_000,
        )

    @classmethod
    def _registered_start(cls, registration, start_id):
        from experiments.formal_campaign.h3_observer_registration import (
            _ValidatedNativeStart,
        )

        if type(registration) is _ValidatedNativeStart:
            return registration.authority_binding(start_id)
        return super()._registered_start(registration, start_id)


def validate_recipe(recipe, expected_sha, recipe_path, arm, *, native=False):
    require(
        sha(recipe_path.read_bytes()) == expected_sha,
        "carrier recipe digest differs from registered command",
    )
    schema = (
        "h3-observer-recipe.schema.json"
        if native
        else "h3-owned-worker-recipe.schema.json"
    )
    Draft7Validator(load(HERE / schema)).validate(recipe)
    require(
        set(recipe["arms"])
        == {"ecpa", "manual-integration", "vanilla-vllm-entry-points"},
        "retain all original arms",
    )
    definition = recipe["arms"][arm]
    for phase in definition["phases"]:
        require(Path(phase["cwd"]).is_dir(), "actual launch cwd missing")
        for source in phase["sources"]:
            checked_reference(source)
        require(
            any(source["path"] in phase["argv"][:2] for source in phase["sources"]),
            "executed launcher has no source binding",
        )
        argv = phase["argv"]
        wrapper = str(HERE / "h3_dynamic_host.py")
        require(
            argv[:2] == [sys.executable, wrapper],
            "phase must execute exact runtime Python "
            "and real source-owned Host wrapper",
        )
        require(
            any(source["path"] == wrapper for source in phase["sources"]),
            "actual Host wrapper source binding missing",
        )
        if arm == "ecpa":
            require(
                argv[2:4] == ["manager", "run"] and "--" in argv,
                "ECPA must execute the actual Manager run entry",
            )
            host_command = argv[argv.index("--") + 1 :]
            require(
                host_command[:4] == [sys.executable, wrapper, "managed-host", "serve"],
                "Manager supervised command must execute real Host activation",
            )
        else:
            require(
                argv[2:4] == ["baseline", "serve"],
                "baseline must execute real Host serve entry",
            )
        flags = set(phase["argv"])
        if native:
            from vllm_hust_ext.discovery import discover_bundles
            from vllm_hust_ext.semantic_runtime_binding import (
                validate_semantic_launch_spec,
            )

            semantic_path = checked_reference(phase["semantic_launch_spec"])
            guard = load(checked_reference(phase["native_guard"]))
            require(
                guard["native_launch_spec"] == phase["semantic_launch_spec"]
                and guard["source_arguments"]["publisher_argv"] == phase["argv"],
                "native actual publisher/spec differs from registered guard",
            )
            declared = load(semantic_path)
            bundles = discover_bundles(
                [s["bundle_id"] for s in declared["enabled_bundles"]]
            )
            semantic = validate_semantic_launch_spec(semantic_path, bundles)
            require(
                phase["plan_artifact"] is not None
                and read_plan_artifact(
                    checked_reference(phase["plan_artifact"])
                ).plan_id
                == semantic["execution_plan_id"],
                "native full Plan differs from recomputed semantic launch",
            )
            bootstrap = phase["native_bootstrap"]
            require(
                phase["environment"].get("ECPA_NATIVE_ATTENTION_OPERATOR_OBSERVER")
                == "1"
                and phase["environment"].get("ECPA_NATIVE_PHASE_DRAIN") == "1"
                and phase["environment"].get("ECPA_NATIVE_SEMANTIC_BOOTSTRAP")
                == bootstrap["native_context_path"]
                and phase["environment"].get("ECPA_NATIVE_TENSOR_ARTIFACT_BOOTSTRAP")
                == bootstrap["tensor_context_path"],
                "actual native Host bootstrap environment differs",
            )
            require(
                len(bootstrap["phases"]) == 60,
                "original60 native request declarations required",
            )

        if arm == "ecpa":
            require(
                phase["manager_source_sha256"] == manager_source_digests(),
                "actual native Manager handoff sources differ",
            )
            require(
                phase["origin"] == "manager-native-handoff"
                and "--phase-binding-socket" in flags,
                "ECPA requires the actual Manager-owned handoff",
            )
            require(
                ("--semantic-launch-spec" in flags) is native,
                "semantic launch requires the explicitly registered native domain",
            )
            require(
                "--disable-ecpa-manager" not in flags, "ECPA cannot disable Manager"
            )
            if native:
                require(
                    phase["argv"].count("--semantic-launch-spec") == 1
                    and phase["argv"][phase["argv"].index("--semantic-launch-spec") + 1]
                    == str(semantic_path),
                    "Manager native spec path differs",
                )
        else:
            expected = (
                "--manual-hooks"
                if arm == "manual-integration"
                else "--enable-entrypoints"
            )
            require(
                phase["origin"] == "host-baseline"
                and "--disable-ecpa-manager" in flags
                and expected in flags,
                "baseline requires its real independent activation",
            )
            require(
                phase["plan_artifact"] is not None and phase["launch_id"],
                "baseline needs a frozen real Plan and distinct launch intent",
            )
            checked_reference(phase["plan_artifact"])
    first, second = definition["phases"]
    require(
        first["evidence_path"] != second["evidence_path"],
        "replacement cannot reuse old evidence stream",
    )
    if arm != "ecpa":
        require(
            first["launch_id"] != second["launch_id"],
            "replacement launch identity reused",
        )
    return definition


def wait_file(path, deadline):
    while time.monotonic() < deadline:
        if path.is_file():
            return load(path)
        time.sleep(0.01)
    raise TimeoutError("native runner handshake deadline: " + path.name)


def launch_phase(phase, arm, output, index, timeout):
    """Launch the real pinned Host; bind events to actual native origin."""
    environment = dict(phase["environment"])
    argv = list(phase["argv"])
    listener = None
    socket_path = Path(phase["handoff_path"]) if phase["handoff_path"] else None
    if phase["origin"] == "manager-native-handoff":
        require(
            socket_path is not None and not socket_path.exists(),
            "fresh Manager handoff socket required",
        )
        listener = bind_receiver(socket_path, timeout)
    else:
        plan = read_plan_artifact(checked_reference(phase["plan_artifact"]))
        if phase.get("semantic_launch_spec"):
            from vllm_hust_ext.discovery import discover_bundles
            from vllm_hust_ext.semantic_runtime_binding import (
                semantic_context_environment,
                validate_semantic_launch_spec,
            )

            path = checked_reference(phase["semantic_launch_spec"])
            declared = load(path)
            bundles = discover_bundles(
                [s["bundle_id"] for s in declared["enabled_bundles"]]
            )
            semantic = validate_semantic_launch_spec(path, bundles)
            require(
                plan.plan_id == semantic["execution_plan_id"],
                "baseline full Plan differs from actual semantic spec",
            )
            environment.update(semantic_context_environment(path, semantic))
            runtime_plan = semantic["native_plan_id"]
        else:
            runtime_plan = plan.plan_id
        environment.update(
            VLLM_ECPA_PLAN_ID=runtime_plan,
            VLLM_ECPA_LAUNCH_ID=phase["launch_id"],
            VLLM_HUST_EXT_EVIDENCE_PATH=phase["evidence_path"],
        )
    require(
        not Path(phase["evidence_path"]).exists(), "fresh Host evidence stream required"
    )
    started_wall = time.time_ns()
    with (output / f"phase{index}.log").open("xb") as log:
        process = subprocess.Popen(
            argv,
            cwd=phase["cwd"],
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    save_new(
        output / f"phase{index}.launch-observation.json",
        {"pid": process.pid, "launched_monotonic_ns": time.monotonic_ns()},
    )
    owner, owned = None, []
    try:
        owner = identity(process.pid)
        owned = [owner]
        save_new(output / f"phase{index}.live-owner.json", owner)
        if listener is not None:
            bound = accept_native_binding(
                listener,
                socket_path,
                owner,
                started_wall,
                phase["manager_source_sha256"],
                output / f"phase{index}.handoff-unvalidated.json",
            )
            save_new(output / f"phase{index}.native-binding.json", bound)
            env = bound["environment"]
            evidence_path = Path(env["VLLM_HUST_EXT_EVIDENCE_PATH"])
            plan_id, launch_id = env["VLLM_ECPA_PLAN_ID"], env["VLLM_ECPA_LAUNCH_ID"]
        else:
            evidence_path = Path(phase["evidence_path"])
            plan_id, launch_id = (
                environment["VLLM_ECPA_PLAN_ID"],
                environment["VLLM_ECPA_LAUNCH_ID"],
            )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            require(
                process.poll() is None,
                "actual Host exited before process-owned readiness",
            )
            if evidence_path.exists():
                workers = [
                    worker(
                        {
                            "evidence_protocol": "vllm-host-worker-event/v1",
                            "target_ordinal": ordinal,
                            "plan_id": plan_id,
                        },
                        {"evidence_path": str(evidence_path), "launch_id": launch_id},
                        owner,
                        started_wall,
                    )
                    for ordinal in phase["required_worker_ordinals"]
                ]
                if all(item is not None for item in workers):
                    target = next(
                        item
                        for item in workers
                        if item["ordinal"] == phase["worker_ordinal"]
                    )
                    records = [
                        parse_host_event(line)
                        for line in evidence_path.read_bytes().splitlines()
                        if line
                    ]
                    parents = [
                        r
                        for r in records
                        if r["event"] == "invoked"
                        and r["process"]["role"] == "api-server"
                        and r["process"].get("assignment_source") == "host"
                        and r["launch_id"] == launch_id
                        and r["plan_id"] == plan_id
                    ]
                    unique = {r["process"]["pid"] for r in parents}
                    require(
                        len(unique) <= 1,
                        "multiple API parents in this exact Host phase",
                    )
                    if parents:
                        parent = identity(parents[-1]["process"]["pid"]) | {
                            "launch_id": launch_id
                        }
                        worker_kernel = target["identity"] | {"launch_id": launch_id}
                        target_worker_ancestry = capture_parent_worker_ancestry(
                            parent, worker_kernel
                        )
                        sessions, descendants = owned_sessions(owner)
                        require(
                            parent["pid"] in descendants
                            and worker_kernel["pid"] in descendants,
                            "Host phase escaped owned adapter subtree",
                        )
                        owned.extend(sessions)
                        membership = [
                            {
                                "role": "api-server",
                                "ordinal": 0,
                                "identity": parent,
                                "event": parents[-1],
                            }
                        ]
                        for member in workers:
                            member_kernel = member["identity"] | {
                                "launch_id": launch_id
                            }
                            ancestry = capture_parent_worker_ancestry(
                                parent, member_kernel
                            )
                            membership.append(
                                {
                                    "role": "worker",
                                    "ordinal": member["ordinal"],
                                    "identity": member_kernel,
                                    "event": member["raw"],
                                    "parent_worker_ancestry": ancestry,
                                }
                            )
                        save_new(
                            output / f"phase{index}.actual-membership.json", membership
                        )
                        if phase.get("semantic_launch_spec"):
                            descriptor = evidence_path.stat()
                            if listener is not None:
                                handoff = {
                                    "record": bound,
                                    "raw": reference(
                                        output
                                        / f"phase{index}.handoff-unvalidated.json"
                                    ),
                                }
                            else:
                                handoff = {
                                    "origin": "host-baseline",
                                    "record": {
                                        "publisher": owner,
                                        "environment": environment,
                                    },
                                }
                            handoff["host_evidence"] = {
                                "path": str(evidence_path),
                                "identity": [
                                    descriptor.st_dev,
                                    descriptor.st_ino,
                                    descriptor.st_uid,
                                ],
                            }
                            save_new(
                                output / f"phase{index}.native-source-handoff.json",
                                handoff,
                            )
                        observed = {
                            "parent": parent,
                            "worker": worker_kernel,
                            "parent_event": parents[-1],
                            "worker_event": target["raw"],
                            "parent_worker_ancestry": target_worker_ancestry,
                            "owned_sessions": [s["pid"] for s in sessions],
                            "observed_ns": time.monotonic_ns(),
                            "route_generation": 0,
                        }
                        return process, owner, owned, observed
            time.sleep(0.02)
        raise TimeoutError("real Host process evidence readiness deadline")
    except Exception:
        if owner is not None:
            cleanup(process, owner, 10, owned)
        else:
            process.wait(timeout=10)
        raise
    finally:
        if listener is not None:
            listener.close()
            if socket_path.exists():
                socket_path.unlink()


def wait_native_health(endpoint, observed, launch_marker, timeout):
    """Original readiness bound, no model request or semantic-positive gate."""
    from experiments.formal_campaign.h3_dynamic_authority import accepted_api_socket
    from vllm_hust_ext.exposure_gate import GateError

    parsed = urlparse(endpoint)
    require(
        parsed.hostname == "127.0.0.1" and parsed.port,
        "native health requires the actual registered loopback backend",
    )
    deadline_ns = launch_marker["launched_monotonic_ns"] + int(timeout * 1e9)
    last_error = None
    while time.monotonic_ns() < deadline_ns:
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=1)
        try:
            connection.connect()
            connection.auto_open = 0
            accepted_api_socket(connection.sock, observed["parent"])
            capture_parent_worker_ancestry(observed["parent"], observed["worker"])
            connection.request("GET", "/health")
            response = connection.getresponse()
            response.read(1024)
            require(response.status == 200, "actual Host health is not ready")
            require(
                time.monotonic_ns() <= deadline_ns,
                "actual Host ready exceeded original readiness deadline",
            )
            capture_parent_worker_ancestry(observed["parent"], observed["worker"])
            return
        except (OSError, ValueError, GateError, http.client.HTTPException) as exc:
            last_error = str(exc)
        finally:
            connection.close()
        time.sleep(0.05)
    raise TimeoutError("actual Host original readiness deadline: " + str(last_error))


def retain_failure(
    output, campaign, args, reason, launched, receipt, authority, cleanup_report
):
    summary = {
        "schema": "ecpa-h3-owned-carrier-failure/v1",
        "phase": "launched" if launched else "preflight",
        "formal_result": False,
        "host_launched": bool(launched),
        "error": str(reason),
        "objective_met": None,
    }
    save_new(
        output
        / ("actual-start-failure.json" if launched else "preflight-rejection.json"),
        summary,
    )
    # This file records an actual launch, never an automatically qualified
    # formal failure. Only the independently source-admitted dynamic intake can
    # classify a registered start. Unknown metrics/objectives remain unknown.
    if launched:
        save_new(
            output / "launch-failure-provenance.json",
            {
                "evidence_class": "prospective-unverified",
                "owned_launches": launched,
                "deployment_receipt": reference(receipt),
                "dynamic_registration": reference(authority),
                "cleanup": cleanup_report,
                "formal_result": False,
                "objective_met": None,
            },
        )


_CLEANUP_EXTERNAL = None


def cleanup(process, owner, timeout, captured=None):
    """Protect explicitly external epochs before every carrier-owned signal."""
    require(_CLEANUP_EXTERNAL is not None, "external ownership contract not bound")
    from experiments.formal_campaign.h3_worker_relaunch import live, members

    candidates = list(captured or [owner]) + [owner]
    if live(owner):
        sessions, descendants = owned_sessions(owner)
        candidates += list(descendants.values()) + sessions
    for session_owner in list(candidates):
        if "pid" in session_owner:
            candidates += members(session_owner)
    require(
        not any(kernel in _CLEANUP_EXTERNAL for kernel in candidates),
        "external service epoch excluded from carrier cleanup",
    )
    return _owned_cleanup(process, owner, timeout, captured)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument("--recipe-sha256", required=True)
    parser.add_argument("--campaign-spec", type=Path, required=True)
    parser.add_argument(
        "--arm",
        choices=("ecpa", "manual-integration", "vanilla-vllm-entry-points"),
        required=True,
    )
    parser.add_argument("--repetition", type=int, choices=(1, 2, 3), required=True)
    parser.add_argument("--arm-order", type=int, choices=(1, 2, 3), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--deployment-receipt", type=Path, required=True)
    parser.add_argument("--authority-registration", type=Path, required=True)
    parser.add_argument(
        "--kernel-observer-handshake", choices=(PROTOCOL,), required=True
    )
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--native-domain", action="store_true")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    require(output.is_dir(), "independent runner must create start-owned output")
    try:
        if args.native_domain:
            from experiments.formal_campaign.h3_observer_registration import (
                validate_materialization,
                validate_receipt_for_start,
            )
        else:
            from experiments.formal_campaign.h3_dynamic_registration import (
                validate_materialization,
                validate_receipt,
            )

        if args.native_domain:
            original_ref = load(args.campaign_spec)["original_campaign"]
            original = load(checked_reference(original_ref))
            start_id = f"{original['cell_id']}-r{args.repetition}-{args.arm}"
            registration = validate_receipt_for_start(
                args.campaign_spec, args.deployment_receipt, start_id
            )
            dynamic, campaign, start = registration.selected(start_id)
        else:
            dynamic, campaign, registration = validate_receipt(
                args.campaign_spec, args.deployment_receipt
            )
            start_id = f"{campaign['cell_id']}-r{args.repetition}-{args.arm}"
            start = next(s for s in dynamic["starts"] if s["start_id"] == start_id)
        require(start["arm_order"] == args.arm_order, "original arm order differs")
        live_scope = None
        live_intent = os.environ.get("ECPA_H3_OBSERVER_LIVE_INTENT")
        live_receipt = os.environ.get("ECPA_H3_OBSERVER_LIVE_RECEIPT")
        require(
            bool(live_intent) == bool(live_receipt),
            "partial v2 receipt environment forbidden",
        )
        if live_intent:
            from experiments.formal_campaign.h3_observer_live_registration import (
                validate_for_start,
            )

            live_scope = validate_for_start(
                live_intent, live_receipt, start_id, check_remote=True
            )
            require(
                live_scope.value()["base_campaign"]["path"]
                == str(args.campaign_spec.resolve())
                and live_scope.value()["base_receipt"]["path"]
                == str(args.deployment_receipt.resolve()),
                "carrier live scope differs from original admission",
            )

        recipe = load(args.recipe)
        validate_materialization(dynamic, start, recipe)
        phase_definition = validate_recipe(
            recipe,
            args.recipe_sha256,
            args.recipe,
            args.arm,
            native=args.native_domain,
        )
        identity_schema = load(HERE / "record.schema.json")["properties"]["identity"]
        Draft7Validator(identity_schema).validate(
            {
                k: value
                for k, value in campaign["fixed_identity"].items()
                if k in identity_schema["properties"]
            }
        )
        start_id = f"{campaign['cell_id']}-r{args.repetition}-{args.arm}"
        require(
            args.authority_registration.resolve() == args.deployment_receipt.resolve(),
            "new domain uses its own independently issued receipt only",
        )
    except Exception as exc:
        save_new(
            output / "preflight-rejection.json",
            {
                "formal_result": False,
                "host_launched": False,
                "phase": "preflight",
                "error": str(exc),
                "objective_met": None,
            },
        )
        return 2
    if args.validate_only:
        print(
            json.dumps(
                {
                    "status": "source-recipe-valid-only",
                    "formal_result": False,
                    "host_launched": False,
                }
            )
        )
        return 0
    from experiments.formal_campaign.h3_observer_cleanup import external_epochs

    global _CLEANUP_EXTERNAL
    _CLEANUP_EXTERNAL = [
        entry["kernel"] for entry in external_epochs(dynamic["observer_cleanup"])
    ]
    require(args.native_domain, "observer carrier requires distinct native domain")
    require(
        start["recovery_action"] == "preserve-host-observe-failed-safe",
        "no actual observer private-context restart/rebind contract exists",
    )
    launches, client_process, client_owner = [], None, None
    failure = None
    cleanup_report = {
        "processes_reclaimed": False,
        "ports_reclaimed": False,
        "devices_reclaimed": False,
    }
    try:
        authority_class = (
            NativeRegisteredAuthority if args.native_domain else RegisteredAuthority
        )
        authority = authority_class(recipe, registration, start_id)
        if live_scope is not None:
            authority.live_scope = live_scope
        capabilities = authority.preflight()
        if live_scope is not None:
            require(
                "ecpa-h3-observer-live-transport-control/v2" in capabilities["profiles"]
                and capabilities.get("live_receipt") == live_scope.receipt_ref(),
                'actual authority lacks this independently '
                'issued v2 control permission',
            )
        save_new(output / "authority-capabilities.json", capabilities)
        current = authority.call("query")
        generation = current["generation"]
        for index, phase in enumerate(phase_definition["phases"]):
            if index:
                raise ValueError(
                    "observer recovery cannot reuse pinned dead collector contexts"
                )
            from experiments.formal_campaign.h3_runtime_source_closure import (
                verify_runtime_source_closure,
            )

            if args.native_domain:
                from experiments.formal_campaign.h3_observer_registration import (
                    preflight_native_spec,
                )

                preflight_native_spec(phase)
            runtime_closure = verify_runtime_source_closure(
                phase,
                campaign["fixed_identity"],
                dynamic["repositories"],
                dynamic["runtime_wheels"],
            )
            save_new(
                output / f"phase{index}.runtime-source-closure.json", runtime_closure
            )
            process, owner, sessions, observed = launch_phase(
                phase, args.arm, output, index, campaign["probe"]["ready_timeout_s"]
            )
            launches.append((process, owner, sessions))
            if args.native_domain:
                wait_native_health(
                    recipe["authority"]["backend_endpoint"],
                    observed,
                    load(output / f"phase{index}.launch-observation.json"),
                    campaign["probe"]["ready_timeout_s"],
                )
            enrollment = authority.enroll(
                observed,
                load(output / f"phase{index}.actual-membership.json"),
                phase["sources"],
                generation,
            )
            generation = enrollment["generation"]
            if args.native_domain:
                authority.prepare_native_epoch(
                    phase_index=index,
                    handoff=reference(
                        output / f"phase{index}.native-source-handoff.json"
                    ),
                    ready_deadline_ns=load(
                        output / f"phase{index}.launch-observation.json"
                    )["launched_monotonic_ns"]
                    + int(campaign["probe"]["ready_timeout_s"] * 1e9),
                )
            observed["route_generation"] = generation
            label = "before" if index == 0 else "after"
            save_new(output / f"carrier-{label}.json", observed)
            wait_file(output / f"runner-{label}-ack.json", time.monotonic() + 10)
            authority.call(
                "admit_generation",
                generation=generation,
                membership_sha256=enrollment["membership_sha256"],
            )
            if index == 0:
                template = start["client_template"]
                spec = dict(
                    template,
                    authority_process_identity={
                        k: authority.process[k]
                        for k in ("pid", "start_ticks", "boot_id")
                    },
                    authority_domain=(
                        authority.profile if args.native_domain else DYNAMIC_AUTHORITY
                    ),
                    dynamic_policy_sha256=sha(
                        client.canonical(load(start["policy"]["path"]))
                    ),
                    dynamic_registration_sha256=authority.registration_sha,
                    initial_enrollment_sha256=enrollment["membership_sha256"],
                )
                save_new(output / "runtime-client-spec.json", spec)
                client_process = subprocess.Popen(
                    [
                        sys.executable,
                        str(HERE / "h3_client_trace.py"),
                        "--spec",
                        str(output / "runtime-client-spec.json"),
                        "--trace",
                        str(output / "client.jsonl"),
                        "--ready",
                        str(output / "client-ready.json"),
                    ],
                    start_new_session=True,
                )
                client_owner = identity(client_process.pid)
                wait_file(output / "client-ready.json", time.monotonic() + 10)
                if args.native_domain:
                    authority.call(
                        "bind_original_client", process_identity=client_owner
                    )
                # Wait for an actual pre-fault request, keeping the original
                # schedule anchored by the client instead of delaying/retrying it.
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    if any(
                        e["kind"] == "request.start"
                        for e in client.read_client_trace(output / "client.jsonl")
                    ):
                        break
                    time.sleep(0.01)
                require(
                    any(
                        e["kind"] == "request.start"
                        for e in client.read_client_trace(output / "client.jsonl")
                    ),
                    "no actual pre-fault request start within original window",
                )
                save_new(
                    output / "carrier-fault-ready.json",
                    {
                        "start_id": start_id,
                        "enrollment_sha256": enrollment["membership_sha256"],
                    },
                )
                wait_file(output / "runner-fault.json", time.monotonic() + 10)
                wait_file(
                    output / "runner-observer-dead.json",
                    time.monotonic() + campaign["fault"]["target_exit_timeout_s"],
                )
                live_transport = None
                live_operator_actions = 0
                if live_scope is not None:
                    # The actual authority monitor must first record the original
                    # observer death and close the public route. No Host relaunch.
                    close_deadline = (
                        load(output / "runner-fault.json")["triggered_ns"]
                        + 30_000_000_000
                    )
                    while True:
                        query = authority.call("query")
                        if query["route"]["generation"] is None:
                            break
                        require(
                            time.monotonic_ns() < close_deadline,
                            "original30s close-before-repair expired",
                        )
                        time.sleep(0.01)
                    declaration = live_scope.value()["declaration"]
                    if declaration["operator"]["kind"] == "source-owned-automatic":
                        live_transport = authority.restart_live_observer(
                            original_fault_ns=load(output / "runner-fault.json")[
                                "triggered_ns"
                            ]
                        )
                    else:
                        from experiments.formal_campaign import (
                            h3_observer_live_operator,
                        )

                        invoke = h3_observer_live_operator.invoke

                        live_transport = invoke(
                            live_scope, args, recipe, registration, output
                        )
                        live_operator_actions = 1
                    save_new(
                        output / "carrier-live-observer-repair.json", live_transport
                    )
                # Original client continues without retries/reanchoring. The
                # distinct source-issued transport route is replayed below.
                client_process.wait(timeout=25)
                from experiments.formal_campaign.h3_observer_delivery import (
                    verify_native_window,
                )

                if live_scope is not None:
                    from experiments.formal_campaign.h3_observer_live_delivery import (
                        verify_native_window,
                    )
                result = verify_native_window(
                    spec,
                    output / "client.jsonl",
                    Path(start["authority"]["journal"]),
                    policy=load(start["policy"]["path"]),
                    frozen_probe=campaign["probe"],
                    expected_client={
                        k: client_owner[k] for k in ("pid", "start_ticks", "boot_id")
                    },
                    fault_ns=load(output / "runner-fault.json")["triggered_ns"],
                    recovery_ns=None,
                    allow_incomplete=True,
                    **(
                        {"live_receipt": live_scope.receipt_ref()}
                        if live_scope is not None
                        else {}
                    ),
                )
                save_new(output / "native-delivery-observation.json", result)
                membership = load(output / "phase0.actual-membership.json")
                from experiments.formal_campaign.h3_observer_loss import (
                    observe_host_kernels,
                )

                expected_hosts = [
                    {
                        k: m["identity"][k]
                        for k in ("pid", "start_ticks", "session", "boot_id")
                    }
                    for m in membership
                ]
                live_members = observe_host_kernels(expected_hosts)
                save_new(
                    output / "observer-recovery-accounting.json",
                    {
                        "schema": "ecpa-h3-observer-live-recovery-accounting/v2"
                        if live_scope
                        else "ecpa-h3-observer-recovery-accounting/v1",
                        "operator_actions": live_operator_actions,
                        "recovery_ns": result.get("recovery_ns"),
                        "actual_recovery": (
                            "source-owned-transport-route-original-delivery-replayed"
                            if live_transport
                            else "unavailable-producer-private-context-rebind-contract"
                        ),
                        "host_kernels_at_client_stop": live_members,
                        "observed_ns": time.monotonic_ns(),
                        "predecessor_alive_through_client_window": live_members
                        == expected_hosts,
                        "replacement_committed": bool(
                            live_transport
                            and live_transport.get("transport_commit_complete")
                        ),
                        "live_transport_attempt": live_transport,
                        "original_expected_final_route": campaign["objective"][
                            "expected_final_route"
                        ],
                    },
                )
                wait_file(
                    output / "runner-host-preserved-ack.json", time.monotonic() + 10
                )
                save_new(
                    output / "carrier-complete.json",
                    {
                        "schema": "ecpa-h3-observer-live-carrier-terminal/v2"
                        if live_scope
                        else "ecpa-h3-observer-carrier-terminal/v1",
                        "formal_result": False,
                        "objective_met": None,
                        "delivery": result,
                    },
                )
                break

    except Exception as exc:
        failure = exc
    finally:
        errors = []
        if client_process is not None:
            try:
                client_process.wait(timeout=25)
            except Exception as exc:
                errors.append("client terminal state: " + str(exc))
                try:
                    cleanup(client_process, client_owner, 5, [client_owner])
                except Exception as cleanup_exc:
                    errors.append(str(cleanup_exc))
        for process, owner, sessions in reversed(launches):
            try:
                cleanup(process, owner, 10, sessions)
            except Exception as exc:
                errors.append(str(exc))
        cleanup_report["processes_reclaimed"] = not errors
        cleanup_report["errors"] = errors

        # launch_phase may fail after Popen and clean its owned session before
        # returning. Its actual kernel observation still makes this a launched
        # failed start, never a preflight rejection.
        actual_launches = [
            load(p) for p in sorted(output.glob("phase*.launch-observation.json"))
        ]
        save_new(output / "carrier-cleanup.json", cleanup_report)
        if failure is not None:
            retain_failure(
                output,
                campaign,
                args,
                failure,
                actual_launches,
                args.deployment_receipt,
                args.authority_registration,
                cleanup_report,
            )
    return 0 if failure is None else (1 if actual_launches else 2)


if __name__ == "__main__":
    raise SystemExit(main())
