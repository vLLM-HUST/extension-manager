"""Read real loopback controller state; never create a route or semantic proof.

The independent issuer supplies pins, not producer registration JSON.  This is
local same-UID administrative verification, not attestation against a malicious
administrator.  The cached-response authority has no route control endpoint and
is deliberately unsupported.  Existing legacy semantic admission remains shut.
"""

from __future__ import annotations

import hashlib
import importlib.metadata as metadata
import json
import os
import socket
import stat
import struct
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from types import MappingProxyType

from experiments.native_attention_candidate import (
    semantic_producer_registry as registry,
)

SCHEMA = "ecpa-live-cell-input-audit/v1"
SNAPSHOT = "ecpa-live-controller-cell-binding/v1"
DISTRIBUTIONS = {
    "host": "vllm",
    "ascend": "vllm-ascend",
    "mod": "vllm-ascend-kvcompress-hust",
    "manager": "vllm-hust-ext",
    "torch": "torch",
    "torch_npu": "torch-npu",
    "triton": "triton-ascend",
}
MAX_MESSAGE = 64 * 1024


def _path(value):
    p = Path(value)
    registry.require(
        p.is_absolute() and p.resolve() == p and not p.is_symlink(),
        "input path is not canonical",
    )
    return p


def _state(meta):
    return {
        key: getattr(meta, key)
        for key in (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_mode",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
    }


def _directory_identity(meta):
    # Child creation changes directory clocks/size during normal runtime imports.
    # Bind its actual namespace identity/permissions; leaves retain every field.
    return meta.st_dev, meta.st_ino, meta.st_uid, meta.st_mode


def _check_file_states(states):
    """Check every declared leaf and ancestor freshly on each invocation."""
    _CompiledFileStates(states).check()


class _CompiledFileStates:
    """Immutable declarations only; descriptors and observations stay in check()."""

    __slots__ = ("_tree",)

    def __init__(self, states):
        tree = {"children": {}, "files": []}
        for path, expected in states.items():
            registry.require(isinstance(path, str), "input path is not canonical")
            parts = path.split("/")
            registry.require(
                len(parts) > 1
                and parts[0] == ""
                and all(
                    part and part not in {".", ".."} and "\0" not in part
                    for part in parts[1:]
                ),
                "input path is not canonical",
            )
            node = tree
            for component in parts[1:-1]:
                node = node["children"].setdefault(
                    component, {"children": {}, "files": []}
                )
            node["files"].append((parts[-1], MappingProxyType(dict(expected))))

        def freeze(node):
            return (
                tuple(
                    (name, freeze(child)) for name, child in node["children"].items()
                ),
                tuple(node["files"]),
            )

        self._tree = freeze(tree)

    def check(self):
        # Only the pure declaration tree is reused. Every observed identity is
        # local to this walk, including the final complete ancestor rewalk.
        tree = self._tree
        identities = {}
        flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

        def walk(descriptor, node, *, leaves):
            before = _directory_identity(os.fstat(descriptor))
            registry.require(stat.S_ISDIR(before[3]), "audited input ancestor changed")
            if leaves:
                identities[id(node)] = before
            else:
                registry.require(
                    before == identities[id(node)], "audited input ancestor changed"
                )
            for name, child in node[0]:
                child_fd = os.open(name, flags, dir_fd=descriptor)
                try:
                    identity = _directory_identity(os.fstat(child_fd))
                    registry.require(
                        _directory_identity(
                            os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                        )
                        == identity,
                        "audited input ancestor changed",
                    )
                    walk(child_fd, child, leaves=leaves)
                    registry.require(
                        _directory_identity(os.fstat(child_fd))
                        == identity
                        == _directory_identity(
                            os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                        ),
                        "audited input ancestor changed",
                    )
                finally:
                    os.close(child_fd)
            if leaves:
                for name, expected in node[1]:
                    actual = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                    registry.require(
                        not stat.S_ISLNK(actual.st_mode) and _state(actual) == expected,
                        "audited input file changed",
                    )
            registry.require(
                _directory_identity(os.fstat(descriptor)) == before,
                "audited input ancestor changed",
            )

        try:
            root_fd = os.open("/", flags)
            try:
                walk(root_fd, tree, leaves=True)
                walk(root_fd, tree, leaves=False)
                registry.require(
                    _directory_identity(os.stat("/", follow_symlinks=False))
                    == identities[id(tree)],
                    "audited input ancestor changed",
                )
            finally:
                os.close(root_fd)
        except OSError as exc:
            raise ValueError("audited input file or ancestor changed") from exc


def _stream_sha(stream):
    digest = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
    return digest.hexdigest()


def _hash(path, states=None):
    path = _path(path)
    with path.open("rb") as stream:
        before = _state(os.fstat(stream.fileno()))
        digest = _stream_sha(stream)
        after = _state(os.fstat(stream.fileno()))
    registry.require(
        before == after == _state(path.stat()), "input changed during hashing"
    )
    if states is not None:
        states[str(path)] = after
    return digest


def _inventory(rows, states=None):
    registry.require(isinstance(rows, list) and rows, "input inventory missing")
    result = {}
    for row in rows:
        path, digest = str(_path(row["path"])), row["sha256"]
        registry.require(path not in result, "input inventory repeats a path")
        registry.require(_hash(path, states) == digest, "input bytes differ")
        result[path] = digest
    return result


def _model_inventory(rows, states):
    """Hash this audit's model files independently; never reuse file results."""
    registry.require(isinstance(rows, list) and rows, "input inventory missing")
    declarations, seen = [], set()
    for row in rows:
        path, digest = str(_path(row["path"])), row["sha256"]
        registry.require(path not in seen, "input inventory repeats a path")
        seen.add(path)
        declarations.append((path, digest))

    def observe(declaration):
        path, expected = declaration
        private_states = {}
        digest = _hash(path, private_states)
        registry.require(digest == expected, "input bytes differ")
        return path, digest, private_states

    # Workers perform only the original complete hash/stat operation. Metadata
    # discovery, installed-package inspection and audit assembly stay sequential.
    with ThreadPoolExecutor(max_workers=4) as executor:
        observations = list(executor.map(observe, declarations))
    result = {}
    for path, digest, private_states in observations:
        for observed_path, state in private_states.items():
            registry.require(
                observed_path not in states or states[observed_path] == state,
                "input file state conflicts",
            )
            states[observed_path] = state
        result[path] = digest
    return result


def _payload(name):
    # Runtime code/ELFs only: generated entry-point scripts/RECORD are not equal
    # to archive bytes.  Metadata/version is checked separately below.
    return name.endswith((".py", ".so", ".o", ".a"))


def _installed_payload(wheel, distribution, states):
    """Compare the actual current interpreter's code and native archive files."""
    dist = metadata.distribution(distribution)
    registry.require(
        dist.version == wheel["version"], "installed wheel version differs"
    )
    checked, roots = {}, set()
    with zipfile.ZipFile(wheel["path"]) as archive:
        names = archive.namelist()
        metadata_names = [n for n in names if n.endswith(".dist-info/METADATA")]
        registry.require(
            len(metadata_names) == 1, "wheel metadata missing or ambiguous"
        )
        metadata_name = metadata_names[0]
        metadata_raw = archive.read(metadata_name)
        wheel_metadata = BytesParser().parsebytes(metadata_raw)

        def normalize(name):
            return name.lower().replace("_", "-").replace(".", "-")

        registry.require(
            wheel_metadata["Version"] == wheel["version"]
            and normalize(wheel_metadata["Name"]) == normalize(distribution),
            "wheel metadata identity differs",
        )
        metadata_path = _path(dist.locate_file(metadata_name))
        registry.require(
            _hash(metadata_path, states) == registry.sha(metadata_raw),
            "installed wheel metadata differs",
        )
        checked[str(metadata_path)] = registry.sha(metadata_raw)
        registry.require(len(names) == len(set(names)), "wheel repeats a member")
        for name in names:
            parts = PurePosixPath(name).parts
            registry.require(
                parts and ".." not in parts and not name.startswith("/"),
                "wheel path is unsafe",
            )
            if parts[0].endswith(".dist-info") or name.endswith("/"):
                continue
            with archive.open(name) as stream:
                is_elf = stream.read(4) == b"\x7fELF"
            if not _payload(name) and not is_elf:
                continue
            relative = name
            if parts[0].endswith(".data"):
                registry.require(
                    len(parts) >= 3 and parts[1] in {"purelib", "platlib"},
                    "unsupported runtime wheel relocation",
                )
                relative = str(PurePosixPath(*parts[2:]))
            installed = _path(dist.locate_file(relative))
            with archive.open(name) as stream:
                digest = _stream_sha(stream)
            registry.require(
                _hash(installed, states) == digest, "installed wheel payload differs"
            )
            checked[str(installed)] = digest
            root = Path(dist.locate_file(PurePosixPath(relative).parts[0]))
            if root.is_dir():
                roots.add(root)
        registry.require(bool(checked), "wheel contains no checked runtime payload")
    # An unrecorded module can shadow a wheel-owned module at the same package.
    for root in roots:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            with path.open("rb") as stream:
                is_elf = stream.read(4) == b"\x7fELF"
            if _payload(path.name) or is_elf:
                registry.require(
                    str(path) in checked, "unrecorded installed runtime payload"
                )
    return checked


def audit_cell_inputs(config_path, recipe_path):
    """Expensive prelaunch audit, run in the actual pinned runtime interpreter.

    Returns observed bytes, not a producer claim.  It proves files and installed
    code at audit time, not model quality or which bytes an accelerator executed.
    The issuer must pin/trust the resulting manifest independently.  No NPU runs.
    """
    config_path, recipe_path = _path(config_path), _path(recipe_path)
    states = {}
    config_raw, recipe_raw = config_path.read_bytes(), recipe_path.read_bytes()
    registry.require(
        _hash(config_path, states) == registry.sha(config_raw)
        and _hash(recipe_path, states) == registry.sha(recipe_raw),
        "input documents changed during audit",
    )
    config, recipe = json.loads(config_raw), json.loads(recipe_raw)
    registry.require(
        Path(sys.executable) == Path(config["python"])
        and Path(sys.prefix) == Path(config["python"]).parent.parent,
        "input audit must run in actual runtime interpreter",
    )
    registry.require(
        str(recipe_path) == config["recipe"]
        and registry.sha(recipe_raw) == config["recipe_sha256"],
        "frozen recipe bytes differ",
    )
    registry.require(
        len(recipe["phases"]) == 1, "only one request-scoped cell supported"
    )
    phase = recipe["phases"][0]
    wheels = config["wheel_artifacts"]
    registry.require(
        set(wheels) == set(DISTRIBUTIONS), "exact seven wheel roles required"
    )
    installed = {}
    for role, wheel in wheels.items():
        registry.require(
            _hash(wheel["path"], states) == wheel["sha256"],
            "genuine wheel bytes differ",
        )
        installed[role] = _installed_payload(wheel, DISTRIBUTIONS[role], states)
    models = _model_inventory(config["model_files"], states)
    # This adapter intentionally supports the current single 7B cell only.
    registry.require(
        len(models) == 14, "single-cell model inventory must contain 14 files"
    )
    tokenization = phase["tokenization"]
    assets = _inventory(tokenization["assets"], states)
    registry.require(
        all(models.get(path) == digest for path, digest in assets.items()),
        "tokenizer assets are outside the exact model inventory",
    )
    binding = tokenization["runtime_binding"]
    host_sources = _inventory(binding["host_sources"], states)
    implementation = _inventory([binding["implementation_source"]], states)
    registry.require(
        all(installed["host"].get(p) == digest for p, digest in host_sources.items())
        and binding["host_version"] == wheels["host"]["version"]
        and binding["host_revision"] == wheels["host"]["revision"]
        and metadata.version("transformers") == binding["transformers_version"],
        "tokenizer runtime binding differs",
    )
    calibration = config["calibration_artifact"]
    registry.require(
        _hash(calibration["path"], states) == calibration["sha256"],
        "calibration bytes differ",
    )
    frozen_sources = {}
    for source in config["sources"]:
        path, digest = source["path"], source["sha256"]
        registry.require(
            path not in frozen_sources or frozen_sources[path] == digest,
            "frozen source inventory conflicts",
        )
        frozen_sources[path] = digest
    sources = _inventory(
        [{"path": p, "sha256": d} for p, d in frozen_sources.items()], states
    )
    result = {
        "schema": SCHEMA,
        "source_files": sources,
        "config": {"path": str(config_path), "sha256": registry.sha(config_raw)},
        "recipe": {"path": str(recipe_path), "sha256": registry.sha(recipe_raw)},
        "profile_id": registry.recipe_profile_id(recipe),
        "request_sha256": registry.sha(registry.canonical(phase["payload"])),
        "wheel_sha256": {r: w["sha256"] for r, w in wheels.items()},
        "wheel_revisions": {r: w["revision"] for r, w in wheels.items()},
        "installed_payload_sha256": registry.sha(registry.canonical(installed)),
        "model_sha256": registry.sha(registry.canonical(models)),
        "tokenizer_sha256": registry.sha(
            registry.canonical(
                {
                    "tokenization": tokenization,
                    "host_sources": host_sources,
                    "implementation": implementation,
                }
            )
        ),
        "calibration_sha256": calibration["sha256"],
        "file_state": states,
        "formal_result": False,
    }
    registry.require(
        all(_state(_path(path).stat()) == state for path, state in states.items()),
        "input files changed during audit",
    )
    # Reject a concurrent replacement of the binding documents during the audit.
    registry.require(
        config_path.read_bytes() == config_raw
        and recipe_path.read_bytes() == recipe_raw,
        "input documents changed during audit",
    )
    return result


def controller_cell_binding(issuer, permit, handoff, inputs, *, trusted_input_audits):
    """Build expected binding from issuer-authenticated original Manager exchange.

    The controller must place this *in its actual route state on commit*. Merely
    creating this object does not install a route or authenticate the controller.
    The independently obtained inputs manifest must already be trusted by issuer.
    """
    registry.require(
        registry.sha(registry.canonical(inputs)) in trusted_input_audits,
        "input audit is not independently trusted",
    )
    value = issuer._permit(permit)
    captured = issuer._open(handoff, registry.HANDOFF)
    registry.require(
        captured["permit_sha256"] == permit["sha256"], "handoff permit differs"
    )
    registry.require(
        inputs["schema"] == SCHEMA and inputs["formal_result"] is False,
        "input audit schema differs",
    )
    cell = value["cell"]
    for key in (
        "profile_id",
        "request_sha256",
        "model_sha256",
        "tokenizer_sha256",
        "calibration_sha256",
        "wheel_sha256",
    ):
        registry.require(inputs[key] == cell[key], "cell input audit differs")
    registry.require(
        inputs["recipe"]["sha256"] == cell["recipe_sha256"], "cell recipe differs"
    )
    fixed, revisions = value["fixed_identity"], inputs["wheel_revisions"]
    registry.require(
        revisions["manager"] == fixed["manager_commit"]
        and revisions["host"] == fixed["host_commit"]
        and revisions["ascend"] == fixed["accelerator_commit"]
        and set(fixed["plugin_commits"].values()) == {revisions["mod"]},
        "source admission and wheel revisions differ",
    )
    environment = captured["record"]["environment"]
    registry.require(
        cell["execution_plan_id"] == "plan:sha256:" + environment["VLLM_ECPA_PLAN_ID"],
        "Manager and execution Plan differ",
    )
    return {
        "schema": SNAPSHOT,
        "permit_sha256": permit["sha256"],
        "source_admission_sha256": value["source_admission_sha256"],
        "inputs_sha256": registry.sha(registry.canonical(inputs)),
        "execution_plan_id": cell["execution_plan_id"],
        "native_launch_id": environment["VLLM_ECPA_LAUNCH_ID"],
        "manager": captured["record"]["publisher"],
        "handoff_sha256": handoff["sha256"],
        "formal_result": False,
    }


class LiveRouteReader:
    """Read-only authenticated client for the real loopback routing authority.

    `authority` and source hashes come from the independent owner, not a quote.
    `expected_cell` comes from controller_cell_binding, not producer output.
    Source files/kernel peer/socket inode are checked on every fresh connection.
    Lease conversion is anchored once; repeated reads cannot renew the lease.
    """

    def __init__(
        self,
        *,
        socket_path,
        authority,
        authority_sources,
        authority_command_sha256,
        inputs,
        grant,
        expected_cell,
        scope,
    ):
        self.socket_path = _path(socket_path)
        self.authority = json.loads(registry.canonical(authority))
        self.authority_sources = json.loads(registry.canonical(authority_sources))
        self.authority_command_sha256 = authority_command_sha256
        self.inputs = json.loads(registry.canonical(inputs))
        registry.require(
            expected_cell.get("inputs_sha256")
            == registry.sha(registry.canonical(inputs)),
            "controller input audit digest differs",
        )
        self._inputs_current()
        self.grant = asdict(grant)
        self.expected_cell = json.loads(registry.canonical(expected_cell))
        self.scope = json.loads(registry.canonical(scope))
        registry.require(
            set(scope) == set(registry.SCOPE_KEYS), "route scope fields differ"
        )
        registry.require(
            expected_cell["schema"] == SNAPSHOT, "controller cell binding missing"
        )
        registry.require(
            expected_cell["execution_plan_id"] == scope["execution_plan_id"]
            and expected_cell["native_launch_id"] == scope["native_launch_id"],
            "controller cell scope differs",
        )
        registry.require(
            type(grant.expires_at) is int and type(grant.fencing_token) is int,
            "lease types differ",
        )
        registry.require(
            grant.holder == scope["controller_instance"]
            and type(scope["candidate_generation"]) is int
            and scope["candidate_generation"] > 0
            and type(scope["membership_epoch"]) is int
            and scope["membership_epoch"] >= 0,
            "controller lease/scope differs",
        )
        # Use the first monotonic sample and exact integer wall expiry, rounding
        # down relative to the authority's int(time.time()) rule. Never extend it.
        mono, wall = time.monotonic_ns(), time.time_ns()
        self.expiry = mono + grant.expires_at * 1_000_000_000 - wall
        registry.require(self.expiry > mono, "controller lease expired")
        self.socket_identity = self._identity()

    def _inputs_current(self):
        registry.require(
            self.inputs["schema"] == SCHEMA and self.inputs["file_state"],
            "actual input file state missing",
        )
        _check_file_states(self.inputs["file_state"])

    def _identity(self):
        registry._kernel(self.authority)
        registry.require(
            _hash(f"/proc/{self.authority['pid']}/cmdline")
            == self.authority_command_sha256,
            "controller command differs",
        )
        registry._files(self.authority_sources)
        p = self.socket_path
        registry.require(_path(p) == p, "controller endpoint is not canonical")
        parent, meta = p.parent.stat(), p.stat()
        registry.require(
            stat.S_ISSOCK(meta.st_mode)
            and meta.st_uid == os.geteuid()
            and parent.st_uid == os.geteuid()
            and not stat.S_IMODE(parent.st_mode) & 0o077,
            "controller endpoint is not private",
        )
        return (meta.st_dev, meta.st_ino, meta.st_uid)

    def _call(self, operation, **fields):
        registry.require(
            self._identity() == self.socket_identity, "controller socket replaced"
        )
        payload = registry.canonical({"operation": operation, **fields}) + b"\n"
        registry.require(len(payload) <= MAX_MESSAGE, "controller request oversized")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(str(self.socket_path))
            pid, uid, _ = struct.unpack(
                "3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            registry.require(
                pid == self.authority["pid"] and uid == os.geteuid(),
                "controller kernel peer differs",
            )
            registry.require(
                self._identity() == self.socket_identity, "controller socket replaced"
            )
            client.sendall(payload)
            response = bytearray()
            while not response.endswith(b"\n"):
                chunk = client.recv(4096)
                registry.require(
                    chunk and len(response) + len(chunk) <= MAX_MESSAGE,
                    "controller response incomplete or oversized",
                )
                response.extend(chunk)
            value = json.loads(response)
        registry.require(
            self._identity() == self.socket_identity, "controller socket replaced"
        )
        registry.require(
            isinstance(value, dict) and value.get("ok") is True,
            "controller rejected query",
        )
        return value

    def read(self):
        """Return registry's seven fields from fresh actual route/lease queries."""
        self._inputs_current()
        before = self._call("query")["route"]
        valid = self._call("lease_valid", grant=self.grant, now=int(time.time()))
        after = self._call("query")["route"]
        self._inputs_current()
        registry.require(before == after, "controller route changed during query")
        registry.require(
            valid.get("valid") is True and time.monotonic_ns() < self.expiry,
            "controller lease changed or expired",
        )
        registry.require(
            set(after) == {"generation", "fence", "snapshot"},
            "controller route fields differ",
        )
        registry.require(
            type(after["generation"]) is int
            and after["generation"] > 0
            and isinstance(after["fence"], str)
            and after["fence"].startswith("gate-"),
            "candidate route is closed or restored predecessor",
        )
        snapshot = after["snapshot"]
        registry.require(
            isinstance(snapshot, dict), "controller route snapshot missing"
        )
        registry.require(
            snapshot.get("semantic_cell") == self.expected_cell,
            "actual controller route lacks exact semantic cell binding",
        )
        actual = {
            key: snapshot.get(key)
            for key in (
                "membership_epoch",
                "controller_instance",
                "execution_plan_id",
                "native_launch_id",
            )
        }
        registry.require(
            actual == {key: self.scope[key] for key in actual}
            and after["generation"] == self.scope["candidate_generation"]
            and type(actual["membership_epoch"]) is int
            and actual["membership_epoch"] >= 0,
            "actual controller route scope differs",
        )
        return {
            "generation": after["generation"],
            "fence": after["fence"],
            **actual,
            "lease_expires_monotonic_ns": self.expiry,
        }
