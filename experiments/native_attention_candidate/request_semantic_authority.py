"""Plan-bound one-use request completions; prospective and strictly nonformal.

The new producer domain records its original first full-verification completion
clock. Independent owner verification never restarts that clock.
"""

from __future__ import annotations

import ast
import configparser
import importlib.metadata
import json
import os
import stat
import sys
import threading
import time
import zipfile
from pathlib import Path

from experiments.formal_campaign import source_provenance
from vllm_hust_ext import (
    contract_compiler,
    ecpa_model,
    host_evidence,
    plan_artifact,
    runtime_evidence,
    semantic_obligations,
    semantic_runtime_binding,
)
from vllm_hust_ext.plan_artifact import parse_plan_artifact
from vllm_hust_ext.runtime_phase_handoff import (
    accept_native_binding,
    manager_source_digests,
)
from vllm_hust_ext.semantic_obligations import EVENT, SCOPE

from . import live_route_reader as routes
from . import request_collector_client, request_drain_collector, request_live_producer
from . import request_drain_consumer as consumer
from . import request_phasebook as books
from . import semantic_producer_registry as registry
from .request_prefix_ticket import (
    MAX_PREFIX_BYTES,
    authenticated_completion_value,
    read_regular,
)

PERMIT = "ecpa-request-semantic-permit/v1"
HANDOFF = "ecpa-request-semantic-manager-handoff/v1"
DEPLOYMENT = "ecpa-request-semantic-deployment/v1"
TICKET = "ecpa-request-semantic-once-completion/v1"
PREPARED_GRANT = "ecpa-request-semantic-prepared-grant/v1"
LIFETIME_NS = 30_000_000_000
canonical, sha, require = registry.canonical, registry.sha, registry.require


def reference(path):
    path = Path(path).resolve()
    return {"path": str(path), "sha256": sha(read_regular(path))}


def route_fields(launch, native_launch_id):
    return {
        "generation": launch["candidate_generation"],
        "membership_epoch": launch["membership_epoch"],
        "controller_instance": launch["controller_instance"],
        "execution_plan_id": launch["execution_plan_id"],
        "native_launch_id": native_launch_id,
    }


def source_expiry(seal_ns, deadline_ns, route_expiry_ns):
    require(
        all(type(n) is int and n > 0 for n in (seal_ns, deadline_ns, route_expiry_ns)),
        "original source/deadline/lease clock invalid",
    )
    return min(seal_ns + LIFETIME_NS, deadline_ns, route_expiry_ns)


def snapshot_files(output):
    output = Path(output)
    prefix = output / "snapshot/native.jsonl"
    return {
        str(path): sha(
            read_regular(path, MAX_PREFIX_BYTES)
            if path == prefix
            else read_regular(path)
        )
        for path in output.rglob("*")
        if path.is_file()
    }


def check_completion_files(body):
    prefix = body["native_prefix_path"]
    require(prefix in body["files"], "bound native global prefix absent")
    for path, expected in body["files"].items():
        require(
            sha(
                read_regular(path, MAX_PREFIX_BYTES)
                if path == prefix
                else read_regular(path)
            )
            == expected,
            "verified completion raw input changed",
        )


class VerifiedRequestCompletion:
    """Opaque issuer-owned verification result; JSON cannot instantiate validity."""

    __slots__ = ()


def protocol_sources():
    from experiments.exposure_gate import loopback_traffic

    modules = (
        loopback_traffic,
        host_evidence,
        runtime_evidence,
        registry,
        routes,
        semantic_runtime_binding,
        semantic_obligations,
        contract_compiler,
        ecpa_model,
        plan_artifact,
        source_provenance,
        consumer,
    )
    paths = [Path(module.__file__).resolve() for module in modules]
    paths += [
        Path(__file__).resolve(),
        Path(__file__).with_name("request_semantic_controller.py").resolve(),
    ]
    return {str(path): sha(read_regular(path)) for path in paths}


class _AuditCut:
    """One stack-local validation cut; no result survives an IO boundary."""

    def __init__(self, audits):
        require(audits, "independent audit union missing")
        self.audits = {sha(canonical(audit)): audit for audit in audits.values()}
        self.states, self.sources = {}, {}
        for audit in audits.values():
            require(
                audit.get("source_files") and audit.get("file_state"),
                "independent audit source closure missing",
            )
            for path, state in audit["file_state"].items():
                require(
                    path not in self.states or self.states[path] == state,
                    "trusted audit file_states conflict",
                )
                self.states[path] = state
            for path, digest in audit["source_files"].items():
                require(
                    path in audit["file_state"]
                    and (path not in self.sources or self.sources[path] == digest),
                    "trusted audit source closure conflict",
                )
                self.sources[path] = digest

    def membership(self, audit, sources):
        require(
            self.audits.get(sha(canonical(audit))) == audit,
            "audit does not belong to this transaction cut",
        )
        require(
            all(
                audit["source_files"].get(path) == digest
                and path in audit["file_state"]
                for path, digest in sources.items()
            ),
            "independent input audit does not cover exact source closure",
        )

    def check(self):
        # Always fresh, even when called twice on the same stack-local object.
        routes._check_file_states(self.states)
        registry._files(self.sources)


def require_audited_sources(audit, sources, *, _cut=None):
    if _cut is not None:
        require(type(_cut) is _AuditCut, "internal audit cut required")
        _cut.membership(audit, sources)
        return
    cut = _AuditCut({"audit": audit})
    cut.membership(audit, sources)
    cut.check()


def audited_reference(ref, audit, *, _cut=None):
    require(set(ref) == {"path", "sha256"}, "exact audited reference required")
    require_audited_sources(audit, {ref["path"]: ref["sha256"]}, _cut=_cut)
    require(reference(ref["path"]) == ref, "independently audited reference changed")
    return read_regular(ref["path"])


def observe_manager_invocation(manager, invocation_reference, audit, *, _cut=None):
    """Observe installed console/core execution, not a caller's desired argv hash.

    Observation alone grants nothing: its independently registered digest and
    original input audit must both be trusted by the issuer.
    """
    registry._kernel(manager)
    intent = json.loads(audited_reference(invocation_reference, audit, _cut=_cut))
    require(
        set(intent)
        == {
            "schema",
            "semantic_launch_spec",
            "phase_binding_socket",
            "host_command",
            "request_control_socket",
        }
        and intent["schema"] == "ecpa-request-manager-invocation-intent/v1"
        and isinstance(intent["host_command"], list)
        and intent["host_command"]
        and all(isinstance(s, str) and s for s in intent["host_command"]),
        "audited Manager invocation intent differs",
    )
    config_ref = audit["config"]
    require(
        reference(config_ref["path"]) == config_ref,
        "original input config bytes changed",
    )
    config = json.loads(read_regular(config_ref["path"]))
    python = Path(config["python"])
    require(
        python.is_absolute() and python.is_file(),
        "audited runtime interpreter path differs",
    )
    script = python.parent / "vllm-hust-ext"
    expected = [
        str(python),
        str(script),
        "run",
        "--semantic-launch-spec",
        intent["semantic_launch_spec"]["path"],
        "--phase-binding-socket",
        intent["phase_binding_socket"],
        "--",
        *intent["host_command"],
    ]
    actual = [
        part.decode()
        for part in Path(f"/proc/{manager['pid']}/cmdline").read_bytes().split(b"\0")
        if part
    ]
    require(
        actual == expected
        and "-c" not in actual[:2]
        and Path(f"/proc/{manager['pid']}/exe").resolve() == python.resolve(),
        "actual Manager invocation differs from audited installed console/core",
    )
    fields = Path(f"/proc/{manager['pid']}/stat").read_text().rsplit(")", 1)[1].split()
    require(
        int(fields[1]) == os.getpid(),
        "Manager is not the independently owned direct child",
    )
    require(
        Path(sys.executable) == python,
        "Manager audit must use the actual runtime interpreter",
    )
    wheel = config["wheel_artifacts"]["manager"]
    require(
        sha(read_regular(wheel["path"]))
        == wheel["sha256"]
        == audit["wheel_sha256"]["manager"],
        "trusted actual Manager wheel differs",
    )
    payload = routes._installed_payload(wheel, routes.DISTRIBUTIONS["manager"], {})
    require_audited_sources(audit, payload, _cut=_cut)
    dist = importlib.metadata.distribution(routes.DISTRIBUTIONS["manager"])
    with zipfile.ZipFile(wheel["path"]) as archive:
        entries = [
            name
            for name in archive.namelist()
            if name.endswith(".dist-info/entry_points.txt")
        ]
        require(len(entries) == 1, "actual Manager wheel console metadata ambiguous")
        raw_entries = archive.read(entries[0])
    require(
        dist.read_text("entry_points.txt").encode() == raw_entries,
        "installed console metadata differs from actual wheel",
    )
    entry = configparser.ConfigParser(interpolation=None)
    entry.read_string(raw_entries.decode())
    require(
        entry["console_scripts"]["vllm-hust-ext"].strip() == "vllm_hust_ext.cli:main",
        "actual wheel does not expose the semantic Manager entrypoint",
    )
    template = (
        "import sys\nfrom vllm_hust_ext.cli import main\n"
        "if __name__ == '__main__':\n"
        "    sys.argv[0] = sys.argv[0].removesuffix('.exe')\n"
        "    sys.exit(main())\n"
    )
    require_audited_sources(audit, {str(script): sha(read_regular(script))}, _cut=_cut)
    require(
        ast.dump(ast.parse(read_regular(script))) == ast.dump(ast.parse(template)),
        "generated installed Manager console wrapper differs",
    )
    audited_reference(intent["semantic_launch_spec"], audit, _cut=_cut)
    registry._kernel(manager)
    return {
        "schema": "ecpa-observed-installed-manager-invocation/v1",
        "manager": manager,
        "observer": registry.process_identity(os.getpid()),
        "argv": actual,
        "argv_sha256": sha(Path(f"/proc/{manager['pid']}/cmdline").read_bytes()),
        "invocation_reference": invocation_reference,
        "input_audit_sha256": sha(canonical(audit)),
        "console": reference(script),
        "manager_wheel_sha256": wheel["sha256"],
        "installed_core_sha256": sha(canonical(payload)),
        "observer_source": reference(__file__),
        "formal_result": False,
    }


class CompletionLedger:
    """Burn a verified completion once; this ledger issues no qualification."""

    def __init__(self):
        self.lock = threading.RLock()
        self.pending = {}
        self.spent = set()
        self.next_phase = 0

    def reserve(self, key, identity, phase_index):
        with self.lock:
            require(
                phase_index == self.next_phase and key not in self.spent,
                "completion phase/order/nonce already consumed",
            )
            previous = self.pending.setdefault(key, identity)
            require(
                previous == identity, "completion identity or original expiry changed"
            )

    def consume(self, key, identity, phase_index, expires_ns, persist):
        with self.lock:
            require(
                phase_index == self.next_phase
                and key not in self.spent
                and self.pending.get(key) == identity
                and time.monotonic_ns() < expires_ns,
                "completion absent, reused, reordered or expired",
            )
            # A failed durable write burns the completion too; never roll back.
            self.spent.add(key)
            del self.pending[key]
            persist()
            require(
                time.monotonic_ns() < expires_ns,
                "completion expired during consume fsync",
            )
            self.next_phase += 1


class RequestSemanticAuthority(registry.CellIssuer):
    """Independent key/source trust plus actual Plan, handoff and request checks."""

    def __init__(
        self,
        key,
        trusted_source_observations,
        *,
        bundles,
        trusted_input_audits,
        trusted_manager_observations=(),
        trusted_route_observations=(),
    ):
        super().__init__(key, trusted_source_observations)
        require(trusted_input_audits, "independent actual input audit trust missing")
        self.bundles = tuple(bundles)
        self.trusted_inputs = frozenset(trusted_input_audits)
        self.trusted_managers = frozenset(trusted_manager_observations)
        self.trusted_routes = frozenset(trusted_route_observations)
        self.ledgers = {}
        self.verified_capabilities = {}
        self.revoked_deployments = set()
        self.lock = threading.RLock()

    def issue_request_permit(
        self,
        *,
        launch_spec_path,
        phasebook,
        fixed,
        source_policy,
        source_observation,
        input_audits,
        native_sources,
        manager_invocation=None,
    ):
        books.validate(phasebook)
        launch = semantic_runtime_binding.validate_semantic_launch_spec(
            launch_spec_path, self.bundles
        )
        source_provenance.validate_observation(source_observation, source_policy, fixed)
        require(
            source_provenance.digest(canonical(source_observation)) in self._trusted,
            "source observation not trusted",
        )
        plan = parse_plan_artifact(read_regular(launch["plan"]["path"]))
        compiled = json.loads(read_regular(launch["binding"]["path"]))
        selected = [b for b in compiled["bindings"] if b["scope"] == SCOPE]
        require(len(selected) == 1, "one actual compiled semantic provider required")
        binding = selected[0]
        obligations = [
            o for o in plan.obligations if o.obligation_id == binding["obligation_id"]
        ]
        require(
            len(plan.plugins) == 1
            and len(obligations) == 1
            and obligations[0].event == EVENT
            and obligations[0].role == "worker"
            and obligations[0].required_ordinals == (0, 1)
            and binding["plugin_id"] in {p.id for p in plan.plugins},
            "compiled Plan lacks exact provider/all-TP2 semantic obligation",
        )
        phases = phasebook["recipe"]["phases"]
        require(
            set(input_audits) == {p["phase_id"] for p in phases},
            "all phases need independent input audits",
        )
        for phase in phases:
            audit = input_audits[phase["phase_id"]]
            require(
                sha(canonical(audit)) in self.trusted_inputs
                and audit["schema"] == routes.SCHEMA
                and audit["formal_result"] is False
                and audit["request_sha256"] == sha(canonical(phase["payload"]))
                and set(audit["wheel_sha256"])
                == {"manager", "host", "ascend", "mod", "torch", "torch_npu", "triton"}
                and audit["wheel_revisions"]["manager"] == fixed["manager_commit"]
                and audit["wheel_revisions"]["host"] == fixed["host_commit"]
                and audit["wheel_revisions"]["ascend"] == fixed["accelerator_commit"]
                and set(fixed["plugin_commits"].values())
                == {audit["wheel_revisions"]["mod"]},
                "actual independently trusted per-request inputs differ",
            )
            routes._check_file_states(audit["file_state"])
        registry._files(native_sources)
        protocol = protocol_sources()
        controller = (
            Path(__file__).with_name("request_semantic_controller.py").resolve()
        )
        protocol[str(controller)] = sha(controller.read_bytes())
        sources = {r["path"]: r["sha256"] for r in phasebook["recipe"]["sources"]}
        for path, digest in protocol.items():
            require(
                path not in sources or sources[path] == digest,
                "protocol source conflicts with book",
            )
            sources[path] = digest
        registry._files(sources)
        plan_refs = [
            reference(launch_spec_path),
            launch["base_plan"],
            launch["plan"],
            launch["binding"],
            launch["plugin_map"],
            *launch["contracts"],
        ]
        required = {
            **sources,
            **native_sources,
            **{ref["path"]: ref["sha256"] for ref in plan_refs},
        }
        if manager_invocation is not None:
            required[manager_invocation["path"]] = manager_invocation["sha256"]
        for phase in phases:
            audit = input_audits[phase["phase_id"]]
            require_audited_sources(audit, required)
            self._check_cell_inputs(audit, phase)
        return self._seal(
            {
                "schema": PERMIT,
                "launch_spec": reference(launch_spec_path),
                "launch": launch,
                "compiled_binding": binding,
                "event": EVENT,
                "scope": SCOPE,
                "phasebook": phasebook,
                "phasebook_sha256": sha(canonical(phasebook)),
                "fixed": fixed,
                "source_policy": source_policy,
                "source_observation": source_observation,
                "input_audits": input_audits,
                "native_sources": native_sources,
                "sources": sources,
                "manager_handoff_sources": manager_source_digests(),
                "manager_invocation": manager_invocation,
                "required_audit_sources": required,
                "route_reader": {
                    "path": str(controller),
                    "sha256": protocol[str(controller)],
                    "callable": "PreparedRequestRouteReader.read",
                },
                "formal_result": False,
            }
        )

    def _check_cell_inputs(self, audit, phase):
        cfg = json.loads(read_regular(audit["config"]["path"]))
        require(
            reference(audit["config"]["path"]) == audit["config"],
            "trusted input config changed",
        )
        models = {row["path"]: row["sha256"] for row in cfg["model_files"]}
        tokenization = phase["tokenization"]
        binding = tokenization["runtime_binding"]
        expected_tokenizer = {
            "tokenization": tokenization,
            "host_sources": {
                row["path"]: row["sha256"] for row in binding["host_sources"]
            },
            "implementation": {
                binding["implementation_source"]["path"]: binding[
                    "implementation_source"
                ]["sha256"]
            },
        }
        require(
            audit["model_sha256"] == sha(canonical(models))
            and audit["tokenizer_sha256"] == sha(canonical(expected_tokenizer))
            and audit["calibration_sha256"] == cfg["calibration_artifact"]["sha256"]
            and all(
                models.get(row["path"]) == row["sha256"]
                for row in tokenization["assets"]
            )
            and all(
                path in audit["file_state"]
                for path in [*models, cfg["calibration_artifact"]["path"]]
            )
            and audit["wheel_sha256"]
            == {k: w["sha256"] for k, w in cfg["wheel_artifacts"].items()},
            "trusted model/tokenizer/calibration/wheels differ from exact book phase",
        )

    def permit_current(self, permit):
        return self._permit_current_with_cut(permit)[0]

    def _permit_current_with_cut(self, permit):
        value = self._open(permit, PERMIT)
        for audit in value["input_audits"].values():
            require(sha(canonical(audit)) in self.trusted_inputs, "input trust absent")
        cut = _AuditCut(value["input_audits"])
        cut.check()
        require(
            source_provenance.digest(canonical(value["source_observation"]))
            in self._trusted,
            "source trust absent",
        )
        source_provenance.validate_observation(
            value["source_observation"], value["source_policy"], value["fixed"]
        )
        require(
            reference(value["launch_spec"]["path"]) == value["launch_spec"],
            "semantic launch bytes changed",
        )
        require(
            semantic_runtime_binding.validate_semantic_launch_spec(
                value["launch_spec"]["path"], self.bundles
            )
            == value["launch"],
            "actual installed semantic launch changed",
        )
        books.validate(value["phasebook"])
        registry._files(value["sources"])
        registry._files(value["native_sources"])
        require(
            manager_source_digests() == value["manager_handoff_sources"],
            "Manager source changed",
        )
        for audit in value["input_audits"].values():
            require(sha(canonical(audit)) in self.trusted_inputs, "input trust absent")
            require_audited_sources(audit, value["required_audit_sources"], _cut=cut)
        for phase in value["phasebook"]["recipe"]["phases"]:
            self._check_cell_inputs(value["input_audits"][phase["phase_id"]], phase)
        cut.check()
        return value, cut

    def _manager_current(self, value, observation, *, _cut=None):
        require(
            isinstance(observation, dict)
            and sha(canonical(observation)) in self.trusted_managers,
            "actual installed Manager observation is not independently trusted",
        )
        audits = [
            audit
            for audit in value["input_audits"].values()
            if sha(canonical(audit)) == observation["input_audit_sha256"]
        ]
        require(
            len(audits) == 1
            and observation["invocation_reference"] == value["manager_invocation"],
            "Manager invocation belongs to another trusted source/input root",
        )
        intent = json.loads(
            audited_reference(value["manager_invocation"], audits[0], _cut=_cut)
        )
        require(
            intent["semantic_launch_spec"] == value["launch_spec"],
            "actual installed Manager invocation uses another compiled launch spec",
        )
        require(
            observe_manager_invocation(
                observation["manager"],
                value["manager_invocation"],
                audits[0],
                _cut=_cut,
            )
            == observation,
            "actual installed Manager invocation/source changed",
        )

    def accept_request_handoff(
        self,
        permit,
        *,
        listener,
        path,
        manager,
        launched_wall_ns,
        raw_record_path,
        manager_observation=None,
    ):
        value = self.permit_current(permit)
        self._manager_current(value, manager_observation)
        require(
            manager == manager_observation["manager"],
            "Manager handshake kernel differs from independent invocation root",
        )
        raw_path = Path(raw_record_path)
        require(
            raw_path.is_absolute()
            and raw_path.resolve() == raw_path
            and stat.S_IMODE(raw_path.parent.stat().st_mode) == 0o700
            and raw_path.parent.stat().st_uid == os.geteuid(),
            "private canonical original Manager wire path required",
        )
        fd = os.open(
            raw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        os.close(fd)
        record = accept_native_binding(
            listener,
            Path(path),
            manager,
            launched_wall_ns,
            value["manager_handoff_sources"],
            raw_path,
        )
        require(
            sha(raw_path.read_bytes()) == record["binding_sha256"]
            and record["environment"]["VLLM_ECPA_PLAN_ID"]
            == value["launch"]["native_plan_id"],
            "authentic Manager handoff belongs to another actual Plan",
        )
        evidence = Path(record["environment"]["VLLM_HUST_EXT_EVIDENCE_PATH"])
        meta = evidence.lstat()
        require(
            stat.S_ISREG(meta.st_mode)
            and stat.S_IMODE(meta.st_mode) == 0o600
            and meta.st_uid == os.geteuid(),
            "Manager original Host evidence must be private regular file",
        )
        return self._seal(
            {
                "schema": HANDOFF,
                "host_evidence": {
                    "path": str(evidence),
                    "identity": [meta.st_dev, meta.st_ino, meta.st_uid],
                },
                "permit_sha256": permit["sha256"],
                "record": record,
                "raw": reference(raw_path),
                "manager_observation": manager_observation,
                "formal_result": False,
            }
        )

    def issue_prepared_route_grant(self, permit, handoff, observation):
        """Seal a root-admitted real external grant; mint no expiry or random fence."""
        from . import request_semantic_controller as control

        value = self.permit_current(permit)
        captured = self._open(handoff, HANDOFF)
        require(
            captured["permit_sha256"] == permit["sha256"],
            "prepared handoff permit differs",
        )
        self._manager_current(value, captured["manager_observation"])
        require(
            sha(canonical(observation)) in self.trusted_routes
            and observation["schema"] == "ecpa-observed-independent-prepared-grant/v1"
            and observation["observer_source"] == reference(control.__file__)
            and observation["observer"] == registry.process_identity(os.getpid()),
            "real external grant observation is not independently admitted",
        )
        control.route_grant_current(observation, value["input_audits"])
        launch = value["launch"]
        require(
            observation["grant"]["holder"] == launch["controller_instance"]
            and observation["candidate_generation"] == launch["candidate_generation"],
            "original grant differs from compiled controller/generation",
        )
        audit = next(
            a
            for a in value["input_audits"].values()
            if sha(canonical(a))
            == captured["manager_observation"]["input_audit_sha256"]
        )
        intent = json.loads(audited_reference(value["manager_invocation"], audit))
        native_launch = captured["record"]["environment"]["VLLM_ECPA_LAUNCH_ID"]
        fence_material = {
            "grant": observation["grant"],
            "authority": observation["descriptor"]["kernel"],
            "predecessor": observation["original_route"],
            "launch": launch,
            "phasebook_sha256": sha(canonical(value["phasebook"])),
        }
        route = {
            **route_fields(launch, native_launch),
            "fence": "prepared-grant:sha256:" + sha(canonical(fence_material)),
            "lease_expires_monotonic_ns": observation["original_monotonic_expiry_ns"],
        }
        return self._seal(
            {
                "schema": PREPARED_GRANT,
                "permit_sha256": permit["sha256"],
                "handoff_sha256": handoff["sha256"],
                "observation": observation,
                "controller": registry.process_identity(os.getpid()),
                "command_sha256": sha(
                    Path(f"/proc/{os.getpid()}/cmdline").read_bytes()
                ),
                "socket_path": intent["request_control_socket"],
                "sources": value["sources"],
                "route": route,
                "formal_result": False,
            }
        )

    def prepared_grant_current(self, permit, grant):
        from . import request_semantic_controller as control

        value, cut = self._permit_current_with_cut(permit)
        body = self._prepared_grant_from_validated_permit(
            permit["sha256"], value, grant, cut
        )
        expiry = control.route_grant_current(
            body["observation"], value["input_audits"], _cut=cut
        )
        require(
            body["route"]["lease_expires_monotonic_ns"] == expiry,
            "original grant expiry was renewed",
        )
        cut.check()
        return body

    def _prepared_grant_from_validated_permit(self, permit_sha256, value, grant, cut):
        require(
            type(cut) is _AuditCut
            and cut.audits
            == {sha(canonical(a)): a for a in value["input_audits"].values()},
            "validated permit audit cut differs",
        )
        body = self._open(grant, PREPARED_GRANT)
        require(
            body["permit_sha256"] == permit_sha256
            and sha(canonical(body["observation"])) in self.trusted_routes,
            "prepared route root differs from independent trust",
        )
        registry._kernel(body["controller"])
        require(
            sha(Path(f"/proc/{body['controller']['pid']}/cmdline").read_bytes())
            == body["command_sha256"],
            "prepared controller invocation changed",
        )
        registry._files(body["sources"])
        require(
            time.monotonic_ns() < body["route"]["lease_expires_monotonic_ns"],
            "original prepared grant expired",
        )
        return body

    def _host_roles_current(self, captured, peers, launch, enrollment):
        require(
            reference(enrollment["spec"]["path"]) == enrollment["spec"],
            "native enrollment spec changed before Host identity join",
        )
        spec = json.loads(read_regular(enrollment["spec"]["path"]))
        senders = enrollment["source_peers"]
        require(
            spec["senders"] == senders,
            "enrollment senders differ from original native spec",
        )
        native_processes = {
            f"{row['process']['role']}/{row['process']['ordinal']}": row["process"]
            for row in senders
        }
        require(
            len(native_processes) == len(senders)
            and set(native_processes) == set(peers),
            "native sender role membership differs from actual enrolled kernels",
        )
        for role, process in native_processes.items():
            require(
                {key: process[key] for key in registry.KERNEL} == peers[role],
                "native sender kernel differs from actual enrolled peer",
            )
        descriptor = captured["host_evidence"]
        path = Path(descriptor["path"])
        before = path.lstat()
        require(
            [before.st_dev, before.st_ino, before.st_uid] == descriptor["identity"]
            and stat.S_ISREG(before.st_mode)
            and stat.S_IMODE(before.st_mode) == 0o600,
            "authentic Manager Host observation endpoint changed",
        )
        raw = read_regular(path)
        require(
            not raw or raw.endswith(b"\n"),
            "Host observer has incomplete original record",
        )
        events = [host_evidence.parse_host_event(line) for line in raw.splitlines()]
        native_launch = captured["record"]["environment"]["VLLM_ECPA_LAUNCH_ID"]
        required_entries = {
            (e.group, e.name, e.value)
            for bundle in self.bundles
            for e in bundle.entry_points
            if (e.group, e.name)
            in {(r.group, r.name) for r in bundle.manifest.activation.entry_points}
        }
        require(required_entries, "installed bundle has no actual loader entrypoints")
        seen = {}
        for event in events:
            require(
                event["plan_id"] == launch["native_plan_id"]
                and event["launch_id"] == native_launch,
                "original Host observer record belongs to another Plan/launch",
            )
            process = event["process"]
            role = f"{process['role']}/{process['ordinal']}"
            if (
                role not in peers
                or event["event"] != "invoked"
                or event["observation_kind"] != "loader_lifecycle"
            ):
                continue
            kernel = peers[role]
            require(
                process.get("assignment_source") == "host"
                and process["pid"] == kernel["pid"]
                and process["start_identity"]
                == f"pid:{kernel['pid']}:start_ticks:{kernel['start_ticks']}",
                "Manager Host role receipt differs from actual enrolled kernel",
            )
            identity_fields = (
                "host",
                "role",
                "ordinal",
                "pid",
                "start_identity",
                "process_epoch",
                "assignment_source",
            )
            require(
                all(
                    process.get(key) == native_processes[role].get(key)
                    for key in identity_fields
                ),
                "original Host receipt identity/epoch differs from native sender spec",
            )
            entry = event["entry_point"]
            if (entry["group"], entry["name"], entry["value"]) in required_entries:
                identity = {**kernel, **{key: process[key] for key in identity_fields}}
                require(
                    role not in seen or seen[role] == identity,
                    "Host observer role epoch changed",
                )
                seen[role] = identity
        require(
            set(seen) == set(peers),
            "independent original Manager Host receipts do not cover API/TP2 roles",
        )
        after = path.lstat()
        require(
            [after.st_dev, after.st_ino, after.st_uid] == descriptor["identity"],
            "Host observation inode changed during verification",
        )
        return {
            "roles": seen,
            "prefix_bytes": len(raw),
            "prefix_sha256": sha(raw),
            "observer": registry.process_identity(os.getpid()),
            "observer_source": reference(__file__),
        }

    def bind_request_deployment(
        self,
        permit,
        *,
        handoff,
        prepared_grant,
        enrollment,
        descriptor,
        producer,
        producer_ready,
        producer_registration,
        route_reader,
    ):
        value = self.permit_current(permit)
        captured = self._open(handoff, HANDOFF)
        require(
            captured["permit_sha256"] == permit["sha256"],
            "Manager handoff permit differs",
        )
        root = self.prepared_grant_current(permit, prepared_grant)
        require(
            root["handoff_sha256"] == handoff["sha256"]
            and getattr(route_reader.__self__, "prepared_grant", None)
            == prepared_grant,
            "route reader lacks exact issuer-sealed external grant root",
        )
        registry._callback(route_reader, value["route_reader"])
        route = route_reader()
        require(
            route == root["route"],
            "actual route differs from independently granted prepared scope",
        )
        peers = {
            f"{s['process']['role']}/{s['process']['ordinal']}": {
                k: s["process"][k] for k in registry.KERNEL
            }
            for s in enrollment["source_peers"]
        }
        require(
            set(peers) == {"api-server/0", "worker/0", "worker/1"},
            "actual API/TP2 membership incomplete",
        )
        body = {
            "schema": DEPLOYMENT,
            "permit_sha256": permit["sha256"],
            "handoff": handoff,
            "prepared_grant": prepared_grant,
            "enrollment": enrollment,
            "descriptor": descriptor,
            "manager": captured["record"]["publisher"],
            "peers": peers,
            "producer": {k: producer[k] for k in registry.KERNEL},
            "producer_ready": producer_ready,
            "producer_registration": producer_registration,
            "route": route,
            "formal_result": False,
        }
        body["host_role_observation"] = self._host_roles_current(
            captured, peers, value["launch"], enrollment
        )
        self._live_request(value, body, route_reader)
        sealed = self._seal(body)
        with self.lock:
            require(sealed["sha256"] not in self.ledgers, "deployment already bound")
            self.ledgers[sealed["sha256"]] = CompletionLedger()
        return sealed

    def _live_request(self, permit, deployment, route_reader, *, _cut=None):
        registry._callback(route_reader, permit["route_reader"])
        if _cut is None:
            route = route_reader()
        else:
            route = route_reader.__self__._read_validated_permit(
                self, permit, deployment["prepared_grant"], _cut
            )
        launch = permit["launch"]
        captured = self._open(deployment["handoff"], HANDOFF)
        require(
            reference(captured["raw"]["path"]) == captured["raw"],
            "original Manager wire changed",
        )
        if _cut is not None:
            _cut.check()
        self._manager_current(permit, captured["manager_observation"], _cut=_cut)
        if _cut is not None:
            _cut.check()
        # Re-open original issuer envelope; caller-selected reader roots fail.
        grant = self._open(deployment["prepared_grant"], PREPARED_GRANT)
        require(
            grant["handoff_sha256"] == deployment["handoff"]["sha256"]
            and grant["route"] == route
            and getattr(route_reader.__self__, "prepared_grant", None)
            == deployment["prepared_grant"],
            "deployment route/grant root changed",
        )
        from . import request_semantic_controller as control

        control.route_grant_current(
            grant["observation"], permit["input_audits"], _cut=_cut
        )
        roles = self._host_roles_current(
            captured, deployment["peers"], launch, deployment["enrollment"]
        )
        original = deployment["host_role_observation"]
        require(
            roles["roles"] == original["roles"]
            and original["observer_source"] == reference(__file__)
            and sha(
                read_regular(captured["host_evidence"]["path"])[
                    : original["prefix_bytes"]
                ]
            )
            == original["prefix_sha256"],
            "independent Manager Host observer role/prefix receipt changed",
        )
        native_launch = captured["record"]["environment"]["VLLM_ECPA_LAUNCH_ID"]
        expected = route_fields(launch, native_launch)
        require(
            set(route) == {*expected, "fence", "lease_expires_monotonic_ns"}
            and route == deployment["route"]
            and all(route[k] == v for k, v in expected.items())
            and isinstance(route["fence"], str)
            and route["fence"]
            and type(route["lease_expires_monotonic_ns"]) is int
            and time.monotonic_ns() < route["lease_expires_monotonic_ns"],
            "actual controller/generation/membership/fence/original lease changed",
        )
        kernels = [
            deployment["manager"],
            deployment["producer"],
            {k: deployment["descriptor"]["collector"][k] for k in registry.KERNEL},
            *deployment["peers"].values(),
        ]
        require(
            len({p["pid"] for p in kernels}) == 6,
            "Manager/API/W0/W1/producer/collector must be six kernels",
        )
        for kernel in kernels:
            registry._kernel(kernel)
        enrollment = deployment["enrollment"]
        books.enrollment_current(permit["phasebook"], enrollment)
        require(
            enrollment["native_plan_id"] == launch["native_plan_id"]
            and enrollment["native_launch_id"] == native_launch,
            "source enrollment Plan/launch differs",
        )
        require(
            books._descendant(enrollment["host"]["pid"], deployment["manager"]["pid"]),
            "actual Host is outside Manager supervision ancestry",
        )
        environment = {
            "VLLM_ECPA_PLAN_ID": launch["native_plan_id"],
            "VLLM_ECPA_LAUNCH_ID": native_launch,
            "ECPA_SEMANTIC_EXECUTION_PLAN_ID": launch["execution_plan_id"],
            "ECPA_SEMANTIC_CONTROLLER_INSTANCE": launch["controller_instance"],
            "ECPA_SEMANTIC_CANDIDATE_GENERATION": str(launch["candidate_generation"]),
            "ECPA_SEMANTIC_MEMBERSHIP_EPOCH": str(launch["membership_epoch"]),
            "ECPA_SEMANTIC_LAUNCH_SPEC": permit["launch_spec"]["path"],
        }
        for sender in enrollment["source_peers"]:
            require(
                {r["path"]: r["sha256"] for r in sender["source_files"]}
                == permit["native_sources"],
                "registered native source tuple differs",
            )
            actual = registry._environment(sender["process"]["pid"])
            require(
                all(
                    actual.get(k.encode()) == v.encode() for k, v in environment.items()
                ),
                "actual semantic worker/API environment differs",
            )
        registration_ref = deployment["producer_registration"]
        require(
            reference(registration_ref["path"]) == registration_ref,
            "producer registration changed",
        )
        registration = json.loads(read_regular(registration_ref["path"]))
        require(
            registration["schema"] == request_live_producer.REGISTRATION
            and registration["formal_result"] is False
            and registration["phasebook"] == permit["phasebook"]
            and registration["enrollment"] == enrollment
            and registration["descriptor"] == deployment["descriptor"],
            "producer book/source deployment differs",
        )
        books.sources_current(registration["sources"])
        command = (
            Path(f"/proc/{deployment['producer']['pid']}/cmdline")
            .read_bytes()
            .split(b"\0")
        )
        command = [part.decode() for part in command if part]
        require(
            command[-6:]
            == [
                "-m",
                "experiments.native_attention_candidate.request_live_producer",
                "--registration",
                registration_ref["path"],
                "--expected-sha256",
                registration_ref["sha256"],
            ],
            "actual producer invocation differs from pinned implementation",
        )
        execution = registration["execution"]
        require(
            execution["spec_path"] == enrollment["spec"]["path"]
            and execution["collector_source_path"]
            == str(Path(request_drain_collector.__file__).resolve()),
            "source collector/spec deployment differs",
        )
        request_collector_client.authenticate(
            Path(execution["socket_path"]),
            deployment["descriptor"],
            Path(execution["spec_path"]),
            Path(execution["collector_source_path"]),
            drain_policy_path=Path(execution["drain_policy_path"]),
        )
        ready = deployment["producer_ready"]
        producer = deployment["producer"]
        require(
            ready["schema"] == request_live_producer.READY
            and ready["producer_source_sha256"]
            == sha(Path(request_live_producer.__file__).read_bytes())
            and ready["producer"]
            == {
                **producer,
                "start_identity": (
                    f"pid:{producer['pid']}:start_ticks:{producer['start_ticks']}"
                ),
            }
            and ready["registration_sha256"] == registration_ref["sha256"],
            "producer ready identity differs",
        )
        socket = Path(registration["socket_path"])
        meta = socket.lstat()
        require(
            stat.S_ISSOCK(meta.st_mode)
            and meta.st_uid == os.geteuid()
            and stat.S_IMODE(meta.st_mode) == 0o600
            and [meta.st_dev, meta.st_ino] == ready["socket_identity"],
            "actual producer endpoint replaced",
        )

    def deployment_current(self, permit, deployment, route_reader):
        require(
            deployment["sha256"] not in self.revoked_deployments,
            "request semantic deployment permanently revoked",
        )
        value, cut = self._permit_current_with_cut(permit)
        body = self._open(deployment, DEPLOYMENT)
        require(body["permit_sha256"] == permit["sha256"], "deployment permit differs")
        self._live_request(value, body, route_reader, _cut=cut)
        cut.check()
        for kernel in [
            body["manager"],
            body["producer"],
            {k: body["descriptor"]["collector"][k] for k in registry.KERNEL},
            *body["peers"].values(),
        ]:
            registry._kernel(kernel)
        require(
            time.monotonic_ns() < body["route"]["lease_expires_monotonic_ns"],
            "original route expired after deployment IO",
        )
        return value, body

    def verify_request_completion(
        self,
        permit,
        deployment,
        *,
        route_reader,
        admission,
        phase_index,
        output,
        observation_arguments,
        producer_receipt,
    ):
        value, bound = self.deployment_current(permit, deployment, route_reader)
        phases = value["phasebook"]["recipe"]["phases"]
        require(
            type(phase_index) is int and 0 <= phase_index < len(phases),
            "phase index invalid",
        )
        phase = phases[phase_index]
        require(
            admission["phase_id"] == phase["phase_id"]
            and admission["request_sha256"] == sha(canonical(phase["payload"]))
            and registry.HEX.fullmatch(admission["admission_nonce"]),
            "semantic admission differs",
        )
        require(
            set(admission)
            == {
                "phase_id",
                "request_sha256",
                "headers_sha256",
                "public_arrived_monotonic_ns",
                "deadline_monotonic_ns",
                "admission_nonce",
                "formal_result",
            }
            and admission["formal_result"] is False
            and type(admission["public_arrived_monotonic_ns"]) is int
            and 0 < admission["public_arrived_monotonic_ns"] < time.monotonic_ns()
            and admission["deadline_monotonic_ns"]
            == admission["public_arrived_monotonic_ns"]
            + value["phasebook"]["total_request_budget_s"] * 1_000_000_000,
            "public arrival/deadline fields differ",
        )
        output = Path(output)
        registration = json.loads(read_regular(bound["producer_registration"]["path"]))
        require(
            output == Path(registration["output_root"]) / f"request-{phase_index:04d}",
            "completion output belongs to another request",
        )
        args = dict(observation_arguments)
        expected_args = {
            "recipe",
            "phase_id",
            "output",
            "descriptor",
            "spec_path",
            "journal_path",
            "policy_path",
            "drain_policy_path",
        }
        require(
            set(args) == expected_args
            and args["recipe"] == value["phasebook"]["recipe"]
            and args["phase_id"] == phase["phase_id"]
            and Path(args["output"]) == output
            and args["descriptor"] == bound["descriptor"]
            and Path(args["journal_path"]) == output / "snapshot/native.jsonl",
            "full consumer arguments differ",
        )
        for key in ("spec_path", "policy_path", "drain_policy_path"):
            require(
                str(args[key]) == registration["execution"][key],
                "consumer source artifact differs",
            )
        require(
            json.loads(read_regular(output.parent / f"claim-{phase_index:04d}.json"))
            == admission,
            "actual handler public arrival claim differs",
        )
        files = snapshot_files(output)
        observed = consumer.verify_observation(**args)
        original = authenticated_completion_value(producer_receipt)
        require(
            producer_receipt.wire
            == read_regular(output / "producer-command-completion.json") + b"\n"
            and {k: producer_receipt.producer[k] for k in registry.KERNEL}
            == bound["producer"]
            and list(producer_receipt.socket_identity)
            == bound["producer_ready"]["socket_identity"],
            "original producer completion differs from authenticated Unix receipt",
        )
        completion = original["completion"]
        require(
            original["schema"] == request_live_producer.FIXED_COMPLETION
            and original["formal_result"] is False
            and original["nonce"] == admission["admission_nonce"]
            and original["registration_sha256"]
            == bound["producer_registration"]["sha256"]
            and {k: original["producer"][k] for k in registry.KERNEL}
            == bound["producer"]
            and completion["phase_id"] == phase["phase_id"]
            and completion["observation_sha256"] == sha(canonical(observed))
            and completion["response_sha256"] == observed["response_sha256"]
            and completion["prefix_sha256"] == observed["full_global_prefix_sha256"],
            "original producer completion differs from independent full verification",
        )
        require(
            observed["tensor_receipt_count"] == observed["operator_receipt_count"] == 56
            and observed["worker_closure_count"] == 2
            and observed["full_phase_source_drained"] is True,
            "compiled obligation requires actual current56/56/2",
        )
        after = json.loads(read_regular(output / "collector-after.json"))
        _, state = consumer.sealed_state(after, phase, args["drain_policy_path"])
        expected_clock = request_live_producer.fixed_completion_clock(
            original["issued_monotonic_ns"],
            admission["deadline_monotonic_ns"],
            bound["route"]["lease_expires_monotonic_ns"],
        )
        require(
            registration.get("completion_domain")
            == request_live_producer.FIXED_COMPLETION
            and registration.get("original_route_expires_monotonic_ns")
            == bound["route"]["lease_expires_monotonic_ns"]
            and all(
                original.get(key) == expected
                for key, expected in expected_clock.items()
            ),
            "producer original fixed clock/domain/independent route lease differs",
        )
        expiry = original["expires_monotonic_ns"]
        require(
            admission["public_arrived_monotonic_ns"]
            < state["sealed_monotonic_ns"]
            <= original["issued_monotonic_ns"]
            <= producer_receipt.received_monotonic_ns
            <= time.monotonic_ns()
            < expiry,
            "original producer completion lease expired or clock order differs",
        )
        metadata = json.loads(read_regular(output / "response-metadata.json"))
        require(
            admission["public_arrived_monotonic_ns"] <= metadata["sent_monotonic_ns"],
            "upstream HTTP preceded actual public arrival",
        )
        require(
            snapshot_files(output) == files,
            "full raw inputs changed during semantic verification",
        )
        self.deployment_current(permit, deployment, route_reader)
        body = {
            "schema": TICKET,
            "permit_sha256": permit["sha256"],
            "deployment_sha256": deployment["sha256"],
            "compiled_obligation": value["compiled_binding"],
            "event": EVENT,
            "scope": SCOPE,
            "route": bound["route"],
            "admission": admission,
            "phase_index": phase_index,
            "phasebook_sha256": value["phasebook_sha256"],
            "observation_sha256": sha(canonical(observed)),
            "response": reference(output / "response.bin"),
            "files": files,
            "native_prefix_path": str(output / "snapshot/native.jsonl"),
            "producer_issued_monotonic_ns": original["issued_monotonic_ns"],
            "source_sealed_monotonic_ns": state["sealed_monotonic_ns"],
            "expires_monotonic_ns": expiry,
            "full_global_prefix": observed["full_global_prefix"],
            "full_global_prefix_sha256": observed["full_global_prefix_sha256"],
            "tensor_receipts": 56,
            "operator_receipts": 56,
            "worker_closures": 2,
            "formal_result": False,
        }
        ticket = self._seal(body)
        ledger = self.ledgers[deployment["sha256"]]
        ledger.reserve(admission["admission_nonce"], ticket["sha256"], phase_index)
        capability = VerifiedRequestCompletion()
        with self.lock:
            self.verified_capabilities[capability] = (ticket, observed)
        return capability

    def verified_completion(self, capability):
        with self.lock:
            require(
                type(capability) is VerifiedRequestCompletion
                and capability in self.verified_capabilities,
                "opaque owner-verified capability absent or already burned",
            )
            ticket, observed = self.verified_capabilities[capability]
            return json.loads(canonical(ticket)), json.loads(canonical(observed))

    def discard_verified_completion(self, capability):
        with self.lock:
            entry = self.verified_capabilities.pop(capability, None)
            if entry is not None:
                self.revoked_deployments.add(entry[0]["body"]["deployment_sha256"])

    def consume_request(
        self, permit, deployment, capability, *, route_reader, admission, persist
    ):
        # Burn opaque capability before any failing IO/current-state check.
        with self.lock:
            require(
                type(capability) is VerifiedRequestCompletion
                and capability in self.verified_capabilities,
                "opaque owner-verified capability absent or already burned",
            )
            ticket, _ = self.verified_capabilities.pop(capability)
        try:
            return self._consume_verified_request(
                permit,
                deployment,
                ticket,
                route_reader=route_reader,
                admission=admission,
                persist=persist,
            )
        except BaseException:
            with self.lock:
                self.revoked_deployments.add(deployment["sha256"])
            raise

    def _consume_verified_request(
        self, permit, deployment, ticket, *, route_reader, admission, persist
    ):
        self.deployment_current(permit, deployment, route_reader)
        value = self._open(ticket, TICKET)
        require(
            value["permit_sha256"] == permit["sha256"]
            and value["deployment_sha256"] == deployment["sha256"]
            and value["admission"] == admission,
            "request completion ticket scope differs",
        )
        check_completion_files(value)
        ledger = self.ledgers[deployment["sha256"]]
        ledger.consume(
            admission["admission_nonce"],
            ticket["sha256"],
            value["phase_index"],
            value["expires_monotonic_ns"],
            persist,
        )
        check_completion_files(value)
        self.deployment_current(permit, deployment, route_reader)
        require(
            time.monotonic_ns() < value["expires_monotonic_ns"],
            "completion expired after consume",
        )
        return value
