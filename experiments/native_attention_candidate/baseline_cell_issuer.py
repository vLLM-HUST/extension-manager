"""Independent baseline-native cell authority; no Manager Plan or formal grant.

Activation-only receipts are prerequisites. Only the unchanged full native drain
verifier plus independently authenticated collector and current real epochs may
establish this finite, exact-request cached-response qualification.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from experiments.formal_campaign import source_provenance
from experiments.native_attention_candidate import baseline_live_producer as producer
from experiments.native_attention_candidate import baseline_native_scope as scopes
from experiments.native_attention_candidate import drain_consumer
from experiments.native_attention_candidate import live_route_reader as inputs_module
from experiments.native_attention_candidate import semantic_producer_registry as util
from experiments.native_challenge_candidate import collector_client
from vllm_hust_ext.activation_profile import load_activation_profile

PERMIT = "ecpa-baseline-cell-semantic-permit/v1"
DEPLOYMENT = "ecpa-baseline-cell-semantic-deployment/v1"
ORIGIN = producer.ORIGIN
CELL_FIELDS = {
    "cell_id",
    "arm",
    "baseline_scope_sha256",
    "activation_profile_sha256",
    "common_query_sha256",
    "profile_id",
    "recipe_sha256",
    "request_sha256",
    "model_sha256",
    "tokenizer_sha256",
    "calibration_sha256",
    "wheel_sha256",
    "native_sources",
    "protocol_sources",
}
PROTOCOL_ROLES = {"producer", "issuer", "verifier", "controller", "input_audit"}
ARTIFACTS = {"registration", "recipe", "spec", "policy", "drain_policy"}
PROOF_FIELDS = {
    "observation_sha256",
    "request_sha256",
    "response_sha256",
    "issued_monotonic_ns",
    "expires_monotonic_ns",
    "tensor_receipts",
    "operator_receipts",
    "full_prefix_records",
    "worker_closures",
}
canonical, sha, require = util.canonical, util.sha, util.require


def _object(reference):
    return json.loads(scopes._reference(reference), object_pairs_hook=scopes._unique)


def _proof_identity(proof):
    return {key: value for key, value in proof.items() if key != "issued_monotonic_ns"}


def _collector(registration, phase):
    """Authenticate the live independent collector, including sealed final prefix."""
    r = registration
    actual = collector_client.authenticate(
        Path(r["collector_socket_path"]),
        r["collector_descriptor"],
        Path(r["spec_path"]),
        Path(r["collector_source"]),
        drain_policy_path=Path(r["drain_policy_path"]),
    )
    require(
        drain_consumer.verify_sealed_status(actual, phase, r["drain_policy_path"]),
        "baseline independent collector source closures unavailable",
    )
    frozen = json.loads((Path(r["probe_output"]) / "collector-after.json").read_bytes())
    require(
        canonical(actual["status"]["acknowledged_prefix"])
        == canonical(frozen["status"]["acknowledged_prefix"]),
        "baseline independently authenticated final prefix changed",
    )
    return actual


class BaselineCellIssuer:
    """Issuer-owned trust sets and MAC; never accept trust from the producer."""

    def __init__(self, key, trusted_source_observations, trusted_input_audits):
        self._envelopes = util.CellIssuer(key, trusted_source_observations)
        require(bool(trusted_input_audits), "independent baseline input trust missing")
        self._input_trust = frozenset(trusted_input_audits)

    def _seal(self, body):
        return self._envelopes._seal(body)

    def _open(self, envelope, schema):
        value = self._envelopes._open(envelope, schema)
        require(value["origin"] == ORIGIN, "baseline envelope origin differs")
        return value

    def issue_permit(
        self,
        cell,
        *,
        baseline_scope_reference,
        activation_profile_reference,
        recipe,
        fixed,
        policy,
        source_observation,
        inputs,
    ):
        require(set(cell) == CELL_FIELDS, "baseline cell fields differ")
        require(
            sha(canonical(inputs)) in self._input_trust,
            "baseline input audit is not independently trusted",
        )
        require(
            inputs["schema"] == inputs_module.SCHEMA
            and inputs["formal_result"] is False
            and inputs["file_state"],
            "baseline actual input audit missing",
        )
        inputs_module._check_file_states(inputs["file_state"])
        source_provenance.validate_observation(source_observation, policy, fixed)
        admission = sha(source_provenance.canonical(source_observation))
        require(
            admission in self._envelopes._trusted,
            "baseline source observation is not independently trusted",
        )
        scope = scopes.BaselineNativeScope(
            scopes._reference(baseline_scope_reference)
        ).value()
        profile = load_activation_profile(
            Path(activation_profile_reference["path"]),
            activation_profile_reference["sha256"],
        )
        require(
            profile.value()["calibration"]["sha256"] == cell["calibration_sha256"],
            "baseline activation and audited calibration differ",
        )
        require(
            cell["baseline_scope_sha256"] == baseline_scope_reference["sha256"]
            and cell["activation_profile_sha256"]
            == profile.sha256
            == scope["activation_profile_sha256"]
            and cell["arm"] == scope["arm"]
            and cell["common_query_sha256"]
            == scope["common_query_sha256"]
            == cell["request_sha256"],
            "baseline permit scope/profile/query differs",
        )
        require(
            isinstance(cell["cell_id"], str)
            and cell["cell_id"]
            and not any(c.isspace() for c in cell["cell_id"]),
            "baseline cell ID invalid",
        )
        require(
            cell["profile_id"] == util.recipe_profile_id(recipe)
            and cell["recipe_sha256"]
            == sha(canonical(recipe))
            == inputs["recipe"]["sha256"]
            and cell["request_sha256"]
            == sha(canonical(recipe["phases"][0]["payload"])),
            "baseline permit recipe differs",
        )
        for name in (
            "profile_id",
            "request_sha256",
            "model_sha256",
            "tokenizer_sha256",
            "calibration_sha256",
            "wheel_sha256",
        ):
            require(
                canonical(cell[name]) == canonical(inputs[name]),
                "baseline cell/input tuple differs",
            )
        require(
            set(cell["wheel_sha256"]) == set(inputs_module.DISTRIBUTIONS)
            and all(
                isinstance(v, str) and util.HEX.fullmatch(v)
                for v in cell["wheel_sha256"].values()
            ),
            "baseline seven wheels missing",
        )
        revisions = inputs["wheel_revisions"]
        require(
            revisions["manager"] == fixed["manager_commit"]
            and revisions["host"] == fixed["host_commit"]
            and revisions["ascend"] == fixed["accelerator_commit"]
            and set(fixed["plugin_commits"].values()) == {revisions["mod"]},
            "baseline source admission and installed wheel revisions differ",
        )
        require(
            set(cell["protocol_sources"]) == PROTOCOL_ROLES,
            "baseline protocol source roles differ",
        )
        require(
            cell["protocol_sources"]["producer"]
            == {
                "path": str(Path(producer.__file__).resolve()),
                "sha256": sha(Path(producer.__file__).read_bytes()),
            }
            and cell["protocol_sources"]["issuer"]
            == {
                "path": str(Path(__file__).resolve()),
                "sha256": sha(Path(__file__).read_bytes()),
            }
            and cell["protocol_sources"]["input_audit"]
            == {
                "path": str(Path(inputs_module.__file__).resolve()),
                "sha256": sha(Path(inputs_module.__file__).read_bytes()),
            },
            "baseline protocol implementation origin differs",
        )
        from experiments.native_attention_candidate import baseline_cached_controller

        require(
            cell["protocol_sources"]["controller"]
            == {
                "path": str(Path(baseline_cached_controller.__file__).resolve()),
                "sha256": sha(Path(baseline_cached_controller.__file__).read_bytes()),
                "callable": "BaselineCachedController.read_route",
            },
            "baseline actual controller implementation differs",
        )
        util._callback(
            drain_consumer.verify_observation, cell["protocol_sources"]["verifier"]
        )
        for ref in cell["protocol_sources"].values():
            util._files({ref["path"]: ref["sha256"]})
        util._files(cell["native_sources"])
        for path, digest in {
            **cell["native_sources"],
            **{ref["path"]: ref["sha256"] for ref in cell["protocol_sources"].values()},
        }.items():
            require(
                inputs["source_files"].get(path) == digest,
                "baseline source is outside independently audited inputs",
            )
        return self._seal(
            {
                "schema": PERMIT,
                "origin": ORIGIN,
                "cell": cell,
                "baseline_scope_reference": baseline_scope_reference,
                "activation_profile_reference": activation_profile_reference,
                "inputs": inputs,
                "fixed_identity": fixed,
                "source_policy": policy,
                "source_observation": source_observation,
                "source_admission_sha256": admission,
                "formal_result": False,
            }
        )

    def _permit(self, permit):
        value = self._open(permit, PERMIT)
        require(
            value["source_admission_sha256"] in self._envelopes._trusted
            and sha(canonical(value["inputs"])) in self._input_trust,
            "baseline independent trust revoked",
        )
        source_provenance.validate_observation(
            value["source_observation"], value["source_policy"], value["fixed_identity"]
        )
        inputs_module._check_file_states(value["inputs"]["file_state"])
        util._files(value["cell"]["native_sources"])
        for ref in value["cell"]["protocol_sources"].values():
            util._files({ref["path"]: ref["sha256"]})
        scopes._reference(value["baseline_scope_reference"])
        load_activation_profile(
            Path(value["activation_profile_reference"]["path"]),
            value["activation_profile_reference"]["sha256"],
        )
        return value

    def bind_deployment(
        self, permit, *, artifacts, producer_kernel, connection, route_reader
    ):
        value = self._permit(permit)
        require(set(artifacts) == ARTIFACTS, "baseline artifact roles differ")
        r = _object(artifacts["registration"])
        route = route_reader()
        body = {
            "schema": DEPLOYMENT,
            "origin": ORIGIN,
            "permit_sha256": permit["sha256"],
            "artifacts": artifacts,
            "producer": producer_kernel,
            "socket_path": r["producer_socket"],
            "socket_identity": util._socket(
                r["producer_socket"], connection, producer_kernel
            ),
            "route": route,
            "formal_result": False,
        }
        self._live(value, body, connection, route_reader)
        return self._seal(body)

    def _live(self, permit, binding, connection, route_reader):
        cell = permit["cell"]
        for ref in binding["artifacts"].values():
            scopes._reference(ref)
        r = _object(binding["artifacts"]["registration"])
        require(
            set(r) == producer.FIELDS
            and r["schema"] == producer.REGISTRATION
            and r["origin"] == ORIGIN
            and r["formal_result"] is False
            and type(r["max_validity_ns"]) is int
            and r["max_validity_ns"] == 30_000_000_000,
            "baseline registration fields/origin/lease differ",
        )
        require(
            r["baseline_scope_reference"] == permit["baseline_scope_reference"]
            and r["activation_profile_reference"]
            == permit["activation_profile_reference"],
            "baseline registration belongs to another permit",
        )
        scope = scopes.BaselineNativeScope(
            scopes._reference(r["baseline_scope_reference"])
        ).value()
        receipt = _object(r["host_observer_receipt_reference"])
        require(
            receipt["schema"] == producer.HOST_SCHEMA
            and receipt["origin"] == ORIGIN
            and receipt["activation_only"] is True
            and receipt["effect_qualification"] is None
            and receipt["formal_result"] is False
            and all(
                canonical(receipt[k]) == canonical(scope[k])
                for k in ("arm", "observer_trial_id", "activation_profile_sha256")
            )
            and receipt["owner"] == r["owner_kernel"] == r["observer_kernel"]
            and receipt["host"] == r["host_kernel"],
            "baseline captured Host prerequisite differs",
        )
        scopes._receipt_sources_and_prefix(receipt)
        expected = {
            f"{p['process']['role']}/{p['process']['ordinal']}": p
            for p in receipt["peers"]
        }
        require(
            set(expected) == {"api-server/0", "worker/0", "worker/1"},
            "baseline Host membership differs",
        )
        kernels = [
            r["owner_kernel"],
            binding["producer"],
            *(p["kernel"] for p in expected.values()),
        ]
        require(
            len({p["pid"] for p in kernels}) == 5,
            "baseline requires five distinct actual processes",
        )
        require(
            r["collector_descriptor"]["collector"]["pid"]
            not in {p["pid"] for p in [*kernels, r["host_kernel"]]},
            "baseline collector must be independent from all execution peers",
        )
        for kernel in [*kernels, r["host_kernel"]]:
            util._kernel(kernel)
        from experiments.native_attention_candidate.baseline_host_binding import (
            _ancestors,
        )

        require(
            r["owner_kernel"] in _ancestors(binding["producer"]["pid"]),
            "baseline producer left owner subtree",
        )
        require(
            util._socket(binding["socket_path"], connection, binding["producer"])
            == binding["socket_identity"]
            and binding["socket_path"] == r["producer_socket"],
            "baseline producer endpoint replaced",
        )
        require(
            r["producer_source_path"] == cell["protocol_sources"]["producer"]["path"]
            and r["producer_source_sha256"]
            == cell["protocol_sources"]["producer"]["sha256"],
            "baseline registered producer source differs",
        )
        recipe = _object(binding["artifacts"]["recipe"])
        require(
            len(recipe["phases"]) == 1
            and recipe["phases"][0]["phase_id"] == r["phase_id"]
            and sha(canonical(recipe)) == cell["recipe_sha256"]
            and scopes._reference(r["common_query_reference"])
            == canonical(recipe["phases"][0]["payload"])
            and r["common_query_reference"]["sha256"] == cell["common_query_sha256"],
            "baseline recipe/common query changed",
        )
        for artifact, key in (
            ("recipe", "recipe_path"),
            ("spec", "spec_path"),
            ("policy", "policy_path"),
            ("drain_policy", "drain_policy_path"),
        ):
            require(
                binding["artifacts"][artifact]["path"] == r[key],
                "baseline artifact alias differs",
            )
        spec = _object(binding["artifacts"]["spec"])
        require(
            spec["native_plan_id"] == scope["native_correlation"]["plan_id"]
            and spec["native_launch_id"] == scope["native_correlation"]["launch_id"]
            and canonical(spec["senders"]) == canonical(r["source_peers"])
            and len(r["source_peers"]) == 3,
            "baseline source registration differs",
        )
        # Reuse the pinned producer's current-source/Host ingress guard only as a
        # guard; effect verification below is independently executed in this PID.
        guard = object.__new__(producer.BaselineLiveProducer)
        guard.registration, guard.receipt, guard.scope = r, receipt, scope
        guard.native_scope = scopes.BaselineNativeScope(
            scopes._reference(r["baseline_scope_reference"])
        )
        guard.profile = load_activation_profile(
            Path(r["activation_profile_reference"]["path"]),
            r["activation_profile_reference"]["sha256"],
        )
        guard.baseline_files = {
            ref["path"]: ref["sha256"] for ref in binding["artifacts"].values()
        }
        producer.BaselineLiveProducer.check_live(guard)
        for peer in r["source_peers"]:
            p = peer["process"]
            key = f"{p['role']}/{p['ordinal']}"
            require(
                key in expected
                and canonical(p) == canonical(expected[key]["process"])
                and {s["path"]: s["sha256"] for s in peer["source_files"]}
                == cell["native_sources"],
                "baseline independent source membership differs",
            )
        util._callback(route_reader, cell["protocol_sources"]["controller"])
        require(
            getattr(route_reader, "__self__", None) is not None
            and route_reader.__self__.owner == r["owner_kernel"]
            and r["owner_kernel"] == util.process_identity(os.getpid()),
            "baseline actual controller/owner differs",
        )
        route = route_reader()
        required = {
            "observer_trial_id",
            "arm",
            "activation_profile_sha256",
            "common_query_sha256",
            "controller_instance",
            "generation",
            "membership_epoch",
            "fence",
            "lease_expires_monotonic_ns",
        }
        require(
            set(route) == required
            and canonical(route) == canonical(binding["route"])
            and all(
                route[k] == scope[k]
                for k in (
                    "observer_trial_id",
                    "arm",
                    "activation_profile_sha256",
                    "common_query_sha256",
                )
            )
            and type(route["generation"]) is int
            and route["generation"] > 0
            and type(route["membership_epoch"]) is int
            and route["membership_epoch"] >= 0
            and all(
                isinstance(route[k], str) and route[k]
                for k in ("fence", "controller_instance")
            )
            and type(route["lease_expires_monotonic_ns"]) is int
            and time.monotonic_ns() < route["lease_expires_monotonic_ns"],
            "baseline actual prepared route changed or expired",
        )
        return r, recipe


class BaselineQuoteVerifier:
    """Single-use challenge and full unchanged drain reconstruction in owner PID."""

    def __init__(self, issuer):
        self.issuer = issuer
        self._pending, self._spent, self._leases = {}, set(), {}
        self._lock = threading.Lock()

    def expect(self, nonce):
        with self._lock:
            require(
                isinstance(nonce, str)
                and util.HEX.fullmatch(nonce)
                and nonce not in self._pending
                and nonce not in self._spent,
                "baseline challenge nonce reused/invalid",
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
        observation_arguments,
    ):
        nonce = quote.get("nonce")
        with self._lock:
            require(nonce in self._pending, "baseline nonce not pending/replayed")
            challenged = self._pending.pop(nonce)
            self._spent.add(nonce)
        value = self.issuer._permit(permit)
        bound = self.issuer._open(deployment, DEPLOYMENT)
        require(
            bound["permit_sha256"] == permit["sha256"],
            "baseline deployment permit differs",
        )
        r, recipe = self.issuer._live(value, bound, connection, route_reader)
        require(
            set(quote)
            == {
                "schema",
                "origin",
                "nonce",
                "registration_sha256",
                "producer",
                "scope",
                "ready",
                "reason",
                "proof",
                "formal_result",
            }
            and quote["schema"] == producer.QUOTE
            and quote["origin"] == ORIGIN
            and quote["ready"] is True
            and quote["formal_result"] is False
            and isinstance(quote["reason"], str)
            and canonical(quote["producer"]) == canonical(bound["producer"])
            and quote["registration_sha256"] == sha(canonical(r))
            and canonical(quote["scope"])
            == canonical(_object(r["baseline_scope_reference"])),
            "baseline typed quote origin/source/scope differs",
        )
        proof = quote["proof"]
        require(
            isinstance(proof, dict)
            and set(proof) == PROOF_FIELDS
            and all(
                type(proof[k]) is int
                for k in PROOF_FIELDS
                - {"observation_sha256", "request_sha256", "response_sha256"}
            )
            and proof["request_sha256"] == value["cell"]["request_sha256"]
            and challenged
            <= proof["issued_monotonic_ns"]
            <= time.monotonic_ns()
            < proof["expires_monotonic_ns"]
            <= bound["route"]["lease_expires_monotonic_ns"],
            "baseline typed proof request/time/count types differ",
        )
        completion_path = Path(bound["artifacts"]["registration"]["path"]).with_name(
            producer.RESERVED_OUTPUTS[0]
        )
        completion_ref = {
            "path": str(completion_path),
            "sha256": sha(completion_path.read_bytes()),
        }
        completion = _object(completion_ref)
        original = completion["proof"]
        require(
            completion["schema"] == producer.COMPLETION
            and completion["origin"] == ORIGIN
            and completion["formal_result"] is False
            and canonical(completion["producer"]) == canonical(bound["producer"])
            and completion["registration_sha256"] == quote["registration_sha256"]
            and canonical(completion["scope"]) == canonical(quote["scope"])
            and set(original) == PROOF_FIELDS
            and type(original["issued_monotonic_ns"]) is int
            and type(original["expires_monotonic_ns"]) is int
            and original["expires_monotonic_ns"] - original["issued_monotonic_ns"]
            == 30_000_000_000
            and original["issued_monotonic_ns"] <= proof["issued_monotonic_ns"]
            and canonical(_proof_identity(original))
            == canonical(_proof_identity(proof)),
            "baseline original completion/proof fixed lifetime differs",
        )
        with self._lock:
            require(
                self._leases.setdefault(
                    deployment["sha256"], proof["expires_monotonic_ns"]
                )
                == proof["expires_monotonic_ns"],
                "baseline proof lease cannot renew",
            )
        expected_args = {
            "recipe": recipe,
            "phase_id": r["phase_id"],
            "output": Path(r["probe_output"]),
            "descriptor": r["collector_descriptor"],
            **{
                k: Path(r[k])
                for k in (
                    "spec_path",
                    "journal_path",
                    "policy_path",
                    "drain_policy_path",
                )
            },
        }
        require(
            set(observation_arguments) == set(expected_args)
            and all(
                canonical(observation_arguments[k]) == canonical(v)
                if k in {"recipe", "descriptor", "phase_id"}
                else str(observation_arguments[k]) == str(v)
                for k, v in expected_args.items()
            ),
            "baseline verifier observation arguments differ",
        )
        _collector(r, recipe["phases"][0])
        util._callback(
            drain_consumer.verify_observation,
            value["cell"]["protocol_sources"]["verifier"],
        )
        observed = drain_consumer.verify_observation(**expected_args)
        journal = Path(r["journal_path"]).read_bytes()
        rows = [json.loads(line) for line in journal.splitlines()]
        response = (Path(r["probe_output"]) / "response.bin").read_bytes()
        require(
            observed["observed_typed_HTTP_ACK_join"] is True
            and observed["finite_native_argument_completion_join"] is True
            and observed["typed_archive_provenance"]["full_phase_source_drained"]
            is True
            and observed["tensor_receipt_count"]
            == observed["operator_receipt_count"]
            == 56
            and sha(canonical(observed)) == proof["observation_sha256"]
            and observed["actual_raw_response_sha256"]
            == proof["response_sha256"]
            == sha(response)
            and observed["whole_journal_sha256"] == sha(journal)
            and proof["tensor_receipts"]
            == sum(x["kind"] == "tensor.artifact.accepted" for x in rows)
            == 56
            and proof["operator_receipts"]
            == sum(x["kind"] == "attention.operator.accepted" for x in rows)
            == 56
            and proof["worker_closures"]
            == sum(x["kind"] == "attention.worker.drained" for x in rows)
            == 2
            and proof["full_prefix_records"] == len(rows),
            "baseline independent full native observation/counts/raw response differ",
        )
        _collector(r, recipe["phases"][0])
        self.issuer._live(self.issuer._permit(permit), bound, connection, route_reader)
        scopes._reference(completion_ref)
        require(
            Path(r["journal_path"]).read_bytes() == journal
            and (Path(r["probe_output"]) / "response.bin").read_bytes() == response,
            "baseline raw evidence changed after independent verification",
        )
        require(
            time.monotonic_ns() < proof["expires_monotonic_ns"],
            "baseline proof expired during independent verification",
        )
        return {
            "schema": "ecpa-baseline-cell-semantic-verdict/v1",
            "origin": ORIGIN,
            "permit_sha256": permit["sha256"],
            "deployment_sha256": deployment["sha256"],
            "observation_sha256": proof["observation_sha256"],
            "scope": "exact-frozen-request-cached-response",
            "formal_result": False,
        }
