"""Independent source-issued observer continuation receipt; no inherited ready bit.

The original native receipt is a freshly revalidated admission input, never a
qualification/result. This v2 extension binds all nine original Latin slots and
all new protocol/Host sources to the same original workload/tuple/full Plans.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

from experiments.formal_campaign import h3_observer_common_registration as common
from experiments.formal_campaign import h3_observer_registration as original
from experiments.formal_campaign.h3_dynamic_authority import (
    canonical,
    check_ref,
    digest,
    require,
)
from experiments.formal_campaign.h3_owned_worker_carrier import save_new

INTENT = "ecpa-h3-observer-live-continuation-intent/v2"
RECEIPT = "ecpa-h3-observer-live-continuation-receipt/v2"
DOMAIN = "original-H3-observer-loss-live-transport-only"
PROTOCOL_FILES = (
    "h3_observer_live_registration.py",
    "h3_observer_live_launcher.py",
    "h3_observer_live_rebind.py",
    "h3_observer_live_operator.py",
    "h3_observer_live_dispatch.py",
    "h3_observer_runner.py",
    "h3_observer_carrier.py",
    "h3_observer_authority.py",
    "h3_native_bootstrap.py",
    "h3_native_source_scope.py",
    "h3_observer_live_route.py",
    "h3_observer_live_http.py",
    "h3_observer_live_delivery.py",
    "h3_observer_live_observe.py",
    "h3_observer_live_cleanup.py",
    "h3_observer_live_intake.py",
    "experiments/exposure_gate/native_semantic_bootstrap.py",
    "experiments/native_kv_tensor_candidate/artifact_bootstrap.py",
)
HOST_FILES = (
    "native_observer_rebind.py",
    "native_semantic_bootstrap.py",
    "native_semantic_collector.py",
    "native_tensor_artifact_bootstrap.py",
    "native_phase_drain.py",
    "native_attention_operator_observer.py",
    "evidence.py",
)
_ISSUER = object()


# Linux pathname AF_UNIX sun_path is 108 bytes INCLUDING terminating NUL.
# Ten bytes conservatively cover every positive signed 32-bit pid_t. This is
# only a size placeholder, never a PID prediction, kernel epoch or ready proof.
UDS_PATH_BYTES = 107
PID_COMPONENT_BYTES = 10
MAX_ACTUAL_PID = 2_147_483_647


def check_uds_path(path):
    path = Path(path)
    raw = os.fsencode(str(path))
    require(
        path.is_absolute() and b"\0" not in raw and len(raw) <= UDS_PATH_BYTES,
        "live observer pathname UDS exceeds Linux sun_path byte bound",
    )
    return path


def precheck_uds_paths(directory, successor_output):
    # Does not resolve/stat, reserve a directory, probe a process or manufacture
    # a future epoch. Admission rejects before Host/collector Popen can occur.
    check_uds_path(Path(directory) / ("P" * PID_COMPONENT_BYTES) / "control.sock")
    check_uds_path(Path(successor_output) / "native.sock")


def actual_control_path(directory, pid):
    require(
        type(pid) is int and 0 < pid <= MAX_ACTUAL_PID,
        "actual Linux producer PID outside conservative preregistered width",
    )
    return check_uds_path(Path(directory) / str(pid) / "control.sock")


def reference(path):
    path = Path(path).resolve()
    return {"path": str(path), "sha256": digest(path.read_bytes())}


def _checked_json(reference):
    # Parse exactly the bytes whose digest is checked, including after any
    # path read performed by the original reference validator.
    raw = check_ref(reference).read_bytes()
    require(digest(raw) == reference["sha256"], "checked JSON readback bytes changed")
    return json.loads(raw)


def _inputs(intent_path, *, check_remote, _selected_start_id=None):
    intent_raw = Path(intent_path).read_bytes()
    intent = json.loads(intent_raw)
    intent_ref = {
        "path": str(Path(intent_path).resolve()),
        "sha256": digest(intent_raw),
    }
    require(
        set(intent)
        == {
            "schema",
            "domain",
            "base_campaign",
            "base_receipt",
            "receipt_path",
            "starts",
        }
        and intent["schema"] == INTENT
        and intent["domain"] == DOMAIN,
        "exact independent live-continuation intent required",
    )
    campaign_path = check_ref(intent["base_campaign"])
    receipt_path = check_ref(intent["base_receipt"])
    # This reconstructs original source/native Plan guards and independent actual
    # wheel/source input audits. No arbitrary caller trust-root set is accepted.
    if _selected_start_id is None:
        # Issuance and the default full reconstruction retain all nine starts.
        spec, campaign, receipt = original.validate_receipt(
            campaign_path, receipt_path, check_remote=check_remote
        )
    else:
        # This existing API validates the whole campaign/receipt/static rows and
        # freshly rebuilds only the selected start's actual runtime/Plan guards.
        native_scope = original.validate_receipt_for_start(
            campaign_path,
            receipt_path,
            _selected_start_id,
            check_remote=check_remote,
        )
        context, campaign, selected = native_scope.selected(_selected_start_id)
        # The remaining nine rows are static declaration data, never a returned
        # whole-campaign validity capability. Recheck both original byte refs.
        spec = _checked_json(intent["base_campaign"])
        receipt = _checked_json(intent["base_receipt"])
        require(
            canonical({k: v for k, v in spec.items() if k != "starts"})
            == canonical(context)
            and [s for s in spec["starts"] if s["start_id"] == _selected_start_id]
            == [selected]
            and [s for s in receipt["starts"] if s["start_id"] == _selected_start_id]
            == [native_scope.authority_binding(_selected_start_id)]
            and receipt["source_observation"]
            == native_scope.guard_receipt(_selected_start_id)["source_observation"],
            "selected native scope differs from original static declaration",
        )
    require(
        campaign["cell_id"] == "observer-loss"
        and campaign["objective"]["max_recovery_ms"] == 30000,
        "original observer cell/30s objective changed",
    )
    protocol = json.loads((Path(__file__).parent / "protocol.json").read_bytes())
    ordered = [
        next(s for s in spec["starts"] if s["repetition"] == r and s["arm"] == arm)
        for r, arms in enumerate(protocol["schedule"], 1)
        for arm in arms
    ]
    require(
        len(intent["starts"]) == 9
        and [s["start_id"] for s in intent["starts"]]
        == [s["start_id"] for s in ordered],
        "exact original Latin nine order required",
    )
    host_sources = []
    roots = []
    for start, decl in zip(ordered, intent["starts"], strict=True):
        require(
            set(decl) == {"start_id", "grant_directory", "successor", "operator"},
            "unknown live declaration fields",
        )
        recipe = _checked_json(start["recipe_template"])
        phase = recipe["arms"][start["arm"]]["phases"][0]
        root = Path(phase["native_bootstrap"]["output"]).parent
        directory = Path(decl["grant_directory"])
        require(
            directory == root / "live-observer-control"
            and directory.is_absolute()
            and directory.resolve() == directory,
            "per-start grant directory differs from actual original output",
        )
        require(
            phase["environment"].get("ECPA_NATIVE_OBSERVER_REBIND_DIRECTORY")
            == str(directory)
            and "ECPA_NATIVE_OBSERVER_REBIND_POLICY" not in phase["environment"],
            "actual Host environment lacks source-owned"
            " per-producer directory bootstrap",
        )
        successor = decl["successor"]
        require(
            set(successor) == {"output", "native_context_path", "tensor_context_path"}
            and successor["output"] == str(root / "live-observer-successor")
            and successor["native_context_path"]
            == str(root / "live-observer-successor" / "semantic-context.json")
            and successor["tensor_context_path"]
            == str(root / "live-observer-successor" / "tensor-context.json"),
            "successor must be new immutable original-start-owned leaves",
        )
        precheck_uds_paths(directory, successor["output"])
        # Counts are executable operator declarations, not an outcome allowance.
        operator = decl["operator"]
        require(
            set(operator) == {"kind", "command"}
            and operator["kind"]
            in {"source-owned-automatic", "explicit-original-operator"}
            and (
                (
                    operator["kind"] == "source-owned-automatic"
                    and operator["command"] == []
                    and start["arm"] == "ecpa"
                )
                or (
                    operator["kind"] == "explicit-original-operator"
                    and start["arm"] != "ecpa"
                    and type(operator["command"]) is list
                    and operator["command"]
                )
            ),
            "original arm must declare its actual operator action, not a claimed count",
        )
        if operator["kind"] == "explicit-original-operator":
            expected = [
                sys.executable,
                str(Path(__file__).with_name("h3_observer_live_operator.py")),
                "--intent",
                str(Path(intent_path).resolve()),
                "--live-receipt",
                intent["receipt_path"],
                "--start-id",
                start["start_id"],
                "--runtime-recipe",
                str(root / "runtime-recipe.json"),
                "--output",
                str(root / "live-operator-result.json"),
            ]
            require(
                operator["command"] == expected,
                "explicit original operator command is not exact source-owned helper",
            )
        admitted = {
            r["path"]: r["sha256"].removeprefix("sha256:")
            for r in _checked_json(start["policy"])["source_refs"]
        }
        source_rows = phase["native_bootstrap"]["source_files"]
        for filename in HOST_FILES:
            found = [
                r
                for r in source_rows
                if r["path"].endswith("/vllm/plugins/" + filename)
            ]
            require(
                len(found) == 1
                and admitted.get(found[0]["path"]) == found[0]["sha256"],
                "new actual Host source missing from independent original closure: "
                + filename,
            )
            raw = Path(found[0]["path"]).read_bytes()
            require(
                hashlib.sha256(raw).hexdigest() == found[0]["sha256"],
                "new Host source bytes changed",
            )
            host_sources.append(found[0])
        roots.append(str(root))
    require(
        len(set(roots)) == 9,
        "original starts cannot share live control/cleanup ownership",
    )
    binding = common._protocol_binding(
        campaign["fixed_identity"]["manager_commit"], PROTOCOL_FILES
    )
    # Fresh observer derives its own canonical roots from original policy/tuple.
    observed = common.source_provenance.observe_sources(
        campaign["fixed_identity"], spec["source_policy"], spec["repositories"]
    )
    require(
        canonical(observed) == canonical(receipt["source_observation"]),
        "live extension source observation differs "
        "from independently issued original source "
        "admission",
    )
    require(
        reference(intent_path) == intent_ref,
        "live intent changed during reconstruction",
    )
    return intent, spec, campaign, receipt, binding, observed, host_sources, intent_ref


def _body_from_inputs(intent_path, inputs):
    intent, spec, campaign, receipt, binding, observed, host_sources, intent_ref = (
        inputs
    )
    require(
        reference(intent_path) == intent_ref, "live intent changed before receipt body"
    )
    return dict(
        schema=RECEIPT,
        domain=DOMAIN,
        intent=intent_ref,
        base_campaign=intent["base_campaign"],
        base_receipt=intent["base_receipt"],
        original_campaign=spec["original_campaign"],
        fixed_identity=campaign["fixed_identity"],
        protocol_sources=binding,
        source_observation=observed,
        host_sources=sorted(
            {canonical(row): row for row in host_sources}.values(),
            key=lambda r: r["path"],
        ),
        starts=[
            {"start_id": s["start_id"], "declaration_sha256": digest(canonical(s))}
            for s in intent["starts"]
        ],
    )


def _body(intent_path, *, check_remote):
    return _body_from_inputs(
        intent_path, _inputs(intent_path, check_remote=check_remote)
    )


def issue(intent_path, output):
    intent = json.loads(Path(intent_path).read_bytes())
    require(
        str(Path(output).resolve()) == intent["receipt_path"],
        "v2 receipt output differs from frozen intent",
    )
    inputs = _inputs(intent_path, check_remote=True)
    require(
        str(Path(output).resolve()) == inputs[0]["receipt_path"],
        "v2 receipt output differs from reconstructed intent",
    )
    result = _body_from_inputs(intent_path, inputs)
    save_new(Path(output), result)
    return result


class ValidatedLiveStart:
    __slots__ = ("_raw", "_receipt_ref")

    def __init__(self, raw, receipt_ref, *, _issuer=None):
        require(_issuer is _ISSUER, "live start scope must be independently issued")
        object.__setattr__(self, "_raw", canonical(raw))
        object.__setattr__(self, "_receipt_ref", canonical(receipt_ref))

    def __setattr__(self, *args):
        raise AttributeError("live start validation is immutable")

    def value(self):
        return json.loads(self._raw)

    def receipt_ref(self):
        return json.loads(self._receipt_ref)


def validate_for_start(intent_path, receipt_path, start_id, *, check_remote=True):
    intent = json.loads(Path(intent_path).read_bytes())
    require(
        str(Path(receipt_path).resolve()) == intent["receipt_path"],
        "v2 receipt path substitution",
    )
    inputs = _inputs(
        intent_path, check_remote=check_remote, _selected_start_id=start_id
    )
    require(
        str(Path(receipt_path).resolve()) == inputs[0]["receipt_path"],
        "v2 receipt path differs from reconstructed intent",
    )
    expected = _body_from_inputs(intent_path, inputs)
    receipt_raw = Path(receipt_path).read_bytes()
    actual = json.loads(receipt_raw)
    receipt_ref = {
        "path": str(Path(receipt_path).resolve()),
        "sha256": digest(receipt_raw),
    }
    require(
        canonical(actual) == canonical(expected),
        "live receipt differs from fresh independent source/Latin/Plan reconstruction",
    )
    intent, spec, campaign, base, _, _, _, _ = inputs
    starts = [s for s in spec["starts"] if s["start_id"] == start_id]
    declarations = [s for s in intent["starts"] if s["start_id"] == start_id]
    require(
        len(starts) == len(declarations) == 1, "exact original selected start required"
    )
    require(
        reference(intent_path) == inputs[-1] and reference(receipt_path) == receipt_ref,
        "live intent or receipt changed before selected scope",
    )
    return ValidatedLiveStart(
        {
            "start": starts[0],
            "declaration": declarations[0],
            "base_campaign": intent["base_campaign"],
            "base_receipt": intent["base_receipt"],
            "original": campaign,
            "intent": inputs[-1],
        },
        receipt_ref,
        _issuer=_ISSUER,
    )
