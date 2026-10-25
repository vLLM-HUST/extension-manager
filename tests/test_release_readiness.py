from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from scripts.check_release_readiness import READINESS, ROOT, main, validate_readiness


def readiness() -> dict[str, object]:
    return json.loads(READINESS.read_text(encoding="utf-8"))


def test_checked_in_release_decision_is_consistent(capsys) -> None:
    assert main([]) == 0
    assert "release-readiness: no-go" in capsys.readouterr().out


def test_publication_gate_rejects_unqualified_development_release(capsys) -> None:
    assert main(["--require-authorized"]) == 1
    assert "publication is not authorized" in capsys.readouterr().out


def test_go_decision_rejects_blocked_required_gate() -> None:
    payload = copy.deepcopy(readiness())
    payload["gates"][0]["status"] = "blocked"
    payload["gates"][0]["remaining_action"] = "repair the required gate"
    payload["decision"] = "go"
    payload["publication_authorized"] = True

    errors = validate_readiness(ROOT, payload)

    assert "publication cannot be authorized" in "\n".join(errors)


def test_inventory_arithmetic_is_checked() -> None:
    payload = copy.deepcopy(readiness())
    payload["inventory"]["inspect_only"] = 14

    errors = validate_readiness(ROOT, payload)

    assert "activation_intent plus inspect_only" in "\n".join(errors)


def test_evidence_paths_cannot_escape_repository(tmp_path: Path) -> None:
    payload = copy.deepcopy(readiness())
    payload["gates"][0]["evidence"] = ["../outside.md"]

    errors = validate_readiness(ROOT, payload)

    assert "unsafe evidence path" in "\n".join(errors)


def test_performance_policy_does_not_hide_runtime_release_blockers() -> None:
    payload = readiness()
    gates = {gate["id"]: gate["status"] for gate in payload["gates"]}

    assert set(gates.values()) == {"blocked"}
    assert gates["scheduler-carrier-qualification"] == "blocked"
    assert payload["publication_authorized"] is False
    assert set(payload["inventory"].values()) == {0}


def test_development_version_does_not_inherit_prior_release_authorization():
    payload = readiness()
    assert payload["package_version"] == "0.3.1.dev1"
    assert validate_readiness(ROOT, payload) == []
    assert payload["publication_authorized"] is False
    assert READINESS == ROOT / "spec/development-release-readiness.json"
    historical = (ROOT / "docs/release-readiness.json").read_bytes()
    assert hashlib.sha256(historical).hexdigest() == (
        "c2cd4f5b0f71b4421f4e5f2fd00a8acc9d08ecfec5088670633226a24c9e3930"
    )
    assert json.loads(historical)["package_version"] == "0.3.0"
    assert (
        "https://github.com/vLLM-HUST/extension-manager/blob/"
        "d090b71b3fe4c1827ccaf6c20e593b63ac5a7dc6/docs/release-readiness.json"
        in (ROOT / "README.md").read_text()
    )
    assert not (ROOT / "docs/evidence/release-readiness-v0.3.0.json").exists()
