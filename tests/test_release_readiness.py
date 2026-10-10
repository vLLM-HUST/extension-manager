from __future__ import annotations

import copy
import json
from pathlib import Path

from scripts.check_release_readiness import READINESS, ROOT, main, validate_readiness


def readiness() -> dict[str, object]:
    return json.loads(READINESS.read_text(encoding="utf-8"))


def test_checked_in_release_decision_is_consistent(capsys) -> None:
    assert main([]) == 0
    assert "release-readiness: no-go" in capsys.readouterr().out


def test_publication_gate_rejects_current_frozen_state(capsys) -> None:
    assert main(["--require-authorized"]) == 1
    assert "publication is not authorized" in capsys.readouterr().out


def test_go_decision_rejects_blocked_required_gate() -> None:
    payload = copy.deepcopy(readiness())
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

    assert gates["performance-and-support-claims"] == "passed"
    assert gates["native-current-host-npu"] == "blocked"
    assert gates["upstream-host-contract"] == "blocked"
    assert payload["publication_authorized"] is False
