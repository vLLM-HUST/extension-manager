import json
from pathlib import Path

from experiments.formal_campaign.semantic_campaign_prospective import build


def test_prospective_matrix_retains_every_original_cell_without_results():
    result = build()
    assert result["formal_result"] is False
    assert result["executable"] is False
    assert result["current_semantic_gate"] == "fail-closed-unverified"
    assert result["old_effective_aggregation_exists"] is True
    assert result["old_effective_aggregation_is_new_typed_admission"] is False
    assert result["planned_campaigns"]["h3"]["planned_starts"] == 225
    assert result["planned_campaigns"]["h4"]["planned_starts"] == 36
    for campaign in result["planned_campaigns"].values():
        assert campaign["formal_starts_completed"] == 0
        for cell in campaign["required_cells"]:
            assert len(cell["starts"]) == 9
            assert all(start["status"] == "unverified" for start in cell["starts"])
    assert all(value is None for value in result["prospective_identity"].values())
    assert all(value is None for value in result["unknown_objectives"].values())


def test_sealed_prospective_manifest_matches_its_bound_source():
    path = (
        Path(__file__).resolve().parents[1]
        / "experiments/formal_campaign/semantic-prospective-source-audit.json"
    )
    assert json.loads(path.read_bytes()) == build()
