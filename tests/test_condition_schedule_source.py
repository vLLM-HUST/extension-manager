"""Future CPU tests only; these do not qualify source or a running Host."""

from experiments.formal_campaign.qualify_conditional import request_schedule


def test_original_warmup_and_measured_selected_frontiers_are_not_shifted():
    rows = request_schedule("unregistered-conditional-r1")
    assert len(rows) == len({r["request_id"] for r in rows}) == 272
    assert [r["kind"] for r in rows[:16]] == ["warmup"] * 16
    assert [r["kind"] for r in rows[16:]] == ["measured"] * 256
    assert [r["all_index"] for r in rows if r["selected"]] == list(range(16)) + list(
        range(16, 272, 16)
    )
    assert rows[-16]["request_id"].endswith("measured-0240")


def test_independent_condition_qualification_cannot_reuse_a_formal_rid():
    old = request_schedule("conditional-resource-pair.sampled-invocation-r1-ecpa")
    new = request_schedule("unregistered-conditional-r1-ecpa")
    assert {r["request_id"] for r in old}.isdisjoint(r["request_id"] for r in new)
