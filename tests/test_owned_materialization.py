"""Private CPU ownership regressions; no native runtime qualification."""

import copy

import pytest
from test_native_attention_source_candidate import context as context
from test_native_attention_source_candidate import pa

from experiments.native_attention_candidate import operator_observer as observer


def owned_case(context):
    pa(context)
    value = copy.deepcopy(context.events[0])
    raw = observer.canonical(context.fact)
    owner = object()
    owned = observer._own_materialization(raw, owner)
    return value, raw, owner, owned


def test_owned_operator_matches_default_and_cannot_skip_source_relation(context):
    value, raw, owner, owned = owned_case(context)
    expected = observer.verify_observation(value, context.fact)
    assert observer._verify_owned_observation(value, owned, raw, owner) == expected
    owned._compact_after_tensor_check(owner)
    assert observer._verify_owned_observation(value, owned, raw, owner) == expected
    assert set(owned._detached(owner)) == set(observer._REPORT_FIELDS) | {
        "cache_views",
        "native_producer",
        "block_size",
        "destination_readback_sha256",
    }
    value["source_materialization_sha256"] = "0" * 64
    for verify in (
        lambda: observer.verify_observation(value, context.fact),
        lambda: observer._verify_owned_observation(value, owned, raw, owner),
    ):
        with pytest.raises(ValueError, match="actual archived materialization"):
            verify()


@pytest.mark.parametrize("replacement", [False, 0.0, -0.0])
def test_owned_token_rejects_changed_bytes_and_numeric_types(context, replacement):
    _, raw, owner, owned = owned_case(context)
    changed = copy.deepcopy(context.fact)
    changed["binding"]["rank"] = replacement
    with pytest.raises(ValueError, match="fresh materialization"):
        owned._match(observer.canonical(changed), owner)
    with pytest.raises(ValueError, match="fresh materialization"):
        owned._match(bytearray(raw), owner)


def test_owned_token_requires_constructor_bytes_and_same_invocation(context):
    value, raw, owner, owned = owned_case(context)
    with pytest.raises(ValueError, match="internal original"):
        observer._OwnedMaterialization(object(), raw, owner)
    for invalid in (context.fact, observer.sha(raw), bytearray(raw)):
        with pytest.raises(ValueError, match="internal original"):
            observer._own_materialization(invalid, owner)
    with pytest.raises(ValueError, match="noncanonical"):
        observer._own_materialization(b'{ "rank":0}', owner)
    with pytest.raises(ValueError, match="invocation"):
        observer._verify_owned_observation(value, owned, raw, object())
    with pytest.raises(ValueError, match="internal owned"):
        observer._verify_owned_observation(value, context.fact, raw, owner)
    with pytest.raises(ValueError, match="internal fresh-byte"):
        observer.verify_observation(value, owned)


def test_detached_mutation_cannot_pollute_operator_or_fresh_report(context):
    value, raw, owner, owned = owned_case(context)
    detached = owned._detached(owner)
    detached["binding"]["rank"] = 123
    detached["destination_blocks"].clear()
    assert observer._verify_owned_observation(value, owned, raw, owner) == (
        observer.verify_observation(value, context.fact)
    )
    owned._release_operator_tree(owner)
    with pytest.raises(ValueError, match="already verified"):
        owned._detached(owner)
    first = owned._report_after_fresh_read(raw, owner)
    first["binding"]["rank"] = 123
    first["keep_indices"].clear()
    second = owned._report_after_fresh_read(raw, owner)
    assert second["binding"] == context.fact["binding"]
    assert second["keep_indices"] == context.fact["keep_indices"]
    with pytest.raises(ValueError, match="fresh materialization"):
        owned._report_after_fresh_read(raw + b" ", owner)
    with pytest.raises(TypeError, match="immutable"):
        owned.raw = raw + b" "


def test_owned_path_parses_and_canonicalizes_materialization_once(context, monkeypatch):
    pa(context)
    value = copy.deepcopy(context.events[0])
    raw = observer.canonical(context.fact)
    owner = object()
    original_loads, original_dumps = observer.json.loads, observer.json.dumps
    counts = {"parse": 0, "canonical": 0}

    def loads(data, *args, **kwargs):
        if data == raw:
            counts["parse"] += 1
        return original_loads(data, *args, **kwargs)

    def dumps(data, *args, **kwargs):
        if isinstance(data, dict) and data.get("schema") == context.fact["schema"]:
            counts["canonical"] += 1
        return original_dumps(data, *args, **kwargs)

    monkeypatch.setattr(observer.json, "loads", loads)
    monkeypatch.setattr(observer.json, "dumps", dumps)
    owned = observer._own_materialization(raw, owner)
    owned._compact_after_tensor_check(owner)
    assert observer._verify_owned_observation(value, owned, raw, owner)[
        "source_argument_completion_relation"
    ]
    owned._release_operator_tree(owner)
    owned._report_after_fresh_read(raw, owner)
    assert counts == {"parse": 1, "canonical": 1}


def test_owned_original_identity_digest_hashes_raw_only_at_constructor(
    context, monkeypatch
):
    value, raw, owner, _ = owned_case(context)
    original_sha = observer.sha
    calls = []

    def counted_sha(data):
        if data == raw:
            calls.append(data)
        return original_sha(data)

    monkeypatch.setattr(observer, "sha", counted_sha)
    owned = observer._own_materialization(raw, owner)
    assert owned._original_digest(raw, owner) == original_sha(raw)
    assert observer._verify_owned_observation(value, owned, raw, owner)[
        "source_argument_completion_relation"
    ]
    different_object = bytes(bytearray(raw))
    assert different_object == raw and different_object is not raw
    with pytest.raises(ValueError, match="original owned"):
        owned._original_digest(different_object, owner)
    with pytest.raises(ValueError, match="original owned"):
        observer._verify_owned_observation(value, owned, different_object, owner)
    owned._release_operator_tree(owner)
    # The caller independently hashes this newly read bytes object first.
    assert original_sha(different_object) == original_sha(raw)
    assert owned._report_after_fresh_read(different_object, owner)["binding"] == (
        context.fact["binding"]
    )
    assert len(calls) == 1
