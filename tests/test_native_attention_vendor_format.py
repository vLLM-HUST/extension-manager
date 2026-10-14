"""Execute pinned actual vendor enum/patch source on CPU; no NPU facts."""

from __future__ import annotations

import ast
import copy
import gzip
import hashlib
import importlib
import json
import sys
import types
from enum import IntEnum
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
from test_native_attention_source_candidate import context as source_context
from test_native_attention_source_candidate import pa

from experiments.native_attention_candidate import operator_observer

context = source_context


@pytest.fixture
def vendor(monkeypatch, tmp_path):
    root = Path(operator_observer.__file__).parent / "source"
    binding = json.loads((root / "format-binding.json").read_bytes())
    raw = gzip.decompress((root / binding["snapshot"]).read_bytes())
    assert hashlib.sha256(raw).hexdigest() == binding["sha256"]
    nodes = [
        node
        for node in ast.parse(raw).body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef))
    ]
    module = types.ModuleType("torch_npu.npu._format")
    source_path = tmp_path / "_format.py"
    source_path.write_bytes(raw)
    module.__file__ = str(source_path)
    module.IntEnum = IntEnum
    native_package = types.ModuleType("torch_npu")
    npu_package = types.ModuleType("torch_npu.npu")
    native_package.npu = npu_package
    npu_package._format = module
    native_package.get_npu_format = lambda tensor: tensor.view["npu_format"]
    module.torch_npu = native_package
    monkeypatch.setitem(sys.modules, "torch_npu", native_package)
    monkeypatch.setitem(sys.modules, "torch_npu.npu", npu_package)
    exec(
        compile(
            ast.Module(body=nodes, type_ignores=[]), "pinned-vendor-format", "exec"
        ),
        module.__dict__,
    )
    module._apply_npu_format_patch()
    monkeypatch.setitem(sys.modules, "torch_npu.npu._format", module)
    return module


def test_exact_vendor_source_enum_and_patched_getter_are_canonicalized(vendor):
    observer = importlib.reload(operator_observer)
    for member in vendor.Format:
        if member is vendor.Format.UNDEFINED:
            continue
        actual = vendor.torch_npu.get_npu_format(NS(view={"npu_format": int(member)}))
        assert type(actual) is vendor.Format and type(actual) is not int
        assert type(observer.canonical_native_format(actual)) is int
        assert observer.canonical_native_format(
            actual
        ) == observer.canonical_native_format(int(member))
    with pytest.raises(observer.SourceObservationRejected):
        observer.canonical_native_format(vendor.Format.UNDEFINED)


def test_actual_vendor_getter_type_passes_pinned_native_source_without_wire_enum(
    context, vendor
):
    c = context
    c.observer._get_format = vendor.torch_npu.get_npu_format
    pa(c)
    actual = c.events[0]["native_arguments"]["cache_views"]
    assert all(
        type(view["npu_format"]) is int and view["npu_format"] == 2
        for view in actual.values()
    )
    assert c.observer.verify_observation(c.events[0], c.fact)[
        "source_argument_completion_relation"
    ]


@pytest.mark.parametrize("value", [True, False, 2.0, "2", -1, 999])
def test_wrong_python_types_and_unknown_codes_keep_real_bounded_rejection(
    value, vendor
):
    observer = importlib.reload(operator_observer)
    with pytest.raises(observer.SourceObservationRejected) as caught:
        observer.canonical_native_format(value)
    diagnostic = caught.value.diagnostic
    assert diagnostic["OP_receipt"] is False
    assert len(str(caught.value)) < 8192
    assert (
        diagnostic["actual_fields"]["npu_format"]["python_type"]
        == type(value).__module__ + "." + type(value).__qualname__
    )
    assert diagnostic["actual_fields"]["npu_format"]["value_repr"] == repr(value)


def test_foreign_enum_is_not_vendor_format(vendor):
    class OtherFormat(IntEnum):
        ND = 2

    with pytest.raises(operator_observer.SourceObservationRejected):
        operator_observer.canonical_native_format(OtherFormat.ND)


def test_reference_format_and_pointer_guards_keep_bounded_actual_descriptors(
    context, vendor
):
    c = context
    c.observer._get_format = vendor.torch_npu.get_npu_format
    c.tensors["K"].view = dict(c.tensors["K"].view, npu_format=30)
    with pytest.raises(c.observer.SourceObservationRejected) as caught:
        pa(c)
    diagnostic = caught.value.diagnostic
    assert diagnostic["stage"] == "after-native-completion-validation"
    assert diagnostic["actual_fields"]["actual.K"]["npu_format"]["value_repr"] == "30"
    assert diagnostic["actual_fields"]["reference.K"]["npu_format"]["value_repr"] == "2"
    assert not c.events
    assert len(c.calls) == len(c.completions) == 1


def test_portable_unknown_format_cannot_match_itself_by_rehash(context, vendor):
    c = context
    pa(c)
    changed, materialization = copy.deepcopy(c.events[0]), copy.deepcopy(c.fact)
    for kind in ("K", "V"):
        materialization["cache_views"][kind]["after"]["npu_format"] = 999
        changed["native_arguments"]["cache_views"][kind]["npu_format"] = 999
        changed["native_argument_descriptors"][
            "key_cache" if kind == "K" else "value_cache"
        ]["view"]["npu_format"] = 999
    changed["source_materialization_sha256"] = c.observer.sha(
        c.observer.canonical(materialization)
    )
    changed["native_argument_descriptors_sha256"] = c.observer.sha(
        c.observer.canonical(changed["native_argument_descriptors"])
    )
    with pytest.raises(ValueError, match="fields/types"):
        c.observer.verify_observation(changed, materialization)


def test_changed_actual_vendor_source_bytes_cannot_normalize_enum(vendor):
    Path(vendor.__file__).write_text("# changed source after declaration\n")
    with pytest.raises(ValueError, match="source bytes changed"):
        operator_observer.canonical_native_format(vendor.Format.ND)


def test_new_host_only_format_patch_applies_exactly(tmp_path):
    import subprocess

    from experiments.native_attention_candidate import (
        build_format_boundary_patch as fix,
    )

    before, after = fix.source_pair()
    manifest = fix.emit(tmp_path / "patch")
    module = tmp_path / "host" / fix.MODULE
    module.parent.mkdir(parents=True)
    module.write_bytes(before)
    subprocess.run(
        ["git", "apply", "--check", str(tmp_path / "patch/host.patch")],
        cwd=tmp_path / "host",
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "apply", str(tmp_path / "patch/host.patch")],
        cwd=tmp_path / "host",
        check=True,
        capture_output=True,
    )
    assert module.read_bytes() == after
    assert manifest["Host_base_commit"] == "a222df060a364a4cce88f39b583f50ea87ef2749"
    assert (
        manifest["required_vendor_source_files"][0]["sha256"]
        == operator_observer._VENDOR_FORMAT_SOURCE_SHA256
    )
    assert manifest["Ascend_source_changed"] is False
    assert manifest["known_format_codes_are_layout_support"] is False
