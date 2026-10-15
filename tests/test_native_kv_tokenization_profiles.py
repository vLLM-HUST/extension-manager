"""CPU-only source-layout binding; no Host import or model execution."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from experiments.native_challenge_candidate import kv_request_runner as kv


class LocalTokenizer:
    def apply_chat_template(self, messages, **kwargs):
        return list(range(1201))

    def encode(self, text, **kwargs):
        return list(range(70))


def installed(monkeypatch, tmp_path, version):
    paths = dict(kv.HOST47_TOKENIZATION_SOURCES)
    for relative in paths:
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("# CPU source fixture: " + relative + "\n")
        paths[relative] = kv.sha(target.read_bytes())
    monkeypatch.setattr(kv, "HOST47_TOKENIZATION_SOURCES", paths)
    host = SimpleNamespace(
        version=version, locate_file=lambda relative: tmp_path / relative
    )
    monkeypatch.setattr(kv.importlib.metadata, "distribution", lambda name: host)
    monkeypatch.setattr(kv.importlib.metadata, "version", lambda name: "CPU-fixture")
    return host


def test_new_main_package_profile_is_exact_and_legacy_layout_is_preserved(
    monkeypatch, tmp_path
):
    host = installed(monkeypatch, tmp_path, kv.HOST47_VERSION)
    binding = kv.runtime_tokenization_binding(LocalTokenizer())
    assert binding["host_tokenization_profile"] == kv.HOST47_PROFILE
    assert binding["host_revision"] == kv.HOST47_REVISION
    assert len(binding["host_sources"]) == 22
    assert "vllm/renderers/chat_utils/__init__.py" in {
        s["relative_path"] for s in binding["host_sources"]
    }
    # Merely finding a package cannot enable this exact-version profile.
    host.version = "0.31.1.post1.dev173+g16bd856.empty"
    with pytest.raises(ValueError, match="source is unavailable"):
        kv.runtime_tokenization_binding(LocalTokenizer())
    old = tmp_path / "vllm/renderers/chat_utils.py"
    old.write_text("# CPU legacy module fixture\n")
    legacy = kv.runtime_tokenization_binding(LocalTokenizer())
    assert "host_tokenization_profile" not in legacy
    assert len(legacy["host_sources"]) == 8
    assert all("relative_path" not in source for source in legacy["host_sources"])
    host.version = kv.HOST47_VERSION
    (tmp_path / "vllm/renderers/chat_utils/chat_message.py").write_text("changed\n")
    with pytest.raises(ValueError, match="module bytes differ"):
        kv.runtime_tokenization_binding(LocalTokenizer())


@pytest.mark.parametrize(
    "mutation", ["version", "revision", "missing", "module", "digest", "downgrade"]
)
def test_frozen_main_profile_rejects_changed_identity_or_source_set(
    monkeypatch, tmp_path, mutation
):
    installed(monkeypatch, tmp_path, kv.HOST47_VERSION)
    source = Path(kv.__file__).resolve()
    refs = [{"path": str(source), "sha256": kv.sha(source.read_bytes())}]
    recipe = kv.make_kv_recipe(
        [("phase", "http://127.0.0.1:29518/v1/chat/completions", "CPU_FIXTURE")],
        refs,
        LocalTokenizer(),
        refs,
        materialized_row=True,
        rpc_budget_s=180,
        prompt_variant=kv.STRICT_COPY,
    )
    kv.validate_kv(recipe)
    binding = recipe["phases"][0]["tokenization"]["runtime_binding"]
    if mutation == "version":
        binding["host_version"] += ".changed"
    elif mutation == "revision":
        binding["host_revision"] = "0" * 40
    elif mutation == "missing":
        binding["host_sources"].pop()
    elif mutation == "module":
        binding["host_sources"][0]["relative_path"] = "vllm/unbound.py"
    elif mutation == "downgrade":
        del binding["host_tokenization_profile"]
        del binding["host_revision"]
        binding["host_sources"] = binding["host_sources"][:8]
    else:
        binding["host_sources"][0]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="profile/version/source binding differs"):
        kv.validate_kv(recipe)
