from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from vllm_hust_ext import activation_profile as profile_api
from vllm_hust_ext import runtime_activation as activation


@pytest.fixture
def installation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for name in (
        profile_api.PATH_ENV,
        profile_api.SHA_ENV,
        profile_api.ENABLE_ENV,
        profile_api.CONFIG_ENV,
        "ECPA_ACTIVATION_CONTRACT",
        activation.MANUAL_BOOTSTRAP_FLAG,
        "VLLM_PLUGINS",
        "VLLMHUST_EXT_ENABLED_BUNDLES",
        "PYTHONPATH",
    ):
        # Record an undo even when configure_activation later adds an absent key.
        monkeypatch.setenv(name, os.environ.get(name, ""))
        monkeypatch.delenv(name, raising=False)
    package = tmp_path / "vllm_ascend_kvcompress"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "config.py").write_text(
        "import os,json\n"
        "def extension_enabled():\n"
        '    return os.getenv("VLLM_ASCEND_KVCOMPRESS_ENABLED")=="1"\n'
        "def load_runtime_selection():\n"
        '    return json.loads(os.environ["VLLM_ASCEND_KVCOMPRESS_CONFIG"])\n'
    )
    (package / "plugin.py").write_text(
        "from .config import extension_enabled,load_runtime_selection\n"
        "observed=[]\n"
        "def register():\n"
        "    if not extension_enabled(): return\n"
        "    observed.append(load_runtime_selection())\n"
    )
    info = tmp_path / "vllm_ascend_kvcompress_hust-0.9.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_text(
        "Name: vllm-ascend-kvcompress-hust\nVersion: 0.9.0\n"
    )
    ep_text = (
        "[vllm.general_plugins]\n"
        "ascend_kvcompress = vllm_ascend_kvcompress.plugin:register\n"
    )
    (info / "entry_points.txt").write_text(ep_text)
    calibration = tmp_path / "calibration.pt"
    calibration.write_bytes(b"frozen CPU fixture")

    def ref(path):
        return {
            "path": str(path),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }

    value = {
        "schema": profile_api.SCHEMA,
        "extension_id": profile_api.EXTENSION_ID,
        "entry_point": {
            "group": profile_api.GROUP,
            "name": profile_api.NAME,
            "value": profile_api.VALUE,
        },
        "distribution": {
            "name": profile_api.DISTRIBUTION,
            "version": "0.9.0",
            "entry_points_sha256": hashlib.sha256(ep_text.encode()).hexdigest(),
        },
        "sources": {
            role: ref(tmp_path / relative)
            for role, relative in profile_api.SOURCES.items()
        },
        "configuration": {
            "schema_version": 1,
            "provider": "ascend_kvcompress",
            "method": "triattention",
            "method_config": {
                "auto_calibrate": False,
                "stats_path": str(calibration),
                "kv_budget": 1024,
            },
        },
        "calibration": ref(calibration),
    }
    path = tmp_path / "profile.json"
    path.write_bytes(profile_api.canonical(value))
    monkeypatch.syspath_prepend(str(tmp_path))
    for name in (
        "vllm_ascend_kvcompress",
        "vllm_ascend_kvcompress.plugin",
        "vllm_ascend_kvcompress.config",
    ):
        monkeypatch.delitem(sys.modules, name, raising=False)
    profile = profile_api.load_activation_profile(
        path, hashlib.sha256(path.read_bytes()).hexdigest()
    )
    yield profile, tmp_path, info, calibration
    for name in (
        "vllm_ascend_kvcompress",
        "vllm_ascend_kvcompress.plugin",
        "vllm_ascend_kvcompress.config",
    ):
        sys.modules.pop(name, None)


def fake_host(monkeypatch):
    plugins = ModuleType("vllm.plugins")
    plugins.plugins_loaded = False
    plugins._plugins_loaded_pid = None
    plugins._fork_reinitializers = {}
    plugins._plugin_values = {}
    plugins.load_general_plugins = lambda: None
    plugins.load_plugins_by_group = lambda **kw: {}
    plugins._invoke_general_plugin = lambda name, function: function()
    evidence = ModuleType("vllm.plugins.evidence")
    evidence._emit_host_event = lambda *args, **kw: None
    monkeypatch.setitem(sys.modules, "vllm.plugins", plugins)
    monkeypatch.setitem(sys.modules, "vllm.plugins.evidence", evidence)
    return plugins


@pytest.mark.parametrize(
    "contract", ["entry-points-unmanaged", "explicit-manual-hooks"]
)
def test_both_arms_invoke_actual_pinned_entry_with_same_direct_provider(
    installation, monkeypatch, contract
):
    profile, _, _, _ = installation
    plugins = fake_host(monkeypatch)
    monkeypatch.setenv("VLLM_PLUGINS", "ascend,ascend_kvcompress")
    activation.configure_activation(contract, profile=profile)
    assert os.environ[profile_api.ENABLE_ENV] == "1"
    assert json.loads(os.environ[profile_api.CONFIG_ENV]) == profile.configuration
    assert "VLLMHUST_EXT_ENABLED_BUNDLES" not in os.environ
    if contract == "entry-points-unmanaged":
        assert os.environ["VLLM_PLUGINS"] == "ascend,ascend_kvcompress"
        # Stock entry-point discovery, rather than the manual helper.
        matches = [
            ep
            for ep in importlib.metadata.entry_points(group=profile_api.GROUP)
            if ep.name == profile_api.NAME
        ]
        matches[0].load()()
    else:
        assert os.environ["VLLM_PLUGINS"] == "ascend"
        plugins.load_general_plugins()
    module = importlib.import_module("vllm_ascend_kvcompress.plugin")
    assert module.observed == [profile.configuration]
    assert (
        activation.probe_receipt(contract, profile=profile)["selected_kv_profile"][
            "formal_result"
        ]
        is False
    )


@pytest.mark.parametrize(
    "drift",
    ["enable", "config", "calibration", "source", "metadata", "version", "profile"],
)
def test_binding_drift_fails_closed(installation, monkeypatch, drift):
    profile, root, info, calibration = installation
    if drift == "enable":
        monkeypatch.setenv(profile_api.ENABLE_ENV, "0")
    if drift == "config":
        monkeypatch.setenv(profile_api.CONFIG_ENV, "{}")
    if drift == "calibration":
        calibration.write_bytes(b"replaced")
    if drift == "source":
        (root / "vllm_ascend_kvcompress/plugin.py").write_text("def register(): pass\n")
    if drift == "metadata":
        (info / "entry_points.txt").write_text(
            "[vllm.general_plugins]\nascend_kvcompress = other:register\n"
        )
    if drift == "version":
        (info / "METADATA").write_text(
            "Name: vllm-ascend-kvcompress-hust\nVersion: 0.9.1\n"
        )
    if drift == "profile":
        profile.path.write_bytes(profile.raw + b" ")
    with pytest.raises(ValueError):
        activation.configure_activation("entry-points-unmanaged", profile=profile)


def test_manual_revalidates_provider_even_after_same_pid_loaded(
    installation, monkeypatch
):
    profile, _, _, _ = installation
    plugins = fake_host(monkeypatch)
    activation.configure_activation("explicit-manual-hooks", profile=profile)
    plugins.load_general_plugins()
    monkeypatch.setenv(profile_api.CONFIG_ENV, "{}")
    with pytest.raises(ValueError, match="configuration differs"):
        plugins.load_general_plugins()


def test_manual_rejects_foreign_callable_even_with_same_name(installation, monkeypatch):
    profile, _, _, _ = installation
    fake_host(monkeypatch)
    module = importlib.import_module("vllm_ascend_kvcompress.plugin")
    module.register = lambda: None
    with pytest.raises(RuntimeError, match="pinned source"):
        activation._target_callable(profile)


def test_spawn_loads_same_profile_and_actual_enabled_callable(
    installation, monkeypatch
):
    profile, root, _, _ = installation
    fake_host(monkeypatch)
    fake = root / "vllm"
    fake.mkdir()
    (fake / "__init__.py").write_text("")
    (fake / "plugins.py").write_text(
        "plugins_loaded=False\n_plugins_loaded_pid=None\n_fork_reinitializers={}\n_plugin_values={}\n"
        "def load_general_plugins(): pass\n"
        "def load_plugins_by_group(*,group): return {}\n"
        "def _invoke_general_plugin(name,function): function()\n"
    )
    # evidence is a package child in the real Host.
    (fake / "plugins").mkdir()
    (fake / "plugins" / "__init__.py").write_text((fake / "plugins.py").read_text())
    (fake / "plugins" / "evidence.py").write_text(
        "def _emit_host_event(*args,**kwargs): pass\n"
    )
    activation.configure_activation("explicit-manual-hooks", profile=profile)
    source = Path(activation.__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([env["PYTHONPATH"], str(root), str(source)])
    script = (
        "import vllm.plugins as p; p.load_general_plugins(); "
        "import vllm_ascend_kvcompress.plugin as k; import json; "
        "print(json.dumps(k.observed))"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout) == [profile.configuration]
    missing = dict(env)
    missing.pop(profile_api.PATH_ENV)
    missing.pop(profile_api.SHA_ENV)
    result = subprocess.run(
        [sys.executable, "-c", "print('UNBOUND_CHILD_CONTINUED')"],
        env=missing,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "UNBOUND_CHILD_CONTINUED" not in result.stdout
    assert "manual activation bootstrap is not authorized" in result.stderr
    profile.path.write_bytes(profile.raw + b" ")
    result = subprocess.run(
        [sys.executable, "-c", script], env=env, capture_output=True, text=True
    )
    assert result.returncode != 0
    assert "profile digest differs" in result.stderr


def test_profile_cannot_select_manager_contract(installation):
    profile, _, _, _ = installation
    with pytest.raises(ValueError, match="Manager-disabled"):
        activation.configure_activation(
            "manager-controlled-activation", profile=profile
        )


def test_vanilla_spawn_validates_profile_without_patching_stock_loader(installation):
    profile, root, _, _ = installation
    fake = root / "vllm"
    fake.mkdir()
    (fake / "__init__.py").write_text("")
    (fake / "plugins.py").write_text("def load_general_plugins(): pass\n")
    activation.configure_activation("entry-points-unmanaged", profile=profile)
    source = Path(activation.__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([env["PYTHONPATH"], str(root), str(source)])
    script = (
        "import vllm.plugins as p; "
        "assert not hasattr(p.load_general_plugins,'__ecpa_manager_contract__'); "
        "import importlib.metadata as m; "
        "[e for e in m.entry_points(group='vllm.general_plugins') "
        "if e.name=='ascend_kvcompress'][0].load()(); "
        "import vllm_ascend_kvcompress.plugin as k; import json; "
        "print(json.dumps(k.observed))"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout) == [profile.configuration]
    env[profile_api.CONFIG_ENV] = "{}"
    result = subprocess.run(
        [sys.executable, "-c", script], env=env, capture_output=True, text=True
    )
    assert result.returncode != 0
    assert "configuration differs" in result.stderr
