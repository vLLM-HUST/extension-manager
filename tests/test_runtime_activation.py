from __future__ import annotations

import importlib.metadata
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from vllm_hust_ext import runtime_activation as activation


@pytest.fixture(autouse=True)
def clean_activation_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "ECPA_ACTIVATION_CONTRACT",
        activation.MANUAL_BOOTSTRAP_FLAG,
        "VLLM_PLUGINS",
        "VLLMHUST_EXT_ENABLED_BUNDLES",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize(
    ("options", "contract"),
    [
        (activation.VANILLA_OPTIONS, "entry-points-unmanaged"),
        (activation.MANUAL_OPTIONS, "explicit-manual-hooks"),
    ],
)
def test_activation_probe_is_exact_and_does_not_import_vllm(
    options: tuple[str, str], contract: str
) -> None:
    parsed, arguments, probe = activation.parse_activation(
        ["serve", "model", *options, activation.FORMAL_PROBE]
    )
    assert (parsed, arguments, probe) == (contract, ["serve", "model"], True)
    assert activation.probe_receipt(contract)["entry_point"] == {
        "group": activation.ENTRY_POINT_GROUP,
        "name": activation.ENTRY_POINT_NAME,
        "value": activation.ENTRY_POINT_VALUE,
    }


@pytest.mark.parametrize(
    "options",
    [[], ["--manual-hooks"], [*activation.VANILLA_OPTIONS, "--manual-hooks"]],
)
def test_activation_options_fail_closed(options: list[str]) -> None:
    with pytest.raises(ValueError, match="exactly one"):
        activation.parse_activation(options)


def test_vanilla_uses_stock_entry_point(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VLLM_PLUGINS", "ascend,kv_materialization")
    activation.configure_activation("entry-points-unmanaged")
    assert os.environ["VLLM_PLUGINS"] == "ascend,kv_materialization"
    assert "VLLMHUST_EXT_ENABLED_BUNDLES" not in os.environ
    assert activation.MANUAL_BOOTSTRAP_FLAG not in os.environ


def test_manual_patch_invokes_exact_callable_without_selecting_its_entry_point(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []
    events: list[tuple[str, str | None]] = []
    plugins = ModuleType("vllm.plugins")
    plugins.plugins_loaded = False  # type: ignore[attr-defined]
    plugins._plugins_loaded_pid = None  # type: ignore[attr-defined]
    plugins._fork_reinitializers = {}  # type: ignore[attr-defined]
    plugins._plugin_values = {}  # type: ignore[attr-defined]

    def load_plugins_by_group(*, group: str):
        assert group == activation.ENTRY_POINT_GROUP
        assert activation.ENTRY_POINT_NAME not in os.environ["VLLM_PLUGINS"]
        return {"ascend": lambda: calls.append(("entry-point", "ascend"))}

    def invoke(name: str, function):
        calls.append(("invoke", name))
        function()

    plugins.load_plugins_by_group = load_plugins_by_group  # type: ignore[attr-defined]
    plugins._invoke_general_plugin = invoke  # type: ignore[attr-defined]
    plugins.load_general_plugins = lambda: None  # type: ignore[attr-defined]
    evidence = ModuleType("vllm.plugins.evidence")
    evidence._emit_host_event = (  # type: ignore[attr-defined]
        lambda event, group, name, value, detail=None: events.append((event, detail))
    )
    target = ModuleType("vllm_kv_materialization.plugin")
    target.register_plugin = lambda: calls.append(("manual", "target"))  # type: ignore[attr-defined]
    vllm = ModuleType("vllm")
    vllm.plugins = plugins  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "vllm", vllm)
    monkeypatch.setitem(sys.modules, "vllm.plugins", plugins)
    monkeypatch.setitem(sys.modules, "vllm.plugins.evidence", evidence)
    monkeypatch.setitem(sys.modules, "vllm_kv_materialization.plugin", target)
    entry_point = SimpleNamespace(
        name=activation.ENTRY_POINT_NAME, value=activation.ENTRY_POINT_VALUE
    )
    monkeypatch.setattr(importlib.metadata, "entry_points", lambda **_kw: [entry_point])
    monkeypatch.setattr(activation, "_bootstrap_directory", lambda: Path("/bootstrap"))
    monkeypatch.setenv("VLLM_PLUGINS", "ascend,kv_materialization")

    activation.configure_activation("explicit-manual-hooks")
    plugins.load_general_plugins()  # type: ignore[attr-defined]

    assert calls == [
        ("invoke", "ascend"),
        ("entry-point", "ascend"),
        ("invoke", activation.ENTRY_POINT_NAME),
        ("manual", "target"),
    ]
    assert events == [("resolved", "manager-explicit-callable")]
    assert plugins._plugin_values[  # type: ignore[attr-defined]
        (activation.ENTRY_POINT_GROUP, activation.ENTRY_POINT_NAME)
    ] == activation.ENTRY_POINT_VALUE


def test_isolated_sitecustomize_installs_patch_in_spawned_python(
    tmp_path: Path,
) -> None:
    fake = tmp_path / "vllm"
    fake.mkdir()
    (fake / "__init__.py").write_text("")
    (fake / "plugins.py").write_text(
        "plugins_loaded=False\n"
        "_plugins_loaded_pid=None\n"
        "_fork_reinitializers={}\n"
        "_plugin_values={}\n"
        "def load_general_plugins(): pass\n"
        "def load_plugins_by_group(*, group): return {}\n"
        "def _invoke_general_plugin(name, function): function()\n"
    )
    source = Path(activation.__file__).resolve().parents[1]
    bootstrap = Path(activation.__file__).resolve().parent / "manual_bootstrap"
    environment = dict(os.environ)
    environment.update(
        ECPA_ACTIVATION_CONTRACT="explicit-manual-hooks",
        ECPA_MANAGER_MANUAL_BOOTSTRAP=activation.MANUAL_BOOTSTRAP_VALUE,
        PYTHONPATH=os.pathsep.join((str(bootstrap), str(source), str(tmp_path))),
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import vllm.plugins as p; "
            "print(p.load_general_plugins.__ecpa_manager_contract__)",
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == activation.MANUAL_BOOTSTRAP_VALUE


def test_probe_cli_output_is_canonical(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["ecpa-host-launch", *activation.VANILLA_OPTIONS, activation.FORMAL_PROBE],
    )
    activation.main()
    raw = capsys.readouterr().out
    assert raw == json.dumps(
        activation.probe_receipt("entry-points-unmanaged"),
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"
