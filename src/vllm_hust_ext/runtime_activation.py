"""Manager-owned launch contracts for an unmodified vLLM-HUST host.

The formal baseline arms must differ in how the same installed MOD callable is
reached.  This module keeps that distinction in the Manager package so the
study does not depend on unpublished Host or MOD launcher commits.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import inspect
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from vllm_hust_ext import activation_profile as profiles

ENTRY_POINT_GROUP = "vllm.general_plugins"
ENTRY_POINT_NAME = "kv_materialization"
ENTRY_POINT_VALUE = "vllm_kv_materialization.plugin:register_plugin"
EXTENSION_ID = "org.vllm-hust.kv-materialization-arrival-control"
MANUAL_BOOTSTRAP_FLAG = "ECPA_MANAGER_MANUAL_BOOTSTRAP"
MANUAL_BOOTSTRAP_VALUE = "v1:kv_materialization"
FORMAL_PROBE = "--ecpa-formal-activation-probe"
VANILLA_OPTIONS = ("--disable-ecpa-manager", "--enable-entrypoints")
MANUAL_OPTIONS = ("--disable-ecpa-manager", "--manual-hooks")
FORMAL_OPTIONS = frozenset((*VANILLA_OPTIONS, *MANUAL_OPTIONS, FORMAL_PROBE))


def _merge_csv(existing: str | None, value: str) -> str:
    values = [] if existing is None else [item.strip() for item in existing.split(",")]
    retained = [item for item in values if item and item != value]
    return ",".join((*retained, value))


def _remove_csv(existing: str | None, value: str) -> str:
    values = [] if existing is None else [item.strip() for item in existing.split(",")]
    return ",".join(item for item in values if item and item != value)


def parse_activation(argv: list[str]) -> tuple[str, list[str], bool]:
    """Consume exactly one formal arm contract and leave vLLM arguments."""
    present = [item for item in argv if item in FORMAL_OPTIONS]
    if len(present) != len(set(present)):
        raise ValueError("formal activation options must not be repeated")
    cleaned = [item for item in argv if item not in FORMAL_OPTIONS]
    probe = FORMAL_PROBE in present
    selected = set(present) - {FORMAL_PROBE}
    if selected == set(VANILLA_OPTIONS):
        return "entry-points-unmanaged", cleaned, probe
    if selected == set(MANUAL_OPTIONS):
        return "explicit-manual-hooks", cleaned, probe
    if not selected and os.getenv("ECPA_ACTIVATION_CONTRACT") == (
        "manager-controlled-activation"
    ):
        if probe:
            raise ValueError("manager-controlled activation has no target-side probe")
        return "manager-controlled-activation", cleaned, False
    raise ValueError("exactly one supported formal activation contract is required")


def probe_receipt(
    contract: str, *, profile: profiles.ActivationProfile | None = None
) -> dict[str, Any]:
    required = {
        "entry-points-unmanaged": VANILLA_OPTIONS,
        "explicit-manual-hooks": MANUAL_OPTIONS,
    }[contract]
    if profile is not None:
        return {
            "accepted_options": sorted(required),
            "activation_contract": contract,
            "schema": "ecpa-activation-probe/v2",
            "selected_kv_profile": profile.receipt(),
        }
    return {
        "accepted_options": sorted(required),
        "activation_contract": contract,
        "schema": "ecpa-activation-probe/v1",
    }


def _bootstrap_directory() -> Path:
    value = Path(__file__).resolve().parent / "manual_bootstrap"
    if not value.is_dir() or not (value / "sitecustomize.py").is_file():
        raise RuntimeError("Manager manual bootstrap is not installed")
    return value


def _inherit_bootstrap() -> None:
    bootstrap = str(_bootstrap_directory())
    inherited = os.getenv("PYTHONPATH")
    components = [] if inherited is None else inherited.split(os.pathsep)
    os.environ["PYTHONPATH"] = os.pathsep.join(
        [bootstrap, *(item for item in components if item and item != bootstrap)]
    )


def configure_activation(
    contract: str, *, profile: profiles.ActivationProfile | None = None
) -> None:
    """Set the inherited process contract before vLLM imports or spawns."""
    if profile is not None:
        if contract not in {"entry-points-unmanaged", "explicit-manual-hooks"}:
            raise ValueError(
                "selected-KV profile only supports Manager-disabled baselines"
            )
        profile.bind_environment()
        _inherit_bootstrap()
    target_name = ENTRY_POINT_NAME if profile is None else profiles.NAME
    observed = os.getenv("ECPA_ACTIVATION_CONTRACT")
    if observed is not None and observed != contract:
        raise ValueError("runner and Manager activation contracts differ")
    os.environ["ECPA_ACTIVATION_CONTRACT"] = contract
    if contract in {"entry-points-unmanaged", "manager-controlled-activation"}:
        os.environ["VLLM_PLUGINS"] = _merge_csv(os.getenv("VLLM_PLUGINS"), target_name)
        os.environ.pop(MANUAL_BOOTSTRAP_FLAG, None)
        if contract == "manager-controlled-activation":
            os.environ["VLLMHUST_EXT_ENABLED_BUNDLES"] = _merge_csv(
                os.getenv("VLLMHUST_EXT_ENABLED_BUNDLES"), EXTENSION_ID
            )
        else:
            os.environ.pop("VLLMHUST_EXT_ENABLED_BUNDLES", None)
        return
    if contract != "explicit-manual-hooks":
        raise ValueError("unsupported activation contract")
    selected = _remove_csv(os.getenv("VLLM_PLUGINS"), target_name)
    if selected:
        os.environ["VLLM_PLUGINS"] = selected
    else:
        # An empty allowlist suppresses every entry point, including the target.
        os.environ["VLLM_PLUGINS"] = ""
    if profile is None:
        os.environ["VLLMHUST_EXT_ENABLED_BUNDLES"] = _merge_csv(
            os.getenv("VLLMHUST_EXT_ENABLED_BUNDLES"), EXTENSION_ID
        )
    else:
        os.environ.pop("VLLMHUST_EXT_ENABLED_BUNDLES", None)
    os.environ[MANUAL_BOOTSTRAP_FLAG] = (
        MANUAL_BOOTSTRAP_VALUE if profile is None else profile.marker
    )
    _inherit_bootstrap()
    install_manual_activation(profile=profile)


def _target_callable(
    profile: profiles.ActivationProfile | None = None,
) -> Callable[[], Any]:
    if profile is not None:
        profile.validate_installed()
    target_value = ENTRY_POINT_VALUE if profile is None else profiles.VALUE
    module_name, attribute = target_value.split(":", 1)
    module = importlib.import_module(module_name)
    candidate = getattr(module, attribute)
    if not callable(candidate):
        raise TypeError("manual activation target is not callable")
    if profile is not None:
        expected = profile.value()["sources"]["plugin"]["path"]
        if (
            getattr(module, "__file__", None) != expected
            or inspect.getsourcefile(candidate) != expected
            or getattr(candidate, "__module__", None) != module_name
            or getattr(candidate, "__name__", None) != attribute
        ):
            raise RuntimeError(
                "imported selected-KV callable differs from pinned source"
            )
    return cast(Callable[[], Any], candidate)


def _installed_target(profile: profiles.ActivationProfile | None = None) -> None:
    if profile is not None:
        profile.validate_installed()
        return
    matches = [
        item
        for item in importlib.metadata.entry_points(group=ENTRY_POINT_GROUP)
        if item.name == ENTRY_POINT_NAME
    ]
    if len(matches) != 1 or matches[0].value != ENTRY_POINT_VALUE:
        raise RuntimeError("installed manual activation target differs from contract")


def install_manual_activation(
    *, profile: profiles.ActivationProfile | None = None
) -> None:
    """Patch the stock Host loader before it captures its callable reference."""
    marker = MANUAL_BOOTSTRAP_VALUE if profile is None else profile.marker
    target_name = ENTRY_POINT_NAME if profile is None else profiles.NAME
    target_value = ENTRY_POINT_VALUE if profile is None else profiles.VALUE
    if profile is not None:
        profile.bind_environment()
    if os.getenv(MANUAL_BOOTSTRAP_FLAG) != marker:
        raise RuntimeError("manual activation bootstrap is not authorized")
    if os.getenv("ECPA_ACTIVATION_CONTRACT") != "explicit-manual-hooks":
        raise RuntimeError("manual activation contract is not bound")
    plugins: Any = importlib.import_module("vllm.plugins")

    current = getattr(plugins.load_general_plugins, "__ecpa_manager_contract__", None)
    if current == marker:
        return
    if current is not None:
        raise RuntimeError("vLLM general plugin loader is already patched")

    def load_general_plugins() -> None:
        if profile is not None:
            profile.bind_environment()
        process_id = os.getpid()
        if plugins.plugins_loaded:
            if plugins._plugins_loaded_pid == process_id:
                return
            plugins._plugins_loaded_pid = process_id
            for name, function in plugins._fork_reinitializers.items():
                plugins._invoke_general_plugin(name, function)
            return
        plugins.plugins_loaded = True
        plugins._plugins_loaded_pid = process_id
        plugins._fork_reinitializers.clear()

        _installed_target(profile)
        loaded = plugins.load_plugins_by_group(group=ENTRY_POINT_GROUP)
        if target_name in loaded:
            raise RuntimeError("manual target was also selected through entry points")
        manual = _target_callable(profile)
        evidence = importlib.import_module("vllm.plugins.evidence")

        plugins._plugin_values[(ENTRY_POINT_GROUP, target_name)] = target_value
        evidence._emit_host_event(
            "resolved",
            ENTRY_POINT_GROUP,
            target_name,
            target_value,
            detail=(
                "manager-explicit-callable"
                if profile is None
                else "baseline-explicit-callable"
            ),
        )
        for name, function in (*loaded.items(), (target_name, manual)):
            plugins._invoke_general_plugin(name, function)
            if getattr(function, "__vllm_reinit_after_fork__", False) is True:
                plugins._fork_reinitializers[name] = function

    load_general_plugins.__ecpa_manager_contract__ = marker  # type: ignore[attr-defined]
    plugins.load_general_plugins = load_general_plugins


def install_manual_activation_from_environment() -> None:
    """Entry used by the isolated sitecustomize directory in child processes."""
    manual = os.getenv(MANUAL_BOOTSTRAP_FLAG)
    selected = (
        os.getenv(profiles.PATH_ENV) is not None
        or os.getenv(profiles.SHA_ENV) is not None
        or (manual is not None and manual.startswith("v2:selected-kv:"))
    )
    if manual is None and not selected:
        return
    try:
        profile = profiles.profile_from_environment()
        if manual is None:
            if os.getenv("ECPA_ACTIVATION_CONTRACT") != "entry-points-unmanaged":
                raise RuntimeError("selected-KV spawned baseline contract differs")
            assert profile is not None
            profile.bind_environment()
            return  # Keep the stock Host loader unchanged in vanilla.
        install_manual_activation(profile=profile)
    except Exception as exc:
        if selected:
            # site.py swallows ordinary sitecustomize exceptions. An explicit
            # profile must never continue with an unpatched child Host.
            raise SystemExit(str(exc)) from exc
        raise


def main() -> None:
    try:
        contract, arguments, probe = parse_activation(sys.argv[1:])
        profile = profiles.profile_from_environment()
        if probe:
            print(
                json.dumps(
                    probe_receipt(contract, profile=profile),
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            return
        configure_activation(contract, profile=profile)
    except (RuntimeError, TypeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
    vllm_main = importlib.import_module("vllm.entrypoints.cli.main").main

    sys.argv[1:] = arguments
    vllm_main()


if __name__ == "__main__":
    main()
