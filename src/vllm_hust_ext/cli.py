"""Command-line lifecycle manager."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

from vllm_hust_ext.config import ExtensionConfig, load_config, save_config
from vllm_hust_ext.core import plan_dict, plan_for, render_plan, status_for
from vllm_hust_ext.discovery import InstalledBundle, discover_bundles
from vllm_hust_ext.providers.base import ProviderPlan


def _bundle_dict(bundle: InstalledBundle, enabled: set[str]) -> dict[str, object]:
    return {
        "bundle_id": bundle.bundle_id,
        "bundle_version": bundle.manifest.bundle_version,
        "distribution": bundle.distribution_name,
        "distribution_version": bundle.distribution_version,
        "enabled": bundle.bundle_id in enabled,
        "kind": bundle.manifest.kind,
        "host": asdict(bundle.manifest.host),
        "runtime": asdict(bundle.manifest.runtime),
        "lifecycle_owner": bundle.manifest.lifecycle_owner,
        "requires_services": [
            asdict(service) for service in bundle.manifest.requires_services
        ],
        "experimental": bundle.manifest.experimental,
        "components": [asdict(component) for component in bundle.manifest.components],
        "activation": asdict(bundle.manifest.activation),
        "manifest_path": str(bundle.manifest_path),
    }


def _activation_environment(bundles: Sequence[InstalledBundle]) -> dict[str, str]:
    environment: dict[str, str] = {}
    for bundle in bundles:
        for key, value in bundle.manifest.activation.environment:
            if key in environment and environment[key] != value:
                raise ValueError(
                    f"enabled Bundles disagree on environment variable {key}"
                )
            environment[key] = value
    environment["VLLM_HUST_EXT_ENABLED_BUNDLES"] = ",".join(
        bundle.bundle_id for bundle in bundles
    )
    return environment


def _activation_config(bundles: Sequence[InstalledBundle]) -> dict[str, object]:
    merged: dict[str, object] = {}
    for bundle in bundles:
        for key, value in bundle.manifest.activation.additional_config:
            if key in merged and merged[key] != value:
                raise ValueError(
                    f"enabled Bundles disagree on additional_config key {key}"
                )
            merged[key] = value
    return merged


def _merge_command_config(
    command: list[str], activation: dict[str, object]
) -> list[str]:
    if not activation:
        return command
    result = list(command)
    existing: dict[str, object] = {}
    option_index: int | None = None
    for index, argument in enumerate(result):
        if argument == "--additional-config":
            if index + 1 >= len(result):
                raise ValueError("--additional-config requires a JSON object")
            option_index = index
            raw = result[index + 1]
            break
        if argument.startswith("--additional-config="):
            option_index = index
            raw = argument.partition("=")[2]
            break
    else:
        raw = None
    if raw is not None:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("--additional-config must contain a JSON object")
        existing = parsed
    conflicts = {
        key
        for key, value in activation.items()
        if key in existing and existing[key] != value
    }
    if conflicts:
        raise ValueError(
            "plugin activation conflicts with additional_config keys: "
            f"{sorted(conflicts)}"
        )
    existing.update(activation)
    encoded = json.dumps(existing, separators=(",", ":"), sort_keys=True)
    if option_index is None:
        result.extend(("--additional-config", encoded))
    elif result[option_index] == "--additional-config":
        result[option_index + 1] = encoded
    else:
        result[option_index] = f"--additional-config={encoded}"
    return result


def _extension_command(args: argparse.Namespace) -> int:
    config = load_config()
    enabled = set(config.enabled)
    if args.action == "list":
        bundles = discover_bundles()
        payload = [_bundle_dict(bundle, enabled) for bundle in bundles]
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            for item in payload:
                state = "enabled" if item["enabled"] else "disabled"
                print(f"{item['bundle_id']} {item['bundle_version']} {state}")
        return 0
    if args.action in {"inspect", "validate"}:
        bundle = discover_bundles((args.bundle_id,))[0]
        print(json.dumps(_bundle_dict(bundle, enabled), indent=2, sort_keys=True))
        return 0
    if args.action == "enable":
        discover_bundles((args.bundle_id,))
        current = config.extension(args.bundle_id)
        save_config(
            config.with_extension(
                args.bundle_id,
                ExtensionConfig(True, current.configuration),
            )
        )
        print(f"enabled {args.bundle_id}")
        return 0
    if args.action == "disable":
        current = config.extension(args.bundle_id)
        save_config(
            config.with_extension(
                args.bundle_id,
                ExtensionConfig(False, current.configuration),
            )
        )
        print(f"disabled {args.bundle_id}")
        return 0
    if args.action == "configure":
        discover_bundles((args.bundle_id,))
        configuration = json.loads(Path(args.file).read_text(encoding="utf-8"))
        if not isinstance(configuration, dict):
            raise ValueError("extension configuration file must contain an object")
        current = config.extension(args.bundle_id)
        save_config(
            config.with_extension(
                args.bundle_id,
                ExtensionConfig(current.enabled, configuration),
            )
        )
        print(f"configured {args.bundle_id}")
        return 0
    if args.action in {"status", "check", "plan", "render"}:
        bundle = discover_bundles((args.bundle_id,))[0]
        extension = config.extension(args.bundle_id)
        if args.action in {"status", "check"}:
            print(json.dumps(status_for(bundle, extension).as_dict(), indent=2))
            return 0
        plan = plan_for(bundle, extension)
        if args.action == "plan":
            print(json.dumps(plan_dict(plan), indent=2, sort_keys=True))
            return 0
        artifacts = [asdict(artifact) for artifact in render_plan(plan)]
        print(json.dumps(artifacts, indent=2, sort_keys=True))
        return 0
    if args.action == "env":
        bundles = discover_bundles(config.enabled) if config.enabled else ()
        print(json.dumps(_activation_environment(bundles), indent=2, sort_keys=True))
        return 0
    raise AssertionError(args.action)


def _run_command(args: argparse.Namespace) -> int:
    config = load_config()
    bundles = discover_bundles(config.enabled) if config.enabled else ()
    activation = _activation_environment(bundles)
    command = list(args.command or ["vllm"])
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise ValueError("run requires a command after --")
    command = _merge_command_config(command, _activation_config(bundles))
    for bundle in bundles:
        extension = config.extension(bundle.bundle_id)
        plan = plan_for(bundle, extension)
        command = _merge_provider_plan(command, plan)
    if args.dry_run:
        print(json.dumps({"command": command, "environment": activation}, indent=2))
        return 0
    environment = os.environ.copy()
    environment.update(activation)
    return subprocess.call(command, env=environment)


def _merge_provider_plan(command: list[str], plan: ProviderPlan) -> list[str]:
    """Merge a Provider's declared vLLM launch capability without name checks."""

    kv_transfer_config = plan.generated_config.get("kv_transfer_config")
    if kv_transfer_config is not None:
        if not isinstance(kv_transfer_config, dict):
            raise ValueError("provider kv_transfer_config must be a JSON object")
        connector_actions = [
            action
            for action in plan.actions
            if action.operation == "render_connector_config"
            and action.target == "vllm"
            and not action.mutating
        ]
        if len(connector_actions) != 1:
            raise ValueError(
                "provider kv_transfer_config requires one non-mutating "
                "render_connector_config action targeting vllm"
            )
        return _merge_json_option(
            command,
            "--kv-transfer-config",
            kv_transfer_config,
        )
    if plan.provider != "vllm":
        raise ValueError(f"{plan.provider} extensions use plan/render/check, not run")
    return command


def _merge_json_option(
    command: list[str], option: str, generated: dict[str, object]
) -> list[str]:
    result = list(command)
    encoded = json.dumps(generated, separators=(",", ":"), sort_keys=True)
    for index, argument in enumerate(result):
        if argument == option:
            if index + 1 >= len(result):
                raise ValueError(f"{option} requires a JSON object")
            existing = json.loads(result[index + 1])
            if existing != generated:
                raise ValueError(f"extension activation conflicts with {option}")
            return result
        if argument.startswith(f"{option}="):
            existing = json.loads(argument.partition("=")[2])
            if existing != generated:
                raise ValueError(f"extension activation conflicts with {option}")
            return result
    result.extend((option, encoded))
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vllm-hust-ext")
    subcommands = parser.add_subparsers(dest="command_name", required=True)
    extension = subcommands.add_parser("extension")
    extension_subcommands = extension.add_subparsers(dest="action", required=True)
    list_parser = extension_subcommands.add_parser("list")
    list_parser.add_argument("--json", action="store_true")
    for action in (
        "inspect",
        "validate",
        "enable",
        "disable",
        "status",
        "check",
        "plan",
        "render",
    ):
        action_parser = extension_subcommands.add_parser(action)
        action_parser.add_argument("bundle_id")
    configure_parser = extension_subcommands.add_parser("configure")
    configure_parser.add_argument("bundle_id")
    configure_parser.add_argument("--file", required=True)
    extension_subcommands.add_parser("env")
    run_parser = subcommands.add_parser("run")
    run_parser.add_argument("--dry-run", action="store_true")
    run_parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command_name == "extension":
            return _extension_command(args)
        return _run_command(args)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 2
