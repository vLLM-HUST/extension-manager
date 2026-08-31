"""Command-line lifecycle manager."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from collections.abc import Sequence
from dataclasses import asdict, replace

from vllmhust.config import load_config, save_config
from vllmhust.discovery import InstalledBundle, discover_bundles


def _bundle_dict(bundle: InstalledBundle, enabled: set[str]) -> dict[str, object]:
    return {
        "bundle_id": bundle.bundle_id,
        "bundle_version": bundle.manifest.bundle_version,
        "distribution": bundle.distribution_name,
        "distribution_version": bundle.distribution_version,
        "enabled": bundle.bundle_id in enabled,
        "components": [asdict(component) for component in bundle.manifest.components],
        "manifest_path": str(bundle.manifest_path),
    }


def _activation_environment(bundles: Sequence[InstalledBundle]) -> dict[str, str]:
    environment: dict[str, str] = {}
    plugin_names: list[str] = []
    for bundle in bundles:
        for key, value in bundle.manifest.activation.environment:
            if key in environment and environment[key] != value:
                raise ValueError(
                    f"enabled Bundles disagree on environment variable {key}"
                )
            environment[key] = value
        declared = bundle.manifest.activation.entry_points
        if declared:
            plugin_names.extend(entry.name for entry in declared)
        else:
            plugin_names.extend(
                entry.name
                for entry in bundle.entry_points
                if entry.group.startswith("vllm.")
            )
    if plugin_names:
        environment["VLLM_PLUGINS"] = ",".join(dict.fromkeys(plugin_names))
    environment["VLLMHUST_ENABLED_BUNDLES"] = ",".join(
        bundle.bundle_id for bundle in bundles
    )
    return environment


def _plugin_command(args: argparse.Namespace) -> int:
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
        if args.bundle_id not in enabled:
            save_config(replace(config, enabled=config.enabled + (args.bundle_id,)))
        print(f"enabled {args.bundle_id}")
        return 0
    if args.action == "disable":
        save_config(
            replace(
                config,
                enabled=tuple(
                    item for item in config.enabled if item != args.bundle_id
                ),
            )
        )
        print(f"disabled {args.bundle_id}")
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
    command = args.command or ["vllm"]
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise ValueError("run requires a command after --")
    if args.dry_run:
        print(json.dumps({"command": command, "environment": activation}, indent=2))
        return 0
    environment = os.environ.copy()
    environment.update(activation)
    return subprocess.call(command, env=environment)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vllmhust")
    subcommands = parser.add_subparsers(dest="command_name", required=True)
    plugin = subcommands.add_parser("plugin")
    plugin_subcommands = plugin.add_subparsers(dest="action", required=True)
    list_parser = plugin_subcommands.add_parser("list")
    list_parser.add_argument("--json", action="store_true")
    for action in ("inspect", "validate", "enable", "disable"):
        action_parser = plugin_subcommands.add_parser(action)
        action_parser.add_argument("bundle_id")
    plugin_subcommands.add_parser("env")
    run_parser = subcommands.add_parser("run")
    run_parser.add_argument("--dry-run", action="store_true")
    run_parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command_name == "plugin":
            return _plugin_command(args)
        return _run_command(args)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 2
