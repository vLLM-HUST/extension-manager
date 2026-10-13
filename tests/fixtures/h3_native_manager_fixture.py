"""CPU-only provider/config fixture using the actual Manager CLI and supervisor.

Provider discovery/checks are fixture inputs; native mint, Unix handoff, CLI
parsing and process supervision are the real implementation. No Host is faked.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace

from vllm_hust_ext import cli, runtime_phase_handoff
from vllm_hust_ext.config import ExtensionConfig, UserConfig
from vllm_hust_ext.core import LifecycleState
from vllm_hust_ext.manifest import BundleActivation
from vllm_hust_ext.providers.base import ProviderPlan

extension = "org.example.cpu-fixture"
bundle = SimpleNamespace(
    bundle_id=extension,
    manifest_path=Path("/cpu-fixture/manifest.json"),
    manifest=SimpleNamespace(
        host=SimpleNamespace(provider="vllm"),
        runtime=SimpleNamespace(isolation="trusted_in_process"),
        activation=BundleActivation(),
        implementation=(),
        bundle_version="1.0",
    ),
)
cli.load_config = lambda: UserConfig({extension: ExtensionConfig(enabled=True)})
cli.discover_bundles = lambda *args: (bundle,)
cli.status_for = lambda *args: SimpleNamespace(
    states=(LifecycleState.COMPATIBLE,), evidence=("CPU fixture provider only",)
)
cli.plan_for = lambda *args: ProviderPlan(extension, "vllm", ())
if os.environ.get("FIXTURE_BAD_PUBLISHER"):
    actual_identity = runtime_phase_handoff.process_identity
    runtime_phase_handoff.process_identity = lambda pid: {
        **actual_identity(pid),
        "pid": pid + 1,
    }
worker = Path(__file__).with_name("h3_worker_relaunch_fixture.py")
raise SystemExit(
    cli.main(
        [
            "run",
            "--phase-binding-socket",
            sys.argv[1],
            "--shutdown-grace-seconds",
            "1",
            "--",
            sys.executable,
            str(worker),
        ]
    )
)
