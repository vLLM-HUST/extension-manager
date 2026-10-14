"""Emit prospective source drain Host patch; old sources and ELF are unchanged."""

from __future__ import annotations

import argparse
import difflib
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).parent
SNAPSHOT = ROOT / "source/drain-199"


def once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("pinned actual source anchor changed")
    return text.replace(old, new, 1)


def sources():
    binding = json.loads((SNAPSHOT / "binding.json").read_bytes())
    before = {}
    for path, entry in binding["files"].items():
        raw = gzip.decompress((SNAPSHOT / entry["snapshot"]).read_bytes())
        if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise ValueError("pinned Host source bytes changed")
        before[path] = raw.decode()
    after = dict(before)
    p = "vllm/plugins/native_block_table_observer.py"
    after[p] = once(
        after[p],
        "    _observer = observer\n",
        "    from .native_phase_drain import callback_with_drain\n"
        "    _observer = callback_with_drain(observer)\n",
    )
    after[p] = once(
        after[p],
        "        _observer(factory())\n",
        "        return _observer(factory())\n",
    )
    p = "vllm/plugins/native_tensor_artifact_bootstrap.py"
    start = after[p].index("        ack = transport.publish_candidate(\n")
    end = after[p].index("        if is_runtime:\n", start)
    publication = after[p][start:end]
    publication = publication.replace(
        "        ack = transport.publish_candidate(\n",
        "            lambda: transport.publish_candidate(\n",
        1,
    )
    publication = "".join(
        "    " + line if i else line
        for i, line in enumerate(publication.splitlines(True))
    )
    after[p] = (
        after[p][:start]
        + "        from .native_phase_drain import acknowledged_publication\n"
        + "        ack = acknowledged_publication(\n"
        + '            published["binding"]["runtime_request_id"],\n'
        + publication
        + "        )\n"
        + after[p][end:]
    )
    p = "vllm/v1/worker/gpu_model_runner.py"
    after[p] = once(
        after[p],
        "        # Zero GPU memory for freshly allocated cache blocks to prevent\n",
        "        # Opt-in source-owned drain follows actual native removal.\n"
        "        from vllm.plugins.native_phase_drain import (\n"
        "            after_finished_request_removal,\n"
        "        )\n"
        "        from vllm.plugins.native_block_table_observer import (\n"
        "            _scope, emit_native_fact,\n"
        "        )\n"
        "        after_finished_request_removal(\n"
        "            self, scheduler_output, scope=_scope,\n"
        "            publish=lambda fact: emit_native_fact(lambda: fact),\n"
        "        )\n\n"
        "        # Zero GPU memory for freshly allocated cache blocks to prevent\n",
    )
    p = "vllm/plugins/native_phase_drain.py"
    before[p] = ""
    after[p] = (ROOT / "phase_drain.py").read_text()
    for path, body in after.items():
        compile(body, path, "exec")
    return binding, before, after


def emit(output):
    binding, before, after = sources()
    output.mkdir(parents=True, exist_ok=False)
    patch = "".join(
        "".join(
            difflib.unified_diff(
                before[p].splitlines(True),
                after[p].splitlines(True),
                fromfile="a/" + p if before[p] else "/dev/null",
                tofile="b/" + p,
            )
        )
        for p in after
    )
    (output / "host.patch").write_text(patch)
    manifest = dict(
        schema="ecpa-native-source-drain-source-patch/v1",
        Host_base_commit=binding["commit"],
        postimage_sha256={
            p: hashlib.sha256(s.encode()).hexdigest() for p, s in after.items()
        },
        preimage_sha256={
            p: hashlib.sha256(s.encode()).hexdigest() for p, s in before.items() if s
        },
        source_opt_in_environment={"ECPA_NATIVE_PHASE_DRAIN": "1"},
        source_hook="actual-Host-finished-request-and-InputBatch-removal",
        collector_module="experiments.native_attention_candidate.drain_collector",
        collector_mandatory_argument="--drain-policy",
        Ascend_source_changed=False,
        native_ELF_rebuild_required=False,
        fresh_Host_commit_wheel_recipe_nonce_cohort_required=True,
        classification="CPU_SOURCE_CANDIDATE_ONLY",
        formal_registration=False,
        NPU_result=None,
        attention_consumption=None,
        full_model_quality=None,
    )
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    print(json.dumps(emit(parser.parse_args().output)))


if __name__ == "__main__":
    main()
