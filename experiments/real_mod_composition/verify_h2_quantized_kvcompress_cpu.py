"""Verify bounded real provider observations; never score an unknown KV oracle."""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
from pathlib import Path

FREEZE_SHA = "1605caf2dd2ebcd8ace5bba00a85c47588ebe6412799dc7afad6ba67af304e85"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def verify(manifest_path, archive_path):
    m = json.loads(manifest_path.read_bytes())
    require(
        m["schema"] == "ecpa-h2-independent-real-source-pair-cpu/v1"
        and sha(archive_path.read_bytes()) == m["archive_sha256"],
        "archive binding",
    )
    for key, value in {
        "classification": "CPU_PLAN_SURFACE_QUALIFICATION_ONLY",
        "independent_runtime_oracle": "unknown",
        "score_eligible": False,
        "formal_result": False,
        "existing_n4_unchanged": True,
    }.items():
        require(m.get(key) == value, "scientific scope changed")
    files = {}
    with tarfile.open(archive_path) as t:
        for member in t:
            require(
                member.isfile()
                and not Path(member.name).is_absolute()
                and ".." not in Path(member.name).parts
                and member.name not in files,
                "unsafe archive member",
            )
            files[member.name] = t.extractfile(member).read()
    require(
        set(files) == set(m["files"])
        and all(sha(b) == m["files"][p] for p, b in files.items()),
        "raw inventory",
    )

    def obj(p):
        return json.loads(files[p])

    freeze = obj("attempt1/freeze.json")
    require(
        files["attempt1/freeze.json"] == files["attempt2/freeze.json"]
        and sha(files["attempt1/freeze.json"]) == m["freeze_sha256"] == FREEZE_SHA,
        "preprediction source/oracle freeze",
    )
    require(
        freeze["provider_semantic_oracle"]["decision"] == "unknown"
        and freeze["provider_semantic_oracle"]["score_eligible"] is False,
        "implementation label substituted for oracle",
    )
    for item in freeze["sources"]:
        require(sha(files[item["snapshot"]]) == item["sha256"], "frozen source bytes")
    before, after = obj("attempt1/execution.json"), obj("attempt2/execution.json")
    require(
        before["exit_code"] == -11 and after["exit_code"] == 0,
        "failed/successful process terminal status",
    )
    require(
        after["start_monotonic_ns"] > freeze["frozen_monotonic_ns"]
        and before["start_monotonic_ns"] > freeze["frozen_monotonic_ns"],
        "prediction before oracle/source freeze",
    )
    require(
        obj("attempt2/execution-freeze.json")["allowed_environment"]
        == after["allowed_environment"],
        "execution environment diverged from freeze",
    )
    require(
        files["attempt1/run-check.py"] == files["attempt2/run-check.py"]
        and sha(files["attempt2/run-check.py"])
        == after["runner_sha256"]
        == before["runner_sha256"],
        "changed provider runner",
    )
    for attempt in ("attempt1", "attempt2"):
        execution, result = (
            obj(attempt + "/execution.json"),
            obj(attempt + "/observation.json"),
        )
        require(
            sha(files[attempt + "/stdout.bin"]) == execution["stdout_sha256"]
            and sha(files[attempt + "/stderr.bin"]) == execution["stderr_sha256"],
            "execution raw hash",
        )
        require(
            files[attempt + "/stdout.bin"].endswith(
                files[attempt + "/observation.json"]
            ),
            "observation not in actual stdout",
        )
        require(
            result["freeze_sha256"] == FREEZE_SHA
            and result["formal_result"] is False
            and result["score_eligible"] is False
            and result["independent_runtime_oracle"] == "unknown"
            and result["runtime_effective"] is None
            and result["inter_MOD_conflict_detection"] is None
            and result["n4_unchanged"] is True,
            "observation promoted",
        )
    failed, observed = (
        obj("attempt1/observation.json"),
        obj("attempt2/observation.json"),
    )
    require(
        failed["actual_capabilities"]["host_api_version"] is None
        and all(
            x["actual_provider_check"]["compatible"] is None for x in failed["members"]
        ),
        "first failed attempt upgraded",
    )
    require(
        observed["actual_capabilities"]["source"]
        == "vllm.plugins.extension_capabilities"
        and observed["actual_capabilities"]["host_api_version"] == "1.0"
        and len(observed["actual_capabilities"]["protocol_versions"]) == 7,
        "actual host capability receipt",
    )
    require(
        len(observed["members"]) == 2
        and all(
            x["actual_provider_check"]["compatible"] is True
            and x["actual_provider_check"]["configured"] is True
            for x in observed["members"]
        ),
        "real provider observations",
    )
    require(
        [x["order"] for x in observed["orders"]] == freeze["orders"]
        and all(
            not x["plan_errors"]
            and x["composition_check"] == "no-declared-plan-conflict"
            and x["runtime_installation_order_executed"] is False
            for x in observed["orders"]
        ),
        "bounded two-order plan observation",
    )
    source_by_path = {x["source_path"]: x["sha256"] for x in freeze["sources"]}
    late = obj("late-source/provenance.json")
    require(
        late["prelaunch_registered"] is False
        and m["prelaunch_import_source_closure"]
        == "partial-two-host-plugin-files-retained-postrun",
        "postrun source upgraded to preregistration",
    )
    require(
        len(late["files"]) == 2
        and all(sha(files[x["snapshot"]]) == x["sha256"] for x in late["files"]),
        "postrun source bytes",
    )
    supplemented = source_by_path | {x["path"]: x["sha256"] for x in late["files"]}
    require(
        observed["actual_imports"]
        and all(
            supplemented.get(x["path"]) == x["sha256"]
            for x in observed["actual_imports"]
        ),
        "actual imported source differs from frozen or explicit postrun snapshots",
    )
    require(
        after["allowed_environment"]["PYTHONDONTWRITEBYTECODE"] == "1"
        and before["allowed_environment"]["PYTHONDONTWRITEBYTECODE"] == "1",
        "old environment bytecode writes allowed",
    )
    return {
        "classification": "CPU_PLAN_SURFACE_QUALIFICATION_ONLY",
        "provider_compatible_members": 2,
        "declared_orders_checked": 2,
        "first_attempt": "SIGSEGV-retained-not-qualified",
        "second_attempt_exit_code": 0,
        "actual_host_versions": observed["actual_versions"],
        "independent_runtime_oracle": "unknown",
        "score_eligible": False,
        "formal_result": False,
        "existing_n4_unchanged": True,
        "runtime_effectiveness": None,
        "prelaunch_import_source_closure": m["prelaunch_import_source_closure"],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--archive", type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(verify(a.manifest, a.archive), indent=2))


if __name__ == "__main__":
    main()
