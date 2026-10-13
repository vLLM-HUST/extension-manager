"""Scientific scope and failed-attempt integrity of the real CPU observation."""

import copy
import io
import json
import tarfile
from pathlib import Path

import pytest

from experiments.real_mod_composition import verify_h2_quantized_kvcompress_cpu as audit

ARTIFACT = (
    Path(__file__).resolve().parents[1]
    / "experiments/real_mod_composition/artifacts/h2-quantized-kvcompress-cpu-20261013"
)


def test_actual_source_pair_is_unknown_and_not_scored():
    result = audit.verify(ARTIFACT / "manifest.json", ARTIFACT / "raw.tar.gz")
    assert result["provider_compatible_members"] == 2
    assert result["independent_runtime_oracle"] == "unknown"
    assert result["score_eligible"] is False
    assert result["first_attempt"] == "SIGSEGV-retained-not-qualified"


@pytest.mark.parametrize("case", ["score", "failed-exit", "backdated-source"])
def test_rehashed_counterfactual_cannot_promote_scope(tmp_path, case):
    manifest = copy.deepcopy(json.loads((ARTIFACT / "manifest.json").read_bytes()))
    with tarfile.open(ARTIFACT / "raw.tar.gz") as t:
        files = {x.name: t.extractfile(x).read() for x in t}
    if case == "score":
        manifest["score_eligible"] = True
    else:
        path = (
            "attempt1/execution.json"
            if case == "failed-exit"
            else "late-source/provenance.json"
        )
        value = json.loads(files[path])
        if case == "failed-exit":
            value["exit_code"] = 0
        else:
            value["prelaunch_registered"] = True
        files[path] = json.dumps(value).encode()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as t:
        for name, data in files.items():
            item = tarfile.TarInfo(name)
            item.size = len(data)
            t.addfile(item, io.BytesIO(data))
    archive = tmp_path / "raw.tar.gz"
    archive.write_bytes(raw.getvalue())
    manifest["archive_sha256"] = audit.sha(archive.read_bytes())
    manifest["files"] = {p: audit.sha(b) for p, b in files.items()}
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        audit.verify(path, archive)
