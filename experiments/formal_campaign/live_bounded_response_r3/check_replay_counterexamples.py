"""Evidence-specific rejection checks; uses no runtime SDK imports."""

import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--bundle", type=Path, default=ROOT)
BUNDLE = parser.parse_args().bundle
spec = importlib.util.spec_from_file_location(
    "portable", ROOT / "verify_live_bounded_observation.py"
)
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
files, manifest = v.load_bundle(BUNDLE)
assert v.verify(files, BUNDLE, replay=False)["formal_result"] is False
results = []


def reject(name, path, mutate):
    changed = dict(files)
    obj = json.loads(changed[path])
    mutate(obj)
    changed[path] = v.canonical(obj)
    try:
        v.verify(changed, BUNDLE, replay=False)
    except (ValueError, KeyError, StopIteration) as error:
        results.append({"case": name, "rejected": True, "reason": str(error)})
    else:
        raise AssertionError("accepted mutation: " + name)


reject(
    "different-request-scope",
    "run/producer-completion.json",
    lambda x: x["scope"].__setitem__("membership_epoch", 1),
)
reject(
    "unregistered-fault-kernel",
    "run/actual-worker-fault-intent.json",
    lambda x: x["worker"].__setitem__("start_ticks", x["worker"]["start_ticks"] + 1),
)
reject(
    "fault-after-original-fixed-lease",
    "run/actual-worker-fault-intent.json",
    lambda x: x.__setitem__("at_monotonic_ns", 2**63),
)
reject(
    "public-body-hash-mismatch",
    "run/live-client-0699.json",
    lambda x: x.__setitem__("response_sha256", "0" * 64),
)
reject(
    "incomplete-final-source-ack",
    "run/probe/collector-after.json",
    lambda x: x["status"]["acknowledged_prefix"].__setitem__("next_sequence", 264),
)
for name, path in [
    ("native-prefix-truncation", "run/native-raw.jsonl"),
    ("authority-prefix-truncation", "run/live-authority-raw.jsonl"),
]:
    changed = dict(files)
    changed[path] = b"\n".join(files[path].splitlines()[:-1]) + b"\n"
    try:
        v.verify(changed, BUNDLE, replay=False)
    except (ValueError, KeyError) as error:
        results.append({"case": name, "rejected": True, "reason": str(error)})
    else:
        raise AssertionError("accepted mutation: " + name)
print(json.dumps({"passed": len(results), "results": results}, sort_keys=True))
