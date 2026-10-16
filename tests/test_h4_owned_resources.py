"""Actual CPU child/session attribution only; no devices or formal measurements."""

import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

SOURCE = (
    Path(__file__).resolve().parents[1]
    / "experiments/formal_campaign/h4_owned_resources.py"
)
spec = importlib.util.spec_from_file_location("h4_owned_resources_candidate", SOURCE)
owned = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owned)


def test_actual_descendant_new_session_is_sampled_and_foreign_child_excluded(tmp_path):
    # The root stays alive until stdin EOF, just as the real H4 wrapper does.
    code = """import subprocess,sys,time,json
child='import sys; x=bytearray(16*1024*1024); '
child+='print(\"ready\",flush=True); sys.stdin.buffer.read()'
p=subprocess.Popen([sys.executable,'-c',child],stdin=subprocess.PIPE,
                   stdout=subprocess.PIPE,start_new_session=True)
p.stdout.readline(); print(json.dumps({'child':p.pid}),flush=True)
sys.stdin.buffer.read(); p.stdin.close(); p.wait(timeout=5)
"""
    root = subprocess.Popen(
        [sys.executable, "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    foreign = subprocess.Popen(
        [sys.executable, "-c", "import sys;sys.stdin.buffer.read()"],
        stdin=subprocess.PIPE,
    )
    try:
        child_pid = json.loads(root.stdout.readline())["child"]
        sampler = owned.OwnedTreeResourceSampler(
            root.pid, None, archive=tmp_path / "samples.json"
        )
        sampler.start()
        time.sleep(0.3)
        metrics = sampler.finish()
        sampler.require_coverage()
        value = owned.verify_archive(sampler.archive, sampler.root, metrics)
        first = {p["pid"]: p for p in value["samples"][0]["members"]}
        assert child_pid in first and foreign.pid not in first
        assert first[child_pid]["session"] != first[root.pid]["session"]
        assert metrics["peak_host_rss_bytes"] >= 16 * 1024 * 1024
        assert value["device_coverage"] == "not-observed"
        changed = dict(metrics, peak_host_rss_bytes=0)
        with pytest.raises(ValueError, match="metrics differ"):
            owned.verify_archive(sampler.archive, sampler.root, changed)
    finally:
        root.stdin.close()
        root.wait(timeout=5)
        foreign.stdin.close()
        foreign.wait(timeout=5)


def test_root_epoch_substitution_is_rejected():
    import os

    expected = owned.kernel(
        owned.read_process(os.getpid()),
        Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    )
    expected["start_ticks"] += 1
    with pytest.raises(ValueError, match="absent or reused"):
        owned.collect_tree(expected)


def test_original_sampling_period_and_fresh_archive_are_enforced(tmp_path):
    import os

    with pytest.raises(ValueError, match="sampling period"):
        owned.OwnedTreeResourceSampler(
            os.getpid(), None, archive=tmp_path / "archive", interval_s=1
        )
    path = tmp_path / "existing"
    path.touch()
    with pytest.raises(FileExistsError, match="fresh"):
        owned.OwnedTreeResourceSampler(os.getpid(), None, archive=path)


def test_reaped_child_cpu_moves_to_parent_without_double_count(tmp_path):
    code = """import subprocess,sys,time,json
child='import time,sys; end=time.process_time()+0.2; '
child+='exec("while time.process_time()<end: pass"); '
child+='print("ready",flush=True); sys.stdin.buffer.read()'
p=subprocess.Popen([sys.executable,'-c',child],stdin=subprocess.PIPE,
                   stdout=subprocess.PIPE,start_new_session=True)
p.stdout.readline(); print(p.pid,flush=True)
sys.stdin.buffer.readline(); p.stdin.close(); p.wait(timeout=5)
print('reaped',flush=True); sys.stdin.buffer.read()
"""
    process = subprocess.Popen(
        [sys.executable, "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    try:
        child = int(process.stdout.readline())
        sampler = owned.OwnedTreeResourceSampler(
            process.pid, None, archive=tmp_path / "resources.json"
        )
        initial = sampler.samples[0]
        members = {r["pid"]: r for r in initial["members"]}
        assert members[child]["own_ticks"] >= 10
        process.stdin.write(b"reap\n")
        process.stdin.flush()
        assert process.stdout.readline().strip() == b"reaped"
        sampler._append_sample()
        final = sampler.samples[-1]
        assert child not in {r["pid"] for r in final["members"]}
        assert final["members"][0]["reaped_child_ticks"] >= members[child]["own_ticks"]
        assert initial["cpu_ticks"] <= final["cpu_ticks"] <= initial["cpu_ticks"] + 10
        resources = sampler.finish()
        owned.verify_archive(sampler.archive, sampler.root, resources)
    finally:
        process.stdin.close()
        process.wait(timeout=5)


def test_product_scope_excludes_real_witness_audit_cpu_and_rss(tmp_path):
    code = """import subprocess,sys,time,json
x=bytearray(32*1024*1024)
print('witness',flush=True); sys.stdin.buffer.readline()
end=time.process_time()+.15
while time.process_time()<end: pass
child="import sys,time; x=bytearray(8*1024*1024); end=time.process_time()+.15; "
child+='exec("while time.process_time()<end: pass"); '
child+='print("ready",flush=True); sys.stdin.buffer.read()'
p=subprocess.Popen([sys.executable,'-c',child],stdin=subprocess.PIPE,
                   stdout=subprocess.PIPE,start_new_session=True)
p.stdout.readline(); print(p.pid,flush=True)
sys.stdin.buffer.read(); p.stdin.close(); p.wait(timeout=5)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    try:
        assert process.stdout.readline().strip() == b"witness"
        sampler = owned.OwnedTreeResourceSampler(
            process.pid, None, archive=tmp_path / "product.json"
        )
        sampler.start()
        process.stdin.write(b"launch\n")
        process.stdin.flush()
        pid = int(process.stdout.readline())
        product = owned.kernel(owned.read_process(pid), sampler.root["boot_id"])
        sampler.select_product_root(product)
        result = sampler.finish()
        archive = owned.verify_archive(sampler.archive, sampler.root, result)
        assert archive["measurement_root"] == product
        assert result["cpu_ms"] >= 100
        full = owned.measured_resources(
            archive["samples"], archive["clock_ticks_per_second"]
        )
        assert full["cpu_ms"] - result["cpu_ms"] >= 100
        assert (
            full["peak_host_rss_bytes"] - result["peak_host_rss_bytes"]
            >= 24 * 1024 * 1024
        )
        with pytest.raises(ValueError, match="already frozen"):
            sampler.select_product_root(product)
        archive["measurement_root"]["start_ticks"] += 1
        sampler.archive.write_bytes(owned.canonical(archive))
        with pytest.raises(ValueError, match="epoch was reused"):
            owned.verify_archive(sampler.archive, sampler.root, result)
    finally:
        process.stdin.close()
        process.wait(timeout=5)
