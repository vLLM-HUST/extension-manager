"""Four actual CPU processes/socket and real private artifact bytes, not NPU proof."""

from __future__ import annotations

import array
import base64
import copy
import json
import os
import select
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

from experiments.exposure_gate import native_semantic_collector as native
from experiments.native_kv_tensor_candidate import artifact_transport as transport
from experiments.native_kv_tensor_candidate import witness

ROOT = Path(__file__).resolve().parents[1]
CODE = """import json,os,sys,time
from pathlib import Path
from experiments.exposure_gate import native_semantic_collector as n
from experiments.native_kv_tensor_candidate import artifact_transport as t
from experiments.native_kv_tensor_candidate import artifact_bootstrap as b
p=n.identity(os.getpid())|dict(host="CPU_FIXTURE_ONLY",role=sys.argv[1],ordinal=int(sys.argv[2]),process_epoch=1,assignment_source="host")
print(json.dumps(p),flush=True)
for line in sys.stdin:
 c=json.loads(line)
 try:
  scope=lambda:dict(process=p,plan_id="plan",launch_id="launch",monotonic_ns=time.monotonic_ns())
  receiver=dict(expected_collector=c['ready']['collector'],expected_socket_identity=tuple(c['ready']['socket_identity']),expected_collector_source_sha256=c['ready']['collector_source_sha256'],expected_archive_identity=c['ready']['archive_identity'])
  if c['op']=='mapping':
   fact=dict(schema=n.MAPPING,**scope(),external_request_id="chatcmpl-client",runtime_request_id="CPU-runtime")
   ack=n.submit_fact(Path(c['ready']['socket_path']),fact,**receiver)
  elif c['op']=='publish':
   f=c['fact'];stamp=time.monotonic_ns()
   keys=['source_before_gather_ns','reference_after_gather_ns',
         'write_completed_barrier_ns','destination_readback_completed_ns']
   for key in keys:f[key]=stamp
   ack=t.publish_candidate(f,directory_path=c['directory'],directory_identity=c['directory_identity'],policy_sha256=c['ready']['policy_sha256'],scope=scope,socket_path=c['ready']['socket_path'],receiver=receiver)
  elif c['op']=='bootstrap':
   f=c['fact'];stamp=time.monotonic_ns()
   keys=['source_before_gather_ns','reference_after_gather_ns',
         'write_completed_barrier_ns','destination_readback_completed_ns']
   for key in keys:f[key]=stamp
   ack=b.callback_from_context(Path(c['context']),actual_scope=scope)(f)
  elif c['op']=='envelope':
   f=c['fact'];stamp=time.monotonic_ns()
   keys=['source_before_gather_ns','reference_after_gather_ns',
         'write_completed_barrier_ns','destination_readback_completed_ns']
   for key in keys:f[key]=stamp
   fd,_=t.directory(c['directory'],c['directory_identity'])
   raw=n.canonical(f);a=t.write_new(fd,n.sha(raw)+'.json',raw);os.close(fd)
   env=dict(schema=t.ENVELOPE,**scope(),runtime_request_id='CPU-runtime',transaction_id=t.transaction(f),artifact=a,transport_policy_sha256=c['ready']['policy_sha256'])
   mutation=c.get('mutation')
   if mutation=='inode':env['artifact']['inode']+=1
   if mutation=='path':env['artifact']['basename']='../bad.json'
   if mutation=='late':Path(c['directory'],a['basename']).write_bytes(raw+b' ')
   if mutation=='rank':env['process']=env['process']|dict(ordinal=1-int(sys.argv[2]))
   if mutation=='transaction':env['transaction_id']='0'*64
   ack=n.submit_fact(Path(c['ready']['socket_path']),env,**receiver)
  print(json.dumps(dict(ack=ack)),flush=True)
 except Exception as exc:print(json.dumps(dict(rejected=str(exc))),flush=True)
"""


def line(child):
    assert select.select([child.stdout], [], [], 10)[0], "CPU child did not respond"
    raw = child.stdout.readline()
    assert raw, child.stderr.read()
    return json.loads(raw)


def fact(rank):
    # Large real owned CPU binary16 buffers, not merely an oversized JSON padding.
    planes = {
        k: array.array("H", [(i + offset) % 4096 for i in range(6 * 128 * 256)])
        for k, offset in [("K", 0), ("V", 17)]
    }
    keep = [0, 127, 128]
    exports, selected, views = {}, {}, {}
    for k, plane in planes.items():
        raw = plane.tobytes()
        exports[k] = {
            str(b): base64.b64encode(raw[b * 65536 : (b + 1) * 65536]).decode()
            for b in [0, 1]
        }
        selected[k] = b"".join(raw[i * 512 : (i + 1) * 512] for i in keep)
        views[k] = dict(
            device="cpu",
            dtype="torch.float16",
            shape=[6, 128, 1, 256],
            stride=[32768, 256, 256, 1],
            npu_format=None,
            data_ptr=plane.buffer_info()[0],
            storage_ptr=plane.buffer_info()[0],
            storage_offset=0,
        )
    encoded = {k: base64.b64encode(v).decode() for k, v in selected.items()}
    return dict(
        schema=witness.SCHEMA,
        classification="CPU_SOURCE_CANDIDATE_ONLY",
        formal_registration=False,
        GPU_qualification=None,
        attention_consumption=None,
        full_model_quality=None,
        binding=dict(
            runtime_request_id="CPU-runtime",
            layer_name="CPU-layer.0",
            layer_index=0,
            expected_layer_indices=[0],
            rank=rank,
            tensor_parallel_size=2,
            physical_num_tokens=129,
            semantic_num_tokens=129,
            compression_plan=dict(
                semantic_anchor=129,
                physical_anchor=3,
                source_block_ids=[0, 1],
                destination_block_ids=[3],
            ),
            cache_blocks_per_scheduler_block=1,
        ),
        source_blocks=[0, 1],
        destination_blocks=[3],
        keep_indices=keep,
        source_slots=[0, 127, 128],
        destination_slots=[384, 385, 386],
        block_size=128,
        source_before_gather_ns=1,
        reference_after_gather_ns=2,
        write_completed_barrier_ns=3,
        destination_readback_completed_ns=4,
        cache_views={
            k: dict(before=v, after=copy.deepcopy(v)) for k, v in views.items()
        },
        exported_source_block_bytes=exports,
        source_after_write_block_bytes=copy.deepcopy(exports),
        selected_source_bytes=encoded,
        gathered_workspace_bytes=copy.deepcopy(encoded),
        destination_readback_bytes=copy.deepcopy(encoded),
        selected_source_sha256={k: native.sha(v) for k, v in selected.items()},
        destination_readback_sha256={k: native.sha(v) for k, v in selected.items()},
    )


@pytest.fixture
def run(tmp_path, request):
    tmp_path.chmod(0o700)
    code = tmp_path / "cpu-source.py"
    code.write_text(CODE)
    procs, senders = [], []
    env = os.environ | {"PYTHONPATH": str(ROOT)}
    try:
        for role, ordinal in [("api-server", 0), ("worker", 0), ("worker", 1)]:
            child = subprocess.Popen(
                [sys.executable, str(code), role, str(ordinal)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            procs.append(child)
            process = line(child)
            sources = [
                code,
                Path(native.__file__),
                Path(transport.__file__),
                Path(witness.__file__),
            ]
            senders.append(
                dict(
                    process=process,
                    peer_uid=os.getuid(),
                    peer_gid=os.getgid(),
                    cmdline_sha256=native.sha(
                        Path(f"/proc/{child.pid}/cmdline").read_bytes()
                    ),
                    source_files=[
                        dict(path=str(p), sha256=native.sha(p.read_bytes()))
                        for p in sources
                    ],
                )
            )
        spec = dict(
            schema=native.SPEC,
            classification="CPU_REVIEW_CANDIDATE_ONLY",
            formal_producer_registration=False,
            native_plan_id="plan",
            native_launch_id="launch",
            frozen_monotonic_ns=time.monotonic_ns(),
            max_event_age_ns=60_000_000_000,
            max_uploads_per_rank=256,
            senders=senders,
            phases=[
                dict(
                    phase_id="phase",
                    client_request_id="client",
                    challenge_nonce="CPU-nonce",
                    external_request_id="chatcmpl-client",
                    expected_ranks=[0, 1],
                )
            ],
        )
        spec_path = tmp_path / "spec.json"
        spec_path.write_bytes(native.canonical(spec))
        spec_path.chmod(0o600)
        directories = {}
        for child in procs[1:]:
            folder = tmp_path / f"worker-{child.pid}"
            folder.mkdir()
            folder.chmod(0o700)
            meta = folder.stat()
            directories[str(child.pid)] = dict(
                path=str(folder), identity=[meta.st_dev, meta.st_ino]
            )
        policy = dict(
            schema=transport.POLICY,
            classification="CPU_SOURCE_CANDIDATE_ONLY",
            formal_registration=False,
            native_spec_sha256=native.sha(spec_path.read_bytes()),
            worker_directories=directories,
            requirements=dict(
                phase=dict(layer_indices=[0], semantic_anchor=129, physical_anchor=3)
            ),
        )
        policy_path = tmp_path / "policy.json"
        policy_path.write_bytes(native.canonical(policy))
        policy_path.chmod(0o600)
        journal, sock = tmp_path / "raw.jsonl", tmp_path / "sock"
        launch = [
            sys.executable,
            "-m",
            "experiments.native_kv_tensor_candidate.artifact_transport",
        ]
        if getattr(request, "param", None) == "fsync-failure":
            fault = tmp_path / "collector_cpu_fault.py"
            fault.write_text("""import os
from experiments.native_kv_tensor_candidate import artifact_transport as t
original=t.write_new
def fail_archive(*args):
 saved=os.fsync
 def fail(fd):raise OSError('CPU-injected-archive-fsync-failure')
 os.fsync=fail
 try:return original(*args)
 finally:os.fsync=saved
t.write_new=fail_archive
t.main()
""")
            launch = [sys.executable, str(fault)]
        collector = subprocess.Popen(
            launch
            + [
                "--spec",
                str(spec_path),
                "--policy",
                str(policy_path),
                "--journal",
                str(journal),
                "--socket",
                str(sock),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        procs.append(collector)
        ready = line(collector)
        yield dict(
            root=tmp_path,
            procs=procs,
            senders=senders,
            spec=spec_path,
            policy=policy_path,
            journal=journal,
            ready=ready,
            dirs=directories,
        )
    finally:
        for child in reversed(procs):
            child.terminate()
            child.wait(timeout=5)


def command(run, child_index, op, **kw):
    child = run["procs"][child_index]
    own = run["dirs"].get(str(child.pid), {})
    value = dict(
        op=op,
        ready=run["ready"],
        directory=own.get("path"),
        directory_identity=own.get("identity"),
        **kw,
    )
    child.stdin.write(json.dumps(value) + "\n")
    child.stdin.flush()
    return line(child)


def seal(run):
    ready = run["ready"]
    return native.probe_collector(
        Path(ready["socket_path"]),
        expected_collector=ready["collector"],
        expected_socket_identity=tuple(ready["socket_identity"]),
        expected_collector_source_sha256=ready["collector_source_sha256"],
        expected_spec_sha256=ready["spec_sha256"],
        expected_archive_identity=ready["archive_identity"],
    )["acknowledged_prefix"]


def test_real_kernel_three_senders_large_artifact_small_envelope_durable_join(run):
    assert command(run, 0, "mapping")["ack"]["schema"] == native.ACK
    for rank in [0, 1]:
        payload = fact(rank)
        assert len(native.canonical(payload)) > native.MAX_FRAME
        ack = command(run, rank + 1, "publish", fact=payload)
        assert "ack" in ack, ack
    prefix = seal(run)
    result = transport.verify_archive(
        run["spec"], run["policy"], run["journal"], acknowledged_prefix=prefix
    )
    assert result["durable_artifact_join_complete"] is True
    assert result["GPU_qualification"] is result["attention_consumption"] is None
    assert result["formal_registration"] is False
    assert (
        transport.verify_archive(run["spec"], run["policy"], run["journal"])[
            "durable_artifact_join_complete"
        ]
        is False
    )
    with pytest.raises(ValueError, match="ACK prefix"):
        transport.verify_archive(
            run["spec"],
            run["policy"],
            run["journal"],
            acknowledged_prefix=prefix
            | dict(next_sequence=prefix["next_sequence"] + 1),
        )


@pytest.mark.parametrize("mutation", ["inode", "path", "late", "rank", "transaction"])
def test_actual_peer_path_inode_late_mutation_or_binding_rejected(run, mutation):
    assert "ack" in command(run, 0, "mapping")
    result = command(run, 1, "envelope", fact=fact(0), mutation=mutation)
    assert "rejected" in result, result
    assert len(run["journal"].read_bytes().splitlines()) == 3


def test_current_unregistered_kernel_peer_cannot_submit_artifact(run):
    assert "ack" in command(run, 0, "mapping")
    raw = native.canonical(dict(schema=transport.ENVELOPE))
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.connect(run["ready"]["socket_path"])
        peer_pid, _, _ = struct.unpack(
            "3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )
        assert peer_pid == run["procs"][-1].pid
        channel.sendall(
            native.canonical(dict(raw_base64=base64.b64encode(raw).decode())) + b"\n"
        )
        result = json.loads(channel.recv(native.MAX_FRAME))
    assert "kernel peer" in result["reason"]


def test_archived_blob_late_mutation_does_not_get_portable_pass(run):
    assert "ack" in command(run, 0, "mapping")
    assert "ack" in command(run, 1, "publish", fact=fact(0))
    prefix = seal(run)
    event = json.loads(run["journal"].read_bytes().splitlines()[-1])
    path = run["root"] / event["artifact"]["basename"]
    raw = bytearray(path.read_bytes())
    raw[-2] ^= 1
    path.write_bytes(raw)
    with pytest.raises(ValueError, match="archived blob changed"):
        transport.verify_archive(
            run["spec"], run["policy"], run["journal"], acknowledged_prefix=prefix
        )


def test_actual_registered_source_changes_fail_closed(run):
    assert "ack" in command(run, 0, "mapping")
    (run["root"] / "cpu-source.py").write_text(CODE + "\n# source changed\n")
    assert (
        "sender source bytes changed"
        in command(run, 1, "publish", fact=fact(0))["rejected"]
    )


def test_actual_source_bootstrap_receives_authenticated_digest_ack(run):
    from experiments.native_kv_tensor_candidate import artifact_bootstrap

    assert "ack" in command(run, 0, "mapping")
    for rank in [0, 1]:
        context = run["root"] / f"context-{rank}.json"
        artifact_bootstrap.write_context(
            context,
            spec_path=run["spec"],
            policy_path=run["policy"],
            ready=run["ready"],
            source_files=run["senders"][rank + 1]["source_files"],
        )
        response = command(
            run, rank + 1, "bootstrap", context=str(context), fact=fact(rank)
        )
        assert "ack" in response, response
    result = transport.verify_archive(
        run["spec"], run["policy"], run["journal"], acknowledged_prefix=seal(run)
    )
    assert result["durable_artifact_join_complete"] is True


def test_collector_socket_identity_and_kernel_receiver_mismatch_reject(run):
    assert "ack" in command(run, 0, "mapping")
    old = run["ready"]["collector"]["pid"]
    run["ready"]["collector"]["pid"] = os.getpid()
    assert "ACK kernel peer" in command(run, 1, "publish", fact=fact(0))["rejected"]
    run["ready"]["collector"]["pid"] = old
    run["ready"]["socket_identity"][1] += 1
    assert "socket changed" in command(run, 2, "publish", fact=fact(1))["rejected"]


@pytest.mark.parametrize(
    "mutation",
    [
        "clock",
        "source",
        "plan",
        "rank",
        "phase",
        "false-prefix",
        "source-inode",
        "source-path",
    ],
)
def test_rehashed_portable_counterfactuals_cannot_make_join(run, mutation):
    assert "ack" in command(run, 0, "mapping")
    for rank in [0, 1]:
        assert "ack" in command(run, rank + 1, "publish", fact=fact(rank))
    prefix = seal(run)
    events = [json.loads(line) for line in run["journal"].read_bytes().splitlines()]
    event = events[-1]
    envelope = json.loads(base64.b64decode(event["raw_base64"]))
    if mutation in {"clock", "plan", "rank"}:
        path = run["root"] / event["artifact"]["basename"]
        payload = json.loads(path.read_bytes())
        if mutation == "clock":
            for key in [
                "source_before_gather_ns",
                "reference_after_gather_ns",
                "write_completed_barrier_ns",
                "destination_readback_completed_ns",
            ]:
                payload[key] = 1
        elif mutation == "rank":
            payload["binding"]["rank"] = 0
        else:
            payload["binding"]["compression_plan"]["source_block_ids"] = [1, 0]
        raw = native.canonical(payload)
        path.write_bytes(raw)
        for descriptor in [
            event["artifact"],
            envelope["artifact"],
            event["source_artifact"],
        ]:
            descriptor["sha256"], descriptor["size"] = native.sha(raw), len(raw)
        # Keep path stable to isolate the semantic predicate, not file lookup.
    elif mutation == "source-inode":
        envelope["artifact"]["inode"] += 1
    elif mutation == "source-path":
        envelope["artifact"]["basename"] = "../unregistered.json"
        event["source_artifact"]["basename"] = envelope["artifact"]["basename"]
    elif mutation == "source":
        first = next(iter(event["source_sha256"]))
        event["source_sha256"][first] = "0" * 64
    elif mutation == "phase":
        event["phase"]["challenge_nonce"] = "forged"
    raw = native.canonical(envelope)
    event["raw_base64"], event["raw_sha256"] = (
        base64.b64encode(raw).decode(),
        native.sha(raw),
    )
    previous = "0" * 64
    for row in events:
        row["previous_sha256"] = previous
        row.pop("event_sha256")
        row["event_sha256"] = native.sha(native.canonical(row))
        previous = row["event_sha256"]
    run["journal"].write_bytes(
        b"".join(native.canonical(row) + b"\n" for row in events)
    )
    forged_prefix = dict(next_sequence=len(events), last_event_sha256=previous)
    if mutation == "false-prefix":
        forged_prefix = prefix | dict(last_event_sha256="0" * 64)
    with pytest.raises(ValueError):
        transport.verify_archive(
            run["spec"],
            run["policy"],
            run["journal"],
            acknowledged_prefix=forged_prefix,
        )


def test_installable_source_patches_preserve_actual_plan_not_owner_nonce(tmp_path):
    import hashlib

    root = ROOT / "experiments/native_kv_tensor_candidate"
    manifest = json.loads((root / "artifact-source/binding.json").read_text())
    for entry in json.loads((root / "source/source-binding.json").read_text())[
        "source_files"
    ]:
        path = tmp_path / entry["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((root / "source" / entry["snapshot"]).read_bytes())
    subprocess.run(
        [
            "git",
            "apply",
            str(root / "artifact-source/kv-private-tensor-artifact.patch"),
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    for entry in manifest["KV_files"]:
        raw = (tmp_path / entry["path"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == entry["postimage_sha256"]
        compile(raw, entry["path"], "exec")
    method = (
        tmp_path / "src/vllm_ascend_kvcompress/methods/triattention/method.py"
    ).read_text()
    assert "plan = request.plan" in method
    assert '"semantic_anchor": plan.semantic_anchor' in method
    assert "challenge_nonce" not in method
    subprocess.run(
        [
            "git",
            "apply",
            str(root / "artifact-source/host-private-tensor-artifact.patch"),
        ],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    for entry in manifest["Host_new_files"]:
        raw = (tmp_path / entry["path"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == entry["sha256"]
        compile(raw, entry["path"], "exec")


def test_native_actual_plan_is_executable_and_bound_to_request(monkeypatch):
    from types import ModuleType, SimpleNamespace

    root = ROOT / "experiments/native_kv_tensor_candidate/artifact-source"
    module = ModuleType("_CPU_actual_plan")
    monkeypatch.setitem(sys.modules, module.__name__, module)
    env = module.__dict__
    exec(compile((root / "transaction.py.snapshot").read_bytes(), "_plan", "exec"), env)
    # The pinned original dataclass, not an invented transaction/phase shape.
    plan = env["CompressionPlan"](129, 3, (0, 1), (3,))
    request = SimpleNamespace(request_id="CPU-runtime", plan=plan)
    payload = fact(0)
    payload["binding"]["compression_plan"] = dict(
        semantic_anchor=request.plan.semantic_anchor,
        physical_anchor=request.plan.physical_anchor,
        source_block_ids=list(request.plan.source_block_ids),
        destination_block_ids=list(request.plan.destination_block_ids),
    )
    assert transport.transaction(payload) == native.sha(
        native.canonical(
            dict(
                runtime_request_id=request.request_id,
                compression_plan=payload["binding"]["compression_plan"],
            )
        )
    )


@pytest.mark.parametrize("run", ["fsync-failure"], indirect=True)
def test_actual_collector_artifact_fsync_failure_has_no_ack_or_completion(run):
    assert "ack" in command(run, 0, "mapping")
    result = command(run, 1, "publish", fact=fact(0))
    assert "CPU-injected-archive-fsync-failure" in result["rejected"]
    assert len(run["journal"].read_bytes().splitlines()) == 3
    with pytest.raises(ValueError, match="status failed"):
        seal(run)
    result = transport.verify_archive(run["spec"], run["policy"], run["journal"])
    assert result["durable_artifact_join_complete"] is False
    assert result["acknowledged_prefix_status"] == "unknown"
