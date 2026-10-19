"""Shared study instrumentation: order actual callbacks; never alter MOD algorithms."""
import dataclasses
import functools
import importlib.metadata as metadata
import json
import os
import time
from pathlib import Path

_original = metadata.entry_points
_probe_pid = None
_observer = None


def record(kind, **fields):
    root = os.environ.get('ECPA_H2_RAW')
    if not root:
        return
    stat = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()
    row = dict(kind=kind, pid=os.getpid(), start_ticks=int(stat[19]),
               monotonic_ns=time.monotonic_ns(), **fields)
    fd = os.open(str(Path(root) / 'study-events.jsonl'), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (json.dumps(row, default=str, sort_keys=True) + '\n').encode())
    finally:
        os.close(fd)


def install_observer():
    global _probe_pid, _observer
    if _probe_pid == os.getpid():
        return
    from vllm.v1.events import EventBus
    from vllm.plugins import native_block_table_observer as native

    if not getattr(native.observe_request_id_mapping, '__h2_mapping__', False):
        original_mapping = native.observe_request_id_mapping

        @functools.wraps(original_mapping)
        def mapped(request):
            answer = original_mapping(request)
            record('actual-request-mapping', external_request_id=request.external_req_id,
                   runtime_request_id=request.request_id,
                   prompt_token_ids=getattr(request, 'prompt_token_ids', None))
            return answer

        mapped.__h2_mapping__ = True
        native.observe_request_id_mapping = mapped
    if os.environ.get('VLLM_ECPA_PLAN_ID') and native._observer is None:
        # Existing opt-in Host API. No socket ACK or formal phase receipt is invented.
        native.register_observer(lambda fact: record('native-fact', fact=fact))

    class Observer:
        def emit(self, event):
            if type(event).__name__ not in {'RequestFinished', 'RequestKvReclaimed', 'RequestPreempted'}:
                return
            fields = dataclasses.asdict(event) if dataclasses.is_dataclass(event) else {
                k: getattr(event, k) for k in ('request_id', 'kv_blocks', 'prompt_tokens', 'output_tokens', 'sequence_tokens') if hasattr(event, k)
            }
            record('host-event', event_type=type(event).__name__, fields=fields)

    if _observer is not None:
        EventBus.unregister_sink(_observer)
    _observer = Observer()
    EventBus.register_sink(_observer)
    _probe_pid = os.getpid()
    record('study-observer-installed')


class OrderedEntry:
    def __init__(self, entry):
        self.entry = entry

    def __getattr__(self, key):
        return getattr(self.entry, key)

    def load(self):
        fn = self.entry.load()

        @functools.wraps(fn)
        def invoke(*args, **kwargs):
            record('callback-start', name=self.name, value=self.value)
            try:
                result = fn(*args, **kwargs)
                install_observer()
            except BaseException as error:
                record('callback-error', name=self.name, error=repr(error))
                raise
            record('callback-complete', name=self.name, value=self.value)
            return result

        return invoke


def ordered_entries(**kwargs):
    entries = _original(**kwargs)
    if kwargs.get('group') != 'vllm.general_plugins' or not os.environ.get('ECPA_H2_RAW'):
        return entries
    order = ['ascend', *json.loads(os.environ['ECPA_H2_ORDER'])]
    rank = {name: n for n, name in enumerate(order)}
    entries = sorted(entries, key=lambda e: rank.get(e.name, 100))
    return tuple(OrderedEntry(e) for e in entries)


metadata.entry_points = ordered_entries
