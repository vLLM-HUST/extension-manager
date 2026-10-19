"""Independent raw evidence projection; no planner, outcome, or passed summary inputs.

Read-only on the cohort. Missing proof is unknown. This bounded reader does not
mint source admission, physical KV completeness, cleanup, or a compatibility label.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

RULE = Path('/root/ecpa-workspace/management/real-mod-H2-native-20261018/compatible-oracle-rule.json')
ORDERS = {
    'host-only': [], 'kv-only': ['ascend_kvcompress'],
    'profiler-only': ['request_lifecycle_profiler'],
    'kv-then-profiler': ['ascend_kvcompress', 'request_lifecycle_profiler'],
    'profiler-then-kv': ['request_lifecycle_profiler', 'ascend_kvcompress'],
}
TARGETS = {
    'ascend_kvcompress': 'vllm_ascend_kvcompress.plugin:register',
    'request_lifecycle_profiler': 'vllm_request_lifecycle_profiler.plugin:register_plugin',
}
REQUIRED_ROLES = {'api-server/0', 'engine-core-scheduler/0', 'worker/0', 'worker/1'}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path, refs, *, lines=False):
    if not path.is_file() or path.is_symlink():
        return None
    raw = path.read_bytes()
    refs.append({'path': str(path), 'sha256': digest(raw), 'bytes': len(raw)})
    if lines:
        if raw and not raw.endswith(b'\n'):
            raise ValueError('incomplete raw journal tail: ' + str(path))
        return [json.loads(line) for line in raw.splitlines()]
    return json.loads(raw)


def source_roster(events):
    roster = {}
    for event in events:
        process = event.get('process', {})
        if process.get('assignment_source') != 'host':
            continue
        pid = process.get('pid')
        match = re.fullmatch(r'pid:(\d+):start_ticks:(\d+)', process.get('start_identity', ''))
        if match is None or int(match[1]) != pid:
            raise ValueError('malformed actual Host process identity')
        key = (pid, int(match[2]))
        slot = f"{process.get('role')}/{process.get('ordinal')}"
        if key in roster and roster[key] != slot:
            raise ValueError('one actual epoch assigned conflicting Host roles')
        roster[key] = slot
    return roster


def callback_order(study, roster, expected):
    actual = defaultdict(list)
    pending = {}
    failures = []
    for event in study:
        kind = event.get('kind')
        if kind not in {'callback-start', 'callback-complete', 'callback-error'}:
            continue
        name = event.get('name')
        if name not in TARGETS:
            continue
        key = (event['pid'], event['start_ticks'])
        if event.get('value', TARGETS[name]) != TARGETS[name]:
            failures.append('substituted callback target')
        token = (key, name)
        if kind == 'callback-start':
            if token in pending:
                failures.append('duplicate/overlapping callback start')
            pending[token] = event['monotonic_ns']
            actual[key].append(name)
        elif kind == 'callback-error':
            failures.append('actual callback error: ' + name)
            pending.pop(token, None)
        elif token not in pending or event['monotonic_ns'] < pending.pop(token):
            failures.append('callback complete without matching original start')
    slots = {}
    for key, names in actual.items():
        slot = roster.get(key)
        if slot is None:
            continue
        if slot in slots:
            failures.append('multiple actual epochs for required Host slot')
        slots[slot] = {'pid': key[0], 'start_ticks': key[1], 'order': names}
        if names != expected:
            failures.append('actual callback order differs: ' + slot)
    complete = REQUIRED_ROLES <= set(slots) and not pending
    # Host-only has no selected callback from which to infer ordering. Retain
    # the actual roster; absence of target callback does not prove effect.
    if not expected:
        complete = REQUIRED_ROLES <= set(roster.values()) and not actual
    return {'status': 'failure' if failures else ('supported' if complete else 'unknown'),
            'actual_slots': slots, 'pending_count': len(pending), 'failures': failures,
            'required_slots': sorted(REQUIRED_ROLES)}


def read_case(root, name):
    directory = root / name
    refs = []
    if not directory.is_dir():
        return {'case': name, 'status': 'not-started', 'raw_refs': refs}
    study = load(directory / 'study-events.jsonl', refs, lines=True) or []
    host = load(directory / 'runtime-evidence.jsonl', refs, lines=True) or []
    popen = load(directory / 'Popen.json', refs)
    roster = source_roster(host)
    loading = callback_order(study, roster, ORDERS[name])
    physical = [event for event in study if event.get('kind') == 'host-event'
                and event.get('event_type') in {'RequestFinished', 'RequestKvReclaimed'}]
    requests = []
    for kind in ['below', 'above']:
        request = load(directory / f'{kind}-request.json', refs)
        response = load(directory / f'{kind}-response.json', refs)
        row = {'kind': kind, 'functional_status': 'unknown'}
        if request is not None and response is not None:
            rid = response.get('id')
            # Pinned Host completion serving.py141,177: HTTP completion ID is
            # cmpl-<original header>; the sole engine prompt is suffix -0.
            expected = 'cmpl-' + name + '-' + kind
            runtime_rid = expected + '-0'
            matched = [event for event in physical
                       if event.get('fields', {}).get('request_id') == runtime_rid]
            finished = [event for event in matched if event['event_type'] == 'RequestFinished']
            reclaimed = [event for event in matched if event['event_type'] == 'RequestKvReclaimed']
            usage = response.get('usage', {})
            bad = rid != expected or response.get('model') != request.get('model')
            bad |= response.get('error') is not None
            choices = response.get('choices', [])
            bad |= not choices or not all(isinstance(c.get('text'), str) and c['text'] for c in choices)
            if len(finished) != 1:
                row['missing_original_Host_finish_or_ambiguous'] = True
            else:
                fields = finished[0]['fields']
                bad |= fields.get('prompt_tokens') != usage.get('prompt_tokens')
                bad |= fields.get('output_tokens') != usage.get('completion_tokens')
                bad |= usage.get('total_tokens') != fields.get('sequence_tokens')
            row.update(response_id=rid, expected_runtime_RID=runtime_rid, usage=usage,
                       original_Host_finished=finished, original_Host_reclaimed=reclaimed,
                       body_and_Host_relation='failure' if bad else 'supported',
                       # This runner does not store raw absolute client HTTP
                       # clocks/headers/status. Do not borrow attempt summary.
                       functional_status='failure' if bad else 'unknown',
                       HTTP_deadline_status='unknown-missing-raw-HTTP-observation')
        requests.append(row)
    stderr = directory / 'stderr.log'
    startup_failure = False
    if stderr.is_file():
        raw = stderr.read_bytes()
        refs.append({'path': str(stderr), 'sha256': digest(raw), 'bytes': len(raw)})
        startup_failure = b'RuntimeError: Engine core initialization failed' in raw
    profiler = load(directory / 'profiler.jsonl', refs, lines=True)
    return {'case': name, 'status': 'raw-observations-only', 'raw_refs': refs,
            'actual_Popen': popen, 'loading': loading, 'Host_roster': [
                {'pid': key[0], 'start_ticks': key[1], 'slot': slot} for key, slot in roster.items()],
            'requests': requests, 'known_startup_failure_from_original_stderr': startup_failure,
            'KV_effect': 'not-applicable' if 'ascend_kvcompress' not in ORDERS[name] else 'unknown',
            'KV_unknown_reason': 'Requires original transaction/rank ACKs plus independent physical evidence; release-event counts alone do not discharge full rule.',
            'profiler_effect': 'not-applicable' if 'request_lifecycle_profiler' not in ORDERS[name] else 'unknown',
            'profiler_raw_record_count': None if profiler is None else len(profiler),
            'profiler_unknown_reason': 'Requires original trace/event/RID/epoch/lifecycle closure and no-loss evidence, not mere file presence.',
            'cleanup': 'unknown-no-independent-root-cleanup-consumed',
            'formal_result': False, 'composition_verdict': None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cohort', type=Path, required=True)
    parser.add_argument('--rule-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    raw = RULE.read_bytes()
    if digest(raw) != args.rule_sha256:
        raise ValueError('independent frozen rule bytes changed')
    rule = json.loads(raw)
    if set(rule['groups']) != set(ORDERS):
        raise ValueError('independent rule group inventory changed')
    result = {'schema': 'ecpa-H2-independent-raw-reader/v1', 'formal_result': False,
              'planner_outputs_consumed': False, 'summary_outputs_consumed': False,
              'oracle_rule': {'path': str(RULE), 'sha256': digest(raw)},
              'cases': [read_case(args.cohort.resolve(), name) for name in ORDERS],
              'composition_verdict': None,
              'limitations': ['Unknown does not mean compatible or incompatible.',
                              'This first reader projects source-owned raw facts and cannot mint a full rule verdict from missing HTTP/physical/root-cleanup evidence.']}
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
