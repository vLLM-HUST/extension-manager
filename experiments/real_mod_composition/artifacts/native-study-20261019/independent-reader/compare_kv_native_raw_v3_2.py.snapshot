"""Supplement v3 with independent original Host/native/log transaction joins.

This reads no attempt/verdict/planner output. Local native callbacks are not ACKs.
Post-result implementation is disclosed; the original pre-Popen rule is unchanged.
"""
import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
V3_SHA = '62b9bc66cffde32b2c46249cc94f73b99a36c4503ed6a72781320e42e40c0f17'
HOST7 = ('host', 'role', 'ordinal', 'pid', 'start_identity', 'process_epoch', 'assignment_source')
SCHED = re.compile(r'\(EngineCore pid=(\d+)\).*KV compression scheduler commit request_id=(\S+) semantic_tokens=(\d+) physical_tokens=(\d+) source_blocks=(\d+) destination_blocks=(\d+) released_blocks=(\d+)')
WORKER = re.compile(r'\(Worker_TP(\d+) pid=(\d+)\).*KV compression worker commit acknowledged request_id=(\S+) semantic_tokens=(\d+) physical_tokens=(\d+) destination_blocks=(\d+)')


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    v3_path = HERE / 'read_native_raw_v3.py'
    require(sha(v3_path.read_bytes()) == V3_SHA, 'frozen v3 changed')
    spec = importlib.util.spec_from_file_location('independent_v3', v3_path)
    v3 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(v3)
    v2 = v3.load_v2()
    v1 = v2.source_reader()
    refs = []
    case = args.case.resolve()
    rule_raw = v1.RULE.read_bytes()
    require(sha(rule_raw) == 'b44b71b98af2c0d2567dd606452847ea34b5c51c85538612c73a3ad886ee235a', 'frozen rule changed')
    token_raw = v2.TOKENIZER.read_bytes()
    require(sha(token_raw) == '59337698f2fb6f5bc89bf4479f63030cf73e5cdc41a02463887a009f150a419e', 'frozen tokenizer input changed')
    projected = v3.read_case(v2, v1, case.parent, case.name, json.loads(token_raw))
    host = v1.load(case / 'runtime-evidence.jsonl', refs, lines=True)
    study = v1.load(case / 'study-events.jsonl', refs, lines=True)
    native = v3.native_rows(study, projected['Host_roster'], projected['actual_Popen'])
    # Bridge each raw native producer back to the original Host event process,
    # including Plan/launch, rather than accepting a self-consistent second chain.
    for item in native:
        fact = item['raw']
        process = {name: fact['process'][name] for name in HOST7}
        matched = [event for event in host if event.get('process') == process
                   and event.get('plan_id') == fact['plan_id']
                   and event.get('launch_id') == fact['launch_id']
                   and event.get('identity_status') == 'launch-bound'
                   and event.get('binding_status') == 'bound']
        require(matched, 'native process/Plan/launch absent from original host-assigned event chain')
    stdout_path = case / 'stdout.log'
    raw = stdout_path.read_bytes()
    refs.append({'path': str(stdout_path), 'sha256': sha(raw), 'bytes': len(raw)})
    scheduler = []
    worker = []
    for number, line in enumerate(raw.decode().splitlines(), 1):
        match = SCHED.search(line)
        if match:
            pid, rid, semantic, physical, source, dest, released = match.groups()
            scheduler.append(dict(pid=int(pid), runtime_request_id=rid, semantic=int(semantic), physical=int(physical), source_blocks=int(source), destination_blocks=int(dest), released_blocks=int(released), original_line=number, raw_line=line))
        match = WORKER.search(line)
        if match:
            rank, pid, rid, semantic, physical, dest = match.groups()
            worker.append(dict(rank=int(rank), pid=int(pid), runtime_request_id=rid, semantic=int(semantic), physical=int(physical), destination_blocks=int(dest), original_line=number, raw_line=line))
    roster = {row['slot']: row for row in projected['Host_roster']}
    for row in scheduler:
        require(row['pid'] == roster['engine-core-scheduler/0']['pid'], 'scheduler commit not actual Host scheduler')
    for row in worker:
        require(row['rank'] in (0, 1) and row['pid'] == roster[f"worker/{row['rank']}"]['pid'], 'MOD worker ACK not actual Host TP rank')
    request_results = []
    for request in projected['requests']:
        if 'runtime_request_id' not in request:
            request_results.append({'kind': request['kind'], 'bounded_transaction_evidence': 'unknown'})
            continue
        rid = request['runtime_request_id']
        commits = [row for row in scheduler if row['runtime_request_id'] == rid]
        acks = [row for row in worker if row['runtime_request_id'] == rid]
        result = {'kind': request['kind'], 'runtime_request_id': rid,
                  'functional_status': request['functional_status'],
                  'scheduler_original_log': commits, 'MOD_worker_original_log_ACKs': acks,
                  'authenticated_native_ACK_claim': False,
                  'Host_finished': request['original_Host_finished'],
                  'Host_reclaimed': request['original_Host_reclaimed'],
                  'bounded_transaction_evidence': 'unknown'}
        ranks = request['independent_NPU_rank_evidence']
        if commits:
            require(len(commits) == 1, 'ambiguous scheduler transaction')
            commit = commits[0]
            require(len(acks) == 2 and {row['rank'] for row in acks} == {0, 1}, 'missing/duplicate original TP ACK')
            summaries = []
            for rank in ranks:
                require(len(rank['projection_transactions']) == 1, 'projection transaction missing/ambiguous')
                projection = rank['projection_transactions'][0]
                ack = next(row for row in acks if row['rank'] == rank['rank'])
                require((commit['semantic'], commit['physical'], commit['destination_blocks']) ==
                        (ack['semantic'], ack['physical'], ack['destination_blocks']) ==
                        (projection['semantic_anchor'], projection['physical_anchor'], len(projection['destination_block_ids'])), 'independent scheduler/MOD ACK/native projection anchors differ')
                before = rank.get('last_pre_apply_NPU_readback')
                after = rank.get('first_post_apply_NPU_readback')
                if before is None or after is None:
                    continue
                group = projection['attention_group']
                pre = [row for row in before['uploaded_rows'] if row['group'] == group]
                post = [row for row in after['uploaded_rows'] if row['group'] == group]
                require(len(pre) == len(post) == 1, 'actual rank cache group missing')
                require(len(pre[0]['blocks']) == commit['source_blocks'], 'scheduler source count differs from independent last pre-apply NPU prefix')
                require(post[0]['blocks'] == projection['host_cpu_block_ids'], 'independent first post-apply NPU prefix differs')
                summaries.append({'rank': rank['rank'], 'actual_kernel': projection['process'],
                                  'rank_local_transaction_id': projection['transaction_id'],
                                  'semantic_anchor': projection['semantic_anchor'], 'physical_anchor': projection['physical_anchor'],
                                  'destination_block_ids': projection['destination_block_ids'], 'scheduled_appended_block_ids': projection['scheduled_appended_block_ids'],
                                  'last_pre_apply_width': len(pre[0]['blocks']), 'first_post_apply_width': len(post[0]['blocks']),
                                  'last_pre_apply_clock': before['observed_after_barrier_monotonic_ns'],
                                  'metadata_effect_clock': projection['metadata_effect_monotonic_ns'],
                                  'first_post_apply_clock': after['observed_after_barrier_monotonic_ns']})
            result['rank_comparisons'] = summaries
            if len(summaries) == 2:
                result['bounded_transaction_evidence'] = 'supported-original-scheduler-and-two-rank-MOD-log-plus-independent-NPU-prefix-transition'
        else:
            result['no_commit_observed'] = True
        request_results.append(result)
    result = {'schema': 'ecpa-H2-independent-native-KV-comparison/v3.2',
              'implementation_freeze_after_result_observation': True,
              'formal_result': False, 'planner_or_attempt_verdict_consumed': False,
              'rule': {'path': str(v1.RULE), 'sha256': sha(rule_raw)},
              'case': str(case), 'original_v3_projection': projected,
              'native_Host7_and_actual_Plan_launch_join': 'supported',
              'requests': request_results, 'additional_raw_refs': refs,
              'counter_semantics': 'Host RequestFinished kv_blocks is original pre-release allocated-block count across cache groups, not TP-rank sum; immediate RequestKvReclaimed reuses that count and is not a second independent physical measurement.',
              'scope_limits': ['Rank-local projection transaction hashes include each rank metadata clock and need not equal each other.',
                               'MOD worker log ACK is distinct from source native callback transport; callback None is not an authenticated ACK.',
                               'NPU block-table prefix readback does not prove KV tensor equivalence, attention consumption, model quality, or performance.',
                               'Complete frozen-rule KV/composition verdict remains unknown pending matched controls, profiler evidence and independent cleanup.'],
              'KV_full_rule_verdict': 'unknown', 'composition_verdict': 'unknown'}
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
