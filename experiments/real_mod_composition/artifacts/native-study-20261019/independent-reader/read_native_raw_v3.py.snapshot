"""Raw-only H2 reader v3: actual opaque mappings, HTTP clocks and native readbacks.

Local callback/None returns are never authenticated ACKs. Native prefix evidence
proves only the declared block-table scope, not KV tensor/model equivalence.
"""
import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
V2 = HERE / 'read_native_raw_v2.py'
V2_SHA = 'd492f122bc1a09c79a375925a9cf23c1b8eeef163b791c4bb7ee79265ee9e8a5'
UPLOAD = 'ecpa-native-block-table-upload/v1'
MAPPING = 'ecpa-native-request-id-mapping/v1'
PROJECTION = 'ecpa-native-kv-blocktable-projection/v2'
TRANSACTION_FIELDS = ('runtime_request_id', 'attention_group', 'semantic_anchor', 'physical_anchor',
                      'destination_block_ids', 'host_cpu_block_ids', 'allocation_block_size',
                      'compression_threshold_tokens', 'scheduled_appended_block_ids',
                      'metadata_effect_monotonic_ns')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def require(value, message):
    if not value:
        raise ValueError(message)


def load_v2():
    require(hashlib.sha256(V2.read_bytes()).hexdigest() == V2_SHA, 'frozen v2 bytes changed')
    spec = importlib.util.spec_from_file_location('independent_h2_raw_v2', V2)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def native_rows(study, host, popen):
    roster = {(row['pid'], row['start_ticks']): row['slot'] for row in host}
    identities = {}
    result = []
    for event in study:
        if event.get('kind') != 'native-fact':
            continue
        fact = event['fact']
        process = fact['process']
        key = (event['pid'], event['start_ticks'])
        require(process['pid'] == key[0] and process['start_ticks'] == key[1], 'native fact/writer epoch differs')
        require(process['assignment_source'] == 'host' and process['boot_id'] == popen['boot_id'], 'native fact Host/boot differs')
        slot = f"{process['role']}/{process['ordinal']}"
        require(roster.get(key) == slot and process['start_identity'] == f'pid:{key[0]}:start_ticks:{key[1]}', 'native fact exact Host role absent')
        require(type(fact['monotonic_ns']) is int and fact['monotonic_ns'] <= event['monotonic_ns'], 'native fact clock differs')
        require(type(fact['plan_id']) is str and fact['plan_id'] and type(fact['launch_id']) is str and fact['launch_id'], 'native fact lacks actual Plan/launch')
        identities.setdefault('epoch', (fact['plan_id'], fact['launch_id']))
        require(identities['epoch'] == (fact['plan_id'], fact['launch_id']), 'mixed native Plan/launch')
        if fact['schema'] == UPLOAD:
            require(slot in {'worker/0', 'worker/1'} and str(fact['device']).startswith('npu'), 'native upload lacks real worker/NPU')
            require(fact['scope'] == 'NPU-block-table-prefix-readback-only', 'native upload scope differs')
            require(hashlib.sha256(canonical(fact['uploaded_rows'])).hexdigest() == fact['uploaded_rows_sha256'], 'native upload rows hash differs')
            require(fact['monotonic_ns'] <= fact['observed_after_barrier_monotonic_ns'] <= event['monotonic_ns'], 'native barrier/readback clock differs')
            groups = []
            for row in fact['uploaded_rows']:
                require(set(row) == {'group', 'row', 'blocks'} and type(row['group']) is int and type(row['row']) is int, 'native uploaded row malformed')
                require(row['blocks'] and all(type(block) is int and block >= 0 for block in row['blocks']), 'native uploaded block prefix malformed')
                groups.append(row['group'])
            require(len(groups) == len(set(groups)), 'native upload duplicates cache group')
            require(all(fact[name] is None for name in ('kv_tensor_equivalence', 'attention_consumed_observed_tensor', 'full_generation_quality')), 'prefix observation misrepresented as tensor/model proof')
        elif fact['schema'] == PROJECTION:
            require(slot in {'worker/0', 'worker/1'}, 'projection lacks actual TP rank')
            transaction = {name: fact[name] for name in TRANSACTION_FIELDS}
            require(hashlib.sha256(canonical(transaction)).hexdigest() == fact['transaction_id'], 'projection actual transaction hash differs')
            require(fact['host_cpu_block_ids'] == fact['destination_block_ids'] + fact['scheduled_appended_block_ids'], 'projection destination/append differs')
            require(fact['physical_anchor'] == len(fact['destination_block_ids']) * fact['allocation_block_size'], 'projection physical anchor differs')
            require(0 < fact['physical_anchor'] < fact['compression_threshold_tokens'] <= fact['semantic_anchor'], 'projection threshold/anchors differ')
            require(fact['metadata_effect_monotonic_ns'] <= fact['monotonic_ns'], 'projection metadata precedes actual apply')
        elif fact['schema'] == MAPPING:
            require(slot == 'api-server/0', 'native mapping not actual API-owned')
        else:
            require(False, 'unsupported native fact schema: ' + str(fact.get('schema')))
        result.append({'writer': key, 'slot': slot, 'raw': fact})
    return result


def read_case(v2, v1, root, name, tokenizer):
    result = v1.read_case(root, name)
    if result['status'] == 'not-started':
        return result
    directory = root / name
    refs = result['raw_refs']
    study = v1.load(directory / 'study-events.jsonl', refs, lines=True) or []
    native = native_rows(study, result['Host_roster'], result['actual_Popen'])
    tokens = {item['id']: item for item in tokenizer['inputs']}
    requests = []
    for kind in ('below', 'above'):
        request = v1.load(directory / f'{kind}-request.json', refs)
        response = v1.load(directory / f'{kind}-response.json', refs)
        start = v1.load(directory / f'{kind}-request-clock.json', refs)
        finish = v1.load(directory / f'{kind}-response-clock.json', refs)
        row = {'kind': kind, 'functional_status': 'unknown', 'KV_physical_evidence': 'unknown'}
        if request is None or response is None or start is None or finish is None:
            requests.append(row)
            continue
        external = f'cmpl-{name}-{kind}-0'
        actual = [event for event in study if event.get('kind') == 'actual-request-mapping' and event.get('external_request_id') == external]
        require(len(actual) <= 1, 'ambiguous actual external/opaque mapping')
        if not actual:
            row['missing'] = 'original API actual mapping'
            requests.append(row)
            continue
        mapping = actual[0]
        key = (mapping['pid'], mapping['start_ticks'])
        require(any((item['pid'], item['start_ticks']) == key and item['slot'] == 'api-server/0' for item in result['Host_roster']), 'actual mapping API kernel absent')
        runtime = mapping['runtime_request_id']
        encoded = tokens[kind]
        require(request['prompt'] == encoded['prompt'] and hashlib.sha256(request['prompt'].encode()).hexdigest() == encoded['prompt_UTF8_sha256'], 'matched prompt bytes differ')
        require(mapping['prompt_token_ids'] == encoded['token_ids'], 'actual Host tokenizer IDs differ from independent encoding')
        require(hashlib.sha256(canonical(encoded['token_ids'])).hexdigest() == encoded['canonical_token_ids_sha256'], 'independent IDs digest differs')
        native_maps = [item for item in native if item['raw']['schema'] == MAPPING and item['raw']['external_request_id'] == external]
        if native_maps:
            require(len(native_maps) == 1 and native_maps[0]['raw']['runtime_request_id'] == runtime and native_maps[0]['writer'] == key, 'original/native API opaque mappings differ')
        events = [event for event in study if event.get('kind') == 'host-event' and event.get('fields', {}).get('request_id') == runtime]
        ended = [event for event in events if event['event_type'] == 'RequestFinished']
        freed = [event for event in events if event['event_type'] == 'RequestKvReclaimed']
        usage = response.get('usage', {})
        elapsed = finish['end_monotonic_ns'] - start['start_monotonic_ns']
        ok = (response.get('id') == external.removesuffix('-0') and response.get('model') == request['model'] and finish['http_status'] == 200
              and 0 <= elapsed <= 240_000_000_000 and usage.get('prompt_tokens') == len(encoded['token_ids'])
              and usage.get('completion_tokens') == request['max_tokens'] == 32
              and usage.get('total_tokens') == usage.get('prompt_tokens', -1000) + usage.get('completion_tokens', -1000)
              and response.get('choices') and all(choice.get('text') for choice in response['choices']))
        if len(ended) == 1:
            fields = ended[0]['fields']
            ok = ok and fields['prompt_tokens'] == usage['prompt_tokens'] and fields['output_tokens'] == usage['completion_tokens'] and fields['sequence_tokens'] == usage['total_tokens']
        row.update(functional_status='supported' if ok and len(ended) == 1 else 'failure' if not ok else 'unknown',
                   external_request_id=external, runtime_request_id=runtime, actual_API_epoch=list(key),
                   actual_token_ids_match=True, actual_prompt_tokens=len(encoded['token_ids']), usage=usage,
                   raw_HTTP_elapsed_ns=elapsed, original_Host_finished=ended, original_Host_reclaimed=freed)
        uploads = [item for item in native if item['raw']['schema'] == UPLOAD and item['raw']['runtime_request_id'] == runtime]
        projections = [item for item in native if item['raw']['schema'] == PROJECTION and item['raw']['runtime_request_id'] == runtime]
        rank_evidence = []
        for rank in (0, 1):
            values = sorted([item for item in uploads if item['slot'] == f'worker/{rank}'], key=lambda item: item['raw']['observed_after_barrier_monotonic_ns'])
            ps = [item for item in projections if item['slot'] == f'worker/{rank}']
            evidence = {'rank': rank, 'original_NPU_readback_count': len(values), 'projection_transactions': [item['raw'] for item in ps]}
            if values:
                evidence['first_NPU_readback'] = values[0]['raw']
                evidence['last_NPU_readback'] = values[-1]['raw']
            if len(ps) == 1:
                projection = ps[0]['raw']
                before = [item for item in values if item['raw']['observed_after_barrier_monotonic_ns'] < projection['metadata_effect_monotonic_ns']]
                after = [item for item in values if item['raw']['monotonic_ns'] >= projection['monotonic_ns']]
                if before:
                    evidence['last_pre_apply_NPU_readback'] = before[-1]['raw']
                if after:
                    first = after[0]['raw']
                    groups = [entry for entry in first['uploaded_rows'] if entry['group'] == projection['attention_group']]
                    require(len(groups) == 1 and groups[0]['blocks'] == projection['host_cpu_block_ids'], 'actual post-apply NPU prefix contradicts Host transaction projection')
                    evidence['first_post_apply_NPU_readback'] = first
                    evidence['actual_projection_NPU_prefix_match'] = True
            rank_evidence.append(evidence)
        row['independent_NPU_rank_evidence'] = rank_evidence
        row['KV_physical_evidence'] = ('bounded-two-rank-NPU-prefix-observed' if all(item['original_NPU_readback_count'] for item in rank_evidence) else 'unknown')
        row['native_callback_authenticated_ACK_claim'] = False
        row['KV_tensor_or_attention_equivalence_claim'] = False
        row['physical_timing_limit'] = 'Compare original per-step readback and actual projection times; no implicit substitution of release count for live occupancy.'
        requests.append(row)
    result['requests'] = requests
    result['raw_native_schema_counts'] = {schema: sum(item['raw']['schema'] == schema for item in native) for schema in (MAPPING, UPLOAD, PROJECTION)}
    result['native_fact_transport'] = 'source-owned local receiver; no authenticated ACK or phase-drain proof'
    result['KV_effect'] = 'not-applicable' if 'ascend_kvcompress' not in v1.ORDERS[name] else 'unknown-until-complete-rule-transaction-and-matched-controls'
    result['composition_verdict'] = 'unknown'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cohort', type=Path, required=True)
    parser.add_argument('--rule-sha256', required=True)
    parser.add_argument('--tokenizer-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    v2 = load_v2()
    v1 = v2.source_reader()
    require(hashlib.sha256(v1.RULE.read_bytes()).hexdigest() == args.rule_sha256, 'frozen rule changed')
    token_raw = v2.TOKENIZER.read_bytes()
    require(hashlib.sha256(token_raw).hexdigest() == args.tokenizer_sha256, 'independent tokenizer subject changed')
    result = {'schema': 'ecpa-H2-independent-raw-reader/v3', 'formal_result': False,
              'rule': {'path': str(v1.RULE), 'sha256': args.rule_sha256},
              'tokenizer': {'path': str(v2.TOKENIZER), 'sha256': args.tokenizer_sha256},
              'planner_or_outcome_or_passed_summary_consumed': False,
              'native_callback_authenticated_ACK_claim': False,
              'cases': [read_case(v2, v1, args.cohort.resolve(), name, json.loads(token_raw)) for name in v1.ORDERS],
              'composition_verdict': 'unknown'}
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
