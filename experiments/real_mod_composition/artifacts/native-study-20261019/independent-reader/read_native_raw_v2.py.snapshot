"""Versioned independent H2 raw reader; adds explicit external HTTP clock whitelist.

No planner/result/decision fields are consumed. v1 remains immutable. The root
runner's actual HTTP measurements are observations, not ECPA validity receipts.
"""
import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
V1 = HERE / 'read_native_raw_v1.py'
V1_SHA256 = '44539d9e44d3006ff17e2568729e3dcc905c969a0a98b9185f5b0fb42f43cbd4'
TOKENIZER = HERE.parent / 'independent-inputs/actual-tokenizer-inputs.json'
HTTP_FIELDS = ('http_status', 'elapsed_ns', 'usage', 'response_id')


def source_reader():
    if hashlib.sha256(V1.read_bytes()).hexdigest() != V1_SHA256:
        raise ValueError('frozen independent reader v1 changed')
    spec = importlib.util.spec_from_file_location('independent_h2_raw_v1', V1)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def external_http_projection(path, refs):
    """Access only genuine external observations, never verdict/error/formal keys."""
    if not path.is_file():
        return {}
    raw = path.read_bytes()
    refs.append({'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(),
                 'consumed_field_whitelist': [kind + '.' + field for kind in ('below', 'above') for field in HTTP_FIELDS]})
    parsed = json.loads(raw)
    projected = {}
    for kind in ('below', 'above'):
        value = parsed.get(kind)
        if isinstance(value, dict):
            projected[kind] = {field: value[field] for field in HTTP_FIELDS if field in value}
    return projected


def case_projection(v1, root, name, tokenizer):
    result = v1.read_case(root, name)
    if result['status'] == 'not-started':
        return result
    directory = root / name
    clocks = external_http_projection(directory / 'attempt.json', result['raw_refs'])
    tokens = {entry['id']: entry for entry in tokenizer['inputs']}
    for request in result['requests']:
        kind = request['kind']
        observation = clocks.get(kind)
        if observation is None or 'body_and_Host_relation' not in request:
            continue
        original = json.loads((directory / f'{kind}-request.json').read_bytes())
        independently_encoded = tokens[kind]
        prompt_digest = hashlib.sha256(original['prompt'].encode()).hexdigest()
        ids = independently_encoded['token_ids']
        ids_raw = json.dumps(ids, sort_keys=True, separators=(',', ':')).encode()
        token_binding = (
            prompt_digest == independently_encoded['prompt_UTF8_sha256']
            and original['prompt'] == independently_encoded['prompt']
            and len(ids) == independently_encoded['token_count']
            and hashlib.sha256(ids_raw).hexdigest() == independently_encoded['canonical_token_ids_sha256']
            and request['usage'].get('prompt_tokens') == len(ids)
        )
        elapsed = observation.get('elapsed_ns')
        deadline_met = type(elapsed) is int and 0 <= elapsed <= 240_000_000_000
        HTTP_match = (observation.get('http_status') == 200
                      and observation.get('response_id') == request['response_id']
                      and observation.get('usage') == request['usage'])
        known_body_failure = request['body_and_Host_relation'] == 'failure'
        finished = request.get('original_Host_finished', [])
        request.update(external_HTTP_observation=observation,
                       independent_tokenizer_prompt_match=token_binding,
                       independently_encoded_prompt_tokens=len(ids),
                       crosses_frozen_1152_token_threshold=len(ids) >= 1152,
                       HTTP_deadline_status='on-time' if deadline_met else 'failure',
                       functional_status=('failure' if known_body_failure or not HTTP_match or not deadline_met or not token_binding
                                          else 'supported' if len(finished) == 1 else 'unknown'),
                       deadline_scope='Actual client complete-response elapsed240s; not a claim that inactivity timeout alone enforces an absolute cancellation.')
    stderr = directory / 'stderr.log'
    text = stderr.read_text(errors='replace') if stderr.is_file() else ''
    sched = re.compile(r'KV compression scheduler commit request_id=(\S+) semantic_tokens=(\d+) physical_tokens=(\d+) source_blocks=(\d+) destination_blocks=(\d+) released_blocks=(\d+)')
    worker = re.compile(r'\(Worker_TP(\d+) pid=(\d+)\).*KV compression worker commit acknowledged request_id=(\S+) semantic_tokens=(\d+) physical_tokens=(\d+) destination_blocks=(\d+)')
    result['scheduler_transaction_raw_matches'] = [dict(request_id=m[1], semantic_anchor=int(m[2]), physical_anchor=int(m[3]), source_blocks=int(m[4]), destination_blocks=int(m[5]), released_blocks=int(m[6])) for m in sched.finditer(text)]
    result['worker_ACK_raw_matches'] = [dict(rank=int(m[1]), pid=int(m[2]), request_id=m[3], semantic_anchor=int(m[4]), physical_anchor=int(m[5]), destination_blocks=int(m[6])) for m in worker.finditer(text)]
    result['KV_effect'] = 'not-applicable' if 'ascend_kvcompress' not in v1.ORDERS[name] else 'unknown'
    result['no_automatic_effect_promotion'] = 'Even complete two-rank log matches are not alone the independent physical result or full rule proof.'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cohort', type=Path, required=True)
    parser.add_argument('--rule-sha256', required=True)
    parser.add_argument('--tokenizer-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    v1 = source_reader()
    rule_raw = v1.RULE.read_bytes()
    token_raw = TOKENIZER.read_bytes()
    if hashlib.sha256(rule_raw).hexdigest() != args.rule_sha256 or hashlib.sha256(token_raw).hexdigest() != args.tokenizer_sha256:
        raise ValueError('independent frozen rule/tokenizer subject changed')
    tokenizer = json.loads(token_raw)
    result = {'schema': 'ecpa-H2-independent-raw-reader/v2', 'formal_result': False,
              'planner_outputs_consumed': False, 'passed_or_error_or_formal_summary_fields_consumed': False,
              'clock_policy_version': 'v2-explicit-root-runner-per-request-HTTP-whitelist',
              'prior_v1_frozen_bytes_preserved': True,
              'rule': {'path': str(v1.RULE), 'sha256': args.rule_sha256},
              'tokenizer': {'path': str(TOKENIZER), 'sha256': args.tokenizer_sha256},
              'cases': [case_projection(v1, args.cohort.resolve(), name, tokenizer) for name in v1.ORDERS],
              'composition_verdict': 'unknown',
              'remaining_obligations': ['Independent physical result and full profiler trace/RID/epoch/no-loss closure.', 'Actual owned process/port/device cleanup rather than a caller cleanup-ready flag.', 'Both singletons and both actual orders before composition acceptance.']}
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')


if __name__ == '__main__':
    main()
