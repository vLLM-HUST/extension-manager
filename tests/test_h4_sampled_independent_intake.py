"""Unexecuted candidate tests: independent replay, never device qualification."""
import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest

from experiments.formal_campaign import h4_sampled_intake as intake
from experiments.formal_campaign import h4_sampled_native_replay as replay
from experiments.formal_campaign.analyze import h4_body_binding, h4_request_identity_observation, h4_response_summary


def wire(request_id='new/req-0', completion=16):
    request=json.dumps({'model':'real-model','prompt':'new independent intent','max_tokens':64}).encode()
    response=json.dumps({'id':'cmpl-'+request_id,'model':'real-model','choices':[
        {'index':0,'text':'actual response','finish_reason':'length'}],
        'usage':{'prompt_tokens':1195,'completion_tokens':completion,'total_tokens':1195+completion}}).encode()
    return request,response


def test_functional_response_exact_new_request_and_usage():
    import sys
    from experiments.formal_campaign.h4_sampled_registration import original_h4_runner
    module=original_h4_runner()
    assert module.validate_receipt.__module__=='experiments.formal_campaign.run_h4'
    assert 'analyze' not in sys.modules
    request,response=wire()
    replay.verify_functional_response('new/req-0',request,response)


@pytest.mark.parametrize('field,value',[
    ('id','cmpl-another-request'),('model','another-model'),
    ('completion_tokens',15),('completion_tokens',65),('total_tokens',0),('completion_tokens',True),
])
def test_functional_response_rejects_cross_request_or_invalid_counts(field,value):
    request,response=wire();data=json.loads(response)
    if field in {'id','model'}:data[field]=value
    else:data['usage'][field]=value
    with pytest.raises(ValueError):
        replay.verify_functional_response('new/req-0',request,json.dumps(data).encode())


def traffic():
    schedule={'requests':[]};rows=[]
    selection=set(range(16))|{16+16*i for i in range(16)}
    request,_=wire();sha=hashlib.sha256(request).hexdigest()
    for i in range(272):
        rid=f'new/start/request-{i:05d}';_,response=wire(rid)
        headers=[['X-Request-Id',rid]]
        evidence={'status_code':200,'headers':[],**h4_body_binding(response)}
        schedule['requests'].append(dict(all_index=i,request_id=rid,selected=i in selection,body_sha256=sha))
        row=dict(all_index=i,request_id=rid,selected=i in selection,kind='warmup' if i<16 else 'measured',
                 dispatch_ns=1+i*10,complete_ns=2+i*10,http_request=h4_body_binding(request),
                 http_response=evidence,request_headers=headers,
                 request_identity=h4_request_identity_observation(rid,headers,evidence),
                 native_clock={'sent_ns':100+i,'deadline_ns':120_000_000_100+i,
                               'backend_sent_ns':101+i,'received_ns':102+i,'http_deadline_met':True},
                 native_verified=i in selection,error=None)
        row.update(h4_response_summary(evidence));rows.append(row)
    return rows,schedule,request


def test_all272_recomputed_and_missing_response_id_stays_null():
    rows,schedule,request=traffic()
    actual=intake.verify_traffic(list(reversed(rows)),schedule,request)
    assert len(actual)==272
    assert sum(r['selected'] for r in actual)==32
    assert actual[0]['request_identity']['server_header_request_id'] is None


@pytest.mark.parametrize('mutation',['duplicate','missing','body','metadata','deadline','header'])
def test_original_traffic_tamper_never_hides_behind32_samples(mutation):
    rows,schedule,request=traffic()
    row=rows[271]  # explicitly unselected measured request
    if mutation=='duplicate':rows[-1]=copy.deepcopy(rows[270])
    elif mutation=='missing':rows.pop()
    elif mutation=='body':row['http_request']['body_sha256']='sha256:'+'0'*64
    elif mutation=='metadata':row['request_identity']['server_completion_id']='cmpl-forged'
    elif mutation=='deadline':row['native_clock']['deadline_ns']+=1
    elif mutation=='header':row['request_headers']=[['X-Request-Id','other']]
    with pytest.raises(ValueError):intake.verify_traffic(rows,schedule,request)


def test_archived_sender_cross_epoch_and_bool_ordinal_rejected():
    peers=[{'process':dict(role=r,ordinal=n,pid=100+i,start_ticks=50+i,session=100,boot_id='boot'),
            'peer_uid':0,'peer_gid':0,'cmdline_sha256':'a'*64,'source_files':[]}
           for i,(r,n) in enumerate((('api-server',0),('worker',0),('worker',1)))]
    replay.verify_archived_senders(peers,copy.deepcopy(peers))
    bad=copy.deepcopy(peers);bad[-1]['process']['start_ticks']+=1
    with pytest.raises(ValueError):replay.verify_archived_senders(bad,peers)
    bad=copy.deepcopy(peers);bad[-1]['process']['ordinal']=True
    with pytest.raises(ValueError):replay.verify_archived_senders(bad,peers)


def test_proof_reference_body_sha_is_independently_recomputed(tmp_path):
    path=tmp_path/'native-consume-report.json';path.write_bytes(b'original')
    ref={'path':str(path),'sha256':hashlib.sha256(b'original').hexdigest()}
    assert replay.check_ref(ref)==path
    path.write_bytes(b'tampered')
    with pytest.raises(ValueError):replay.check_ref(ref)


def test_coherent_four_role_sample_must_not_mix_different_times():
    owner=dict(pid=10,start_ticks=1,session=10,boot_id='boot')
    roster={};kernels={}
    for i,slot in enumerate(('api-server/0','engine-core-scheduler/0','worker/0','worker/1')):
        role,n=slot.split('/');pid=20+i
        kernels[slot]=dict(pid=pid,start_ticks=5+i,session=10,boot_id='boot')
        roster[slot]=dict(role=role,ordinal=int(n),pid=pid,assignment_source='host',
                          start_identity=f'pid:{pid}:start_ticks:{5+i}')
    all_members=[{k:v for k,v in row.items() if k!='boot_id'} for row in kernels.values()]
    archive={'root':owner,'samples':[{'members':all_members}]}
    intake.coherent_roster(archive,owner,roster,kernels)
    archive['samples']=[{'members':all_members[:2]},{'members':all_members[2:]}]
    with pytest.raises(ValueError):intake.coherent_roster(archive,owner,roster,kernels)


def test_full_native_consumer_is_called_on_original_global_journal(tmp_path,monkeypatch):
    request,response=wire()
    peers=[{'process':dict(role=r,ordinal=n),'peer_uid':0,'peer_gid':0,'cmdline_sha256':'a'*64}
           for r,n in (('api-server',0),('worker',0),('worker',1))]
    spec={'native_plan_id':'plan','native_launch_id':'launch','senders':peers}
    records={}
    for key,value in (('native_spec',spec),('tensor_policy',{}),('drain_policy',{})):
        path=tmp_path/(key+'.json');raw=json.dumps(value).encode();path.write_bytes(raw);records[key]=str(path)
        records[{'native_spec':'spec_sha256','tensor_policy':'policy_sha256','drain_policy':'drain_sha256'}[key]]=hashlib.sha256(raw).hexdigest()
    journal=tmp_path/'global-original.jsonl';journal.write_bytes(b'global unfiltered original bytes\n')
    record=dict(records,request_id='new/req-0',response_sha256=hashlib.sha256(response).hexdigest(),
        response_body_base64=base64.b64encode(response).decode(),original_sent_ns=1,backend_sent_ns=2,
        backend_received_ns=3,verified_monotonic_ns=4,original_deadline_ns=120_000_000_001,
        journal=str(journal),sealed_prefix={'original':'prefix'})
    path=tmp_path/'report.json';path.write_text(json.dumps(record))
    class ReachedOriginalFullConsumer(Exception):pass
    def full_consumer(spec,policy,original,**kwargs):
        assert original==str(journal)
        assert Path(original).read_bytes()==b'global unfiltered original bytes\n'
        assert kwargs['acknowledged_prefix']=={'original':'prefix'}
        assert kwargs['_owner'] is not None and kwargs['_owned_materializations']=={}
        raise ReachedOriginalFullConsumer
    monkeypatch.setattr(replay.attention_consumer,'_verify_attention_archive',full_consumer)
    with pytest.raises(ReachedOriginalFullConsumer):
        replay.replay_sampled_native_report({'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()},
            request_id='new/req-0',request_body=request,response_body=response,
            response_expectation={'min_completion_tokens':16,'max_completion_tokens':64},
            enrollment={'native_plan_id':'plan','native_launch_id':'launch','source_peers':peers},deadline_ns=120_000_000_001)


def profiler_case(tmp_path, runtime='actual-opaque-runtime'):
    # A valid typed Host runtime_effective event, not a boolean mock.
    process=dict(host='actual-host',role='api-server',ordinal=0,pid=120,
                 start_identity='pid:120:start_ticks:90',process_epoch=1,assignment_source='host')
    entry=dict(zip(('group','name','value'),intake.pair.ENTRIES[intake.PROFILER]))
    occurrence=hashlib.sha256(('request_finished\0'+runtime).encode()).hexdigest()
    event=dict(schema='vllm-hust-plugin-evidence/0.1',event_id='',event='effective',
        observation_kind='runtime_effective',entry_point=entry,process=process,observed_at_ns=150,
        delivery_attempt=1,plan_id='plan',launch_id='launch',binding_status='bound',
        occurrence_id=occurrence,controller_instance_id=None,invocation_seq=None,dispatch_id=None,
        plugin_id=None,artifact_digest=None,identity_status='unresolved',
        detail='request-lifecycle-eventbus:request_finished')
    material=[process['host'],120,process['start_identity'],1,'api-server',0,
              *entry.values(),'effective',event['detail'],occurrence,'plan','launch',
              'runtime_effective',None,1,150,'host']
    event['event_id']=hashlib.sha256(json.dumps(material,separators=(',',':')).encode()).hexdigest()
    raw=json.dumps(event,separators=(',',':')).encode()+b'\n'
    path=tmp_path/'profiler-original.jsonl';path.write_bytes(raw)
    record=dict(profiler_snapshot=str(path),profiler_snapshot_sha256=hashlib.sha256(raw).hexdigest(),
        profiler_before_prefix_sha256=hashlib.sha256(b'').hexdigest(),profiler_before_wall_ns=100,
        profiler_after_wall_ns=200,profiler_occurrence_id=occurrence,profiler_matched_events=[event],
        phase={'phase_id':'selected-0'},full_archive={'attention_complete_transactions':[
            {'phase_id':'selected-0','runtime_request_id':runtime}]})
    epoch=dict(enrollment={'native_plan_id':'plan','native_launch_id':'launch'},roster={'api-server/0':process})
    return record,{'path':str(tmp_path/'native-consume-report.json')},epoch,raw


def test_profiler_replays_valid_typed_event_for_same_native_opaque_request(tmp_path):
    intake.verify_profiler(*profiler_case(tmp_path))


def test_profiler_different_real_runtime_cannot_be_relabelled_by_metadata(tmp_path):
    record,ref,epoch,raw=profiler_case(tmp_path)
    record['full_archive']['attention_complete_transactions'][0]['runtime_request_id']='another-real-runtime'
    with pytest.raises(ValueError):intake.verify_profiler(record,ref,epoch,raw)


@pytest.mark.parametrize('reported_span,caller_renewal',[(10_000_000_000,0),(120_000_000_000,1)])
def test_archived_native_deadline_is_original120_not_h3_or_renewable(tmp_path,reported_span,caller_renewal):
    request,response=wire()
    deadline=1+reported_span
    record=dict(request_id='new/req-0',response_sha256=hashlib.sha256(response).hexdigest(),
        response_body_base64=base64.b64encode(response).decode(),original_sent_ns=1,
        backend_sent_ns=2,backend_received_ns=3,verified_monotonic_ns=4,original_deadline_ns=deadline)
    path=tmp_path/'report.json';path.write_text(json.dumps(record))
    with pytest.raises(ValueError):
        replay.replay_sampled_native_report({'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()},
            request_id='new/req-0',request_body=request,response_body=response,
            response_expectation={'min_completion_tokens':16,'max_completion_tokens':64},
            enrollment={},deadline_ns=deadline+caller_renewal)


def test_unselected_late200_cannot_be_on_time_performance():
    rows,schedule,request=traffic();row=rows[271]
    row['native_clock'].update(received_ns=row['native_clock']['deadline_ns']+1,http_deadline_met=False)
    with pytest.raises(ValueError):intake.verify_traffic(rows,schedule,request)
    # Original late bytes remain, but only as a failed request, never hidden.
    row['error']='ObservedHTTPDeadlineExceeded: original absolute HTTP120 expired'
    actual=intake.verify_traffic(rows,schedule,request)
    assert actual[271]['http_response']['status_code']==200
    assert actual[271]['native_clock']['http_deadline_met'] is False


def test_unselected240_missing_receive_clock_is_unknown_not_pass():
    rows,schedule,request=traffic();rows[271]['native_clock']['received_ns']=None
    with pytest.raises(ValueError):intake.verify_traffic(rows,schedule,request)


def _typed_event(event):
    p=event['process'];e=event['entry_point']
    material=[p['host'],p['pid'],p['start_identity'],p['process_epoch'],p['role'],p['ordinal'],
              e['group'],e['name'],e['value'],event['event'],event['detail'],event['occurrence_id'],
              event['plan_id'],event['launch_id'],event['observation_kind'],event['controller_instance_id'],
              event['delivery_attempt'],event['observed_at_ns'],p['assignment_source']]
    event['event_id']=hashlib.sha256(json.dumps(material,separators=(',',':')).encode()).hexdigest()
    return json.dumps(event,separators=(',',':')).encode()+b'\n'


@pytest.mark.parametrize('role',['api-server','engine-core-scheduler'])
def test_environment_effective_never_substitutes_assigned_profiler_callback(tmp_path,role):
    record,ref,epoch,raw=profiler_case(tmp_path)
    event=json.loads(raw)
    event['process'].update(assignment_source='environment',role=role,pid=999,start_identity='pid:999:start_ticks:888')
    raw=_typed_event(event);Path(record['profiler_snapshot']).write_bytes(raw)
    record.update(profiler_snapshot_sha256=hashlib.sha256(raw).hexdigest(),profiler_matched_events=[event])
    with pytest.raises(ValueError):intake.verify_profiler(record,ref,epoch,raw)


def test_environment_unknown_loader_requires_exact_later_assigned_epoch(tmp_path):
    record,ref,epoch,raw=profiler_case(tmp_path)
    unknown=json.loads(raw)
    unknown.update(event='discovered',observation_kind='loader_lifecycle',occurrence_id=None)
    unknown['process'].update(role='unknown',assignment_source='environment')
    prefix=_typed_event(unknown);full=prefix+raw
    Path(record['profiler_snapshot']).write_bytes(full)
    record['profiler_snapshot_sha256']=hashlib.sha256(full).hexdigest()
    intake.verify_profiler(record,ref,epoch,full)
    unknown['process'].update(pid=999,start_identity='pid:999:start_ticks:888')
    full=_typed_event(unknown)+raw;Path(record['profiler_snapshot']).write_bytes(full)
    record['profiler_snapshot_sha256']=hashlib.sha256(full).hexdigest()
    with pytest.raises(ValueError):intake.verify_profiler(record,ref,epoch,full)


def test_full_schedule_unsampled_identity_is_bound_to_registered_sha(tmp_path):
    from experiments.formal_campaign.h4_sampled_native_schedule import SELECTED_INDICES
    from experiments.formal_campaign.h4_sampled_registration import read_registered_schedule
    selected=set(SELECTED_INDICES);rows=[];phases=[]
    for i in range(272):
        rid=f'new-freeze/request-{i:04d}';phase_id=f'p{i:04d}'
        rows.append(dict(all_index=i,request_id=rid,external_request_id='cmpl-'+rid+'-0',
                         phase_id=phase_id,body_sha256='a'*64,selected=i in selected))
        if i in selected:phases.append(dict(phase_id=phase_id,client_request_id=rid,
            external_request_id='cmpl-'+rid+'-0',expected_ranks=[0,1],challenge_nonce=f'{i:032x}'))
    schedule=dict(schema='ecpa-h4-sampled-native-schedule/v1',request_count=272,warmup_count=16,
        measured_count=256,concurrency=8,timeout_s=120,selected_all_indices=list(SELECTED_INDICES),requests=rows)
    path=tmp_path/'schedule.json';raw=json.dumps(schedule,sort_keys=True,separators=(',',':')).encode()
    path.write_bytes(raw);path.chmod(0o600)
    ref={'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()}
    read_registered_schedule(ref,phases)
    schedule['requests'][271].update(request_id='replacement-unsampled',external_request_id='cmpl-replacement-unsampled-0')
    path.write_bytes(json.dumps(schedule,sort_keys=True,separators=(',',':')).encode())
    with pytest.raises(ValueError):read_registered_schedule(ref,phases)


@pytest.mark.parametrize('drip_phase',['headers','body'])
def test_actual_socket_absolute_deadline_interrupts_drip_before_server_finishes(drip_phase):
    import http.server
    import threading
    import time
    from types import SimpleNamespace
    from experiments.formal_campaign import run_h4_sampled as runner
    from experiments.formal_campaign.h3_worker_relaunch import identity
    stop=threading.Event();server_done=threading.Event();connected=threading.Event()
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            if drip_phase=='body':
                # Forces HTTPConnection.sock=None while HTTPResponse keeps its
                # socket makefile. The watchdog must retain that original socket.
                self.send_response(200);self.send_header('Content-Length','1000000')
                self.send_header('Connection','close');self.end_headers()
            else:
                self.connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\nConnection: close\r\nX-Drip: ')
            connected.set()
            # Intentionally do not finish even when the client aborts; prove
            # the client returns at its budget, before this independent end.
            while not stop.wait(.02):
                try:self.connection.sendall(b'x')
                except OSError:pass
            server_done.set()
        def log_message(self,*args):pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=lambda:server.serve_forever(poll_interval=.01),daemon=True);thread.start()
    epoch={'kernels':{'api-server/0':identity(__import__('os').getpid())},
           'bound':SimpleNamespace(validate_current=lambda *args:None),'enrollment':{},'host_journal':None}
    clock={};started=time.monotonic_ns();deadline=started+200_000_000
    try:
        with pytest.raises(TimeoutError):
            runner.exchange(f'http://127.0.0.1:{server.server_port}/v1/completions','POST',b'{}','new-rid',
                            epoch,deadline,clock_observation=clock)
        returned=time.monotonic_ns()
        assert connected.is_set() and not server_done.is_set()
        assert deadline<=returned<started+900_000_000
        assert clock['deadline_cancellation_ns']>=deadline
        assert not any(t.name=='h4-http-absolute-deadline' for t in threading.enumerate())
        if 'interrupted_response' in clock:
            partial=clock['interrupted_response']
            assert partial['body_complete'] is False
            assert h4_body_binding(h4_decode_for_test(partial))['body_sha256']==partial['body_sha256']
    finally:
        stop.set();server.shutdown();server.server_close();thread.join(timeout=1)


def h4_decode_for_test(binding):
    return base64.b64decode(binding['body_base64'],validate=True)


def _preflight_phase(tmp_path):
    from experiments.formal_campaign.h4_sampled_native_source_scope import (
        API_SOURCE_SUFFIXES, WORKER_RECEIVER_SUFFIXES,
    )
    sources=[]
    for suffix in set(API_SOURCE_SUFFIXES + WORKER_RECEIVER_SUFFIXES):
        path=tmp_path / suffix.lstrip('/')
        path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'actual source bytes')
        sources.append(dict(path=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    phases=[dict(phase_id=f'p{i:02d}',client_request_id=f'new-frozen/warmup-{i:04d}',
        external_request_id=f'cmpl-new-frozen/warmup-{i:04d}-0',
        expected_ranks=[0,1],challenge_nonce=f'{i:032x}') for i in range(32)]
    kv={p['phase_id']:dict(semantic_anchor=1152,physical_anchor=1024) for p in phases}
    tensors={k:dict(layer_indices=list(range(28)),**v) for k,v in kv.items()}
    path=tmp_path/'semantic.json';raw=json.dumps({'native_plan_id':'a'*64}).encode();path.write_bytes(raw)
    return dict(semantic_launch_spec=dict(path=str(path),sha256=hashlib.sha256(raw).hexdigest()),
        native_bootstrap=dict(source_files=sources,phases=phases,kv_requirements=kv,tensor_requirements=tensors))


def test_pre_popen_size_retains_all32_full_source_union_and_is_not_authentication(tmp_path):
    from experiments.formal_campaign.h4_sampled_registration import preflight_native_spec
    phase=_preflight_phase(tmp_path);before=copy.deepcopy(phase)
    report=preflight_native_spec(phase)
    assert phase==before and report['actual_request_count']==32
    assert report['source_paths']==len(phase['native_bootstrap']['source_files'])
    assert report['native_or_kernel_authentication_performed'] is False
    assert report['conservative_spec_bytes']<=65536


@pytest.mark.parametrize('mutation',['over64k','missing-phase','missing-tensor'])
def test_pre_popen_size_rejects_overlimit_or_reduced_original32(tmp_path,mutation):
    from experiments.formal_campaign.h4_sampled_registration import preflight_native_spec
    phase=_preflight_phase(tmp_path);boot=phase['native_bootstrap']
    if mutation=='over64k':
        boot['phases'][0]['client_request_id']='x'*65536
        boot['phases'][0]['external_request_id']='cmpl-'+'x'*65536+'-0'
    elif mutation=='missing-phase':boot['phases'].pop()
    else:boot['tensor_requirements'].pop('p00')
    with pytest.raises(ValueError):preflight_native_spec(phase)


def test_launch_rejects_failed_size_before_any_product_popen(monkeypatch,tmp_path):
    from experiments.formal_campaign import h4_sampled_registration as registration
    from experiments.formal_campaign import h4_sampled_host_launch as launch
    def reject(_):raise ValueError('preflight64KiB')
    def forbidden(*args,**kwargs):raise AssertionError('product Popen before size rejection')
    monkeypatch.setattr(registration,'preflight_native_spec',reject)
    monkeypatch.setattr(launch.subprocess,'Popen',forbidden)
    with pytest.raises(ValueError,match='preflight64KiB'):
        launch.launch_phase({},'ecpa',tmp_path,0,900)

