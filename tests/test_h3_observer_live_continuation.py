"""Source-only CPU regression specifications; never original real H3 evidence.

These have not been imported, collected or executed in the current NPU window.
Fixtures exercise rejection/fences only and cannot create a source-issued scope.
"""
from copy import deepcopy
from types import SimpleNamespace
from pathlib import Path
import base64
import json
import pytest
from vllm_hust_ext.exposure_gate import GateError
from experiments.formal_campaign.h3_dynamic_authority import canonical,digest
from experiments.formal_campaign.h3_observer_live_route import verify_transport,routing_copy,SCHEMA,DOMAIN
from experiments.formal_campaign.h3_observer_live_http import LiveProxyHandler
from experiments.formal_campaign.h3_observer_live_intake import verify_live_terminal
from experiments.formal_campaign.h3_observer_live_cleanup import unix_owned


def fixture_transport():
    kernels=[{'pid':i,'start_ticks':i*3,'session':9,'boot_id':'cpu-fixture'} for i in (11,12,13)]
    semantic={'sha256':'sha256:semantic-fixture','generation':1,'nonce':'old-nonce',
        'members':[{'identity':k} for k in kernels]}
    successor={'collector':{'pid':14,'start_ticks':42,'session':14,'boot_id':'cpu-fixture'}}
    receipt={'path':'/cpu-fixture/receipt','sha256':'sha256:fixture'}
    prepared=[];committed=[]
    for kernel in kernels:
        common={'producer':kernel,'collector':successor['collector'],'contexts':{'semantic':'fixture-only'},
            'transition_nonce':'transition','receipt_sha256':receipt['sha256'],'old_client_request_ids':['old-rid']}
        prepared.append(dict(common,state='prepared',generation=0))
        committed.append(dict(common,state='committed',generation=1))
    commit={'transport_commit_complete':True,'error':None,'generation':1,'prepared':prepared,'committed':committed,
        'fault':{'triggered_ns':100},'observer_dead_ns':101,'committed_ns':102,
        'original_deadline_ns':30_000_000_100,'transition_nonce':'transition','old_client_request_ids':['old-rid']}
    value=dict(schema=SCHEMA,domain=DOMAIN,semantic_enrollment=semantic,successor_descriptor=successor,
        commit=commit,live_receipt=receipt,generation=2,nonce='c'*64,issued_ns=103)
    value['sha256']=digest(canonical(value))
    return value,semantic,dict(receipt=receipt,descriptor=successor,commit=commit,
        observed_ns=104,revoked={semantic['sha256']})


def resign(value):
    value['sha256']=digest(canonical({k:v for k,v in value.items() if k!='sha256'}))


def test_typed_transport_does_not_rewrite_semantic_host_enrollment():
    value,semantic,args=fixture_transport();before=deepcopy(semantic)
    verify_transport(value,semantic,**args)
    view=routing_copy(value)
    assert semantic==before and view['sha256']!=semantic['sha256']
    assert view['members']==semantic['members'] and view['transport_enrollment']==value


def test_old_membership_must_be_revoked_before_new_transport_enrollment():
    value,semantic,args=fixture_transport();args['revoked']=set()
    with pytest.raises(GateError,match='revocation'):
        verify_transport(value,semantic,**args)


@pytest.mark.parametrize('field',['live_receipt','successor_descriptor','generation','nonce'])
def test_self_resigned_transport_cannot_substitute_receipt_receiver_or_fence(field):
    value,semantic,args=fixture_transport()
    value=deepcopy(value)
    value[field]={'wrong':'fixture'} if field in ('live_receipt','successor_descriptor') else 1
    resign(value)
    with pytest.raises(GateError):verify_transport(value,semantic,**args)


def test_missing_actual_worker_commit_cannot_be_success_summary():
    value,semantic,args=fixture_transport();value['commit']['committed'].pop();resign(value)
    with pytest.raises(GateError,match='actual transport'):
        verify_transport(value,semantic,**args)


def test_wrong_same_pid_new_kernel_commit_is_rejected():
    value,semantic,args=fixture_transport()
    value['commit']['committed'][1]['producer']=dict(value['commit']['committed'][1]['producer'],start_ticks=999)
    resign(value)
    with pytest.raises(GateError,match='producer successor'):
        verify_transport(value,semantic,**args)


def test_commit_over_original30s_is_rejected_without_inventing_recovery():
    value,semantic,args=fixture_transport();args['observed_ns']=30_000_000_101
    with pytest.raises(GateError,match='original30s'):
        verify_transport(value,semantic,**args)


def test_old_inflight_request_cannot_release_after_actual_transport_changes():
    old={'sha256':'old','generation':1}
    current={'sha256':'new-transport','generation':2}
    checked=[]
    authority=SimpleNamespace(routing_enrollment=lambda:current,
        route=SimpleNamespace(generation=2),_recheck=lambda:checked.append(True))
    with pytest.raises(GateError,match='generation/membership'):
        LiveProxyHandler._same_epoch(authority,old)
    assert checked==[]


def test_same_host_and_generation_with_wrong_transport_sha_still_rejects():
    current={'sha256':'correct-transport','generation':2}
    authority=SimpleNamespace(routing_enrollment=lambda:current,
        route=SimpleNamespace(generation=2),_recheck=lambda:None)
    with pytest.raises(GateError):
        LiveProxyHandler._same_epoch(authority,{'sha256':'other-transport','generation':2})


def test_cleanup_keeps_unix_socket_under_exact_owned_scope():
    raw=b'Num RefCount Protocol Flags Type St Inode Path\n0: 00000002 00000000 00010000 0001 01 10 /owned/control/11/control.sock\n1: 00000002 00000000 00010000 0001 01 11 /external/control.sock\n'
    rows=unix_owned(base64.b64encode(raw).decode(),['/owned/control'])
    assert len(rows)==1 and '/owned/control/11/control.sock' in rows[0]


def test_cleanup_scope_prefix_does_not_claim_external_sibling():
    raw=b'Num RefCount Protocol Flags Type St Inode Path\n0: 2 0 10000 1 01 10 /owned/control-external/server.sock\n'
    assert unix_owned(base64.b64encode(raw).decode(),['/owned/control'])==[]


def test_terminal_true_summary_cannot_hide_missing_actual_predecessor():
    hosts=[{'pid':i} for i in range(3)];client={'pid':4}
    trace=[{'kind':'client.start','client':client,'detail':{'start_id':'fixture'},'monotonic_ns':2},
        {'kind':'client.stop','client':client,'monotonic_ns':10}]
    accounting={'observed_ns':11,'replacement_committed':True,'host_kernels_at_client_stop':hosts,
        'predecessor_alive_through_client_window':True}
    witness={'client_stop_ns':10,'observed_ns':12,'replacement_committed':True,
        'host_kernels':[None,hosts[1],hosts[2]],'host_preserved':True}
    result=verify_live_terminal(accounting,witness,original_host_kernels=hosts,
        client_trace=trace,expected_client=client,start_id='fixture',launch_ns=1,dead_ns=3)
    assert result['host_preserved'] is False and result['summary_consistent'] is False


def test_terminal_commit_summary_cannot_borrow_wrong_original_stop():
    hosts=[{'pid':i} for i in range(3)];client={'pid':4}
    trace=[{'kind':'client.start','client':client,'detail':{'start_id':'fixture'},'monotonic_ns':2},
        {'kind':'client.stop','client':client,'monotonic_ns':10}]
    accounting={'observed_ns':11,'replacement_committed':True,'host_kernels_at_client_stop':hosts,
        'predecessor_alive_through_client_window':True}
    witness={'client_stop_ns':9,'observed_ns':12,'replacement_committed':True,
        'host_kernels':hosts,'host_preserved':True}
    with pytest.raises(GateError,match='chained stop'):
        verify_live_terminal(accounting,witness,original_host_kernels=hosts,client_trace=trace,
            expected_client=client,start_id='fixture',launch_ns=1,dead_ns=3)


@pytest.mark.parametrize('mutate',['old-epoch','pid-reuse','wrong-archive'])
def test_receiver_report_cannot_substitute_predecessor_or_same_pid_other_epoch(mutate):
    from experiments.formal_campaign.h3_observer_live_delivery import verify_report_receiver
    descriptor={'collector':{'pid':11,'start_ticks':3,'boot_id':'CPU-only'},
        'archive_identity':{'directory_inode':1}}
    report={'descriptor':deepcopy(descriptor)}
    if mutate=='old-epoch': report['descriptor']['collector']['pid']=10
    elif mutate=='pid-reuse': report['descriptor']['collector']['start_ticks']=2
    else: report['descriptor']['archive_identity']['directory_inode']=2
    with pytest.raises(GateError,match='receiver|collector'):
        verify_report_receiver(report,'new',{'new':descriptor['collector']},
            {'new':{'successor_descriptor':descriptor}})


@pytest.mark.parametrize('case',['exact-reaped','wrong-peer','permission-error','unproven-death'])
def test_connected_peer_lookup_race_requires_exact_expected_peer_and_captured_pidfd(
        tmp_path,monkeypatch,case):
    import errno
    import os
    import socket
    import struct
    from vllm.plugins import native_observer_rebind as host
    native=host.native
    path=tmp_path/'real-unix-inode.sock'
    original=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    original.bind(str(path))
    info=path.stat();expected={'pid':123,'start_ticks':5,'boot_id':'CPU-fixture'}
    class Channel:
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def settimeout(self,*args):pass
        def connect(self,*args):pass
        def getsockopt(self,*args):
            return struct.pack('3i',124 if case=='wrong-peer' else 123,os.getuid(),os.getgid())
    def lookup(pid):
        if case=='permission-error':raise PermissionError(errno.EACCES,'denied',f'/proc/{pid}/stat')
        raise FileNotFoundError(errno.ENOENT,'reaped',f'/proc/{pid}/stat')
    monkeypatch.setattr(native.socket,'socket',lambda *a,**k:Channel())
    monkeypatch.setattr(native,'identity',lookup)
    monkeypatch.setattr(host,'collector_kernel_gone',lambda *a:case!='unproven-death')
    expected_error=native.CollectorKernelGone if case=='exact-reaped' else ValueError
    try:
        with pytest.raises(expected_error):
            native._submit_fact(path,{},expected_collector=expected,
                expected_socket_identity=(info.st_dev,info.st_ino),
                expected_collector_source_sha256='CPU-fixture',expected_archive_identity={})
    finally:
        original.close()


@pytest.mark.parametrize('case',['wrong-scope','forged-empty-unix','missing-successor-epoch'])
def test_continuation_cleanup_cannot_skip_scope_raw_listener_or_materialized_epoch(monkeypatch,case):
    from experiments.formal_campaign import h3_observer_live_cleanup as cleanup
    scopes=['/CPU-owned/control']
    raw=base64.b64encode(b'Num RefCount Protocol Flags Type St Inode Path\n').decode()
    witness={'live_cleanup_schema':'ecpa-h3-observer-live-cleanup/v2',
        'unix_scopes':scopes,'unix_raw_base64':raw,'owned_unix_sockets':[]}
    before=deepcopy(witness);after=deepcopy(witness)
    monkeypatch.setattr(cleanup,'scopes_for',lambda *a:scopes)
    def original_must_not_authorize(*a,**k):
        raise AssertionError('new continuation prerequisite must reject before original cleanup')
    monkeypatch.setattr(cleanup.original,'verify',original_must_not_authorize)
    extras=[]
    if case=='wrong-scope':after['unix_scopes']=['/other-start/control']
    elif case=='forged-empty-unix':
        after['unix_raw_base64']=base64.b64encode(
            b'Num RefCount Protocol Flags Type St Inode Path\n0: 2 0 10000 1 01 10 /CPU-owned/control/live.sock\n').decode()
    else:extras=[{'pid':14,'start_ticks':42,'session':14,'boot_id':'CPU-only'}]
    with pytest.raises(GateError):
        cleanup.verify(before,after,{},scope=None,recipe=None,extra_epochs=extras,owned_kernels=[])
