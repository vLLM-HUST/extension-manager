"""Manager issuer/launcher contract tests using actual Manager modules."""
import json
import os
import threading
from types import SimpleNamespace

import pytest

from vllm_hust_ext.exposure_gate import GateError
from experiments.formal_campaign import h3_observer_live_registration as registration
from experiments.formal_campaign.h3_observer_live_launcher import LiveGrants


def test_caller_trust_roots_or_ready_flag_cannot_enter_receipt_issuer(tmp_path):
    path=tmp_path/'caller.json'
    path.write_text(json.dumps({'schema':registration.INTENT,'domain':registration.DOMAIN,
        'base_campaign':{},'base_receipt':{},'receipt_path':str(tmp_path/'receipt.json'),
        'starts':[],'ready':True,'trusted_roots':['caller']}))
    with pytest.raises(GateError,match='exact independent live-continuation intent'):
        registration.issue(path,tmp_path/'receipt.json')


def test_unissued_scope_cannot_publish_launcher_grants():
    with pytest.raises(GateError,match='actual original authority'):
        LiveGrants(SimpleNamespace(),SimpleNamespace(ready=True))


def test_old_receipt_cannot_construct_new_issued_capability():
    with pytest.raises(GateError,match='independently issued'):
        registration.ValidatedLiveStart({'schema':'old-receipt','ready':True},{})


def test_forged_ready_file_with_wrong_actual_socket_kernel_is_rejected(tmp_path):
    import socket
    import time
    from experiments.exposure_gate import native_semantic_collector as native
    tmp_path.chmod(0o700)
    socket_path=tmp_path/'fake-ready.sock'
    server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    server.bind(str(socket_path));socket_path.chmod(0o600);server.listen(1);server.settimeout(2)
    def accept():
        with server.accept()[0] as peer:
            peer.recv(1)  # Real verifier closes immediately after credential mismatch.
    thread=threading.Thread(target=accept,daemon=True);thread.start()
    actual=native.identity(os.getpid());wrong={**actual,'pid':actual['pid']+1_000_000}
    metadata=socket_path.stat();ready_path=tmp_path/'ready.json'
    scope=SimpleNamespace(receipt_ref=lambda:{'path':'CPU-only','sha256':'fixture-live-receipt'})
    member={'producer':wrong,'socket_path':str(socket_path),'ready_path':str(ready_path)}
    ready=dict(schema='ecpa-native-observer-control-ready/v2',producer=wrong,
        socket_identity=[metadata.st_dev,metadata.st_ino],socket_path=str(socket_path),
        policy_sha256='fixture-policy',receipt_sha256='fixture-live-receipt')
    ready_path.write_bytes(native.canonical(ready));ready_path.chmod(0o600)
    launcher=LiveGrants.__new__(LiveGrants)
    launcher.recheck=lambda:None;launcher.scope=scope;launcher.endpoints=[]
    launcher.group=[member,{**member,'producer':{**wrong,'pid':wrong['pid']+1}},
        {**member,'producer':{**wrong,'pid':wrong['pid']+2}}]
    launcher.policies={str(wrong['pid']):({'start_id':'observer-loss-r1-ecpa',
        'receipt_sha256':'fixture-live-receipt','controller':actual,'control_nonce':'a'*64},
        {'sha256':'fixture-policy'})}
    try:
        with pytest.raises(GateError,match='not actual source-owned original producer'):
            launcher.wait_actual_endpoints(time.monotonic_ns()+1_000_000_000)
    finally:
        thread.join(timeout=1);server.close()

