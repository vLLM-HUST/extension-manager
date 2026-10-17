"""Continuation cleanup adds frozen Unix scopes and materialized actual epochs.

All original NPU/TCP/external-service and exact-seven-role checks are retained.
The same run's successor/operator kernels must be in independently captured owned
cleanup, including failed repairs; Unix listeners are recomputed from raw bytes.
"""
from __future__ import annotations
import base64
from pathlib import Path
from experiments.formal_campaign import h3_observer_cleanup as original
from experiments.formal_campaign.h3_dynamic_authority import require


def context_for(spec_path,receipt_path,spec,start,scope):
    return {**original.context_for(spec_path,receipt_path,spec,start),
        'live_receipt':scope.receipt_ref(),'live_intent':scope.value()['intent']}


def scopes_for(scope,recipe):
    value=scope.value();phase=recipe['arms'][value['start']['arm']]['phases'][0]
    return sorted([value['declaration']['grant_directory'],value['declaration']['successor']['output'],
        phase['native_bootstrap']['output']])


def unix_owned(raw,scopes):
    rows=[]
    for line in base64.b64decode(raw,validate=True).decode().splitlines()[1:]:
        parts=line.split(maxsplit=7)
        if len(parts)==8 and any(Path(parts[7]).is_relative_to(Path(root)) for root in scopes):
            rows.append(line)
    return rows


def observe(policy,ports,*,unix_scopes,**fields):
    value=original.observe(policy,ports,**fields)
    raw=base64.b64encode(Path('/proc/net/unix').read_bytes()).decode()
    return {**value,'live_cleanup_schema':'ecpa-h3-observer-live-cleanup/v2',
        'unix_scopes':unix_scopes,'unix_raw_base64':raw,'owned_unix_sockets':unix_owned(raw,unix_scopes)}


def verify(before,after,policy,*,scope,recipe,extra_epochs,**fields):
    scopes=scopes_for(scope,recipe)
    require(before['live_cleanup_schema']==after['live_cleanup_schema']=='ecpa-h3-observer-live-cleanup/v2'
        and before['unix_scopes']==after['unix_scopes']==scopes,
        'cleanup Unix resource scope belongs to another original start/receipt')
    for witness in (before,after):
        require(witness['owned_unix_sockets']==unix_owned(witness['unix_raw_base64'],scopes),
            'cleanup Unix summary differs from independently captured raw table')
    require(all(kernel in fields['owned_kernels'] for kernel in extra_epochs),
        'materialized successor/operator epoch absent from independent cleanup ownership')
    result=original.verify(before,after,policy,**fields)
    result['ports_reclaimed']=result['ports_reclaimed'] and not after['owned_unix_sockets']
    return result
