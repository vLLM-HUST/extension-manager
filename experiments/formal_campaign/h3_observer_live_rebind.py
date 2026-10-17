"""Actual SO_PEERCRED-bound three-producer live transport coordinator.

This component never opens a public route or asserts completion/recovery. The
source-owned authority must keep the original route closed throughout prepare
and commit, preserve all original evidence, and subsequently attach/replay the
actual successor native verifier. Missing authority/registration support fails
closed; a supplied JSON 'ready' flag is never a substitute for live transport.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import stat
import struct
import time
from pathlib import Path

from experiments.exposure_gate import native_semantic_collector as native

COMMAND='ecpa-native-observer-rebind-command/v1'
REPLY='ecpa-native-observer-rebind-reply/v1'
DOMAIN='original-H3-observer-loss-live-transport-only'


def require(value,reason):
    if not value:
        raise ValueError(reason)


def kernel_alive(kernel):
    try:
        require(set(kernel) in ({'pid','start_ticks','session','boot_id'},
            {'pid','start_ticks','session','boot_id','start_identity'}), 'exact kernel identity fields required')
        observed=native.identity(kernel['pid'])
        same=all(observed[key]==kernel[key] for key in ('pid','start_ticks','boot_id'))
        if same:
            require(all(observed[key]==value for key,value in kernel.items()),
                'live process kernel metadata changed')
        return same
    except FileNotFoundError as error:
        require(error.filename==f"/proc/{kernel['pid']}/stat",'exact process liveness unavailable')
        return False
    except ProcessLookupError:
        require(not Path(f"/proc/{kernel['pid']}").exists(),'exact process liveness unknown')
        return False


def frame(connection,deadline_ns):
    raw=b''
    while not raw.endswith(b'\n'):
        remaining=(deadline_ns-time.monotonic_ns())/1e9
        require(remaining>0,'original observer30s recovery deadline expired')
        connection.settimeout(remaining)
        piece=connection.recv(native.MAX_FRAME+1)
        require(piece and len(raw)+len(piece)<=native.MAX_FRAME,'bounded rebind reply required')
        raw+=piece
    value=json.loads(raw)
    require(raw==native.canonical(value)+b'\n','noncanonical producer rebind reply')
    return value


def call(endpoint,command,deadline_ns):
    path=Path(endpoint['socket_path'])
    require(path.is_absolute() and path.resolve()==path,'producer endpoint is noncanonical')
    info,parent=path.lstat(),path.parent.lstat()
    require(stat.S_ISSOCK(info.st_mode) and stat.S_IMODE(info.st_mode)==0o600
        and info.st_uid==os.getuid() and info.st_gid==os.getgid()
        and (info.st_dev,info.st_ino)==tuple(endpoint['socket_identity'])
        and stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode)==0o700
        and parent.st_uid==os.getuid(),'producer socket owner/mode/inode changed')
    remaining=(deadline_ns-time.monotonic_ns())/1e9
    require(remaining>0,'original30s deadline expired before control connect')
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(remaining)
        connection.connect(str(path))
        pid,uid,gid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        require(uid==os.getuid() and gid==os.getgid()
            and native.identity(pid)==endpoint['producer'],'actual rebind peer is not original Host producer epoch')
        connection.sendall(native.canonical(command)+b'\n')
        response=frame(connection,deadline_ns)
    require(response.get('schema')==REPLY and response.get('domain')==DOMAIN
        and response.get('producer')==endpoint['producer']
        and response.get('start_id')==command['start_id']
        and response.get('receipt_sha256')==command['receipt_sha256']
        and response.get('transition_nonce')==command['transition_nonce']
        and response.get('native_completion_proved') is False,'producer rejected or substituted rebind transition')
    return response


class Coordinator:
    def __init__(self,authority):
        """Only the actual source-owned authority can own this operation.

        Independently issued v2 receipt and source-owned immutable grants must
        precede Popen/socket traffic; never infer a grant from caller readiness.
        Public route admission is a separate typed source-owned transition.
        """
        from experiments.formal_campaign.h3_observer_authority import NativeAuthority
        from experiments.formal_campaign.h3_dynamic_authority import check_ref
        require(type(authority) is NativeAuthority, 'exact source-owned observer authority required')
        from experiments.formal_campaign.h3_observer_live_launcher import LiveGrants
        grants=getattr(authority,'live_grants',None)
        require(type(grants) is LiveGrants and grants.authority is authority,
            'source-issued v2 grants and actual endpoint observation absent')
        grants.recheck()
        require(len(grants.endpoints)==3,'independent live producer endpoint challenge incomplete')
        policy=dict(start_id=authority.start['start_id'],
            receipt_sha256=grants.scope.receipt_ref()['sha256'],controller=native.identity(os.getpid()),
            successor=grants.value['declaration']['successor'],max_recovery_ns=30_000_000_000,
            workload={'requests':60,'concurrency':8,'interval_s':.2,'timeout_s':10,
                'dispatch_slack_s':.5,'retries':0,'max_num_seqs':1})
        endpoints=grants.endpoints
        require(len(endpoints)==3 and len({native.canonical(x['producer']) for x in endpoints})==3,
            'exact original API+TP2 producer set required')
        with authority.lock:
            require(authority.route.generation is None and authority.observer_lost
                and authority.current_observer is not None, 'actual observer loss and closed route required')
            authority._lease()
            authority._observe_members(authority.enrollment['members'])
            expected=[native.canonical(native.identity(m['event']['process']['pid']))
                for m in authority.enrollment['members']]
            require(expected==[native.canonical(e['producer']) for e in endpoints],
                'producer endpoints are not complete original actual Host membership')
        self.authority=authority
        self.policy,self.endpoints=policy,endpoints
        self.source_recheck=grants.recheck
        self.source_recheck()
        require(policy['controller']==native.identity(os.getpid()),
            'coordinator must run inside actual preregistered authority process')
        require(policy['max_recovery_ns']==30_000_000_000
            and policy['workload']=={'requests':60,'concurrency':8,'interval_s':.2,
                'timeout_s':10,'dispatch_slack_s':.5,'retries':0,'max_num_seqs':1},
            'original frozen observer workload/objective changed')
        self.used=set()
        self.successor=None
        self._committed=None
        self._fault_raw=None
        self._contexts=None

    def prepare_successor(self):
        """Launch actual collector with new immutable contexts; keep healthy Host."""
        from experiments.formal_campaign.h3_native_bootstrap import start_native_epoch
        authority=self.authority
        self.source_recheck()
        with authority.lock:
            require(authority.route.generation is None and authority.observer_lost,
                'close route before successor preparation')
            old=authority._epoch(authority.enrollment)
            old['guard'].validate_current(old['native_enrollment'],old['host_journal'])
            old_spec=json.loads(old['verifier'].spec_path.read_bytes())
            old_policy=json.loads(old['verifier'].policy_path.read_bytes())
            require(self.successor is None,'one replacement collector per registered attempt')
        from experiments.formal_campaign.h3_observer_loss import validate_raw
        from experiments.formal_campaign.h3_dynamic_authority import read_dynamic_journal
        from experiments.formal_campaign.h3_observer_authority import JOURNAL
        raw_path=authority.output/'observer-fault-raw.json'
        raw_bytes,_=native.read_private(raw_path,0o600)
        actual_fault=json.loads(raw_bytes)
        original=authority.current_observer[1]
        hosts=[{k:e['producer'][k] for k in ('pid','start_ticks','session','boot_id')}
            for e in self.endpoints]
        require(original['observer']==actual_fault['fault']['target']
            and authority.current_observer[0].poll() is not None
            and not kernel_alive(original['observer']), 'original owned collector kernel is not actually dead')
        assessment=validate_raw(actual_fault,original,
            authority_events=read_dynamic_journal(authority.start['authority']['journal'],domain=JOURNAL),
            independent_host_kernels=actual_fault['host_kernels_immediately_after_observer_death'],
            original_host_kernels=hosts)
        require(assessment['host_preserved_after_fault'] is True,
            'original healthy Host/predecessor was lost at observer death')
        require(time.monotonic_ns() < actual_fault['fault']['triggered_ns']+30_000_000_000,
            'original30s bound expired before successor launch')
        self._fault_raw=(actual_fault,raw_bytes,raw_path)
        declaration=self.policy['successor']
        output=Path(declaration['output'])
        require(all(Path(declaration[key]).parent==output for key in
            ('native_context_path','tensor_context_path')), 'successor contexts must be new declared epoch leaves')
        from experiments.formal_campaign.h3_observer_live_registration import check_uds_path
        check_uds_path(output/'native.sock')  # Actual declared successor, before Popen.
        process,descriptor=start_native_epoch(output=output,senders=old_spec['senders'],
            phases=old_spec['phases'],native_plan_id=old_spec['native_plan_id'],
            native_launch_id=old_spec['native_launch_id'],kv_requirements=old_spec['kv_requirements'],
            tensor_requirements=old_policy['requirements'],
            native_context_path=declaration['native_context_path'],
            tensor_context_path=declaration['tensor_context_path'],
            source_files=old_spec['senders'][1]['source_files'],_observer_successor=True)
        # Include even a subsequently rejected successor in original owned cleanup.
        authority.collectors.append(process)
        self.successor=(process,descriptor,output,old)
        def reference(path):
            return {'path':str(path),'sha256':native.sha(Path(path).read_bytes())}
        result={}
        for endpoint in self.endpoints:
            role=next(m['event']['process']['role'] for m in authority.enrollment['members']
                if m['event']['process']['pid']==endpoint['producer']['pid'])
            channels={'semantic':reference(declaration['native_context_path'])}
            if role=='worker':
                channels['tensor']=reference(declaration['tensor_context_path'])
            result[str(endpoint['producer']['pid'])]=channels
        self._contexts=json.loads(native.canonical(result))
        return json.loads(native.canonical(result))

    def attach_committed_successor(self):
        """Swap verifier only for this object's actual committed RPC transcript.

        No caller JSON, replacement Host identity, new semantic enrollment or
        widened guard is accepted. Original route remains closed. Original
        enrollment is retained and each pre-fault verifier retained for replay.
        """
        from experiments.formal_campaign.h3_native_verifier import NativeEpochVerifier
        require(self._committed is not None and self.successor is not None,
            'no actual complete transport commit owned by this authority')
        authority=self.authority
        process,descriptor,output,old=self.successor
        self.source_recheck()
        old['guard'].validate_current(old['native_enrollment'],old['host_journal'])
        verifier=NativeEpochVerifier(native_spec=output/'native-spec.json',
            tensor_policy=output/'tensor-policy.json',drain_policy=output/'drain-policy.json',
            descriptor=descriptor,socket_path=output/'native.sock',journal_path=output/'native.jsonl',
            snapshots=output/'consumed')
        verifier._current()  # Independently authenticate actual collector/inputs.
        with authority.lock:
            require(authority.route.generation is None and authority.observer_lost
                and authority._epoch(authority.enrollment) is old
                and all(kernel_alive(e['producer']) for e in self.endpoints),
                'original authority/Host/predecessor epoch changed before verifier commit')
            require(time.monotonic_ns()<=self._committed['original_deadline_ns'],
                'verifier commit exceeded original30s bound')
            history=getattr(authority,'observer_transport_history',[])
            history.append((old,self._committed))
            authority.observer_transport_history=history
            authority.native_epochs[authority.enrollment['sha256']]={**old,'verifier':verifier}
            previous=authority.current_observer[1]
            from experiments.formal_campaign.h3_observer_loss import binding
            from experiments.formal_campaign.h3_worker_relaunch import identity
            from experiments.formal_campaign import h3_native_collector
            bound=binding(process,descriptor,authority=identity(os.getpid()),
                start_id=authority.start['start_id'],enrollment=authority.enrollment['sha256'],
                phase_index=0,collector_source=Path(h3_native_collector.__file__).resolve(),
                collector_argv=process.args)
            bound={**bound,'transport_generation':self._committed['generation'],
                'transition_nonce':self._committed['transition_nonce']}
            authority.current_observer=(process,bound)
            authority.observer_lost=False
            authority._record('observer.live-transport.committed',authority.route,
                actual_transport=self._committed,original_binding=previous,successor_descriptor=descriptor,
                enrollment_sha256=authority.enrollment['sha256'])
            self.attached_commit=json.loads(native.canonical(self._committed))
            self.attached_old=old
            self.attached_verifier=verifier
            self._committed=None
        return {'transport':'actual-Host-preserved-verifier-attached-route-closed',
            'formal_result':False,'recovery_ns':None}

    def rebind(self):
        """One real replacement; partial commits remain failures with route closed."""
        self.source_recheck()
        p=self.policy
        require(self._fault_raw is not None,'source-owned original pidfd fault record unavailable')
        require(self._contexts is not None,'actual owned immutable successor contexts unavailable')
        contexts=json.loads(native.canonical(self._contexts))
        actual_fault,raw_bytes,raw_path=self._fault_raw
        require(native.read_private(raw_path,0o600)[0]==raw_bytes,'original fault bytes changed')
        fault=actual_fault['fault']
        observer_dead_ns=actual_fault['pidfd_observed_dead_ns']
        old_collector=self.authority.current_observer[1]['observer']
        expected_generation=0
        require(self.successor is not None,'actual owned successor must be prepared first')
        require(old_collector==self.authority.current_observer[1]['observer'],
            'fault target differs from authority-owned original observer')
        require(fault['signal']=='SIGKILL' and fault['target']==old_collector
            and 0<fault['triggered_ns']<=observer_dead_ns<=time.monotonic_ns()
            and not kernel_alive(old_collector),'actual original collector death required')
        require(set(contexts)=={str(e['producer']['pid']) for e in self.endpoints},'replacement context coverage differs from actual Host3')
        deadline=fault['triggered_ns']+p['max_recovery_ns']
        require(time.monotonic_ns()<deadline,'original30s recovery deadline expired')
        from experiments.formal_campaign.h3_dynamic_authority import read_dynamic_journal
        from experiments.formal_campaign.h3_observer_authority import JOURNAL
        events=read_dynamic_journal(self.authority.start['authority']['journal'],domain=JOURNAL)
        losses=[event for event in events if event['kind']=='observer.loss.observed']
        require(len(losses)==1 and all(event['monotonic_ns']<=losses[0]['monotonic_ns']
            for event in events if event['kind']=='request.private-forward'),
            'old native admissions not frozen behind exact original observer-close fence')
        old_client_ids=sorted({event['detail']['request_id'] for event in events
            if event['kind']=='request.private-forward'})
        nonce=secrets.token_hex(32)
        require(nonce not in self.used,'recovery nonce reused')
        self.used.add(nonce)
        result=dict(schema='ecpa-h3-observer-live-rebind-attempt/v1',start_id=p['start_id'],
            fault=fault,observer_dead_ns=observer_dead_ns,transition_nonce=nonce,
            original_deadline_ns=deadline,old_client_request_ids=old_client_ids,
            original_authority_journal_sha256=native.sha(Path(self.authority.start['authority']['journal']).read_bytes()),prepared=[],committed=[],error=None,
            transport_commit_complete=False,formal_result=False,recovery_ns=None)
        try:
            commands=[]
            successor=None
            for endpoint in self.endpoints:
                require(kernel_alive(endpoint['producer']),'original Host producer lost before successor commit')
                command=dict(schema=COMMAND,domain=DOMAIN,operation='prepare',start_id=p['start_id'],
                    receipt_sha256=p['receipt_sha256'],control_nonce=endpoint['control_nonce'],
                    producer=endpoint['producer'],expected_generation=expected_generation,
                    transition_nonce=nonce,fault_ns=fault['triggered_ns'],deadline_ns=deadline,
                    contexts=contexts[str(endpoint['producer']['pid'])],
                    old_client_request_ids=old_client_ids)
                response=call(endpoint,command,deadline)
                require(response['state']=='prepared' and response['generation']==expected_generation
                    and response['contexts']==command['contexts']
                    and response['old_client_request_ids']==old_client_ids
                    and response['collector']==self.successor[1]['collector']
                    and (successor is None or successor==response['collector']), 'producer prepared a different observer/generation/context')
                require(response['collector']!=old_collector and kernel_alive(response['collector']),
                    'successor collector not actual live distinct epoch')
                successor=response['collector']
                result['prepared'].append(response)
                commands.append((endpoint,command,response))
            self.source_recheck()
            for endpoint,prepared,reply in commands:
                require(all(kernel_alive(e['producer']) for e in self.endpoints),
                    'original Host/predecessor lost before commit bound')
                command={k:v for k,v in prepared.items() if k!='contexts'}
                command.update(operation='commit',prepared_sha256=native.sha(native.canonical(reply)))
                response=call(endpoint,command,deadline)
                require(response['state']=='committed' and response['generation']==expected_generation+1
                    and response['collector']==successor and response['contexts']==prepared['contexts']
                    and response['old_client_request_ids']==old_client_ids,
                    'producer did not commit exact paired successor context')
                result['committed'].append(response)
            self.source_recheck()
            require(all(kernel_alive(e['producer']) for e in self.endpoints) and kernel_alive(successor)
                and time.monotonic_ns()<=deadline,'actual original Host/successor or original30s bound lost')
            result['transport_commit_complete']=True
            result['committed_ns']=time.monotonic_ns()
            result['generation']=expected_generation+1
            self._committed=json.loads(native.canonical(result))
            # NativeEpochVerifier attachment plus original successful response
            # replay is still required. No recovery time is invented here.
        except Exception as error:
            result['error']=type(error).__name__+': '+str(error)
        result['recorded_ns']=time.monotonic_ns()
        return result
