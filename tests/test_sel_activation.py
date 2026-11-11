# TRACEWEAVER: file-role=durable-local-promotion-verification; req=REQ-SEL-003; trace=TRACE-SEL-003; ver=VER-SEL-003
# TRACEWEAVER: verifies=VER-SEL-003; req=REQ-SEL-003; trace=TRACE-SEL-003
# TRACEWEAVER: file-role=maintenance-activation-verification; req=REQ-SEL-004; trace=TRACE-SEL-004; ver=VER-SEL-004
# TRACEWEAVER: verifies=VER-SEL-004; req=REQ-SEL-004; trace=TRACE-SEL-004
# TRACEWEAVER: file-role=maintenance-activation-verification; req=REQ-SEL-002,REQ-SEL-003,REQ-SEL-005; trace=TRACE-SEL-002,TRACE-SEL-003,TRACE-SEL-005; ver=VER-SEL-002,VER-SEL-003,VER-SEL-005
"""Precode RED: real Flask/SQLite workflow, synthetic external tool only.

The snapshot/archive inputs come from the existing adapter and durable rows.
No fixture here constitutes physical qualification or commissioning evidence.
"""
import hashlib
import json
import os
from pathlib import Path

import pytest

from tests.test_sel_management import BMC, intent, qualified_site, sel_site


@pytest.mark.parametrize('failure', ['fsync', 'symlink'])
def test_unavailable_durable_archive_file_prevents_any_clear(qualified_site, monkeypatch, tmp_path, failure):
    (client, _app, _db, _models, runtime, commands), state, _registry = qualified_site
    if failure == 'fsync':
        monkeypatch.setattr(os, 'fsync', lambda _fd: (_ for _ in ()).throw(OSError('disk failure')))
    else:
        (Path(os.environ['DATA_DIR']) / 'sel-archives').symlink_to(tmp_path, target_is_directory=True)
    headers, data = intent(client)
    response = client.post(f'/api/server/{BMC}/clear_sel', json=data, headers=headers)
    assert response.status_code == 202, response.get_json()
    assert response.get_json()['state'] == 'failed'
    assert not state['cleared']
    assert not any('0x47' in argv for argv, _ in commands)


@pytest.fixture()
def manual_site(qualified_site, monkeypatch):
    """Synthetic typed admission exercises real loader/API/SQLite, never hardware."""
    (client, app, db, _models, runtime, commands), state, registry = qualified_site
    value = json.loads(registry.read_bytes())
    record = value['records'][0]
    record.pop('clock_semantics')
    record.pop('ntp_probe')
    record.pop('supporting_evidence')
    record['evidence_artifacts'] = []
    commission_id = '1ea50bc7-be62-41b2-a47d-051bddbce088'
    with app.app_context():
        target_id = runtime.SELTarget.query.one().id
    base = {'schema': 'sel-typed-evidence/2', 'record_id': record['record_id'],
            'fingerprint': record['fingerprint'], 'runtime_identity': record['runtime_identity'],
            'action': 'clear', 'provenance': 'synthetic unit fixture; never physical evidence'}

    def artifact(kind, **extra):
        body = dict(base, kind=kind, **extra)
        payload = json.dumps(body, sort_keys=True).encode()
        path = registry.parent / (kind + '.json')
        path.write_bytes(payload)
        digest = hashlib.sha256(payload).hexdigest()
        record['evidence_artifacts'].append({'path': path.name, 'kind': kind, 'sha256': digest})
        return digest

    owner = artifact('owner_scope', target_id=target_id, commission_id=commission_id,
        max_attempts=1, approved_at=record['approved_at'], expires_at=record['expires_at'],
        owner_instruction='synthetic bounded owner receipt for unit test only')
    vendor = artifact('vendor_semantics', evidence={'source_sha256': 'a' * 64,
        'section': 'synthetic exact model/firmware conditional erase semantics',
        'applicability': record['fingerprint']})
    native = artifact('native_guard_observation', observed_at=record['approved_at'],
        probe_id='7c2f7e03-93c0-44dc-a30b-b2a624991e55',
        raw_receipts=[{'command': [10, 66], 'response': '3412'}],
        evidence={'competing_reservation': 'synthetic_observed', 'insertion': 'unobserved_vendor_bound'})
    source = artifact('source_guard_verification', evidence={
        'environment': 'local synthetic subprocess fixture',
        'tests': ['same_reservation', 'dual_archive', 'no_retry'], 'log_sha256': 'b' * 64})
    record['actions'] = {'clear': {'phase': 'manual_commissioning', 'commission_id': commission_id,
        'owner_scope_sha256': owner, 'claims': {
            'reservation_required_for_erase': [vendor, native],
            'same_reservation_snapshot_and_clear': [vendor, native, source],
            'insertion_invalidates_or_equivalent_guard': [vendor, native],
            'competing_reservation_invalidates': [vendor, native],
            'complete_dual_archive_before_dispatch': [source],
            'bounded_completion_and_unknown_reconciliation': [source],
            'saved_history_preserved': [source]}}}
    value['schema'] = 'sel-device-qualification/2'
    registry.write_text(json.dumps(value))
    monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
    return qualified_site, commission_id


def test_typed_manual_commissioning_admits_one_manual_action_but_never_auto(manual_site):
    ((client, app, db, _models, runtime, commands), state, _registry), commission_id = manual_site
    headers, data = intent(client)
    denied = client.post(f'/api/server/{BMC}/sel/policy', json=dict(data, automatic_clear=True), headers=headers)
    assert denied.status_code == 409
    headers, data = intent(client)
    first = client.post(f'/api/server/{BMC}/clear_sel', json=data, headers=headers)
    assert first.status_code == 200, first.get_json()
    assert first.get_json()['outcome'] == 'clear_verified'
    with app.app_context():
        op = runtime.SELOperation.query.one()
        # Remove cooldown only to show durable one-use survives ordinary eligibility.
        runtime.SELTarget.query.one().cooldown_until = None
        db.session.commit()
    state['cleared'] = False
    commands.clear()
    headers, data = intent(client)
    second = client.post(f'/api/server/{BMC}/clear_sel', json=data, headers=headers)
    assert second.status_code == 409, second.get_json()
    assert not state['cleared']
    assert not any('0x47' in argv for argv, _ in commands)
    with app.app_context():
        op = runtime.SELOperation.query.one()
        assert op.commission_id == commission_id
        assert op.automatic is False
        assert runtime.SELAudit.query.filter_by(action='commission_consumed').count() == 1


@pytest.mark.parametrize('action,command,path', [
    ('clear', 0x47, f'/api/server/{BMC}/clear_sel'),
    ('clock', 0x49, f'/api/server/{BMC}/sel/clock'),
])
def test_raw_snapshot_has_two_matching_durable_representations_before_write(
        qualified_site, monkeypatch, action, command, path):
    (client, app, _db, _models, runtime, _commands), _state, _registry = qualified_site
    original = runtime.subprocess.run
    observations = []

    def observe_dispatch(argv, **kwargs):
        if 'raw' in argv:
            values = [int(value, 16) for value in argv[argv.index('raw') + 1:]]
            if values[:2] == [0x0a, command]:
                # Observe at the actual write boundary, before simulated effect.
                with app.app_context():
                    archives = runtime.SELArchive.query.all()
                    payloads = [row.payload.encode() for row in archives]
                    files = list((Path(os.environ['DATA_DIR']) / 'sel-archives').glob('*.json'))
                    observations.append({
                        'database_payloads': payloads,
                        'files': [p.read_bytes() for p in files],
                        'digests_valid': all(row.sha256 == hashlib.sha256(row.payload.encode()).hexdigest()
                                             for row in archives),
                    })
        return original(argv, **kwargs)

    monkeypatch.setattr(runtime.subprocess, 'run', observe_dispatch)
    headers, data = intent(client)
    response = client.post(path, json=data, headers=headers)
    assert response.status_code == 200, response.get_json()
    assert response.get_json()['state'] == 'complete'
    assert observations, f'{action} must reach its guarded write in this positive fixture'
    for observed in observations:
        assert len(observed['database_payloads']) == 1, 'raw snapshot missing before hardware write'
        assert observed['digests_valid']
        assert observed['files'] == observed['database_payloads'], 'independent durable file copy missing/mismatched before hardware write'


def test_commission_claim_race_consumes_once_even_if_attempt_fails(manual_site, monkeypatch):
    from threading import Barrier, Thread
    from ipmi_monitor.sel_management import SELUnavailable
    ((_client, app, db, _models, runtime, commands), _state, registry), commission_id = manual_site
    gate, outcomes = Barrier(2), []
    def worker():
        with app.app_context():
            target = runtime.sel_manager.target(BMC)
            gate.wait(timeout=5)
            try:
                op = runtime.sel_manager.claim(target, 'clear', 'test-admin')
                outcomes.append(('claimed', op.id))
            except SELUnavailable as exc:
                db.session.rollback()
                outcomes.append(('held', exc.code))
    workers = [Thread(target=worker) for _ in range(2)]
    for worker in workers: worker.start()
    for worker in workers: worker.join(timeout=10)
    assert all(not worker.is_alive() for worker in workers)
    assert sorted(x[0] for x in outcomes) == ['claimed', 'held'], outcomes
    with app.app_context():
        op = runtime.SELOperation.query.one()
        target = runtime.SELTarget.query.one()
        runtime.sel_manager.finish(target, op, 'failed', 'test_backup_failure')
        target.cooldown_until = None
        db.session.commit()
        original_binding = op.qualification_binding
        db.session.remove()  # Fresh session/restart must not refund the UUID.
        # A different valid registry pin must not refund the same stable attempt.
        registry.write_text(registry.read_text() + '\n')
        monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
        target = runtime.sel_manager.target(BMC)
        from ipmi_monitor.sel_management import qualification_selection
        assert qualification_selection(json.loads(target.fingerprint), 'clear')[1] != original_binding
        with pytest.raises(SELUnavailable, match='commission_already_consumed'):
            runtime.sel_manager.claim(target, 'clear', 'test-admin')
        db.session.rollback()
        assert runtime.SELOperation.query.count() == 1
        assert runtime.SELOperation.query.one().commission_id == commission_id
        assert runtime.SELAudit.query.filter_by(action='commission_consumed').count() == 1


def test_source_only_promotion_cannot_admit_automatic_qualification(manual_site, monkeypatch):
    from ipmi_monitor.sel_management import qualification_records
    (_site, _state, registry), commission_id = manual_site
    value = json.loads(registry.read_bytes())
    record = value['records'][0]
    admission = record['actions']['clear']
    admission['phase'] = 'automatic_qualified'
    source = admission['claims']['saved_history_preserved'][0]
    admission['parent_commission'] = {'envelope_sha256': 'a' * 64, 'pointer_sha256': 'b' * 64,
        'commission_id': commission_id, 'operation_id': '05b23fa6-182a-4b2b-a099-993407501dc6', 'result_sha256': source}
    for name in ('actual_clear_completion_readback', 'actual_final_dual_archive_verified',
                 'saved_history_preserved_after_action', 'subsequent_collection_verified'):
        admission['claims'][name] = [source]
    registry.write_text(json.dumps(value))
    monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
    assert qualification_records() == []


def test_replace_is_explicit_cas_operation_and_environment_override_still_refuses(qualified_site, monkeypatch, capsys):
    import io
    from ipmi_monitor import sel_qualifications as q
    monkeypatch.setattr(q.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(q.sys, 'stdin', io.TextIOWrapper(io.BytesIO(b'{}')))
    assert q.main(['replace', '--expected-sha256', 'a' * 64,
                   '--expected-active-pointer-sha256', 'b' * 64]) == 1
    assert json.loads(capsys.readouterr().out)['reason'] == 'environment_mode_selected'


def test_well_formed_result_json_without_local_operation_never_promotes(manual_site, monkeypatch):
    from ipmi_monitor.sel_management import qualification_records
    (_site, _state, registry), commission_id = manual_site
    value = json.loads(registry.read_bytes())
    record = value['records'][0]
    admission = record['actions']['clear']
    owner_artifact = next(a for a in record['evidence_artifacts'] if a['kind'] == 'owner_scope')
    body = json.loads((registry.parent / owner_artifact['path']).read_bytes())
    target_id = body.pop('target_id')
    for key in ('commission_id', 'max_attempts', 'approved_at', 'expires_at', 'owner_instruction'):
        body.pop(key)
    operation_id = '05b23fa6-182a-4b2b-a099-993407501dc6'
    body.update(kind='commissioning_result', target_id=target_id, commission_id=commission_id,
        operation_id=operation_id, evidence={'original_qualification_binding': 'c' * 64,
        'archive_id': '8577f92a-c54f-42f1-bd1d-2666fd0535d9', 'archive_sha256': 'd' * 64,
        'dispatch_audit_id': 1, 'completion_audit_id': 2, 'collection_audit_id': 3,
        'collection_receipt_digest': 'e' * 64})
    payload = json.dumps(body).encode()
    result_sha = hashlib.sha256(payload).hexdigest()
    (registry.parent / 'result.json').write_bytes(payload)
    record['evidence_artifacts'].append({'path': 'result.json', 'kind': 'commissioning_result', 'sha256': result_sha})
    admission.update(phase='automatic_qualified', parent_commission={'envelope_sha256': 'a' * 64,
        'pointer_sha256': 'b' * 64, 'commission_id': commission_id, 'operation_id': operation_id,
        'result_sha256': result_sha})
    for name in ('actual_clear_completion_readback', 'actual_final_dual_archive_verified',
                 'saved_history_preserved_after_action', 'subsequent_collection_verified'):
        admission['claims'][name] = [result_sha]
    registry.write_text(json.dumps(value))
    monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
    assert qualification_records() == [], 'JSON self-attestation cannot replace the actual durable operation/audit/archive/collection'


@pytest.mark.parametrize('copy', ['file', 'database'])
def test_final_archive_corruption_blocks_dispatch(qualified_site, monkeypatch, copy):
    (client, app, db, _models, runtime, commands), state, _registry = qualified_site
    original = runtime.sel_manager.dispatch_intent
    def corrupt(target, operation, adapter, fingerprint, evidence):
        archive = db.session.get(runtime.SELArchive, operation.archive_id)
        if copy == 'database':
            archive.payload += ' '
            db.session.commit()
        else:
            directory = Path(os.environ['DATA_DIR']) / 'sel-archives'
            directory.mkdir(mode=0o700, exist_ok=True)
            (directory / (archive.id + '.json')).write_bytes(b'changed')
        return original(target, operation, adapter, fingerprint, evidence)
    monkeypatch.setattr(runtime.sel_manager, 'dispatch_intent', corrupt)
    headers, data = intent(client)
    response = client.post(f'/api/server/{BMC}/clear_sel', json=data, headers=headers)
    assert response.status_code == 202, response.get_json()
    assert response.get_json()['state'] == 'failed'
    assert not state['cleared']
    assert not any('0x47' in argv for argv, _ in commands)


def test_valid_empty_clock_snapshot_is_preserved_before_write(qualified_site, monkeypatch):
    (client, app, _db, _models, runtime, _commands), _state, _registry = qualified_site
    original = runtime.subprocess.run
    def empty_info(argv, **kwargs):
        result = original(argv, **kwargs)
        if 'raw' in argv and [int(v, 16) for v in argv[argv.index('raw') + 1:]] == [10, 0x40]:
            raw = bytearray.fromhex(result.stdout)
            raw[1:3] = b'\0\0'
            result.stdout = raw.hex(' ')
        return result
    monkeypatch.setattr(runtime.subprocess, 'run', empty_info)
    headers, data = intent(client)
    response = client.post(f'/api/server/{BMC}/sel/clock', json=data, headers=headers)
    assert response.status_code == 200, response.get_json()
    with app.app_context():
        archive = runtime.SELArchive.query.one()
        assert json.loads(archive.payload)['records'] == []
        assert (Path(os.environ['DATA_DIR']) / 'sel-archives' / (archive.id + '.json')).read_bytes() == archive.payload.encode()


@pytest.mark.parametrize('layer', ['execute', 'claim', 'final'])
def test_manual_only_phase_rejects_automatic_work_at_each_authority_layer(manual_site, layer):
    from ipmi_monitor import sel_management as sel
    ((_client, app, db, _models, runtime, commands), _state, _registry), _commission_id = manual_site
    with app.app_context():
        manager = runtime.sel_manager
        target = runtime.SELTarget.query.one()
        fingerprint = json.loads(target.fingerprint)
        operation = manager.claim(target, 'clear', 'admin') if layer == 'final' else None
        if operation:
            operation.automatic = True
        target.auto_clear = True
        target.consent_fingerprint = sel.digest(fingerprint)
        target.consent_qualification = json.dumps({'clear': sel.qualification_selection(fingerprint, 'clear')[1]})
        db.session.commit()
        with pytest.raises(sel.SELUnavailable):
            if layer == 'execute':
                manager.execute(target, 'clear', 'old-policy', automatic=True)
            elif layer == 'claim':
                manager.claim(target, 'clear', 'old-policy', automatic=True)
            else:
                manager.check_authority(target.id, operation.id, fingerprint)
        db.session.rollback()
        assert runtime.SELTarget.query.one().auto_clear is False
    assert not any('0x47' in argv for argv, _ in commands)


@pytest.mark.parametrize('failure', ['missing_claim', 'source_as_firmware', 'changed_guid', 'boolean_budget'])
def test_typed_evidence_cannot_launder_scope_or_hardware_claims(manual_site, monkeypatch, failure):
    from ipmi_monitor.sel_management import qualification_records
    (_site, _state, registry), _commission_id = manual_site
    value = json.loads(registry.read_bytes())
    record = value['records'][0]
    admission = record['actions']['clear']
    if failure == 'missing_claim':
        admission['claims'].pop('insertion_invalidates_or_equivalent_guard')
    elif failure == 'source_as_firmware':
        admission['claims']['reservation_required_for_erase'] = admission['claims']['saved_history_preserved']
    elif failure == 'changed_guid':
        record['fingerprint']['guid'] = 'f' * 32
    else:
        artifact = next(a for a in record['evidence_artifacts'] if a['kind'] == 'owner_scope')
        path = registry.parent / artifact['path']
        owner = json.loads(path.read_bytes())
        owner['max_attempts'] = True
        path.write_text(json.dumps(owner))
        artifact['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        admission['owner_scope_sha256'] = artifact['sha256']
    registry.write_text(json.dumps(value))
    monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
    assert qualification_records() == []


@pytest.mark.parametrize('tree', ['src/ipmi_monitor/templates', 'templates'])
def test_manual_commissioning_does_not_offer_automatic_opt_in(manual_site, login_as, tmp_path, tree):
    from tests.test_sel_management import test_full_rendered_sel_pages_keep_machine_names_text_and_local_health_urls
    site = manual_site[0][0]
    test_full_rendered_sel_pages_keep_machine_names_text_and_local_health_urls(
        site, login_as, tmp_path, tree, 'server', 'admin', '', expected_manual=True)


def clock_manual_site(qualified, mp):
    """Same real registry producer with clock CA/ownership and existing TLS boundary."""
    from ipmi_monitor import sel_qualifications as q
    manual = manual_site.__wrapped__(qualified, mp)
    (site, state, registry), commission_id = manual
    client, app, db, models, runtime, commands = site
    value = json.loads(registry.read_bytes())
    record = value['records'][0]
    by_kind = {}
    for artifact in record['evidence_artifacts']:
        path = registry.parent / artifact['path']
        body = json.loads(path.read_bytes())
        body['action'] = 'clock'
        if artifact['kind'] == 'native_guard_observation':
            body['raw_receipts'] = [{'command': [10, 0x48], 'response': state['clock'].to_bytes(4, 'little').hex()},
                {'command': [10, 0x5c], 'response': state['offset'].to_bytes(2, 'little', signed=True).hex()}]
            body['evidence'] = {'clock_semantics': 'synthetic explicit local_epoch_with_utc_offset'}
        path.write_text(json.dumps(body))
        artifact['sha256'] = q.sha(path.read_bytes())
        by_kind[artifact['kind']] = artifact['sha256']
    ownership = {k: v for k, v in body.items() if k in {'schema', 'record_id', 'fingerprint', 'runtime_identity', 'action', 'provenance'}}
    ownership.update(kind='clock_ownership', evidence={'writers': 'synthetic standalone fixture only; no external writer'})
    path = registry.parent / 'clock-ownership-v2.json'
    path.write_text(json.dumps(ownership))
    by_kind['clock_ownership'] = q.sha(path.read_bytes())
    record['evidence_artifacts'].append({'path': path.name, 'kind': 'clock_ownership', 'sha256': by_kind['clock_ownership']})
    ca_path = registry.parent / 'trusted-ca.pem'
    by_kind['ca_certificate'] = q.sha(ca_path.read_bytes())
    record['evidence_artifacts'].append({'path': ca_path.name, 'kind': 'ca_certificate', 'sha256': by_kind['ca_certificate']})
    record['clock_semantics'] = 'local_epoch_with_utc_offset'
    record['ntp_probe'] = {'path': '/redfish/v1/Managers/BMC/NetworkProtocol', 'ca_file': ca_path.name,
        'ca_sha256': by_kind['ca_certificate']}
    record['actions'] = {'clock': {'phase': 'manual_commissioning', 'commission_id': commission_id,
        'owner_scope_sha256': by_kind['owner_scope'],
        'claims': {name: [by_kind[kind] for kind in sorted(kinds)] for name, kinds in q.CLOCK_CLAIMS.items()}}}
    registry.write_text(json.dumps(value))
    mp.setenv('SEL_QUALIFICATIONS_SHA256', q.sha(registry.read_bytes()))
    original_tls = runtime.requests.get
    def managed_tls(url, **kwargs):
        # Keep the actual selected managed CA path/hash and credential boundary.
        assert Path(kwargs['verify']).read_bytes() == ca_path.read_bytes()
        assert kwargs['auth'] == ('target-admin', 'synthetic-test-secret')
        kwargs['verify'] = str(ca_path)
        return original_tls(url, **kwargs)
    mp.setattr(runtime.requests, 'get', managed_tls)
    return manual


def run_managed_promotion_round_trip(manual, mp, action='clear'):
    """Explicit real-root Linux lane; existing synthetic transport fixture only.

    Exercises the actual operation, collector, archives, managed envelope/pointer,
    promotion and consent construction. It never accesses physical hardware.
    """
    import base64
    from ipmi_monitor import sel_qualifications as q
    (site, state, registry), commission_id = manual
    client, app, db, _models, _runtime, _commands = site
    runtime=site[4]
    with app.app_context():
     data=Path(db.engine.url.database).parent
    mp.setenv('DATA_DIR',str(data))
    mp.delenv('SEL_QUALIFICATIONS_FILE');mp.delenv('SEL_QUALIFICATIONS_SHA256')
    def envelope(raw):
     parsed=json.loads(raw)
     files={'registry.json':raw}
     for record in parsed['records']:
      for a in record['evidence_artifacts']:files[a['path']]=(registry.parent/a['path']).read_bytes()
     return json.dumps({'schema':'sel-qualification-envelope/1','identity':q.runtime_identity(),
      'registry_sha256':q.sha(raw),'files':{k:base64.b64encode(v).decode() for k,v in files.items()}}).encode()
    manual_raw=registry.read_bytes();manual=envelope(manual_raw)
    assert q.install_bundle(manual,q.sha(manual))['outcome']=='installed'
    pointer_path=data/'sel-qualifications/active.json';pointer=pointer_path.read_bytes()
    headers,body=intent(client)
    response=client.post((f'/api/server/{BMC}/clear_sel' if action == 'clear' else f'/api/server/{BMC}/sel/clock'),json=body,headers=headers)
    assert response.status_code==200,response.get_json()
    assert response.get_json()['outcome']==('clear_verified' if action == 'clear' else 'clock_verified'),response.get_json()
    with app.app_context():
     target=runtime.SELTarget.query.one();operation=runtime.SELOperation.query.one()
     assert operation.commission_id==commission_id
     assert runtime.IPMIEvent.query.count()==1
     manager=runtime.sel_manager
     ticket=manager.begin_collection(BMC)
     adapter=manager.adapter(target)
     snapshot=adapter.snapshot(adapter.reserve());snapshot['fingerprint']=adapter.fingerprint()
     result=manager.finish_collection(ticket,snapshot)
     assert result['outcome']=='persisted',result
     assert runtime.IPMIEvent.query.count()==2
     archive=runtime.SELArchive.query.one()
     dispatch=runtime.SELAudit.query.filter_by(action=('dispatch_intent' if action == 'clear' else 'clock_dispatch_intent')).one()
     complete=runtime.SELAudit.query.filter_by(action='operation_complete').one()
     collection=runtime.SELAudit.query.filter_by(action='collection_persisted').one()
     original_op_evidence=operation.evidence
     result_evidence={'original_qualification_binding':operation.qualification_binding,
       'archive_id':archive.id,'archive_sha256':archive.sha256,
       'dispatch_audit_id':dispatch.id,'completion_audit_id':complete.id,
       'collection_audit_id':collection.id,'collection_receipt_digest':json.loads(collection.evidence)['receipt_digest']}
     candidate=json.loads(manual_raw);record=candidate['records'][0]
     from datetime import datetime, timedelta, timezone
     # The current automatic admission has a new, longer reviewed lifetime.
     # Its retired manual parent remains historical proof of the consumed attempt.
     record['expires_at'] = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()
     owner_artifact = next(a for a in record['evidence_artifacts'] if a['kind'] == 'owner_scope')
     owner_path = registry.parent / owner_artifact['path']
     owner_body = json.loads(owner_path.read_bytes())
     owner_body['expires_at'] = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
     owner_path.write_text(json.dumps(owner_body))
     owner_artifact['sha256'] = q.sha(owner_path.read_bytes())
     record['actions'][action]['owner_scope_sha256'] = owner_artifact['sha256']
     result_body={'schema':'sel-typed-evidence/2','record_id':record['record_id'],
      'fingerprint':record['fingerprint'],'runtime_identity':record['runtime_identity'],
      'action':action,'kind':'commissioning_result','provenance':'synthetic actual local operation; not hardware',
      'target_id':target.id,'commission_id':commission_id,'operation_id':operation.id,'evidence':result_evidence}
     result_bytes=json.dumps(result_body).encode();result_sha=q.sha(result_bytes)
     (registry.parent/'result.json').write_bytes(result_bytes)
     record['evidence_artifacts'].append({'path':'result.json','sha256':result_sha,'kind':'commissioning_result'})
     admission=record['actions'][action];admission['phase']='automatic_qualified'
     admission['parent_commission']={'envelope_sha256':q.sha(manual),'pointer_sha256':q.sha(pointer),
       'commission_id':commission_id,'operation_id':operation.id,'result_sha256':result_sha}
     for name in (q.PROMOTION_CLAIMS if action == 'clear' else q.CLOCK_PROMOTION_CLAIMS):admission['claims'][name]=[result_sha]
     promoted=envelope(json.dumps(candidate).encode())
    real_datetime = q.datetime
    class AfterManualExpiry(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime.now(tz) + timedelta(hours=2)
    mp.setattr(q, 'datetime', AfterManualExpiry)
    from unittest.mock import patch
    with patch.object(q.os, 'replace', side_effect=OSError('pre-publication fault')):
        with pytest.raises(OSError):
            q.install_bundle(promoted, q.sha(promoted), q.sha(pointer))
    assert pointer_path.read_bytes() == pointer
    assert not q.qualification_state()['records'], 'dormant receipt must not activate expired manual predecessor'
    promoted += b'\n'  # Explicit different reviewed local test transition; no blind replay.
    result=q.install_bundle(promoted,q.sha(promoted),q.sha(pointer))
    assert result['outcome']=='replaced',result
    assert q.qualification_state()['records'][0]['actions'][action]['phase']=='automatic_qualified'
    # Ordinary retention must delete raw proof without revoking accepted authority.
    with app.app_context():
        manager.cleanup_archives(datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=1))
        assert runtime.SELArchive.query.count() == 0
    assert q.qualification_state()['records'], 'normal raw archive expiry must not revoke accepted promotion'
    structural_records = q.validate_envelope(promoted, q.sha(promoted), q.runtime_identity())[2]
    with pytest.raises(q.Refused, match='promotion_archive_missing'):
        q.verify_promotions(structural_records)
    active_sha = q.sha(pointer_path.read_bytes())
    acceptance = next(p for p in (data / 'sel-qualifications/transitions').glob('accept-*.json')
        if json.loads(p.read_bytes())['binding']['candidate_pointer_sha256'] == active_sha)
    original_acceptance = acceptance.read_bytes()
    damaged = json.loads(original_acceptance)
    damaged['accepted_at'] += 'corrupt'
    acceptance.write_text(json.dumps(damaged))
    assert not q.qualification_state()['records'], 'corrupted trusted acceptance must refuse'
    acceptance.write_bytes(original_acceptance)
    assert q.qualification_state()['records']
    for delta in (timedelta(days=2, hours=1), timedelta(days=4)):
        class AfterCurrentExpiry(real_datetime):
            @classmethod
            def now(cls, tz=None):
                return real_datetime.now(tz) + delta
        mp.setattr(q, 'datetime', AfterCurrentExpiry)
        assert not q.qualification_state()['records'], 'current owner/record expiry remains enforced now'
    mp.setattr(q, 'datetime', AfterManualExpiry)
    headers,body=intent(client)
    response=client.post(f'/api/server/{BMC}/sel/policy',json={**body, 'automatic_' + action: True},headers=headers)
    assert response.status_code==200,response.get_json()
    with app.app_context():
     operation=runtime.SELOperation.query.one();bad=json.loads(operation.evidence);bad['raw_receipts']=[]
     operation.evidence=json.dumps(bad);db.session.commit()
     assert not q.qualification_state()['records'],'tampered actual completion must revoke qualification'
     target=runtime.sel_manager.refresh_consent(runtime.SELTarget.query.one())
     assert not (target.auto_clear if action == 'clear' else target.auto_clock)
     operation=db.session.get(runtime.SELOperation,operation.id);operation.evidence=original_op_evidence;db.session.commit()
     collection = db.session.get(runtime.SELAudit, result_evidence['collection_audit_id'])
     original_collection = collection.evidence
     collection.evidence = json.dumps({'receipt_digest': '0' * 64})
     db.session.commit()
     assert not q.qualification_state()['records'], 'altered retained collection audit must refuse'
     collection.evidence = original_collection
     db.session.commit()
    assert q.qualification_state()['records']
    headers, body = intent(client)
    assert client.post(f'/api/server/{BMC}/sel/policy', json={**body, 'automatic_' + action: False}, headers=headers).status_code == 200
    before_carry = pointer_path.read_bytes()
    carried = promoted + b' '
    assert q.install_bundle(carried, q.sha(carried), q.sha(before_carry))['outcome'] == 'replaced'
    assert q.qualification_state()['records'], 'unchanged accepted admission must carry forward after raw expiry'
    headers, body = intent(client)
    assert client.post(f'/api/server/{BMC}/sel/policy', json={**body, 'automatic_' + action: True}, headers=headers).status_code == 200
    with app.app_context():
        runtime.SELTarget.query.one().cooldown_until = None
        db.session.commit()
        if action == 'clock':
            state['clock'] += 3600  # Actual external-boundary drift makes auto correction eligible.
        manager.tick(BMC)
        automatic = runtime.SELOperation.query.filter_by(automatic=True).one()
        assert automatic.state == 'complete' and automatic.outcome == ('clear_verified' if action == 'clear' else 'clock_verified')
        assert automatic.commission_id is None
        assert runtime.SELArchive.query.count() == 1
        assert runtime.IPMIEvent.query.count() == 2
    return {'result':'PASS', 'action': action ,'cases':['actual one-use admin ' + action,'dual archive preserved','genuine ordinary collection',
      'dormant pre-publication receipt held','managed promotion after retired manual expiry','normal archive cleanup retained acceptance','receipt/op tamper rejected','unchanged carry-forward','fresh consent and automatic ' + action + ' with fresh dual archive'],
      'environment':'root Linux isolated network none; synthetic external tool/TLS only'}


if __name__ == '__main__':
    import sys
    import tempfile
    assert sys.argv[1:] in (['--linux-promotion'], ['--linux-clock-promotion'])
    assert sys.platform == 'linux' and os.geteuid() == 0
    from tests.conftest import app_fixture, login_as
    patcher = pytest.MonkeyPatch()
    setup = app_fixture.__wrapped__()
    try:
        app_value = next(setup)
        sel_value = sel_site.__wrapped__(app_value, login_as.__wrapped__(), patcher)
        qualified = qualified_site.__wrapped__(sel_value, patcher, Path(tempfile.mkdtemp()))
        action = 'clock' if sys.argv[1] == '--linux-clock-promotion' else 'clear'
        manual = clock_manual_site(qualified, patcher) if action == 'clock' else manual_site.__wrapped__(qualified, patcher)
        print(json.dumps(run_managed_promotion_round_trip(manual, patcher, action), sort_keys=True))
    finally:
        try:
            next(setup)
        except StopIteration:
            pass
        patcher.undo()
