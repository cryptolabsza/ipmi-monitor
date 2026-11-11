# TRACEWEAVER: file-role=charlotte-native-state-verification; req=REQ-SEL-001; trace=TRACE-SEL-001; ver=VER-CHARLOTTESEL-001
# TRACEWEAVER: verifies=VER-CHARLOTTESEL-001; req=REQ-SEL-001; trace=TRACE-SEL-001
# TRACEWEAVER: file-role=charlotte-native-state-verification; req=REQ-SEL-001,REQ-SEL-002,REQ-SEL-003,REQ-SEL-004; trace=TRACE-SEL-001,TRACE-SEL-002,TRACE-SEL-003,TRACE-SEL-004; ver=VER-CHARLOTTESEL-001,VER-CHARLOTTESEL-002,VER-CHARLOTTESEL-003,VER-CHARLOTTESEL-004
"""A01–A12 contracts: native acquisition plus real transactional SQLite state.

Missing begin/finish APIs are planned-interface RED, not a historical cause.
Existing snapshot/collector/transport failures independently reproduce defects.
"""
from copy import deepcopy
from datetime import datetime
import importlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from ipmi_monitor import sel_management as sel


BMC = '192.0.2.40'
DEVICE = bytes.fromhex('2001020151005701000100')
GUID = bytes(range(16))
RECORDS = json.loads((Path(__file__).parent / 'fixtures/charlotte_sel_native_prefix.json').read_text())['records']


@pytest.fixture()
def native_boundary(monkeypatch):
    """Exact archived bytes; synthetic stable count and returned-next-ID framing."""
    def make(skipped_prefix=False, failure=None):
        calls = []
        adapter = sel.IPMISELAdapter(SimpleNamespace(subprocess=None), BMC, ('fixture', 'synthetic-secret'))
        monkeypatch.setattr(adapter, 'open_session', lambda reservation=None: None)

        def raw(netfn, command, *data):
            calls.append((netfn, command, data))
            assert len(calls) < 150, 'native recovery has a finite per-acquisition probe bound'
            if (netfn, command) == (6, 1): return DEVICE
            if (netfn, command) == (6, 0x37): return GUID
            if (netfn, command) == (10, 0x40):
                return bytes.fromhex('5107008000020000000000000002')
            if (netfn, command) == (10, 0x42): return bytes.fromhex('3412')
            if (netfn, command) == (6, 0x2f): return bytes([8])
            if (netfn, command) == (10, 0x48): return bytes.fromhex('02000000')
            if (netfn, command) == (10, 0x5c): return bytes.fromhex('ff07')
            assert (netfn, command) == (10, 0x43), 'no write commands authorized in collection'
            assert data[:2] == (0x34, 0x12)
            requested = data[2] | data[3] << 8
            record_id = requested or (45716 if skipped_prefix else 45710)
            if failure and requested and requested < 45716:
                raise sel.SELUnavailable(failure)
            row = next((row for row in RECORDS if row['record_id'] == record_id), None)
            if row is None: raise sel.SELUnavailable('record_not_present')
            next_id = record_id + 1 if record_id < 45716 else 65535
            return next_id.to_bytes(2, 'little') + bytes.fromhex(row['raw'])

        monkeypatch.setattr(adapter, 'raw', raw)
        return adapter, calls
    return make


def test_ccc96_live_direct_prefix_recovery_preserves_all_seven_records(native_boundary):
    adapter, calls = native_boundary(skipped_prefix=True)
    snapshot = adapter.snapshot(bytes.fromhex('3412'))
    assert snapshot['complete'] is True
    assert sorted(snapshot['records'], key=lambda row: row['record_id']) == RECORDS
    addressed = {data[2] | data[3] << 8 for n, c, data in calls if (n, c) == (10, 0x43)}
    assert set(range(45710, 45716)) <= addressed, 'archive bytes cannot substitute for live direct reads'


def test_session_failure_during_prefix_recovery_cannot_be_treated_as_absent(native_boundary):
    adapter, _calls = native_boundary(skipped_prefix=True, failure='rmcp_session_failed')
    with pytest.raises(sel.SELUnavailable) as caught:
        adapter.snapshot(bytes.fromhex('3412'))
    assert caught.value.code == 'rmcp_session_failed'


@pytest.fixture()
def collection_site(app_fixture, monkeypatch):
    _client, app, db, models = app_fixture
    runtime = importlib.import_module('ipmi_monitor.app')
    monkeypatch.setattr(runtime, 'update_server_status', lambda *a, **kw: None)
    monkeypatch.setattr(runtime.requests.sessions.Session, 'request', lambda *a, **kw: pytest.fail('network forbidden'))
    alerts = []
    monkeypatch.setattr(runtime, '_send_sel_event_alert', lambda ip, name, event: alerts.append(event.sel_id))
    monkeypatch.setattr(runtime, 'get_ipmi_credentials', lambda ip: ('fixture', 'synthetic-secret'))
    with app.app_context():
        server = models['Server'](bmc_ip=BMC, server_name='fixture-host', enabled=True, status='active', protocol='ipmi')
        db.session.add(server)
        db.session.commit()
        target = runtime.sel_manager.target(BMC)
        target.fingerprint = json.dumps({'device_id_reply': DEVICE.hex(), 'guid': GUID.hex()})
        db.session.commit()
    return app, db, models, runtime, alerts


def snapshot(records=None):
    return {'complete': True, 'records': deepcopy(RECORDS if records is None else records),
            'info': {'entries': len(RECORDS if records is None else records), 'last_add': '02000000',
                     'last_erase': '00000000'}, 'reservation': '3412',
            'collected_at': '2026-11-11T05:00:00Z'}


@pytest.mark.parametrize('protocol', ['auto', 'ipmi'])
def test_native_count_not_nonempty_redfish_controls_existing_collector(collection_site, native_boundary, monkeypatch, protocol):
    app, _db, _models, runtime, _alerts = collection_site
    with app.app_context():
        _models['Server'].query.filter_by(bmc_ip=BMC).update({'protocol':protocol}); _db.session.commit()
    adapter, _calls = native_boundary()
    monkeypatch.setattr(runtime.sel_manager, 'adapter', lambda target: adapter)
    monkeypatch.setattr(runtime, 'should_use_redfish', lambda ip: True)
    partial = runtime.IPMIEvent(bmc_ip=BMC, server_name='fixture-host', sel_id='45716',
        event_date=datetime(1970, 1, 1), sensor_type='OEM', event_description='filtered view', raw_entry='redfish-only', severity='warning')
    monkeypatch.setattr(runtime, 'collect_sel_redfish', lambda *a: [partial])
    with app.app_context():
        events = runtime.collect_ipmi_sel(BMC, 'fixture-host')
        assert len(events) == 7, 'one stale Redfish row cannot replace seven native records'


def test_existing_save_path_does_not_replay_historical_native_warnings(collection_site):
    app, _db, models, runtime, alerts = collection_site
    with app.app_context():
        events = [runtime.IPMIEvent(bmc_ip=BMC, server_name='fixture-host',
            sel_id=str(row['record_id']), event_date=datetime(1970, 1, 1),
            sensor_type='Power Supply', event_description='Archived historical warning',
            raw_entry=row['raw'], severity='warning') for row in RECORDS]
        runtime.save_events_to_db(BMC, 'fixture-host', events)
        assert models['IPMIEvent'].query.filter_by(bmc_ip=BMC).count() == 7
        assert alerts == [], 'first native backfill must persist without replaying incident alerts'


def test_first_baseline_restart_prospective_and_failed_catchup_alerts(collection_site):
    app, db, models, runtime, alerts = collection_site
    with app.app_context():
        manager = runtime.sel_manager
        ticket = manager.begin_collection(BMC)
        with pytest.raises(sel.SELUnavailable):
            manager.begin_collection(BMC)  # One durable in-flight acquisition per target.
        assert manager.finish_collection(ticket, snapshot=snapshot())['outcome'] == 'persisted'
        assert alerts == []
        assert models['IPMIEvent'].query.filter_by(bmc_ip=BMC).count() == 7
        # Read the durable JSON column directly, independently of representation.
        from sqlalchemy import text
        stored = db.session.execute(text('SELECT collection_state FROM sel_target WHERE bmc_ip=:ip'), {'ip': BMC}).scalar_one()
        assert json.loads(stored)['baseline_complete'] is True
        db.session.remove()  # Baseline protection must survive a new database session.
        manager.migrate()
        manager.migrate()  # Additive migration is idempotent and cannot reset baseline.
        baseline = manager.representation(manager.target(BMC))['collection']
        assert baseline['baseline_complete'] is True
        assert baseline['native_expected'] == baseline['native_received'] == baseline['native_persisted'] == 7
        assert baseline['last_attempt_at'] and baseline['last_complete_success_at']
        newer = {'record_id': 45717, 'raw': '95b2023062816820000408e201520000'}
        assert manager.finish_collection(manager.begin_collection(BMC), snapshot=snapshot(RECORDS + [newer]))['outcome'] == 'persisted'
        assert alerts == ['45717'], 'only a prospective native record after baseline alerts'
        previous_success = manager.representation(manager.target(BMC))['collection']['last_complete_success_at']
        assert manager.finish_collection(manager.begin_collection(BMC), error='device_timeout')['outcome'] == 'failed'
        failed = manager.representation(manager.target(BMC))['collection']
        assert failed['last_complete_success_at'] == previous_success
        assert failed['safe_reason'] == 'device_timeout'
        catchup = {'record_id': 45718, 'raw': '96b2023162816820000408e201520000'}
        manager.finish_collection(manager.begin_collection(BMC), snapshot=snapshot(RECORDS + [newer, catchup]))
        assert alerts == ['45717'], 'unseen rows after a failed interval are catch-up, not fresh incidents'


@pytest.mark.parametrize('change', ['snapshot_epoch', 'generation', 'binding', 'revision'])
def test_stale_acquisition_ticket_cannot_commit_rows_or_success(collection_site, change):
    app, db, models, runtime, alerts = collection_site
    with app.app_context():
        manager = runtime.sel_manager
        ticket = manager.begin_collection(BMC)
        target = manager.target(BMC)
        setattr(target, change, 'changed-binding' if change == 'binding' else getattr(target, change) + 1)
        db.session.commit()
        result = manager.finish_collection(ticket, snapshot=snapshot())
        assert result['outcome'] == 'failed'
        assert models['IPMIEvent'].query.filter_by(bmc_ip=BMC).count() == 0
        assert manager.representation(manager.target(BMC))['collection']['last_complete_success_at'] is None
        assert alerts == []


def test_store_failure_rolls_back_records_and_success_together(collection_site, monkeypatch):
    app, db, models, runtime, alerts = collection_site
    from sqlalchemy.exc import OperationalError
    with app.app_context():
        manager = runtime.sel_manager
        manager.finish_collection(manager.begin_collection(BMC), snapshot=snapshot([]))
        previous = manager.representation(manager.target(BMC))['collection']['last_complete_success_at']
        ticket = manager.begin_collection(BMC)
        from sqlalchemy import event
        def refuse_insert(*args): raise OperationalError('fixture insert refused', {}, Exception('synthetic'))
        event.listen(models['IPMIEvent'], 'before_insert', refuse_insert)
        try:
            result = manager.finish_collection(ticket, snapshot=snapshot())
        finally:
            event.remove(models['IPMIEvent'], 'before_insert', refuse_insert)
        assert result['outcome'] == 'failed'
        db.session.remove()
        assert models['IPMIEvent'].query.filter_by(bmc_ip=BMC).count() == 0
        assert manager.representation(manager.target(BMC))['collection']['last_complete_success_at'] == previous
        assert alerts == []


@pytest.mark.parametrize('cipher,mismatch', [(17, None), (3, None), (3, 'guid'), (3, 'binding')])
def test_managed_read_profile_selects_exact_bound_cipher_and_rejects_identity_mismatch(
        collection_site, monkeypatch, tmp_path, cipher, mismatch):
    app, db, _models, runtime, _alerts = collection_site
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, deepcopy(kwargs)))
        values = [int(v, 16) for v in argv[argv.index('raw') + 1:]]
        output = DEVICE if values == [6, 1] else GUID
        return SimpleNamespace(returncode=0, stdout=output.hex(' '), stderr='')
    monkeypatch.setattr(runtime.subprocess, 'run', run)
    with app.app_context():
        target = runtime.sel_manager.target(BMC)
        if cipher == 3:
            path = tmp_path / 'read-profile.json'
            path.write_text(json.dumps({'schema_version': 'sel-read-profiles/1', 'profiles': [{
                'server_id': target.server_id, 'binding': 'stale' if mismatch == 'binding' else target.binding,
                'bmc_ip': BMC, 'cipher': 3, 'device_id_reply': DEVICE.hex(),
                'guid': bytes(reversed(GUID)).hex() if mismatch == 'guid' else GUID.hex()}]}))
            path.chmod(0o600)
            monkeypatch.setenv('SEL_READ_PROFILES_FILE', str(path))
        else:
            monkeypatch.delenv('SEL_READ_PROFILES_FILE', raising=False)
        if mismatch:
            with pytest.raises(sel.SELUnavailable):
                runtime.sel_manager.adapter(target).fingerprint()
        else:
            fingerprint = runtime.sel_manager.adapter(target).fingerprint()
            assert calls and all(argv[argv.index('-C') + 1] == str(cipher) for argv, _kw in calls)
            assert fingerprint['transport'] == f'lanplus-cipher{cipher}-admin'
            observed = runtime.sel_manager.observe(BMC)
            assert observed['probes']['identity']['profile'] == f'lanplus-cipher{cipher}-admin'
        assert all('-P' not in argv and kw['env']['IPMI_PASSWORD'] == 'synthetic-secret' for argv, kw in calls)
        assert runtime.sel_manager.representation(target)['capabilities']['clear']['available'] is False


@pytest.mark.parametrize('owner_status', ['running', 'unverifiable', 'dead_child_reaped'])
def test_expired_read_owner_needs_death_and_reaping_proof_then_fences_late_finish(
        collection_site, monkeypatch, owner_status):
    from datetime import timedelta
    app, db, models, runtime, alerts = collection_site
    now = [datetime(2026, 11, 11, 5, 0)]
    monkeypatch.setattr(sel, 'utcnow', lambda: now[0])
    with app.app_context():
        manager = runtime.sel_manager
        old = manager.begin_collection(BMC)
        now[0] += timedelta(seconds=211)  #180s acquisition +30s reaping/reconciliation grace.
        monkeypatch.setattr(manager, 'collection_owner_status', lambda ticket: owner_status)
        if owner_status != 'dead_child_reaped':
            with pytest.raises(sel.SELUnavailable):
                manager.recover_collection(BMC, old['attempt_id'])
            with pytest.raises(sel.SELUnavailable): manager.begin_collection(BMC)
            return
        manager.recover_collection(BMC, old['attempt_id'])
        fresh = manager.begin_collection(BMC)
        assert fresh['attempt_id'] != old['attempt_id']
        assert manager.finish_collection(old, snapshot=snapshot())['outcome'] == 'failed'
        db.session.remove()
        state = json.loads(manager.target(BMC).collection_state)
        assert state['active_attempt_id'] == fresh['attempt_id'], 'late owner cannot release replacement lease'
        assert manager.representation(manager.target(BMC))['collection']['last_complete_success_at'] is None
        assert models['IPMIEvent'].query.filter_by(bmc_ip=BMC).count() == 0
        assert alerts == []
        assert manager.finish_collection(fresh, snapshot=snapshot([]))['outcome'] == 'persisted'


@pytest.mark.parametrize('failure', ['device_timeout', 'skipped_unreachable'])
def test_empty_success_freshness_cannot_be_refreshed_by_probes_reachability_or_failed_attempt(
        collection_site, monkeypatch, failure):
    from datetime import timedelta
    app, db, models, runtime, _alerts = collection_site
    now = [datetime(2026, 11, 11, 5, 0)]
    monkeypatch.setattr(sel, 'utcnow', lambda: now[0])
    monkeypatch.setattr(runtime, 'POLL_INTERVAL', 300)
    with app.app_context():
        manager = runtime.sel_manager
        manager.finish_collection(manager.begin_collection(BMC), snapshot=snapshot([]))
        complete = manager.representation(manager.target(BMC))['collection']
        assert complete['last_complete_success_at'] and complete['stale'] is False
        now[0] += timedelta(seconds=781)  #2poll intervals +180s acquisition budget +1.
        target = manager.target(BMC)
        target.observed_at = now[0]
        db.session.add(models['ServerStatus'](bmc_ip=BMC, server_name='fixture-host',
            is_reachable=True, last_check=now[0]))
        db.session.commit()
        manager.finish_collection(manager.begin_collection(BMC), error=failure)
        actual = manager.representation(manager.target(BMC))['collection']
        assert actual['stale'] is True
        assert actual['last_complete_success_at'] == complete['last_complete_success_at']
        assert actual['safe_reason'] == failure


@pytest.mark.parametrize('producer', ['worker', 'bulk'])
@pytest.mark.parametrize('failure', [None, 'acquisition', 'storage'])
def test_normal_producers_use_atomic_native_success_and_baseline_boundary(
        collection_site, native_boundary, monkeypatch, producer, failure):
    from queue import Queue
    from threading import Event
    from sqlalchemy import event
    from sqlalchemy.exc import OperationalError
    app, db, models, runtime, alerts = collection_site
    adapter, _calls = native_boundary()
    if failure == 'acquisition':
        def unavailable(*args): raise sel.SELUnavailable('device_timeout')
        monkeypatch.setattr(adapter, 'raw', unavailable)
    monkeypatch.setattr(runtime.sel_manager, 'adapter', lambda target: adapter)
    monkeypatch.setattr(runtime, 'should_use_redfish', lambda ip: False)
    monkeypatch.setattr(runtime, 'get_servers', lambda: {BMC: 'fixture-host'})
    monkeypatch.setattr(runtime, 'get_collection_workers', lambda: 1)
    monkeypatch.setattr(runtime.sel_manager, 'tick', lambda ip: None)
    monkeypatch.setattr(runtime, 'check_ssh_xid_errors', lambda *args: None)
    # Only the legacy child boundary is substituted, never collect/save/finish.
    lines = '\n'.join(f"{row['record_id']:04x} | 11/11/2026 | 05:00:00 | Power Supply | Historical warning | Asserted" for row in RECORDS)
    monkeypatch.setattr(runtime.subprocess, 'run', lambda *a, **kw: SimpleNamespace(
        returncode=1 if failure == 'acquisition' else 0, stdout=lines, stderr='device_timeout'))
    def refuse_insert(*args): raise OperationalError('fixture insert refused', {}, Exception('synthetic'))
    if failure == 'storage': event.listen(models['IPMIEvent'], 'before_insert', refuse_insert)
    try:
        if producer == 'bulk':
            runtime.collect_all_events()
        else:
            jobs = Queue()
            jobs.put(('sel', BMC, 'fixture-host'))
            jobs.put(None)
            monkeypatch.setattr(runtime, '_collection_queue', jobs)
            monkeypatch.setattr(runtime, '_shutdown_event', Event())
            runtime.collection_worker(991)
    finally:
        if failure == 'storage': event.remove(models['IPMIEvent'], 'before_insert', refuse_insert)
    with app.app_context():
        state = runtime.sel_manager.representation(runtime.sel_manager.target(BMC))['collection']
        count = models['IPMIEvent'].query.filter_by(bmc_ip=BMC).count()
        if failure:
            assert state['last_complete_success_at'] is None and state['stale'] is True
            assert state['outcome'] != 'persisted' and count == 0
        else:
            assert state['last_complete_success_at'] and state['stale'] is False
            assert state['baseline_complete'] is True and count == 7
        assert alerts == [], 'historical imports from either producer cannot replay incidents'


def test_real_process_owner_proof_holds_live_owner_and_unreaped_child(collection_site):
    """PC01: real OS start identities, never a caller-provided liveness enum."""
    import subprocess
    import sys
    from ipmi_monitor.sel_collection import process_identity, owner_status
    owner = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
    try:
        ticket = {'owner': process_identity(owner.pid), 'child': process_identity(child.pid),
                  'child_state': 'running'}
        assert ticket['owner']['start'] and ticket['owner']['boot']
        assert owner_status(ticket) == 'running'
        owner.terminate(); owner.wait(timeout=3)
        assert owner_status(ticket) == 'unverifiable', 'live old child prevents recovery'
        child.terminate(); child.wait(timeout=3)
        assert owner_status(ticket) == 'dead_child_reaped'
        ticket['owner']['boot'] = 'foreign-boot'
        assert owner_status(ticket) == 'unverifiable', 'foreign boot is not local death proof'
    finally:
        for process in (owner, child):
            if process.poll() is None: process.kill()
            process.wait(timeout=3)


def test_raw_decoder_preserves_oem_time_and_conservative_standard_severity():
    from ipmi_monitor.sel_collection import decode_record
    warning = decode_record(RECORDS[0])
    assert warning['severity'] == 'critical' and warning['event_direction'] == 'Asserted'
    assert warning['native_timestamp'] == str(int.from_bytes(bytes.fromhex(RECORDS[0]['raw'])[3:7], 'little'))
    assert warning['time_quality'] == 'native-unverified'
    oem = {'record_id': 1, 'raw': (b'\x01\x00\xe0' + bytes(range(13))).hex()}
    decoded = decode_record(oem)
    assert decoded['severity'] == 'info' and decoded['time_quality'] == 'oem-no-timestamp'
    assert decoded['native_timestamp'] is None and decoded['raw_entry'] == oem['raw']


def test_process_restart_suppresses_first_catchup_without_global_mute(collection_site, monkeypatch):
    app, _db, models, runtime, alerts = collection_site
    with app.app_context():
        manager = runtime.sel_manager
        manager.finish_collection(manager.begin_collection(BMC), snapshot=snapshot())
        monkeypatch.setattr(sel, 'PROCESS_INSTANCE', 'new-synthetic-process-instance')
        added = {'record_id': 45717, 'raw': '95b2023062816820000408e201520000'}
        assert manager.finish_collection(manager.begin_collection(BMC), snapshot=snapshot(RECORDS + [added]))['outcome'] == 'persisted'
        assert alerts == [], 'records accumulated across process restart are catch-up'
        current = {'record_id': 45718, 'raw': '96b2023162816820000408e201520000'}
        manager.finish_collection(manager.begin_collection(BMC), snapshot=snapshot(RECORDS + [added, current]))
        assert alerts == ['45718'], 'prospective notifications resume after the new baseline'


def test_native_erase_evidence_fences_old_generation_before_inserts(collection_site):
    app, _db, models, runtime, _alerts = collection_site
    with app.app_context():
        manager = runtime.sel_manager
        manager.finish_collection(manager.begin_collection(BMC), snapshot=snapshot())
        target = manager.target(BMC)
        generation = target.generation
        changed = snapshot([{'record_id': 45717, 'raw': '95b2023062816820000408e201520000'}])
        changed['info']['last_erase'] = '01000000'
        assert manager.finish_collection(manager.begin_collection(BMC), snapshot=changed)['outcome'] == 'failed'
        assert models['IPMIEvent'].query.filter_by(bmc_ip=BMC).count() == 7
        assert manager.target(BMC).generation == generation + 1
        assert manager.finish_collection(manager.begin_collection(BMC), snapshot=changed)['outcome'] == 'persisted'
        assert models['IPMIEvent'].query.filter_by(bmc_ip=BMC).count() == 8


def test_foreign_pid_namespace_cannot_prove_owner_death(monkeypatch):
    import subprocess
    import sys
    from ipmi_monitor import sel_collection as collection
    owner = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
    ticket = {'owner': collection.process_identity(owner.pid), 'child': None, 'child_state': 'none'}
    owner.terminate(); owner.wait(timeout=3)
    assert collection.owner_status(ticket) == 'dead_child_reaped'
    ticket['owner']['namespace'] = 'different-container-pid-namespace'
    assert collection.owner_status(ticket) == 'unverifiable'


def test_failed_collection_health_cannot_be_healthy_from_fresh_probes(collection_site):
    app, db, _models, runtime, _alerts = collection_site
    with app.app_context():
        manager = runtime.sel_manager
        target = manager.target(BMC)
        target.health = json.dumps({'logging_enabled': True, 'full': False,
            'clock': {'offset_minutes': 0}, 'clock_mapping': 'utc_epoch', 'reference_verified': True})
        target.observed_at = sel.utcnow()
        db.session.commit()
        manager.finish_collection(manager.begin_collection(BMC), error='device_timeout')
        view = manager.representation(manager.target(BMC))
        assert view['health']['state'] == 'collection_degraded'
        assert view['health']['logging_enabled'] is True
        assert view['collection']['stale'] is True


@pytest.mark.parametrize('initial_store_failure', [False, True])
def test_live_owned_child_prevents_finish_and_lease_release(collection_site, monkeypatch, initial_store_failure):
    import subprocess
    import sys
    app, db, models, runtime, _alerts = collection_site
    with app.app_context():
        manager = runtime.sel_manager
        ticket = manager.begin_collection(BMC)
        manager.collection_child(ticket, 'launching')
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        try:
            manager.collection_child(ticket, 'running', child)
            state = json.loads(manager.target(BMC).collection_state)
            assert state['active_ticket']['child']['pid'] == child.pid
            if initial_store_failure:
                from sqlalchemy.exc import OperationalError
                original = manager.collection_lock
                attempts = [0]
                def fail_first_lock(target_id):
                    attempts[0] += 1
                    if attempts[0] == 1:
                        raise OperationalError('fixture lock refused', {}, Exception('synthetic'))
                    return original(target_id)
                monkeypatch.setattr(manager, 'collection_lock', fail_first_lock)
            result = manager.finish_collection(ticket, snapshot=snapshot([]))
            assert result['outcome'] == 'failed'
            state = json.loads(manager.target(BMC).collection_state)
            assert state['active_attempt_id'] == ticket['attempt_id']
            assert manager.representation(manager.target(BMC))['collection']['last_complete_success_at'] is None
            with pytest.raises(sel.SELUnavailable): manager.begin_collection(BMC)
        finally:
            child.terminate(); child.wait(timeout=3)
        manager.collection_child(ticket, 'reaped')
        assert manager.finish_collection(ticket, snapshot=snapshot([]))['outcome'] == 'persisted'


@pytest.mark.parametrize('sensor,offset,severity', [(8, 3, 'critical'), (7, 11, 'critical'),
    (12, 1, 'critical'), (0xc1, 11, 'info')])
def test_known_native_failures_and_unknown_oem_are_classified_conservatively(sensor, offset, severity):
    from ipmi_monitor.sel_collection import decode_record
    raw = bytearray.fromhex(RECORDS[0]['raw'])
    raw[10], raw[12], raw[13] = sensor, 0x6f, offset
    row = {'record_id': RECORDS[0]['record_id'], 'raw': raw.hex()}
    assert decode_record(row)['severity'] == severity
    raw[12] |= 0x80
    assert decode_record({'record_id': row['record_id'], 'raw': raw.hex()})['severity'] == 'info'


def test_child_receipt_database_contention_is_bounded_and_does_not_change_mutation_timeout(collection_site):
    from threading import Event, Thread
    from sqlalchemy import text
    app, db, _models, runtime, _alerts = collection_site
    done = Event()
    results = []
    with app.app_context():
        manager = runtime.sel_manager
        ticket = manager.begin_collection(BMC)
        blocker = db.engine.connect()
        blocker.exec_driver_sql('BEGIN IMMEDIATE')
    def receive_child():
        with app.app_context():
            try:
                manager.collection_child(ticket, 'launching')
                results.append('accepted')
            except sel.SELUnavailable as exc:
                results.append(exc.code)
            finally:
                done.set()
    worker = Thread(target=receive_child)
    worker.start()
    try:
        assert done.wait(timeout=2), 'a blocked child receipt cannot consume the60s global SQLite timeout'
    finally:
        blocker.rollback(); blocker.close()
        worker.join(timeout=3)
    assert results == ['collection_child_identity_unavailable']
    with app.app_context():
        assert db.session.execute(text('PRAGMA busy_timeout')).scalar_one() == 60000
        db.session.rollback()


def test_modified_ticket_cannot_reassign_old_snapshot_to_current_generation(collection_site):
    app, db, models, runtime, _alerts = collection_site
    with app.app_context():
        manager = runtime.sel_manager
        ticket = manager.begin_collection(BMC)
        target = manager.target(BMC)
        target.generation += 1
        target.snapshot_epoch += 1
        db.session.commit()
        # A producer must not be able to relabel captured evidence at save time.
        ticket['generation'], ticket['snapshot_epoch'] = target.generation, target.snapshot_epoch
        assert manager.finish_collection(ticket, snapshot=snapshot())['outcome'] == 'failed'
        assert models['IPMIEvent'].query.filter_by(bmc_ip=BMC).count() == 0
        assert manager.representation(manager.target(BMC))['collection']['last_complete_success_at'] is None


@pytest.mark.parametrize('concurrent', ['lease', 'success'])
def test_observe_does_not_overwrite_concurrent_collection_commit(collection_site, monkeypatch, concurrent):
    app, db, _models, runtime, _alerts = collection_site
    manager = runtime.sel_manager
    committed = []
    info = {'entries': 7, 'free_bytes': 128, 'percent_used': 0,
            'last_add': '02000000', 'last_erase': '00000000'}
    with app.app_context():
        target = manager.target(BMC)
        target.health = json.dumps({'info': info})
        fingerprint = json.loads(target.fingerprint)
        original_generation = target.generation
        db.session.commit()
    def during_info():
        with app.app_context():
            ticket = manager.begin_collection(BMC)
            if concurrent == 'success':
                assert manager.finish_collection(ticket, snapshot=snapshot())['outcome'] == 'persisted'
            committed.append(json.loads(manager.target(BMC).collection_state))
        # An older probe cannot apply this erase after a newer collection commit.
        return dict(info, last_erase='01000000')
    adapter = SimpleNamespace(fingerprint=lambda: fingerprint, info=during_info, logging=lambda: 8,
        clock=lambda: {'native_seconds': 0, 'offset_minutes': None, 'quality': 'uninitialized'}, close=lambda: None)
    monkeypatch.setattr(manager, 'adapter', lambda target: adapter)
    with app.app_context():
        manager.observe(BMC)
        target = manager.target(BMC)
        actual = json.loads(target.collection_state)
        assert actual == committed[0], 'observer must merge against durable current state, never its stale JSON'
        assert target.generation == original_generation, 'stale erase observation cannot mutate authority'
        if concurrent == 'lease':
            with pytest.raises(sel.SELUnavailable): manager.begin_collection(BMC)
        else:
            assert actual['baseline_complete'] and actual['last_complete_success_at']
            assert actual['native_persisted'] == 7


@pytest.mark.parametrize('result', ['complete', 'empty', 'acquisition_failure', 'storage_failure'])
def test_actual_single_host_manual_route_finishes_native_batch(collection_site, native_boundary, monkeypatch, result):
    from sqlalchemy import event
    from sqlalchemy.exc import OperationalError
    app, db, models, runtime, alerts = collection_site
    adapter, _calls = native_boundary()
    normal_raw = adapter.raw
    if result == 'empty':
        def empty_raw(netfn, command, *data):
            if (netfn, command) == (10, 0x40): return bytes.fromhex('5100008000020000000000000002')
            return normal_raw(netfn, command, *data)
        monkeypatch.setattr(adapter, 'raw', empty_raw)
    if result == 'acquisition_failure':
        monkeypatch.setattr(adapter, 'raw', lambda *args: (_ for _ in ()).throw(sel.SELUnavailable('device_timeout')))
    monkeypatch.setattr(runtime.sel_manager, 'adapter', lambda target: adapter)
    monkeypatch.setattr(runtime.sel_manager, 'tick', lambda ip: None)
    monkeypatch.setattr(runtime, 'build_sensor_cache', lambda ip: None)
    scheduled = []
    monkeypatch.setattr(runtime.threading, 'Thread', lambda target, **kw: SimpleNamespace(start=lambda: scheduled.append(target)))
    client = app.test_client()
    with client.session_transaction() as session:
        session.update(logged_in=True, username='testadmin', user_role='admin')
    response = client.post('/api/collect?bmc_ip=' + BMC)
    assert response.status_code == 200 and len(scheduled) == 1
    def refuse_insert(*args): raise OperationalError('fixture insert refused', {}, Exception('synthetic'))
    if result == 'storage_failure': event.listen(models['IPMIEvent'], 'before_insert', refuse_insert)
    try:
        scheduled[0]()  # Real handler/collector/persistence; only scheduling is controlled.
    finally:
        if result == 'storage_failure': event.remove(models['IPMIEvent'], 'before_insert', refuse_insert)
    with app.app_context():
        state = json.loads(runtime.sel_manager.target(BMC).collection_state)
        assert state['active_attempt_id'] is None
        expected = 7 if result == 'complete' else 0
        assert models['IPMIEvent'].query.filter_by(bmc_ip=BMC).count() == expected
        assert bool(state['last_complete_success_at']) == (result in {'complete', 'empty'})
        assert state['outcome'] == ('persisted' if result in {'complete', 'empty'} else 'failed')
        assert alerts == [], 'manual backfill must not replay historical incidents'
        # A subsequent ordinary native producer must be admitted, not stranded.
        if result == 'acquisition_failure': monkeypatch.setattr(adapter, 'raw', normal_raw)
        batch = runtime.collect_ipmi_sel(BMC, 'fixture-host')
        assert runtime.save_events_to_db(BMC, 'fixture-host', batch)['outcome'] == 'persisted'
        assert json.loads(runtime.sel_manager.target(BMC).collection_state)['active_attempt_id'] is None


def test_manual_collection_rejects_unconfigured_target_before_any_io(collection_site, monkeypatch):
    app, _db, _models, runtime, _alerts = collection_site
    seen = []
    monkeypatch.setattr(runtime, 'build_sensor_cache', lambda ip: seen.append('sensor'))
    monkeypatch.setattr(runtime, 'get_ipmi_credentials', lambda ip: seen.append('credentials'))
    monkeypatch.setattr(runtime.threading, 'Thread', lambda **kw: seen.append('thread'))
    client = app.test_client()
    with client.session_transaction() as session:
        session.update(logged_in=True, username='testadmin', user_role='admin')
    response = client.post('/api/collect?bmc_ip=192.0.2.250')
    assert response.status_code == 404
    assert seen == []


from tests.test_sel_collection_regressions import redfish_reader


@pytest.mark.parametrize('producer', ['worker', 'bulk', 'manual'])
@pytest.mark.parametrize('result', ['complete', 'empty', 'failure', 'storage_failure'])
def test_explicit_redfish_mode_preserves_all_producers_without_native_claims(
        collection_site, redfish_reader, monkeypatch, producer, result):
    from queue import Queue
    from threading import Event
    from sqlalchemy import event
    from sqlalchemy.exc import OperationalError
    app, db, models, runtime, alerts = collection_site
    page = {'Members': [] if result == 'empty' else [{'Id': 'rf-1', 'EntryType': 'SEL',
        'Created': '2026-11-11T01:00:00Z', 'Message': 'Power fault', 'Severity': 'Warning'}]}
    if result == 'failure': page['Members@odata.nextLink'] = '//foreign.invalid/Entries'
    client, calls = redfish_reader(page)
    monkeypatch.setattr(runtime, 'get_redfish_client', lambda ip: client)
    monkeypatch.setattr(runtime.subprocess, 'run', lambda *a, **kw: pytest.fail('native child forbidden'))
    monkeypatch.setattr(runtime.subprocess, 'Popen', lambda *a, **kw: pytest.fail('native child forbidden'))
    monkeypatch.setattr(runtime, 'build_sensor_cache', lambda *a: pytest.fail('native cache forbidden'))
    monkeypatch.setattr(runtime, 'check_ssh_xid_errors', lambda *a: None)
    monkeypatch.setattr(runtime, 'get_servers', lambda: {BMC: 'fixture-host'})
    monkeypatch.setattr(runtime, 'get_collection_workers', lambda: 1)
    with app.app_context():
        models['Server'].query.filter_by(bmc_ip=BMC).update({'protocol': 'redfish'}); db.session.commit()
    def refuse(*a): raise OperationalError('fixture refused', {}, Exception('synthetic'))
    if result == 'storage_failure': event.listen(models['IPMIEvent'], 'before_insert', refuse)
    try:
        if producer == 'bulk': runtime.collect_all_events()
        elif producer == 'worker':
            jobs = Queue(); jobs.put(('sel', BMC, 'fixture-host')); jobs.put(None)
            monkeypatch.setattr(runtime, '_collection_queue', jobs); monkeypatch.setattr(runtime, '_shutdown_event', Event())
            runtime.collection_worker(994)
        else:
            monkeypatch.setattr(runtime.threading, 'Thread', lambda target, **kw: SimpleNamespace(start=target))
            http = app.test_client()
            with http.session_transaction() as session: session.update(logged_in=True,username='testadmin',user_role='admin')
            assert http.post('/api/collect?bmc_ip='+BMC).status_code == 200
    finally:
        if result == 'storage_failure': event.remove(models['IPMIEvent'], 'before_insert', refuse)
    with app.app_context():
        manager = runtime.sel_manager; target = manager.target(BMC)
        state = json.loads(target.collection_state)
        rows = models['IPMIEvent'].query.filter_by(bmc_ip=BMC).all()
        assert calls, 'the actual bounded genuine SEL reader must be used'
        assert state['active_attempt_id'] is None
        rf = manager.representation(target)['collection']['redfish']
        assert bool(rf.get('last_success_at')) == (result in {'complete','empty'})
        assert len(rows) == (1 if result == 'complete' else 0)
        assert state.get('last_complete_success_at') is None and state.get('native_expected') is None
        assert not state.get('baseline_complete') and manager.collection_view(target)['stale'] is True
        assert not any(value['available'] for value in manager.representation(target)['capabilities'].values())
        assert alerts == []
        if rows:
            assert rows[0].native_timestamp == '2026-11-11T01:00:00Z'
            assert rows[0].time_quality.startswith('redfish-') and 'rf-1' in rows[0].raw_entry


def test_redfish_only_status_leaves_never_fall_back_to_native(collection_site, monkeypatch):
    app, db, models, runtime, _alerts = collection_site
    with app.app_context():
        models['Server'].query.filter_by(bmc_ip=BMC).update({'protocol':'redfish'});db.session.commit()
        monkeypatch.setattr(runtime, 'collect_power_status_redfish', lambda ip: None)
        monkeypatch.setattr(runtime, 'get_ipmi_credentials', lambda ip: pytest.fail('native credential/child path forbidden'))
        assert runtime.collect_power_status(BMC) == 'Unknown'
        assert runtime.collect_sensors(BMC, 'fixture') == []
        assert runtime.collect_power_reading(BMC, 'fixture') is None


def test_redfish_view_baseline_prospective_and_failed_catchup_notifications(collection_site, redfish_reader, monkeypatch):
    app, db, models, runtime, alerts = collection_site
    first = {'Id':'rf-1','EntryType':'SEL','Created':'2026-11-11T01:00:00Z','Message':'Fault','Severity':'Warning'}
    page = {'Members':[first]}
    client,calls = redfish_reader(page)
    monkeypatch.setattr(runtime, 'get_redfish_client', lambda ip: client)
    with app.app_context():
        models['Server'].query.filter_by(bmc_ip=BMC).update({'protocol':'redfish'});db.session.commit()
        def collect():
            calls.clear()  # Existing fixture bounds each acquisition, not five independent polls.
            return runtime.save_events_to_db(BMC,'fixture',runtime.collect_ipmi_sel(BMC,'fixture'))
        assert collect()['outcome'] == 'persisted_diagnostic'; assert alerts == []
        assert collect()['outcome'] == 'persisted_diagnostic'; assert alerts == []
        page['Members'].append(dict(first,Id='rf-2',Created='2026-11-11T01:00:01Z'))
        assert collect()['outcome'] == 'persisted_diagnostic'; assert alerts == ['rf-2']
        page['Members@odata.nextLink'] = '//foreign.invalid/Entries'
        assert collect()['outcome'] == 'failed'
        del page['Members@odata.nextLink']
        page['Members'].append(dict(first,Id='rf-3',Created='2026-11-11T01:00:02Z'))
        assert collect()['outcome'] == 'persisted_diagnostic'; assert alerts == ['rf-2']
