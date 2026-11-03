# TRACEWEAVER: file-role=sel-verification-005; req=REQ-SEL-005; trace=TRACE-SEL-005; ver=VER-SEL-005
# TRACEWEAVER: verifies=VER-SEL-005; req=REQ-SEL-005; trace=TRACE-SEL-005
# TRACEWEAVER: file-role=sel-verification-004; req=REQ-SEL-004; trace=TRACE-SEL-004; ver=VER-SEL-004
# TRACEWEAVER: verifies=VER-SEL-004; req=REQ-SEL-004; trace=TRACE-SEL-004
# TRACEWEAVER: file-role=sel-verification-003; req=REQ-SEL-003; trace=TRACE-SEL-003; ver=VER-SEL-003
# TRACEWEAVER: verifies=VER-SEL-003; req=REQ-SEL-003; trace=TRACE-SEL-003
# TRACEWEAVER: file-role=sel-verification-002; req=REQ-SEL-002; trace=TRACE-SEL-002; ver=VER-SEL-002
# TRACEWEAVER: verifies=VER-SEL-002; req=REQ-SEL-002; trace=TRACE-SEL-002
# TRACEWEAVER: file-role=sel-verification-001; req=REQ-SEL-001; trace=TRACE-SEL-001; ver=VER-SEL-001
# TRACEWEAVER: verifies=VER-SEL-001; req=REQ-SEL-001; trace=TRACE-SEL-001
# TRACEWEAVER: verifies=REQ-SEL-001,REQ-SEL-002,REQ-SEL-003,REQ-SEL-004,REQ-SEL-005; trace=TRACE-SEL-001,TRACE-SEL-002,TRACE-SEL-003,TRACE-SEL-004,TRACE-SEL-005; ver=VER-SEL-001,VER-SEL-002,VER-SEL-003,VER-SEL-004,VER-SEL-005
"""Observable SEL contracts, using the application's parser, persistence and Flask routes.

No hardware is accessed. Only subprocess/network boundaries are substituted;
the producer, database and request authorization paths remain real.
"""

from datetime import datetime
import importlib
from types import SimpleNamespace

import pytest


BMC = "192.0.2.40"


@pytest.fixture()
def sel_site(app_fixture, login_as, monkeypatch):
    client, app, db, models = app_fixture
    runtime = importlib.import_module("ipmi_monitor.app")
    commands = []
    models['credential_resolver'] = runtime.get_ipmi_credentials
    models['command_runner'] = runtime.subprocess.run

    def command_boundary(argv, **kwargs):
        commands.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="Clearing SEL.\n", stderr="")

    def no_network(*args, **kwargs):
        raise AssertionError("SEL contract tests must not access a network")

    monkeypatch.setattr(runtime.subprocess, "run", command_boundary)
    monkeypatch.setattr(runtime.requests.sessions.Session, "request", no_network)
    monkeypatch.setattr(runtime, "get_ipmi_password", lambda ip: "synthetic-test-secret")
    monkeypatch.setattr(runtime, "get_ipmi_credentials", lambda ip: ("target-admin", "synthetic-test-secret"))
    with app.app_context():
        db.session.add(models["Server"](
            bmc_ip=BMC, server_name="sel-contract-host", enabled=True, status="active", protocol="ipmi"
        ))
        event = runtime.parse_sel_line(
            "0001 | 11/03/2026 | 12:00:00 | System Event | Previous saved evidence | Asserted",
            BMC, "sel-contract-host",
        )
        assert event is not None
        runtime.save_events_to_db(BMC, "sel-contract-host", [event])
        assert models["IPMIEvent"].query.filter_by(bmc_ip=BMC).count() == 1
    commands.clear()  # Observe request dispatch separately from seed status collection.
    login_as(client, "admin")
    return client, app, db, models, runtime, commands


def test_unobserved_health_is_unknown_and_automation_defaults_off(sel_site):
    client, _app, _db, _models, _runtime, commands = sel_site
    response = client.get(f"/api/server/{BMC}/sel/health")
    assert response.status_code == 200
    body = response.get_json()
    assert body["bmc_ip"] == BMC
    assert body["server_name"] == "sel-contract-host"
    assert body["health"]["state"] == "unknown"
    assert body["health"]["logging_enabled"] is None
    assert body["health"]["percent_used"] is None
    assert body["policies"]["automatic_clear"] is False
    assert body["policies"]["automatic_clock"] is False
    assert commands == []  # Viewing unobserved health must not mutate a device.


@pytest.mark.parametrize("path", [f"/api/server/{BMC}/clear_sel", "/api/clear_all_sel"])
def test_bmc_clear_never_deletes_saved_history(sel_site, path):
    """A bodyless request currently erases history; guarded rejection must preserve it."""
    client, app, _db, models, _runtime, _commands = sel_site
    response = client.post(path, json={})
    with app.app_context():
        assert models["IPMIEvent"].query.filter_by(bmc_ip=BMC).count() == 1, response.get_json()


@pytest.mark.parametrize("path", [f"/api/server/{BMC}/clear_sel", "/api/clear_all_sel"])
def test_readwrite_cannot_dispatch_sel_mutation(sel_site, login_as, path):
    client, _app, _db, _models, _runtime, commands = sel_site
    login_as(client, "readwrite")
    response = client.post(path, json={})
    assert response.status_code == 403
    assert commands == []


@pytest.mark.parametrize("headers", [{}, {"Origin": "https://attacker.invalid"}])
def test_admin_clear_requires_session_intent_and_exact_origin(sel_site, headers):
    client, _app, _db, _models, _runtime, commands = sel_site
    response = client.post(f"/api/server/{BMC}/clear_sel", json={}, headers=headers)
    assert response.status_code == 403
    assert commands == []


def test_unknown_configured_target_is_rejected_before_credentials(sel_site, monkeypatch):
    client, _app, _db, _models, runtime, commands = sel_site
    lookups = []
    monkeypatch.setattr(runtime, "get_ipmi_password", lambda ip: lookups.append(ip) or "synthetic-test-secret")
    response = client.post("/api/server/192.0.2.250/clear_sel", json={})
    assert response.status_code in (403, 404)  # CSRF may reject before target lookup.
    assert lookups == []
    assert commands == []


def test_raw_record_reuse_survives_real_parse_save_pipeline(sel_site):
    """A later generation can reuse both record ID and native timestamp."""
    _client, app, _db, models, runtime, _commands = sel_site
    with app.app_context():
        line = "0001 | 11/03/2026 | 12:00:00 | System Event | New generation evidence | Asserted"
        runtime.save_events_to_db(BMC, "sel-contract-host", [runtime.parse_sel_line(line, BMC, "sel-contract-host")])
        runtime.save_events_to_db(BMC, "sel-contract-host", [runtime.parse_sel_line(line, BMC, "sel-contract-host")])
        events = models["IPMIEvent"].query.filter_by(bmc_ip=BMC).all()
        assert len(events) == 2
        assert {event.raw_entry for event in events} == {
            "0001 | 11/03/2026 | 12:00:00 | System Event | Previous saved evidence | Asserted", line
        }


def test_newly_collected_bad_native_date_does_not_expire_history(sel_site):
    _client, app, db, models, runtime, _commands = sel_site
    now = datetime.utcnow()
    with app.app_context():
        event = runtime.parse_sel_line(
            "0002 | 01/01/2000 | 00:00:00 | System Event | Clock uninitialized evidence | Asserted",
            BMC, "sel-contract-host",
        )
        event.collected_at = now
        runtime.save_events_to_db(BMC, "sel-contract-host", [event])
        summary = runtime.cleanup_old_data(now=now)
        assert not summary["events"]["failed"]
        db.session.expire_all()
        assert models["IPMIEvent"].query.filter_by(bmc_ip=BMC, sel_id="0002").count() == 1


def test_policy_update_requires_session_intent(sel_site):
    client, _app, _db, _models, _runtime, commands = sel_site
    response = client.post(f"/api/server/{BMC}/sel/policy", json={"automatic_clear": True})
    assert response.status_code == 403
    assert commands == []


def test_native_clock_action_is_guarded_before_dispatch(sel_site):
    client, _app, _db, _models, _runtime, commands = sel_site
    response = client.post(f"/api/server/{BMC}/sel/clock", json={})
    assert response.status_code == 403
    assert commands == []


@pytest.mark.parametrize("command", ["sel clear", "sel time set 11/03/2026", "raw 0x0a 0x47 0 0 0x43 0x4c 0x52 0xaa", "mc setenables eventmsg=on"])
def test_custom_command_cannot_bypass_guarded_sel_actions(sel_site, command):
    client, _app, _db, _models, _runtime, commands = sel_site
    response = client.post(f"/api/server/{BMC}/execute", json={"type": "ipmi", "command": command})
    assert response.status_code == 409
    assert commands == []


@pytest.fixture()
def qualified_site(sel_site, monkeypatch, tmp_path):
    """A real registry + real adapter; only raw subprocess and TLS HTTP are replaced.

    Synthetic qualification is confined to this temporary test installation.
    It is never shipped or claimed as device qualification evidence.
    """
    import hashlib
    import json
    import time
    from datetime import timedelta
    from ipmi_monitor.sel_management import utcnow

    client, app, db, models, runtime, commands = sel_site
    state = {"offset": 120, "clock": int(time.time()) + 7200 + 3600,
             "logging": 0x05, "cleared": False, "invalidate": False,
             "offset_failure": False, "bad_readback": False, "raw_short": False,
             "ntp_enabled": False, "unsynchronized": False}
    raw_record = bytes.fromhex('01000200000020630104050102030405')
    assert len(raw_record) == 16

    def raw_boundary(argv, **kwargs):
        commands.append((argv, kwargs))
        if argv[0] == 'timedatectl':
            return SimpleNamespace(returncode=0, stdout='no' if state['unsynchronized'] else 'yes', stderr='')
        assert '-P' not in argv
        assert argv[argv.index('-U') + 1] == 'target-admin'
        assert kwargs['env']['IPMI_PASSWORD'] == 'synthetic-test-secret'
        values = [int(value, 16) for value in argv[argv.index('raw') + 1:]]
        netfn, cmd, *data = values
        output = b''
        if (netfn, cmd) == (6, 1):
            output = bytes.fromhex('2001020151005701000100')
        elif (netfn, cmd) == (6, 0x37):
            output = bytes(range(16))
        elif (netfn, cmd) == (10, 0x40):
            # A new event remains after clear; nonempty does not authorize another clear.
            free = state.get('free_bytes', 0)
            flags = 2 | (1 if state.get('allocation') else 0) | (128 if state.get('overflow') else 0)
            output = bytes([0x51, 1, 0, free & 255, free >> 8, 1, 0, 0, 0, int(state['cleared']), 0, 0, 0, flags])
        elif (netfn, cmd) == (10, 0x41):
            output = bytes([100, 0, 32, 0, 10, 0, 10, 0, 1])
        elif (netfn, cmd) == (6, 0x2f):
            output = bytes([state['logging']])
        elif (netfn, cmd) == (6, 0x2e):
            if not state['bad_readback']:
                state['logging'] = data[0]
        elif (netfn, cmd) == (10, 0x42):
            output = bytes.fromhex('3412')
        elif (netfn, cmd) == (10, 0x43):
            assert data[:2] == [0x34, 0x12]
            output = bytes.fromhex('ffff') + raw_record
            if state['raw_short']:
                output = output[:-1]
        elif (netfn, cmd) == (10, 0x47):
            assert data[:2] == [0x34, 0x12]
            with app.app_context():
                archive = runtime.SELArchive.query.one()
                payload = json.loads(archive.payload)
                assert payload['records'] == [{'record_id': 1, 'raw': raw_record.hex()}]
                assert archive.sha256 == hashlib.sha256(archive.payload.encode()).hexdigest()
                assert runtime.SELAudit.query.filter_by(action='archive_committed').count() == 1
                assert runtime.SELOperation.query.one().state == 'mutating'
            if state['invalidate']:
                return SimpleNamespace(returncode=1, stdout='', stderr='rsp=0xc5 synthetic-test-secret')
            state['cleared'] = True
            output = bytes([1])
        elif (netfn, cmd) == (10, 0x48):
            output = state['clock'].to_bytes(4, 'little')
        elif (netfn, cmd) == (10, 0x5c):
            output = state['offset'].to_bytes(2, 'little', signed=True)
        elif (netfn, cmd) == (10, 0x49):
            state['clock'] = int.from_bytes(bytes(data), 'little')
            state['offset'] = 2047
        elif (netfn, cmd) == (10, 0x5d):
            if state['offset_failure']:
                return SimpleNamespace(returncode=1, stdout='', stderr='unsafe synthetic-test-secret output')
            state['offset'] = int.from_bytes(bytes(data), 'little', signed=True)
        else:
            raise AssertionError(f'unexpected fixed command {values}')
        return SimpleNamespace(returncode=0, stdout=output.hex(' '), stderr='')

    monkeypatch.setattr(runtime.subprocess, 'run', raw_boundary)
    import ipmi_monitor.sel_management as sel_module
    monkeypatch.setattr(sel_module, 'kernel_clock_status', lambda: {'result': 0, 'status': 0x40 if state['unsynchronized'] else 1,
        'maxerror_us': 1000, 'offset_us': 0, 'utc': time.time()})

    def tls_boundary(url, **kwargs):
        assert url == f'https://{BMC}/redfish/v1/Managers/BMC/NetworkProtocol'
        assert kwargs['verify'] == '/test/qualified-ca.pem'
        assert kwargs['allow_redirects'] is False
        return SimpleNamespace(status_code=200, content=b'{}', json=lambda: {
            'NTP': {'ProtocolEnabled': state['ntp_enabled'], 'Status': {'Health': 'OK'}}})

    monkeypatch.setattr(runtime.requests, 'get', tls_boundary)
    with app.app_context():
        db.session.add(models['ServerConfig'](bmc_ip=BMC, server_name='sel-contract-host',
            ipmi_user='target-admin', ipmi_pass='synthetic-test-secret'))
        db.session.commit()
        target = runtime.sel_manager.target(BMC)
        fingerprint = runtime.sel_manager.adapter(target).fingerprint()
    checks = {
        'clear': ['same_reservation', 'insertion_invalidates', 'competing_reservation', 'complete_raw_backup', 'completion_readback', 'new_events_survive'],
        'enable': ['unrelated_bits_preserved', 'enabled_readback'],
        'clock': ['positive_offset', 'negative_offset', 'offset_restored', 'interrupted_write', 'trusted_reference', 'ntp_ownership', 'clock_readback'],
    }
    record = {'fingerprint': fingerprint, 'test_only': False, 'reviewer': 'synthetic-test-reviewer',
        'approved_at': (utcnow() - timedelta(hours=1)).isoformat() + 'Z',
        'expires_at': (utcnow() + timedelta(hours=1)).isoformat() + 'Z',
        'firmware_identity_scope': fingerprint.get('firmware_identity_capability'),
        'actions': {action: {'checks': dict.fromkeys(names, True), 'canary_operation_ids': ['synthetic-only'],
                            'sha256': ['1' * 64]} for action, names in checks.items()},
        'clock_semantics': 'local_epoch_with_utc_offset',
        'ntp_probe': {'path': '/redfish/v1/Managers/BMC/NetworkProtocol', 'ca_file': '/test/qualified-ca.pem'}}
    evidence = tmp_path / 'canary.json'
    evidence.write_text(json.dumps({'synthetic_fixture_only': True, 'fingerprint': fingerprint, 'checks': checks}))
    record['record_id'] = '54f962a7-f5e0-4b34-b776-bae08729a541'
    record['evidence_artifacts'] = [{'path': 'canary.json', 'sha256': hashlib.sha256(evidence.read_bytes()).hexdigest()}]
    registry = tmp_path / 'qualifications.json'
    registry.write_text(json.dumps({'schema': 'sel-device-qualification/1', 'records': [record]}))
    monkeypatch.setenv('SEL_QUALIFICATIONS_FILE', str(registry))
    monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
    with app.app_context():
        runtime.sel_manager.observe(BMC)
    commands.clear()
    return sel_site, state, registry


def intent(client, bmc_ip=BMC):
    """Consume the real API producer for token and current identity/policy versions."""
    response = client.get(f'/api/server/{bmc_ip}/sel/health')
    assert response.status_code == 200
    value = response.get_json()
    return ({'Origin': 'http://localhost', 'X-CSRF-Token': value['csrf_token']},
            {'target_id': value['target_id'], 'identity_revision': value['identity_revision'],
             'policy_revision': value['policies']['revision']})


def test_qualified_clear_archives_raw_before_same_reservation_dispatch(qualified_site):
    (client, app, _db, models, runtime, commands), state, _registry = qualified_site
    headers, data = intent(client)
    response = client.post(f'/api/server/{BMC}/clear_sel', json=data, headers=headers)
    assert response.status_code == 200, response.get_json()
    assert response.get_json()['state'] == 'complete'
    assert response.get_json()['archive_receipt']
    assert state['cleared'] is True
    assert sum('0x47' in argv[argv.index('raw') + 1:] for argv, _ in commands if 'raw' in argv) == 1
    with app.app_context():
        assert models['IPMIEvent'].query.filter_by(bmc_ip=BMC).count() == 1
        assert runtime.SELArchive.query.count() == 1
        assert runtime.SELOperation.query.one().state == 'complete'


@pytest.mark.parametrize('failure', ['invalidate', 'raw_short'])
def test_incomplete_or_invalidated_snapshot_cannot_clear(qualified_site, failure):
    (client, app, _db, models, runtime, _commands), state, _registry = qualified_site
    state[failure] = True
    headers, data = intent(client)
    response = client.post(f'/api/server/{BMC}/clear_sel', json=data, headers=headers)
    assert response.status_code == 202
    assert response.get_json()['state'] == 'failed'
    assert state['cleared'] is False
    with app.app_context():
        assert models['IPMIEvent'].query.count() == 1
        assert runtime.SELArchive.query.count() == (1 if failure == 'invalidate' else 0)


@pytest.mark.parametrize('offset', [-180, 120])
def test_clock_restores_positive_and_negative_offset_using_real_raw_adapter(qualified_site, offset):
    (client, app, _db, _models, runtime, _commands), state, _registry = qualified_site
    state['offset'] = offset
    headers, data = intent(client)
    response = client.post(f'/api/server/{BMC}/sel/clock', json=data, headers=headers)
    assert response.status_code == 200, response.get_json()
    assert response.get_json()['outcome'] == 'clock_verified'
    assert state['offset'] == offset
    with app.app_context():
        assert runtime.SELAudit.query.filter_by(action='clock_dispatch_intent').count() == 1


@pytest.mark.parametrize('condition', ['offset_failure', 'ntp_enabled', 'unsynchronized'])
def test_clock_failure_or_external_authority_never_reports_success(qualified_site, condition):
    (client, app, _db, _models, runtime, commands), state, _registry = qualified_site
    state[condition] = True
    headers, data = intent(client)
    response = client.post(f'/api/server/{BMC}/sel/clock', json=data, headers=headers)
    assert response.status_code == 202
    assert response.get_json()['state'] == ('outcome-unknown' if condition == 'offset_failure' else 'failed')
    assert 'synthetic-test-secret' not in response.get_data(as_text=True)
    with app.app_context():
        target = runtime.SELTarget.query.one()
        if condition == 'offset_failure':
            assert target.active_operation
        else:
            assert not any('0x49' in argv[argv.index('raw') + 1:] for argv, _ in commands if 'raw' in argv)


@pytest.mark.parametrize('bad_readback', [False, True])
def test_enable_preserves_unrelated_bits_and_requires_readback(qualified_site, bad_readback):
    (client, _app, _db, _models, _runtime, _commands), state, _registry = qualified_site
    state['bad_readback'] = bad_readback
    headers, data = intent(client)
    response = client.post(f'/api/server/{BMC}/sel/enable', json=data, headers=headers)
    assert response.get_json()['state'] == ('outcome-unknown' if bad_readback else 'complete')
    assert state['logging'] & ~8 == 5


@pytest.mark.parametrize('lifecycle', ['unconfigured', 'disabled', 'retired'])
def test_valid_session_intent_rejects_bad_inventory_before_credentials(qualified_site, monkeypatch, lifecycle):
    (client, app, db, models, runtime, commands), _state, _registry = qualified_site
    headers, data = intent(client)
    path = BMC
    with app.app_context():
        server = models['Server'].query.one()
        if lifecycle == 'unconfigured':
            path = '192.0.2.250'
        elif lifecycle == 'disabled':
            server.enabled = False
        else:
            server.status = 'deprecated'
        db.session.commit()
    monkeypatch.setattr(runtime.sel_manager, 'adapter', lambda target: pytest.fail('credential adapter must not be reached'))
    response = client.post(f'/api/server/{path}/clear_sel', json=data, headers=headers)
    assert response.status_code == 404, response.get_json()
    assert commands == []


def test_registry_pin_or_firmware_mismatch_is_warning_only(qualified_site, monkeypatch):
    (client, _app, _db, _models, _runtime, commands), _state, _registry = qualified_site
    monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', '0' * 64)
    headers, data = intent(client)
    response = client.post(f'/api/server/{BMC}/clear_sel', json=data, headers=headers)
    assert response.status_code == 409
    assert response.get_json()['error'] == 'exact_hardware_qualification_required'
    assert not any('0x47' in argv[argv.index('raw') + 1:] for argv, _ in commands if 'raw' in argv)


def test_policy_defaults_are_independent_and_revocation_stops_queued_dispatch(qualified_site):
    (client, app, db, _models, runtime, _commands), _state, _registry = qualified_site
    headers, data = intent(client)
    response = client.post(f'/api/server/{BMC}/sel/policy', json={**data, 'automatic_clear': True}, headers=headers)
    assert response.status_code == 200
    assert response.get_json()['policies']['automatic_clear'] is True
    assert response.get_json()['policies']['automatic_clock'] is False
    with app.app_context():
        target = runtime.SELTarget.query.one()
        operation = runtime.sel_manager.claim(target, 'clear', 'automatic-policy', True)
        fingerprint = __import__('json').loads(target.fingerprint)
        adapter = runtime.sel_manager.adapter(target)
        headers, data = intent(client)
        response = client.post(f'/api/server/{BMC}/sel/policy', json={**data, 'automatic_clear': False}, headers=headers)
        assert response.status_code == 200
        from ipmi_monitor.sel_management import SELUnavailable
        with pytest.raises(SELUnavailable, match='revoked'):
            runtime.sel_manager.recheck(target, operation, adapter, fingerprint)
        db.session.rollback()


def test_archive_database_failure_prevents_hardware_clear(qualified_site):
    from sqlalchemy import event
    (client, _app, _db, _models, runtime, commands), state, _registry = qualified_site

    def fail_archive(*args):
        raise RuntimeError('synthetic storage outage')

    event.listen(runtime.SELArchive, 'before_insert', fail_archive)
    try:
        headers, data = intent(client)
        response = client.post(f'/api/server/{BMC}/clear_sel', json=data, headers=headers)
    finally:
        event.remove(runtime.SELArchive, 'before_insert', fail_archive)
    assert response.status_code == 202
    assert response.get_json()['state'] == 'failed'
    assert state['cleared'] is False
    assert not any('0x47' in argv[argv.index('raw') + 1:] for argv, _ in commands if 'raw' in argv)


def test_ownership_serializes_independent_workers_and_clock_clear(qualified_site):
    from threading import Barrier, Thread
    from ipmi_monitor.sel_management import SELUnavailable
    (_client, app, _db, _models, runtime, _commands), _state, _registry = qualified_site
    gate, results = Barrier(2), []

    def worker(action):
        with app.app_context():
            target = runtime.sel_manager.target(BMC)
            gate.wait(timeout=5)
            try:
                operation = runtime.sel_manager.claim(target, action, 'independent-worker')
                results.append(operation.state)
            except SELUnavailable as exc:
                results.append(exc.code)

    workers = [Thread(target=worker, args=(action,)) for action in ('clear', 'clock')]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)
    assert all(not worker.is_alive() for worker in workers)
    assert sorted(results) == ['operation_busy_or_cooldown', 'queued']
    with app.app_context():
        assert runtime.SELOperation.query.count() == 1


@pytest.mark.parametrize('dispatched', [False, True])
def test_restart_reconciliation_never_replays_hardware_mutation(qualified_site, dispatched):
    from datetime import timedelta
    from ipmi_monitor.sel_management import utcnow
    (_client, app, db, _models, runtime, commands), state, _registry = qualified_site
    with app.app_context():
        target = runtime.sel_manager.target(BMC)
        operation = runtime.sel_manager.claim(target, 'clear', 'interrupted-worker')
        operation.updated_at = utcnow() - timedelta(seconds=100)
        operation.dispatched_at = operation.updated_at if dispatched else None
        db.session.commit()
        runtime.sel_manager.reconcile(target)
        assert operation.state == ('outcome-unknown' if dispatched else 'failed')
        assert bool(target.active_operation) is dispatched
    assert state['cleared'] is False
    assert not any('0x47' in argv[argv.index('raw') + 1:] for argv, _ in commands if 'raw' in argv)


def test_pending_archive_and_independent_audit_survive_retention_and_history_clear(qualified_site):
    from datetime import timedelta
    from ipmi_monitor.sel_management import utcnow
    (client, app, db, _models, runtime, _commands), _state, _registry = qualified_site
    with app.app_context():
        target = runtime.sel_manager.target(BMC)
        operation = runtime.sel_manager.claim(target, 'clear', 'interrupted-worker')
        archive = runtime.SELArchive(id='active-receipt', target_id=target.id, operation_id=operation.id,
            generation=target.generation, snapshot_epoch=target.snapshot_epoch, sha256='0'*64,
            payload='{}', archived_at=utcnow() - timedelta(days=100))
        db.session.add(archive)
        operation.archive_id = archive.id
        db.session.commit()
        runtime.sel_manager.cleanup_archives(utcnow())
        assert runtime.SELArchive.query.count() == 1
        audit_count = runtime.SELAudit.query.count()
    response = client.post(f'/api/server/{BMC}/clear_db_events', json={})
    assert response.status_code == 200
    with app.app_context():
        assert runtime.SELArchive.query.count() == 1
        assert runtime.SELAudit.query.count() == audit_count
        operation = runtime.SELOperation.query.one()
        operation.state = 'complete'
        db.session.commit()
        runtime.sel_manager.cleanup_archives(utcnow())
        assert runtime.SELArchive.query.count() == 0


def test_unknown_native_timestamp_remains_raw_and_unknown_in_real_api(sel_site):
    client, app, _db, _models, runtime, _commands = sel_site
    line = '0009 | Pre-Init | Time | System Event | Raw time evidence | Asserted'
    with app.app_context():
        runtime.save_events_to_db(BMC, 'sel-contract-host', [runtime.parse_sel_line(line, BMC, 'sel-contract-host')])
    value = client.get(f'/api/server/{BMC}/events').get_json()
    item = next(event for event in value if event['sel_id'] == '0009')
    assert item['event_date'] is None
    assert item['time_quality'] == 'unknown'
    assert item['native_timestamp'] == 'Pre-Init Time'
    assert item['raw_entry'] == line


def test_unspecified_utc_offset_produces_no_clock_write(qualified_site):
    (client, _app, _db, _models, _runtime, commands), state, _registry = qualified_site
    state['offset'] = 2047  # IPMI 0x07ff, not signed -2048.
    headers, data = intent(client)
    response = client.post(f'/api/server/{BMC}/sel/clock', json=data, headers=headers)
    assert response.status_code == 202
    assert response.get_json()['outcome'] == 'clock_mapping_unknown'
    assert not any('0x49' in argv[argv.index('raw') + 1:] for argv, _ in commands if 'raw' in argv)


def test_managed_credential_revocation_is_preserved(sel_site, monkeypatch):
    _client, app, db, models, runtime, _commands = sel_site
    monkeypatch.setattr(runtime, 'get_ipmi_credentials', models['credential_resolver'])
    monkeypatch.setattr(runtime, '_file_bmc_credentials', lambda ip: (('stale-user', 'stale-secret'), None))
    with app.app_context():
        db.session.add(runtime.InventoryBinding(source_id='site', source_server_id='machine', bmc_ip=BMC,
            server_name='sel-contract-host', server_ip='192.0.2.41', lifecycle='active', revision=1, bmc_managed=True))
        db.session.commit()
    with app.app_context():
        target = runtime.sel_manager.target(BMC)
        from ipmi_monitor.sel_management import SELUnavailable
        with pytest.raises(SELUnavailable, match='credentials_unavailable'):
            runtime.sel_manager.adapter(target)


def test_legacy_sqlite_migration_preserves_rows_and_replaces_record_id_constraint(sel_site, tmp_path):
    from sqlalchemy import create_engine
    _client, app, _db, _models, runtime, _commands = sel_site
    engine = create_engine('sqlite:///' + str(tmp_path / 'legacy.db'))
    with engine.begin() as connection:
        connection.exec_driver_sql('''CREATE TABLE ipmi_event (
            id INTEGER PRIMARY KEY, bmc_ip VARCHAR(20) NOT NULL, server_name VARCHAR(50) NOT NULL,
            sel_id VARCHAR(20) NOT NULL, event_date DATETIME NOT NULL, sensor_type VARCHAR(50) NOT NULL,
            sensor_id VARCHAR(20), sensor_number VARCHAR(10), event_description VARCHAR(200) NOT NULL,
            event_direction VARCHAR(20), event_data VARCHAR(50), severity VARCHAR(20) NOT NULL,
            raw_entry TEXT, collected_at DATETIME, CONSTRAINT unique_event UNIQUE (bmc_ip,sel_id))''')
        connection.exec_driver_sql("INSERT INTO ipmi_event VALUES (42,'192.0.2.40','legacy','0001','2000-01-01','OEM',NULL,NULL,'evidence',NULL,NULL,'info','deadbeef','2026-11-03')")
        before = connection.exec_driver_sql('SELECT * FROM ipmi_event').one()
    with app.app_context():
        runtime.sel_manager.migrate(engine)
        runtime.sel_manager.migrate(engine)  # Idempotent actual migration entrypoint.
    with engine.connect() as connection:
        after = connection.exec_driver_sql('SELECT * FROM ipmi_event').one()
        assert tuple(after[:len(before)]) == tuple(before)
        constraints = __import__('sqlalchemy').inspect(engine).get_unique_constraints('ipmi_event')
        assert not any(set(c['column_names']) == {'bmc_ip', 'sel_id'} for c in constraints)
    engine.dispose()


@pytest.mark.parametrize('status, result, error, expected', [(1,0,1000,True), (0x40,5,1000,False), (0,0,1000,False), (1,0,16000000,False)])
def test_linux_reference_requires_real_kernel_sync_contract(sel_site, monkeypatch, status, result, error, expected):
    import time
    import ipmi_monitor.sel_management as sel
    _client, _app, _db, _models, runtime, _commands = sel_site
    monkeypatch.setattr(sel.sys, 'platform', 'linux')
    monkeypatch.setattr(sel, 'kernel_clock_status', lambda: {'result': result, 'status': status,
        'maxerror_us': error, 'offset_us': 0, 'utc': time.time()})
    value = sel.trusted_reference(runtime)
    assert (value is not None) is expected
    if value:
        assert value['source'] == 'linux-adjtimex-read-only'


def test_hostile_origin_and_cross_session_token_cannot_be_forwarded_into_authority(qualified_site, login_as):
    (client, _app, _db, _models, _runtime, commands), _state, _registry = qualified_site
    headers, data = intent(client)
    response = client.post(f'/api/server/{BMC}/clear_sel', json=data,
        headers={**headers, 'Origin': 'https://attacker.invalid', 'X-Forwarded-Host': 'attacker.invalid',
                 'X-Forwarded-Proto': 'https'}, environ_overrides={'REMOTE_ADDR':'192.0.2.200'})
    assert response.status_code == 403
    assert commands == []
    with client.session_transaction() as saved:
        saved.pop('sel_csrf')
    response = client.post(f'/api/server/{BMC}/clear_sel', json=data, headers=headers)
    assert response.status_code == 403
    assert commands == []


@pytest.mark.parametrize('free,overflow,allocation,expected_full,percent', [
    (64, True, False, False, None), (65535, True, False, None, None),
    (0, False, False, True, None), (320, False, True, False, 90.0)])
def test_current_capacity_does_not_infer_full_from_historical_overflow_or_16_byte_units(
        qualified_site, free, overflow, allocation, expected_full, percent):
    (_client, app, _db, _models, runtime, _commands), state, _registry = qualified_site
    state.update(free_bytes=free, overflow=overflow, allocation=allocation)
    with app.app_context():
        health = runtime.sel_manager.observe(BMC)
        assert health['full'] is expected_full
        assert health['percent_used'] == percent
        assert health['info']['overflow'] is overflow


def test_health_freshness_matches_normal_collection_interval(qualified_site, monkeypatch):
    from datetime import timedelta
    from ipmi_monitor.sel_management import utcnow
    (_client, app, db, _models, runtime, _commands), _state, _registry = qualified_site
    monkeypatch.setattr(runtime, 'POLL_INTERVAL', 300)
    with app.app_context():
        target = runtime.sel_manager.target(BMC)
        target.observed_at = utcnow() - timedelta(seconds=400)
        db.session.commit()
        assert runtime.sel_manager.health(target)['stale'] is False
        target.observed_at = utcnow() - timedelta(seconds=601)
        assert runtime.sel_manager.health(target)['stale'] is True


@pytest.mark.parametrize('command', ['raw 10 71 0 0 67 76 82 170', 'raw 012 0107 0 0 0103 0114 0122 0252', 'sel clear-extra'])
def test_custom_clear_numeric_or_prefix_aliases_cannot_bypass_guard(sel_site, command):
    client, _app, _db, _models, _runtime, commands = sel_site
    response = client.post(f'/api/server/{BMC}/execute', json={'type':'ipmi','command':command})
    assert response.status_code == 409
    assert commands == []


def test_accepted_clear_poll_reservation_loss_retains_uncertain_ownership(qualified_site, monkeypatch):
    (client, app, _db, _models, runtime, _commands), _state, _registry = qualified_site
    original, calls = runtime.subprocess.run, []

    def boundary(argv, **kwargs):
        if 'raw' in argv:
            values = [int(v, 16) for v in argv[argv.index('raw') + 1:]]
            if values[:2] == [10, 71]:
                calls.append(values[-1])
                return SimpleNamespace(returncode=0, stdout='00', stderr='') if values[-1] == 170 else SimpleNamespace(returncode=1, stdout='', stderr='rsp=0xc5')
        return original(argv, **kwargs)

    monkeypatch.setattr(runtime.subprocess, 'run', boundary)
    headers, data = intent(client)
    response = client.post(f'/api/server/{BMC}/clear_sel', json=data, headers=headers)
    assert calls == [170, 0]
    assert response.get_json()['state'] == 'outcome-unknown'
    with app.app_context():
        target = runtime.SELTarget.query.one()
        operation = runtime.SELOperation.query.one()
        assert target.active_operation == operation.id
        assert runtime.SELArchive.query.filter_by(id=operation.archive_id).count() == 1


@pytest.mark.parametrize('action', ['enable', 'clear', 'clock'])
def test_revocation_during_final_device_identity_io_prevents_dispatch(qualified_site, monkeypatch, action):
    (client, app, db, models, runtime, commands), state, _registry = qualified_site
    original, guids = runtime.subprocess.run, 0

    def boundary(argv, **kwargs):
        nonlocal guids
        if 'raw' in argv:
            values = [int(v, 16) for v in argv[argv.index('raw') + 1:]]
            if values[:2] == [6, 55]:
                guids += 1
                if guids == (3 if action == 'clear' else 2):
                    with app.app_context():
                        models['Server'].query.filter_by(bmc_ip=BMC).update({'enabled': False})
                        db.session.commit()
        return original(argv, **kwargs)

    monkeypatch.setattr(runtime.subprocess, 'run', boundary)
    headers, data = intent(client)
    route = '/clear_sel' if action == 'clear' else '/sel/' + action
    response = client.post(f'/api/server/{BMC}' + route, json=data, headers=headers)
    assert response.get_json()['state'] == 'failed'
    mutations = {(6, 46), (10, 71), (10, 73), (10, 93)}
    assert not any(tuple(int(v, 16) for v in argv[argv.index('raw')+1:argv.index('raw')+3]) in mutations for argv, _ in commands if 'raw' in argv)
    assert state['logging'] == 5


def test_auxiliary_firmware_changes_exact_identity_and_revokes_consent(qualified_site, monkeypatch):
    from ipmi_monitor.sel_management import qualified
    (client, app, db, _models, runtime, _commands), _state, _registry = qualified_site
    with app.app_context():
        target = runtime.sel_manager.target(BMC)
        adapter = runtime.sel_manager.adapter(target)
        original = adapter.raw
        prefix = bytes.fromhex('2001020151005701000100')
        adapter.raw = lambda netfn, cmd: prefix + bytes.fromhex('01020304') if (netfn,cmd) == (6,1) else original(netfn,cmd)
        first = runtime.sel_manager.identify(target, adapter)
        import hashlib
        import json
        registry = json.loads(_registry.read_text())
        registry['records'][0]['fingerprint'] = first
        registry['records'][0]['firmware_identity_scope'] = first['firmware_identity_capability']
        _registry.write_text(json.dumps(registry))
        monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(_registry.read_bytes()).hexdigest())
        assert qualified(first, 'clear') is not None
        target.auto_clear = target.auto_clock = True
        target.consent_fingerprint = __import__('ipmi_monitor.sel_management', fromlist=['digest']).digest(first)
        db.session.commit()
        adapter.raw = lambda netfn, cmd: prefix + bytes.fromhex('09080706') if (netfn,cmd) == (6,1) else original(netfn,cmd)
        second = runtime.sel_manager.identify(target, adapter)
        assert first != second
        assert target.auto_clear is False and target.auto_clock is False
        assert target.consent_fingerprint is None
        assert qualified(second, 'clear') is None


@pytest.mark.parametrize('tree,kind,role,prefix', [
    (tree, kind, role, prefix) for tree in ('src/ipmi_monitor/templates', 'templates')
    for role in ('admin', 'readonly') for kind, prefix in (('dashboard',''), ('server',''), ('server','/fleet/ipmi'))])
def test_full_rendered_sel_pages_keep_machine_names_text_and_local_health_urls(
        sel_site, login_as, tmp_path, tree, kind, role, prefix):
    from html import unescape
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread
    from pathlib import Path
    import json
    import os
    import re
    import shutil
    from jinja2 import FileSystemLoader
    from tests.test_dashboard_ai_reports import CHROMIUM

    client, app, db, models, _runtime, _commands = sel_site
    login_as(client, role)
    hostile = '<img src=x onerror=window.SEL_XSS=1>machine'
    with app.app_context():
        models['Server'].query.filter_by(bmc_ip=BMC).update({'server_name': hostile})
        models['ServerStatus'].query.filter_by(bmc_ip=BMC).update({'server_name': hostile})
        db.session.commit()
    headers = {'X-Forwarded-Prefix': prefix, 'X-Fleet-Authenticated': 'true',
               'X-Fleet-Auth-User': 'testadmin' if role == 'admin' else 'testreader',
               'X-Fleet-Auth-Role': role} if prefix else {}
    paths = ['/api/servers', f'/api/server/{BMC}/sel/health', f'/api/server/{BMC}/events']
    responses = {prefix + path: client.get(path, headers=headers).get_json() for path in paths}
    previous = app.jinja_loader
    try:
        app.jinja_loader = FileSystemLoader(str(Path.cwd()/tree))
        app.jinja_env.cache.clear()
        route = '/' if kind == 'dashboard' else f'/server/{BMC}'
        page = client.get(route, headers=headers).get_data(as_text=True)
    finally:
        app.jinja_loader = previous
        app.jinja_env.cache.clear()
    # Entire actual rendered page and startup run. Only unrelated HTTP responses
    # are empty fixture data; the tested API inputs are actual application output.
    probe = '''<script>setTimeout(() => {
        try {
            if (typeof populateDeviceSelectors === 'function') {
                serversData = FIXTURE_SERVERS; populateDeviceSelectors();
            }
            const panel=document.getElementById('selHealthPanel');
            const result={xss:window.SEL_XSS===1,unsafeOptions:document.querySelectorAll('option img,option svg,option [onerror]').length,
                optionNames:[...document.querySelectorAll('#summaryDevices option,#tasksDevices option,#rcaDevice option')].map(option=>option.textContent),
                panelText:panel?.textContent || '',buttons:panel?.querySelectorAll('button').length || 0};
            const node=document.createElement('pre');node.id='sel-full-page-result';node.textContent=JSON.stringify(result);document.body.append(node);
        } catch(error) { const node=document.createElement('pre');node.id='sel-full-page-result';node.textContent=JSON.stringify({fatal:String(error)});document.body.append(node); }
    },800);</script>'''.replace('FIXTURE_SERVERS', json.dumps(responses[prefix+'/api/servers']).replace('</', '<\\/'))
    page = page.replace('</body>', probe+'</body>')
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            content = page.encode() if self.path == prefix + route else json.dumps(responses.get(self.path, {})).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8' if self.path == prefix + route else 'application/json')
            self.end_headers()
            self.wfile.write(content)

        def log_message(self, *_):
            pass

    executable = os.environ.get('IPMI_AICSS_CHROMIUM') or shutil.which('chromium') or shutil.which('chromium-browser') or str(CHROMIUM)
    assert Path(executable).is_file(), 'Real Chromium required for complete-page SEL regression'
    server = HTTPServer(('127.0.0.1',0),Handler)
    thread = Thread(target=server.serve_forever,daemon=True)
    thread.start()
    try:
        result = models['command_runner']([executable,'--headless','--disable-gpu','--no-first-run',
            '--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-sync',
            '--disable-extensions','--no-proxy-server','--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1',
            '--password-store=basic','--use-mock-keychain',f'--user-data-dir={tmp_path/"profile"}',
            '--virtual-time-budget=1500','--dump-dom',f'http://127.0.0.1:{server.server_port}'+prefix+route],
            capture_output=True,text=True,timeout=30,check=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    match = re.search(r'<pre id="sel-full-page-result">(.*?)</pre>',result.stdout,re.S)
    assert match, result.stdout[-2000:]
    observed = json.loads(unescape(match.group(1)))
    observed['requests'] = requests
    assert not observed.get('fatal'), observed
    assert not observed['xss'] and observed['unsafeOptions'] == 0, observed
    if kind == 'dashboard':
        assert sum(hostile in name for name in observed['optionNames']) == 3, observed
    assert hostile in observed['panelText'], observed
    assert observed['buttons'] == (3 if role == 'admin' else 0), observed
    assert prefix + f'/api/server/{BMC}/sel/health' in requests, observed


def test_dispatch_intent_serializes_a_revocation_at_the_database_transition(qualified_site):
    from threading import Event, Thread
    from sqlalchemy import event
    (client, app, db, models, runtime, _commands), _state, _registry = qualified_site
    entered, finished = Event(), Event()
    observations, workers = [], []

    def revoke():
        with app.app_context():
            entered.set()
            models['Server'].query.filter_by(bmc_ip=BMC).update({'enabled': False})
            db.session.commit()
            operation = runtime.SELOperation.query.one()
            observations.append(operation.dispatched_at is not None)
            finished.set()

    def at_transition(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith('UPDATE sel_operation SET') and 'mutating' in parameters and not workers:
            worker = Thread(target=revoke)
            workers.append(worker)
            worker.start()
            assert entered.wait(timeout=3)
            assert not finished.wait(timeout=0.1), 'revocation must serialize after the accepted transition'

    with app.app_context():
        engine = db.engine
    event.listen(engine, 'before_cursor_execute', at_transition)
    try:
        headers, data = intent(client)
        response = client.post(f'/api/server/{BMC}/sel/enable', json=data, headers=headers)
        assert response.status_code in (200, 202), response.get_json()
    finally:
        event.remove(engine, 'before_cursor_execute', at_transition)
        for worker in workers:
            worker.join(timeout=5)
    assert workers and finished.is_set()
    assert observations == [True]  # Revocation was committed after dispatch was accepted.
