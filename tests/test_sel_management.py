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
    from ipmi_monitor.sel_management import IPMISELAdapter
    def local_transport(adapter, reservation=None):
        if adapter._shell is None:
            adapter._shell = SimpleNamespace(raw=adapter._run_raw, close=lambda: None)
    monkeypatch.setattr(IPMISELAdapter, 'open_session', local_transport)
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
                assert runtime.SELAudit.query.filter_by(action='archive_committed', operation_id=archive.operation_id).count() == 1
                assert runtime.SELOperation.query.filter_by(id=archive.operation_id).one().state == 'mutating'
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
        assert kwargs['verify'] == str(tmp_path / 'trusted-ca.pem')
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
    from ipmi_monitor import sel_qualifications
    # Only the external tool boundary is substituted in unit tests. Real root
    # Linux/image checks separately exercise the actual binary/version/hash.
    tool_bytes = b'unit-test-only-ipmitool-boundary'
    monkeypatch.setattr(sel_qualifications, 'tool_identity', lambda: {
        'tool_sha256': hashlib.sha256(tool_bytes).hexdigest(), 'tool_version': 'ipmitool version 1.8.19'})
    record = {'fingerprint': fingerprint, 'test_only': False, 'reviewer': 'synthetic-test-reviewer',
        'runtime_identity': sel_qualifications.runtime_identity(),
        'approved_at': (utcnow() - timedelta(hours=1)).isoformat() + 'Z',
        'expires_at': (utcnow() + timedelta(hours=1)).isoformat() + 'Z',
        'firmware_identity_scope': fingerprint.get('firmware_identity_capability'),
        'actions': {},
        'clock_semantics': 'local_epoch_with_utc_offset',
        'ntp_probe': {'path': '/redfish/v1/Managers/BMC/NetworkProtocol', 'ca_file': 'trusted-ca.pem'},
        'supporting_evidence': {}}
    record['record_id'] = '54f962a7-f5e0-4b34-b776-bae08729a541'
    record['evidence_artifacts'] = []
    # Producer-faithful evidence links in this temporary subprocess-only test
    # installation. These local files are never production hardware evidence.
    # Each action resolves both its digest and its exact canary operation ID.
    for index, (action, names) in enumerate(checks.items(), 1):
        operation_id = f'9da61ed4-e055-4672-bc57-{index:012d}'
        evidence = tmp_path / f'{action}-canary.json'
        evidence.write_text(json.dumps({
            'record_id': record['record_id'], 'fingerprint': fingerprint,
            'action': action, 'checks': dict.fromkeys(names, True),
            'canary_operations': [{'operation_id': operation_id, 'action': action,
                'observed_at': utcnow().isoformat() + 'Z', 'outcome': 'complete',
                'raw_receipts': [{'command': [0x06, 0x01],
                    'response': fingerprint['device_id_reply']}]}],
        }, sort_keys=True))
        evidence_sha = hashlib.sha256(evidence.read_bytes()).hexdigest()
        record['evidence_artifacts'].append({'path': evidence.name, 'sha256': evidence_sha})
        record['actions'][action] = {'checks': dict.fromkeys(names, True),
            'canary_operation_ids': [operation_id], 'sha256': [evidence_sha]}
    import certifi
    import re
    from pathlib import Path
    public_ca = re.search(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
                         Path(certifi.where()).read_text(), re.S).group(0).encode() + b'\n'
    (tmp_path / 'trusted-ca.pem').write_bytes(public_ca)
    ca_digest = hashlib.sha256(public_ca).hexdigest()
    record['ntp_probe']['ca_sha256'] = ca_digest
    record['evidence_artifacts'].append({'path': 'trusted-ca.pem', 'sha256': ca_digest, 'kind': 'ca_certificate'})
    for purpose in ('vendor', 'clock_ownership'):
        path = tmp_path / (purpose + '.json')
        path.write_text(json.dumps({'schema': 'sel-supporting-evidence/1', 'record_id': record['record_id'],
            'fingerprint': fingerprint, 'action': 'clock', 'purpose': purpose,
            'evidence': {'source': 'local synthetic subprocess fixture; never hardware qualification'}}))
        support_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        record['evidence_artifacts'].append({'path': path.name, 'sha256': support_digest, 'kind': 'supporting_json'})
        record['supporting_evidence'][purpose] = [support_digest]
    registry = tmp_path / 'qualifications.json'
    registry.write_text(json.dumps({'schema': 'sel-device-qualification/1', 'records': [record]}))
    monkeypatch.setenv('SEL_QUALIFICATIONS_FILE', str(registry))
    monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
    with app.app_context():
        runtime.sel_manager.observe(BMC)
    commands.clear()
    return sel_site, state, registry



@pytest.fixture()
def qualification_transport(qualified_site, monkeypatch):
    """Rewrite only temporary synthetic evidence, preserving real loader checks."""
    import hashlib
    import json
    import uuid
    from copy import deepcopy
    _site, _state, registry = qualified_site

    def rewrite(transport, append=False):
        value = json.loads(registry.read_bytes())
        record = deepcopy(value['records'][0])
        record['fingerprint']['transport'] = transport
        if append:
            record['record_id'] = str(uuid.uuid4())
        remap = {}
        for artifact in record['evidence_artifacts']:
            path = registry.parent / artifact['path']
            content = path.read_bytes()
            if artifact.get('kind') != 'ca_certificate':
                body = json.loads(content)
                body.update(record_id=record['record_id'], fingerprint=record['fingerprint'])
                content = json.dumps(body, sort_keys=True).encode()
            if append:
                artifact['path'] = 'copy-' + artifact['path']
                path = registry.parent / artifact['path']
            path.write_bytes(content)
            remap[artifact['sha256']] = hashlib.sha256(content).hexdigest()
            artifact['sha256'] = remap[artifact['sha256']]
        for evidence in record['actions'].values():
            evidence['sha256'] = [remap[digest] for digest in evidence['sha256']]
        for purpose, digests in record['supporting_evidence'].items():
            record['supporting_evidence'][purpose] = [remap[digest] for digest in digests]
        record['ntp_probe']['ca_sha256'] = remap[record['ntp_probe']['ca_sha256']]
        if append:
            record['ntp_probe']['ca_file'] = 'copy-' + record['ntp_probe']['ca_file']
            value['records'].append(record)
        else:
            value['records'][0] = record
        registry.write_text(json.dumps(value))
        monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
        return record
    return rewrite


@pytest.mark.parametrize('cipher,qualification', [(3, 'matching'), (17, 'matching'),
    (3, 'different_transport'), (3, 'absent'), (17, 'absent')])
def test_guarded_action_uses_bound_transport_and_requires_action_evidence(
        qualified_site, qualification_transport, monkeypatch, tmp_path, cipher, qualification):
    import json
    (client, app, _db, _models, runtime, commands), state, _registry = qualified_site
    record_cipher = 17 if qualification == 'different_transport' else cipher
    record = qualification_transport(f'lanplus-cipher{record_cipher}-admin')
    if qualification == 'absent':
        monkeypatch.delenv('SEL_QUALIFICATIONS_FILE')
        monkeypatch.delenv('SEL_QUALIFICATIONS_SHA256')
    if cipher == 3:
        with app.app_context():
            target = runtime.sel_manager.target(BMC)
            profile = {'server_id': target.server_id, 'binding': target.binding, 'bmc_ip': BMC,
                       'cipher': cipher, 'device_id_reply': record['fingerprint']['device_id_reply'],
                       'guid': record['fingerprint']['guid']}
        path = tmp_path / 'read-profile.json'
        path.write_text(json.dumps({'schema_version': 'sel-read-profiles/1', 'profiles': [profile]}))
        path.chmod(0o600)
        monkeypatch.setenv('SEL_READ_PROFILES_FILE', str(path))
    else:
        monkeypatch.delenv('SEL_READ_PROFILES_FILE', raising=False)
    with app.app_context():
        runtime.sel_manager.observe(BMC)
    commands.clear()
    headers, data = intent(client)
    response = client.post(f'/api/server/{BMC}/clear_sel', json=data, headers=headers)
    raw = [argv for argv, _kwargs in commands if 'raw' in argv]
    assert raw and all(argv[argv.index('-C') + 1] == str(cipher) for argv in raw)
    assert [int(v, 16) for v in raw[0][raw[0].index('raw') + 1:]] == [6, 1]
    allowed = qualification == 'matching' or (qualification == 'different_transport' and cipher == 17)
    assert state['cleared'] is allowed, response.get_json()
    if allowed:
        assert response.status_code == 200 and response.get_json()['state'] == 'complete'
    else:
        assert response.status_code == 409, response.get_json()
        # Only identity reads are allowed; a read profile grants no mutation.
        assert all([int(v, 16) for v in argv[argv.index('raw') + 1:]] in ([6, 1], [6, 0x37]) for argv in raw)


def intent(client, bmc_ip=BMC):
    """Consume the real API producer for token and current identity/policy versions."""
    response = client.get(f'/api/server/{bmc_ip}/sel/health')
    assert response.status_code == 200
    value = response.get_json()
    return ({'Origin': 'http://localhost', 'X-CSRF-Token': value['csrf_token']},
            {'target_id': value['target_id'], 'identity_revision': value['identity_revision'],
             'policy_revision': value['policies']['revision']})


@pytest.fixture()
def ltx_reads():
    """Actual read-only producer replies; no credentials or routable target argv."""
    import json
    from pathlib import Path
    return json.loads((Path(__file__).parent / 'fixtures/ltx_sel_reads_20261104.json').read_text())['targets']


def replay_ltx(monkeypatch, runtime, receipts, failure=None):
    """Replace only subprocess IO, preserving real raw adapter/collector/API."""
    import subprocess
    calls = []
    replies = {tuple(int(v, 16) for v in row['raw']): row for row in receipts}

    def boundary(argv, **kwargs):
        values = tuple(int(v, 16) for v in argv[argv.index('raw') + 1:])
        calls.append(values)
        assert '-P' not in argv and argv[argv.index('-C') + 1] == '17' and '-E' in argv
        row = failure if failure and values == failure['command'] else replies[values]
        if row.get('timeout_expired'):
            raise subprocess.TimeoutExpired(argv, kwargs['timeout'])
        return SimpleNamespace(returncode=row['returncode'], stdout=row['stdout'], stderr=row['stderr'])

    monkeypatch.setattr(runtime.subprocess, 'run', boundary)
    return calls


@pytest.mark.parametrize('device', ['full_device', 'partial_device'])
def test_ltx_unqualified_native_epoch_never_asserts_five_hour_clock_fault(sel_site, monkeypatch, ltx_reads, device):
    import ipmi_monitor.sel_management as sel
    client, app, _db, _models, runtime, _commands = sel_site
    rows = ltx_reads[device]
    native = next(int.from_bytes(bytes.fromhex(row['stdout']), 'little') for row in rows if row['raw'] == ['0xa', '0x48'])
    monkeypatch.delenv('SEL_QUALIFICATIONS_FILE', raising=False)
    monkeypatch.delenv('SEL_QUALIFICATIONS_SHA256', raising=False)
    monkeypatch.setattr(sel, 'trusted_reference', lambda _: {'utc': native, 'source': 'test-fresh-UTC'})
    replay_ltx(monkeypatch, runtime, rows)
    with app.app_context():
        runtime.sel_manager.observe(BMC)
    health = client.get(f'/api/server/{BMC}/sel/health').get_json()['health']
    assert health['clock']['native_seconds'] == native
    assert health['clock']['offset_minutes'] == -300
    assert health.get('drift_seconds') is None, health
    assert 'clock_incorrect' not in health['flags'], health
    assert 'clock_unknown' in health['flags'], health


@pytest.mark.parametrize('failed_command', [(6, 0x37), (10, 0x5c)])
def test_ltx_optional_identity_or_offset_failure_preserves_independent_reads(sel_site, monkeypatch, ltx_reads, failed_command):
    client, app, _db, _models, runtime, _commands = sel_site
    failure = {'command': failed_command, 'returncode': 1, 'stdout': '',
               'stderr': 'Unable to send RAW command: rsp=0xc1: Invalid command\n'}
    replay_ltx(monkeypatch, runtime, ltx_reads['full_device'], failure)
    with app.app_context():
        runtime.sel_manager.observe(BMC)
    body = client.get(f'/api/server/{BMC}/sel/health').get_json()
    health = body['health']
    assert health.get('info', {}).get('entries') == 3639, health
    assert health['full'] is True and health['logging_enabled'] is True, health
    assert health['capacity_observed_at'] and health['logging_observed_at']
    assert (health.get('clock') or {}).get('native_seconds') == 1793793196, health
    assert not body['capabilities']['clear']['available']


@pytest.mark.parametrize('fixture,code', [('cipher_rejected', 'unsupported_cipher'),
    ('role_rejected', 'role_or_auth_rejected'), ('session_rejected', 'rmcp_session_failed'), ('timeout', 'device_timeout')])
def test_ltx_transport_failures_have_distinct_sanitized_reasons(sel_site, monkeypatch, ltx_reads, fixture, code):
    from ipmi_monitor.sel_management import IPMISELAdapter, SELUnavailable
    _client, _app, _db, _models, runtime, _commands = sel_site
    calls = replay_ltx(monkeypatch, runtime, ltx_reads[fixture])
    adapter = IPMISELAdapter(runtime, BMC, ('fixture-user', 'synthetic-secret'))
    with pytest.raises(SELUnavailable) as caught:
        adapter.fingerprint()
    assert caught.value.code == code
    assert calls == [(6, 1)]
    assert 'synthetic-secret' not in str(caught.value)


@pytest.mark.parametrize('policy', ['automatic_clear', 'automatic_clock'])
def test_unqualified_policy_opt_in_is_denied_but_opt_out_remains_available(qualified_site, monkeypatch, policy):
    (client, _app, _db, _models, _runtime, commands), _state, _registry = qualified_site
    headers, data = intent(client)
    assert client.post(f'/api/server/{BMC}/sel/policy', json={**data, policy: True}, headers=headers).status_code == 200
    monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', '0' * 64)
    headers, data = intent(client)
    disabled = client.post(f'/api/server/{BMC}/sel/policy', json={**data, policy: False}, headers=headers)
    assert disabled.status_code == 200
    assert disabled.get_json()['policies'][policy] is False
    headers, data = intent(client)
    refused = client.post(f'/api/server/{BMC}/sel/policy', json={**data, policy: True}, headers=headers)
    assert refused.status_code == 409, refused.get_json()
    assert commands == []


def test_changed_qualification_bundle_revokes_queued_consent_before_dispatch(qualified_site, monkeypatch):
    import hashlib
    import json
    from ipmi_monitor.sel_management import SELUnavailable
    (client, app, _db, _models, runtime, _commands), _state, registry = qualified_site
    headers, data = intent(client)
    assert client.post(f'/api/server/{BMC}/sel/policy', json={**data, 'automatic_clear': True}, headers=headers).status_code == 200
    with app.app_context():
        target = runtime.SELTarget.query.one()
        operation = runtime.sel_manager.claim(target, 'clear', 'automatic-policy', True)
        fingerprint = json.loads(target.fingerprint)
        changed = json.loads(registry.read_bytes())
        changed['records'][0]['reviewer'] = 'second-independent-synthetic-reviewer'
        registry.write_text(json.dumps(changed))
        monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
        with pytest.raises(SELUnavailable, match='qualification|revoked'):
            runtime.sel_manager.dispatch_intent(target, operation, runtime.sel_manager.adapter(target), fingerprint, {})


def test_qualification_selected_before_claim_cannot_survive_a_changed_valid_bundle(qualified_site, monkeypatch):
    import hashlib
    import json
    (client, _app, _db, _models, runtime, commands), _state, registry = qualified_site
    claim = runtime.sel_manager.claim

    def changed_claim(*args, **kwargs):
        value = json.loads(registry.read_bytes())
        value['records'][0]['clock_semantics'] = 'utc_epoch'
        registry.write_text(json.dumps(value))
        monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
        return claim(*args, **kwargs)

    monkeypatch.setattr(runtime.sel_manager, 'claim', changed_claim)
    headers, data = intent(client)
    response = client.post(f'/api/server/{BMC}/sel/clock', json=data, headers=headers)
    assert response.status_code == 409, response.get_json()
    assert not any(tuple(int(v, 16) for v in argv[argv.index('raw')+1:argv.index('raw')+3])
                   in {(10, 0x49), (10, 0x5d)} for argv, _ in commands if 'raw' in argv)


@pytest.mark.parametrize('action', ['clear', 'clock'])
@pytest.mark.parametrize('edit', ['threshold', 'other_off'])
def test_unrelated_policy_edit_never_renews_changed_action_consent(qualified_site, monkeypatch, action, edit):
    import hashlib
    import json
    (client, app, _db, _models, runtime, _commands), _state, registry = qualified_site
    headers, data = intent(client)
    assert client.post(f'/api/server/{BMC}/sel/policy', json={**data, 'automatic_clear': True, 'automatic_clock': True}, headers=headers).status_code == 200
    value = json.loads(registry.read_bytes())
    value['records'][0]['reviewer'] = 'new-synthetic-reviewer'
    registry.write_text(json.dumps(value))
    monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
    headers, data = intent(client)
    other = 'clock' if action == 'clear' else 'clear'
    update = {'near_full_percent': 91} if edit == 'threshold' else {'automatic_' + other: False}
    response = client.post(f'/api/server/{BMC}/sel/policy', json={**data, **update}, headers=headers)
    assert response.status_code == 200
    with app.app_context():
        target = runtime.SELTarget.query.one()
        assert getattr(target, 'auto_' + action) is False
        assert not json.loads(target.consent_qualification).get(action)


@pytest.mark.parametrize('action', ['clear', 'clock'])
@pytest.mark.parametrize('unavailable', ['changed', 'invalid_pin'])
def test_observed_qualification_revocation_survives_rollback_and_restore(qualified_site, monkeypatch, action, unavailable):
    import hashlib
    import json
    from ipmi_monitor.sel_management import SELUnavailable
    (client, app, db, _models, runtime, commands), _state, registry = qualified_site
    headers, data = intent(client)
    assert client.post(f'/api/server/{BMC}/sel/policy', json={**data, 'automatic_' + action: True}, headers=headers).status_code == 200
    original = registry.read_bytes()
    if unavailable == 'changed':
        value = json.loads(original)
        value['records'][0]['reviewer'] = 'new-synthetic-reviewer'
        registry.write_text(json.dumps(value))
        pin = hashlib.sha256(registry.read_bytes()).hexdigest()
    else:
        pin = '0' * 64
    monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', pin)
    with app.app_context():
        with pytest.raises(SELUnavailable):
            runtime.sel_manager.execute(runtime.SELTarget.query.one(), action, 'automatic-policy', True)
        db.session.rollback()  # This must not roll back the safety revocation.
    registry.write_bytes(original)
    monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(original).hexdigest())
    with app.app_context():
        target = runtime.SELTarget.query.one()
        assert getattr(target, 'auto_' + action) is False
        with pytest.raises(SELUnavailable):
            runtime.sel_manager.claim(target, action, 'automatic-policy', True)
        db.session.rollback()
        assert runtime.SELOperation.query.count() == 0
    headers, data = intent(client)
    assert client.post(f'/api/server/{BMC}/sel/policy', json={**data, 'automatic_' + action: True}, headers=headers).status_code == 200
    with app.app_context():
        operation = runtime.sel_manager.claim(runtime.SELTarget.query.one(), action, 'automatic-policy', True)
        assert operation.state == 'queued'
    assert not any('raw' in argv and tuple(int(v, 16) for v in argv[argv.index('raw')+1:argv.index('raw')+3])
                   in {(10, 0x47), (10, 0x49), (10, 0x5d)} for argv, _ in commands)


@pytest.mark.parametrize('action', ['clear', 'clock'])
def test_other_action_off_preserves_unchanged_action_consent(qualified_site, action):
    import json
    (client, app, _db, _models, runtime, _commands), _state, _registry = qualified_site
    headers, data = intent(client)
    assert client.post(f'/api/server/{BMC}/sel/policy', json={**data, 'automatic_clear': True, 'automatic_clock': True}, headers=headers).status_code == 200
    with app.app_context():
        original = json.loads(runtime.SELTarget.query.one().consent_qualification)[action]
    headers, data = intent(client)
    other = 'clock' if action == 'clear' else 'clear'
    assert client.post(f'/api/server/{BMC}/sel/policy', json={**data, 'automatic_' + other: False}, headers=headers).status_code == 200
    with app.app_context():
        target = runtime.SELTarget.query.one()
        assert getattr(target, 'auto_' + action) is True
        assert json.loads(target.consent_qualification)[action] == original
        assert not json.loads(target.consent_qualification).get(other)


@pytest.mark.parametrize('phase,column', [('claim', 'policy_revision'), ('claim', 'revision'),
    ('claim', 'snapshot_epoch'), ('expired_io', 'policy_revision'), ('expired_io', 'snapshot_epoch'), ('bulk', 'policy_revision')])
def test_original_request_authority_survives_io_and_claim_refresh(qualified_site, monkeypatch, phase, column):
    from sqlalchemy import text
    from ipmi_monitor.sel_management import IPMISELAdapter
    (client, app, db, _models, runtime, commands), state, _registry = qualified_site
    changed = []
    with app.app_context():
        target_id = runtime.SELTarget.query.one().id
    def revoke():
        if not changed:
            with db.engine.begin() as connection:
                connection.execute(text(f'UPDATE sel_target SET {column}={column}+1 WHERE id=:id'), {'id': target_id})
            changed.append(True)
    if phase == 'expired_io':
        original = IPMISELAdapter.fingerprint
        def boundary(adapter):
            revoke()
            db.session.expire_all()
            return original(adapter)
        monkeypatch.setattr(IPMISELAdapter, 'fingerprint', boundary)
    else:
        original = runtime.sel_manager.claim
        def boundary(*args, **kwargs):
            revoke()
            db.session.expire_all()
            return original(*args, **kwargs)
        monkeypatch.setattr(runtime.sel_manager, 'claim', boundary)
    headers, data = intent(client)
    response = client.post('/api/clear_all_sel' if phase == 'bulk' else f'/api/server/{BMC}/clear_sel',
                           json={'targets': [data]} if phase == 'bulk' else data, headers=headers)
    if phase == 'bulk':
        assert response.status_code == 200
        assert response.get_json()['operations'][0]['state'] == 'failed'
    else:
        assert response.status_code == 409, response.get_json()
    with app.app_context():
        assert runtime.SELOperation.query.count() == 0
    assert state['cleared'] is False and changed


def test_final_dispatch_observed_missing_qualification_durably_disarms(qualified_site, monkeypatch):
    (client, app, _db, _models, runtime, _commands), state, _registry = qualified_site
    headers, data = intent(client)
    assert client.post(f'/api/server/{BMC}/sel/policy', json={**data, 'automatic_clear': True}, headers=headers).status_code == 200
    dispatch = runtime.sel_manager.dispatch_intent
    def invalidate(*args, **kwargs):
        monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', '0' * 64)
        return dispatch(*args, **kwargs)
    monkeypatch.setattr(runtime.sel_manager, 'dispatch_intent', invalidate)
    with app.app_context():
        operation = runtime.sel_manager.execute(runtime.SELTarget.query.one(), 'clear', 'automatic-policy', True)
        assert operation.state == 'failed'
        assert runtime.SELTarget.query.one().auto_clear is False
    assert state['cleared'] is False


@pytest.mark.parametrize('count,latency', [(885, 0), (3639, 0), (3639, 0.19)])
def test_complete_chain_preserves_every_next_id_or_holds_within_existing_deadline(sel_site, monkeypatch, ltx_reads, count, latency):
    """Actual capacity/latency, synthetic raw entries: not hardware/session proof."""
    import ipmi_monitor.sel_management as sel
    _client, _app, _db, _models, runtime, _commands = sel_site
    clock, reads, tokens = [0.0], [], []
    monkeypatch.setattr(sel.time, 'monotonic', lambda: clock[0])
    rows = ltx_reads['partial_device' if count == 885 else 'full_device']
    info = next(row['stdout'] for row in rows if row['raw'] == ['0xa', '0x40'])
    allocation = next(row['stdout'] for row in rows if row['raw'] == ['0xa', '0x41'])

    def boundary(argv, **kwargs):
        values = [int(v, 16) for v in argv[argv.index('raw') + 1:]]
        clock[0] += latency
        if values[:2] == [10, 0x40]:
            return SimpleNamespace(returncode=0, stdout=info, stderr='')
        if values[:2] == [10, 0x41]:
            return SimpleNamespace(returncode=0, stdout=allocation, stderr='')
        assert values[:2] == [10, 0x43], 'snapshot must never dispatch clear'
        tokens.append(values[2:4])
        requested = values[4] | values[5] << 8
        actual = requested or 1
        reads.append(actual)
        next_id = actual + 1 if actual < count else 65535
        raw = actual.to_bytes(2, 'little') + bytes(14)
        return SimpleNamespace(returncode=0, stdout=(next_id.to_bytes(2, 'little') + raw).hex(' '), stderr='')

    monkeypatch.setattr(runtime.subprocess, 'run', boundary)
    adapter = sel.IPMISELAdapter(runtime, BMC, ('fixture-user', 'synthetic-secret'))
    if latency:
        with pytest.raises(sel.SELUnavailable, match='device_deadline_exceeded'):
            adapter.snapshot(bytes.fromhex('3412'))
        assert len(reads) < count and clock[0] <= 60 + latency
    else:
        snapshot = adapter.snapshot(bytes.fromhex('3412'))
        assert snapshot['complete'] and len(snapshot['records']) == count
        assert [row['record_id'] for row in snapshot['records']] == list(range(1, count + 1))
    assert all(token == [0x34, 0x12] for token in tokens)


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


@pytest.mark.parametrize('actions', [('clear', 'clock'), ('collection', 'collection'),
                                     ('collection', 'clear'), ('collection', 'clock')])
def test_ownership_serializes_independent_workers_and_clock_clear(qualified_site, actions):
    from threading import Barrier, Thread
    from ipmi_monitor.sel_management import SELUnavailable
    (_client, app, _db, _models, runtime, commands), _state, _registry = qualified_site
    gate, results = Barrier(2), []
    commands.clear()

    def worker(action):
        with app.app_context():
            target = runtime.sel_manager.target(BMC)
            gate.wait(timeout=5)
            try:
                if action == 'collection':
                    ticket = runtime.sel_manager.begin_collection(BMC)
                    results.append(('collection', ticket['attempt_id']))
                else:
                    operation = runtime.sel_manager.claim(target, action, 'independent-worker')
                    results.append(operation.state)
            except SELUnavailable as exc:
                results.append(exc.code)
            except Exception as exc:
                results.append('unexpected:' + type(exc).__name__)

    workers = [Thread(target=worker, args=(action,)) for action in actions]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)
    assert all(not worker.is_alive() for worker in workers)
    if actions == ('clear', 'clock'):
        assert sorted(results) == ['operation_busy_or_cooldown', 'queued']
        with app.app_context():
            assert runtime.SELOperation.query.count() == 1
    else:
        winners = [value for value in results if isinstance(value, tuple) or value == 'queued']
        losers = [value for value in results if value in ('operation_busy_or_cooldown', 'collection_busy_or_maintenance')]
        assert len(winners) == len(losers) == 1, results
    assert not any('raw' in argv or 'shell' in argv for argv, _kwargs in commands), 'claims and losing workers perform no BMC IO'


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


@pytest.mark.parametrize('semantics', ['local_epoch_with_utc_offset', 'utc_epoch'])
def test_unspecified_utc_offset_produces_no_clock_write(qualified_site, monkeypatch, semantics):
    import hashlib
    import json
    registry = qualified_site[2]
    value = json.loads(registry.read_bytes())
    value['records'][0]['clock_semantics'] = semantics
    registry.write_text(json.dumps(value))
    monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
    (client, _app, _db, _models, _runtime, commands), state, _registry = qualified_site
    state['offset'] = 2047  # IPMI 0x07ff, not signed -2048.
    headers, data = intent(client)
    response = client.post(f'/api/server/{BMC}/sel/clock', json=data, headers=headers)
    assert response.status_code == 202
    assert response.get_json()['outcome'] == 'clock_mapping_unknown'
    assert not any([int(v, 16) for v in argv[argv.index('raw') + 1:]][:2] in ([10, 0x49], [10, 0x5d])
                   for argv, _ in commands if 'raw' in argv)


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
        record = registry['records'][0]
        for artifact in record['evidence_artifacts']:
            if artifact.get('kind') == 'ca_certificate':
                continue
            evidence_path = _registry.parent / artifact['path']
            evidence = json.loads(evidence_path.read_bytes())
            evidence['fingerprint'] = first
            evidence_path.write_text(json.dumps(evidence, sort_keys=True))
            replacement_digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
            for action in record['actions'].values():
                action['sha256'] = [replacement_digest if old == artifact['sha256'] else old for old in action['sha256']]
            for purpose, digests in record['supporting_evidence'].items():
                record['supporting_evidence'][purpose] = [replacement_digest if old == artifact['sha256'] else old for old in digests]
            artifact['sha256'] = replacement_digest
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
        sel_site, login_as, tmp_path, tree, kind, role, prefix, expected_manual=False):
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
                panelText:panel?.textContent || '',buttons:panel?.querySelectorAll('button').length || 0,
                autoInputs:[...panel.querySelectorAll('input[type=checkbox]')].map(input=>({disabled:input.disabled,checked:input.checked}))};
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
    if expected_manual:
        assert observed['autoInputs'] == [{'disabled': True, 'checked': False}, {'disabled': True, 'checked': False}], observed
        assert 'Automatic maintenance awaits a verified manual operation.' in observed['panelText'], observed


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
