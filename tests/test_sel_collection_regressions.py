# TRACEWEAVER: file-role=charlotte-collection-regression; req=REQ-SEL-001; trace=TRACE-SEL-001; ver=VER-CHARLOTTESEL-001
# TRACEWEAVER: verifies=VER-CHARLOTTESEL-001; req=REQ-SEL-001; trace=TRACE-SEL-001
# TRACEWEAVER: file-role=charlotte-collection-regression; req=REQ-SEL-001,REQ-SEL-003,REQ-SEL-004,REQ-SEL-005; trace=TRACE-SEL-001,TRACE-SEL-003,TRACE-SEL-004,TRACE-SEL-005; ver=VER-CHARLOTTESEL-001,VER-CHARLOTTESEL-003,VER-CHARLOTTESEL-004,VER-CHARLOTTESEL-005
"""Captured Charlotte failures through existing reader and persistence boundaries.

The small route graph reconstructs the two retained diagnostic reproductions;
it is not a verbatim HTTP capture. Native fixture bytes are exact archive bytes.
No hardware, credential store, or network is accessed.
"""
from copy import deepcopy
from datetime import datetime
import importlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


BMC = '192.0.2.40'
LOGS = '/redfish/v1/Managers/Self/LogServices'
SEL = LOGS + '/SEL'
ENTRIES = SEL + '/Entries'


def entry(record_id):
    return {'Id': record_id, 'Message': 'Hardware fault', 'Severity': 'Warning',
            'EntryType': 'SEL', 'Created': '2026-11-11T01:00:00Z'}


@pytest.fixture()
def redfish_reader(monkeypatch):
    runtime = importlib.import_module('ipmi_monitor.app')

    def make(page, services=None, extra=None):
        routes = {
            '/redfish/v1/': {'Managers': {'@odata.id': '/redfish/v1/Managers'}},
            '/redfish/v1/Managers': {'Members': [{'@odata.id': '/redfish/v1/Managers/Self'}]},
            '/redfish/v1/Managers/Self': {'LogServices': {'@odata.id': LOGS}},
            LOGS: {'Members': [{'@odata.id': path} for path in (services or [SEL])]},
            SEL: {'Id': 'SEL', 'Name': 'System Event Log', 'LogEntryType': 'SEL',
                  'Entries': {'@odata.id': ENTRIES}},
            ENTRIES: page,
            **(extra or {}),
        }
        calls = []
        client = runtime.RedfishClient(BMC, 'fixture-only', 'synthetic-secret')

        def get(uri, timeout=None):
            calls.append(uri)
            assert not uri.startswith(('https://foreign.invalid', '//foreign.invalid')), 'foreign next link must never be fetched'
            assert len(calls) <= 20, 'cyclic pagination must terminate within a finite bound'
            return deepcopy(routes.get(uri))

        monkeypatch.setattr(client, '_get', get)
        monkeypatch.setattr(client.session, 'get', lambda *a, **kw: pytest.fail('network forbidden'))
        return client, calls

    return make


@pytest.mark.parametrize('unrelated', ['AuditLog', 'EventLog'])
def test_self_manager_does_not_make_audit_or_event_log_a_hardware_sel(redfish_reader, unrelated):
    """Actual deployed reproduction returned old-login-audit, never hardware-fault."""
    wrong = LOGS + '/' + unrelated
    client, _calls = redfish_reader(
        {'Members': [entry('hardware-fault')]}, services=[wrong, SEL],
        extra={wrong: {'Id': unrelated, 'Name': 'Manager audit events',
                       'LogEntryType': 'Event', 'Entries': {'@odata.id': wrong + '/Entries'}},
               wrong + '/Entries': {'Members': [entry('old-login-audit')]}},
    )
    assert [row['sel_id'] for row in client.get_sel_entries()] == ['hardware-fault']


def test_reads_newest_second_page_without_duplicate_records(redfish_reader):
    client, calls = redfish_reader(
        {'Members': [entry('old-1'), entry('old-2')], 'Members@odata.count': 3,
         'Members@odata.nextLink': ENTRIES + '?page=2'},
        extra={ENTRIES + '?page=2': {'Members': [entry('old-2'), entry('new-3')]}},
    )
    assert [row['sel_id'] for row in client.get_sel_entries()] == ['old-1', 'old-2', 'new-3']
    assert ENTRIES + '?page=2' in calls


@pytest.mark.parametrize('failure', ['foreign', 'cycle', 'partial', 'empty-page'])
def test_incomplete_pagination_cannot_return_first_page_as_complete(redfish_reader, failure):
    """Reject incomplete reads rather than promote old first-page events as success."""
    link = {'foreign': 'https://foreign.invalid/Entries', 'cycle': ENTRIES,
            'partial': ENTRIES + '?page=2', 'empty-page': ENTRIES + '?page=2'}[failure]
    extra = {link: {'Members': []}} if failure == 'empty-page' else {}
    client, _calls = redfish_reader(
        {'Members': [entry('old-1')], 'Members@odata.count': 2,
         'Members@odata.nextLink': link}, extra=extra,
    )
    assert client.get_sel_entries() == [], 'an incomplete hardware log is not a successful complete result'


def test_confirmed_empty_hardware_sel_is_a_valid_empty_read(redfish_reader):
    client, _calls = redfish_reader({'Members': [], 'Members@odata.count': 0})
    assert client.get_sel_entries() == []


def test_real_get_disables_redirects_and_rejects_redirect_body(monkeypatch):
    runtime = importlib.import_module('ipmi_monitor.app')
    client = runtime.RedfishClient(BMC, 'fixture', 'synthetic-secret')
    requests = []
    class RedirectResponse:
        status_code = 302
        headers = {'Location': 'https://foreign.invalid/credential-sink'}
        def raise_for_status(self): pass  # requests does not raise for302.
        def json(self): return {'Members': [entry('redirect-body-not-hardware-proof')]}
    def get(url, **kwargs):
        requests.append((url, kwargs))
        return RedirectResponse()
    monkeypatch.setattr(client.session, 'get', get)
    body = client._get(ENTRIES)
    assert {'body_rejected': body is None, 'one_request': len(requests) == 1,
            'redirects_disabled': requests[0][1].get('allow_redirects') is False} == {
                'body_rejected': True, 'one_request': True, 'redirects_disabled': True}


@pytest.fixture()
def native_site(app_fixture, monkeypatch):
    _client, app, db, models = app_fixture
    runtime = importlib.import_module('ipmi_monitor.app')
    monkeypatch.setattr(runtime, 'update_server_status', lambda *args, **kw: None)
    monkeypatch.setattr(runtime, '_send_sel_event_alert', lambda *args, **kw: None)
    monkeypatch.setattr(runtime.requests.sessions.Session, 'request', lambda *args, **kw: pytest.fail('network forbidden'))
    with app.app_context():
        db.session.add(models['Server'](bmc_ip=BMC, server_name='fixture-host', enabled=True,
                                       status='active', protocol='ipmi'))
        db.session.commit()
    return app, db, models, runtime


def test_same_native_bytes_deduplicate_after_decoder_wording_changes(native_site):
    app, _db, models, runtime = native_site
    fixture = json.loads((Path(__file__).parent / 'fixtures/charlotte_sel_native_prefix.json').read_text())
    raw = fixture['records'][0]
    with app.app_context():
        for description in ['OEM sensor unknown', 'Power supply AC lost (decoded)']:
            runtime.save_events_to_db(BMC, 'fixture-host', [runtime.IPMIEvent(
                bmc_ip=BMC, server_name='fixture-host', sel_id=str(raw['record_id']),
                event_date=datetime(1970, 1, 1), sensor_type='OEM',
                event_description=description, raw_entry=raw['raw'], severity='warning')])
        rows = models['IPMIEvent'].query.filter_by(bmc_ip=BMC).all()
        assert len(rows) == 1, 'decoder text must not change identity of identical native bytes'
        assert rows[0].raw_entry == raw['raw']


def test_clock_rewind_alone_does_not_invent_a_new_native_generation(native_site, monkeypatch):
    app, _db, _models, runtime = native_site
    state = {'last_add': '02000000'}
    adapter = SimpleNamespace(
        fingerprint=lambda: {'device': 'unchanged-fixture'},
        info=lambda: {'entries': 7, 'free_bytes': 128, 'percent_used': 50,
                      'last_add': state['last_add'], 'last_erase': '00000000'},
        logging=lambda: 8,
        clock=lambda: {'native_seconds': 2, 'offset_minutes': None, 'quality': 'unknown'},
        close=lambda: None,
    )
    monkeypatch.setattr(runtime.sel_manager, 'adapter', lambda target: adapter)
    with app.app_context():
        runtime.sel_manager.observe(BMC)
        generation = runtime.sel_manager.target(BMC).generation
        state['last_add'] = '01000000'
        runtime.sel_manager.observe(BMC)
        assert runtime.sel_manager.target(BMC).generation == generation, 'clock correction is not evidence of erasure or replacement'


def test_native_collection_keeps_password_out_of_argv_and_logs(native_site, monkeypatch, caplog):
    _app, _db, _models, runtime = native_site
    secret = 'fixture-password-never-log'
    calls = []
    monkeypatch.setattr(runtime.sel_manager, 'observe', lambda ip: None)
    monkeypatch.setattr(runtime, 'should_use_redfish', lambda ip: False)
    monkeypatch.setattr(runtime, 'get_ipmi_credentials', lambda ip: ('fixture-only', secret))

    def command(argv, **kwargs):
        calls.append((argv, kwargs))
        raise RuntimeError('transport rejected ' + secret)

    # Native collection now owns one persistent child; intercept that actual
    # boundary and retain the same argv/env/log assertions as the original RED.
    monkeypatch.setattr(runtime.subprocess, 'Popen', command)
    runtime.collect_ipmi_sel(BMC, 'fixture-host')
    assert calls, 'exercise the real collection subprocess boundary'
    observed = {
        'password_in_argv': any('-P' in argv or secret in argv for argv, _kwargs in calls),
        'password_in_logs': secret in caplog.text,
        'environment_password_present': all(kwargs.get('env', {}).get('IPMI_PASSWORD') == secret for _argv, kwargs in calls),
    }
    assert observed == {'password_in_argv': False, 'password_in_logs': False,
                        'environment_password_present': True}


@pytest.mark.parametrize('link', ['//foreign.invalid/Entries', ENTRIES + '#fragment',
    ENTRIES + '?page=%0a', 'https://user@192.0.2.40' + ENTRIES, ENTRIES + '/../../AuditLog/Entries',
    ENTRIES.replace('/Entries', '\\Entries')])
def test_hostile_next_links_are_rejected_before_request(redfish_reader, link):
    client, calls = redfish_reader({'Members': [entry('old')], 'Members@odata.count': 2,
        'Members@odata.nextLink': link}, extra={link: {'Members': [entry('new')]}})
    assert client.get_sel_entries() == []
    assert link not in calls


def test_conflicting_duplicate_page_cannot_complete(redfish_reader):
    changed = entry('old'); changed['Severity'] = 'Critical'
    client, _calls = redfish_reader({'Members': [entry('old')], 'Members@odata.nextLink': ENTRIES + '?page=2'},
        extra={ENTRIES + '?page=2': {'Members': [changed]}})
    assert client.get_sel_entries() == []


def test_real_get_bounds_body_and_closes_response(monkeypatch):
    runtime = importlib.import_module('ipmi_monitor.app')
    client = runtime.RedfishClient(BMC, 'fixture', 'synthetic-secret')
    seen = []
    class LargeResponse:
        status_code = 200
        def raise_for_status(self): pass
        def iter_content(self, chunk_size):
            for _ in range(300):
                seen.append('chunk'); yield b'x' * 16384
        def json(self): return {'Members': [entry('unbounded-body')]}
        def close(self): seen.append('closed')
    monkeypatch.setattr(client.session, 'get', lambda *a, **kw: LargeResponse())
    assert client._get(ENTRIES) is None
    assert seen[-1] == 'closed' and seen.count('chunk') <= 257
