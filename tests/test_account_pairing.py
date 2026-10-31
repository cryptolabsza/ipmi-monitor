# TRACEWEAVER: file-role=ipmi-account-pairing-verification; req=REQ-PAIR-004; trace=TRACE-PAIR-004; ver=VER-PAIR-004
# TRACEWEAVER: verifies=VER-PAIR-004; req=REQ-PAIR-004; trace=TRACE-PAIR-004
# TRACEWEAVER: verifies=VER-PAIR-001,VER-PAIR-003,VER-PAIR-004,VER-PAIR-005,VER-PAIR-006; req=REQ-PAIR-001,REQ-PAIR-003,REQ-PAIR-004,REQ-PAIR-005,REQ-PAIR-006; trace=TRACE-PAIR-001,TRACE-PAIR-003,TRACE-PAIR-004,TRACE-PAIR-005,TRACE-PAIR-006
"""Real Flask/SQLite account pairing; replace only the remote HTTPS boundary.

Wire samples are copied byte-for-byte from the frozen shared contract fixture.
The central producer must emit equivalent samples before GREEN is accepted.
Legacy callback regressions remain in test_account_link_security.py.
"""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timedelta
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import subprocess
import threading
import time
from unittest.mock import Mock
from urllib.parse import urlsplit

import pytest
import requests
from sqlalchemy import event


WIRE = json.loads((Path(__file__).parent / 'fixtures/pairing-wire-v1.json').read_text())
PRODUCER = json.loads((Path(__file__).parent / 'fixtures/pairing-producer-v1.json').read_text())
ROOT = '/api/account-link/'
OLD_KEY = 'original-test-key'


class Remote:
    """Faithful response boundary; the actual route/store/validator still execute."""
    def __init__(self):
        self.calls = []
        self.start = deepcopy(WIRE['start_response'])
        self.result = deepcopy(PRODUCER['responses']['success_response']['body'])
        self.ai = deepcopy(WIRE['ai_validation'])
        self.wp = deepcopy(WIRE['wp_validation'])
        self.poll_error = None
        self.on_poll = None
        self.installation_id = None

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        path = urlsplit(url).path
        if path.endswith('/pairing/start'):
            self.installation_id = kwargs['json']['installation_id']
            body, status = self.start, 201
        elif path.endswith('/pairing/status'):
            if self.on_poll:
                self.on_poll()
            if self.poll_error:
                if isinstance(self.poll_error, Exception):
                    raise self.poll_error
                body, status = self.poll_error, 400
            else:
                body, status = deepcopy(self.result), 200
                body['installation_id'] = self.installation_id
        elif path.endswith('/api/v1/validate'):
            body, status = self.ai, 200
        elif path.endswith('/ipmi/validate'):
            body, status = self.wp, 200
        else:
            raise AssertionError('Unexpected outbound endpoint: ' + url)
        return Mock(ok=status < 400, status_code=status, headers={},
                    json=lambda: deepcopy(body), text=json.dumps(body))


@pytest.fixture()
def pairing(app_fixture, login_as, monkeypatch):
    client, app, db, models = app_fixture
    import ipmi_monitor.app as runtime
    remote = Remote()
    monkeypatch.setattr(runtime.requests, 'post', remote.post)
    monkeypatch.setattr(runtime, 'sync_to_cloud', Mock(return_value={'success': True}))
    monkeypatch.setattr(runtime, 'report_crash', lambda **kwargs: None)
    with app.app_context():
        config = runtime.CloudSync.get_config()
        config.license_key = OLD_KEY
        config.subscription_valid = True
        config.subscription_tier = 'professional'
        config.features = '["old-feature"]'
        config.sync_enabled = False
        db.session.commit()
    login_as(client)
    return client, app, db, models, runtime, remote


def csrf(client):
    response = client.get(ROOT + 'config', base_url='https://localhost')
    assert response.status_code == 200, response.get_data(as_text=True)
    assert set(response.get_json()) == {'csrf_token'}
    token = response.get_json()['csrf_token']
    assert isinstance(token, str) and len(token) >= 43
    assert 'no-store' in response.headers.get('Cache-Control', '')
    assert 'Access-Control-Allow-Origin' not in response.headers
    return token


def post(client, action, body, token, **headers):
    return client.post(ROOT + action, json=body, base_url='https://localhost',
                       headers={'X-CSRF-Token': token, **headers})


def start(client):
    token = csrf(client)
    response = post(client, 'start', {}, token)
    assert response.status_code in (200, 201), response.get_data(as_text=True)
    body = response.get_json()
    assert set(body) == set(WIRE['local_browser']['start_response'])
    assert body['status'] == 'pending'
    assert body['verification_uri'] == WIRE['transport']['verification_uri']
    assert 0 < body['expires_in'] <= 300 and body['interval'] >= 5
    return token, body['attempt_id']


def saved(env):
    _, app, _, _, runtime, _ = env
    with app.app_context():
        config = runtime.CloudSync.get_config()
        return (config.license_key, config.sync_enabled, config.subscription_valid,
                config.subscription_tier, config.features)


def assert_browser_safe(response, client, app, caplog=None):
    cookie = client.get_cookie(app.config['SESSION_COOKIE_NAME'])
    decoded = app.session_interface.get_signing_serializer(app).loads(cookie.value) if cookie else {}
    visible = response.get_data(as_text=True) + str(response.headers) + json.dumps(decoded)
    if caplog is not None:
        visible += caplog.text
    for secret in [WIRE['start_response']['device_code'], WIRE['success_response']['credential']['api_key'],
                   WIRE['wp_validation']['litellm_api_key'], 'SYNTHETIC-NEVER-COPY-INSTANCE']:
        assert secret not in visible


@pytest.mark.parametrize('role', [None, 'readonly', 'readwrite'])
def test_only_current_admin_can_bootstrap_or_start(pairing, login_as, role):
    client, _, _, _, _, remote = pairing
    with client.session_transaction() as session:
        session.clear()
    if role:
        login_as(client, role)
    assert client.get(ROOT + 'config').status_code in (401, 403)
    assert post(client, 'start', {}, 'not-issued').status_code in (401, 403)
    assert remote.calls == []


@pytest.mark.parametrize('headers', [{}, {'X-CSRF-Token': 'wrong'},
    {'Origin': 'https://localhost.evil.test'}, {'Sec-Fetch-Site': 'cross-site'}])
def test_all_mutations_require_csrf_and_same_origin(pairing, headers):
    client, _, _, _, _, remote = pairing
    token = csrf(client)
    for action, body in [('start', {}), ('status', {'attempt_id': 'unknown'}),
                         ('commit', {'attempt_id': 'unknown', 'confirm': True}),
                         ('cancel', {'attempt_id': 'unknown'})]:
        effective = {'X-CSRF-Token': token, **headers} if headers else {}
        response = client.post(ROOT + action, json=body, base_url='https://localhost', headers=effective)
        assert response.status_code == 403
    assert remote.calls == []


def test_outbound_pairing_stages_then_commits_without_browser_secrets(pairing, caplog):
    client, app, _, _, runtime, remote = pairing
    before = saved(pairing)
    token, attempt = start(client)
    response = post(client, 'status', {'attempt_id': attempt}, token)
    assert response.status_code == 200
    body = response.get_json()
    assert body['status'] == 'awaiting_confirmation'
    assert body['account'] == WIRE['success_response']['account']
    assert body['requires_confirmation'] is True and body['can_commit'] is True
    assert body['service_status'] == 'available'
    assert saved(pairing) == before
    assert_browser_safe(response, client, app, caplog)
    response = post(client, 'commit', {'attempt_id': attempt, 'confirm': True}, token)
    assert response.status_code == 200 and response.get_json()['status'] == 'linked'
    assert saved(pairing)[:4] == (WIRE['success_response']['credential']['api_key'], False, True, 'standard')
    runtime.sync_to_cloud.assert_not_called()
    assert_browser_safe(response, client, app, caplog)
    for url, kwargs in remote.calls:
        assert urlsplit(url).scheme == 'https' and not urlsplit(url).query
        assert kwargs.get('verify', True) is True and kwargs.get('allow_redirects') is False
    outbound = [(u, k) for u, k in remote.calls if '/pairing/' in u]
    assert outbound[0][0] == WIRE['transport']['origin'] + WIRE['transport']['rest_prefix'] + '/pairing/start'
    assert set(outbound[0][1]['json']) == set(WIRE['start_request'])
    assert outbound[1][1]['headers']['Authorization'] == 'Bearer ' + remote.start['device_code']
    assert outbound[1][1]['json'] == {'client_id': 'cryptolabs-ipmi-monitor', 'user_code': remote.start['user_code']}
    calls = len(remote.calls)
    assert post(client, 'commit', {'attempt_id': attempt, 'confirm': True}, token).status_code in (400, 409, 410)
    assert len(remote.calls) == calls


@pytest.mark.parametrize('error', ['access_denied', 'expired_token', 'authorization_pending', 'slow_down', 'network'])
def test_failed_or_pending_status_preserves_working_link(pairing, error, caplog):
    client, app, _, _, _, remote = pairing
    token, attempt = start(client)
    producer_name = 'pending_response' if error == 'authorization_pending' else error
    remote.poll_error = (requests.ConnectionError('synthetic service unavailable') if error == 'network'
                         else deepcopy(PRODUCER['responses'][producer_name]['body']))
    before = saved(pairing)
    response = post(client, 'status', {'attempt_id': attempt}, token)
    assert response.status_code in (200, 400, 409, 410, 429, 502, 503)
    assert saved(pairing) == before
    assert post(client, 'commit', {'attempt_id': attempt, 'confirm': True}, token).status_code in (400, 409, 410)
    assert_browser_safe(response, client, app, caplog)


@pytest.mark.parametrize('attack', ['other_session', 'other_admin', 'logout', 'demoted', 'deleted'])
def test_initiating_live_admin_session_owns_attempt(pairing, login_as, attack):
    client, app, db, models, _, remote = pairing
    token, attempt = start(client)
    if attack in ('other_session', 'other_admin'):
        client = app.test_client()
        if attack == 'other_admin':
            with app.app_context():
                db.session.add(models['User'](username='secondadmin', password_hash='synthetic', role='admin', password_changed=True))
                db.session.commit()
            with client.session_transaction() as session:
                session.update(logged_in=True, username='secondadmin', user_role='admin')
        else:
            login_as(client)
        token = csrf(client)
    elif attack == 'logout':
        client.get('/logout')
        login_as(client)
        token = csrf(client)
    else:
        with app.app_context():
            user = models['User'].query.filter_by(username='testadmin').one()
            if attack == 'deleted':
                db.session.delete(user)
            else:
                user.role = 'readonly'
            db.session.commit()
    before = saved(pairing)
    assert post(client, 'status', {'attempt_id': attempt}, token).status_code in (400, 401, 403, 409, 410)
    assert saved(pairing) == before
    assert len(remote.calls) == 1


@pytest.mark.parametrize('invalidation', ['cancel', 'supersede', 'expiry', 'config_change'])
def test_invalidated_or_stale_attempt_cannot_commit(pairing, monkeypatch, invalidation):
    client, _, db, _, runtime, _ = pairing
    token, attempt = start(client)
    assert post(client, 'status', {'attempt_id': attempt}, token).status_code == 200
    if invalidation == 'cancel':
        assert post(client, 'cancel', {'attempt_id': attempt}, token).get_json()['status'] == 'cancelled'
    elif invalidation == 'supersede':
        start(client)
    elif invalidation == 'config_change':
        with pairing[1].app_context():
            runtime.CloudSync.get_config().license_key = 'customer-changed-key'
            db.session.commit()
    else:
        real_time, real_datetime = time.time, runtime.datetime
        monkeypatch.setattr(time, 'time', lambda: real_time() + 301)
        class Later(datetime):
            @classmethod
            def utcnow(cls):
                return real_datetime.utcnow() + timedelta(seconds=301)
        monkeypatch.setattr(runtime, 'datetime', Later)
    before = saved(pairing)
    assert post(client, 'commit', {'attempt_id': attempt, 'confirm': True}, token).status_code in (400, 409, 410)
    assert saved(pairing) == before


def test_cancel_wins_against_late_remote_completion(pairing):
    client, app, _, _, _, remote = pairing
    token, attempt = start(client)
    cookie = client.get_cookie(app.config['SESSION_COOKIE_NAME'])
    entered, release = threading.Event(), threading.Event()
    remote.on_poll = lambda: (entered.set(), release.wait(5))
    def poll():
        contender = app.test_client()
        contender.set_cookie(app.config['SESSION_COOKIE_NAME'], cookie.value)
        return post(contender, 'status', {'attempt_id': attempt}, token).status_code
    before = saved(pairing)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(poll)
        try:
            assert entered.wait(5)
            assert post(client, 'cancel', {'attempt_id': attempt}, token).status_code == 200
        finally:
            release.set()
        assert future.result(timeout=5) in (400, 409, 410)
    assert saved(pairing) == before


def test_concurrent_commit_is_one_use_at_real_database_boundary(pairing):
    client, app, _, _, _, _ = pairing
    token, attempt = start(client)
    assert post(client, 'status', {'attempt_id': attempt}, token).status_code == 200
    cookie = client.get_cookie(app.config['SESSION_COOKIE_NAME'])
    barrier = threading.Barrier(2)
    def commit(_):
        contender = app.test_client()
        contender.set_cookie(app.config['SESSION_COOKIE_NAME'], cookie.value)
        barrier.wait(timeout=5)
        return post(contender, 'commit', {'attempt_id': attempt, 'confirm': True}, token).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(commit, range(2)))
    assert statuses.count(200) == 1
    assert set(statuses) <= {200, 400, 409, 410}
    assert saved(pairing)[0] == WIRE['success_response']['credential']['api_key']


@pytest.mark.parametrize('writer', ['configuration', 'admin_demotion'])
def test_concurrent_legacy_writer_cannot_be_overwritten_by_stale_commit(pairing, writer):
    """Pause immediately before the real consume UPDATE, then run a second DB writer.

    Either pairing holds a write lock and finishes first, or the other writer
    wins first and pairing must reject its stale authority/configuration.
    """
    client, app, db, models, runtime, _ = pairing
    token, attempt = start(client)
    assert post(client, 'status', {'attempt_id': attempt}, token).status_code == 200
    cookie = client.get_cookie(app.config['SESSION_COOKIE_NAME'])
    before_write, release, written = threading.Event(), threading.Event(), threading.Event()
    with app.app_context():
        engine = db.engine
    def barrier(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith('UPDATE account_link_attempt') and 'consumed' in parameters:
            before_write.set()
            assert release.wait(5)
    def commit():
        contender = app.test_client()
        contender.set_cookie(app.config['SESSION_COOKIE_NAME'], cookie.value)
        return post(contender, 'commit', {'attempt_id': attempt, 'confirm': True}, token).status_code
    def legacy_write():
        if writer == 'configuration':
            contender = app.test_client()
            contender.set_cookie(app.config['SESSION_COOKIE_NAME'], cookie.value)
            response = contender.put('/api/ai/config', json={'license_key': 'customer-new-key', 'sync_enabled': False})
            assert response.status_code == 200
        else:
            with app.app_context():
                models['User'].query.filter_by(username='testadmin').update({'role': 'readonly'})
                db.session.commit()
        written.set()
    event.listen(engine, 'before_cursor_execute', barrier)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            committed = pool.submit(commit)
            assert before_write.wait(5)
            changed = pool.submit(legacy_write)
            writer_won_first = written.wait(0.5)
            release.set()
            status = committed.result(timeout=5)
            changed.result(timeout=5)
    finally:
        release.set()
        event.remove(engine, 'before_cursor_execute', barrier)
    if writer == 'configuration':
        assert saved(pairing)[0] == 'customer-new-key'
    if writer_won_first:
        assert status in (403, 409)
    else:
        assert status == 200


@pytest.mark.parametrize('issue', ['missing_id', 'wrong_id', 'wrong_wp_id', 'missing_customer', 'missing_features'])
def test_pairing_specific_legacy_identity_bridge_stays_strict(pairing, issue):
    client, _, _, _, _, remote = pairing
    if issue == 'missing_id':
        remote.ai.pop('user_id')
    elif issue == 'wrong_id':
        remote.ai['user_id'] = 999
    elif issue == 'wrong_wp_id':
        remote.ai.pop('user_id')
        remote.wp['user_id'] = 999
    elif issue == 'missing_customer':
        remote.ai.pop('customer_id')
    else:
        remote.ai.pop('features')
    before = saved(pairing)
    token, attempt = start(client)
    response = post(client, 'status', {'attempt_id': attempt}, token)
    assert response.status_code == 200
    assert response.get_json()['can_commit'] is (issue == 'missing_id')
    committed = post(client, 'commit', {'attempt_id': attempt, 'confirm': True}, token)
    if issue == 'missing_id':
        assert committed.status_code == 200
        assert any(url.endswith('/ipmi/validate') for url, _ in remote.calls)
        assert saved(pairing)[0] == WIRE['success_response']['credential']['api_key']
    else:
        assert committed.status_code in (400, 409)
        assert saved(pairing) == before


def test_first_identity_link_does_not_invent_paid_access_or_customer_id(pairing):
    client, app, db, _, runtime, remote = pairing
    with app.app_context():
        config = runtime.CloudSync.get_config()
        config.license_key = None
        config.subscription_valid = False
        config.features = '[]'
        db.session.commit()
    remote.ai = {'valid': False}
    token, attempt = start(client)
    response = post(client, 'status', {'attempt_id': attempt}, token)
    assert response.status_code == 200 and response.get_json()['can_commit'] is True
    assert response.get_json()['service_status'] in ('unavailable', 'not_entitled', 'unknown')
    assert post(client, 'commit', {'attempt_id': attempt, 'confirm': True}, token).status_code == 200
    assert saved(pairing)[:3] == (WIRE['success_response']['credential']['api_key'], False, False)
    status = client.get('/api/ai/config').get_json()
    assert status['linked_account']['wp_user_id'] == 123
    assert not status['linked_account'].get('customer_id')
    assert status['features'] == []
    runtime.sync_to_cloud.assert_not_called()


@pytest.mark.parametrize('field,value', [('api_key', 'browser-credential'),
    ('device_code', 'browser-device-code'), ('account', {'id': 999}), ('service_url', 'https://attacker.test')])
def test_browser_cannot_supply_authority_fields(pairing, field, value):
    client, _, _, _, _, remote = pairing
    token, attempt = start(client)
    response = post(client, 'status', {'attempt_id': attempt, field: value}, token)
    assert response.status_code == 400
    assert len(remote.calls) == 1 and saved(pairing)[0] == OLD_KEY


@pytest.mark.parametrize('confirm', [False, None, 'true'])
def test_staged_account_needs_explicit_boolean_confirmation(pairing, confirm):
    client, _, _, _, _, _ = pairing
    token, attempt = start(client)
    assert post(client, 'status', {'attempt_id': attempt}, token).status_code == 200
    before = saved(pairing)
    assert post(client, 'commit', {'attempt_id': attempt, 'confirm': confirm}, token).status_code == 400
    assert saved(pairing) == before


@pytest.mark.parametrize('field,value', [('client_id', 'cryptolabs-dc-controller'),
    ('account', {'id': True, 'email': 'customer@example.test', 'display_name': 'Customer'}),
    ('credential', {'type': 'admin_token', 'api_key': 'unexpected', 'scope': 'admin'})])
def test_malformed_central_binding_never_stages_authority(pairing, field, value):
    client, _, _, _, _, remote = pairing
    remote.result[field] = value
    token, attempt = start(client)
    before = saved(pairing)
    response = post(client, 'status', {'attempt_id': attempt}, token)
    assert response.status_code in (400, 409, 502)
    assert post(client, 'commit', {'attempt_id': attempt, 'confirm': True}, token).status_code in (400, 409, 410)
    assert saved(pairing) == before


class Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.active = False
        self.parts = []
    def handle_starttag(self, tag, attrs):
        self.active = tag == 'script'
    def handle_endtag(self, tag):
        if tag == 'script': self.active = False
    def handle_data(self, data):
        if self.active: self.parts.append(data)


@pytest.mark.parametrize('page', ['settings', 'setup', 'dashboard'])
def test_all_pairing_entry_pages_have_executable_javascript(pairing, page):
    """All three entry points must parse; setup currently has a real syntax defect."""
    client, _, _, _, _, _ = pairing
    response = client.get('/' if page == 'dashboard' else '/' + page)
    assert response.status_code == 200
    parser = Scripts(); parser.feed(response.get_data(as_text=True))
    subprocess.run(['node', '-e', "new (require('vm').Script)(require('fs').readFileSync(0,'utf8'))"],
                   input='\n'.join(parser.parts), text=True, capture_output=True, check=True)


@pytest.mark.parametrize('prefix', ['/', '/ipmi'])
@pytest.mark.parametrize('page', ['settings', 'setup', 'dashboard'])
def test_pairing_entry_api_urls_stay_on_local_root_or_mount(pairing, monkeypatch, page, prefix):
    client, _, _, _, runtime, _ = pairing
    monkeypatch.setattr(runtime, 'APPLICATION_ROOT', prefix)
    response = client.get('/' if page == 'dashboard' else '/' + page)
    html = response.get_data(as_text=True)
    script = re.search(r"const BASE_PATH = [^;]+;", html).group() + '\n' + re.search(
        r"function apiUrl\(path\) \{.*?\n\s*\}", html, re.S).group()
    result = subprocess.run(['node', '-e', script + "\nconsole.log(apiUrl('/api/account-link/config'));"],
                            text=True, capture_output=True, check=True)
    assert result.stdout.strip() == prefix.rstrip('/') + '/api/account-link/config'


def test_dashboard_trial_starts_local_authenticated_pairing_instead_of_callback(pairing):
    client, _, _, _, _, _ = pairing
    template = (Path(__file__).parents[1] / 'src/ipmi_monitor/templates/dashboard.html').read_text()
    start_at = template.index('function startFreeTrial()')
    script = template[start_at:template.index('// Iframe offer timeout', start_at)]
    harness = r'''
const urls=[]; const apiUrl=(p)=>'/ipmi'+p;
const location={origin:'https://localhost',host:'localhost',assign:(u)=>urls.push(u),
 set href(u){urls.push(u)}};
const window={location,open:(u)=>urls.push(u)};
'''
    result = subprocess.run(['node', '-e', harness + script + '\nstartFreeTrial();console.log(JSON.stringify(urls));'],
                            text=True, capture_output=True, check=True)
    urls = json.loads(result.stdout)
    assert urls and all(url.startswith('/ipmi/settings') for url in urls)
    assert all('redirect_uri' not in url and 'oauth-callback' not in url for url in urls)


@pytest.mark.parametrize('page', ['settings', 'dashboard', 'setup'])
def test_account_entry_does_not_advertise_retired_month_or_price(page):
    """Approved neutral CTA lane avoids renewing an unverified trial promise."""
    template = (Path(__file__).parents[1] / 'src/ipmi_monitor/templates' / (page + '.html')).read_text()
    for retired in ['1 MONTH FREE TRIAL', '1 month of full AI features', 'Start Your Free Month',
                    '$100/month for 50 servers']:
        assert retired not in template


def test_setup_cannot_receive_a_browser_credential_before_local_admin_exists():
    template = (Path(__file__).parents[1] / 'src/ipmi_monitor/templates/setup.html').read_text()
    start_at = template.index('function loginWithCryptoLabs()')
    script = template[start_at:template.index('// Complete setup', start_at)]
    harness = r'''
const urls=[],messages=[]; let listener;
const element={value:'',checked:false};
const document={getElementById:()=>element};
const window={location:{origin:'https://localhost'},open:(u)=>{urls.push(u);return {close(){}}},
 addEventListener:(name,fn)=>listener=fn};
const screen={width:1280,height:800};
const showAlert=(message)=>messages.push(message);
'''
    run = r'''
loginWithCryptoLabs();
if(listener)listener({origin:'https://attacker.test',source:{},
 data:{type:'cryptolabs_ipmi_auth',api_key:'browser-attacker-key',user_email:'attacker@example.test'}});
console.log(JSON.stringify({urls,value:element.value,messages}));
'''
    result = subprocess.run(['node', '-e', harness + script + run], text=True, capture_output=True, check=True)
    observed = json.loads(result.stdout)
    assert observed['urls'] == [] and observed['value'] == ''
    assert any('setup' in message.lower() or 'administrator' in message.lower() for message in observed['messages'])
