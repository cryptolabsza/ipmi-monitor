# TRACEWEAVER: file-role=ipmi-monitor-verification; req=REQ-IPMI-MON-02; trace=TRACE-IPMI-MON-02; ver=VER-IPMI-MON-02
# TRACEWEAVER: verifies=VER-IPMI-MON-02; req=REQ-IPMI-MON-02; trace=TRACE-IPMI-MON-02
"""Approved repair-plan step 1: real Flask account-link boundary regressions.

Only remote validation and background sync are substituted; session, routes,
database writes, nonce consumption and rendered responses are production code.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlsplit
from unittest.mock import Mock
import json
from pathlib import Path
import subprocess

import pytest


@pytest.fixture()
def link_env(app_fixture, monkeypatch):
    import ipmi_monitor.app as runtime
    client, app, db, models = app_fixture
    validation = Mock(ok=True, json=lambda: {
        'valid': True, 'tier': 'standard', 'max_servers': 125,
        'features': ['chat', 'summary'], 'email': 'verified@example.test',
        'user_id': 71, 'customer_id': 'customer-71',
    })
    post = Mock(return_value=validation)
    monkeypatch.setattr(runtime.requests, 'post', post)
    monkeypatch.setattr(runtime, 'sync_to_cloud', Mock(return_value={'success': True}))
    monkeypatch.setattr(runtime, 'report_crash', lambda **kwargs: None)
    with app.app_context():
        config = runtime.CloudSync.get_config()
        config.license_key = 'original-test-key'
        config.subscription_valid = False
        db.session.commit()
    return client, app, db, models, runtime, post


def _start(client):
    response = client.post('/api/ai/oauth-start', json={'mode': 'signin'},
                           base_url='https://localhost')
    assert response.status_code == 200, response.get_data(as_text=True)
    return parse_qs(urlsplit(response.get_json()['authorization_url']).query)


def _callback(client, state=None, **overrides):
    query = {'api_key': 'returned-test-key', 'subscription': 'enterprise',
             'user_email': 'forged@example.test', 'wp_user_id': '999',
             'user_name': "');window.injected=true;//"}
    if state is not None:
        query['state'] = state
    query.update(overrides)
    return client.get('/api/ai/oauth-callback', query_string=query,
                      base_url='https://localhost')


@pytest.mark.parametrize('role', [None, 'readonly', 'readwrite', 'admin'])
def test_callback_without_state_cannot_change_identity_or_credentials(link_env, login_as, role):
    client, app, db, models, runtime, post = link_env
    if role:
        login_as(client, role)
    response = _callback(client)
    with app.app_context():
        assert runtime.CloudSync.get_config().license_key == 'original-test-key'
        assert models['User'].query.filter(models['User'].wp_email.isnot(None)).count() == 0
    assert response.status_code in (400, 401, 403)
    assert 'returned-test-key' not in response.headers.get('Location', '')
    post.assert_not_called()


@pytest.mark.parametrize('role', ['readonly', 'readwrite'])
def test_only_admin_can_start_account_link(link_env, login_as, role):
    client, *_ = link_env
    login_as(client, role)
    response = client.post('/api/ai/oauth-start', json={})
    assert response.status_code in (401, 403)


@pytest.mark.parametrize('prefix', ['', '/ipmi'])
def test_start_uses_random_session_bound_state_and_exact_mount(link_env, login_as, monkeypatch, prefix):
    client, app, db, models, runtime, post = link_env
    monkeypatch.setattr(runtime, 'APPLICATION_ROOT', prefix)
    login_as(client)
    first, second = _start(client), _start(client)
    assert first['clai_ipmi_oauth'] == ['1']
    assert first['redirect_uri'] == [f'https://localhost{prefix}/api/ai/oauth-callback']
    assert len(first['state'][0]) >= 32
    assert first['state'] != second['state']
    other = app.test_client()
    login_as(other)
    assert _callback(other, first['state'][0]).status_code in (400, 401, 403)
    with app.app_context():
        assert runtime.CloudSync.get_config().license_key == 'original-test-key'


def test_callback_verifies_identity_entitlements_and_never_exposes_key(link_env, login_as):
    client, app, db, models, runtime, post = link_env
    login_as(client)
    state = _start(client)['state'][0]
    response = _callback(client, state)
    assert response.status_code == 200
    with app.app_context():
        config = runtime.CloudSync.get_config()
        user = models['User'].query.filter_by(username='testadmin').one()
        assert (config.license_key, config.subscription_tier, config.max_servers,
                config.get_features_list(), config.subscription_valid) == (
                    'returned-test-key', 'standard', 125, ['chat', 'summary'], True)
        assert (user.wp_user_id, user.wp_email) == (71, 'verified@example.test')
    assert post.call_args.args[0].endswith('/api/v1/validate')
    assert post.call_args.kwargs.get('verify', True) is True
    assert 'no-store' in response.headers['Cache-Control']
    assert response.headers['Referrer-Policy'] == 'no-referrer'
    html = response.get_data(as_text=True)
    assert 'returned-test-key' not in html
    assert "window.injected=true" not in html
    post.reset_mock()
    assert _callback(client, state).status_code in (400, 401, 403)
    post.assert_not_called()


def test_proxy_only_sso_persists_verified_account_status_without_creating_local_admin(link_env):
    client, app, db, models, runtime, post = link_env
    headers = {'X-Fleet-Authenticated': 'true', 'X-Fleet-Auth-User': 'fleet-only-admin',
               'X-Fleet-Auth-Role': 'admin'}
    response = client.post('/api/ai/oauth-start', json={'mode': 'signin'},
                           headers=headers, base_url='https://localhost',
                           environ_overrides={'REMOTE_ADDR': '127.0.0.1'})
    assert response.status_code == 200
    state = parse_qs(urlsplit(response.get_json()['authorization_url']).query)['state'][0]
    assert _callback(client, state).status_code == 200
    # A new proxy session sees the persisted cloud account rather than relying on a local User row.
    returning = app.test_client()
    response = returning.get('/api/ai/config', headers=headers,
                              environ_overrides={'REMOTE_ADDR': '127.0.0.1'})
    body = response.get_json()
    assert body['linked_account']['wp_email'] == 'verified@example.test'
    assert body['linked_account']['wp_user_id'] == 71
    assert body['linked_account']['customer_id'] == 'customer-71'
    assert body['linked_account_status'] == 'verified'
    assert 'returned-test-key' not in response.get_data(as_text=True)
    with app.app_context():
        assert models['User'].query.filter_by(username='fleet-only-admin').first() is None
        assert models['User'].query.filter_by(username='testadmin').one().wp_email is None
    assert returning.put('/api/ai/config', json={'license_key': ''}, headers=headers).status_code == 200
    body = returning.get('/api/ai/config', headers=headers).get_json()
    assert body.get('linked_account') is None
    assert body['linked_account_status'] == 'unlinked'


@pytest.mark.parametrize('body', [
    {'valid': False}, {'valid': True},
    {'valid': True, 'tier': 'standard', 'max_servers': 50, 'features': [], 'email': 'verified@example.test'},
])
def test_callback_denied_or_incomplete_validation_is_consumed_without_mutation(link_env, login_as, body):
    client, app, db, models, runtime, post = link_env
    login_as(client)
    state = _start(client)['state'][0]
    post.return_value = Mock(ok=True, json=lambda: body)
    assert _callback(client, state).status_code in (400, 401, 403, 502)
    with app.app_context():
        assert runtime.CloudSync.get_config().license_key == 'original-test-key'
    post.reset_mock()
    assert _callback(client, state).status_code in (400, 401, 403)
    post.assert_not_called()


def test_expired_state_and_simultaneous_replay_cannot_validate_twice(link_env, login_as, monkeypatch):
    client, app, db, models, runtime, post = link_env
    login_as(client)
    expired = _start(client)['state'][0]
    real_datetime = runtime.datetime

    class Later(datetime):
        @classmethod
        def utcnow(cls):
            return real_datetime.utcnow() + timedelta(hours=1)

    monkeypatch.setattr(runtime, 'datetime', Later)
    assert _callback(client, expired).status_code in (400, 401, 403)
    post.assert_not_called()
    monkeypatch.setattr(runtime, 'datetime', real_datetime)
    state = _start(client)['state'][0]
    with client.session_transaction() as session:
        snapshot = dict(session)

    def callback(_):
        contender = app.test_client()
        with contender.session_transaction() as session:
            session.update(snapshot)
        return _callback(contender, state).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(callback, range(2)))
    assert sorted(statuses)[0] == 200
    assert sum(status == 200 for status in statuses) == 1
    assert post.call_count == 1


def test_logout_invalidates_pending_link_even_after_same_admin_signs_in_again(link_env, login_as):
    client, app, db, models, runtime, post = link_env
    login_as(client)
    state = _start(client)['state'][0]
    client.get('/logout')
    login_as(client)
    assert _callback(client, state).status_code in (400, 401, 403)
    post.assert_not_called()


@pytest.mark.parametrize('role', [None, 'readonly'])
def test_embed_config_never_discloses_shared_key_to_nonadmin(link_env, login_as, role):
    client, app, db, models, runtime, post = link_env
    with app.app_context():
        config = runtime.CloudSync.get_config()
        config.sync_enabled = config.subscription_valid = True
        db.session.commit()
    if role:
        login_as(client, role)
    response = client.get('/api/ai/embed-config', headers={'Accept': 'application/json'})
    assert 'original-test-key' not in response.get_data(as_text=True)
    assert response.status_code in (401, 403)


def test_periodic_validation_replaces_validity_features_and_paid_limit(link_env, monkeypatch):
    client, app, db, models, runtime, post = link_env
    with app.app_context():
        config = runtime.CloudSync.get_config()
        config.sync_enabled = True
        config.subscription_valid = True
        config.features = '["old-feature"]'
        db.session.commit()
    # Drive exactly one real timer iteration; only scheduling/remote boundaries are replaced.
    stop = Mock()
    stop.is_set.side_effect = [False, True]
    monkeypatch.setattr(runtime, '_shutdown_event', stop)
    monkeypatch.setattr(runtime, 'sync_telemetry', lambda: None)
    monkeypatch.setattr(runtime, 'report_startup', lambda: None)
    monkeypatch.setattr(runtime, 'poll_agent_tasks', lambda: None)
    runtime.sync_timer()
    with app.app_context():
        config = runtime.CloudSync.get_config()
        assert config.get_features_list() == ['chat', 'summary']
        assert config.max_servers == 125
    post.return_value = Mock(ok=True, json=lambda: {'valid': False})
    stop.is_set.side_effect = [False, True]
    runtime.sync_timer()
    with app.app_context():
        config = runtime.CloudSync.get_config()
        assert config.subscription_valid is False
        assert config.get_features_list() == []


def test_rejected_validation_cannot_be_reported_as_active(app_fixture, login_as, monkeypatch):
    client, app, db, models = app_fixture
    import ipmi_monitor.app as runtime
    login_as(client)
    monkeypatch.setattr(runtime, 'validate_license_key', lambda key: {'valid': False})
    response = client.put('/api/ai/config', json={'license_key': 'invalid-test-key', 'sync_enabled': True})
    assert response.status_code in (400, 401, 403)
    assert response.get_json().get('status') != 'success'
    with app.app_context():
        assert runtime.CloudSync.get_config().subscription_valid is False


@pytest.mark.parametrize('origin,source,expected_reload', [
    ('https://localhost.evil.test', 'popup', 0),
    ('https://localhost', 'other', 0),
    ('https://localhost', 'popup', 1),
])
def test_settings_popup_uses_exact_origin_source_and_server_owned_status(origin, source, expected_reload):
    """Execute actual template JavaScript in Node; browser/popup boundaries are simulated."""
    template = (Path(__file__).parents[1] / 'src/ipmi_monitor/templates/settings.html').read_text()
    script = template[template.index('function loginWithCryptoLabs('):template.index('// Toggle API key visibility')]
    # Both existing sync and repaired async function declarations can execute in this harness.
    if template[template.index('function loginWithCryptoLabs(') - 6:].startswith('async '):
        script = 'async ' + script
    harness = '''
let handler, saves = 0, reloads = 0;
const popup = { closed: false, close() {} };
const window = { location: { origin: 'https://localhost', host: 'localhost' },
  open: () => popup, addEventListener: (name, fn) => { handler = fn; }, removeEventListener() {} };
const screen = { width: 1280, height: 800 };
const document = { getElementById: () => ({ value: '', checked: false }) };
const CRYPTOLABS_OAUTH_URL = 'https://www.cryptolabs.co.za/?clai_ipmi_oauth=1';
const apiUrl = (path) => '/ipmi' + path;
const fetch = async () => ({ok: true, json: async () => ({authorization_url: CRYPTOLABS_OAUTH_URL})});
const showAlert = () => {}, saveAiConfig = async () => { saves++; }, loadAiConfig = async () => { reloads++; };
const setTimeout = () => 0, setInterval = () => 0, clearInterval = () => {};
'''
    invocation = f'''
(async () => {{
  await loginWithCryptoLabs();
  if (!handler) throw new Error('No popup message listener');
  await handler({{origin: {json.dumps(origin)}, source: {'popup' if source == 'popup' else '{}'},
    data: {{type: 'cryptolabs_ipmi_auth', success: true, api_key: 'untrusted-browser-key'}}}});
  console.log(JSON.stringify({{saves, reloads}}));
}})().catch(error => {{ console.error(error); process.exit(1); }});
'''
    result = subprocess.run(['node', '-e', harness + script + invocation],
                            text=True, capture_output=True, check=True)
    assert json.loads(result.stdout) == {'saves': 0, 'reloads': expected_reload}


def test_settings_url_cannot_bypass_session_bound_sso():
    """A legacy settings query must not silently connect an attacker's valid account."""
    template = (Path(__file__).parents[1] / 'src/ipmi_monitor/templates/settings.html').read_text()
    start = template.index('async function handleOAuthCallback()')
    script = template[start:template.index('// Initialize', start)]
    harness = '''
let posts = 0, cleared = false;
const window = { location: { search: '?api_key=attacker-valid-key&user_email=attacker@example.test',
 origin: 'https://localhost', pathname: '/ipmi/settings' },
 history: { replaceState() { cleared = true; } } };
const document = {title: 'settings'};
const apiUrl = (path) => path, showAlert = () => {}, showTab = () => {}, loadAiConfig = async () => {};
const fetch = async () => { posts++; return {ok: true}; };
'''
    result = subprocess.run(['node', '-e', harness + script + '''
(async () => { await handleOAuthCallback(); console.log(JSON.stringify({posts, cleared})); })();
'''], text=True, capture_output=True, check=True)
    assert json.loads(result.stdout.splitlines()[-1]) == {'posts': 0, 'cleared': True}
