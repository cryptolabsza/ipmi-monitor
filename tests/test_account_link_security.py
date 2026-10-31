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


@pytest.mark.parametrize('mode', ['signin', 'signup', 'unsolicited_message'])
def test_settings_pairing_uses_server_status_and_never_browser_credentials(mode):
    """Retain the browser credential boundary after retiring popup-message SSO."""
    template = (Path(__file__).parents[1] / 'src/ipmi_monitor/templates/settings.html').read_text()
    script = template[template.index('function loginWithCryptoLabs('):template.index('// Toggle API key visibility')]
    if template[template.index('function loginWithCryptoLabs(') - 6:].startswith('async '):
        script = 'async ' + script
    harness = '''
let handler, saves = 0, reloads = 0; const requests=[], urls=[];
const elements={}; const element=(id)=>elements[id] ||= {disabled:id==='#pairConfirm',textContent:'',href:'',focus(){},setAttribute(name,value){this[name]=value;}};
const dialog={style:{},querySelector:element,showModal(){},close(){},remove(){},addEventListener(){},setAttribute(){}};
const document={getElementById:()=>null,createElement:()=>dialog,body:{appendChild(){}}};
const window={location:{origin:'https://localhost',host:'localhost'},open:(url)=>urls.push(url),
 addEventListener:(name,fn)=>{handler=fn},removeEventListener(){}};
const apiUrl = (path) => '/ipmi' + path;
const fetch=async(url,options={})=>{
 requests.push({url,method:options.method||'GET',headers:options.headers,body:options.body&&JSON.parse(options.body)});
 return {ok:true,json:async()=>url.endsWith('/config')?{csrf_token:'browser-csrf'}:
 {status:'pending',attempt_id:'local-attempt',user_code:'01-ABCD-EFGH',
 verification_uri:'https://www.cryptolabs.co.za/?clai_pair=1',interval:5,expires_in:300}};
};
const showAlert = () => {}, saveAiConfig = async () => { saves++; }, loadAiConfig = async () => { reloads++; };
const setTimeout = () => 0, setInterval = () => 0, clearInterval = () => {};
'''
    invocation = f'''
(async () => {{
  await loginWithCryptoLabs({json.dumps(mode)});
  if(handler)await handler({{origin:'https://localhost.evil.test',source:{{}},
    data:{{type:'cryptolabs_ipmi_auth',success:true,api_key:'untrusted-browser-key'}}}});
  console.log(JSON.stringify({{saves,reloads,requests,urls,elements}}));
}})().catch(error => {{ console.error(error); process.exit(1); }});
'''
    result = subprocess.run(['node', '-e', harness + script + invocation],
                            text=True, capture_output=True, check=True)
    observed = json.loads(result.stdout)
    assert observed['saves'] == observed['reloads'] == 0
    assert observed['urls'] == []
    assert [(r['url'], r['method']) for r in observed['requests']] == [
        ('/ipmi/api/account-link/config', 'GET'), ('/ipmi/api/account-link/start', 'POST')]
    assert observed['requests'][1]['body'] == {}
    assert observed['requests'][1]['headers']['X-CSRF-Token'] == 'browser-csrf'
    assert observed['elements']['#pairCode']['textContent'] == '01-ABCD-EFGH'
    assert observed['elements']['#pairConfirm']['disabled'] is True
    assert 'untrusted-browser-key' not in json.dumps(observed)


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


def _pair_dialog_scenario(kind, mode='signup', interval=5):
    """Run the actual client handler; substitute only DOM, HTTP and elapsed time."""
    template = (Path(__file__).parents[1] / 'src/ipmi_monitor/templates/settings.html').read_text()
    start = template.index('async function loginWithCryptoLabs(')
    script = template[start:template.index('// Toggle API key visibility', start)]
    harness = r'''
const vm = require('vm');
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const elements = {}, timers = [], requests = [], alerts = [];
let removed = false, reloads = 0, clock = 0, statusCalls = 0;
const finishCommit = [];
const element = id => elements[id] ||= {disabled:id==='#pairConfirm',textContent:'',value:'',
 style:{},setAttribute(name,value){this[name]=value;},focus(){}};
const dialog = {style:{},querySelector:element,showModal(){},close(){},
 remove(){removed=true;},addEventListener(){},setAttribute(){}};
const context = {
 document:{getElementById:()=>null,createElement:()=>dialog,body:{appendChild(){}}},
 window:{location:{origin:'https://local.example'},open(){throw Error('Unexpected automatic navigation');}},
 URL, URLSearchParams, Date:class extends Date {static now(){return clock;}},
 apiUrl:path=>'/ipmi'+path,
 setTimeout:(fn,ms)=>{const timer={fn,ms,active:true};timers.push(timer);return timer;},
 clearTimeout:timer=>{if(timer)timer.active=false;},
 loadAiConfig:async()=>{reloads++;if(input.kind==='lost_stalled_refresh')await new Promise(()=>{});},
 showAlert:(message,type)=>alerts.push({message,type}),
 fetch:async(url,options={})=>{
  requests.push({url,method:options.method||'GET',body:options.body?JSON.parse(options.body):null});
  let value={},ok=true,status=200;
  if(url.endsWith('/account-link/config'))value={csrf_token:'isolated-csrf'};
  if(url.endsWith('/start')){
   if(input.kind==='slow_start')clock+=20000;
   value={attempt_id:'isolated-attempt',user_code:'01-ABCD-EFGH',
    verification_uri:input.kind==='bad_uri'?'https://attacker.example/?clai_pair=1':
    'https://www.cryptolabs.co.za/?clai_pair=1',interval:input.interval,expires_in:300};
  }
  if(url.endsWith('/status')){
   statusCalls++;
   if(input.kind==='poll_error'&&statusCalls===1)throw Error('Offline');
   value=input.kind==='pending'?{status:'pending',interval:input.interval}:
    {status:'awaiting_confirmation',account:{id:71,email:'isolated@example.test'},
     service_status:input.kind==='blocked'?'unavailable':'available',can_commit:input.kind!=='blocked'};
  }
  if(url.endsWith('/ai/config'))value=['lost_saved','lost_stalled_refresh'].includes(input.kind)?
   {linked_account_status:'verified',linked_account:{wp_user_id:71,wp_email:'isolated@example.test'}}:
   {linked_account_status:'verified',linked_account:{wp_user_id:29,wp_email:'previous@example.test'}};
  if(url.endsWith('/commit')){
   if(input.kind==='saving')return await new Promise(resolve=>{finishCommit.push(resolve);});
   if(input.kind.startsWith('lost_'))throw Error('Response lost');
   value={status:'linked',account:{id:71,email:'isolated@example.test'},service_status:'available'};
  }
  return {ok,status,json:async()=>value};
 }
};
const snapshot=()=>({disabled:element('#pairConfirm').disabled,cancelDisabled:element('#pairCancel').disabled,status:element('#pairStatus').textContent,
 requests:requests.map(item=>({...item})),reloads,removed,alerts:alerts.map(item=>({...item})),
 activeTimers:timers.filter(item=>item.active).map(item=>item.ms)});
vm.createContext(context);
vm.runInContext(input.script+'\nthis.start=loginWithCryptoLabs;',context);
(async()=>{
 await context.start(input.mode);
 const initial=snapshot();
 const expiry=timers.find(item=>item.ms===300000);
 const poll=timers.find(item=>item.ms===input.interval*1000);
 if(poll){poll.active=false;clock+=poll.ms;await poll.fn();}
 const afterPoll=snapshot();
 let duringCommit=null,beforeClose=null;
 if(['pending','blocked','saving','lost_saved','lost_unsaved','lost_stalled_refresh','success'].includes(input.kind)){
  const first=element('#pairConfirm').onclick();
  if(input.kind==='saving'){
   const duplicate=element('#pairConfirm').onclick();
   await new Promise(resolve=>setImmediate(resolve));
   duringCommit=snapshot();
   if(expiry)await expiry.fn(); // A callback already queued before saving cannot win.
   for(const finish of finishCommit)finish({ok:true,status:200,json:async()=>({status:'linked',
    account:{id:71,email:'isolated@example.test'},service_status:'available'})});
   await duplicate;
  }
  if(input.kind==='lost_stalled_refresh'){
   await new Promise(resolve=>setImmediate(resolve));
   beforeClose=snapshot();
   await element('#pairCancel').onclick();
  }else await first;
 }
 if(input.kind==='poll_error'){
  const retry=timers.find(item=>item.active&&item.ms<300000);
  if(retry){retry.active=false;clock+=retry.ms;await retry.fn();}
 }
 const beforeExpiredRetry=requests.length;
 if(input.kind==='poll_error'){
  clock=300001;
  for(const timer of timers.filter(item=>item.active&&item.ms<300000)){timer.active=false;await timer.fn();}
 }
 console.log(JSON.stringify({initial,afterPoll,duringCommit,beforeClose,final:snapshot(),beforeExpiredRetry,
  markup:dialog.innerHTML,elements}));
})().catch(error=>{console.error(error);process.exit(1);});
'''
    result = subprocess.run(['node', '-e', harness], input=json.dumps({
        'script': script, 'kind': kind, 'mode': mode, 'interval': interval,
    }), text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


@pytest.mark.parametrize('kind', ['pending', 'blocked'])
def test_pair_dialog_cannot_commit_without_current_server_authority(kind):
    observed = _pair_dialog_scenario(kind)
    assert observed['afterPoll']['disabled'] is True
    assert not any(r['url'].endswith('/commit') for r in observed['final']['requests'])
    assert observed['final']['alerts'] == []


def test_pair_dialog_saving_is_immediate_single_flight_and_expiry_cannot_replace_it():
    observed = _pair_dialog_scenario('saving')
    during = observed['duringCommit']
    assert 'saving' in during['status'].lower()
    assert during['disabled'] is True
    assert sum(r['url'].endswith('/commit') for r in during['requests']) == 1
    assert observed['final']['removed'] is True
    assert observed['final']['reloads'] == 1
    assert observed['final']['alerts'][-1]['type'] == 'success'


@pytest.mark.parametrize('kind', ['lost_saved', 'lost_unsaved'])
def test_pair_dialog_lost_commit_response_reconciles_read_only_without_replay(kind):
    observed = _pair_dialog_scenario(kind)
    requests = observed['final']['requests']
    assert sum(r['url'].endswith('/commit') for r in requests) == 1
    assert any(r['url'].endswith('/ai/config') and r['method'] == 'GET' for r in requests)
    assert observed['final']['disabled'] is True
    if kind == 'lost_unsaved':
        assert not any(a['type'] == 'success' for a in observed['final']['alerts'])
        assert 'confirm' in observed['final']['status'].lower()
    else:
        assert 'linked' in observed['final']['status'].lower()


def test_pair_dialog_transient_poll_failure_retries_only_before_original_deadline():
    observed = _pair_dialog_scenario('poll_error')
    assert any(5000 <= delay < 300000 for delay in observed['afterPoll']['activeTimers'])
    assert observed['final']['disabled'] is False
    assert len(observed['final']['requests']) == observed['beforeExpiredRetry']
    assert not any(r['url'].endswith('/commit') for r in observed['final']['requests'])


def test_pair_dialog_retry_respects_server_interval_after_transport_error():
    observed = _pair_dialog_scenario('poll_error', interval=60)
    retries = [delay for delay in observed['afterPoll']['activeTimers'] if delay < 300000]
    assert retries and all(delay >= 60000 for delay in retries)
    assert len(observed['final']['requests']) == observed['beforeExpiredRetry']


def test_pair_dialog_stalled_optional_refresh_does_not_disable_close():
    observed = _pair_dialog_scenario('lost_stalled_refresh')
    assert observed['beforeClose']['reloads'] == 1
    assert observed['beforeClose']['cancelDisabled'] is False
    assert 'linked' in observed['beforeClose']['status'].lower()
    assert observed['final']['removed'] is True
    assert sum(r['url'].endswith('/commit') for r in observed['final']['requests']) == 1


def test_pair_dialog_delayed_start_response_does_not_extend_browser_deadline():
    observed = _pair_dialog_scenario('slow_start')
    assert 280000 in observed['initial']['activeTimers']
    assert 300000 not in observed['initial']['activeTimers']


@pytest.mark.parametrize('mode', ['signin', 'signup'])
def test_pair_dialog_branded_handoff_posts_displayed_code_without_extending_start(mode):
    from html.parser import HTMLParser

    class Form(HTMLParser):
        def __init__(self):
            super().__init__()
            self.forms, self.inputs = [], []

        def handle_starttag(self, tag, attrs):
            if tag == 'form':
                self.forms.append(dict(attrs))
            if tag == 'input':
                self.inputs.append(dict(attrs))

    observed = _pair_dialog_scenario('pending', mode)
    parser = Form(); parser.feed(observed['markup'])
    assert len(parser.forms) == 1
    form = parser.forms[0]
    configured = observed['elements']['#' + form['id']]
    assert configured.get('action', form.get('action')) == 'https://www.cryptolabs.co.za/?clai_pair=1'
    assert form['method'].lower() == 'post' and form['target'] == '_blank'
    assert 'noopener' in form['rel'].split()
    fields = {field['name']: observed['elements'].get('#' + field.get('id', ''), {}).get(
        'value', field.get('value')) for field in parser.inputs}
    assert fields == {'action': 'begin', 'user_code': '01-ABCD-EFGH', 'mode': mode}
    start = next(r for r in observed['initial']['requests'] if r['url'].endswith('/start'))
    assert start['body'] == {}
    assert all('01-ABCD-EFGH' not in r['url'] for r in observed['final']['requests'])


def test_pair_dialog_rejects_unexpected_verification_destination():
    observed = _pair_dialog_scenario('bad_uri')
    assert 'attacker.example' not in json.dumps(observed['elements'])
    assert not any(delay < 300000 for delay in observed['initial']['activeTimers'])
