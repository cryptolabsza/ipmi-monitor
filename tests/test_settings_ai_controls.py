# TRACEWEAVER: file-role=ipmi-monitor-verification; req=REQ-IPMI-MON-02; trace=TRACE-IPMI-MON-02; ver=VER-IPMI-MON-02
# TRACEWEAVER: verifies=VER-IPMI-MON-02; req=REQ-IPMI-MON-02; trace=TRACE-IPMI-MON-02
"""Execute the real rendered Settings handlers with only DOM/HTTP boundaries replaced."""
from html.parser import HTMLParser
import json
import subprocess

import pytest


class Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.active = False
        self.text = []

    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            self.active = True

    def handle_endtag(self, tag):
        if tag == 'script':
            self.active = False

    def handle_data(self, data):
        if self.active:
            self.text.append(data)


@pytest.mark.parametrize('control', ['test', 'disconnect', 'apply', 'sync', 'status'])
def test_rendered_ai_controls_use_mounted_endpoints_and_report_results(app_fixture, login_as, monkeypatch, control):
    client, app, db, models = app_fixture
    import ipmi_monitor.app as runtime
    monkeypatch.setattr(runtime, 'APPLICATION_ROOT', '/ipmi')
    login_as(client)
    response = client.get('/settings')
    assert response.status_code == 200
    parser = Scripts()
    parser.feed(response.get_data(as_text=True))
    script = '\n'.join(parser.text)
    prefix = script[:script.index('// Theme management')]
    controls = script[script.index('// Toggle API key visibility'):script.index('// ============== Email Alerts')]
    ui = script[script.index('async function updateAiUI(config)'):script.index('// Signup uses')]
    harness = r'''
const vm = require('vm');
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
new vm.Script(input.full); // Full rendered script must parse, including Jinja output.
const elements = {};
const document = {getElementById(id) { return elements[id] ||= {value:'',checked:false,style:{}}; }};
document.getElementById('aiLicenseKeyManual').value = '  isolated-manual-key  ';
const requests = [], alerts = [], statuses = [];
const showAlert = (message,type) => alerts.push({message,type});
const confirm = () => true, updateAiUI = () => {};
let aiSyncInProgress = false;
const fetch = async (url, options={}) => {
 const method = options.method || 'GET';
 requests.push({url, method, body:options.body ? JSON.parse(options.body) : null});
 if (method === 'PUT' && input.control === 'disconnect')
  return {ok:false,status:401,json:async()=>({error:'Admin authentication required'})};
 if (String(url).endsWith('/api/ai/config') && method === 'GET')
  return {ok:true,status:200,json:async()=>({license_key:'***test',sync_enabled:true})};
 return {ok:true,status:200,json:async()=>({valid:true,tier:'standard',max_servers:10,
  status:'success',success:true,message:'isolated sync complete'})};
};
eval(input.prefix + input.controls);
(async () => {
 if(input.control==='test') await testAiConnection();
 if(input.control==='disconnect') await disconnectAi();
 if(input.control==='apply') applyManualKey();
 if(input.control==='sync') await triggerAiSync();
 if(input.control==='status') {
  const renderStatus = eval('(' + input.ui.trim() + ')');
  for (const last_sync_status of ['error', null]) {
   await renderStatus({subscription_valid:true,license_key:'***test',sync_enabled:true,
     subscription_tier:'standard',max_servers:10,last_sync:'2026-10-26T12:00:00Z',last_sync_status});
   statuses.push({label:document.getElementById('aiSyncStatus').textContent,
     result:document.getElementById('aiLastSyncResult').textContent});
  }
 }
 await new Promise(resolve => setImmediate(resolve));
 console.log(JSON.stringify({requests,alerts,statuses}));
})().catch(error=>{console.error(error);process.exit(1);});
'''
    result = subprocess.run(['node', '-e', harness], input=json.dumps({
        'full': script, 'prefix': prefix, 'controls': controls, 'control': control, 'ui': ui,
    }), text=True, capture_output=True, check=True)
    observed = json.loads(result.stdout)
    if control == 'test':
        posts = [r for r in observed['requests'] if r['method'] == 'POST']
        assert posts == [{'url': '/ipmi/api/ai/test', 'method': 'POST', 'body': {}}]
        assert observed['alerts'][-1]['type'] == 'success'
    elif control == 'disconnect':
        assert observed['requests'][0]['url'] == '/ipmi/api/ai/config'
        assert observed['requests'][0]['body'] == {'license_key': '', 'sync_enabled': False}
        assert observed['alerts'] == [{'message': 'Admin authentication required', 'type': 'error'}]
    elif control == 'apply':
        assert observed['requests'][0]['url'] == '/ipmi/api/ai/config'
        assert observed['requests'][0]['body']['license_key'] == 'isolated-manual-key'
        assert observed['requests'][0]['body']['sync_enabled'] is True
        assert observed['alerts'][-1]['type'] == 'success'
    elif control == 'sync':
        assert observed['requests'][0]['url'] == '/ipmi/api/ai/sync'
        assert observed['requests'][0]['method'] == 'POST'
        assert observed['alerts'][-1]['type'] == 'success'
    else:
        assert observed['statuses'] == [
            {'label': '✅ Sync enabled', 'result': 'error'},
            {'label': '✅ Sync enabled', 'result': 'Status unavailable'},
        ]
        assert '>✅ Sync enabled</span>' in response.get_data(as_text=True)


@pytest.mark.parametrize('subscription_valid', [False, True])
def test_saved_account_remains_visible_when_service_is_unavailable_or_paused(app_fixture, login_as, subscription_valid):
    client, _, _, _ = app_fixture
    login_as(client)
    parser = Scripts(); parser.feed(client.get('/settings').get_data(as_text=True))
    script = '\n'.join(parser.text)
    ui = script[script.index('async function updateAiUI(config)'):script.index('// Signup uses')]
    harness = r'''
const elements={};
let aiSyncInProgress=false;
const document={getElementById:id=>elements[id]||=( {style:{},textContent:''} )};
const apiUrl=path=>'/ipmi'+path;
const fetch=async()=>({ok:true,json:async()=>({servers:[]})});
'''
    invocation = r'''
(async()=>{
 await updateAiUI({license_key:'***stored',subscription_valid:SUBSCRIPTION_VALID,sync_enabled:false,
  linked_account_status:'verified',linked_account:{wp_user_id:71,wp_email:'saved@example.test'}});
 console.log(JSON.stringify(elements));
})().catch(error=>{console.error(error);process.exit(1);});
'''.replace('SUBSCRIPTION_VALID', json.dumps(subscription_valid))
    result = subprocess.run(['node', '-e', harness + ui + invocation],
                            text=True, capture_output=True, check=True)
    observed = json.loads(result.stdout)
    assert observed['aiConnectedSection']['style']['display'] == 'block'
    assert observed['linkedAccountSection']['style']['display'] == 'block'
    assert observed['linkedAccountEmail']['textContent'] == 'saved@example.test'
    assert ('paused' if subscription_valid else 'unavailable') in observed['aiStatusMessage']['textContent'].lower()
    assert observed['aiTrialBanner']['style']['display'] == 'none'
    assert observed['aiSyncRetry']['disabled'] is True


@pytest.mark.parametrize('sync_ok', [True, False])
def test_connect_starts_first_sync_and_reports_result(app_fixture, login_as, sync_ok):
    client, _, _, _ = app_fixture
    login_as(client)
    parser = Scripts(); parser.feed(client.get('/settings').get_data(as_text=True))
    script = '\n'.join(parser.text)
    pairing = script[script.index('// Signup uses'):script.index('// ============== Email Alerts')]
    harness = r'''
const vm = require('vm');
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const nodes = {}, timers = [], requests = [], alerts = [];
let syncOk = input.sync_ok;
const node = id => nodes[id] ||= {style:{},disabled:false,textContent:'',
 setAttribute(){},focus(){},addEventListener(){},showModal(){},close(){},remove(){},
 querySelector(selector){return node(selector.slice(1));}};
const document = {getElementById:id=>id==='accountPairDialog'?null:node(id),
 createElement:()=>node('dialog'),body:{appendChild(){}}};
const apiUrl = path => '/ipmi'+path;
const showAlert = (message,type)=>alerts.push({message,type});
const setTimeout = (fn,ms)=>{timers.push({fn,ms});return timers.length;};
const clearTimeout = ()=>{};
const fetch = async (url,options={})=>{
 requests.push(url);
 let body = {};
 if(url.endsWith('/account-link/config')) body={csrf_token:'synthetic-csrf'};
 if(url.endsWith('/start')) body={attempt_id:'synthetic-attempt',user_code:'1N-CTP7-3JSZ',
   verification_uri:'https://www.cryptolabs.co.za/?clai_pair=1',expires_in:300,interval:5};
 if(url.endsWith('/status')) body={status:'awaiting_confirmation',can_commit:true,
   account:{id:71,email:'owner@example.test'},service_status:'available'};
 if(url.endsWith('/commit')) body={status:'linked',account:{id:71,email:'owner@example.test'},service_status:'available'};
 if(url.endsWith('/sync')) body={success:syncOk,message:syncOk?'9 servers synced':'Service temporarily unavailable'};
 return {ok:true,status:200,json:async()=>body};
};
eval(input.script);
loadAiConfig = async()=>{};
(async()=>{
 await loginWithCryptoLabs();
 await timers.find(t=>t.ms===5000).fn();
 await node('pairConfirm').onclick();
 const first = JSON.parse(JSON.stringify(nodes));
 if(!input.sync_ok) {syncOk=true;await node('aiSyncRetry').onclick();}
 console.log(JSON.stringify({requests,alerts,nodes,first}));
})().catch(e=>{console.error(e);process.exit(1);});
'''
    result = subprocess.run(['node', '-e', harness], input=json.dumps({'script': pairing, 'sync_ok': sync_ok}),
                            text=True, capture_output=True, check=True)
    observed = json.loads(result.stdout)
    assert observed['requests'].count('/ipmi/api/account-link/commit') == 1
    assert observed['requests'].count('/ipmi/api/ai/sync') == (1 if sync_ok else 2)
    assert observed['requests'].index('/ipmi/api/ai/sync') > observed['requests'].index('/ipmi/api/account-link/commit')
    message = observed['first']['aiConnectionProgress']['textContent']
    assert ('AI ready' in message) if sync_ok else ('Service temporarily unavailable' in message)
    assert observed['first']['aiSyncRetry']['hidden'] is sync_ok
    assert 'AI ready' in observed['nodes']['aiConnectionProgress']['textContent']


@pytest.mark.parametrize('state', ['paused', 'unavailable', 'error', 'http-error'])
def test_dashboard_never_advertises_trial_for_paused_link_or_status_error(app_fixture, login_as, state):
    client, _, _, _ = app_fixture
    login_as(client)
    parser = Scripts(); parser.feed(client.get('/').get_data(as_text=True))
    script = '\n'.join(parser.text)
    status = script[script.index('async function loadAiStatus()'):script.index('function updateSyncStatus(data)')]
    harness = r'''
const input=JSON.parse(require('fs').readFileSync(0,'utf8'));
const nodes={};
const document={getElementById:id=>nodes[id]||={style:{},dataset:{},classList:{add(){},remove(){}}}};
let aiEnabled=false;
const apiUrl=path=>'/ipmi'+path, serversData=[];
const getTierDisplayName=t=>t.toUpperCase(),getTierClass=t=>t;
const updateSyncStatus=()=>{},loadCachedAiResults=()=>{};
const fetch=async()=>{if(input.state==='error')throw Error('Offline');
 return {ok:input.state!=='http-error',json:async()=>({has_license:true,enabled:false,
 subscription_valid:input.state==='paused',subscription_tier:'enterprise',max_servers:-1})};};
eval(input.script);
(async()=>{await loadAiStatus();console.log(JSON.stringify(nodes));})()
 .catch(e=>{console.error(e);process.exit(1);});
'''
    result = subprocess.run(['node', '-e', harness], input=json.dumps({'script': status, 'state': state}),
                            text=True, capture_output=True, check=True)
    observed = json.loads(result.stdout)
    assert observed['aiUpgradePrompt']['style']['display'] == 'none'
    assert observed['aiBadge']['textContent'] != 'FREE'
    assert observed['aiAccountNotice']['textContent']
