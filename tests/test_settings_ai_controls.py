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
