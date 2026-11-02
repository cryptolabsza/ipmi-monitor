# TRACEWEAVER: file-role=verification; req=REQ-AICSS-001; trace=TRACE-AICSS-001; ver=VER-AICSS-001
# TRACEWEAVER: verifies=VER-AICSS-001; req=REQ-AICSS-001; trace=TRACE-AICSS-001
"""Exercise actual Flask-rendered report handlers and CSS in isolated Chromium.

Only HTTP responses and unrelated dashboard startup are substituted. No report
formatter/sanitizer is mirrored here. Four browser batches cover all report
paths at dark/light desktop/mobile sizes; the browser is a verification tool,
not a production dependency. Set IPMI_AICSS_CHROMIUM for another installation.
"""
from html import unescape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from threading import Thread

import pytest


CHROMIUM = Path.home() / 'Library/Caches/ms-playwright/chromium_headless_shell-1234/chrome-headless-shell-mac-arm64/chrome-headless-shell'

# The body rule is the generic rule observed in the actual saved report, with
# customer content replaced by generic readable markup.
LEGACY = '''<style>body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 900px; margin: 0 auto; padding: 20px; }</style>
<h2>Report retained</h2><p>Readable <strong>bold</strong> text.</p>
<ul><li>Host check</li></ul><table><tr><td>Host 1</td></tr></table>
<a href="https://example.test/report">Safe link</a>
<a href="/report">Relative link</a><a href="#details">Section link</a>
<a href="file:///report">File link</a>
<a href="javascript:window.fixtureActive=true">Unsafe link</a>'''

HARNESS = r'''
const fixtureResults = [], fixtureErrors = [];
const apiUrl = path => '/ipmi' + path, BASE_PATH = '/ipmi';
const aiEnabled = true, useAiEmbeds = false;
const getSelectedDevices = () => [];
let fixtureResponse = {};
const fetch = async () => ({ok:true,json:async()=>fixtureResponse});
const snapshot = () => {
 const body = getComputedStyle(document.body);
 const container = document.querySelector('.container');
 return {font:body.fontFamily,color:body.color,maxWidth:body.maxWidth,
   width:body.width,containerWidth:container.getBoundingClientRect().width};
};
const targets = ['aiSummaryContent','aiTasksContent','aiPredictionsContent'];
const reset = () => targets.forEach(id => document.getElementById(id).replaceChildren());
const inspect = (name, target, before, markup=false, text=null) => {
 const node = document.getElementById(target);
 const after = snapshot(), problems = [];
 if(JSON.stringify(before)!==JSON.stringify(after))problems.push('dashboard CSS changed');
 if(node.querySelector('style,link,script,iframe,object,embed,img,svg,math,form,input,video,audio,source,base,meta'))problems.push('active/resource/style node retained');
 if(node.querySelector('[onload],[onerror],[src],[srcset]'))problems.push('active/resource attribute retained');
 if(Array.from(node.querySelectorAll('a[href]')).some(a=>!['http:','https:'].includes(new URL(a.getAttribute('href'),location.href).protocol)))problems.push('unsafe link retained');
 if(markup && node.querySelector('[style],[class],[id],[name]'))problems.push('supplied presentation/identity attribute retained');
 if(window.fixtureActive)problems.push('active input executed');
 const safeLinks=Array.from(node.querySelectorAll('a[href]')).filter(a=>['http:','https:'].includes(new URL(a.getAttribute('href'),location.href).protocol));
 if(markup && (!node.querySelector('h2') || !node.querySelector('strong') || !node.querySelector('li') || !node.querySelector('td') || !node.textContent.includes('Report retained') || !node.textContent.includes('Host 1') || safeLinks.length!==3))problems.push('readable basic formatting/links lost');
 if(text && !node.textContent.includes(text))problems.push('structured text not retained literally');
 if(node.querySelector('.report-owned'))problems.push('input controls class');
 fixtureResults.push({name,before,after,problems,text:node.textContent});
};
async function runFixture() {
 const legacy = FIXTURE_LEGACY;
 document.documentElement.dataset.theme=FIXTURE_THEME;
 // Make the real report containers visible without changing their CSS rules.
 document.querySelectorAll('.tab-content').forEach(el=>el.style.display='block');
 for(const mode of ['cached','fresh-html','fresh-content']) {
  reset(); const before=snapshot();
  if(mode==='cached') {
   fixtureResponse={summary:{content:legacy}}; await loadCachedAiResults();
  } else {
   fixtureResponse={summary:{[mode==='fresh-html'?'html':'content']:legacy}}; await generateSummary();
  }
  inspect(mode,'aiSummaryContent',before,true);
 }
 const hostile='<style>body{max-width:777px!important;color:red!important}</style><em>literal report field</em>';
 const enumAttack='high report-owned';
 const summary={status:'warning report-owned',executive_summary:hostile,fleet_size:hostile,
  servers_healthy:hostile,servers_warning:hostile,servers_critical:hostile,event_count:hostile,time_range_hours:hostile,
  critical_issues:[{server:hostile,component:hostile,description:hostile,action:hostile}],
  warnings:[{server:hostile,description:hostile,trend:hostile}],
  recommendations:[{priority:enumAttack,text:hostile}],patterns:[hostile],positive_notes:[hostile]};
 for(const mode of ['cached-structured','fresh-structured']) {
  reset();const before=snapshot();
  fixtureResponse={summary:mode==='cached-structured'?{content:JSON.stringify(summary)}:summary};
  if(mode==='cached-structured')await loadCachedAiResults();else await generateSummary();
  inspect(mode,'aiSummaryContent',before,false,hostile);
 }
 reset();let before=snapshot();
 renderTasks([{priority:enumAttack,title:hostile,component:hostile,server:hostile,
  affected_servers:[hostile],reason:hostile,suggested_action:hostile},
  {title:'Second task',server:hostile,description:hostile}]);
 inspect('tasks','aiTasksContent',before,false,hostile);
 reset();before=snapshot();
 renderPredictions([{component:hostile,server:hostile,confidence:hostile,prediction:hostile,timeframe:hostile,warning_signs:hostile}]);
 inspect('predictions','aiPredictionsContent',before,false,hostile);
 reset();before=snapshot();
 fixtureResponse={summary:{html:legacy+'<img src="/__report_probe_image"><iframe src="/__report_probe_frame"></iframe><link rel="stylesheet" href="/__report_probe_style"><svg onload="window.fixtureActive=true"></svg><p style="color:red" class="report-owned" id="body" name="report-owned">Plain paragraph</p>'}};
 await generateSummary();
 await new Promise(resolve=>setTimeout(resolve,50));
 inspect('resource-and-attributes','aiSummaryContent',before,true);
 reset();before=snapshot();
 const serviceError='AI service error: <!doctype html><html><head><style>body { font-family: Arial, sans-serif; color: #333; max-width: 900px; }</style></head><body><h1>Service unavailable</h1></body></html>';
 fixtureResponse={error:serviceError};
 await generateSummary();
 inspect('fresh-summary-upstream-html-error','aiSummaryContent',before,false,serviceError);
 reset();
 const out=document.createElement('pre');out.id='fixture-result';
 out.textContent=JSON.stringify({results:fixtureResults,errors:fixtureErrors,
  resourceEntries:performance.getEntriesByType('resource').map(r=>r.name)});
 document.body.append(out);
}
window.addEventListener('error',event=>fixtureErrors.push(event.message));
runFixture().catch(error=>{
 const out=document.createElement('pre');out.id='fixture-result';out.textContent=JSON.stringify({fatal:String(error)});document.body.append(out);
});
'''


@pytest.fixture(scope='module')
def report_dashboard():
    # Reuse the normal app fixture once for the browser batch; scope adaptation
    # keeps database setup/teardown with its existing fixture implementation.
    from tests.conftest import app_fixture, _login_as
    fixture = app_fixture.__wrapped__()
    client, _, _, _ = next(fixture)
    _login_as(client)
    response = client.get('/')
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    try:
        next(fixture)
    except StopIteration:
        pass
    scripts = re.findall(r'<script\b[^>]*>(.*?)</script>', html, re.S)
    full = '\n'.join(scripts)
    subprocess.run(['node', '-e', 'new (require("vm").Script)(require("fs").readFileSync(0,"utf8"));'], input=full, text=True, capture_output=True, check=True)
    handlers = full[full.index('async function loadCachedAiResults()'):full.index('async function generateTasks()')]
    escape = full[full.index('function escapeHtml(text)'):full.index('async function loadStats()')]
    # Real DOM/styles stay intact. Only unrelated startup scripts and external
    # font resources are omitted. CSP prevents external access; harmless owned
    # resource probes are permitted so premature loading is observable.
    html = re.sub(r'<script\b[^>]*>.*?</script>', '', html, flags=re.S)
    html = re.sub(r'<link\b[^>]*>', '', html)
    html = html.replace('<head>', '<head><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; script-src \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\'; frame-src \'self\'; form-action \'none\'; connect-src \'none\'">', 1)
    return html, handlers, escape


@pytest.mark.parametrize('theme,width', [('dark',1440),('light',1440),('dark',390),('light',390)])
def test_reports_preserve_dashboard_css_and_readable_content(report_dashboard, tmp_path, theme, width):
    executable = os.environ.get('IPMI_AICSS_CHROMIUM') or shutil.which('chromium') or shutil.which('chromium-browser') or str(CHROMIUM)
    assert Path(executable).is_file(), 'Real Chromium required; set IPMI_AICSS_CHROMIUM (no production browser dependency).'
    html, handlers, escape = report_dashboard
    harness = HARNESS.replace('FIXTURE_LEGACY', json.dumps(LEGACY)).replace('FIXTURE_THEME', json.dumps(theme))
    page = html.replace('</body>', '<script>\n'+handlers+'\n'+escape+'\n'+harness+'\n</script></body>')
    fixture = tmp_path / 'report.html'
    fixture.write_text(page)
    probe_requests = []

    class FixtureHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != '/':
                if self.path.startswith('/__report_probe_'):
                    probe_requests.append(self.path)
                self.send_response(204)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(page.encode())

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), FixtureHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run([executable,'--headless','--disable-gpu','--no-first-run','--no-default-browser-check',
                             '--disable-background-networking','--disable-component-update','--disable-sync',
                             '--disable-extensions','--no-proxy-server','--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1',
                             '--password-store=basic','--use-mock-keychain',
                             f'--user-data-dir={tmp_path / "profile"}',f'--window-size={width},1000',
                             '--virtual-time-budget=1500','--dump-dom',f'http://127.0.0.1:{server.server_port}/'],
                            text=True,capture_output=True,timeout=30,check=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    match = re.search(r'<pre id="fixture-result">(.*?)</pre>', result.stdout, re.S)
    assert match, result.stderr[-2000:] + result.stdout[-2000:]
    observed = json.loads(unescape(match.group(1)))
    observed['probeRequests'] = probe_requests
    evidence = Path(os.environ.get('IPMI_AICSS_EVIDENCE_DIR', tmp_path))
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / f'{theme}-{width}.json').write_text(json.dumps(observed,indent=2)+'\n')
    assert not observed.get('fatal'), observed
    assert not observed['errors'], observed
    assert len(observed['results']) == 9, observed
    failures = [{'name':r['name'],'before':r['before'],'after':r['after'],'problems':r['problems']} for r in observed['results'] if r['problems']]
    if probe_requests:
        failures.append({'name':'resource-network','problems':probe_requests})
    assert not failures, json.dumps(failures,indent=2)
