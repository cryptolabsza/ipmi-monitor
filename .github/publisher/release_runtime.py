"""Fixed API/tool client for the immutable artifact-only publisher leaf."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time
import tomllib
import zipfile
from urllib.error import HTTPError,URLError
from urllib.parse import quote,urlsplit
from urllib.request import urlopen

import verify_artifact as v
import package_publisher as package
Held=package.Held
require=package.require
PROJECT_FILES={'cryptolabsza/cryptolabs-proxy':'pyproject.toml','cryptolabsza/dc-overview':'pyproject.toml',
               'cryptolabsza/ipmi-monitor':'pyproject.toml','cryptolabsza/sre.ai':'services/sre-agent/pyproject.toml'}

class Client:
    def __init__(self,repository,project_file):
        require(PROJECT_FILES.get(repository)==project_file,'fixed repository project path')
        self.repository=repository;self.project_file=project_file
    def api(self,path):return v.gh_json('/repos/'+self.repository+'/'+path)
    def source_project(self,sha):
        require(v.sha(sha),'source SHA')
        value=self.api('contents/'+self.project_file+'?ref='+sha)
        require(value['type']=='file' and value['encoding']=='base64' and 0<value['size']<=package.MAX_METADATA,'source TOML file bound')
        content=base64.b64decode(''.join(value['content'].split()),validate=True)
        require(len(content)<=package.MAX_METADATA,'source TOML data bound')
        project=tomllib.loads(content.decode())['project']
        return {'name':project['name'],'version':project['version']}
    def tag_commit(self,tag):
        require(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+',tag) is not None,'release tag')
        value=self.api('git/ref/tags/'+quote(tag,safe=''))['object']
        for _ in range(5):
            require(v.sha(value['sha']),'tag object SHA')
            if value['type']=='commit':return value['sha']
            require(value['type']=='tag','tag object type');value=self.api('git/tags/'+value['sha'])['object']
        raise Held('tag peeling bound')
    def release(self,tag):
        require(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+',tag) is not None,'release tag')
        release=self.api('releases/tags/'+tag);require(v.positive(release['id']),'release ID')
        release['assets']=[]
        for page in range(1,11):
            batch=self.api(f'releases/{release["id"]}/assets?per_page=100&page={page}')
            require(type(batch)is list and len(batch)<=100,'release assets shape');release['assets'].extend(batch)
            if len(batch)<100:return release
        raise Held('release assets pagination bound')
    def producer_runs(self,policy,sha):
        require(policy.repository==self.repository and v.sha(sha),'producer discovery identity')
        filename=policy.workflow_path.rsplit('/',1)[1]
        data=self.api('actions/workflows/'+filename+'/runs?head_sha='+sha+'&status=success&per_page=100')
        require(type(data['workflow_runs'])is list and len(data['workflow_runs'])==data['total_count']<=100,'producer discovery pagination bound')
        return data['workflow_runs']
    def artifacts(self,run_id):
        require(v.positive(run_id),'producer run ID')
        return v.pages(v.gh_json,'/repos/'+self.repository+f'/actions/runs/{run_id}/artifacts','artifacts')
    @staticmethod
    def download(url,maximum=package.MAX_FILE):
        require(urlsplit(url).scheme=='https' and urlsplit(url).netloc in {'pypi.org','files.pythonhosted.org','github.com'},'fixed download host')
        try:
            deadline=time.monotonic()+120;data=bytearray()
            with urlopen(url,timeout=30) as response:
                while chunk:=response.read(64*1024):
                    require(time.monotonic()<deadline and len(data)+len(chunk)<=maximum,'destination download bound');data.extend(chunk)
            return bytes(data)
        except HTTPError:raise
        except (URLError,OSError):raise Held('destination download unavailable') from None
    def pypi(self,project,version):
        require(package.PROJECTS.get(project)==self.repository and package.VERSION.fullmatch(version),'fixed PyPI project/version')
        try:return json.loads(self.download('https://pypi.org/pypi/'+project+'/'+version+'/json',package.MAX_METADATA))
        except HTTPError as error:
            if error.code==404:return None
            raise Held('PyPI metadata unavailable') from None
    @staticmethod
    def run(command):
        result=subprocess.run(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=300,check=False)
        require(result.returncode==0,'publication tool failed')
    def upload_pypi(self,paths):
        require(bool(os.environ.get('TWINE_PASSWORD')),'PyPI credential unavailable')
        self.run([sys.executable,'-m','twine','upload','--non-interactive','--disable-progress-bar',
                  '--config-file','/dev/null','--repository-url','https://upload.pypi.org/legacy/',*map(str,paths)])
    def upload_github(self,tag,paths):
        require(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+',tag) is not None,'release tag')
        self.run(['/tmp/ci-publish-tools/gh','release','upload',tag,'--repo',self.repository,*map(str,paths)])

def resolve_ids(policy,client,event,values):
    require(event['name'] in {'release','workflow_dispatch'},'release event')
    inputs=event['event'].get('inputs',{})
    require(type(inputs)is dict,'manual inputs shape')
    raw=[inputs.get(k) for k in ('producer_run_id','producer_attempt','artifact_id')]
    require(sum(bool(x) for x in raw) in {0,3},'all three producer IDs required')
    require(len(values)==3 and sum(bool(x) for x in values) in {0,3},'all three producer IDs required')
    if all(values):
        require(all(type(x)is str and re.fullmatch('[1-9][0-9]{0,19}',x) for x in values),'numeric producer IDs')
        return tuple(map(int,values))
    tag=event['event'].get('release',{}).get('tag_name') if event['name']=='release' else inputs.get('release_tag')
    if not tag:
        version=inputs.get('version') or client.source_project(event['sha'])['version'];tag='v'+version
    require(type(tag)is str and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+',tag) is not None,'release tag')
    release=client.release(tag)
    require(release.get('tag_name')==tag and release.get('draft')is False,'published release required')
    sha=client.tag_commit(tag)
    runs=[run for run in client.producer_runs(policy,sha) if run['head_sha']==sha and run['head_branch']=='main'
          and run['event'] in {'push','workflow_dispatch'} and run['status']=='completed' and run['conclusion']=='success']
    require(runs and all(v.positive(x['id']) and v.positive(x['run_attempt']) for x in runs),'matching protected producer absent')
    run=max(runs,key=lambda x:x['id'])
    name=f'{policy.artifact_stem}-{run["id"]}-{run["run_attempt"]}'
    artifacts=[a for a in client.artifacts(run['id']) if a['name']==name and a['expired']is False]
    require(len(artifacts)==1 and v.positive(artifacts[0]['id']),'unique producer artifact absent')
    return run['id'],run['run_attempt'],artifacts[0]['id']

def main(argv=None):
    # This module is checked out only with these literal reviewed policy files.
    # The caller and artifact have no policy/ref/repository CLI or env option.
    from policy import POLICY,PROJECT,PROJECT_FILE,MIRROR_GITHUB
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('command',choices=['verify','upload']);parser.add_argument('ids',nargs='*');args=parser.parse_args(argv)
    event={'name':os.environ['GITHUB_EVENT_NAME'],'sha':os.environ['GITHUB_SHA'],'event':json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())}
    client=Client(POLICY.repository,PROJECT_FILE);planfile=v.OUTPUT/'publication-plan.json'
    try:
        require(os.environ.get('GITHUB_REPOSITORY')==POLICY.repository,'publisher repository')
        if args.command=='verify':
            ids=resolve_ids(POLICY,client,event,args.ids);proof=v.verify(POLICY,*ids)
            plan=package.prepare(PROJECT,v.OUTPUT/'files',proof,event,client,mirror_github=MIRROR_GITHUB)
            planfile.write_text(json.dumps({'ids':ids,'proof':proof,'plan':plan},sort_keys=True)+'\n')
            print(json.dumps({'status':'verified-producer','run_id':ids[0],'attempt':ids[1],'artifact_id':ids[2],'tag':plan['tag']},sort_keys=True))
        else:
            require(not args.ids,'upload has no dynamic policy/paths');saved=json.loads(planfile.read_text());ids=saved['ids']
            require(len(ids)==3 and all(v.positive(x) for x in ids),'verified IDs')
            current=v.verify_metadata(v.gh_json,POLICY,*ids)
            require(all(saved['proof'].get(k)==value for k,value in current.items()),'producer changed before upload')
            plan=package.prepare(PROJECT,v.OUTPUT/'files',current,event,client,mirror_github=MIRROR_GITHUB)
            require(plan==saved['plan'],'publication data changed')
            receipt=package.publish(plan,v.OUTPUT/'files',client)
            (v.OUTPUT/'publication-receipt.json').write_text(json.dumps(receipt,sort_keys=True)+'\n')
            print(json.dumps({'status':'verified','project':PROJECT,'version':receipt['version'],'tag':receipt['tag']},sort_keys=True))
        return 0
    except (Held,v.Refused,KeyError,TypeError,ValueError,OSError,RuntimeError,subprocess.SubprocessError,zipfile.BadZipFile,tarfile.TarError):
        print('Publication held: producer, package or destination verification failed; no verified receipt.',file=sys.stderr);return 1

if __name__=='__main__':sys.exit(main())
