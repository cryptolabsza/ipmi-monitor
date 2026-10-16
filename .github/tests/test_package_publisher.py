"""Adversarial tests for the data-only package consumer; no live uploads."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"publisher"))
import zipfile

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/"publisher"))
import package_publisher as p

PROJECT='cryptolabs-proxy';VERSION='1.2.0';SHA='a'*40

def distributions(root,project=PROJECT,version=VERSION,wheel_metadata=None,sdist_metadata=None):
    stem=project.replace('-','_')+'-'+version
    metadata=f'Metadata-Version: 2.1\nName: {project}\nVersion: {version}\n'.encode()
    wheel=root/(stem+'-py3-none-any.whl');sdist=root/(stem+'.tar.gz')
    with zipfile.ZipFile(wheel,'w') as archive:
        archive.writestr(stem+'.dist-info/METADATA',wheel_metadata or metadata)
        archive.writestr(project.replace('-','_')+'/__init__.py',b'raise RuntimeError("artifact code must never execute")')
    with tarfile.open(sdist,'w:gz') as archive:
        data=sdist_metadata or metadata;item=tarfile.TarInfo(stem+'/PKG-INFO');item.size=len(data);archive.addfile(item,io.BytesIO(data))
        data=b'raise RuntimeError("sdist installer must never execute")';item=tarfile.TarInfo(stem+'/setup.py');item.size=len(data);archive.addfile(item,io.BytesIO(data))
    sums=''.join(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.name+'\n' for path in [wheel,sdist])
    (root/'SHA256SUMS').write_text(sums)
    return wheel,sdist

class Client:
    def __init__(self):
        self.source={'name':PROJECT,'version':VERSION};self.sha=SHA;self.release_data={'id':123,'tag_name':'v'+VERSION,'draft':False,'assets':[]};self.pypi_data=None;self.downloads={};self.calls=[]
    def source_project(self,sha):return self.source
    def tag_commit(self,tag):return self.sha
    def release(self,tag):return self.release_data
    def pypi(self,project,version):return self.pypi_data
    def download(self,url):return self.downloads[url]
    def upload_pypi(self,paths):self.calls.append(('pypi',[path.name for path in paths]))
    def upload_github(self,tag,paths):self.calls.append(('github',[path.name for path in paths]))

class PackagePublisherTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);distributions(self.root);self.client=Client();self.proof={'head_sha':SHA,'branch':'main','repository':'cryptolabsza/'+PROJECT};self.release_event={'name':'release','sha':SHA,'event':{'action':'published','release':{'tag_name':'v'+VERSION,'draft':False}}}
    def plan(self,mirror=True,event=None):return p.prepare(PROJECT,self.root,self.proof,event or self.release_event,self.client,mirror_github=mirror)
    def test_real_wheel_sdist_bytes_and_checksums_are_inspected_without_execution(self):
        plan=self.plan();self.assertEqual(plan['version'],VERSION);self.assertEqual(len(plan['artifacts']),2);self.assertEqual(plan['source_sha'],SHA)
        for item in plan['artifacts']:self.assertEqual(item['sha256'],hashlib.sha256((self.root/item['filename']).read_bytes()).hexdigest())
    def test_changed_checksums_project_version_or_extra_output_refuse(self):
        for mode in ['checksum','project','version','extra']:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);distributions(root,project='wrong-project' if mode=='project' else PROJECT,version='9.9.9' if mode=='version' else VERSION)
                if mode=='checksum':(root/'SHA256SUMS').write_text('0'*64+'  missing.whl\n')
                if mode=='extra':(root/'extra.py').write_text('raise RuntimeError()')
                with self.assertRaises(p.Held):p.prepare(PROJECT,root,self.proof,self.release_event,self.client,mirror_github=True)
    def test_wheel_and_sdist_metadata_must_both_match(self):
        for kind in ['wheel','sdist']:
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);distributions(root,**{kind+'_metadata':b'Name: attacker\nVersion: 1.2.0\n'})
                with self.assertRaises(p.Held):p.prepare(PROJECT,root,self.proof,self.release_event,self.client,mirror_github=True)
    def test_published_tag_source_project_and_event_semantics_are_all_required(self):
        for mode in ['tag','source','draft','event','event-sha','version','tag-input','partial-ids']:
            with self.subTest(mode=mode):
                client=Client();event=json.loads(json.dumps(self.release_event))
                if mode=='tag':client.sha='b'*40
                if mode=='source':client.source['version']='9.9.9'
                if mode=='draft':client.release_data['draft']=True
                if mode=='event':event['name']='pull_request_target'
                if mode=='event-sha':event['sha']='b'*40
                if mode in ('version','tag-input','partial-ids'):
                    event={'name':'workflow_dispatch','sha':SHA,'event':{'inputs':{'release_tag':'v'+VERSION,'version':VERSION}}}
                    event['event']['inputs'].update({'version':'9.9.9'} if mode=='version' else {'release_tag':'v9.9.9'} if mode=='tag-input' else {'producer_run_id':'123'})
                with self.assertRaises(p.Held):p.prepare(PROJECT,self.root,self.proof,event,client,mirror_github=True)
                self.assertEqual(client.calls,[])
    def test_main_producer_preserves_dc_release_build_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);distributions(root,project='dc-overview');client=Client();client.source['name']='dc-overview'
            proof={**self.proof,'repository':'cryptolabsza/dc-overview'}
            self.assertEqual(p.prepare('dc-overview',root,proof,self.release_event,client,mirror_github=True)['project'],'dc-overview')
            with self.assertRaises(p.Held):p.prepare('dc-overview',root,{**proof,'branch':'dev'},self.release_event,client,mirror_github=True)
    def test_manual_version_tag_matches_and_missing_version_remains_supported(self):
        event={'name':'workflow_dispatch','sha':'b'*40,'event':{'inputs':{'release_tag':'v'+VERSION,'version':VERSION}}}
        self.assertEqual(self.plan(event=event)['tag'],'v'+VERSION)
        # Legacy IPMI/SRE manual version input is optional; derive it from verified
        # package/source data and still require a real published matching tag.
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);distributions(root,project='ipmi-monitor');c=Client();c.source['name']='ipmi-monitor'
            proof={**self.proof,'repository':'cryptolabsza/ipmi-monitor'}
            plan=p.prepare('ipmi-monitor',root,proof,{'name':'workflow_dispatch','sha':SHA,'event':{'inputs':{}}},c,mirror_github=False)
            self.assertEqual(plan['version'],VERSION)
    def test_conflicting_existing_destinations_refuse_before_any_upload(self):
        for destination in ['pypi','github']:
            with self.subTest(destination=destination):
                client=Client();plan=self.plan();item=plan['artifacts'][0]
                if destination=='pypi':client.pypi_data={'info':{'name':PROJECT,'version':VERSION},'urls':[{'filename':item['filename'],'url':'https://evil.invalid/file','digests':{'sha256':item['sha256']},'size':item['size'],'yanked':False}]}
                else:client.release_data['assets']=[{'name':item['filename'],'size':item['size'],'browser_download_url':'https://evil.invalid/file'}]
                with self.assertRaises(p.Held):p.publish(plan,self.root,client,attempts=1)
                self.assertEqual(client.calls,[])
    def test_existing_files_require_actual_bytes_not_only_matching_metadata(self):
        plan=self.plan();item=plan['artifacts'][0];url='https://files.pythonhosted.org/packages/'+item['filename'];self.client.downloads[url]=b'wrong'
        self.client.pypi_data={'info':{'name':PROJECT,'version':VERSION},'urls':[{'filename':item['filename'],'url':url,'digests':{'sha256':item['sha256']},'size':item['size'],'yanked':False}]}
        with self.assertRaises(p.Held):p.publish(plan,self.root,self.client,attempts=1)
        self.assertEqual(self.client.calls,[])
    def test_success_requires_independent_both_destination_readback_and_never_rebuilds(self):
        plan=self.plan();client=self.client
        def pypi(paths):
            client.calls.append(('pypi',[x.name for x in paths]));records=[]
            for item in plan['artifacts']:
                url='https://files.pythonhosted.org/packages/'+item['filename'];client.downloads[url]=(self.root/item['filename']).read_bytes();records.append({'filename':item['filename'],'url':url,'digests':{'sha256':item['sha256']},'size':item['size'],'yanked':False})
            client.pypi_data={'info':{'name':PROJECT,'version':VERSION},'urls':records}
        def github(tag,paths):
            client.calls.append(('github',[x.name for x in paths]))
            for path in paths:
                url='https://github.com/cryptolabsza/'+PROJECT+'/releases/download/'+tag+'/'+path.name;client.downloads[url]=path.read_bytes();client.release_data['assets'].append({'name':path.name,'size':path.stat().st_size,'browser_download_url':url})
        client.upload_pypi=pypi;client.upload_github=github
        self.assertEqual(p.publish(plan,self.root,client,attempts=1)['status'],'verified')
        self.assertEqual([x[0] for x in client.calls],['pypi','github'])
        self.assertEqual(p.publish(plan,self.root,client,attempts=1)['status'],'verified')
        self.assertEqual(len(client.calls),2)
    def test_no_success_when_upload_response_has_no_independent_readback(self):
        with self.assertRaises(p.Held):p.publish(self.plan(),self.root,self.client,attempts=1)
    def test_byte_or_tag_drift_before_upload_refuses(self):
        plan=self.plan();(self.root/plan['artifacts'][0]['filename']).write_bytes(b'changed')
        with self.assertRaises(p.Held):p.publish(plan,self.root,self.client,attempts=1)
        self.assertEqual(self.client.calls,[])


if __name__=='__main__':unittest.main()
