"""Fixed producer discovery and official publication tools without network writes."""
import base64
import json
from pathlib import Path
import tempfile
import contextlib
import io
import os
import sys
from types import SimpleNamespace
import unittest
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"publisher"))
from unittest.mock import patch
import release_runtime as r
from verify_artifact import Policy

SHA='a'*40
POLICY=Policy('cryptolabsza/cryptolabs-proxy',1140353276,'.github/workflows/publish.yml',
              'cryptolabsza/cryptolabs-proxy/.github/workflows/ci-python-build-recipe.yml@'+'b'*40,
              'cpu-build / build',11,'ci-linux-cpu-v1-r1140353276','pypi','cpu-python')

class Producer:
 def __init__(self):
  self.runs=[{'id':123,'run_attempt':2,'head_sha':SHA,'head_branch':'main','event':'push','status':'completed','conclusion':'success'}]
  self.assets=[{'id':456,'name':'cpu-python-123-2','expired':False}]
 def producer_runs(self,policy,sha):return self.runs
 def artifacts(self,run):return self.assets
 def tag_commit(self,tag):return SHA
 def release(self,tag):return {'id':22,'tag_name':tag,'draft':False}
 def source_project(self,sha):return {'name':'cryptolabs-proxy','version':'1.2.0'}

class ReleaseRuntimeTest(unittest.TestCase):
 def setUp(self):
  self.event={'name':'release','sha':SHA,'event':{'action':'published','release':{'tag_name':'v1.2.0','draft':False}}}
 def test_automatic_release_selects_actual_exact_commit_attempt_artifact(self):
  self.assertEqual(r.resolve_ids(POLICY,Producer(),self.event,['','','']),(123,2,456))
 def test_dynamic_ids_are_only_three_positive_numbers(self):
  self.assertEqual(r.resolve_ids(POLICY,Producer(),self.event,['123','2','456']),(123,2,456))
  for ids in [['123','','456'],['0','2','456'],['123','-1','456'],['true','2','456'],['1;echo','2','456']]:
   with self.subTest(ids=ids),self.assertRaises(r.Held):r.resolve_ids(POLICY,Producer(),self.event,ids)
 def test_wrong_commit_pr_branch_failed_or_ambiguous_artifact_has_no_fallback(self):
  for mode in ['sha','branch','event','failed','duplicate','expired','name','no-runs']:
   p=Producer()
   if mode=='sha':p.runs[0]['head_sha']='c'*40
   if mode=='branch':p.runs[0]['head_branch']='arbitrary'
   if mode=='event':p.runs[0]['event']='pull_request'
   if mode=='failed':p.runs[0]['conclusion']='failure'
   if mode=='duplicate':p.assets.append(dict(p.assets[0]))
   if mode=='expired':p.assets[0]['expired']=True
   if mode=='name':p.assets[0]['name']='caller-selected'
   if mode=='no-runs':p.runs=[]
   with self.subTest(mode=mode),self.assertRaises(r.Held):r.resolve_ids(POLICY,p,self.event,['','',''])
 def test_newest_producer_is_deterministic_and_never_silently_falls_back(self):
  p=Producer();p.runs.append({**p.runs[0],'id':124});p.assets[0]['name']='cpu-python-124-2'
  self.assertEqual(r.resolve_ids(POLICY,p,self.event,['','','']),(124,2,456))
  p.assets=[]
  with self.assertRaises(r.Held):r.resolve_ids(POLICY,p,self.event,['','',''])
 def test_manual_existing_tag_version_or_optional_version_uses_data_only(self):
  for inputs in [{'release_tag':'v1.2.0','version':'1.2.0'},{'version':'1.2.0'},{}]:
   event={'name':'workflow_dispatch','sha':SHA,'event':{'inputs':inputs}}
   self.assertEqual(r.resolve_ids(POLICY,Producer(),event,['','','']),(123,2,456))
 def test_arbitrary_event_tag_and_partial_user_ids_refuse(self):
  for event in [{'name':'repository_dispatch','sha':SHA,'event':{}},
                {'name':'workflow_dispatch','sha':SHA,'event':{'inputs':{'release_tag':'../../main'}}},
                {'name':'workflow_dispatch','sha':SHA,'event':{'inputs':{'producer_run_id':'1'}}}]:
   with self.subTest(event=event),self.assertRaises(r.Held):r.resolve_ids(POLICY,Producer(),event,['','',''])
 def test_source_toml_is_fetched_at_verified_sha_from_fixed_path(self):
  client=r.Client('cryptolabsza/cryptolabs-proxy','pyproject.toml')
  body={'type':'file','size':100,'encoding':'base64','content':base64.b64encode(b'[project]\nname="cryptolabs-proxy"\nversion="1.2.0"\n').decode()}
  with patch.object(r.v,'gh_json',return_value=body) as api:
   self.assertEqual(client.source_project(SHA),{'name':'cryptolabs-proxy','version':'1.2.0'})
   self.assertEqual(api.call_args.args[0],'/repos/cryptolabsza/cryptolabs-proxy/contents/pyproject.toml?ref='+SHA)
  with self.assertRaises(r.Held):r.Client('attacker/repo','setup.py')
 def test_upload_commands_use_only_fixed_endpoints_and_explicit_files(self):
  client=r.Client('cryptolabsza/cryptolabs-proxy','pyproject.toml');paths=[Path('/verified/a.whl'),Path('/verified/a.tar.gz')]
  with patch.object(r.subprocess,'run') as run:
   run.return_value.returncode=0
   with patch.dict(r.os.environ,{'TWINE_PASSWORD':'fixture-only'}):client.upload_pypi(paths)
   command=run.call_args.args[0]
   self.assertEqual(command[command.index('--repository-url')+1],'https://upload.pypi.org/legacy/')
   self.assertEqual(command[-2:],list(map(str,paths)))
   self.assertNotIn('--skip-existing',command)
   client.upload_github('v1.2.0',paths)
   command=run.call_args.args[0]
   self.assertEqual(command[:6],['/tmp/ci-publish-tools/gh','release','upload','v1.2.0','--repo','cryptolabsza/cryptolabs-proxy'])
   self.assertNotIn('--clobber',command)
 def test_upload_failure_diagnostics_never_expose_tool_stderr(self):
  client=r.Client('cryptolabsza/cryptolabs-proxy','pyproject.toml')
  with patch.object(r.subprocess,'run') as run:
   run.return_value.returncode=1;run.return_value.stderr=b'fixture-token-do-not-print'
   with self.assertRaises(r.Held) as error:client.upload_github('v1.2.0',[Path('/verified/a.whl')])
  self.assertNotIn('fixture-token',str(error.exception))
 def test_main_refuses_bad_ids_with_sanitized_failure_and_no_upload(self):
  policy=SimpleNamespace(POLICY=POLICY,PROJECT='cryptolabs-proxy',PROJECT_FILE='pyproject.toml',MIRROR_GITHUB=True)
  with tempfile.TemporaryDirectory() as directory:
   event=Path(directory)/'event.json';event.write_text(json.dumps(self.event['event']))
   env={'GITHUB_EVENT_NAME':'release','GITHUB_SHA':SHA,'GITHUB_EVENT_PATH':str(event),'GITHUB_REPOSITORY':POLICY.repository}
   with patch.dict(sys.modules,{'policy':policy}),patch.dict(os.environ,env),patch.object(r.package,'publish') as upload,contextlib.redirect_stderr(io.StringIO()) as error:
    self.assertEqual(r.main(['verify','0','2','456']),1)
   upload.assert_not_called();self.assertIn('Publication held',error.getvalue())

if __name__=='__main__':unittest.main()
