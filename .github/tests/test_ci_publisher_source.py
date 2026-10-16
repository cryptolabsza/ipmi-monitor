"""Immutable publisher authority is limited to verified distribution data."""
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import unittest
import yaml

ROOT=Path(__file__).resolve().parents[2]
SPEC=json.loads((Path(__file__).parent/'publisher_contract.json').read_text())
HELPERS=['verify_artifact.py','package_publisher.py','release_runtime.py','bootstrap_gh.py','policy.py']

class PublisherSourceTest(unittest.TestCase):
 def leaf(self):
  path=ROOT/'.github/workflows/ci-pypi-publish-recipe.yml'
  self.assertTrue(path.is_file(),'artifact-only publisher leaf missing')
  return yaml.safe_load(path.read_text())
 def test_verifier_snapshot_and_literal_producer_policy(self):
  self.assertEqual(hashlib.sha256((ROOT/'.github/publisher/verify_artifact.py').read_bytes()).hexdigest(),SPEC['verifier_sha256'])
  tree=ast.parse((ROOT/'.github/publisher/policy.py').read_text())
  assignments={n.targets[0].id:n.value for n in tree.body if isinstance(n,ast.Assign)}
  values={k.arg:ast.literal_eval(k.value) for k in assignments['POLICY'].keywords}
  self.assertEqual(values,dict(repository=SPEC['repository'],repository_id=SPEC['repository_id'],workflow_path=SPEC['workflow_path'],recipe_ref=SPEC['build_ref'],producer_job='cpu-build / build',group_id=SPEC['build_group_id'],build_label='ci-linux-cpu-v1-r'+str(SPEC['repository_id']),artifact_kind='pypi',artifact_stem='cpu-python'))
  self.assertEqual(ast.literal_eval(assignments['PROJECT']),SPEC['project'])
  self.assertEqual(ast.literal_eval(assignments['PROJECT_FILE']),SPEC['project_file'])
  self.assertIs(ast.literal_eval(assignments['MIRROR_GITHUB']),SPEC['mirror_github'])
 def test_publisher_has_static_authority_and_only_three_dynamic_ids(self):
  leaf=self.leaf();call=leaf.get('on',leaf.get(True))['workflow_call'];job=leaf['jobs']['publish']
  self.assertEqual(set(call['inputs']),{'producer_run_id','producer_attempt','artifact_id'})
  self.assertEqual(call['secrets'],{'PYPI_API_TOKEN':{'required':True}})
  for value in call['inputs'].values():self.assertEqual(value,{'type':'string','required':False,'default':''})
  self.assertEqual(job['runs-on'],{'group':'ci-publish-ephemeral','labels':['ci-linux-publish-v1-r'+str(SPEC['repository_id'])]})
  self.assertEqual(job['timeout-minutes'],45)
  self.assertEqual(job['permissions'],{'actions':'read','contents':'write' if SPEC['mirror_github'] else 'read'})
  self.assertEqual(leaf['permissions'],job['permissions'])
  expected="github.repository_id == '"+str(SPEC['repository_id'])+"' && (github.event_name == 'release' || github.event_name == 'workflow_dispatch')"
  self.assertEqual(job['if'],expected)
  for event in ['push','pull_request','pull_request_target','repository_dispatch','release','workflow_dispatch']:
   for identity in [str(SPEC['repository_id']),'999']:
    expr=job['if'].replace('github.repository_id',repr(identity)).replace('github.event_name',repr(event)).replace('&&',' and ').replace('||',' or ')
    self.assertEqual(eval(expr,{'__builtins__':{}}),identity==str(SPEC['repository_id']) and event in {'release','workflow_dispatch'})
 def test_only_literal_reviewed_helper_snapshot_is_checked_out(self):
  steps=self.leaf()['jobs']['publish']['steps'];checkouts=[s for s in steps if s.get('uses','').startswith('actions/checkout@')]
  self.assertEqual(len(checkouts),1);checkout=checkouts[0]['with']
  self.assertEqual(checkout['repository'],SPEC['repository']);self.assertRegex(checkout['ref'],r'^[a-f0-9]{40}$')
  self.assertIs(checkout['persist-credentials'],False);self.assertIs(checkout['sparse-checkout-cone-mode'],False)
  self.assertEqual(checkout['path'],'publisher-code')
  self.assertEqual(checkout['sparse-checkout'].splitlines(),['/.github/publisher/'+p for p in HELPERS])
  for name in HELPERS:
   immutable=subprocess.check_output(['git','show',checkout['ref']+':.github/publisher/'+name],cwd=ROOT)
   self.assertEqual(immutable,(ROOT/'.github/publisher'/name).read_bytes())
 def test_credentials_are_supplied_only_to_reviewed_verify_upload(self):
  steps=self.leaf()['jobs']['publish']['steps']
  for step in steps:
   if 'uses' in step:self.assertRegex(step['uses'],r'@[a-f0-9]{40}$')
   text=json.dumps(step)
   if 'secrets.' in text:
    self.assertEqual(step['id'],'upload');self.assertEqual(step['env']['TWINE_PASSWORD'],'${{ secrets.PYPI_API_TOKEN }}')
   if 'GH_TOKEN' in step.get('env',{}):self.assertIn(step['id'],['verify','upload']);self.assertEqual(step['env']['GH_TOKEN'],'${{ github.token }}')
   command=step.get('run','')
   self.assertNotIn('${{',command);self.assertNotIn('--skip-existing',command);self.assertNotIn('python -m build',command)
   self.assertNotIn('scripts/',command);self.assertNotIn('pip install .',command)
  verify=next(s for s in steps if s.get('id')=='verify');upload=next(s for s in steps if s.get('id')=='upload')
  self.assertEqual(verify['run'],'python publisher-code/.github/publisher/release_runtime.py verify "$PRODUCER_RUN_ID" "$PRODUCER_ATTEMPT" "$ARTIFACT_ID"')
  self.assertEqual(upload['run'],'python publisher-code/.github/publisher/release_runtime.py upload')
  self.assertEqual([s['with']['python-version'] for s in steps if s.get('uses','').startswith('actions/setup-python@')],['3.12'])
 def test_caller_pins_recipe_and_preserves_producer_and_release_semantics(self):
  caller=yaml.safe_load((ROOT/SPEC['workflow_path']).read_text());jobs=caller['jobs']
  self.assertEqual(set(jobs),{'cpu-build','publish'});self.assertEqual(jobs['cpu-build']['uses'],SPEC['build_ref'])
  self.assertEqual(jobs['cpu-build']['permissions'],{'contents':'read'});self.assertNotIn('secrets',jobs['cpu-build'])
  pub=jobs['publish'];self.assertRegex(pub['uses'],re.escape(SPEC['repository'])+r'/\.github/workflows/ci-pypi-publish-recipe.yml@[a-f0-9]{40}$')
  self.assertEqual(pub['secrets'],{'PYPI_API_TOKEN':'${{ secrets.PYPI_API_TOKEN }}'});self.assertEqual(pub['needs'],'cpu-build')
  self.assertEqual(set(pub['with']),{'producer_run_id','producer_attempt','artifact_id'})
  self.assertIn("github.event_name == 'release'",pub['if']);self.assertIn("github.event_name == 'workflow_dispatch'",pub['if'])
  triggers=caller.get('on',caller.get(True));self.assertEqual(triggers['release'],{'types':['published']})
  self.assertEqual(triggers['push']['branches'],['dev','main']);self.assertEqual(triggers['pull_request']['branches'],['dev','main'])
  self.assertIn('version',triggers['workflow_dispatch']['inputs'])
  if SPEC['mirror_github']:self.assertIn('release_tag',triggers['workflow_dispatch']['inputs'])

if __name__=='__main__':unittest.main()
