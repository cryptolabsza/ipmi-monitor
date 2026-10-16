"""Public image artifact boundary: real recipe shapes and package visibility continuity."""
import importlib.util,json,sys,unittest,yaml
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
class ImageBoundary(unittest.TestCase):
 def module(self):
  p=ROOT/'.github/image-publisher';sys.path.insert(0,str(p));spec=importlib.util.spec_from_file_location('public_image_transport',p/'transport.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
 def test_real_producer_exports_complete_oci_images_without_authority(self):
  p=ROOT/'.github/workflows/ci-image-build-recipe.yml';self.assertTrue(p.exists());d=yaml.safe_load(p.read_text());job=d['jobs']['build'];self.assertEqual(job['runs-on']['group'],'ci-build-public-ephemeral');self.assertEqual(job['permissions'],{'contents':'read'});self.assertNotIn('secrets.',p.read_text())
  builds=[s for s in job['steps'] if s.get('uses','').startswith('docker/build-push-action@')];self.assertEqual(len(builds),3 if ROOT.name.startswith('dc-overview') else 1)
  for s in builds:self.assertIs(s['with']['push'],False);self.assertIs(s['with']['provenance'],False);self.assertIn('type=oci,',s['with']['outputs'])
  if len(builds)==3:self.assertEqual([s['with']['context'] for s in builds],['.','./runpod-exporter','./vastai-exporter']);self.assertIn('Verify packaged RunPod health contract',str(job));self.assertIn('Test Vast dashboards',str(job));self.assertIn('Verify RunPod exporter health and alert contract',str(job))
 def package(self,visibility='public',id=12):return {'id':id,'name':'sample','package_type':'container','owner':{'login':'cryptolabsza'},'visibility':visibility}
 def test_existing_visibility_and_id_are_preserved_for_all_visibility_modes(self):
  m=self.module()
  for visibility in ['public','private','internal']:
   before=m.package_identity('sample',200,self.package(visibility));self.assertEqual(m.package_identity('sample',200,self.package(visibility),after=True,previous=before),before)
   for mutation in [self.package(visibility,13),self.package('private' if visibility!='private' else 'public')]:
    with self.assertRaises(m.Held):m.package_identity('sample',200,mutation,after=True,previous=before)
 def test_actual_403_shapes_are_not_absence_and_new_package_stays_private(self):
  m=self.module()
  for code in [401,403,500]:
   with self.assertRaises(m.Held):m.package_identity('sample',code,{'message':'You need at least read:packages scope to get a package.'})
  self.assertIsNone(m.package_identity('sample',404,{'message':'Not Found','status':'404'}))
  self.assertEqual(m.package_identity('sample',200,self.package('private'),after=True,previous=None),{'id':12,'visibility':'private'})
  with self.assertRaises(m.Held):m.package_identity('sample',200,self.package('public'),after=True,previous=None)
 def test_metadata_main_guard_reuses_frozen_tag_policy(self):
  if ROOT.name.startswith('ipmi-monitor'):return
  import base64,os,tempfile
  from unittest.mock import patch
  m=self.module();name='dc-overview' if ROOT.name.startswith('dc-overview') else 'cryptolabs-proxy'
  class Policy:repository='cryptolabsza/'+name
  data=('[project]\nname="'+name+'"\nversion="1.2.3"\n').encode();api=lambda path:{'encoding':'base64','path':'pyproject.toml','size':len(data),'content':base64.b64encode(data).decode()}
  with tempfile.TemporaryDirectory() as td,patch.dict(os.environ,{'GITHUB_SHA':'a'*40,'RUNNER_TEMP':td,'GITHUB_OUTPUT':td+'/output'}):
   receipt=m.metadata(Policy(),'preflight',api);self.assertEqual((receipt['status'],receipt['build'],receipt['channel']),('discovery',True,'main'));self.assertEqual(receipt['release']['version'],'1.2.3');self.assertEqual(receipt['operations'],[])
 def test_immutable_publisher_has_only_literal_helpers_and_no_application_execution(self):
  p=ROOT/'.github/workflows/ci-image-publish-recipe.yml';self.assertTrue(p.exists());d=yaml.safe_load(p.read_text())
  for name,j in d['jobs'].items():
   self.assertEqual(j['runs-on']['group'],'ci-publish-ephemeral');self.assertIn("github.ref == 'refs/heads/main'",j['if']);self.assertIn('github.ref_protected == true',j['if']);checkout=j['steps'][0];self.assertRegex(checkout['with']['ref'],r'^[0-9a-f]{40}$');self.assertFalse(checkout['with']['persist-credentials']);self.assertFalse(checkout['with']['sparse-checkout-cone-mode']);self.assertTrue(all(x.startswith('/.github/image-publisher/') for x in checkout['with']['sparse-checkout'].splitlines()))
   for forbidden in ['docker build','pip install','scripts/image_promotion.py','secrets.CR_PAT','secrets: inherit']:self.assertNotIn(forbidden,str(j))
if __name__=='__main__':unittest.main()
