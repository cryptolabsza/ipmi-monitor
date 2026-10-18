"""Immutable local build recipe changes only artifact transport steps."""
import copy,hashlib,json,subprocess,unittest,yaml
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
BH='96d0bf5584e4df5a87d971bf2fe6e08f9bc0c8d0'
class LocalBuildRecipeTests(unittest.TestCase):
 def test_build_recipe_pins_actual_producer_and_only_uploads_tiny_manifest(self):
  path='.github/workflows/ci-image-build-recipe.yml';recipe=yaml.safe_load((ROOT/path).read_text());job=recipe['jobs']['build'];steps=job['steps']
  checkout=next(s for s in steps if s['name']=='Checkout immutable local image producer')
  self.assertEqual(checkout['with']['ref'],BH);self.assertEqual(checkout['with']['repository'],'cryptolabsza/ipmi-monitor');self.assertFalse(checkout['with']['persist-credentials']);self.assertEqual(checkout['with']['path'],'.local-image-producer')
  self.assertEqual(checkout['with']['sparse-checkout'].splitlines(),['/.github/image-publisher/local_handoff.py','/.github/image-publisher/local_artifacts/'])
  verify=next(s for s in steps if s['name']=='Verify immutable local producer bytes')
  for name in ['local_handoff.py','local_artifacts/local_artifact.py','local_artifacts/local_artifact_routes.py','local_artifacts/verify_artifact.py']:
   raw=subprocess.check_output(['git','show',BH+':.github/image-publisher/'+name],cwd=ROOT);self.assertIn(hashlib.sha256(raw).hexdigest()+'  .local-image-producer/.github/image-publisher/'+name,verify['run'])
  handoff=next(s for s in steps if s['name']=='Upload fixed image bundle to local store');self.assertEqual(handoff['run'],'python3 .local-image-producer/.github/image-publisher/local_handoff.py');self.assertNotIn('env',handoff)
  upload=next(s for s in steps if s.get('id')=='upload');self.assertEqual(upload['with']['path'],'${{ runner.temp }}/image-local-manifest/manifest.json');self.assertEqual(upload['with']['compression-level'],0);self.assertEqual(upload['with']['retention-days'],7)
  baseline=yaml.safe_load(subprocess.check_output(['git','show',BH+':'+path],cwd=ROOT));normal=copy.deepcopy(recipe);normal['jobs']['build']['steps']=[s for s in normal['jobs']['build']['steps'] if s['name'] not in {checkout['name'],verify['name'],handoff['name']}]
  target=next(s for s in normal['jobs']['build']['steps'] if s.get('id')=='upload');target['with']=next(s for s in baseline['jobs']['build']['steps'] if s.get('id')=='upload')['with']
  self.assertEqual(normal,baseline)
