"""Public publisher swaps only the independently verified transport bytes."""
import hashlib,json,subprocess,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
BR='7a8e38d6a61a10337e4f71f6219f67d03f9b2aa1'
class LocalPublisherTests(unittest.TestCase):
 def test_real_policy_and_shared_v2_dispatch_with_legacy_default_retained(self):
  script="import sys,json;sys.path.insert(0,sys.argv[1]);import policy;from verify_artifact import Policy;print(json.dumps({'schema':policy.POLICY.transport_schema,'recipe':policy.POLICY.recipe_ref,'default':Policy.__dataclass_fields__['transport_schema'].default}))"
  actual=json.loads(subprocess.check_output([sys.executable,'-I','-c',script,str(ROOT/'.github/image-publisher')]))
  self.assertEqual(actual,dict(schema=2,recipe='cryptolabsza/ipmi-monitor'+'/.github/workflows/ci-image-build-recipe.yml@'+BR,default=1))
  origin=json.loads((ROOT/'.github/image-publisher/publisher-origin.json').read_text())
  for name,digest in origin['files'].items():self.assertEqual(hashlib.sha256((ROOT/'.github/image-publisher'/name).read_bytes()).hexdigest(),digest)
 def test_public_package_registry_tags_and_promotion_code_are_unchanged(self):
  for name in ('transport.py','image_publisher.py','image_promotion.py','bootstrap_tools.py','tools.json'):
   path='.github/image-publisher/'+name
   if (ROOT/path).exists():self.assertEqual((ROOT/path).read_bytes(),subprocess.check_output(['git','show',BR+':'+path],cwd=ROOT))
