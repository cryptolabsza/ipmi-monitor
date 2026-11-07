# TRACEWEAVER: file-role=latest-alias-frozen-boundary; req=REQ-IPMI-LATEST-001; trace=TRACE-IPMI-LATEST-001; ver=VER-IPMI-LATEST-001
# TRACEWEAVER: verifies=VER-IPMI-LATEST-001; req=REQ-IPMI-LATEST-001; trace=TRACE-IPMI-LATEST-001
"""Public publisher swaps only the independently verified transport bytes."""
import ast,hashlib,json,subprocess,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
BR='a034e480f77032f3f9afdb079363dea23e48c87a'
ORIGINAL_BR='7a8e38d6a61a10337e4f71f6219f67d03f9b2aa1'
class LocalPublisherTests(unittest.TestCase):
 def test_real_policy_and_shared_v2_dispatch_with_legacy_default_retained(self):
  script="import sys,json;sys.path.insert(0,sys.argv[1]);import policy;from verify_artifact import Policy;print(json.dumps({'schema':policy.POLICY.transport_schema,'recipe':policy.POLICY.recipe_ref,'default':Policy.__dataclass_fields__['transport_schema'].default}))"
  actual=json.loads(subprocess.check_output([sys.executable,'-I','-c',script,str(ROOT/'.github/image-publisher')]))
  self.assertEqual(actual,dict(schema=2,recipe='cryptolabsza/ipmi-monitor'+'/.github/workflows/ci-image-build-recipe.yml@'+BR,default=1))
  origin=json.loads((ROOT/'.github/image-publisher/publisher-origin.json').read_text())
  for name,digest in origin['files'].items():self.assertEqual(hashlib.sha256((ROOT/'.github/image-publisher'/name).read_bytes()).hexdigest(),digest)
 def test_frozen_helpers_and_all_transport_but_reviewed_alias_rule_are_unchanged(self):
  for name in ('transport.py','image_publisher.py','image_promotion.py','bootstrap_tools.py','tools.json'):
   path='.github/image-publisher/'+name
   if not (ROOT/path).exists():continue
   original=subprocess.check_output(['git','show',ORIGINAL_BR+':'+path],cwd=ROOT)
   if name=='transport.py':
    current=ast.parse((ROOT/path).read_bytes());baseline=ast.parse(original)
    tags=next(n for n in baseline.body if isinstance(n,ast.FunctionDef) and n.name=='image_tags')
    main_tags=next(n for n in ast.walk(tags) if isinstance(n,ast.IfExp))
    main_tags.body=ast.parse("['latest','main','sha-'+proof['head_sha'][:7]]",mode='eval').body
    self.assertEqual(ast.dump(current),ast.dump(baseline))
   else:self.assertEqual((ROOT/path).read_bytes(),original)
