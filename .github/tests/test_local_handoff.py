"""Fixed producer closure, native source identity and tiny manifest boundary."""
import hashlib,importlib.util,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
REPOSITORY="cryptolabsza/ipmi-monitor"
ID=1109244855
IMAGES=['ipmi-monitor']
class LocalHandoffTests(unittest.TestCase):
 def module(self):
  p=ROOT/'.github/image-publisher/local_handoff.py';spec=importlib.util.spec_from_file_location('fixed_local_handoff',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
 def fixture(self,root):
  workspace=root/'workspace';source=workspace/'ci-artifacts';source.mkdir(parents=True);temp=root/'temp';temp.mkdir()
  env=dict(GITHUB_WORKSPACE=str(workspace),RUNNER_TEMP=str(temp),GITHUB_REPOSITORY=REPOSITORY,GITHUB_REPOSITORY_ID=str(ID),GITHUB_SHA='a'*40,GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='2')
  sums=[]
  for image in IMAGES:
   data=('opaque '+image).encode();(source/(image+'.tar')).write_bytes(data);digest=hashlib.sha256(data).hexdigest();sums.append(digest+'  '+image+'.tar\n')
   receipt=dict(artifact_kind='oci-archive',expected_image='ghcr.io/cryptolabsza/'+image,repository=REPOSITORY,repository_id=ID,source_sha='a'*40,run_id='123',run_attempt='2',filename=image+'.tar',sha256=digest)
   (source/(image+'.json')).write_text(json.dumps(receipt)+'\n')
  if len(IMAGES)>1:(source/'SHA256SUMS').write_text(''.join(sums));(source/'runpod-test.tar').write_bytes(b'functional test only')
  return source,temp,env
 def test_fixed_staging_excludes_test_export_and_writes_only_canonical_manifest(self):
  m=self.module()
  with tempfile.TemporaryDirectory() as td:
   source,temp,env=self.fixture(Path(td));calls=[]
   class Transport:
    def upload_bundle(self,files,context,**kwargs):
     names=set(files.iterdir());expected={image+suffix for image in IMAGES for suffix in ('.json','.tar')}|({'SHA256SUMS'} if len(IMAGES)>1 else set())
     selftest.assertEqual({p.name for p in names},expected);selftest.assertEqual(context,dict(repository_id=ID,run_id=123,run_attempt=2,head_sha='a'*40));selftest.assertEqual(kwargs,{'endpoint':'http://10.244.240.1:18080'})
     for p in names:selftest.assertEqual(p.stat().st_ino,(source/p.name).stat().st_ino)
     result=dict(schema=2,object_id='a1234567-1234-4234-8234-123456789abc',producer_lease_id='a1234567-1234-4234-8234-123456789abc',producer_runner_id=44,**context,files=[dict(path=p.name,size=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in sorted(names)])
     calls.append(result);return result
    def validate_manifest(self,result):return result
    def canonical_manifest(self,result):return (json.dumps(result,sort_keys=True,separators=(',',':'))+'\n').encode()
   selftest=self;t=Transport()
   with patch.object(m,'_transport',return_value=t):output=m.handoff(env)
   self.assertEqual(output,temp/'image-local-manifest/manifest.json');self.assertEqual(output.read_bytes(),t.canonical_manifest(calls[0]));self.assertLess(output.stat().st_size,65536)
   self.assertFalse(list(temp.glob('.image-upload-*')));self.assertEqual(set(output.parent.iterdir()),{output})
 def test_invalid_source_receipt_symlink_and_oversize_refuse_before_upload(self):
  m=self.module()
  for kind in ('repository','missing','symlink','receipt','oversize'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as td:
    source,temp,env=self.fixture(Path(td));first=source/(IMAGES[0]+'.tar')
    if kind=='repository':env['GITHUB_REPOSITORY']='cryptolabsza/other'
    if kind=='missing':first.unlink()
    if kind=='symlink':first.rename(source/'outside');first.symlink_to(source/'outside')
    if kind=='receipt':(source/(IMAGES[0]+'.json')).write_text('{}')
    if kind=='oversize':
     with first.open('r+b') as f:f.truncate(5*1024**3)
    with patch.object(m,'_transport',side_effect=AssertionError('must fail before any upload')):
     with self.assertRaises((ValueError,OSError)):m.handoff(env)
    self.assertFalse((temp/'image-local-manifest').exists())
if __name__=='__main__':unittest.main()

class ImmutableCommonTests(unittest.TestCase):
 def test_exact_committed_common_source_copies(self):
  source=ROOT/'.github/image-publisher/local_artifacts';origin=json.loads((source/'origin.json').read_text())
  self.assertEqual(origin['commit'],'86d3f5b8437385278e745e2fc4098a54e3d5d59b')
  self.assertEqual(set(origin['files']),{'local_artifact.py','local_artifact_routes.py','verify_artifact.py'})
  for name,digest in origin['files'].items():self.assertEqual(hashlib.sha256((source/name).read_bytes()).hexdigest(),digest)
