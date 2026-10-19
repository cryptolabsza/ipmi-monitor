"""Fixed public image bytes to local store; only manifest.json goes to GitHub."""
import json,os,re,sys,tempfile
from pathlib import Path
REPOSITORY='cryptolabsza/ipmi-monitor'
REPOSITORY_ID=1109244855
IMAGES=['ipmi-monitor']
FILES=tuple(sorted([image+suffix for image in IMAGES for suffix in ('.json','.tar')]+(['SHA256SUMS'] if len(IMAGES)>1 else [])))
MAX_BYTES=5*1024**3
ENDPOINT='http://10.244.240.1:18080'

def require(value,message):
 if not value:raise ValueError(message)

def _transport():
 sys.path.insert(0,str(Path(__file__).resolve().with_name('local_artifacts')))
 import local_artifact
 return local_artifact

def _json(raw):
 def unique(pairs):
  result={}
  for key,value in pairs:require(key not in result,'duplicate receipt field');result[key]=value
  return result
 return json.loads(raw,object_pairs_hook=unique)

def handoff(env=None):
 env=os.environ if env is None else env
 require(env.get('GITHUB_REPOSITORY')==REPOSITORY and env.get('GITHUB_REPOSITORY_ID')==str(REPOSITORY_ID),'fixed native repository')
 require(re.fullmatch('[0-9a-f]{40}',env.get('GITHUB_SHA','')) is not None,'native source SHA')
 for key in ('GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT'):require(re.fullmatch('[1-9][0-9]*',env.get(key,'')) is not None,'native run identity')
 workspace=Path(env.get('GITHUB_WORKSPACE',''));root=Path(env.get('RUNNER_TEMP',''))
 require(all(p.is_absolute() and p.is_dir() and not p.is_symlink() for p in (workspace,root)),'native workspace and temporary directory')
 source=workspace/'ci-artifacts';destination=root/'image-local-manifest'
 require(source.is_dir() and not source.is_symlink(),'fixed build artifact directory')
 allowed=set(FILES)|({'runpod-test.tar'} if len(IMAGES)>1 else set())
 require(set(FILES)<={p.name for p in source.iterdir()}<=allowed,'fixed build file closure')
 require(not os.path.lexists(destination),'manifest destination exists')
 total=0
 for name in FILES:
  path=source/name;require(path.is_file() and not path.is_symlink(),'regular fixed producer output');size=path.stat().st_size;total+=size
  require(size>0 and total<=MAX_BYTES,'aggregate local bundle exceeds fixed5GiB')
 receipts={};sums=[]
 for image in IMAGES:
  path=source/(image+'.json');require(path.stat().st_size<=65536,'bounded image receipt');receipt=_json(path.read_bytes())
  expected=dict(artifact_kind='oci-archive',expected_image='ghcr.io/cryptolabsza/'+image,repository=REPOSITORY,repository_id=REPOSITORY_ID,source_sha=env['GITHUB_SHA'],run_id=env['GITHUB_RUN_ID'],run_attempt=env['GITHUB_RUN_ATTEMPT'],filename=image+'.tar')
  require(type(receipt)is dict and set(receipt)==set(expected)|{'sha256'} and all(type(receipt.get(k))is type(v) and receipt[k]==v for k,v in expected.items()) and type(receipt['sha256'])is str and re.fullmatch('[0-9a-f]{64}',receipt['sha256']),'exact native image receipt')
  receipts[image]=receipt;sums.append(receipt['sha256']+'  '+image+'.tar\n')
 if len(IMAGES)>1:require((source/'SHA256SUMS').read_text()==''.join(sums),'complete image checksum list')
 transport=_transport();context=dict(repository_id=REPOSITORY_ID,run_id=int(env['GITHUB_RUN_ID']),run_attempt=int(env['GITHUB_RUN_ATTEMPT']),head_sha=env['GITHUB_SHA'])
 # The fixed projection excludes functional-only exports without copying GiB.
 # Cross-filesystem hardlink failure holds clearly before the first PUT.
 with tempfile.TemporaryDirectory(prefix='.image-upload-',dir=root) as temporary:
  stage=Path(temporary)
  for name in FILES:os.link(source/name,stage/name,follow_symlinks=False)
  manifest=transport.validate_manifest(transport.upload_bundle(stage,context,endpoint=ENDPOINT))
 require(all(type(manifest[k])is type(v) and manifest[k]==v for k,v in context.items()),'manifest native source binding')
 for image,receipt in receipts.items():require(next(item['sha256'] for item in manifest['files'] if item['path']==image+'.tar')==receipt['sha256'],'uploaded archive receipt mismatch')
 raw=transport.canonical_manifest(manifest);require(len(raw)<=65536,'tiny canonical manifest bound')
 with tempfile.TemporaryDirectory(prefix='.image-manifest-',dir=root) as temporary:
  work=Path(temporary);path=work/'manifest.json'
  with path.open('xb') as output:os.chmod(path,0o600);output.write(raw)
  require(not os.path.lexists(destination),'manifest destination exists');os.rename(work,destination)
 return destination/'manifest.json'

def main():
 try:
  require(len(sys.argv)==1,'fixed handoff accepts no arguments');handoff();print('Image local manifest ready.');return 0
 except Exception:
  print('Image local handoff held: fixed source, files,5GiB capacity or local transport unavailable.',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
