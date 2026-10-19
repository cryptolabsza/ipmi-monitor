"""Fixed public-repository artifact transport; no application execution or visibility mutation."""
import argparse,base64,json,os,re,tempfile,tomllib,urllib.error,urllib.parse,urllib.request
from pathlib import Path
import image_publisher as frozen
from verify_artifact import verify,gh_json,Refused
Held=frozen.Held
require=frozen.require
NAMES={'cryptolabs-proxy','dc-overview','runpod-exporter','vastai-exporter','ipmi-monitor'}

def package_identity(name,code,package,*,after=False,previous=None):
    require(type(code)is int and isinstance(package,dict),'package metadata shape')
    if code==404:
        require(not after and package.get('message') in {'Not Found','Package not found.'} and package.get('status','404')=='404','actual package absence required')
        return None
    require(code==200,'package metadata permission/status')
    require(package.get('name')==name and package.get('package_type')=='container' and isinstance(package.get('owner'),dict) and package['owner'].get('login')=='cryptolabsza','package identity')
    identity={'id':package.get('id'),'visibility':package.get('visibility')}
    require(type(identity['id'])is int and identity['id']>0 and identity['visibility'] in {'public','private','internal'},'package identity/visibility')
    if after:require(identity==previous if previous is not None else identity['visibility']=='private','package identity/visibility changed')
    return identity

def package_get(name):
    require(name in NAMES,'fixed package name')
    url='https://api.github.com/orgs/cryptolabsza/packages/container/'+urllib.parse.quote(name,safe='')
    request=urllib.request.Request(url,headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],'Accept':'application/vnd.github+json','User-Agent':'verified-image-transport'})
    try:response=urllib.request.build_opener(frozen.NoPackageRedirect).open(request,timeout=30)
    except urllib.error.HTTPError as error:response=error
    try:
        body=response.read(65537);require(len(body)<=65536,'package metadata bound');return response.getcode(),json.loads(body)
    finally:response.close()

def package_gate(images,*,after=False,previous=None,lookup=package_get):
    return {name:package_identity(name,*lookup(name),after=after,previous=None if previous is None else previous[name]) for name in images}

def source_version(policy,source_sha,api=gh_json):
    value=api('/repos/'+policy.repository+'/contents/pyproject.toml?ref='+source_sha)
    require(value.get('encoding')=='base64' and value.get('path')=='pyproject.toml' and type(value.get('size'))is int and 0<value['size']<=65536,'source project metadata')
    data=base64.b64decode(value['content'],validate=False);require(len(data)==value['size'],'project metadata size')
    project=tomllib.loads(data.decode())['project'];require(project['name']==policy.repository.split('/')[1] and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',project['version']),'project identity/version')
    return project['version']

def image_tags(policy,image,proof,api=gh_json):
    require(proof['branch'] in {'main','dev'},'source branch')
    if policy.repository.endswith('/ipmi-monitor'):
        branch=proof['branch'];return [branch,'sha-'+proof['head_sha'][:7]] if branch=='main' else ['dev','develop','sha-'+proof['head_sha'][:7]]
    import image_promotion as promotion
    result=promotion.build_tags('ghcr.io/cryptolabsza/'+image,'refs/heads/'+proof['branch'],proof['head_sha'],proof['event'],version=source_version(policy,proof['head_sha'],api),override='')
    return [tag.rsplit(':',1)[1] for tag in result['tags']]

def prepare(policy,images,files,proof,context,api=gh_json):
    require(context=={'repository':policy.repository,'repository_id':policy.repository_id,'sha':proof['head_sha'],'branch':proof['branch'],'run_id':proof['run_id'],'run_attempt':proof['run_attempt']},'current source/producer identity')
    expected={name for image in images for name in (image+'.tar',image+'.json')}
    if len(images)>1:expected.add('SHA256SUMS')
    require({p.name for p in files.iterdir()}==expected and all(p.is_file() and not p.is_symlink() for p in files.iterdir()),'exact image artifact files')
    plans=[];sums=[]
    for image in images:
        archive=files/(image+'.tar');identity=frozen.digest(archive);receipt=frozen.metadata(archive.with_suffix('.json'));destination='ghcr.io/cryptolabsza/'+image
        require(receipt=={'artifact_kind':'oci-archive','expected_image':destination,'repository':policy.repository,'repository_id':policy.repository_id,'source_sha':proof['head_sha'],'run_id':str(proof['run_id']),'run_attempt':str(proof['run_attempt']),'filename':archive.name,'sha256':identity},'archive receipt corroboration')
        tags=image_tags(policy,image,proof,api);digest,selection=frozen.oci(archive,set(tags+[destination+':'+t for t in tags]));plans.append({'archive':archive,'archive_sha256':identity,'digest':digest,'selection':selection,'destinations':[destination+':'+t for t in tags[::-1]]});sums.append(identity+'  '+archive.name+'\n')
    if len(images)>1:require((files/'SHA256SUMS').read_text()==''.join(sums),'image checksum list')
    return plans

def promote_verified(policy,images,release_tag,source_sha,expected,api=gh_json,receipt_path=None):
    import image_promotion as promotion
    require(re.fullmatch('[0-9a-f]{40}',source_sha) and set(expected)==set(images),'complete manual promotion identities')
    version=source_version(policy,source_sha,api);require(release_tag=='v'+version,'release source version')
    client=promotion.Client();require(client.release_commit(policy.repository,release_tag)==source_sha,'published release source')
    branch=api('/repos/'+policy.repository+'/branches/main');require(branch['protected']is True,'protected promotion branch')
    comparison=api('/repos/'+policy.repository+'/compare/'+source_sha+'...'+branch['commit']['sha']);require(comparison['status'] in {'ahead','identical'} and comparison['merge_base_commit']['sha']==source_sha,'promotion source ancestry')
    context={'project':policy.repository.split('/')[1],'repository':policy.repository,'version':version,'tag':release_tag,'source_sha':source_sha}
    before=package_gate(images);receipt=promotion.promote(context,expected,['linux/amd64'],client)
    if receipt_path is not None:receipt_path.write_text(json.dumps(receipt,indent=2)+'\n')
    require(receipt['status']=='verified','manual promotion held or partial')
    require(client.release_commit(policy.repository,release_tag)==source_sha,'release source changed')
    package_gate(images,after=True,previous=before);return receipt

def promote(policy,images,release_tag,source_sha,expected,api=gh_json,receipt_path=None):
    if receipt_path is None:receipt_path=Path(os.environ['RUNNER_TEMP'])/'promotion-receipt.json'
    try:
        return promote_verified(policy,images,release_tag,source_sha,expected,api,receipt_path)
    except Exception:
        receipt=json.loads(receipt_path.read_text()) if receipt_path is not None and receipt_path.exists() else {'schema_version':1,'status':'held','targets':[],'operations':[]}
        if receipt.get('status')=='verified':receipt['status']='partial'
        receipt.setdefault('error_code','promotion_source_package_or_registry_proof_failed')
        if receipt_path is not None:receipt_path.write_text(json.dumps(receipt,indent=2)+'\n')
        return receipt

def metadata(policy,mode,api=gh_json):
    import image_promotion as promotion
    source_sha=os.environ['GITHUB_SHA'];version=source_version(policy,source_sha,api)
    result=promotion.build_tags('ghcr.io/'+policy.repository,'refs/heads/main',source_sha,'push',version=version,override='')
    require(result['channel']=='main','main discovery guard')
    context={'project':policy.repository.split('/')[1],'repository':policy.repository,'version':version,'tag':'v'+version,'source_sha':source_sha}
    receipt={'schema_version':1,'status':'discovery','build':True,'release':context,'channel':result['channel'],'targets':[],'operations':[]}
    (Path(os.environ['RUNNER_TEMP'])/('image-release-'+mode+'-receipt.json')).write_text(json.dumps(receipt,indent=2)+'\n')
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('build=true\nstatus=discovery\n')
    return receipt

def main(policy,images):
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['verify','publish','promote','preflight','readback']);parser.add_argument('run',type=int,nargs='?');parser.add_argument('attempt',type=int,nargs='?');parser.add_argument('artifact',type=int,nargs='?');args=parser.parse_args()
    try:
        require(frozen.digest(Path(__file__).with_name('image_publisher.py'))=='ef55392ffcdf59a30a232c436520e10b318a3895e139f0c40904e33f7dccd2a8','frozen OCI parser bytes')
        require(os.environ['GITHUB_REPOSITORY']==policy.repository and int(os.environ['GITHUB_REPOSITORY_ID'])==policy.repository_id,'current repository')
        require(os.environ['GITHUB_REF']=='refs/heads/main' and os.environ['GITHUB_REF_PROTECTED']=='true' and os.environ['GITHUB_EVENT_NAME'] in {'push','workflow_dispatch'},'protected main publisher')
        os.umask(0o077)
        if args.mode in {'preflight','readback'}:
            print(json.dumps(metadata(policy,args.mode)));return 0
        if args.mode=='promote':
            require(os.environ['GITHUB_EVENT_NAME']=='workflow_dispatch','manual promotion only')
            expected={image:os.environ[image.upper().replace('-','_')+'_DIGEST'] for image in images}
            receipt=promote(policy,images,os.environ['RELEASE_TAG'],os.environ['SOURCE_SHA'],expected,receipt_path=Path(os.environ['RUNNER_TEMP'])/'promotion-receipt.json')
            print(json.dumps(receipt));return 0 if receipt['status']=='verified' else 1
        run=int(os.environ['GITHUB_RUN_ID']);attempt=int(os.environ['GITHUB_RUN_ATTEMPT']);require((args.run,args.attempt)==(run,attempt),'current run/attempt')
        with tempfile.TemporaryDirectory(prefix='image-transport-',dir=os.environ.get('RUNNER_TEMP','/tmp')) as td:
            root=Path(td);proof=verify(policy,args.run,args.attempt,args.artifact,output=root/'verified');context={'repository':policy.repository,'repository_id':policy.repository_id,'sha':os.environ['GITHUB_SHA'],'branch':'main','run_id':run,'run_attempt':attempt};plans=prepare(policy,images,root/'verified/files',proof,context)
            if args.mode=='verify':print('Actual artifact verification passed; no registry operation');return 0
            before=package_gate(images);client=frozen.Registry(root);client.login(os.environ['GITHUB_ACTOR'],os.environ['GH_TOKEN']);result=frozen.publish(plans,client);after=package_gate(images,after=True,previous=before);print(json.dumps({'packages':after,'images':result}));return 0
    except (Held,Refused,KeyError,TypeError,ValueError,OSError):
        print('Image operation held: source, artifact, package or registry proof unavailable.',file=__import__('sys').stderr);return 1
