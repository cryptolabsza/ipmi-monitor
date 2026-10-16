"""Consume independently verified OCI archive data; never run or rebuild an image."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from verify_artifact import Policy, Refused, verify

DESTINATIONS={
 'cryptolabsza/ipmi-monitor-ai': [('image.tar','ghcr.io/cryptolabsza/ipmi-monitor-ai','sha')],
 'cryptolabsza/wordpress-backup-monitor': [('image.tar','ghcr.io/cryptolabsza/wordpress-backup-monitor','short')],
 'cryptolabsza/Custom-TTS': [('custom-tts-build-2.tar','ghcr.io/cryptolabsza/custom-tts/backend','full'),('custom-tts-build-3.tar','ghcr.io/cryptolabsza/custom-tts/frontend','full')],
}
MAX_METADATA=4*1024**2
class Held(ValueError):pass
def require(value,reason):
    if not value:raise Held(reason)
def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024**2),b''):h.update(chunk)
    return h.hexdigest()
def metadata(path):
    require(path.stat().st_size<=MAX_METADATA,'receipt metadata bound')
    return json.loads(path.read_bytes())
MANIFEST_TYPES={'application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json','application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json'}
CANONICAL_FIELDS={key.casefold():key for key in ('schemaVersion','mediaType','manifests','config','layers','digest','size','urls','data','artifactType','annotations','platform','subject','architecture','os','os.version','os.features','variant','features','imageLayoutVersion')}
def strict_json(data):
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value,'duplicate OCI JSON key');value[key]=item
        return value
    value=json.loads(data,object_pairs_hook=unique)
    def canonical(item):
        if isinstance(item,dict):
            for key,child in item.items():
                require(CANONICAL_FIELDS.get(key.casefold(),key)==key,'noncanonical OCI schema field')
                # OCI annotations are a case-sensitive string dictionary, not
                # a Go schema struct: preserve distinct Foo and foo keys.
                if key!='annotations':canonical(child)
        elif isinstance(item,list):
            for child in item:canonical(child)
    canonical(value)
    return value

def oci(path,allowed_names):
    """Validate a bounded plain tar without extracting members or following URLs."""
    offsets={};docs={};seen=set();count=0;total=0
    with path.open('rb') as stream:
        while True:
            header=stream.read(512)
            require(len(header)==512,'OCI tar header')
            if header==b'\0'*512:
                for chunk in iter(lambda:stream.read(1024**2),b''):require(not chunk.strip(b'\0'),'OCI tar trailing bytes')
                break
            try:member=tarfile.TarInfo.frombuf(header,'utf-8','strict')
            except (ValueError,tarfile.HeaderError,UnicodeError):raise Held('OCI tar header') from None
            name=member.name
            if name.startswith('./'):name=name[2:]
            name=name.rstrip('/')
            require(name and name not in seen and '\\' not in name,'OCI unique canonical member')
            seen.add(name);count+=1;total+=member.size
            require(count<=10000 and 0<=member.size<=4*1024**3 and total<=8*1024**3,'OCI member/size bound')
            require(member.type in {tarfile.REGTYPE,tarfile.AREGTYPE,tarfile.DIRTYPE},'OCI tar links/extensions forbidden')
            if member.isdir():
                require(name in {'blobs','blobs/sha256'} and member.size==0,'OCI directory')
                continue
            blob=re.fullmatch('blobs/sha256/([0-9a-f]{64})',name)
            require(blob is not None or name in {'index.json','oci-layout'},'OCI fixed layout member')
            offset=stream.tell();remaining=member.size;h=hashlib.sha256();data=bytearray()
            if blob:offsets['sha256:'+blob[1]]=(offset,member.size)
            else:require(member.size<=MAX_METADATA,'OCI index/layout bound')
            while remaining:
                chunk=stream.read(min(1024**2,remaining));require(chunk,'OCI truncated member');remaining-=len(chunk);h.update(chunk)
                if not blob:data.extend(chunk)
            if blob:require(h.hexdigest()==blob[1],'OCI content-addressed blob digest')
            else:docs[name]=strict_json(data)
            padding=(-member.size)%512;require(len(stream.read(padding))==padding,'OCI tar padding')
        require(docs.get('oci-layout')=={'imageLayoutVersion':'1.0.0'},'OCI layout version')
        index=docs.get('index.json',{});roots=index.get('manifests',[])
        require(index.get('schemaVersion')==2 and isinstance(roots,list) and roots,'OCI root index')
        require(all(isinstance(r,dict) and r.get('mediaType') in MANIFEST_TYPES for r in roots),'OCI root must be image index or manifest')
        require(len({r.get('digest') for r in roots})==1,'OCI ambiguous root image')
        visited=set()
        def walk(descriptor,depth=0):
            require(depth<=16 and isinstance(descriptor,dict) and not descriptor.get('urls') and not descriptor.get('data'),'OCI local descriptor only')
            dg=descriptor.get('digest');size=descriptor.get('size')
            require(dg in offsets and type(size)is int and offsets[dg][1]==size,'OCI referenced blob identity')
            if dg in visited:return
            visited.add(dg);mt=descriptor.get('mediaType')
            if mt in MANIFEST_TYPES:
                require(size<=MAX_METADATA,'OCI manifest bound');stream.seek(offsets[dg][0]);value=strict_json(stream.read(size))
                require(value.get('schemaVersion')==2,'OCI manifest schema')
                children=value.get('manifests') if 'manifests' in value else [value.get('config'),*value.get('layers',[])]
                require(isinstance(children,list) and len(children)<=10000,'OCI child descriptors')
                for child in children:walk(child,depth+1)
                if 'subject' in value:walk(value['subject'],depth+1)
            else:
                require(mt in {'application/vnd.oci.image.config.v1+json','application/vnd.docker.container.image.v1+json','application/vnd.oci.image.layer.v1.tar','application/vnd.oci.image.layer.v1.tar+gzip','application/vnd.oci.image.layer.v1.tar+zstd','application/vnd.docker.image.rootfs.diff.tar.gzip','application/vnd.in-toto+json'},'OCI unsupported media type')
        for root in roots:walk(root)
        selection=roots[0].get('annotations',{}).get('org.opencontainers.image.ref.name')
        require(selection is None or selection in allowed_names,'OCI source image/tag name')
        require(len(roots)==1 or selection is not None,'OCI root selection required')
        return roots[0]['digest'],selection

def prepare(policy,files,proof,context,mode):
    require(isinstance(policy,Policy) and policy.repository in DESTINATIONS,'fixed repository policy')
    require(mode in {'verify','publish'},'fixed mode')
    identity={'repository':policy.repository,'repository_id':policy.repository_id,'sha':proof.get('head_sha'),'branch':proof.get('branch'),'run_id':proof.get('run_id'),'run_attempt':proof.get('run_attempt')}
    require(identity==context and proof.get('repository')==policy.repository and proof.get('repository_id')==policy.repository_id,'producer/current source identity')
    require(re.fullmatch('[0-9a-f]{40}',str(identity['sha'])) is not None,'source SHA')
    require(identity['branch']==('main' if mode=='publish' else 'dev'),'publication source branch')
    spec=DESTINATIONS[policy.repository];expected={n for filename,_,_ in spec for n in (filename,str(Path(filename).with_suffix('.json')))}
    if len(spec)>1:expected.add('SHA256SUMS')
    require({f.name for f in files.iterdir()}==expected and all(f.is_file() and not f.is_symlink() for f in files.iterdir()),'exact regular image artifact outputs')
    plans=[];sums=[]
    for filename,image,style in spec:
        archive=files/filename;receipt=metadata(archive.with_suffix('.json'));archive_sha=digest(archive)
        expected_receipt={'artifact_kind':'oci-archive','expected_image':image,'repository':policy.repository,'repository_id':policy.repository_id,'source_sha':identity['sha'],'run_id':str(identity['run_id']),'run_attempt':str(identity['run_attempt']),'filename':filename,'sha256':archive_sha}
        require(receipt==expected_receipt,'archive receipt corroboration/digest')
        tags=['sha-'+identity['sha']] if style=='sha' else ['latest',identity['sha'][:7] if style=='short' else identity['sha']]
        image_digest,selection=oci(archive,set(tags+[image+':'+tag for tag in tags]))
        # Publish the immutable source tag before advancing latest.
        destinations=[image+':'+tag for tag in (tags if style=='sha' else [tags[1],tags[0]])]
        plans.append({'archive':archive,'archive_sha256':archive_sha,'digest':image_digest,'selection':selection,'destinations':destinations})
        sums.append(archive_sha+'  '+filename+'\n')
    if len(spec)>1:require((files/'SHA256SUMS').read_text()==''.join(sums),'image checksum bytes')
    return plans

class NoPackageRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,message,headers,newurl):return None

def package_get(name):
    allowed={image.removeprefix('ghcr.io/cryptolabsza/') for images in DESTINATIONS.values() for _,image,_ in images}
    require(name in allowed,'fixed package metadata target')
    url='https://api.github.com/orgs/cryptolabsza/packages/container/'+urllib.parse.quote(name,safe='')
    request=urllib.request.Request(url,headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2026-03-10','User-Agent':'verified-image-publisher'})
    try:response=urllib.request.build_opener(NoPackageRedirect).open(request,timeout=30)
    except urllib.error.HTTPError as error:response=error
    try:
        code=response.getcode();body=response.read(65537)
        require(len(body)<=65536,'package metadata response bound')
        return code,json.loads(body)
    finally:response.close()

def package_gate(policy,lookup=package_get,*,after=False,previous=None):
    require(policy.repository in DESTINATIONS,'fixed package repository')
    result={}
    for _,image,_ in DESTINATIONS[policy.repository]:
        name=image.removeprefix('ghcr.io/cryptolabsza/')
        try:code,package=lookup(name)
        except (OSError,ValueError,TypeError):raise Held('package metadata unavailable') from None
        require(type(code)is int and isinstance(package,dict),'package metadata shape')
        if code==404:
            require(not after and package.get('message') in {'Not Found','Package not found.'} and package.get('status','404')=='404','package absence must be actual preflight 404')
            result[name]=None;continue
        require(code==200,'package metadata permission/status')
        require(package.get('name')==name and package.get('package_type')=='container' and isinstance(package.get('owner'),dict) and package['owner'].get('login')=='cryptolabsza','fixed package identity')
        require(package.get('visibility')=='private' and type(package.get('id'))is int and package['id']>0,'private package required')
        if after:
            require(isinstance(previous,dict) and name in previous and (previous[name]is None or previous[name]==package['id']),'package identity changed during publication')
        result[name]=package['id']
    return result

def publish(plans,client):
    results=[]
    for plan in plans:
        require(digest(plan['archive'])==plan['archive_sha256'],'archive bytes changed before publication')
        first=plan['destinations'][0];client.import_archive(first,plan['archive'],plan['selection'])
        require(client.digest(first)==plan['digest'],'registry immutable image digest mismatch')
        for target in plan['destinations'][1:]:
            client.copy(first.rsplit(':',1)[0]+'@'+plan['digest'],target)
            require(client.digest(target)==plan['digest'],'registry tag digest mismatch')
        results.append({'published':plan['destinations'],'digest':plan['digest']})
    return results

class Registry:
    def __init__(self,root):
        self.tool='/tmp/ci-publish-tools/regctl'
        pin=json.loads(Path(__file__).with_name('tools.json').read_text())['regctl']
        require(digest(Path(self.tool))==pin['sha256'],'registry tool checksum')
        self.env={'PATH':'/usr/bin:/bin','HOME':str(root),'REGCTL_CONFIG':str(root/'regctl.json'),'DOCKER_CONFIG':str(root/'docker')}
    def run(self,args,input=None):
        result=subprocess.run([self.tool,*args],input=input,text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=self.env,timeout=1200)
        require(result.returncode==0,'registry operation failed');return result.stdout.strip()
    def login(self,actor,token):
        require(re.fullmatch('[A-Za-z0-9_-]+',actor) is not None and token,'registry job credential')
        self.run(['registry','login','ghcr.io','--user',actor,'--pass-stdin'],token+'\n')
    def import_archive(self,reference,archive,name):
        args=['image','import',reference,str(archive)]
        if name:args+=['--name',name]
        self.run(args)
    def copy(self,source,destination):self.run(['image','copy','--force-recursive',source,destination])
    def digest(self,reference):return self.run(['image','digest',reference])

def main(policy):
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['verify','publish']);parser.add_argument('producer_run_id',type=int);parser.add_argument('producer_attempt',type=int);parser.add_argument('artifact_id',type=int);args=parser.parse_args()
    try:
        context={'repository':os.environ['GITHUB_REPOSITORY'],'repository_id':int(os.environ['GITHUB_REPOSITORY_ID']),'sha':os.environ['GITHUB_SHA'],'branch':os.environ['GITHUB_REF_NAME'],'run_id':int(os.environ['GITHUB_RUN_ID']),'run_attempt':int(os.environ['GITHUB_RUN_ATTEMPT'])}
        require((args.producer_run_id,args.producer_attempt)==(context['run_id'],context['run_attempt']),'current producer run/attempt')
        os.umask(0o077)
        with tempfile.TemporaryDirectory(prefix='ci-image-publish-',dir=os.environ.get('RUNNER_TEMP','/tmp')) as td:
            root=Path(td);proof=verify(policy,args.producer_run_id,args.producer_attempt,args.artifact_id,output=root/'verified')
            plans=prepare(policy,root/'verified/files',proof,context,args.mode)
            if args.mode=='verify':print('DEV VERIFICATION PASSED; NO REGISTRY PUBLICATION');return 0
            before=package_gate(policy)
            client=Registry(root);client.login(os.environ['GITHUB_ACTOR'],os.environ['GH_TOKEN']);results=publish(plans,client)
            packages=package_gate(policy,after=True,previous=before)
            print(json.dumps({'verified_private_packages':packages,'images':results}))
        return 0
    except (Held,Refused,KeyError,TypeError,ValueError,OSError,subprocess.TimeoutExpired):
        print('Image publication held: source/artifact/layout/tool/registry verification failed.',file=__import__('sys').stderr);return 1
