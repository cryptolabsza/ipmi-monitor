"""Opt-in bounded local payloads, independently bound to GitHub producer proof."""
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.parse
import uuid
import zipfile
from functools import partial
from local_artifact_routes import ROUTES,ACTIVE_RECIPE_REFS
from verify_artifact import Policy,Refused,require,positive,sha,gh_json,gh_download,verify_metadata

ENDPOINT='http://10.244.240.1:18080'
MAX_MANIFEST_BYTES=65536
# Allow three existing 60-second controller polls; never retry payload failures.
GRANT_WAIT_SECONDS=180
GRANT_RETRY_SECONDS=5
class PendingGrant(Refused):pass
MAX_BUNDLE_BYTES=5*1024**3
REPOSITORY='cryptolabsza/knowledge-base-hosting-troubleshooting'
REPOSITORY_ID=1130243159
FILES=('kb-api.json','kb-api.tar')
FIELDS={'schema','object_id','producer_lease_id','repository_id','run_id','run_attempt','head_sha','producer_runner_id','files'}

def canonical_manifest(manifest):
    return (json.dumps(manifest,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('utf-8')

def unique_json(data):
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value,'duplicate manifest JSON field');value[key]=item
        return value
    try:return json.loads(data,object_pairs_hook=unique)
    except (ValueError,UnicodeError):raise Refused('manifest JSON') from None

def object_uuid(value):
    try:return type(value)is str and str(uuid.UUID(value))==value
    except (ValueError,AttributeError):return False

def validate_manifest(manifest,route=None):
    require(type(manifest)is dict and set(manifest)==FIELDS,'exact local manifest schema')
    require(type(manifest['schema'])is int and manifest['schema']==2,'local manifest version')
    require(object_uuid(manifest['object_id']) and manifest['object_id']==manifest['producer_lease_id'],'local producer object identity')
    route=ROUTES.get(manifest['repository_id']) if route is None else route
    require(route is not None and route==ROUTES.get(manifest['repository_id']),'fixed manifest route')
    allowed=route['files']
    require(all(positive(manifest[k]) for k in ('repository_id','run_id','run_attempt','producer_runner_id')) and manifest['repository_id']==route['repository_id'] and sha(manifest['head_sha']),'local manifest source identity')
    files=manifest['files'];require(type(files)is list and len(files)==len(allowed),'local file closure')
    total=0;names=[]
    for item in files:
        require(type(item)is dict and set(item)=={'path','size','sha256'},'exact local file schema')
        require(type(item['path'])is str and item['path'] in allowed and positive(item['size']),'local file name/size')
        require(type(item['sha256'])is str and re.fullmatch('[0-9a-f]{64}',item['sha256']),'local file digest')
        names.append(item['path']);total+=item['size']
    require(tuple(names)==allowed and total<=MAX_BUNDLE_BYTES,'local exact sorted closure/bundle bound')
    require(len(canonical_manifest(manifest))<=MAX_MANIFEST_BYTES,'local manifest byte bound')
    return manifest

def local_policy(policy):
    require(isinstance(policy,Policy) and policy.transport_schema==2,'fixed local policy')
    route=ROUTES.get(policy.repository_id)
    require(route is not None and policy.artifact_kind=='oci' and all(getattr(policy,key)==route[key] for key in ('repository','repository_id','workflow_path','producer_job','group_id','build_label','artifact_stem')),'fixed local route policy')
    return route

def verify_manifest(policy,run_id,attempt,artifact_id,*,api=gh_json,download=gh_download,now=None):
    route=local_policy(policy)
    proof=verify_metadata(api,policy,run_id,attempt,artifact_id,now)
    require(proof['size_in_bytes']<=MAX_MANIFEST_BYTES,'tiny manifest ZIP bound')
    with tempfile.TemporaryDirectory(prefix='local-manifest-') as temporary:
        archive=Path(temporary)/'manifest.zip'
        download(f'/repos/{policy.repository}/actions/artifacts/{artifact_id}/zip',archive,MAX_MANIFEST_BYTES)
        require(archive.is_file() and not archive.is_symlink() and archive.stat().st_size<=MAX_MANIFEST_BYTES,'tiny manifest ZIP bound')
        data=archive.read_bytes()
        require(len(data)==proof['size_in_bytes'] and 'sha256:'+hashlib.sha256(data).hexdigest()==proof['artifact_digest'],'manifest ZIP digest/size mismatch')
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as bundle:
                entries=bundle.infolist();require(len(entries)==1,'sole manifest ZIP member')
                member=entries[0];kind=stat.S_IFMT(member.external_attr>>16)
                require(member.filename=='manifest.json' and kind in {0,stat.S_IFREG} and not member.flag_bits&1 and member.compress_type in {zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED} and 0<member.file_size<=MAX_MANIFEST_BYTES,'fixed regular manifest ZIP member')
                with bundle.open(member) as source:raw=source.read(MAX_MANIFEST_BYTES+1)
                require(len(raw)==member.file_size,'manifest expanded size')
        except (zipfile.BadZipFile,RuntimeError,NotImplementedError,ValueError):raise Refused('manifest ZIP invalid') from None
        manifest=validate_manifest(unique_json(raw),route);require(raw==canonical_manifest(manifest),'canonical manifest bytes required')
    for key in ('repository_id','run_id','run_attempt','head_sha','producer_runner_id'):
        require(manifest[key]==proof[key] and type(manifest[key])is type(proof[key]),'manifest producer proof binding')
    require(verify_metadata(api,policy,run_id,attempt,artifact_id,now)==proof,'producer changed during manifest verification')
    return dict(proof,transport_schema=2),manifest

def http_request(method,path,*,endpoint=ENDPOINT,body=None,size=None,output=None,maximum=MAX_MANIFEST_BYTES,expect_continue=False):
    """No proxies, credentials, redirects, compression or caller-selected guest URL."""
    if method=='PUT' and expect_continue:return expect_put(path,endpoint=endpoint,body=body,size=size,maximum=maximum)
    target=urllib.parse.urlsplit(endpoint)
    require(target.scheme=='http' and target.hostname and not target.username and not target.password and target.path in {'','/'} and not target.query and not target.fragment,'fixed local endpoint')
    connection=http.client.HTTPConnection(target.hostname,target.port or 80,timeout=30)
    try:
        headers={'Connection':'close','Accept-Encoding':'identity'}
        if size is not None:headers['Content-Length']=str(size)
        connection.request(method,path,body=body,headers=headers,encode_chunked=False)
        response=connection.getresponse()
        if method=='GET' and response.status in {403,503}:
            length=response.getheader('Content-Length')
            require(length is not None and re.fullmatch('[0-9]+',length) and 0<int(length)<=256 and not response.getheader('Transfer-Encoding') and response.getheader('Content-Encoding') in {None,'identity'},'bounded fixed local denial')
            body=response.read(int(length)+1)
            require(len(body)==int(length),'complete fixed local denial')
            reason=unique_json(body)
            require(type(reason)is dict and set(reason)=={'code'} and reason['code']==('denied' if response.status==403 else 'capacity'),'fixed local pending denial')
            raise PendingGrant('local reader grant pending')
        require(response.status==(201 if method=='PUT' else 200),'local artifact operation refused')
        length=response.getheader('Content-Length');require(length is not None and re.fullmatch('[0-9]+',length),'local Content-Length required')
        length=int(length);require(0<length<=maximum and not response.getheader('Transfer-Encoding') and response.getheader('Content-Encoding') in {None,'identity'},'local bounded identity response')
        destination=output if output is not None else io.BytesIO();count=0;deadline=time.monotonic()+1200
        while count<length:
            require(time.monotonic()<deadline,'local artifact timeout')
            chunk=response.read(min(65536,length-count));require(chunk,'local artifact truncated')
            destination.write(chunk);count+=len(chunk)
        require(not response.read(1),'local artifact extra bytes')
        return destination.getvalue() if output is None else count
    except (OSError,http.client.HTTPException):raise Refused('local artifact connection failed') from None
    finally:connection.close()

def fetch_file(object_id,name,destination,maximum,*,route=None):
    allowed=FILES if route is None else route['files']
    require(object_uuid(object_id) and name in allowed,'fixed local GET target')
    with destination.open('xb') as output:
        return http_request('GET','/v2/objects/'+object_id+'/files/'+urllib.parse.quote(name,safe=''),output=output,maximum=maximum)

def fetch_payload(fetch,object_id,item,path,*,wait_for_grant=False):
    deadline=time.monotonic()+GRANT_WAIT_SECONDS
    while True:
        try:return fetch(object_id,item['path'],path,item['size'])
        except PendingGrant:
            require(wait_for_grant,'local grant wait allowed only at first small receipt')
            if os.path.lexists(path):
                require(path.is_file() and not path.is_symlink() and path.stat().st_size==0,'local payload began before grant refusal')
                path.unlink()
            remaining=deadline-time.monotonic()
            require(remaining>0,'local reader grant wait expired')
            time.sleep(min(GRANT_RETRY_SECONDS,remaining))

def materialize(policy,run_id,attempt,artifact_id,*,output,api=gh_json,download=gh_download,fetch=None,describe=None):
    output=Path(output);require(not os.path.lexists(output),'verified output already exists')
    route=local_policy(policy)
    proof,manifest=verify_manifest(policy,run_id,attempt,artifact_id,api=api,download=download)
    if describe is not None:
        record=describe(manifest['object_id'])
        require(type(record)is dict and record.get('schema')==2 and record.get('state')=='sealed' and record.get('manifest')==manifest,'sealed local origin required')
        for key in ('object_id','producer_lease_id','repository_id','producer_runner_id'):
            require(type(record.get(key))is type(manifest[key]) and record.get(key)==manifest[key],'captured local producer origin')
    total=sum(item['size'] for item in manifest['files'])
    require(shutil.disk_usage(output.parent).free>=total+1024**3,'local materialization disk reserve')
    with tempfile.TemporaryDirectory(prefix='.local-artifact-',dir=output.parent) as temporary:
        work=Path(temporary);files=work/'files';files.mkdir(mode=0o700)
        for item in manifest['files']:
            path=files/item['path'];default_fetch=fetch_file if route['repository_id']==REPOSITORY_ID else partial(fetch_file,route=route)
            fetch_payload(fetch or default_fetch,manifest['object_id'],item,path,wait_for_grant=item['path']==route['files'][0] and item['size']<=MAX_MANIFEST_BYTES)
            require(path.is_file() and not path.is_symlink() and path.stat().st_size==item['size'],'local payload exact size/type')
            digest=hashlib.sha256()
            with path.open('rb') as source:
                for chunk in iter(lambda:source.read(65536),b''):digest.update(chunk)
            require(digest.hexdigest()==item['sha256'],'local payload digest mismatch')
            os.chmod(path,0o600)
        current=verify_metadata(api,policy,run_id,attempt,artifact_id)
        require(dict(current,transport_schema=2)==proof,'producer changed during local materialization')
        require(not os.path.lexists(output),'verified output already exists');os.rename(work,output)
    return dict(proof,local_object_id=manifest['object_id'],local_manifest_sha256=hashlib.sha256(canonical_manifest(manifest)).hexdigest(),files=manifest['files'])

def upload_bundle(files,producer_context,*,endpoint=ENDPOINT):
    require(type(producer_context)is dict and set(producer_context)=={'repository_id','run_id','run_attempt','head_sha'},'exact producer context')
    route=ROUTES.get(producer_context['repository_id']);require(route is not None,'fixed producer route')
    require(producer_context['repository_id']==route['repository_id'] and all(positive(producer_context[k]) for k in ('repository_id','run_id','run_attempt')) and sha(producer_context['head_sha']),'producer context identity')
    files=Path(files);require(files.is_dir() and not files.is_symlink() and {p.name for p in files.iterdir()}==set(route['files']),'exact producer file closure')
    entries=[];binding=None;total=0
    for name in route['files']:
        path=files/name;require(path.is_file() and not path.is_symlink(),'regular producer file required')
        size=path.stat().st_size;total+=size;require(0<size and total<=MAX_BUNDLE_BYTES,'producer bundle bound')
        digest=hashlib.sha256()
        with path.open('rb') as source:
            for chunk in iter(lambda:source.read(65536),b''):digest.update(chunk)
        item=dict(path=name,size=size,sha256=digest.hexdigest())
        with path.open('rb') as source:
            result=unique_json(http_request('PUT','/v2/files/'+urllib.parse.quote(name,safe=''),endpoint=endpoint,body=source,size=size,expect_continue=True))
        require(type(result)is dict and set(result)=={'schema','object_id','producer_lease_id','producer_runner_id','path','size','sha256'} and type(result['schema'])is int and result['schema']==2,'upload receipt schema')
        require(all(type(result.get(k))is type(value) and result.get(k)==value for k,value in item.items()),'upload server digest/size')
        current={k:result[k] for k in ('object_id','producer_lease_id','producer_runner_id')}
        require(binding is None or current==binding,'upload producer binding changed');binding=current;entries.append(item)
    manifest=validate_manifest(dict(schema=2,**binding,**producer_context,files=entries),route);raw=canonical_manifest(manifest)
    result=http_request('PUT','/v2/manifest',endpoint=endpoint,body=raw,size=len(raw),expect_continue=True)
    require(result==raw,'server sealed canonical manifest mismatch')
    return manifest

def metadata_pages(api,path,key):
    rows=[]
    for page in range(1,11):
        response=api(path+('&' if '?' in path else '?')+f'per_page=100&page={page}')
        batch=response[key];require(type(batch)is list and len(batch)<=100,'local metadata page shape');rows.extend(batch)
        if len(batch)<100:
            require(response.get('total_count')==len(rows),'local metadata pagination changed');return rows
    raise Refused('local metadata pagination bound')

def active_policy(repository_id):
    route=ROUTES.get(repository_id)
    if route is None:return None
    if repository_id==REPOSITORY_ID:
        import kb_completion as kb
        if kb.LOCAL_POLICY is None:return None
        local_policy(kb.LOCAL_POLICY)
        return kb.LOCAL_POLICY,dict(build_ref=kb.LOCAL_POLICY.recipe_ref,publish_ref=kb.LOCAL_PUBLISH_REF,operation_ref=kb.LOCAL_OPERATION_REF)
    refs=ACTIVE_RECIPE_REFS.get(repository_id)
    if refs is None:return None
    policy=Policy(repository=route['repository'],repository_id=repository_id,workflow_path=route['workflow_path'],recipe_ref=refs['build_ref'],producer_job=route['producer_job'],group_id=route['group_id'],build_label=route['build_label'],artifact_kind='oci',artifact_stem=route['artifact_stem'],transport_schema=2)
    return policy,refs

def exact_reference(run,ref):
    require(type(ref)is str and re.fullmatch(r'cryptolabsza/[A-Za-z0-9_.-]+/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml@[0-9a-f]{40}',ref),'reviewed local recipe required')
    rows=[r for r in run['referenced_workflows'] if r['path'].split('@')[0]==ref.split('@')[0]]
    require(len(rows)==1 and rows[0]['path']==ref and rows[0]['sha']==ref.rsplit('@',1)[1],'exact reviewed local recipe')

def grant_for_lease(lease,*,api,download):
    active=active_policy(lease.get('repository_id'))
    if lease.get('purpose')!='publish' or active is None:return None
    policy,refs=active;route=local_policy(policy)
    label=f"ci-linux-publish-v1-r{policy.repository_id}"
    require(lease.get('state')=='running' and positive(lease.get('runner_id')) and lease.get('group_id')==12 and lease.get('label')==label,'actual local publisher lease')
    require(refs['publish_ref'] is not None,'installed local publisher recipe')
    base='/repos/'+policy.repository;matches=[]
    runs=metadata_pages(api,base+'/actions/runs?status=in_progress','workflow_runs')
    candidates=[r for r in runs if r.get('path')==policy.workflow_path]
    require(len(candidates)<=4,'local publisher active run bound')
    for run in candidates:
        require(positive(run.get('id')) and positive(run.get('run_attempt')),'active local run identity')
        jobs=metadata_pages(api,base+f'/actions/runs/{run["id"]}/attempts/{run["run_attempt"]}/jobs','jobs')
        for job in jobs:
            if job.get('runner_id')==lease['runner_id'] and job.get('status')=='in_progress':matches.append((run,job,jobs))
    if not matches:return None
    require(len(matches)==1,'unique active local publisher job');run,job,jobs=matches[0]
    require((run.get('head_branch'),job.get('name')) in {(branch,name) for branch,name,_ in route['reader_jobs']} and job.get('conclusion')is None and positive(job.get('id')) and type(job.get('runner_group_id'))is int and job['runner_group_id']==12 and job.get('runner_group_name')=='ci-publish-ephemeral' and label in job.get('labels',[]),'active local publisher group/job/label')
    require(all(type(job.get(k))is type(value) and job.get(k)==value for k,value in dict(run_id=run['id'],run_attempt=run['run_attempt'],head_sha=run['head_sha']).items()),'active publisher run/source identity')
    exact_reference(run,refs['publish_ref'])
    producers=[j for j in jobs if j.get('name')==policy.producer_job]
    require(len(producers)==1,'unique local producer job')
    if producers[0].get('status') in {'queued','in_progress','waiting','pending'} and producers[0].get('conclusion')is None:return None
    require(producers[0].get('status')=='completed' and producers[0].get('conclusion')=='success','successful local producer required')
    artifacts=metadata_pages(api,base+f'/actions/runs/{run["id"]}/artifacts','artifacts')
    artifacts=[a for a in artifacts if a.get('name')==f'{policy.artifact_stem}-{run["id"]}-{run["run_attempt"]}']
    if not artifacts:return None
    require(len(artifacts)==1,'unique local producer artifact')
    proof,manifest=verify_manifest(policy,run['id'],run['run_attempt'],artifacts[0]['id'],api=api,download=download)
    require(proof['head_sha']==run['head_sha'],'local publisher producer source')
    # Re-read active assignment after the independent producer download/checks.
    latest=api(base+f'/actions/runs/{run["id"]}')
    require(latest==run,'publisher run changed during local grant')
    jobs=metadata_pages(api,base+f'/actions/runs/{run["id"]}/attempts/{run["run_attempt"]}/jobs','jobs')
    require([j for j in jobs if j.get('runner_id')==lease['runner_id'] and j.get('status')=='in_progress']==[job],'publisher assignment changed during local grant')
    return dict(proof=proof,manifest=manifest)

HOST_COMMAND=['/usr/bin/ssh','-F','/Users/hanneszietsman/CrypotAI/ci-pool-control/ssh_config','192.168.1.101','/usr/libexec/ci-simple-pool']
def host_control(verb,object_id,filename=None,*,output=None,maximum=MAX_MANIFEST_BYTES):
    require(verb in {'artifact_describe','artifact_export','artifact_delete'} and object_uuid(object_id),'fixed local artifact host operation')
    request=dict(verb=verb,object_id=object_id)
    if verb=='artifact_export':require(filename in {name for route in ROUTES.values() for name in route['files']} and output is not None,'fixed artifact export filename');request['filename']=filename
    else:require(filename is None and output is None,'fixed artifact describe')
    process=subprocess.Popen(HOST_COMMAND,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    result=io.BytesIO() if output is None else output;count=0;deadline=time.monotonic()+1200
    try:
        process.stdin.write(json.dumps(request,sort_keys=True).encode());process.stdin.close()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout,selectors.EVENT_READ)
            while True:
                remaining=deadline-time.monotonic();require(remaining>0 and selector.select(remaining),'local host export timeout')
                chunk=os.read(process.stdout.fileno(),65536)
                if not chunk:break
                count+=len(chunk);require(count<=maximum,'local host response bound');result.write(chunk)
        require(process.wait(timeout=max(.001,deadline-time.monotonic()))==0,'local host operation failed')
        return unique_json(result.getvalue()) if output is None else count
    except (OSError,subprocess.SubprocessError):raise Refused('local host transport failed') from None
    finally:
        if process.poll()is None:process.kill()
        process.wait();process.stdout.close()

def host_describe(object_id):return host_control('artifact_describe',object_id)
def host_fetch(object_id,name,destination,maximum):
    with destination.open('xb') as output:return host_control('artifact_export',object_id,name,output=output,maximum=maximum)

def host_delete(object_id):return host_control('artifact_delete',object_id)

def pr_artifact_disposition(terminal,snapshot,*,api):
    """GC only: root-captured runner binds PR bytes; manifest source is no authority."""
    if terminal.get('artifact_transport_schema')!=2 or terminal.get('purpose')!='build' or terminal.get('state')!='destroyed' or terminal.get('repository_id') not in ROUTES:return 'retain'
    try:
        active=active_policy(terminal['repository_id']);require(active is not None,'installed PR cleanup recipe required')
        policy,refs=active;route=local_policy(policy)
        object_id=terminal['id'];require(object_uuid(object_id) and terminal.get('artifact_object_id')==object_id and positive(terminal.get('runner_id')),'root PR terminal identity')
        require(type(snapshot)is dict and type(snapshot.get('schema'))is int and snapshot['schema']==2,'root PR object schema')
        for key,value in dict(object_id=object_id,producer_lease_id=object_id,repository_id=policy.repository_id,producer_runner_id=terminal['runner_id']).items():
            require(type(snapshot.get(key))is type(value) and snapshot.get(key)==value,'captured PR object identity')
        if snapshot.get('state')=='deleted':return 'delete'
        require(snapshot.get('state')=='sealed','sealed PR object required');manifest=validate_manifest(snapshot['manifest'],route)
        require(all(manifest[k]==snapshot[k] for k in ('object_id','producer_lease_id','repository_id','producer_runner_id')),'sealed PR origin binding')
        run_id=manifest['run_id'];attempt=manifest['run_attempt'];base='/repos/'+policy.repository;path=base+f'/actions/runs/{run_id}'
        def inspect():
            repo=api(base);require(type(repo.get('id'))is int and repo['id']==policy.repository_id and repo.get('full_name')==policy.repository,'PR repository identity')
            latest=api(path);run=api(path+f'/attempts/{attempt}')
            for value in (latest,run):
                require(type(value['id'])is int and value['id']==run_id and type(value['run_attempt'])is int and value['run_attempt']==attempt,'PR exact actual attempt')
                for key in ('repository','head_repository'):
                    require(type(value[key]['id'])is int and value[key]['id']==policy.repository_id and value[key]['full_name']==policy.repository,'PR actual source repository')
                require(sha(value['head_sha']),'PR actual source SHA')
            keys=('id','run_attempt','head_sha','head_branch','event','path','status','conclusion')
            require(all(latest[k]==run[k] for k in keys),'PR latest attempt/source agreement')
            if run['event'] in {'push','workflow_dispatch'}:return 'retain',None
            require(run['event']=='pull_request' and run['path'] in {policy.workflow_path,policy.workflow_path+'@'+run['head_branch'],policy.workflow_path+'@refs/heads/'+run['head_branch']},'fixed PR workflow')
            for value in (latest,run):exact_reference(value,policy.recipe_ref)
            if run['status']!='completed':return 'pending',None
            jobs=metadata_pages(api,path+f'/attempts/{attempt}/jobs','jobs')
            producers=[j for j in jobs if j['name']==policy.producer_job];require(len(producers)==1,'unique PR producer job');job=producers[0]
            require(all(type(job.get(k))is type(v) and job.get(k)==v for k,v in dict(run_id=run_id,run_attempt=attempt,head_sha=run['head_sha'],runner_id=terminal['runner_id'],runner_group_id=policy.group_id).items()),'PR actual producer runner/source')
            require(positive(job['id']) and type(job['conclusion'])is str and bool(job['conclusion']) and job['status']=='completed' and job['runner_group_name']==route['build_group'] and policy.build_label in job['labels'],'completed PR producer placement')
            consumer_names={name for _,name,_ in route['reader_jobs']}
            if policy.repository_id==REPOSITORY_ID:consumer_names.add('deploy / operation')
            if policy.repository_id==1184455700:consumer_names.update({'Deploy dry-run (wk01) / operation','Deploy to wk01 / operation'})
            consumers=[j for j in jobs if j['name'] in consumer_names]
            if any(j['status']!='completed' or j['conclusion']!='skipped' for j in consumers):return 'retain',None
            fields=('id','name','run_id','run_attempt','head_sha','status','conclusion','runner_id','runner_group_id','runner_group_name','labels')
            signature=({k:run[k] for k in keys},[{k:j.get(k) for k in fields} for j in jobs])
            return 'delete',signature
        disposition,authority=inspect()
        if disposition!='delete':return disposition
        second,current=inspect()
        return 'delete' if second=='delete' and current==authority else 'pending'
    except Exception:return 'pending'

# Admission retries are pre-body only; one absolute deadline spans fresh sockets.
PUT_RETRY_SECONDS=5
PUT_IO_SECONDS=1800
PUT_WAIT_SECONDS=PUT_IO_SECONDS

def _wire_line(connection,stream,deadline):
    line=bytearray()
    while not line.endswith(b'\r\n'):
        remaining=deadline-time.monotonic();require(remaining>0,'local PUT response timeout')
        connection.sock.settimeout(min(30,remaining));part=stream.read1(1)
        require(part,'local PUT truncated headers');line.extend(part)
        require(len(line)<=4096,'local PUT header bound')
    return bytes(line)

def _wire_head(connection,stream,deadline):
    status=_wire_line(connection,stream,deadline)
    match=re.fullmatch(rb'HTTP/1\.[01] ([0-9]{3}) [\x20-\x7e]*\r\n',status);require(match is not None,'local PUT status shape')
    headers={};total=len(status)
    while True:
        line=_wire_line(connection,stream,deadline);total+=len(line);require(total<=16384,'local PUT headers bound')
        if line==b'\r\n':break
        require(b':' in line and not line.startswith((b' ',b'\t')),'local PUT header shape')
        key,value=line[:-2].split(b':',1)
        require(re.fullmatch(rb'[A-Za-z0-9-]+',key) is not None and key.lower() not in headers,'local PUT duplicate header')
        headers[key.lower()]=value.strip()
    return int(match[1]),headers

def _wire_body(connection,stream,headers,maximum,deadline,*,eof=False):
    length=headers.get(b'content-length')
    require(length is not None and re.fullmatch(rb'0|[1-9][0-9]*',length) and 0<int(length)<=maximum and b'transfer-encoding' not in headers and headers.get(b'content-encoding') in {None,b'identity'},'local PUT bounded response')
    body=bytearray();length=int(length)
    while len(body)<length:
        remaining=deadline-time.monotonic();require(remaining>0,'local PUT response timeout');connection.sock.settimeout(min(30,remaining))
        part=stream.read1(min(65536,length-len(body)));require(part,'local PUT truncated body');body.extend(part)
    if eof:
        remaining=deadline-time.monotonic();require(remaining>0,'local PUT response timeout');connection.sock.settimeout(min(30,remaining))
        require(stream.read1(1)==b'','local PUT extra capacity bytes')
    return bytes(body)

def expect_put(path,*,endpoint,body,size,maximum):
    target=urllib.parse.urlsplit(endpoint)
    require(target.scheme=='http' and target.hostname and not target.username and not target.password and target.path in {'','/'} and not target.query and not target.fragment,'fixed local endpoint')
    require(positive(size) and size<=MAX_BUNDLE_BYTES,'local PUT body bound')
    started=time.monotonic();admission_deadline=started+PUT_WAIT_SECONDS;deadline=started+PUT_IO_SECONDS
    while True:
        connection=http.client.HTTPConnection(target.hostname,target.port or 80,timeout=min(30,max(.001,admission_deadline-time.monotonic())));stream=None;capacity=False
        try:
            require(time.monotonic()<admission_deadline,'local PUT admission wait expired')
            connection.connect();connection.putrequest('PUT',path,skip_accept_encoding=True)
            for key,value in {'Content-Length':str(size),'Expect':'100-continue','Connection':'close','Accept-Encoding':'identity'}.items():connection.putheader(key,value)
            connection.endheaders();stream=connection.sock.makefile('rb')
            status,headers=_wire_head(connection,stream,min(admission_deadline,time.monotonic()+30))
            if status==503:
                raw=_wire_body(connection,stream,headers,256,min(admission_deadline,time.monotonic()+30),eof=True)
                require(raw==canonical_manifest({'code':'capacity'}),'local PUT exact capacity response')
                capacity=True
            else:
                require(status==100 and headers=={},'local PUT explicit admission required')
                sent=0
                while sent<size:
                    remaining=deadline-time.monotonic();require(remaining>0,'local PUT body timeout');connection.sock.settimeout(min(30,remaining))
                    chunk=body.read(min(65536,size-sent)) if hasattr(body,'read') else body[sent:sent+min(65536,size-sent)]
                    require(chunk and len(chunk)<=size-sent,'local PUT source length');connection.send(chunk);sent+=len(chunk)
                status,headers=_wire_head(connection,stream,min(deadline,time.monotonic()+30))
                require(status==201,'local PUT final acceptance required')
                return _wire_body(connection,stream,headers,maximum,min(deadline,time.monotonic()+30))
        except (OSError,http.client.HTTPException):raise Refused('local PUT uncertain IO; no replay') from None
        finally:
            if stream is not None:stream.close()
            connection.close()
        require(capacity,'local PUT admission required')
        remaining=admission_deadline-time.monotonic();require(remaining>0,'local PUT admission wait expired')
        time.sleep(min(PUT_RETRY_SECONDS,remaining))
