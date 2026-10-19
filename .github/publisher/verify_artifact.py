"""Verify a fixed reviewed producer and safely materialize its GitHub artifact.

A pinned publisher leaf calls main(Policy(...literal constants...)). No checkout,
artifact member, receipt, caller input or command-line policy supplies authority.
"""
import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zipfile

MAX_DOWNLOAD_BYTES=4*1024**3
MAX_EXPANDED_BYTES=8*1024**3
MAX_FILES=10000
MAX_METADATA_BYTES=4*1024**2
OUTPUT=Path('verified-artifact')

class Refused(Exception):
    """Controlled operator reason; never includes API bodies, secrets or redirects."""

def require(condition,reason):
    if not condition:raise Refused(reason)

def positive(value):
    return type(value)is int and value>0

def sha(value):
    return type(value)is str and re.fullmatch('[0-9a-f]{40}',value)is not None

@dataclass(frozen=True)
class Policy:
    repository:str
    repository_id:int
    workflow_path:str
    recipe_ref:str
    producer_job:str
    group_id:int
    build_label:str
    artifact_kind:str
    artifact_stem:str

    def __post_init__(self):
        require(type(self.repository)is str and re.fullmatch(r'(Oxiom-Systems|cryptolabsza)/[A-Za-z0-9_.-]+',self.repository),'fixed repository')
        require(positive(self.repository_id),'fixed repository ID')
        require(type(self.workflow_path)is str and re.fullmatch(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml',self.workflow_path),'fixed workflow path')
        require(type(self.recipe_ref)is str and re.fullmatch(re.escape(self.repository)+r'/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml@[0-9a-f]{40}',self.recipe_ref),'immutable build recipe')
        groups={'Oxiom-Systems':{4,5},'cryptolabsza':{10,11}}
        require(type(self.group_id)is int and self.group_id in groups[self.repository.split('/')[0]],'build group')
        require(self.build_label==f'ci-linux-cpu-v1-r{self.repository_id}','build label')
        require(type(self.producer_job)is str and 0<len(self.producer_job)<=200 and all(ord(c)>=32 for c in self.producer_job),'producer job')
        require(self.artifact_kind in {'oci','docker-save','pypi','apk','site'},'artifact kind')
        require(type(self.artifact_stem)is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}',self.artifact_stem),'artifact name stem')

def timestamp(value):
    try:
        result=datetime.fromisoformat(value.replace('Z','+00:00'))
        require(result.tzinfo is not None,'timestamp timezone')
        return result
    except (ValueError,TypeError,AttributeError):raise Refused('metadata timestamp') from None

def gh_stream(path,destination,maximum,timeout=300):
    """Bound stdout, wall clock and memory; suppress GH error/redirect diagnostics."""
    gh=next((p for p in ('/usr/bin/gh','/opt/homebrew/bin/gh','/tmp/ci-publish-tools/gh') if os.path.isfile(p)),None)
    require(gh is not None,'installed gh required')
    command=[gh,'api','--hostname','github.com','--method','GET','--allow-escape-sequences',path]
    try:
        process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    except OSError:raise Refused('GitHub process unavailable') from None
    size=0;deadline=time.monotonic()+timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout,selectors.EVENT_READ)
            while True:
                remaining=deadline-time.monotonic()
                require(remaining>0,'GitHub request timeout')
                require(selector.select(remaining),'GitHub request timeout')
                chunk=os.read(process.stdout.fileno(),64*1024)
                if not chunk:break
                size+=len(chunk);require(size<=maximum,'GitHub response size bound')
                destination.write(chunk)
            require(process.wait(timeout=max(.001,deadline-time.monotonic()))==0,'GitHub GET failed')
    except subprocess.TimeoutExpired:raise Refused('GitHub request timeout') from None
    finally:
        if process.poll()is None:process.kill()
        process.wait();process.stdout.close()
    return size

def gh_json(path):
    data=io.BytesIO();gh_stream(path,data,MAX_METADATA_BYTES,30)
    try:return json.loads(data.getvalue())
    except (ValueError,UnicodeError):raise Refused('GitHub JSON response') from None

def gh_download(path,destination,maximum):
    with destination.open('xb') as output:gh_stream(path,output,maximum)

def pages(api,path,key):
    items=[]
    for page in range(1,11):
        response=api(path+f'?per_page=100&page={page}')
        batch=response[key];require(type(batch)is list and len(batch)<=100,'metadata page shape')
        items.extend(batch)
        if len(batch)<100:
            require(response.get('total_count')==len(items),'metadata list changed or incomplete')
            return items
    raise Refused('metadata pagination bound')

def verify_metadata(api,policy,run_id,attempt,artifact_id,now=None):
    require(isinstance(policy,Policy),'fixed leaf policy required')
    require(all(positive(x) for x in (run_id,attempt,artifact_id)),'numeric dynamic IDs')
    base=f'/repos/{policy.repository}';runpath=f'{base}/actions/runs/{run_id}'
    repo=api(base)
    require(repo['id']==policy.repository_id and repo['full_name']==policy.repository,'repository identity')
    latest=api(runpath);run=api(runpath+f'/attempts/{attempt}')
    for value in (latest,run):
        require(value['id']==run_id and value['run_attempt']==attempt,'latest run attempt')
        for key in ('repository','head_repository'):
            require(value[key]['id']==policy.repository_id and value[key]['full_name']==policy.repository,'run repository identity')
        branch=value['head_branch'];head=value['head_sha']
        require(branch in {'main','dev'} and sha(head),'protected source ref')
        require(value['event'] in {'push','workflow_dispatch'} and value.get('pull_requests')==[],'protected source event')
        require(value['path'] in {policy.workflow_path,policy.workflow_path+'@'+branch,policy.workflow_path+'@refs/heads/'+branch},'producer workflow path')
        require((value['status']=='completed' and value['conclusion']=='success') or (value['status']=='in_progress' and value['conclusion']is None),'producer run state')
        refs=[r for r in value['referenced_workflows'] if r['path'].split('@')[0]==policy.recipe_ref.split('@')[0]]
        require(len(refs)==1 and refs[0]['path']==policy.recipe_ref and refs[0]['sha']==policy.recipe_ref.rsplit('@',1)[1],'immutable producer recipe')
    for key in ('head_sha','head_branch','event','path'):
        require(latest[key]==run[key],'attempt source mismatch')
    branch=api(base+'/branches/'+run['head_branch'])
    require(branch['name']==run['head_branch'] and branch['protected']is True and sha(branch['commit']['sha']),'branch protection')
    comparison=api(base+'/compare/'+run['head_sha']+'...'+branch['commit']['sha'])
    require(comparison['status'] in {'ahead','identical'} and comparison['base_commit']['sha']==run['head_sha'] and comparison['merge_base_commit']['sha']==run['head_sha'],'source not merged into protected branch')
    jobs=pages(api,runpath+f'/attempts/{attempt}/jobs','jobs')
    jobs=[j for j in jobs if j['name']==policy.producer_job]
    require(len(jobs)==1,'unique producer job')
    job=jobs[0]
    require(job['run_id']==run_id and job['run_attempt']==attempt and job['head_sha']==run['head_sha'],'producer job identity')
    group_name='ci-build-public-ephemeral' if policy.group_id in {5,11} else 'ci-build-ephemeral'
    require(job['status']=='completed' and job['conclusion']=='success' and positive(job['id']) and positive(job['runner_id']),'successful producer job')
    require(job['runner_group_id']==policy.group_id and job['runner_group_name']==group_name and policy.build_label in job['labels'],'producer ephemeral group/label')
    artifact=api(base+f'/actions/artifacts/{artifact_id}')
    name=f'{policy.artifact_stem}-{run_id}-{attempt}'
    artifacts=pages(api,runpath+'/artifacts','artifacts')
    matches=[a for a in artifacts if a['name']==name]
    require(len(matches)==1 and matches[0]==artifact,'unique artifact metadata')
    require(artifact['id']==artifact_id and artifact['name']==name and artifact['expired']is False,'artifact identity/expiration')
    identity=artifact['workflow_run']
    require(identity['id']==run_id and identity['repository_id']==policy.repository_id and identity['head_repository_id']==policy.repository_id and identity['head_sha']==run['head_sha'] and identity['head_branch']==run['head_branch'],'artifact producer identity')
    require(type(artifact['digest'])is str and re.fullmatch('sha256:[0-9a-f]{64}',artifact['digest']),'artifact API digest required')
    require(positive(artifact['size_in_bytes']) and artifact['size_in_bytes']<=MAX_DOWNLOAD_BYTES,'artifact download size')
    require(timestamp(job['started_at'])<=timestamp(artifact['created_at'])<=timestamp(job['completed_at']),'artifact outside successful job attempt')
    current=timestamp(now) if now else datetime.now(timezone.utc)
    require(timestamp(artifact['expires_at'])>current,'artifact expired')
    return dict(repository=policy.repository,repository_id=policy.repository_id,run_id=run_id,run_attempt=attempt,
                head_sha=run['head_sha'],branch=run['head_branch'],event=run['event'],producer_job_id=job['id'],
                recipe_ref=policy.recipe_ref,artifact_id=artifact_id,artifact_name=name,
                artifact_kind=policy.artifact_kind,artifact_digest=artifact['digest'],size_in_bytes=artifact['size_in_bytes'])

def bounded_directory(archive):
    # ZipFile reads the whole central directory before infolist/count checks.
    # Bound that allocation first. ZIP64 directory envelopes are unsupported.
    with archive.open('rb') as source:
        size=source.seek(0,os.SEEK_END);source.seek(max(0,size-65557))
        tail=source.read(65557);offset=tail.rfind(b'PK\x05\x06')
    require(offset>=0 and len(tail)-offset>=22,'ZIP directory footer')
    _,disk,start_disk,count_disk,count,length,start,comment=struct.unpack_from('<4s4H2LH',tail,offset)
    require(offset+22+comment==len(tail) and disk==start_disk==0 and count_disk==count and 0<count<=MAX_FILES,'ZIP directory shape')
    require(tail[max(0,offset-20):max(0,offset-20)+4]!=b'PK\x06\x07' and length<=16*1024**2 and start+length<=size-len(tail)+offset,'ZIP directory memory bound')

def extract_zip(archive,destination):
    """Only regular files/directories. Inner tar/wheel/APK payloads remain opaque."""
    try:
        bounded_directory(archive)
        with zipfile.ZipFile(archive) as bundle:
            entries=bundle.infolist();require(0<len(entries)<=MAX_FILES,'ZIP entry count')
            seen=set();namespace=set();total=0
            for member in entries:
                name=member.filename;path=PurePosixPath(name)
                parts=name.rstrip('/').split('/')
                require(name and len(name)<=1024 and all(0<len(p)<=240 and p not in {'.','..'} for p in parts) and not path.is_absolute() and all(ord(c)>=32 for c in name) and '\\' not in name and ':' not in name,'unsafe ZIP path')
                key=name.rstrip('/').casefold();require(key not in seen,'duplicate ZIP path');seen.add(key)
                for depth in range(1,len(parts)+1):
                    namespace.add(tuple(parts[:depth]))
                    require(len(namespace)<=MAX_FILES,'ZIP namespace bound')
                mode=member.external_attr>>16;kind=stat.S_IFMT(mode)
                require(kind in {0,stat.S_IFREG,stat.S_IFDIR} and (kind!=stat.S_IFDIR or member.is_dir()),'ZIP link or special file')
                require(not member.flag_bits&1 and member.compress_type in {zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED},'unsupported ZIP entry')
                total+=member.file_size
                require(total<=MAX_EXPANDED_BYTES and member.file_size<=MAX_DOWNLOAD_BYTES,'ZIP expanded size bound')
                require(member.file_size<=max(1024**2,member.compress_size*200),'ZIP compression ratio bound')
            files=[];actual_total=0
            for member in entries:
                target=destination/member.filename
                if member.is_dir():target.mkdir(parents=True,exist_ok=True);continue
                target.parent.mkdir(parents=True,exist_ok=True);digest=hashlib.sha256();size=0
                with bundle.open(member) as source,target.open('xb') as output:
                    os.chmod(target,0o600)
                    while chunk:=source.read(64*1024):
                        size+=len(chunk);actual_total+=len(chunk)
                        require(size<=member.file_size and actual_total<=MAX_EXPANDED_BYTES,'ZIP actual size bound')
                        output.write(chunk);digest.update(chunk)
                require(size==member.file_size,'ZIP member size mismatch')
                files.append(dict(path=member.filename,size=size,sha256=digest.hexdigest()))
            require(files,'ZIP contains no regular files')
            return files
    except (zipfile.BadZipFile,NotImplementedError,RuntimeError,OSError,ValueError):
        raise Refused('ZIP extraction failed') from None

def verify(policy,run_id,attempt,artifact_id,*,output=OUTPUT,api=gh_json,download=gh_download,now=None):
    require(not os.path.lexists(output),'verified output already exists')
    summary=verify_metadata(api,policy,run_id,attempt,artifact_id,now)
    output=Path(output)
    require(shutil.disk_usage(output.parent).free>=MAX_DOWNLOAD_BYTES+MAX_EXPANDED_BYTES+1024**3,'verification disk reserve')
    with tempfile.TemporaryDirectory(prefix='.artifact-verify-',dir=output.parent) as temporary:
        work=Path(temporary);archive=work/'artifact.zip'
        download(f'/repos/{policy.repository}/actions/artifacts/{artifact_id}/zip',archive,MAX_DOWNLOAD_BYTES)
        digest=hashlib.sha256();size=0
        with archive.open('rb') as source:
            while chunk:=source.read(1024**2):
                size+=len(chunk);require(size<=MAX_DOWNLOAD_BYTES,'download size bound');digest.update(chunk)
        require(size==summary['size_in_bytes'] and 'sha256:'+digest.hexdigest()==summary['artifact_digest'],'download digest/size mismatch')
        files=work/'files';files.mkdir(mode=0o700)
        verified_files=extract_zip(archive,files)
        require(verify_metadata(api,policy,run_id,attempt,artifact_id,now)==summary,'producer changed during verification')
        summary['files']=verified_files
        archive.unlink()
        require(not os.path.lexists(output),'verified output already exists')
        os.rename(work,output)
    return summary

def main(policy=None,argv=None):
    require(isinstance(policy,Policy),'fixed leaf policy required')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('producer_run_id',type=int);parser.add_argument('producer_attempt',type=int);parser.add_argument('artifact_id',type=int)
    args=parser.parse_args(argv)
    try:
        summary=verify(policy,args.producer_run_id,args.producer_attempt,args.artifact_id)
        print(json.dumps(summary,sort_keys=True));return 0
    except (Refused,KeyError,TypeError,ValueError,OSError) as error:
        print(json.dumps({'error':str(error) if isinstance(error,Refused) else 'verification metadata or local IO failure'}),file=sys.stderr);return 1

if __name__=='__main__':
    print('A reviewed immutable publisher leaf must supply literal Policy constants.',file=sys.stderr)
    sys.exit(1)
