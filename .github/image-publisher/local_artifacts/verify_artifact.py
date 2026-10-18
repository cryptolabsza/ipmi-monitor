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
    allow_queued_run:bool=False
    max_download_bytes:int=MAX_DOWNLOAD_BYTES
    transport_schema:int=1

    def __post_init__(self):
        require(type(self.transport_schema)is int and self.transport_schema in {1,2},'fixed artifact transport')
        if self.transport_schema==2:
            from local_artifact_routes import ROUTES
            route=ROUTES.get(self.repository_id)
            require(route is not None and self.artifact_kind=='oci' and all(getattr(self,key)==route[field] for key,field in (('repository','repository'),('repository_id','repository_id'),('workflow_path','workflow_path'),('producer_job','producer_job'),('group_id','group_id'),('build_label','build_label'),('artifact_stem','artifact_stem'))),'fixed mapped artifact transport')
        require(type(self.allow_queued_run)is bool,'fixed queued run policy')
        require(type(self.repository)is str and re.fullmatch(r'(Oxiom-Systems|cryptolabsza)/[A-Za-z0-9_.-]+',self.repository),'fixed repository')
        require(positive(self.repository_id),'fixed repository ID')
        require(type(self.workflow_path)is str and re.fullmatch(r'\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml',self.workflow_path),'fixed workflow path')
        require(type(self.recipe_ref)is str and re.fullmatch(re.escape(self.repository)+r'/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml@[0-9a-f]{40}',self.recipe_ref),'immutable build recipe')
        groups={'Oxiom-Systems':{4,5},'cryptolabsza':{10,11}}
        require(type(self.group_id)is int and self.group_id in groups[self.repository.split('/')[0]],'build group')
        require(self.build_label==f'ci-linux-cpu-v1-r{self.repository_id}','build label')
        require(type(self.producer_job)is str and 0<len(self.producer_job)<=200 and all(ord(c)>=32 for c in self.producer_job),'producer job')
        require(self.artifact_kind in {'oci','docker-save','pypi','apk','site','plugin','litellm-config'},'artifact kind')
        require(type(self.artifact_stem)is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}',self.artifact_stem),'artifact name stem')
        require(type(self.max_download_bytes)is int and (self.max_download_bytes==MAX_DOWNLOAD_BYTES or
                (self.max_download_bytes==5*1024**3 and self.repository=='cryptolabsza/knowledge-base-hosting-troubleshooting' and
                 self.repository_id==1130243159 and self.artifact_kind=='oci' and self.artifact_stem=='kb-image')),'fixed artifact download bound')

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
    require(policy.max_download_bytes==MAX_DOWNLOAD_BYTES or repo.get('private')is True,'private large artifact repository')
    latest=api(runpath);run=api(runpath+f'/attempts/{attempt}')
    for value in (latest,run):
        require(value['id']==run_id and value['run_attempt']==attempt,'latest run attempt')
        for key in ('repository','head_repository'):
            require(value[key]['id']==policy.repository_id and value[key]['full_name']==policy.repository,'run repository identity')
        branch=value['head_branch'];head=value['head_sha']
        require(branch in {'main','dev'} and sha(head),'protected source ref')
        require(value['event'] in {'push','workflow_dispatch'} and value.get('pull_requests')==[],'protected source event')
        require(value['path'] in {policy.workflow_path,policy.workflow_path+'@'+branch,policy.workflow_path+'@refs/heads/'+branch},'producer workflow path')
        require((value['status']=='completed' and value['conclusion']=='success') or (value['status']=='in_progress' and value['conclusion']is None) or (policy.allow_queued_run and value['status']=='queued' and value['conclusion']is None),'producer run state')
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
    require(positive(artifact['size_in_bytes']) and artifact['size_in_bytes']<=policy.max_download_bytes,'artifact download size')
    require(timestamp(job['started_at'])<=timestamp(artifact['created_at'])<=timestamp(job['completed_at']),'artifact outside successful job attempt')
    current=timestamp(now) if now else datetime.now(timezone.utc)
    require(timestamp(artifact['expires_at'])>current,'artifact expired')
    return dict(repository=policy.repository,repository_id=policy.repository_id,run_id=run_id,run_attempt=attempt,
                head_sha=run['head_sha'],branch=run['head_branch'],event=run['event'],producer_job_id=job['id'],producer_runner_id=job['runner_id'],
                recipe_ref=policy.recipe_ref,artifact_id=artifact_id,artifact_name=name,
                artifact_kind=policy.artifact_kind,artifact_digest=artifact['digest'],size_in_bytes=artifact['size_in_bytes'])

def bounded_directory(archive,*,max_download_bytes=MAX_DOWNLOAD_BYTES):
    # ZipFile reads the whole central directory before infolist/count checks.
    # Bound that allocation first, including the opt-in KB ZIP64 envelope.
    require(type(max_download_bytes)is int and max_download_bytes in {MAX_DOWNLOAD_BYTES,5*1024**3},'fixed ZIP download bound')
    with archive.open('rb') as source:
        size=source.seek(0,os.SEEK_END);require(size<=max_download_bytes,'ZIP download size bound')
        source.seek(max(0,size-65557));tail=source.read(65557);offset=tail.rfind(b'PK\x05\x06')
        require(offset>=0 and len(tail)-offset>=22,'ZIP directory footer')
        _,disk,start_disk,count_disk,count,length,start,comment=struct.unpack_from('<4s4H2LH',tail,offset)
        footer=size-len(tail)+offset;directory_end=footer
        require(offset+22+comment==len(tail) and disk==start_disk==0,'ZIP directory shape')
        source.seek(max(0,footer-20));locator=source.read(20)
        if locator[:4]==b'PK\x06\x07':
            require(max_download_bytes>MAX_DOWNLOAD_BYTES,'ZIP64 policy required')
            _,record_disk,record_offset,disks=struct.unpack('<4sLQL',locator)
            require(record_disk==0 and disks==1 and record_offset+56==footer-20,'ZIP64 locator')
            source.seek(record_offset);record=source.read(56)
            require(len(record)==56,'ZIP64 end record')
            signature,payload,made,needed,record_disk,central_disk,entries_disk,entries,central_length,central_start=struct.unpack('<4sQ2H2L4Q',record)
            require(signature==b'PK\x06\x06' and payload==44 and record_disk==central_disk==0 and entries_disk==entries,'ZIP64 end record')
            for ordinary,resolved,sentinel in ((count_disk,entries_disk,65535),(count,entries,65535),(length,central_length,0xffffffff),(start,central_start,0xffffffff)):
                require(ordinary==sentinel or ordinary==resolved,'ZIP64 ordinary directory mismatch')
            count,length,start=entries,central_length,central_start;directory_end=record_offset
        else:
            require(count_disk==count and count!=65535 and length!=0xffffffff and start!=0xffffffff,'ZIP directory shape')
        require(0<count<=MAX_FILES and length<=16*1024**2 and start+length==directory_end,'ZIP directory memory bound')
        source.seek(start);directory=source.read(length)
        require(len(directory)==length,'ZIP directory truncated')
        cursor=0
        for _ in range(count):
            require(cursor+46<=length and directory[cursor:cursor+4]==b'PK\x01\x02','ZIP central entry')
            compressed,expanded=struct.unpack_from('<LL',directory,cursor+20)
            name_length,extra_length,comment_length,entry_disk=struct.unpack_from('<4H',directory,cursor+28)
            entry_offset=struct.unpack_from('<L',directory,cursor+42)[0]
            extra_start=cursor+46+name_length;entry_end=extra_start+extra_length+comment_length
            require(entry_end<=length,'ZIP central entry length')
            extra=directory[extra_start:extra_start+extra_length];position=0;zip64=None
            while position<len(extra):
                require(position+4<=len(extra),'ZIP extra header')
                tag,field_length=struct.unpack_from('<HH',extra,position);position+=4
                require(position+field_length<=len(extra),'ZIP extra field')
                if tag==1:
                    require(zip64 is None,'ZIP64 entry extra')
                    zip64=extra[position:position+field_length]
                position+=field_length
            values=[expanded,compressed,entry_offset,entry_disk];widths=[8,8,8,4];sentinels=[0xffffffff,0xffffffff,0xffffffff,65535]
            required=sum(width for value,width,sentinel in zip(values,widths,sentinels) if value==sentinel)
            require((zip64 is None and required==0) or (zip64 is not None and len(zip64)==required),'ZIP64 entry extra size')
            position=0
            for index,(value,width,sentinel) in enumerate(zip(values,widths,sentinels)):
                if value==sentinel:
                    values[index]=int.from_bytes(zip64[position:position+width],'little');position+=width
            expanded,compressed,entry_offset,entry_disk=values
            require(entry_disk==0 and entry_offset<start and max(expanded,compressed)<=max_download_bytes,'ZIP entry size or offset')
            cursor=entry_end
        require(cursor==length,'ZIP directory entry count')

def extract_zip(archive,destination,*,max_download_bytes=MAX_DOWNLOAD_BYTES):
    """Only regular files/directories. Inner tar/wheel/APK payloads remain opaque."""
    try:
        bounded_directory(archive,max_download_bytes=max_download_bytes)
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
                require(total<=MAX_EXPANDED_BYTES and member.file_size<=max_download_bytes,'ZIP expanded size bound')
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
    if isinstance(policy,Policy) and policy.transport_schema==2:
        from local_artifact import materialize
        return materialize(policy,run_id,attempt,artifact_id,output=output,api=api,download=download)
    require(not os.path.lexists(output),'verified output already exists')
    summary=verify_metadata(api,policy,run_id,attempt,artifact_id,now)
    output=Path(output)
    require(shutil.disk_usage(output.parent).free>=policy.max_download_bytes+MAX_EXPANDED_BYTES+1024**3,'verification disk reserve')
    with tempfile.TemporaryDirectory(prefix='.artifact-verify-',dir=output.parent) as temporary:
        work=Path(temporary);archive=work/'artifact.zip'
        download(f'/repos/{policy.repository}/actions/artifacts/{artifact_id}/zip',archive,policy.max_download_bytes)
        digest=hashlib.sha256();size=0
        with archive.open('rb') as source:
            while chunk:=source.read(1024**2):
                size+=len(chunk);require(size<=policy.max_download_bytes,'download size bound');digest.update(chunk)
        require(size==summary['size_in_bytes'] and 'sha256:'+digest.hexdigest()==summary['artifact_digest'],'download digest/size mismatch')
        files=work/'files';files.mkdir(mode=0o700)
        verified_files=extract_zip(archive,files,max_download_bytes=policy.max_download_bytes)
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
