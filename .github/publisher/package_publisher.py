"""Inspect package data and publish exact verified bytes; never import a package."""
from email.parser import BytesParser
import hashlib
import re
import stat
import tarfile
import time
from urllib.parse import urlsplit
import zipfile

PROJECTS={'cryptolabs-proxy':'cryptolabsza/cryptolabs-proxy','dc-overview':'cryptolabsza/dc-overview',
          'ipmi-monitor':'cryptolabsza/ipmi-monitor','cryptolabs-sre-agent':'cryptolabsza/sre.ai'}
VERSION=re.compile(r'[0-9]+\.[0-9]+\.[0-9]+')
MAX_FILE=256*1024**2
MAX_METADATA=1024**2

class Held(ValueError):pass
def require(condition,reason):
    if not condition:raise Held(reason)
def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda:stream.read(1024**2),b''):h.update(data)
    return h.hexdigest()
def metadata(data,project,version):
    require(len(data)<=MAX_METADATA,'package metadata bound')
    value=BytesParser().parsebytes(data)
    require(value.get_all('Name')==[project] and value.get_all('Version')==[version],'package metadata identity')
def names(project,version):
    stem=project.replace('-','_')+'-'+version
    return stem,[stem+'-py3-none-any.whl',stem+'.tar.gz']
def inspect(files,project):
    require(project in PROJECTS,'fixed project')
    all_files=list(files.iterdir())
    require(all(p.is_file() and not p.is_symlink() and 0<p.stat().st_size<=MAX_FILE for p in all_files),'package regular file bound')
    wheels=[p for p in all_files if p.suffix=='.whl']
    require(len(wheels)==1,'unique wheel')
    match=re.fullmatch(re.escape(project.replace('-','_'))+r'-([0-9]+\.[0-9]+\.[0-9]+)-py3-none-any\.whl',wheels[0].name)
    require(match is not None,'wheel filename identity');version=match[1];stem,expected=names(project,version)
    require({p.name for p in all_files}==set(expected+['SHA256SUMS']),'exact package outputs')
    # Bound central-directory allocation before ZipFile parses it, using the
    # separately reviewed verifier's unchanged directory-envelope check.
    from verify_artifact import bounded_directory,Refused
    try:bounded_directory(wheels[0])
    except Refused:raise Held('wheel directory envelope') from None
    with zipfile.ZipFile(wheels[0]) as wheel:
        entries=wheel.infolist();require(0<len(entries)<=10000,'wheel entry count')
        require(len({m.filename.casefold() for m in entries})==len(entries),'duplicate wheel members')
        require(sum(m.file_size for m in entries)<=MAX_FILE,'wheel expanded bound')
        infos=[m for m in entries if m.filename.endswith('.dist-info/METADATA')]
        require(len(infos)==1 and infos[0].filename==stem+'.dist-info/METADATA','wheel metadata path')
        require(infos[0].file_size<=MAX_METADATA and stat.S_IFMT(infos[0].external_attr>>16) in {0,stat.S_IFREG},'wheel metadata bound/type')
        metadata(wheel.read(infos[0]),project,version)
    seen=set();total=0;count=0;found=0
    with tarfile.open(files/expected[1],'r|gz') as sdist:
        for member in sdist:
            count+=1;total+=member.size
            require(count<=10000 and total<=MAX_FILE,'sdist expanded bound')
            parts=member.name.rstrip('/').split('/')
            require(parts[0]==stem and all(p not in {'','..','.'} for p in parts) and '\\' not in member.name,'sdist member path')
            require(member.isfile() or member.isdir(),'sdist member type')
            key=member.name.rstrip('/').casefold();require(key not in seen,'duplicate sdist member');seen.add(key)
            if member.name==stem+'/PKG-INFO':
                require(member.isfile() and member.size<=MAX_METADATA,'sdist metadata bound/type')
                metadata(sdist.extractfile(member).read(MAX_METADATA+1),project,version);found+=1
    require(found==1,'unique sdist metadata')
    artifacts=[{'filename':name,'sha256':digest(files/name),'size':(files/name).stat().st_size} for name in expected]
    sums=''.join(a['sha256']+'  '+a['filename']+'\n' for a in artifacts).encode()
    require((files/'SHA256SUMS').read_bytes()==sums,'package checksum bytes')
    return version,artifacts

def prepare(project,files,proof,event,client,*,mirror_github):
    version,artifacts=inspect(files,project)
    repository=PROJECTS[project]
    require(proof['repository']==repository and re.fullmatch('[0-9a-f]{40}',proof['head_sha']) is not None,'verified source identity')
    require(proof['branch']=='main','publication requires verified protected main producer')
    require(client.source_project(proof['head_sha'])=={'name':project,'version':version},'source project/version')
    tag='v'+version;data=event['event'];kind=event['name']
    require(kind in {'release','workflow_dispatch'},'release event')
    if kind=='release':
        require(data.get('action')=='published' and data['release'].get('tag_name')==tag and data['release'].get('draft')is False,'published release event')
        require(event['sha']==proof['head_sha'],'release event commit')
    else:
        inputs=data.get('inputs',{})
        require(isinstance(inputs,dict),'manual input shape')
        if project in {'cryptolabs-proxy','dc-overview'}:require(inputs.get('release_tag')==tag and inputs.get('version')==version,'manual release identity')
        else:require(not inputs.get('version') or inputs['version']==version,'manual version')
        dynamic=[inputs.get(x) for x in ('producer_run_id','producer_attempt','artifact_id')]
        require(sum(bool(x) for x in dynamic) in {0,3},'all three producer IDs required')
        if all(dynamic):require(all(type(x)is str and re.fullmatch('[1-9][0-9]{0,19}',x) for x in dynamic),'numeric producer IDs')
    require(client.tag_commit(tag)==proof['head_sha'],'published tag producer commit')
    release=client.release(tag)
    require(release.get('tag_name')==tag and release.get('draft')is False and type(release.get('id'))is int,'published release required')
    return {'project':project,'version':version,'repository':repository,'tag':tag,'source_sha':proof['head_sha'],'artifacts':artifacts,'mirror_github':mirror_github}

def checksum_bytes(plan):return ''.join(a['sha256']+'  '+a['filename']+'\n' for a in plan['artifacts']).encode()
def verify_local(plan,files):
    version,artifacts=inspect(files,plan['project'])
    require(version==plan['version'] and artifacts==plan['artifacts'],'package bytes changed')
def index(records,key):
    result={}
    for item in records:
        require(item[key] not in result,'duplicate destination file');result[item[key]]=item
    return result
def check_pypi(plan,client,required=False):
    response=client.pypi(plan['project'],plan['version'])
    if response is None:
        require(not required,'PyPI files not visible');return {}
    require(response['info']['name']==plan['project'] and response['info']['version']==plan['version'],'PyPI project/version')
    records=index(response['urls'],'filename');expected={a['filename'] for a in plan['artifacts']}
    require(set(records)<=expected and (not required or set(records)==expected),'PyPI file set')
    for item in plan['artifacts']:
        record=records.get(item['filename'])
        if record is None:continue
        url=urlsplit(record['url'])
        require(url.scheme=='https' and url.netloc=='files.pythonhosted.org' and not url.query and not url.fragment and url.path.rsplit('/',1)[-1]==item['filename'],'PyPI file URL')
        require(record.get('yanked')is False and record['digests']['sha256']==item['sha256'] and record['size']==item['size'],'PyPI file metadata collision')
        data=client.download(record['url']);require(len(data)==item['size'] and hashlib.sha256(data).hexdigest()==item['sha256'],'PyPI actual file collision')
    return records
def check_github(plan,client,required=False):
    release=client.release(plan['tag']);require(release.get('tag_name')==plan['tag'] and release.get('draft')is False,'published release required')
    records=index(release['assets'],'name');sums=checksum_bytes(plan)
    expected={a['filename']:a for a in plan['artifacts']};expected['SHA256SUMS']={'sha256':hashlib.sha256(sums).hexdigest(),'size':len(sums)}
    require(not required or set(expected)<=set(records),'GitHub assets not visible')
    for name,item in expected.items():
        record=records.get(name)
        if record is None:continue
        url='https://github.com/'+plan['repository']+'/releases/download/'+plan['tag']+'/'+name
        require(record['browser_download_url']==url and record['size']==item['size'],'GitHub asset metadata collision')
        data=client.download(url);require(len(data)==item['size'] and hashlib.sha256(data).hexdigest()==item['sha256'],'GitHub actual asset collision')
    return records
def publish(plan,files,client,*,attempts=6):
    verify_local(plan,files);require(client.tag_commit(plan['tag'])==plan['source_sha'],'tag changed before upload')
    py=check_pypi(plan,client);gh=check_github(plan,client) if plan['mirror_github'] else {}
    paths=[files/a['filename'] for a in plan['artifacts']]
    missing=[path for path in paths if path.name not in py]
    if missing:client.upload_pypi(missing)
    if plan['mirror_github']:
        missing=[path for path in paths+[files/'SHA256SUMS'] if path.name not in gh]
        if missing:client.upload_github(plan['tag'],missing)
    for attempt in range(attempts):
        try:
            check_pypi(plan,client,required=True)
            if plan['mirror_github']:check_github(plan,client,required=True)
            break
        except (Held,RuntimeError):
            if attempt+1==attempts:raise
            time.sleep(5)
    verify_local(plan,files);require(client.tag_commit(plan['tag'])==plan['source_sha'],'tag changed after upload')
    return {'status':'verified',**plan}
