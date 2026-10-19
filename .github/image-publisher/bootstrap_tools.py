"""Install only checksum-pinned official tools into this fresh normal-user guest."""
import hashlib
import json
import os
from pathlib import Path
import tarfile
import tempfile
import urllib.request


def main():
    root=Path('/tmp/ci-publish-tools');root.mkdir(mode=0o700)
    pins=json.loads(Path(__file__).with_name('tools.json').read_text())
    for name,pin in pins.items():
        with tempfile.TemporaryDirectory(prefix='download-',dir=root) as td:
            archive=Path(td)/'archive';h=hashlib.sha256();size=0
            with urllib.request.urlopen(pin['url'],timeout=60) as response,archive.open('xb') as output:
                while chunk:=response.read(1024**2):
                    size+=len(chunk)
                    if size>pin['size']:raise ValueError('official tool size bound')
                    h.update(chunk);output.write(chunk)
            if size!=pin['size'] or h.hexdigest()!=pin['sha256']:raise ValueError('official tool checksum/size')
            target=root/name
            if name=='gh':
                with tarfile.open(archive,'r:gz') as bundle:
                    member=bundle.getmember(pin['member'])
                    if not member.isfile() or member.size>128*1024**2:raise ValueError('official gh binary')
                    with bundle.extractfile(member) as source,target.open('xb') as output:
                        while chunk:=source.read(1024**2):output.write(chunk)
            else:os.rename(archive,target)
            target.chmod(0o700)
    print('Verified official gh and regctl installed in /tmp/ci-publish-tools')

if __name__=='__main__':main()
