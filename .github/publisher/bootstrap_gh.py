"""Install the pinned official GH CLI in one fixed normal-user location."""
import hashlib
from pathlib import Path
import tarfile
import urllib.request

TOOLS=Path('/tmp/ci-publish-tools')
URL='https://github.com/cli/cli/releases/download/v2.102.0/gh_2.102.0_linux_amd64.tar.gz'
SHA256='bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386'
SIZE=15319960
MEMBER='gh_2.102.0_linux_amd64/bin/gh'

class Held(ValueError):pass
def require(condition,reason):
 if not condition:raise Held(reason)
def install():
 try:TOOLS.mkdir(mode=0o700)
 except FileExistsError:raise Held('fixed publisher tool directory already exists') from None
 archive=TOOLS/'gh.tar.gz';digest=hashlib.sha256();size=0
 try:
  with urllib.request.urlopen(URL,timeout=60) as response,archive.open('xb') as target:
   while chunk:=response.read(64*1024):
    size+=len(chunk);require(size<=SIZE,'official CLI size bound');digest.update(chunk);target.write(chunk)
  require(size==SIZE and digest.hexdigest()==SHA256,'official CLI checksum')
  with tarfile.open(archive,'r:gz') as tar:
   entries=[m for m in tar.getmembers() if m.name==MEMBER]
   require(len(entries)==1 and entries[0].isfile() and 0<entries[0].size<64*1024**2,'official CLI member')
   data=tar.extractfile(entries[0]).read(64*1024**2+1)
   require(len(data)==entries[0].size and data.startswith(b'\x7fELF'),'official Linux CLI executable')
   target=TOOLS/'gh'
   with target.open('xb') as output:output.write(data)
   target.chmod(0o700)
 finally:archive.unlink(missing_ok=True)

if __name__=='__main__':install()
