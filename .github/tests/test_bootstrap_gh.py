"""Official CLI archive verification and fixed private tool directory."""
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"publisher"))
from unittest.mock import patch
import bootstrap_gh as b

def archive(name='gh_2.102.0_linux_amd64/bin/gh',symlink=False):
 data=io.BytesIO()
 with tarfile.open(fileobj=data,mode='w:gz') as tar:
  item=tarfile.TarInfo(name);payload=b'\x7fELFfixture-linux-cli';item.size=len(payload)
  if symlink:item.type=tarfile.SYMTYPE;item.linkname='/outside';item.size=0
  tar.addfile(item,None if symlink else io.BytesIO(payload))
 return data.getvalue()

class BootstrapTest(unittest.TestCase):
 def test_verified_cli_is_installed_only_in_a_new_mode0700_directory(self):
  data=archive()
  with tempfile.TemporaryDirectory() as directory,patch.object(b,'TOOLS',Path(directory)/'tools'),patch.object(b,'SHA256',hashlib.sha256(data).hexdigest()),patch.object(b,'SIZE',len(data)),patch.object(b.urllib.request,'urlopen',return_value=io.BytesIO(data)):
   b.install();target=b.TOOLS/'gh'
   self.assertTrue(target.read_bytes().startswith(b'\x7fELF'));self.assertEqual(target.stat().st_mode&0o777,0o700);self.assertEqual(b.TOOLS.stat().st_mode&0o777,0o700)
   self.assertEqual([p.name for p in b.TOOLS.iterdir()],['gh'])
 def test_changed_payload_never_creates_executable(self):
  data=archive()
  with tempfile.TemporaryDirectory() as directory,patch.object(b,'TOOLS',Path(directory)/'tools'),patch.object(b,'SHA256','0'*64),patch.object(b,'SIZE',len(data)),patch.object(b.urllib.request,'urlopen',return_value=io.BytesIO(data)):
   with self.assertRaises(b.Held):b.install()
   self.assertFalse((b.TOOLS/'gh').exists())
 def test_existing_directory_is_not_reused_or_erased(self):
  with tempfile.TemporaryDirectory() as directory,patch.object(b,'TOOLS',Path(directory)),patch.object(b.urllib.request,'urlopen') as download:
   with self.assertRaises(b.Held):b.install()
   download.assert_not_called();self.assertTrue(Path(directory).exists())
 def test_wrong_member_or_link_refuses_even_if_checksum_matches(self):
  for data in [archive('../outside'),archive(symlink=True)]:
   with self.subTest(),tempfile.TemporaryDirectory() as directory,patch.object(b,'TOOLS',Path(directory)/'tools'),patch.object(b,'SHA256',hashlib.sha256(data).hexdigest()),patch.object(b,'SIZE',len(data)),patch.object(b.urllib.request,'urlopen',return_value=io.BytesIO(data)):
    with self.assertRaises(b.Held):b.install()
    self.assertFalse((b.TOOLS/'gh').exists())

if __name__=='__main__':unittest.main()
