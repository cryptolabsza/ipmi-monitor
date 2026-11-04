# TRACEWEAVER: file-role=installed-linux-custody-verification; req=REQ-SEL-004; trace=TRACE-SEL-004; ver=VER-SEL-004
# TRACEWEAVER: verifies=VER-SEL-004; req=REQ-SEL-004; trace=TRACE-SEL-004
"""Standalone real-root Linux custody/SQLite acceptance, run in a disposable image.

No BMC credentials, network, target mounts or application startup are used.
The empty registry proves storage/activation mechanics only, never qualification.
"""
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time
import unittest

from ipmi_monitor import sel_qualifications as q


class InstalledDataContract(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0, 'Run only in the disposable Linux image')
        self.root = Path('/app/data')
        for path in self.root.iterdir():
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()
        os.environ['DATA_DIR'] = str(self.root)
        os.environ.pop('SEL_QUALIFICATIONS_FILE', None)
        os.environ.pop('SEL_QUALIFICATIONS_SHA256', None)
        with sqlite3.connect(self.root / 'ipmi_events.db') as db:
            db.executescript('CREATE TABLE sel_target (id TEXT PRIMARY KEY, auto_clear INTEGER, auto_clock INTEGER, active_operation TEXT);'
                             'CREATE TABLE sel_operation (id TEXT PRIMARY KEY, state TEXT);'
                             "INSERT INTO sel_target VALUES ('target',0,0,NULL);")
        registry = json.dumps({'schema': 'sel-device-qualification/1', 'records': []}).encode()
        self.envelope = json.dumps({'schema': 'sel-qualification-envelope/1',
            'identity': q.runtime_identity(), 'registry_sha256': q.sha(registry),
            'files': {'registry.json': base64.b64encode(registry).decode('ascii')}}).encode()

    def invoke(self, payload=None, expected=None):
        payload = self.envelope if payload is None else payload
        old_stdin = q.sys.stdin
        q.sys.stdin = io.TextIOWrapper(io.BytesIO(payload), encoding='utf-8')
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                code = q.main(['install', '--expected-sha256', expected or q.sha(payload)])
        finally:
            q.sys.stdin = old_stdin
        return code, json.loads(output.getvalue())

    def test_install_reopen_idempotence_and_zero_policy_effect(self):
        code, result = self.invoke()
        self.assertEqual((code, result['outcome']), (0, 'installed'), result)
        state = q.qualification_state()
        self.assertEqual(state['mode'], 'operator')
        self.assertEqual(state['envelope_sha256'], q.sha(self.envelope))
        self.assertEqual(state['records'], [])
        self.assertEqual(self.invoke()[1]['outcome'], 'already_installed')
        self.assertEqual(sqlite3.connect(self.root / 'ipmi_events.db').execute('SELECT auto_clear,auto_clock FROM sel_target').fetchall(), [(0, 0)])
        self.assertNotIn('ipmi_monitor.app', q.sys.modules)

    def test_armed_or_uncertain_work_refuses_before_publication(self):
        for condition in ('armed', 'queued', 'mutating', 'outcome-unknown'):
            with self.subTest(condition=condition):
                with sqlite3.connect(self.root / 'ipmi_events.db') as db:
                    db.execute('DELETE FROM sel_operation')
                    db.execute('UPDATE sel_target SET auto_clear=?', (int(condition == 'armed'),))
                    if condition != 'armed':
                        db.execute('INSERT INTO sel_operation VALUES (?,?)', (condition, condition))
                self.assertEqual(self.invoke()[1]['reason'], 'automation_or_operation_active')
                self.assertFalse((self.root / 'sel-qualifications/active.json').exists())

    def test_invalid_envelopes_do_not_create_active_state(self):
        value = json.loads(self.envelope)
        variants = [b'{"schema":0,"schema":1}', self.envelope + b' trailing']
        for path in ('../escape', '/absolute', 'a\\b', 'a/./b'):
            changed = dict(value, files={path: 'eA=='})
            variants.append(json.dumps(changed).encode())
        for payload in variants:
            with self.subTest(payload=payload[:80]):
                code, result = self.invoke(payload)
                self.assertEqual((code, result['outcome']), (1, 'refused'))
                self.assertNotEqual(result['reason'], 'installation_unavailable')
                self.assertFalse((self.root / 'sel-qualifications/active.json').exists())

    def test_symlink_ancestry_and_hardlink_pointer_fail_closed(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (self.root / 'sel-qualifications').symlink_to(outside)
        self.assertEqual(self.invoke()[1]['reason'], 'unsafe_storage')
        self.assertEqual(list(outside.iterdir()), [])
        (self.root / 'sel-qualifications').unlink()
        self.assertEqual(self.invoke()[0], 0)
        pointer = self.root / 'sel-qualifications/active.json'
        os.link(pointer, self.root / 'pointer-link')
        self.assertIsNone(q.qualification_state()['binding'])

    def test_environment_presence_and_corrupt_pointer_never_fall_back(self):
        self.assertEqual(self.invoke()[0], 0)
        for key in ('SEL_QUALIFICATIONS_FILE', 'SEL_QUALIFICATIONS_SHA256'):
            os.environ[key] = ''
            self.assertEqual(q.qualification_state()['mode'], 'environment')
            self.assertIsNone(q.qualification_state()['binding'])
            del os.environ[key]
        pointer = self.root / 'sel-qualifications/active.json'
        pointer.write_bytes(b'{}')
        self.assertIsNone(q.qualification_state()['binding'])
        self.assertEqual(self.invoke()[1]['outcome'], 'refused')

    def test_real_sqlite_writer_committed_first_blocks_install(self):
        db = sqlite3.connect(self.root / 'ipmi_events.db')
        db.execute('BEGIN IMMEDIATE')
        process = subprocess.Popen([sys.executable, '-I', '-m', 'ipmi_monitor.sel_qualifications',
            'install', '--expected-sha256', q.sha(self.envelope)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            process.stdin.write(self.envelope)
            process.stdin.close()
            process.stdin = None
            deadline = time.monotonic() + 5
            while not (self.root / 'sel-qualifications/bundles' / q.sha(self.envelope)).exists():
                self.assertIsNone(process.poll(), 'installer exited before its database authority check')
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            time.sleep(0.05)
            self.assertFalse((self.root / 'sel-qualifications/active.json').exists())
            db.execute('UPDATE sel_target SET auto_clock=1')
            db.commit()
            output, error = process.communicate(timeout=18)
            self.assertEqual(process.returncode, 1, error)
            self.assertEqual(json.loads(output)['reason'], 'automation_or_operation_active')
        finally:
            db.close()
            if process.poll() is None:
                process.kill()
                process.communicate()

    def test_missing_db_and_digest_mismatch_create_no_activation(self):
        self.assertEqual(self.invoke(expected='0' * 64)[1]['reason'], 'envelope_digest_mismatch')
        database = self.root / 'ipmi_events.db'
        database.unlink()
        self.assertEqual(self.invoke()[1]['outcome'], 'refused')
        self.assertFalse(database.exists())
        self.assertFalse((self.root / 'sel-qualifications/active.json').exists())

    def test_isolated_installed_origin_ignores_poisoned_cwd_pythonpath_and_path(self):
        self.assertEqual(self.invoke()[0], 0)
        poison = Path('/tmp/qualification-poison')
        poison.mkdir(exist_ok=True)
        package = poison / 'ipmi_monitor'
        package.mkdir(exist_ok=True)
        (package / '__init__.py').write_text("raise RuntimeError('untrusted module imported')")
        (poison / 'ipmitool').write_text("#!/bin/sh\ntouch /tmp/untrusted-tool-executed\nexit 42\n")
        (poison / 'ipmitool').chmod(0o700)
        environment = dict(os.environ, PYTHONPATH=str(poison), PATH=str(poison))
        result = subprocess.run([sys.executable, '-I', '-m', 'ipmi_monitor.sel_qualifications', 'status'],
            cwd=poison, env=environment, capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['envelope_sha256'], q.sha(self.envelope))
        self.assertFalse(Path('/tmp/untrusted-tool-executed').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
