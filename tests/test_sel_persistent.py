# TRACEWEAVER: file-role=persistent-snapshot-verification; req=REQ-SEL-002; trace=TRACE-SEL-002; ver=VER-SEL-002
# TRACEWEAVER: verifies=VER-SEL-002; req=REQ-SEL-002; trace=TRACE-SEL-002
"""Real local child/PTY framing; fake executable never opens a BMC connection."""
from pathlib import Path
from types import SimpleNamespace
import os
import subprocess
import sys
import time

import pytest
from ipmi_monitor import sel_management as sel


@pytest.fixture()
def child_tool(tmp_path, monkeypatch):
    children = []
    original = subprocess.Popen
    executable = tmp_path / 'ipmitool'

    def launch(*args, **kwargs):
        if args and args[0][0] == '/usr/bin/ipmitool':
            args = ([str(executable), *args[0][1:]], *args[1:])
        child = original(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(subprocess, 'Popen', launch)

    def make(mode='fragmented'):
        executable.write_text('#!' + sys.executable + '\n' + '''
import sys, time
MODE = MODE_VALUE
def response(values):
    if values[:2] == [10,64]: return bytes.fromhex('5103000000010000000000000002')
    if values[:2] == [10,66]: return bytes.fromhex('3412')
    if values[:2] == [10,67]:
        if values[2:4] != [52,18]: raise ValueError('reservation')
        actual = values[4] + (values[5] << 8) or 1
        return (actual+1 if actual<3 else 65535).to_bytes(2,'little') + actual.to_bytes(2,'little') + bytes(14)
    if values[:2] == [10,71]:
        if values[2:4] != [52,18] or values[4:7] != [67,76,82]: raise ValueError('clear token')
        return b'\\x01'
    raise ValueError('not fixed')
if sys.argv[-1] != 'shell':
    values = [int(v,16) for v in sys.argv[sys.argv.index('raw')+1:]]
    print(response(values).hex(' ')); raise SystemExit(0)
if MODE == 'timeout': time.sleep(10)
sys.stdout.write('ipmitool> '); sys.stdout.flush()
for line in sys.stdin:
    if MODE == 'eof': raise SystemExit(0)
    values = [int(v,16) for v in line.split()[1:]]
    output = response(values).hex(' ')
    if MODE == 'malformed': output = 'secret-looking-error is not a hex response'
    if MODE == 'oversize': output = 'aa ' * 3000
    sys.stdout.write(output + '\\n' + 'ipmi'); sys.stdout.flush()
    time.sleep(0.001)
    sys.stdout.write('tool> '); sys.stdout.flush()
'''.replace('MODE_VALUE', repr(mode)))
        executable.chmod(0o700)
        monkeypatch.setenv('PATH', str(tmp_path) + os.pathsep + os.environ['PATH'])
        return sel.IPMISELAdapter(SimpleNamespace(subprocess=subprocess), '192.0.2.40', ('fixture', 'synthetic-secret'))

    yield make, children
    for child in children:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=2)


def test_complete_snapshot_and_clear_share_one_child_and_reservation(child_tool):
    make, children = child_tool
    adapter = make()
    try:
        snapshot = adapter.snapshot(bytes.fromhex('3412'))
        adapter.clear(bytes.fromhex('3412'))
        assert [row['record_id'] for row in snapshot['records']] == [1, 2, 3]
        assert len(children) == 1, 'full snapshot must not authenticate a new process per record'
    finally:
        getattr(adapter, 'close', lambda: None)()
    assert all(child.poll() is not None for child in children)


@pytest.mark.parametrize('mode', ['eof', 'malformed', 'oversize', 'timeout'])
def test_bad_or_missing_prompt_frames_fail_closed_and_reap_child(child_tool, mode):
    make, children = child_tool
    adapter = make(mode)
    adapter.deadline = time.monotonic() + (0.15 if mode == 'timeout' else 2)
    try:
        with pytest.raises(sel.SELUnavailable):
            adapter.snapshot(bytes.fromhex('3412'))
    finally:
        getattr(adapter, 'close', lambda: None)()
    assert all(child.poll() is not None for child in children)
