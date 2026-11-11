# TRACEWEAVER: file-role=native-collection-boundaries; req=REQ-SEL-001,REQ-SEL-002,REQ-SEL-003,REQ-SEL-004; trace=TRACE-SEL-001,TRACE-SEL-002,TRACE-SEL-003,TRACE-SEL-004; ver=VER-CHARLOTTESEL-001,VER-CHARLOTTESEL-002,VER-CHARLOTTESEL-003,VER-CHARLOTTESEL-004
"""Read-only collection evidence helpers. No mutation qualification is granted here."""
from datetime import datetime, timezone
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import uuid
from urllib.parse import urlsplit, unquote

READ_SECONDS = 180
REAP_SECONDS = 30
PROCESS_INSTANCE = uuid.uuid4().hex


class EventBatch(list):
    """List-compatible handoff carrying the immutable acquisition evidence."""
    def __init__(self, values=(), ticket=None, snapshot=None, error=None):
        super().__init__(values)
        self.ticket, self.snapshot, self.error = ticket, snapshot, error


def native_digest(raw):
    if isinstance(raw, str) and re.fullmatch('[0-9a-fA-F]{32}', raw):
        return hashlib.sha256(b'ipmi-sel-raw16-v1\0' + bytes.fromhex(raw)).hexdigest()
    return None


# TRACEWEAVER: entrypoint=read_profile; req=REQ-SEL-001,REQ-SEL-002,REQ-SEL-003,REQ-SEL-004; trace=TRACE-SEL-001,TRACE-SEL-002,TRACE-SEL-003,TRACE-SEL-004; ver=VER-CHARLOTTESEL-001,VER-CHARLOTTESEL-002,VER-CHARLOTTESEL-003,VER-CHARLOTTESEL-004
def read_profile(runtime, target):
    """Explicit data-mount configuration; bounded strict parsing, no symlink files."""
    from .sel_qualifications import read_file, strict_json, fields
    path = os.environ.get('SEL_READ_PROFILES_FILE')
    explicit = bool(path)
    path = path or str(Path(runtime.app.config['DATA_DIR']) / 'sel-read-profiles.json')
    try:
        os.lstat(path)  # Missing default file is ordinary cipher17, even on a symlinked temp parent.
        value = read_file(path, 65536)
    except FileNotFoundError:
        if not explicit:
            return None
        raise ValueError('read_profile_unavailable') from None
    except Exception:
        raise ValueError('read_profile_custody') from None
    try:
        # read_file checks owner/type/link/write custody, including every ancestor
        # against symlink traversal. Require private file permissions as well.
        metadata = os.stat(path, follow_symlinks=False)
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ValueError()
        data = strict_json(value)
        fields(data, {'schema_version', 'profiles'})
        if data['schema_version'] != 'sel-read-profiles/1' or type(data['profiles']) is not list or len(data['profiles']) > 256:
            raise ValueError()
        seen = set()
        selected = None
        for row in data['profiles']:
            fields(row, {'server_id', 'binding', 'bmc_ip', 'cipher', 'device_id_reply', 'guid'})
            if (type(row['server_id']) is not int or row['server_id'] <= 0 or
                    type(row['binding']) is not str or not re.fullmatch('[0-9a-f]{64}', row['binding']) or
                    type(row['bmc_ip']) is not str or not 1 <= len(row['bmc_ip']) <= 253 or
                    type(row['cipher']) is not int or row['cipher'] != 3 or
                    type(row['device_id_reply']) is not str or not re.fullmatch('(?:[0-9a-f]{22}|[0-9a-f]{30})', row['device_id_reply']) or
                    type(row['guid']) is not str or not re.fullmatch('[0-9a-f]{32}', row['guid']) or
                    row['guid'] in {'00' * 16, 'ff' * 16} or row['bmc_ip'] in seen):
                raise ValueError()
            seen.add(row['bmc_ip'])
            if row['bmc_ip'] == target.bmc_ip:
                if row['server_id'] != target.server_id or row['binding'] != target.binding:
                    raise ValueError()
                selected = row
        return selected
    except Exception:
        raise ValueError('read_profile_invalid_or_stale') from None


class _Timeval(ctypes.Structure):
    _fields_ = [('seconds', ctypes.c_long), ('microseconds', ctypes.c_int)]


class _ProcBSDInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in (
        'flags', 'status', 'xstatus', 'pid', 'ppid', 'uid', 'gid', 'ruid', 'rgid', 'svuid', 'svgid', 'rfu')] + [
        ('comm', ctypes.c_char * 16), ('name', ctypes.c_char * 32)] + [
        (name, ctypes.c_uint32) for name in ('nfiles', 'pgid', 'pjobc', 'tdev', 'tpgid', 'nice')] + [
        ('start_seconds', ctypes.c_uint64), ('start_microseconds', ctypes.c_uint64)]


def _boot_identity():
    if sys.platform.startswith('linux'):
        return Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if sys.platform == 'darwin':
        value, length = _Timeval(), ctypes.c_size_t(ctypes.sizeof(_Timeval))
        libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        if libc.sysctlbyname(b'kern.boottime', ctypes.byref(value), ctypes.byref(length), None, 0):
            raise OSError(ctypes.get_errno(), 'boot_identity_unavailable')
        return f'{value.seconds}.{value.microseconds:06d}'
    raise OSError('process_identity_unavailable')


def _namespace_identity():
    if sys.platform.startswith('linux'):
        value = Path('/proc/1/stat').read_text()
        init_start = value[value.rfind(')') + 2:].split()[19]
        return os.readlink('/proc/self/ns/pid') + ':' + init_start
    if sys.platform == 'darwin':
        return 'darwin-host'
    raise OSError('process_namespace_unavailable')


def process_identity(pid):
    """Capture boot and kernel PID start ticks/usecs without shelling out."""
    if type(pid) is not int or pid <= 0:
        raise ValueError('invalid_process_identity')
    boot = _boot_identity()
    if sys.platform.startswith('linux'):
        value = Path(f'/proc/{pid}/stat').read_text()
        parts = value[value.rfind(')') + 2:].split()
        return {'pid': pid, 'start': parts[19], 'boot': boot, 'state': parts[0], 'ppid': int(parts[1]), 'namespace': _namespace_identity()}
    if sys.platform == 'darwin':
        value = _ProcBSDInfo()
        libproc = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
        length = libproc.proc_pidinfo(pid, 3, 0, ctypes.byref(value), ctypes.sizeof(value))
        if length != ctypes.sizeof(value):
            code = ctypes.get_errno()
            if code == errno.ESRCH:
                raise ProcessLookupError()
            raise OSError(code, 'process_identity_unavailable')
        return {'pid': pid, 'start': f'{value.start_seconds}.{value.start_microseconds:06d}',
                'boot': boot, 'state': 'Z' if value.status == 5 else 'R', 'ppid': value.ppid, 'namespace': _namespace_identity()}
    raise OSError('process_identity_unavailable')


def _process_status(identity):
    if (type(identity) is not dict or type(identity.get('pid')) is not int or
            not identity.get('start') or not identity.get('boot')):
        return 'unknown'
    try:
        if identity['boot'] != _boot_identity() or identity.get('namespace') != _namespace_identity():
            return 'unknown'
        current = process_identity(identity['pid'])
    except (FileNotFoundError, ProcessLookupError):
        return 'absent'
    except Exception:
        return 'unknown'
    if current['start'] != identity['start']:
        return 'absent'  # Kernel says a different process owns this PID now.
    # A zombie still exists and must be reaped before its lease can be recovered.
    return 'zombie' if current.get('state', '').startswith('Z') else 'running'


def owner_status(ticket):
    owner = _process_status(ticket.get('owner'))
    if owner in {'running', 'zombie'}:
        return 'running'
    if owner != 'absent':
        return 'unverifiable'
    state = ticket.get('child_state')
    if state == 'none' and ticket.get('child') is None:
        return 'dead_child_reaped'
    if state in {'running', 'reaped'} and _process_status(ticket.get('child')) == 'absent':
        return 'dead_child_reaped'
    # Includes a crash in the spawn-to-record window: unknown is held.
    return 'unverifiable'


def child_is_terminal(ticket):
    state, child = ticket.get('child_state'), ticket.get('child')
    if state == 'none' and child is None:
        return True
    return state in {'running', 'reaped'} and _process_status(child) == 'absent'


def canonical_redfish_link(value, base_url, service=None):
    if (type(value) is not str or not value or len(value) > 2048 or
            any(ord(c) < 33 or ord(c) == 127 for c in value) or '\\' in value or value.startswith('//')):
        raise ValueError('unsafe_redfish_link')
    if service and value.startswith('?'):
        value = service + value
    decoded_value = unquote(value)
    if any(ord(c) < 33 or ord(c) == 127 for c in decoded_value) or '\\' in decoded_value:
        raise ValueError('unsafe_redfish_link')
    parts, origin = urlsplit(value), urlsplit(base_url)
    if parts.fragment or parts.username is not None or parts.password is not None:
        raise ValueError('unsafe_redfish_link')
    if parts.scheme or parts.netloc:
        if parts.scheme != origin.scheme or parts.netloc.lower() != origin.netloc.lower():
            raise ValueError('unsafe_redfish_link')
    path = parts.path
    decoded = unquote(path)
    if (not path.startswith('/redfish/v1/') or decoded != path or
            any(component in {'', '.', '..'} for component in path.rstrip('/').split('/')[1:]) or
            '\\' in decoded or '//' in path):
        raise ValueError('unsafe_redfish_link')
    if service and path != service:
        raise ValueError('foreign_redfish_service')
    return path + ('?' + parts.query if parts.query else '')


# TRACEWEAVER: entrypoint=decode_record; req=REQ-SEL-001,REQ-SEL-003; trace=TRACE-SEL-001,TRACE-SEL-003; ver=VER-CHARLOTTESEL-001,VER-CHARLOTTESEL-003
def decode_record(row):
    """Preserve raw identity/time and decode only standard, recognizable events."""
    raw = bytes.fromhex(row['raw'])
    if len(raw) != 16 or int.from_bytes(raw[:2], 'little') != row['record_id'] or row['record_id'] in (0, 65535):
        raise ValueError('invalid_native_record')
    record_type = raw[2]
    seconds = int.from_bytes(raw[3:7], 'little') if record_type == 2 or 0xc0 <= record_type <= 0xdf else None
    timestamp = datetime.fromtimestamp(seconds, timezone.utc).replace(tzinfo=None) if seconds is not None else datetime(1970, 1, 1)
    value = {'sel_id': str(row['record_id']), 'raw_entry': raw.hex(), 'event_date': timestamp,
             'native_timestamp': str(seconds) if seconds is not None else None,
             'time_quality': ('native-uninitialized' if seconds < 0x20000000 else 'native-unverified') if seconds is not None else 'oem-no-timestamp',
             'sensor_type': 'OEM', 'event_description': f'OEM record type 0x{record_type:02x}; raw evidence retained',
             'severity': 'info', 'event_direction': None, 'event_data': raw[13:16].hex()}
    if record_type != 2:
        return value
    sensor, event_type, offset = raw[10], raw[12] & 0x7f, raw[13] & 15
    asserted = not bool(raw[12] & 0x80)
    value['event_direction'] = 'Asserted' if asserted else 'Deasserted'
    value['sensor_number'] = str(raw[11])
    sensors = {1: 'Temperature', 2: 'Voltage', 3: 'Current', 4: 'Fan', 7: 'Processor',
               8: 'Power Supply', 9: 'Power Unit', 12: 'Memory', 15: 'System Firmware',
               16: 'Event Logging', 19: 'Critical Interrupt', 32: 'OS Stop', 35: 'Watchdog'}
    value['sensor_type'] = sensors.get(sensor, f'Sensor 0x{sensor:02x}')
    description = f'Event type 0x{event_type:02x}, offset 0x{offset:x}; raw evidence retained'
    severity = 'info'
    if event_type == 1:
        descriptions = ['Lower non-critical', 'Lower critical', 'Lower non-recoverable',
                        'Upper non-critical', 'Upper critical', 'Upper non-recoverable']
        if offset < 12:
            description = descriptions[offset // 2] + (' going low' if offset % 2 == 0 else ' going high')
            # Threshold severity is defined by threshold class, independent of text.
            severity = 'warning' if offset // 2 in {0, 3} else 'critical'
    elif event_type == 0x6f:
        standard = {
            7: {0: ('Processor internal error', 'critical'), 1: ('Processor thermal trip', 'critical'),
                11: ('Uncorrectable machine check', 'critical'), 12: ('Correctable machine check', 'warning')},
            8: {0: ('Presence detected', 'info'), 1: ('Power supply failure', 'critical'),
                2: ('Predictive power supply failure', 'warning'), 3: ('Power supply input lost', 'critical'),
                4: ('Power supply input lost or out of range', 'critical'), 5: ('Power supply input out of range', 'warning')},
            12: {0: ('Correctable ECC', 'warning'), 1: ('Uncorrectable ECC', 'critical'),
                 5: ('Correctable ECC logging limit reached', 'warning')},
            32: {0: ('OS critical stop', 'critical'), 1: ('OS critical stop', 'critical')},
            35: {0: ('Watchdog timer expired', 'critical'), 1: ('Watchdog hard reset', 'critical'),
                 2: ('Watchdog power down', 'critical'), 3: ('Watchdog power cycle', 'critical')},
        }
        description, severity = standard.get(sensor, {}).get(offset, (description, 'info'))
    # Generic discrete transition to non-critical/critical/non-recoverable state.
    elif event_type == 7 and offset in {1, 2, 3}:
        description, severity = ('Severity state transition', 'warning' if offset == 1 else 'critical')
    value['event_description'] = description + (' (deasserted)' if not asserted else '')
    value['severity'] = severity if asserted else 'info'
    return value
