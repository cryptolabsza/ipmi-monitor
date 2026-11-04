# TRACEWEAVER: file-role=sel-health-and-guarded-actions; req=REQ-SEL-001; trace=TRACE-SEL-001; ver=VER-SEL-001
"""Durable SEL evidence and qualified, conditional IPMI mutations.

The qualification registry is operator supplied, read-only and empty by default.
Synthetic adapter tests establish application contracts, never firmware support.
"""
import ctypes
import hashlib
import hmac
import json
import os
import re
import select
import secrets
import subprocess
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import jsonify, request, session
from sqlalchemy import event, inspect, text
from sqlalchemy.schema import CreateTable, CreateIndex
from sqlalchemy.orm import Session

ADAPTER_VERSION = "sel-raw-v3-persistent"
TRANSPORT = "lanplus-cipher17-admin"
MAX_RECORDS = 65535
MAX_SECONDS = 60
COOLDOWN = 300
TERMINAL = {"complete", "failed"}


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def stamp(value):
    return value.isoformat() + "Z" if value else None


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class SELUnavailable(Exception):
    """A fixed, nonsecret error code safe for API/audit output."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


class ReservationLost(SELUnavailable):
    pass


class ClearRejectedError(ReservationLost):
    """The initial erase was explicitly rejected before any accepted response."""
    pass


class ClearAcceptedError(SELUnavailable):
    """A clear was accepted; later errors cannot prove that it had no effect."""
    pass


def scoped_custom_command(command):
    """Reject feature writes and raw aliases before the generic credential lookup."""
    parts = command.lower().split()
    if not parts:
        return False
    if parts[0] == 'sel':
        return len(parts) > 1 and (any(parts[1].startswith(name) for name in ('clear', 'delete', 'add', 'writeraw', 'readraw')) or
                                  (parts[1] == 'time' and 'set' in parts[2:]))
    if parts[0] in {'mc', 'bmc'} and len(parts) > 1:
        return any(parts[1].startswith(name) for name in ('setenables', 'reset'))
    if parts[0] == 'raw':
        try:
            values = [int(p, 16) if p.startswith('0x') else int(p, 8) if p.startswith('0') and len(p) > 1 else int(p, 10) for p in parts[1:]]
            if any(not 0 <= value <= 255 for value in values):
                return True
        except ValueError:
            return True
        # SEL deletion, time/offset, logging control, and device reset aliases.
        return len(values) < 2 or ((values[0], values[1]) in {
            (0x0a, 0x44), (0x0a, 0x45), (0x0a, 0x46), (0x0a, 0x47),
            (0x0a, 0x49), (0x0a, 0x5d), (0x06, 0x2e), (0x06, 0x02), (0x06, 0x03),
        })
    return False


class IPMIShellSession:
    """One bounded local child, fixed numeric commands, no shell builtins/input."""
    PROMPT = b'ipmitool> '

    def __init__(self, adapter, reservation=None):
        self.adapter = adapter
        self.process = self.master = None
        self.pending, self.total = b'', 0
        self.reservation = reservation
        try:
            import pty
            import termios
            tool = '/usr/bin/ipmitool'
            master, slave = pty.openpty()
            self.master = master
            try:
                attributes = termios.tcgetattr(slave)
                attributes[3] &= ~termios.ECHO
                termios.tcsetattr(slave, termios.TCSANOW, attributes)
                env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TERM': 'dumb',
                       'IPMI_PASSWORD': adapter.secret}
                self.process = adapter.runtime.subprocess.Popen([tool, '-I', 'lanplus', '-C', '17',
                    '-L', 'ADMINISTRATOR', '-H', adapter.bmc_ip, '-U', adapter.user, '-E',
                    '-N', '1', '-R', '1', 'shell'], stdin=slave, stdout=slave, stderr=slave,
                    env=env, close_fds=True, shell=False)
                env.clear()
            finally:
                os.close(slave)
            if self.frame().strip():
                raise SELUnavailable('malformed_device_response')
        except BaseException as exc:
            self.close()
            if isinstance(exc, SELUnavailable):
                raise
            raise SELUnavailable('device_transport_unavailable') from None

    def frame(self):
        deadline = min(self.adapter.deadline, time.monotonic() + 10)
        while True:
            position = self.pending.find(self.PROMPT)
            if position >= 0:
                body, self.pending = self.pending[:position], self.pending[position + len(self.PROMPT):]
                if len(body) > 4096 or self.pending:
                    raise SELUnavailable('malformed_device_response')
                return body
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SELUnavailable('device_deadline_exceeded' if time.monotonic() >= self.adapter.deadline else 'device_timeout')
            if len(self.pending) > 4096 or self.total > 8 * 1024 * 1024:
                raise SELUnavailable('malformed_device_response')
            ready, _, _ = select.select([self.master], [], [], remaining)
            if not ready:
                continue
            try:
                chunk = os.read(self.master, 1024)
            except OSError:
                raise SELUnavailable('device_stream_closed') from None
            if not chunk:
                raise SELUnavailable('device_stream_closed')
            self.total += len(chunk)
            self.pending += chunk

    def raw(self, netfn, command, *data):
        values = (netfn, command, *data)
        fixed_reads = {(6, 1), (6, 0x37), (6, 0x2f), (10, 0x40), (10, 0x41), (10, 0x48), (10, 0x5c)}
        if any(type(value) is not int or not 0 <= value <= 255 for value in values):
            raise SELUnavailable('command_not_allowlisted')
        allowed = values in fixed_reads or values == (10, 0x42)
        if values[:2] == (10, 0x43):
            allowed = (len(values) == 8 and bytes(values[2:4]) == self.reservation and
                       values[6:] == (0, 255) and values[4:6] != (255, 255))
        elif values[:2] == (10, 0x47):
            allowed = (len(values) == 8 and bytes(values[2:4]) == self.reservation and
                       values[4:7] == (0x43, 0x4c, 0x52) and values[7] in (0, 0xaa))
        if not allowed:
            raise SELUnavailable('command_not_allowlisted')
        if not self.process or self.process.poll() is not None or time.monotonic() >= self.adapter.deadline:
            raise SELUnavailable('device_deadline_exceeded')
        line = 'raw ' + ' '.join(hex(value) for value in values)
        try:
            encoded = (line + '\n').encode('ascii')
            if os.write(self.master, encoded) != len(encoded):
                raise SELUnavailable('device_stream_closed')
            response = self.frame().decode('ascii').replace('\r', '').strip()
            lines = response.splitlines()
            if lines and lines[0].strip() == line:
                response = '\n'.join(lines[1:]).strip()
            parts = response.split()
            if not parts or len(parts) > 512 or any(not re.fullmatch('[0-9a-fA-F]{2}', value) for value in parts):
                if re.search(r'rsp\s*=\s*0xc5\b', response, re.I):
                    raise ReservationLost('reservation_invalid')
                raise SELUnavailable('malformed_device_response')
            result = bytes(int(value, 16) for value in parts)
            if values == (10, 0x42):
                if len(result) != 2 or result == bytes(2):
                    raise SELUnavailable('hardware_reservation_unavailable')
                self.reservation = result
            return result
        except ReservationLost:
            raise
        except SELUnavailable:
            self.close()
            raise
        except (OSError, UnicodeError):
            self.close()
            raise SELUnavailable('device_stream_or_response_failure') from None

    def close(self):
        if self.master is not None:
            os.close(self.master)
            self.master = None
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=1)
            else:
                self.process.wait()


class IPMISELAdapter:
    """Fixed authenticated raw commands, with the reservation carried explicitly."""

    def __init__(self, runtime, bmc_ip, credentials):
        self.runtime, self.bmc_ip = runtime, bmc_ip
        self.user, self.secret = credentials
        if not self.user or not self.secret:
            raise SELUnavailable('target_credentials_unavailable')
        self.deadline = time.monotonic() + MAX_SECONDS
        self.terminal_error = None
        self._shell = None

    def open_session(self, reservation=None):
        if self._shell is None:
            self._shell = IPMIShellSession(self, reservation)

    def close(self):
        if self._shell is not None:
            self._shell.close()
            self._shell = None

    def raw(self, netfn, command, *data):
        if self._shell is not None:
            return self._shell.raw(netfn, command, *data)
        return self._run_raw(netfn, command, *data)

    def _run_raw(self, netfn, command, *data):
        if self.terminal_error:
            raise SELUnavailable(self.terminal_error)
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise SELUnavailable('device_deadline_exceeded')
        argv = ['/usr/bin/ipmitool', '-I', 'lanplus', '-C', '17', '-L', 'ADMINISTRATOR', '-H', self.bmc_ip,
                '-U', self.user, '-E', 'raw'] + [hex(v) for v in (netfn, command, *data)]
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'IPMI_PASSWORD': self.secret}
        try:
            result = self.runtime.subprocess.run(argv, env=env, capture_output=True, text=True,
                                                 timeout=min(10, remaining))
        except subprocess.TimeoutExpired:
            self.terminal_error = 'device_timeout'
            raise SELUnavailable('device_timeout') from None
        except Exception:
            self.terminal_error = 'device_transport_unavailable'
            raise SELUnavailable('device_transport_unavailable') from None
        if result.returncode:
            # No external command body, argv or exception is returned/logged.
            if re.search(r'(?:rsp\s*=\s*0x|completion code.*0x)c5\b', result.stderr or '', re.I):
                raise ReservationLost('reservation_invalid')
            stderr = (result.stderr or '').lower()
            if 'no matching cipher' in stderr:
                code = 'unsupported_cipher'
            elif any(value in stderr for value in ('invalid role', 'unauthorized', 'authentication', 'rakp 2 hmac')):
                code = 'role_or_auth_rejected'
            elif 'unable to establish ipmi v2' in stderr or 'rmcp+' in stderr:
                code = 'rmcp_session_failed'
            elif re.search(r'(?:rsp\s*=\s*0x|completion code.*0x)c1\b', stderr) or 'invalid command' in stderr:
                code = 'unsupported_command'
            else:
                code = 'device_command_failed'
            if code in {'unsupported_cipher', 'role_or_auth_rejected', 'rmcp_session_failed'}:
                self.terminal_error = code
            raise SELUnavailable(code)
        output = result.stdout.strip().split()
        if len(output) > 512 or any(not re.fullmatch(r'[a-fA-F0-9]{2}', v) for v in output):
            raise SELUnavailable('malformed_device_response')
        return bytes(int(v, 16) for v in output)

    def fingerprint(self):
        device = self.raw(0x06, 0x01)
        guid = self.raw(0x06, 0x37)
        if len(device) not in (11, 15) or len(guid) != 16 or guid in (bytes(16), bytes([255]) * 16):
            raise SELUnavailable('hardware_identity_unknown')
        return {'manufacturer': device[6:9].hex(), 'product': device[9:11].hex(),
                'firmware': device[2:4].hex(), 'device_id_reply': device.hex(),
                'aux_firmware_present': len(device) == 15,
                'aux_firmware': device[11:15].hex() if len(device) == 15 else None,
                'firmware_identity_capability': 'get-device-id-' + str(len(device)),
                'guid': guid.hex(), 'log': 'ipmi:sel',
                'adapter': ADAPTER_VERSION, 'transport': TRANSPORT}

    def info(self):
        value = self.raw(0x0a, 0x40)
        if len(value) != 14:
            raise SELUnavailable('sel_info_unknown')
        info = {'entries': int.from_bytes(value[1:3], 'little'),
                'free_bytes': int.from_bytes(value[3:5], 'little'),
                'last_add': value[5:9].hex(), 'last_erase': value[9:13].hex(),
                'overflow': bool(value[13] & 0x80), 'supports_reserve': bool(value[13] & 2),
                'percent_used': None}
        if value[13] & 1:  # Get SEL Allocation Info support, never assume 16-byte allocation units.
            try:
                allocation = self.raw(0x0a, 0x41)
                if len(allocation) == 9:
                    units = int.from_bytes(allocation[:2], 'little')
                    size = int.from_bytes(allocation[2:4], 'little')
                    free = int.from_bytes(allocation[4:6], 'little')
                    if 0 < units < 65535 and 0 < size < 65535 and free <= units:
                        info['percent_used'] = 100 * (units - free) / units
                        info['allocation_unit_bytes'] = size
            except SELUnavailable:
                pass
        return info

    def logging(self):
        value = self.raw(0x06, 0x2f)
        if len(value) != 1:
            raise SELUnavailable('logging_control_unknown')
        return value[0]

    def clock(self):
        value = self.raw(0x0a, 0x48)
        if len(value) != 4:
            raise SELUnavailable('clock_mapping_unknown')
        seconds = int.from_bytes(value, 'little')
        reason = None
        try:
            offset = self.raw(0x0a, 0x5c)
            if len(offset) != 2:
                raise SELUnavailable('malformed_device_response')
            minutes = int.from_bytes(offset, 'little', signed=True)
        except SELUnavailable as exc:
            minutes, reason = 2047, exc.code
        return {'native_seconds': seconds, 'offset_minutes': None if minutes == 2047 else minutes,
                'offset_reason': reason, 'quality': 'uninitialized' if seconds < 0x20000000 else 'native'}

    def reserve(self):
        value = self.raw(0x0a, 0x42)
        if len(value) != 2 or value == bytes(2):
            raise SELUnavailable('hardware_reservation_unavailable')
        return value

    def snapshot(self, reservation):
        self.open_session(reservation)
        before = self.info()
        if not before['supports_reserve']:
            raise SELUnavailable('hardware_reservation_unavailable')
        records, seen, actual_ids, record_id = [], set(), set(), 0
        if before['entries']:
            while True:
                if record_id in seen or len(records) >= MAX_RECORDS:
                    raise SELUnavailable('incomplete_record_chain')
                seen.add(record_id)
                response = self.raw(0x0a, 0x43, *reservation, record_id & 255, record_id >> 8, 0, 255)
                if len(response) != 18:
                    raise SELUnavailable('incomplete_raw_record')
                next_id = int.from_bytes(response[:2], 'little')
                raw = response[2:]
                actual = int.from_bytes(raw[:2], 'little')
                if actual in actual_ids or (record_id and actual != record_id):
                    raise SELUnavailable('incomplete_record_chain')
                actual_ids.add(actual)
                records.append({'record_id': actual, 'raw': raw.hex()})
                if next_id == 65535:
                    break
                record_id = next_id
        after = self.info()
        if before != after or len(records) != before['entries']:
            raise ReservationLost('snapshot_changed')
        # Validate the reservation even for empty snapshots. Get SEL Entry on an
        # empty SEL cannot validate it; a zero-count snapshot is not a clear trigger.
        return {'complete': True, 'records': records, 'info': after,
                'reservation': reservation.hex(), 'collected_at': stamp(utcnow())}

    def clear(self, reservation):
        try:
            value = self.raw(0x0a, 0x47, *reservation, 0x43, 0x4c, 0x52, 0xaa)
        except ReservationLost as exc:
            raise ClearRejectedError(exc.code) from None
        if len(value) != 1 or value[0] not in (0, 1):
            raise SELUnavailable('clear_outcome_unknown')
        # From the first accepted response onward, every poll/readback failure
        # is an uncertain accepted erase, including a later reservation C5.
        try:
            while value[0] == 0:
                if time.monotonic() >= self.deadline:
                    raise SELUnavailable('clear_outcome_unknown')
                time.sleep(0.2)
                value = self.raw(0x0a, 0x47, *reservation, 0x43, 0x4c, 0x52, 0)
                if len(value) != 1 or value[0] not in (0, 1):
                    raise SELUnavailable('clear_outcome_unknown')
            return self.info()
        except SELUnavailable as exc:
            raise ClearAcceptedError(exc.code) from None

    def enable(self):
        before = self.logging()
        self.raw(0x06, 0x2e, before | 0x08)
        after = self.logging()
        if after != before | 0x08:
            raise SELUnavailable('logging_readback_mismatch')
        return {'before': before, 'after': after}

    def time_management(self, qualification):
        probe = qualification.get('ntp_probe', {})
        path, ca = probe.get('path', ''), probe.get('ca_file')
        if not re.fullmatch(r'/redfish/v1/Managers/[A-Za-z0-9_.-]+/NetworkProtocol', path) or not ca:
            raise SELUnavailable('time_management_unknown')
        try:
            response = self.runtime.requests.get('https://' + self.bmc_ip + path,
                auth=(self.user, self.secret), verify=ca, allow_redirects=False, timeout=5)
            if response.status_code != 200 or len(response.content) > 65536:
                raise ValueError()
            ntp = response.json()['NTP']
            enabled = ntp['ProtocolEnabled']
            if type(enabled) is not bool:
                raise ValueError()
            return {'managed': enabled, 'healthy': ntp.get('Status', {}).get('Health') == 'OK',
                    'observed_at': stamp(utcnow())}
        except Exception:
            raise SELUnavailable('time_management_unknown') from None

    def sync_clock(self, qualification, reference, before, management):
        if management['managed']:
            raise SELUnavailable('externally_managed_clock')
        offset = before['offset_minutes']
        if offset is None or not -720 <= offset <= 840 or qualification.get('clock_semantics') not in {'local_epoch_with_utc_offset', 'utc_epoch'}:
            raise SELUnavailable('clock_mapping_unknown')
        desired = int(reference['utc']) + (offset * 60 if qualification['clock_semantics'] == 'local_epoch_with_utc_offset' else 0)
        if not 0x20000000 <= desired < 0xffffffff:
            raise SELUnavailable('trusted_time_out_of_range')
        # Set SEL Time resets UTC offset on IPMI hardware. Restore and verify it.
        self.raw(0x0a, 0x49, *desired.to_bytes(4, 'little'))
        self.raw(0x0a, 0x5d, *int(offset).to_bytes(2, 'little', signed=True))
        after = self.clock()
        if after['offset_minutes'] != offset or abs(after['native_seconds'] - desired) > 5:
            raise SELUnavailable('clock_readback_mismatch')
        return {'before': before, 'desired_utc': reference['utc'], 'after': after, 'reference': reference}


class _Timeval(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_long), ('tv_usec', ctypes.c_long)]


class _LinuxTimex(ctypes.Structure):
    # Linux UAPI LP64 struct timex. Never use this layout on another ABI.
    _fields_ = [('modes', ctypes.c_uint), ('offset', ctypes.c_long), ('freq', ctypes.c_long),
        ('maxerror', ctypes.c_long), ('esterror', ctypes.c_long), ('status', ctypes.c_int),
        ('constant', ctypes.c_long), ('precision', ctypes.c_long), ('tolerance', ctypes.c_long),
        ('time', _Timeval), ('tick', ctypes.c_long), ('ppsfreq', ctypes.c_long),
        ('jitter', ctypes.c_long), ('shift', ctypes.c_int), ('stabil', ctypes.c_long),
        ('jitcnt', ctypes.c_long), ('calcnt', ctypes.c_long), ('errcnt', ctypes.c_long),
        ('stbcnt', ctypes.c_long), ('tai', ctypes.c_int), ('padding', ctypes.c_int * 11)]


def kernel_clock_status():
    """Read-only Linux kernel synchronization query, without CAP_SYS_TIME.

    adjtimex(2) modes=0 retrieves state only. No modes, offset or clock write
    is accepted from configuration or API. The local Mac is never queried.
    """
    if not sys.platform.startswith('linux') or ctypes.sizeof(ctypes.c_long) != 8 or ctypes.sizeof(_LinuxTimex) != 208:
        return None
    try:
        query = ctypes.CDLL(None, use_errno=True).adjtimex
        query.argtypes, query.restype = [ctypes.POINTER(_LinuxTimex)], ctypes.c_int
        value = _LinuxTimex()  # all zero, including modes=0, read-only
        result = query(ctypes.byref(value))
        divisor = 1e9 if value.status & 0x2000 else 1e6
        return {'result': result, 'status': value.status, 'maxerror_us': value.maxerror,
                'offset_us': value.offset / (1000 if value.status & 0x2000 else 1),
                'utc': value.time.tv_sec + value.time.tv_usec / divisor}
    except (AttributeError, OSError, ValueError):
        return None


# TRACEWEAVER: entrypoint=trusted_reference; req=REQ-SEL-001,REQ-SEL-002,REQ-SEL-003,REQ-SEL-004,REQ-SEL-005; trace=TRACE-SEL-001,TRACE-SEL-002,TRACE-SEL-003,TRACE-SEL-004,TRACE-SEL-005; ver=VER-SEL-001,VER-SEL-002,VER-SEL-003,VER-SEL-004,VER-SEL-005
def trusted_reference(runtime):
    """Fresh synchronized UTC proof; a container uses its read-only kernel state.

    Linux adjtimex modes=0 works without a systemd executable/bus. Require
    TIME_OK, active discipline, no UNSYNC/CLOCKERR, bounded estimated error
    and a contemporaneous realtime sample. Leap/ambiguous states fail closed.
    Source: https://man7.org/linux/man-pages/man2/adjtimex.2.html
    """
    started = time.monotonic()
    if sys.platform.startswith('linux'):
        status = kernel_clock_status()
        if (not status or status['result'] != 0 or status['status'] & (0x40 | 0x1000) or
                not status['status'] & (0x01 | 0x08) or not 0 <= status['maxerror_us'] <= 500000 or
                abs(status['offset_us']) > 500000 or time.monotonic() - started > 1 or
                abs(status['utc'] - time.time()) > 1):
            return None
        return {'utc': status['utc'], 'checked_monotonic': time.monotonic(),
                'source': 'linux-adjtimex-read-only', 'kernel_status': status}
    # Optional non-container systemd lane. This never adjusts the monitor clock.
    try:
        result = runtime.subprocess.run(['timedatectl', 'show', '--property=NTPSynchronized', '--value'],
                                        capture_output=True, text=True, timeout=3)
        if result.returncode or result.stdout.strip() != 'yes' or time.monotonic() - started > 3:
            return None
        return {'utc': time.time(), 'checked_monotonic': time.monotonic(), 'source': 'timedatectl:NTPSynchronized'}
    except Exception:
        return None


def qualification_records():
    from .sel_qualifications import qualification_state
    return qualification_state()['records']


def qualification_selection(fingerprint, action):
    from .sel_qualifications import qualification_state
    state = qualification_state()
    for record in state['records']:
        if record['fingerprint'] == fingerprint and action in record['actions']:
            return record, digest({'source': state['binding'], 'record': digest(record),
                                   'action': digest(record['actions'][action])})
    return None, None


def qualified(fingerprint, action):
    return qualification_selection(fingerprint, action)[0]


# TRACEWEAVER: entrypoint=register_sel_management; req=REQ-SEL-001,REQ-SEL-002,REQ-SEL-003,REQ-SEL-004,REQ-SEL-005; trace=TRACE-SEL-001,TRACE-SEL-002,TRACE-SEL-003,TRACE-SEL-004,TRACE-SEL-005; ver=VER-SEL-001,VER-SEL-002,VER-SEL-003,VER-SEL-004,VER-SEL-005
def register_sel_management(runtime):
    """Register durable models and the narrow API against the real application."""
    app, db = runtime.app, runtime.db

    class SELTarget(db.Model):
        id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
        server_id = db.Column(db.Integer, unique=True, nullable=False)
        bmc_ip = db.Column(db.String(45), nullable=False)
        binding = db.Column(db.String(64), nullable=False)
        revision = db.Column(db.Integer, nullable=False, default=1)
        fingerprint = db.Column(db.Text)
        generation = db.Column(db.Integer, nullable=False, default=0)
        snapshot_epoch = db.Column(db.Integer, nullable=False, default=0)
        health = db.Column(db.Text)
        observed_at = db.Column(db.DateTime)
        active_operation = db.Column(db.String(36))
        cooldown_until = db.Column(db.DateTime)
        failure_count = db.Column(db.Integer, nullable=False, default=0)
        auto_clear = db.Column(db.Boolean, nullable=False, default=False)
        auto_clock = db.Column(db.Boolean, nullable=False, default=False)
        policy_revision = db.Column(db.Integer, nullable=False, default=0)
        consent_fingerprint = db.Column(db.String(64))
        consent_qualification = db.Column(db.Text)
        near_full = db.Column(db.Integer, nullable=False, default=90)
        drift_seconds = db.Column(db.Integer, nullable=False, default=300)

    class SELOperation(db.Model):
        id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
        target_id = db.Column(db.String(36), nullable=False, index=True)
        action = db.Column(db.String(20), nullable=False)
        state = db.Column(db.String(24), nullable=False, default='queued')
        identity_revision = db.Column(db.Integer, nullable=False)
        policy_revision = db.Column(db.Integer, nullable=False)
        epoch = db.Column(db.Integer, nullable=False)
        initiator = db.Column(db.String(120), nullable=False)
        automatic = db.Column(db.Boolean, default=False, nullable=False)
        reason = db.Column(db.String(80), nullable=False)
        qualification_binding = db.Column(db.String(64))
        archive_id = db.Column(db.String(36))
        outcome = db.Column(db.String(80))
        evidence = db.Column(db.Text)
        attempts = db.Column(db.Integer, nullable=False, default=0)
        created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
        updated_at = db.Column(db.DateTime, nullable=False, default=utcnow)
        dispatched_at = db.Column(db.DateTime)

    class SELArchive(db.Model):
        id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
        target_id = db.Column(db.String(36), nullable=False, index=True)
        operation_id = db.Column(db.String(36), nullable=False)
        generation = db.Column(db.Integer, nullable=False)
        snapshot_epoch = db.Column(db.Integer, nullable=False)
        sha256 = db.Column(db.String(64), nullable=False)
        payload = db.Column(db.Text, nullable=False)
        archived_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    class SELAudit(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        target_id = db.Column(db.String(36), nullable=False, index=True)
        operation_id = db.Column(db.String(36))
        subject = db.Column(db.String(120), nullable=False)
        action = db.Column(db.String(40), nullable=False)
        evidence = db.Column(db.Text, nullable=False)
        created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    for model in (SELTarget, SELOperation, SELArchive, SELAudit):
        setattr(runtime, model.__name__, model)

    class Manager:
        def audit(self, target, action, evidence, operation=None, subject=None):
            db.session.add(SELAudit(target_id=target.id, operation_id=operation.id if operation else None,
                subject=subject or (operation.initiator if operation else session.get('username', 'collector') if request else 'collector'),
                action=action, evidence=json.dumps(evidence, sort_keys=True)))

        def current_server(self, bmc_ip):
            binding = runtime.InventoryBinding.query.filter_by(bmc_ip=bmc_ip).first()
            if binding and binding.lifecycle != 'active':
                raise SELUnavailable('configured_active_target_required')
            server = runtime.Server.query.filter_by(bmc_ip=bmc_ip).first()
            if not server or not server.enabled or server.status not in ('active', None):
                raise SELUnavailable('configured_active_target_required')
            return server

        def binding(self, server):
            row = runtime.InventoryBinding.query.filter_by(bmc_ip=server.bmc_ip).first()
            return digest([server.id, stamp(server.created_at), server.bmc_ip, server.protocol,
                [row.source_id, row.source_server_id, row.revision, row.credential_revision,
                 row.credential_digest, row.lifecycle] if row else None])

        def target(self, bmc_ip):
            server = self.current_server(bmc_ip)
            binding = self.binding(server)
            target = SELTarget.query.filter_by(server_id=server.id).first()
            if not target:
                target = SELTarget(server_id=server.id, bmc_ip=bmc_ip, binding=binding)
                db.session.add(target)
                try:
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                    target = SELTarget.query.filter_by(server_id=server.id).first()
                    if not target:
                        raise SELUnavailable('target_store_unavailable') from None
            if target.binding != binding:
                target.binding, target.bmc_ip = binding, bmc_ip
                target.revision += 1
                target.generation += 1
                target.snapshot_epoch += 1
                target.auto_clear = target.auto_clock = False
                target.consent_fingerprint = None
                target.policy_revision += 1
                target.fingerprint = target.health = None
                self.audit(target, 'binding_revoked', {'revision': target.revision}, subject='inventory')
                db.session.commit()
            return target

        def adapter(self, target):
            # No shared username/password fallback: only explicit per-target source.
            server = self.current_server(target.bmc_ip)
            if self.binding(server) != target.binding or server.protocol == 'redfish':
                raise SELUnavailable('configured_identity_changed')
            # Preserve the existing managed-credential revocation and configured
            # unmanaged credential sources, always as a complete username/secret pair.
            credentials = runtime.get_ipmi_credentials(target.bmc_ip)
            if not credentials or not all(credentials):
                raise SELUnavailable('target_credentials_unavailable')
            return IPMISELAdapter(runtime, target.bmc_ip, credentials)

        def identify(self, target, adapter):
            fingerprint = adapter.fingerprint()
            encoded = json.dumps(fingerprint, sort_keys=True)
            if target.fingerprint != encoded:
                if target.fingerprint:
                    target.revision += 1
                    target.generation += 1
                    target.auto_clear = target.auto_clock = False
                    target.consent_fingerprint = None
                    target.policy_revision += 1
                target.snapshot_epoch += 1
                target.fingerprint = encoded
                self.audit(target, 'hardware_identity', {'fingerprint': fingerprint}, subject='collector')
                db.session.commit()
            return fingerprint

        def observe(self, bmc_ip):
            target = self.target(bmc_ip)
            try:
                adapter = self.adapter(target)
                health = {'state': 'unknown', 'logging_enabled': None, 'percent_used': None,
                          'capacity_observed_at': None, 'logging_observed_at': None, 'clock_observed_at': None,
                          'probes': {}}
                def observed(name, reason=None):
                    health['probes'][name] = {'reason': reason, 'observed_at': stamp(utcnow()),
                                             'source': 'ipmitool:raw', 'profile': TRANSPORT}
                try:
                    fingerprint = self.identify(target, adapter)
                    observed('identity')
                except SELUnavailable as exc:
                    fingerprint = None
                    observed('identity', exc.code)
                    if target.fingerprint:
                        target.revision += 1
                        target.policy_revision += 1
                        target.fingerprint = target.consent_fingerprint = target.consent_qualification = None
                        target.auto_clear = target.auto_clock = False
                        self.audit(target, 'identity_unavailable', {'reason': exc.code}, subject='collector')
                try:
                    info = adapter.info()
                    old = json.loads(target.health or '{}').get('info')
                    if old and (old['last_erase'] != info['last_erase'] or info['entries'] < old['entries'] or
                            int.from_bytes(bytes.fromhex(info['last_add']), 'little') < int.from_bytes(bytes.fromhex(old['last_add']), 'little')):
                        target.generation += 1
                        target.snapshot_epoch += 1
                    health['info'], health['capacity_observed_at'] = info, stamp(utcnow())
                    health['percent_used'] = info['percent_used']
                    # Overflow is a historical loss warning, not current capacity.
                    health['full'] = (None if info['free_bytes'] in (0xffff, 0xfffe) else info['free_bytes'] == 0)
                    observed('capacity')
                except SELUnavailable as exc:
                    health['full'] = None
                    observed('capacity', exc.code)
                try:
                    health['logging_enabled'] = bool(adapter.logging() & 8)
                    health['logging_observed_at'] = stamp(utcnow())
                    observed('logging')
                except SELUnavailable as exc:
                    observed('logging', exc.code)
                try:
                    health['clock'] = adapter.clock()
                    health['clock_observed_at'] = stamp(utcnow())
                    reference = trusted_reference(runtime)
                    health['reference_verified'] = bool(reference)
                    native = health['clock']
                    offset = native['offset_minutes']
                    health['clock_incorrect'] = native['quality'] == 'uninitialized'
                    mapping = qualified(fingerprint, 'clock') if fingerprint else None
                    health['clock_mapping'] = mapping.get('clock_semantics') if mapping else None
                    if reference and offset is not None and mapping:
                        health['drift_seconds'] = native['native_seconds'] - (offset * 60 if mapping['clock_semantics'] == 'local_epoch_with_utc_offset' else 0) - reference['utc']
                        health['clock_incorrect'] |= abs(health['drift_seconds']) > target.drift_seconds
                    observed('clock', 'clock_mapping_unknown' if not mapping else None)
                    observed('offset', native.get('offset_reason'))
                except SELUnavailable as exc:
                    health['clock'] = None
                    observed('clock', exc.code)
                health['fingerprint'] = fingerprint
                target.health, target.observed_at = json.dumps(health), utcnow()
                db.session.commit()
            except SELUnavailable as exc:
                target.health = json.dumps({'state': 'unknown', 'error': exc.code})
                target.observed_at = utcnow()
                db.session.commit()
            return self.health(self.refresh_consent(target))

        def health(self, target):
            health = json.loads(target.health or '{}')
            fresh = bool(target.observed_at and 0 <= (utcnow() - target.observed_at).total_seconds() <= max(120, 2 * runtime.POLL_INTERVAL))
            flags = []
            if fresh:
                if health.get('info', {}).get('overflow'):
                    flags.append('overflow')
                if health.get('full'):
                    flags.append('full')
                elif health.get('percent_used') is not None and health['percent_used'] >= target.near_full:
                    flags.append('nearly_full')
                if health.get('logging_enabled') is False:
                    flags.append('logging_disabled')
                if health.get('clock_incorrect'):
                    flags.append('clock_incorrect')
                elif not health.get('clock') or not health.get('clock_mapping') or not health.get('reference_verified') or health['clock'].get('offset_minutes') is None:
                    flags.append('clock_unknown')
            known = fresh and health.get('logging_enabled') is not None and health.get('full') is not None
            health.update(state=next((flag for flag in flags if flag != 'overflow'), 'overflow') if flags else 'healthy' if known else 'unknown', flags=flags,
                          stale=not fresh, observed_at=stamp(target.observed_at))
            health.setdefault('logging_enabled', None)
            health.setdefault('percent_used', None)
            if not fresh:
                health.update(logging_enabled=None, percent_used=None, full=None)
            return health

        def representation(self, target):
            target = self.refresh_consent(target)
            server = self.current_server(target.bmc_ip)
            fingerprint = json.loads(target.fingerprint) if target.fingerprint else None
            capabilities = {action: {'available': bool(target.failure_count < 3 and fingerprint and qualified(fingerprint, action)),
                            'reason': 'Exact device/firmware qualification required'} for action in ('clear', 'enable', 'clock')}
            op = (db.session.get(SELOperation, target.active_operation) if target.active_operation else
                  SELOperation.query.filter_by(target_id=target.id).order_by(SELOperation.created_at.desc()).first())
            return {'bmc_ip': target.bmc_ip, 'server_name': server.server_name, 'target_id': target.id,
                'identity_revision': target.revision, 'health': self.health(target),
                'policies': {'automatic_clear': target.auto_clear, 'automatic_clock': target.auto_clock,
                    'revision': target.policy_revision, 'near_full_percent': target.near_full,
                    'clock_drift_seconds': target.drift_seconds}, 'capabilities': capabilities,
                'operation': self.operation_view(op) if op else None}

        def operation_view(self, op):
            return {'id': op.id, 'action': op.action, 'state': op.state, 'outcome': op.outcome,
                'archive_receipt': op.archive_id, 'created_at': stamp(op.created_at), 'updated_at': stamp(op.updated_at)}

        def valid_revision(self, target, body):
            if (body.get('target_id') != target.id or type(body.get('identity_revision')) is not int or
                    body['identity_revision'] != target.revision or type(body.get('policy_revision')) is not int or
                    body['policy_revision'] != target.policy_revision):
                raise SELUnavailable('stale_target_or_policy_revision')

        def authority(self, target):
            return (target.revision, target.policy_revision, target.snapshot_epoch)

        def consent_state(self, target, selections):
            consent = json.loads(target.consent_qualification or '{}')
            armed = {'clear': target.auto_clear, 'clock': target.auto_clock}
            fingerprint = json.loads(target.fingerprint) if target.fingerprint else None
            revoked = []
            for action in ('clear', 'clock'):
                if armed[action] and (not selections[action] or consent.get(action) != selections[action] or
                        target.consent_fingerprint != (digest(fingerprint) if fingerprint else None)):
                    armed[action] = False
                    consent[action] = None
                    revoked.append(action)
            return consent, armed, revoked

        def revoke_locked(self, target, selections):
            consent, armed, revoked = self.consent_state(target, selections)
            if revoked:
                target.auto_clear, target.auto_clock = armed['clear'], armed['clock']
                target.consent_qualification = json.dumps(consent, sort_keys=True)
                target.policy_revision += 1
                self.audit(target, 'qualification_consent_revoked', {'actions': revoked}, subject='qualification-observer')
                # Commit the safety revocation before a caller rejects/rolls back.
                db.session.commit()
            return bool(revoked)

        def refresh_consent(self, target):
            target_id = target.id
            db.session.rollback()
            if db.engine.dialect.name != 'sqlite':
                raise SELUnavailable('serialized_dispatch_unavailable')
            db.session.execute(text('BEGIN IMMEDIATE'))
            db.session.expire_all()
            target = db.session.get(SELTarget, target_id)
            fingerprint = json.loads(target.fingerprint) if target.fingerprint else None
            selections = {action: qualification_selection(fingerprint, action)[1] for action in ('clear', 'clock')}
            self.revoke_locked(target, selections)
            db.session.commit()
            return target

        def claim(self, target, action, initiator, automatic=False, expected_qualification=None, expected_authority=None):
            expected_authority = self.authority(target) if expected_authority is None else expected_authority
            target_id = target.id
            db.session.rollback()
            if db.engine.dialect.name != 'sqlite':
                raise SELUnavailable('serialized_dispatch_unavailable')
            db.session.execute(text('BEGIN IMMEDIATE'))
            db.session.expire_all()
            target = db.session.get(SELTarget, target_id)
            if self.authority(target) != expected_authority:
                raise SELUnavailable('identity_or_policy_revoked')
            fingerprint = json.loads(target.fingerprint) if target.fingerprint else None
            selections = {name: qualification_selection(fingerprint, name)[1] for name in ('clear', 'clock')}
            if self.revoke_locked(target, selections):
                raise SELUnavailable('qualification_consent_revoked')
            _, selection = qualification_selection(fingerprint, action)
            if not selection:
                raise SELUnavailable('exact_hardware_qualification_required')
            if expected_qualification is not None and selection != expected_qualification:
                raise SELUnavailable('qualification_revoked')
            if automatic and (not (target.auto_clear if action == 'clear' else target.auto_clock) or
                    json.loads(target.consent_qualification or '{}').get(action) != selection):
                raise SELUnavailable('qualification_consent_revoked')
            operation = SELOperation(id=str(uuid.uuid4()), target_id=target.id, action=action,
                state='queued', identity_revision=target.revision, policy_revision=target.policy_revision,
                epoch=target.snapshot_epoch, initiator=initiator, automatic=automatic, reason='automatic' if automatic else 'admin_request',
                qualification_binding=selection)
            updated = db.session.query(SELTarget).filter(SELTarget.id == target.id,
                SELTarget.active_operation.is_(None), SELTarget.revision == target.revision,
                SELTarget.policy_revision == target.policy_revision,
                db.or_(SELTarget.cooldown_until.is_(None), SELTarget.cooldown_until <= utcnow())).update(
                    {'active_operation': operation.id}, synchronize_session=False)
            if updated != 1:
                db.session.rollback()
                raise SELUnavailable('operation_busy_or_cooldown')
            db.session.add(operation)
            self.audit(target, 'operation_queued', {'action': action}, operation)
            db.session.commit()
            return operation

        def check_authority(self, target_id, operation_id, fingerprint):
            target = db.session.get(SELTarget, target_id)
            operation = db.session.get(SELOperation, operation_id)
            if not target or not operation:
                raise SELUnavailable('identity_or_policy_revoked')
            server = self.current_server(target.bmc_ip)
            if (self.binding(server) != target.binding or target.active_operation != operation.id or
                    target.revision != operation.identity_revision or target.policy_revision != operation.policy_revision or
                    target.snapshot_epoch != operation.epoch or target.fingerprint != json.dumps(fingerprint, sort_keys=True)):
                raise SELUnavailable('identity_or_policy_revoked')
            if operation.automatic and (target.consent_fingerprint != digest(fingerprint) or
                    not (target.auto_clear if operation.action == 'clear' else target.auto_clock)):
                raise SELUnavailable('automation_revoked')
            _, selection = qualification_selection(fingerprint, operation.action)
            selections = {name: qualification_selection(fingerprint, name)[1] for name in ('clear', 'clock')}
            if self.revoke_locked(target, selections):
                raise SELUnavailable('qualification_consent_revoked')
            if not selection or selection != operation.qualification_binding:
                raise SELUnavailable('qualification_revoked')
            if operation.automatic and json.loads(target.consent_qualification or '{}').get(operation.action) != selection:
                raise SELUnavailable('qualification_consent_revoked')
            return target, operation

        def recheck(self, target, operation, adapter, fingerprint):
            target_id, operation_id = target.id, operation.id
            # Network identity proof precedes fresh database authority, never the reverse.
            if adapter.fingerprint() != fingerprint:
                raise SELUnavailable('identity_or_policy_revoked')
            db.session.rollback()
            if db.engine.dialect.name != 'sqlite':
                raise SELUnavailable('serialized_dispatch_unavailable')
            db.session.execute(text('BEGIN IMMEDIATE'))
            db.session.expire_all()
            return self.check_authority(target_id, operation_id, fingerprint)[0]

# TRACEWEAVER: entrypoint=dispatch_intent; req=REQ-SEL-001,REQ-SEL-002,REQ-SEL-003,REQ-SEL-004,REQ-SEL-005; trace=TRACE-SEL-001,TRACE-SEL-002,TRACE-SEL-003,TRACE-SEL-004,TRACE-SEL-005; ver=VER-SEL-001,VER-SEL-002,VER-SEL-003,VER-SEL-004,VER-SEL-005
        def dispatch_intent(self, target, operation, adapter, fingerprint, evidence):
            target_id, operation_id = target.id, operation.id
            if adapter.fingerprint() != fingerprint:
                raise SELUnavailable('identity_or_policy_revoked')
            # Discard stale read snapshots, then serialize the FINAL authority
            # decision and accepted intent with all SQLite lifecycle/policy writers.
            # A revocation committed first wins; after this commit dispatch is
            # accepted and cannot be promised recall at the physical BMC boundary.
            db.session.rollback()
            if db.engine.dialect.name != 'sqlite':
                raise SELUnavailable('serialized_dispatch_unavailable')
            db.session.execute(text('BEGIN IMMEDIATE'))
            db.session.expire_all()
            target, operation = self.check_authority(target_id, operation_id, fingerprint)
            current_credentials = runtime.get_ipmi_credentials(target.bmc_ip)
            if current_credentials != (adapter.user, adapter.secret):
                raise SELUnavailable('target_credentials_revoked')
            accepted_at = utcnow()
            updated = db.session.query(SELOperation).filter(SELOperation.id == operation.id,
                SELOperation.state.in_(['queued', 'archiving']), SELOperation.dispatched_at.is_(None)).update(
                    {'state': 'mutating', 'dispatched_at': accepted_at, 'updated_at': accepted_at}, synchronize_session=False)
            if updated != 1:
                raise SELUnavailable('dispatch_intent_already_consumed')
            if operation.action == 'clock':
                target.snapshot_epoch += 1
            self.audit(target, 'clock_dispatch_intent' if operation.action == 'clock' else 'dispatch_intent', evidence, operation)
            db.session.commit()
            return target, operation

        def durability(self):
            if db.engine.dialect.name == 'sqlite':
                # Must be FULL or EXTRA, not a weak filesystem receipt.
                if db.session.execute(text('PRAGMA synchronous')).scalar() not in (2, 3):
                    raise SELUnavailable('durable_store_required')

        def finish(self, target, operation, state, outcome, evidence=None):
            operation.state, operation.outcome, operation.updated_at = state, outcome, utcnow()
            target.failure_count = 0 if state == 'complete' else target.failure_count + 1
            if target.failure_count >= 3:
                target.auto_clear = target.auto_clock = False
                target.policy_revision += 1
            if evidence is not None:
                existing = json.loads(operation.evidence or '{}')
                existing.update(evidence)
                operation.evidence = json.dumps(existing, sort_keys=True)
            if state in TERMINAL:
                target.active_operation = None
            target.cooldown_until = utcnow() + timedelta(seconds=COOLDOWN)
            self.audit(target, 'operation_' + state, {'outcome': outcome}, operation)
            db.session.commit()

        def execute(self, target, action, initiator, automatic=False, expected_authority=None):
            expected_authority = self.authority(target) if expected_authority is None else expected_authority
            expected_revision = expected_authority[0]
            if target.failure_count >= 3:
                raise SELUnavailable('repeated_failure_hold')
            adapter = self.adapter(target)
            fingerprint = self.identify(target, adapter)
            qualification, selected_binding = qualification_selection(fingerprint, action)
            if not qualification:
                self.refresh_consent(target)
                raise SELUnavailable('exact_hardware_qualification_required')
            if target.revision != expected_revision:
                raise SELUnavailable('configured_identity_changed')
            operation = self.claim(target, action, initiator, automatic, expected_qualification=selected_binding,
                                   expected_authority=expected_authority)
            operation.evidence = json.dumps({'qualification_id': qualification['record_id'],
                                             'qualification_sha256': digest(qualification)})
            self.audit(target, 'qualification_bound', json.loads(operation.evidence), operation)
            db.session.commit()
            dispatched = False
            try:
                self.durability()
                if action == 'clear':
                    adapter.open_session()
                    if adapter.fingerprint() != fingerprint:
                        raise SELUnavailable('identity_or_policy_revoked')
                    operation.state = 'archiving'
                    db.session.commit()
                    snapshot = None
                    for attempt in range(2):
                        operation.attempts = attempt + 1
                        try:
                            reservation = adapter.reserve()
                            snapshot = adapter.snapshot(reservation)
                            break
                        except ReservationLost:
                            if attempt == 1:
                                raise
                    if not snapshot or not snapshot['complete'] or not snapshot['records']:
                        raise SELUnavailable('no_complete_nonempty_snapshot')
                    self.recheck(target, operation, adapter, fingerprint)
                    snapshot.update(target_id=target.id, fingerprint=fingerprint, generation=target.generation,
                                    snapshot_epoch=target.snapshot_epoch, qualification_id=qualification['record_id'],
                                    qualification_sha256=digest(qualification))
                    payload = json.dumps(snapshot, sort_keys=True)
                    if len(payload) > 4 * 1024 * 1024:
                        raise SELUnavailable('archive_size_limit')
                    archive = SELArchive(id=str(uuid.uuid4()), target_id=target.id, operation_id=operation.id,
                        generation=target.generation, snapshot_epoch=target.snapshot_epoch,
                        payload=payload, sha256=hashlib.sha256(payload.encode()).hexdigest())
                    db.session.add(archive)
                    operation.archive_id = archive.id
                    self.audit(target, 'archive_committed', {'receipt': archive.id, 'sha256': archive.sha256,
                        'count': len(snapshot['records'])}, operation)
                    db.session.commit()
                    # Read the actual durable receipt back before dispatch.
                    db.session.expire_all()
                    saved = db.session.get(SELArchive, archive.id)
                    if not saved or saved.sha256 != hashlib.sha256(saved.payload.encode()).hexdigest():
                        raise SELUnavailable('archive_receipt_invalid')
                    target, operation = self.dispatch_intent(target, operation, adapter, fingerprint, {'receipt': archive.id})
                    dispatched = True
                    after = adapter.clear(reservation)
                    operation.state = 'verifying'
                    db.session.commit()
                    target.generation += 1
                    target.snapshot_epoch += 1
                    self.finish(target, operation, 'complete', 'clear_verified', {'after': after})
                elif action == 'enable':
                    target, operation = self.dispatch_intent(target, operation, adapter, fingerprint, {'action': action})
                    dispatched = True
                    result = adapter.enable()
                    self.finish(target, operation, 'complete', 'logging_enabled_verified', result)
                elif action == 'clock':
                    before = adapter.clock()
                    management = adapter.time_management(qualification)
                    if management['managed']:
                        raise SELUnavailable('externally_managed_clock')
                    reference = trusted_reference(runtime)
                    if not reference or time.monotonic() - reference['checked_monotonic'] > 30:
                        raise SELUnavailable('trusted_fresh_utc_required')
                    if before['offset_minutes'] is None:
                        raise SELUnavailable('clock_mapping_unknown')
                    target, operation = self.dispatch_intent(target, operation, adapter, fingerprint,
                        {'before': before, 'reference': reference, 'time_management': management})
                    dispatched = True
                    result = adapter.sync_clock(qualification, reference, before, management)
                    self.finish(target, operation, 'complete', 'clock_verified', result)
                adapter.close()
                try:
                    self.observe(target.bmc_ip)
                except Exception:
                    db.session.rollback()
                    app.logger.warning('SEL health refresh unavailable after verified operation')
            except Exception as exc:
                db.session.rollback()
                operation = db.session.get(SELOperation, operation.id)
                target = db.session.get(SELTarget, target.id)
                code = exc.code if isinstance(exc, SELUnavailable) else 'operation_store_or_device_failure'
                # Durable intent is authoritative even if its commit reply failed.
                # Only initial erase C5 proves no clear acceptance; later C5 and
                # clock/enable errors cannot release an uncertain accepted effect.
                accepted_intent = dispatched or operation.dispatched_at is not None
                state = 'outcome-unknown' if accepted_intent and not isinstance(exc, ClearRejectedError) else 'failed'
                try:
                    self.finish(target, operation, state, code,
                        {'hardware_erase_acceptance_observed': True} if isinstance(exc, ClearAcceptedError) else None)
                except Exception:
                    db.session.rollback()  # Committed dispatch intent remains owned and reconcilable.
                    app.logger.warning('SEL operation requires durable reconciliation')
            finally:
                adapter.close()
            return operation

        def reconcile(self, target):
            op = db.session.get(SELOperation, target.active_operation) if target.active_operation else None
            if not op:
                return
            # Never reclaim an active worker. A bounded command cannot run >60s;
            # grace prevents a healthy request being mistaken for a crashed one.
            if (utcnow() - op.updated_at).total_seconds() < MAX_SECONDS + 30:
                return
            if not op.dispatched_at:
                self.finish(target, op, 'failed', 'interrupted_before_dispatch')
                return
            try:
                adapter = self.adapter(target)
                fingerprint = adapter.fingerprint()
                if json.dumps(fingerprint, sort_keys=True) != target.fingerprint:
                    raise SELUnavailable('reconcile_identity_changed')
                evidence = {'info': adapter.info(), 'logging': adapter.logging()}
                if op.action == 'clock':
                    evidence['clock'] = adapter.clock()
                self.finish(target, op, 'outcome-unknown', 'owner_reconciliation_required', evidence)
            except SELUnavailable:
                self.finish(target, op, 'outcome-unknown', 'reconciliation_unavailable')
            # Outcome-unknown deliberately retains ownership. No automatic replay.

        def tick(self, bmc_ip):
            try:
                target = self.target(bmc_ip)
                self.reconcile(target)
                health = self.observe(bmc_ip)
                fingerprint = json.loads(target.fingerprint) if target.fingerprint else None
                if not fingerprint or target.active_operation or target.consent_fingerprint != digest(fingerprint):
                    return
                if target.auto_clear and health.get('full') is True and not health['stale']:
                    self.execute(target, 'clear', 'automatic-policy', True)
                elif target.auto_clock and health.get('clock_incorrect') is True and not health['stale']:
                    self.execute(target, 'clock', 'automatic-policy', True)
            except SELUnavailable:
                db.session.rollback()
            except Exception:
                db.session.rollback()
                app.logger.warning('SEL health unavailable; no automatic action authorized')

        def cleanup_archives(self, cutoff):
            # Bound work like ordinary retention; immutable active receipts protected.
            protected = db.session.query(SELOperation.archive_id).filter(
                SELOperation.state.notin_(TERMINAL), SELOperation.archive_id.isnot(None))
            ids = [r.id for r in SELArchive.query.filter(SELArchive.archived_at < cutoff,
                SELArchive.id.notin_(protected)).limit(500).all()]
            if ids:
                SELArchive.query.filter(SELArchive.id.in_(ids)).delete(synchronize_session=False)
                db.session.commit()

        def migrate(self, engine=None):
            """Transactional SQLite replacement of the obsolete record-ID constraint."""
            engine = engine if engine is not None else db.engine
            inspector = inspect(engine)
            if 'ipmi_event' not in inspector.get_table_names():
                return
            old_columns = [c['name'] for c in inspector.get_columns('ipmi_event')]
            new_columns = [c.name for c in runtime.IPMIEvent.__table__.columns]
            needs_rebuild = 'record_digest' not in old_columns or any(
                set(c['column_names']) == {'bmc_ip', 'sel_id'} for c in inspector.get_unique_constraints('ipmi_event'))
            if needs_rebuild:
                if engine.dialect.name != 'sqlite' or set(old_columns) - set(new_columns):
                    raise RuntimeError('SEL migration requires reviewed SQLite legacy schema')
                with engine.connect() as connection:
                    connection.exec_driver_sql('BEGIN IMMEDIATE')
                    try:
                        count = connection.exec_driver_sql('SELECT count(*) FROM ipmi_event').scalar()
                        connection.exec_driver_sql('ALTER TABLE ipmi_event RENAME TO ipmi_event__sel_legacy')
                        connection.execute(CreateTable(runtime.IPMIEvent.__table__))
                        columns = ','.join('"' + c + '"' for c in old_columns)
                        connection.exec_driver_sql(f'INSERT INTO ipmi_event ({columns}) SELECT {columns} FROM ipmi_event__sel_legacy')
                        if connection.exec_driver_sql('SELECT count(*) FROM ipmi_event').scalar() != count:
                            raise RuntimeError('SEL migration row mismatch')
                        connection.exec_driver_sql('DROP TABLE ipmi_event__sel_legacy')
                        for index in runtime.IPMIEvent.__table__.indexes:
                            connection.execute(CreateIndex(index))
                        connection.commit()
                    except Exception:
                        connection.rollback()
                        raise
            for model in (SELTarget, SELOperation, SELArchive, SELAudit):
                model.__table__.create(bind=engine, checkfirst=True)
            with engine.begin() as connection:
                for table, column, datatype in [('sel_target', 'consent_qualification', 'TEXT'),
                                                 ('sel_operation', 'qualification_binding', 'VARCHAR(64)')]:
                    if column not in {entry['name'] for entry in inspect(connection).get_columns(table)}:
                        connection.exec_driver_sql(f'ALTER TABLE {table} ADD COLUMN {column} {datatype}')

    manager = Manager()
    runtime.sel_manager = manager

    def event_identity(row, sql_session=None):
        # One identity policy covers every ORM insertion path, including diagnostics.
        if row.record_digest:
            return
        store = sql_session if sql_session is not None else db.session
        server = store.query(runtime.Server).filter_by(bmc_ip=row.bmc_ip).first()
        target = store.query(SELTarget).filter_by(server_id=server.id).first() if server else None
        row.sel_target_id = target.id if target else 'legacy:' + row.bmc_ip
        row.sel_generation = target.generation if target else 0
        row.record_digest = digest([row.raw_entry or '', row.sensor_type, row.event_description,
                                   row.sel_id]) if row.raw_entry else uuid.uuid4().hex
        row.native_timestamp = row.native_timestamp or (row.event_date.isoformat() if row.event_date else None)
        row.time_quality = row.time_quality or ('native-unverified' if row.raw_entry else 'monitor')
        row.collected_at = row.collected_at or utcnow()

    @event.listens_for(Session, 'before_flush')
    def identify_insertions(sql_session, flush_context, instances):
        with sql_session.no_autoflush:
            for row in list(sql_session.new):
                if isinstance(row, runtime.IPMIEvent):
                    event_identity(row, sql_session)

    manager.event_identity = event_identity

    def reply(body, status=200):
        response = jsonify(body)
        response.status_code = status
        response.headers['Cache-Control'] = 'no-store'
        return response

    def live_admin():
        runtime.is_proxy_authenticated()
        if not session.get('logged_in') or session.get('user_role') != 'admin':
            return False
        if session.get('auth_via') == 'fleet_proxy':
            return runtime.is_proxy_authenticated()
        user = runtime.User.query.filter_by(username=session.get('username')).first()
        return bool(user and user.role == 'admin' and user.password_changed)

    def token():
        subject = [session.get('username'), session.get('auth_via', 'local')]
        if session.get('sel_subject') != subject or not session.get('sel_csrf'):
            session['sel_subject'] = subject
            session['sel_csrf'] = secrets.token_urlsafe(32)
        return session['sel_csrf']

    def guard():
        if not live_admin():
            return reply({'error': 'administrator_required'}, 403)
        expected = token()
        supplied = request.headers.get('X-CSRF-Token', '')
        original = request.environ.get('werkzeug.proxy_fix.orig', {})
        # Forwarded origin is authority only at the positively authenticated proxy.
        if runtime.is_proxy_authenticated():
            origin = request.host_url.rstrip('/')
        else:
            host = original.get('HTTP_HOST', request.host)
            scheme = original.get('wsgi.url_scheme', request.scheme)
            origin = scheme + '://' + host
        if (not supplied or not hmac.compare_digest(supplied, expected) or
                request.headers.get('Origin') != origin or request.headers.get('Sec-Fetch-Site') == 'cross-site'):
            return reply({'error': 'invalid_session_intent_or_origin'}, 403)
        if not request.is_json or request.content_length is None or request.content_length > 4096:
            return reply({'error': 'invalid_request'}, 400)
        return None

    def body():
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError()
                result[key] = value
            return result
        try:
            data = json.loads(request.get_data(), object_pairs_hook=unique)
            if not isinstance(data, dict):
                raise ValueError()
            return data
        except (ValueError, TypeError):
            raise SELUnavailable('invalid_request') from None

    def guarded(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            rejected = guard()
            if rejected:
                return rejected
            try:
                return function(*args, **kwargs)
            except SELUnavailable as exc:
                db.session.rollback()
                return reply({'error': exc.code, 'message': exc.code.replace('_', ' ')},
                    404 if exc.code == 'configured_active_target_required' else 409)
            except Exception:
                db.session.rollback()
                app.logger.warning('SEL action unavailable; retained evidence preserved')
                return reply({'error': 'sel_action_unavailable'}, 503)
        return wrapped

    @app.get('/api/server/<bmc_ip>/sel/health')
    @runtime.view_required
    def sel_health(bmc_ip):
        try:
            target = manager.target(bmc_ip)
            result = manager.representation(target)
            if live_admin():
                result['csrf_token'] = token()
            return reply(result)
        except SELUnavailable:
            return reply({'error': 'configured_active_target_required'}, 404)

    @app.post('/api/server/<bmc_ip>/sel/policy')
    @guarded
    def sel_policy(bmc_ip):
        data = body()
        target = manager.target(bmc_ip)
        target_id = target.id
        db.session.rollback()
        if db.engine.dialect.name != 'sqlite':
            raise SELUnavailable('serialized_dispatch_unavailable')
        db.session.execute(text('BEGIN IMMEDIATE'))
        db.session.expire_all()
        target = db.session.get(SELTarget, target_id)
        manager.valid_revision(target, data)
        allowed = {'target_id', 'identity_revision', 'policy_revision', 'automatic_clear', 'automatic_clock', 'near_full_percent', 'clock_drift_seconds'}
        if set(data) - allowed:
            raise SELUnavailable('invalid_policy_fields')
        for key in ('automatic_clear', 'automatic_clock'):
            if key in data and type(data[key]) is not bool:
                raise SELUnavailable('invalid_policy_boolean')
        for key, low, high in (('near_full_percent', 1, 100), ('clock_drift_seconds', 30, 86400)):
            if key in data and (type(data[key]) is not int or not low <= data[key] <= high):
                raise SELUnavailable('invalid_policy_threshold')
        fingerprint = json.loads(target.fingerprint) if target.fingerprint else None
        if (data.get('automatic_clear') or data.get('automatic_clock')) and not fingerprint:
            raise SELUnavailable('observed_identity_required')
        selections = {action: qualification_selection(fingerprint, action)[1] for action in ('clear', 'clock')}
        consent, armed, revoked = manager.consent_state(target, selections)
        for action in ('clear', 'clock'):
            if data.get('automatic_' + action) is True and not selections[action]:
                manager.revoke_locked(target, selections)
                raise SELUnavailable('exact_hardware_qualification_required')
            if 'automatic_' + action in data:
                armed[action] = data['automatic_' + action]
                consent[action] = selections[action] if armed[action] else None
        changes = {'auto_clear': armed['clear'],
            'auto_clock': armed['clock'],
            'near_full': data.get('near_full_percent', target.near_full),
            'drift_seconds': data.get('clock_drift_seconds', target.drift_seconds),
            'consent_fingerprint': digest(fingerprint) if fingerprint else None,
            'consent_qualification': json.dumps(consent, sort_keys=True),
            'policy_revision': target.policy_revision + 1}
        updated = db.session.query(SELTarget).filter(SELTarget.id == target.id,
            SELTarget.revision == data['identity_revision'],
            SELTarget.policy_revision == data['policy_revision']).update(changes, synchronize_session=False)
        if updated != 1:
            raise SELUnavailable('stale_target_or_policy_revision')
        manager.audit(target, 'policy_consent', {'automatic_clear': changes['auto_clear'],
            'automatic_clock': changes['auto_clock'], 'revision': changes['policy_revision']})
        db.session.commit()
        db.session.expire_all()
        return reply(manager.representation(target))

    @guarded
    def action_request(bmc_ip, action):
        data = body()
        if set(data) != {'target_id', 'identity_revision', 'policy_revision'}:
            raise SELUnavailable('invalid_action_fields')
        target = manager.target(bmc_ip)
        manager.valid_revision(target, data)
        expected_authority = manager.authority(target)
        operation = manager.execute(target, action, session['username'], expected_authority=expected_authority)
        return reply(manager.operation_view(operation), 200 if operation.state == 'complete' else 202)

    @app.post('/api/server/<bmc_ip>/sel/enable')
    def sel_enable(bmc_ip):
        return action_request(bmc_ip, 'enable')

    @app.post('/api/server/<bmc_ip>/sel/clock')
    def sel_clock(bmc_ip):
        return action_request(bmc_ip, 'clock')

    @guarded
    def clear_all_request():
        data = body()
        if set(data) != {'targets'} or not isinstance(data['targets'], list) or len(data['targets']) > 100:
            raise SELUnavailable('invalid_target_list')
        results = []
        authorities = {}
        for entry in data['targets']:
            if not isinstance(entry, dict):
                raise SELUnavailable('invalid_target_list')
            target = db.session.get(SELTarget, entry.get('target_id'))
            if not target:
                raise SELUnavailable('configured_active_target_required')
            manager.current_server(target.bmc_ip)
            manager.valid_revision(target, entry)
            authorities[entry['target_id']] = manager.authority(target)
        for entry in data['targets']:
            target = db.session.get(SELTarget, entry['target_id'])
            try:
                operation = manager.execute(target, 'clear', session['username'], expected_authority=authorities[entry['target_id']])
                results.append({'bmc_ip': target.bmc_ip, **manager.operation_view(operation)})
            except SELUnavailable as exc:
                db.session.rollback()
                results.append({'bmc_ip': target.bmc_ip, 'state': 'failed', 'outcome': exc.code})
        return reply({'operations': results})

    @app.get('/api/server/<bmc_ip>/sel/operations/<operation_id>')
    @runtime.view_required
    def sel_operation(bmc_ip, operation_id):
        try:
            target = manager.target(bmc_ip)
            operation = db.session.get(SELOperation, operation_id)
            if not operation or operation.target_id != target.id:
                return reply({'error': 'operation_not_found'}, 404)
            return reply(manager.operation_view(operation))
        except SELUnavailable:
            return reply({'error': 'configured_active_target_required'}, 404)

    @app.get('/api/server/<bmc_ip>/sel/archives/<archive_id>')
    @runtime.view_required
    def sel_archive(bmc_ip, archive_id):
        try:
            archive = db.session.get(SELArchive, archive_id)
            target = db.session.get(SELTarget, archive.target_id) if archive else None
            if not archive or not target or target.bmc_ip != bmc_ip:
                return reply({'error': 'archive_not_found'}, 404)
            return reply({'receipt': archive.id, 'sha256': archive.sha256,
                          'archived_at': stamp(archive.archived_at), 'snapshot': json.loads(archive.payload)})
        except SELUnavailable:
            return reply({'error': 'configured_active_target_required'}, 404)

    manager.action_request = action_request
    manager.clear_all_request = clear_all_request
    return manager
