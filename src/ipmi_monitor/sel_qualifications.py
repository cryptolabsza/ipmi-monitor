# TRACEWEAVER: file-role=qualification-data-custody; req=REQ-SEL-004; trace=TRACE-SEL-004; ver=VER-SEL-004
"""Fixed, offline qualification data custody. No application startup or BMC IO.

This module is installed with the official package and supports ``python -I -m``.
Registry acceptance is application evidence validation, never firmware proof.
"""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import stat
import subprocess
import sys
import time
import uuid

ENVELOPE_LIMIT = 64 * 1024 * 1024
DECODED_LIMIT = 32 * 1024 * 1024
REGISTRY_LIMIT = 1024 * 1024
EVIDENCE_LIMIT = 4 * 1024 * 1024
POINTER_LIMIT = 16384
SUPPORTED_RECORD_TRANSPORTS = frozenset({'lanplus-cipher17-admin', 'lanplus-cipher3-admin'})
CHECKS = {
    'clear': {'same_reservation', 'insertion_invalidates', 'competing_reservation', 'complete_raw_backup', 'completion_readback', 'new_events_survive'},
    'enable': {'unrelated_bits_preserved', 'enabled_readback'},
    'clock': {'positive_offset', 'negative_offset', 'offset_restored', 'interrupted_write', 'trusted_reference', 'ntp_ownership', 'clock_readback'},
}


class Refused(ValueError):
    """Only fixed error codes may cross the operator boundary."""


def sha(value):
    return hashlib.sha256(value).hexdigest()


def strict_json(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise Refused('duplicate_json_key')
            result[key] = item
        return result
    try:
        return json.loads(value, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refused('invalid_json')))
    except (ValueError, UnicodeError, RecursionError):
        raise Refused('invalid_json') from None


def fields(value, required, optional=()):
    if type(value) is not dict or set(value) - set(required) - set(optional) or set(required) - set(value):
        raise Refused('invalid_manifest_fields')


def hex_digest(value):
    if type(value) is not str or not re.fullmatch('[0-9a-f]{64}', value):
        raise Refused('invalid_digest')
    return value


def relative_path(value):
    if type(value) is not str or len(value.split('/')) > 8:
        raise Refused('unsafe_path')
    parts = value.split('/')
    if any(not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', part) or part in {'.', '..'} for part in parts):
        raise Refused('unsafe_path')
    return parts


def directory(path):
    """Open every ancestor without following symlinks; caller owns the fd."""
    path = os.path.abspath(os.fspath(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.split('/')[1:]:
            if not part:
                continue
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def custody(metadata, private=False, is_dir=False):
    expected_type = stat.S_ISDIR if is_dir else stat.S_ISREG
    if (not expected_type(metadata.st_mode) or
            metadata.st_uid not in ({0} if private else {0, os.geteuid()}) or
            (not is_dir and metadata.st_nlink != 1) or
            (stat.S_IMODE(metadata.st_mode) != (0o700 if is_dir else 0o600) if private else bool(metadata.st_mode & 0o022))):
        raise Refused('unsafe_file_custody')


def read_file(path, limit, private=False):
    path = Path(path)
    parent = directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            custody(os.fstat(fd), private)
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                value = stream.read(limit + 1)
            if len(value) > limit:
                raise Refused('file_size_limit')
            return value
        finally:
            os.close(fd)
    finally:
        os.close(parent)


_tool_cache = None


def tool_identity():
    """Read the installed tool boundary; no BMC commands or credentials."""
    global _tool_cache
    tool = '/usr/bin/ipmitool'
    value = read_file(tool, 32 * 1024 * 1024)
    tool_digest = sha(value)
    if not _tool_cache or _tool_cache[0] != tool_digest:
        try:
            process = subprocess.Popen([tool, '-V'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, close_fds=True)
            try:
                output, _ = process.communicate(timeout=3)
            except BaseException:
                process.kill()
                process.communicate()
                raise
            if process.returncode or len(output) > 256:
                raise Refused('tool_identity_unavailable')
            version = output.decode('ascii').strip()
            if not re.fullmatch(r'ipmitool version [0-9][A-Za-z0-9.+~-]{0,63}', version):
                raise Refused('tool_identity_unavailable')
            _tool_cache = (tool_digest, version)
        except (OSError, ValueError, subprocess.SubprocessError):
            raise Refused('tool_identity_unavailable') from None
    return {'tool_sha256': tool_digest, 'tool_version': _tool_cache[1]}


def runtime_identity():
    """Hash installed source/tool bytes; transport names the adapter default.

    Each record's fingerprint binds its actual supported transport separately.
    Unknown or changed runtime identity still grants nothing.
    """
    return {'adapter_version': 'sel-raw-v3-persistent', 'transport': 'lanplus-cipher17-admin',
            'adapter_sha256': sha(Path(__file__).with_name('sel_management.py').read_bytes()),
            'loader_sha256': sha(Path(__file__).read_bytes()), **tool_identity()}


def validate_registry_v1(value, files, identity):
    registry = strict_json(value)
    fields(registry, {'schema', 'records'})
    if registry['schema'] != 'sel-device-qualification/1' or type(registry['records']) is not list:
        raise Refused('invalid_registry')
    seen, referenced = set(), set()
    for record in registry['records']:
        fields(record, {'record_id', 'fingerprint', 'test_only', 'reviewer', 'approved_at', 'expires_at',
                        'firmware_identity_scope', 'actions', 'evidence_artifacts', 'runtime_identity'},
               {'clock_semantics', 'ntp_probe', 'supporting_evidence'})
        try:
            uuid.UUID(record['record_id'])
            approved = datetime.fromisoformat(record['approved_at'].replace('Z', '+00:00'))
            expires = datetime.fromisoformat(record['expires_at'].replace('Z', '+00:00'))
            if not approved <= datetime.now(timezone.utc) < expires:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise Refused('invalid_record_identity_or_expiry') from None
        if (record['record_id'] in seen or record['test_only'] is not False or
                type(record['reviewer']) is not str or not record['reviewer'].strip() or
                record['runtime_identity'] != identity or type(record['fingerprint']) is not dict or
                record['firmware_identity_scope'] != record['fingerprint'].get('firmware_identity_capability')):
            raise Refused('invalid_record_applicability')
        seen.add(record['record_id'])
        fields(record['fingerprint'], {'manufacturer', 'product', 'firmware', 'device_id_reply',
            'aux_firmware_present', 'aux_firmware', 'firmware_identity_capability', 'guid', 'log', 'adapter', 'transport'})
        fingerprint = record['fingerprint']
        if (type(fingerprint['aux_firmware_present']) is not bool or
                fingerprint['aux_firmware'] is not None and type(fingerprint['aux_firmware']) is not str or
                any(type(value) is not str for key, value in fingerprint.items()
                    if key not in {'aux_firmware_present', 'aux_firmware'})):
            raise Refused('invalid_fingerprint_types')
        if (record['fingerprint']['adapter'] != identity['adapter_version'] or
                record['fingerprint']['transport'] not in SUPPORTED_RECORD_TRANSPORTS or record['fingerprint']['log'] != 'ipmi:sel'):
            raise Refused('invalid_record_applicability')
        if 'ntp_probe' in record:
            fields(record['ntp_probe'], {'path', 'ca_file', 'ca_sha256'})
            if any(type(v) is not str or not v for v in record['ntp_probe'].values()):
                raise Refused('invalid_time_management_probe')
        artifacts = {}
        if type(record['evidence_artifacts']) is not list or not record['evidence_artifacts']:
            raise Refused('missing_evidence')
        for artifact in record['evidence_artifacts']:
            fields(artifact, {'path', 'sha256'}, {'kind'})
            path = artifact['path']
            relative_path(path)
            digest = hex_digest(artifact['sha256'])
            if path not in files or path in referenced or sha(files[path]) != digest:
                raise Refused('evidence_digest_mismatch')
            referenced.add(path)
            kind = artifact.get('kind', 'canary')
            if kind not in {'canary', 'ca_certificate', 'supporting_json'}:
                raise Refused('invalid_evidence_kind')
            if kind == 'ca_certificate':
                try:
                    pem = files[path].decode('ascii')
                    if not re.fullmatch(r'(?:-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*)+', pem):
                        raise ValueError()
                    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=pem)
                except (ValueError, UnicodeError, ssl.SSLError):
                    raise Refused('invalid_public_ca') from None
                artifacts[digest] = {'kind': kind, 'path': path}
                continue
            evidence = strict_json(files[path])
            if kind == 'supporting_json':
                fields(evidence, {'schema', 'record_id', 'fingerprint', 'action', 'purpose', 'evidence'})
                if (evidence['schema'] != 'sel-supporting-evidence/1' or evidence['record_id'] != record['record_id'] or
                        evidence['fingerprint'] != record['fingerprint'] or evidence['action'] != 'clock' or
                        evidence['purpose'] not in {'vendor', 'clock_ownership'} or
                        type(evidence['evidence']) is not dict or not evidence['evidence']):
                    raise Refused('invalid_supporting_evidence')
                artifacts[digest] = {'kind': kind, 'body': evidence, 'path': path}
                continue
            fields(evidence, {'record_id', 'fingerprint', 'action', 'checks', 'canary_operations'})
            if evidence['record_id'] != record['record_id'] or evidence['fingerprint'] != record['fingerprint']:
                raise Refused('evidence_identity_mismatch')
            artifacts[digest] = {'kind': kind, 'body': evidence, 'path': path}
        if type(record['actions']) is not dict or not record['actions'] or set(record['actions']) - CHECKS.keys():
            raise Refused('invalid_action')
        used = set()
        for action, admission in record['actions'].items():
            fields(admission, {'checks', 'canary_operation_ids', 'sha256'})
            if (type(admission['checks']) is not dict or set(admission['checks']) != CHECKS[action] or
                    not all(value is True for value in admission['checks'].values()) or
                    type(admission['sha256']) is not list or not admission['sha256'] or
                    type(admission['canary_operation_ids']) is not list or not admission['canary_operation_ids']):
                raise Refused('invalid_action_evidence')
            ids = set()
            for digest in admission['sha256']:
                hex_digest(digest)
                if digest not in artifacts or artifacts[digest]['kind'] != 'canary':
                    raise Refused('action_digest_not_admitted')
                evidence = artifacts[digest]['body']
                used.add(digest)
                if evidence['action'] != action or evidence['checks'] != admission['checks']:
                    raise Refused('action_evidence_mismatch')
                if type(evidence['canary_operations']) is not list or not evidence['canary_operations']:
                    raise Refused('missing_canary_operations')
                for operation in evidence['canary_operations']:
                    fields(operation, {'operation_id', 'action', 'observed_at', 'outcome', 'raw_receipts'})
                    try:
                        uuid.UUID(operation['operation_id'])
                        observed = datetime.fromisoformat(operation['observed_at'].replace('Z', '+00:00'))
                        if observed.tzinfo is None or operation['operation_id'] in ids:
                            raise ValueError()
                    except (ValueError, TypeError, AttributeError):
                        raise Refused('invalid_canary_operation') from None
                    if (operation['action'] != action or operation['outcome'] != 'complete' or
                            type(operation['raw_receipts']) is not list or not operation['raw_receipts']):
                        raise Refused('invalid_canary_operation')
                    for receipt in operation['raw_receipts']:
                        fields(receipt, {'command', 'response'})
                        if (type(receipt['command']) is not list or not 2 <= len(receipt['command']) <= 32 or
                                any(type(v) is not int or not 0 <= v <= 255 for v in receipt['command']) or
                                type(receipt['response']) is not str or not re.fullmatch('[0-9a-f]{2,1024}', receipt['response']) or
                                len(receipt['response']) % 2):
                            raise Refused('invalid_raw_receipt')
                    ids.add(operation['operation_id'])
            if len(set(admission['canary_operation_ids'])) != len(admission['canary_operation_ids']) or not set(admission['canary_operation_ids']) <= ids:
                raise Refused('action_operation_not_admitted')
        if 'clock' in record['actions']:
            if record.get('clock_semantics') not in {'local_epoch_with_utc_offset', 'utc_epoch'}:
                raise Refused('clock_mapping_unknown')
            supporting = record.get('supporting_evidence')
            fields(supporting, {'vendor', 'clock_ownership'})
            for purpose, digests in supporting.items():
                if type(digests) is not list or not digests or len(digests) != len(set(digests)):
                    raise Refused('invalid_supporting_evidence')
                for digest in digests:
                    hex_digest(digest)
                    if (digest not in artifacts or artifacts[digest]['kind'] != 'supporting_json' or
                            artifacts[digest]['body']['purpose'] != purpose):
                        raise Refused('supporting_evidence_not_admitted')
                    used.add(digest)
            probe = record.get('ntp_probe', {})
            relative_path(probe.get('ca_file'))
            ca_digest = hex_digest(probe.get('ca_sha256'))
            if (ca_digest not in artifacts or artifacts[ca_digest]['kind'] != 'ca_certificate' or
                    artifacts[ca_digest]['path'] != probe['ca_file']):
                raise Refused('ca_not_admitted')
            used.add(ca_digest)
        if used != artifacts.keys():
            raise Refused('unreferenced_evidence')
    if referenced != files.keys():
        raise Refused('unreferenced_files')
    return registry['records']


CLEAR_CLAIMS = {
    'reservation_required_for_erase': {'vendor_semantics', 'native_guard_observation'},
    'same_reservation_snapshot_and_clear': {'vendor_semantics', 'native_guard_observation', 'source_guard_verification'},
    'insertion_invalidates_or_equivalent_guard': {'vendor_semantics', 'native_guard_observation'},
    'competing_reservation_invalidates': {'vendor_semantics', 'native_guard_observation'},
    'complete_dual_archive_before_dispatch': {'source_guard_verification'},
    'bounded_completion_and_unknown_reconciliation': {'source_guard_verification'},
    'saved_history_preserved': {'source_guard_verification'},
}
CLOCK_CLAIMS = {
    'native_clock_semantics': {'vendor_semantics', 'native_guard_observation'},
    'external_timewriter_ownership': {'clock_ownership'},
    'trusted_bmc_management': {'native_guard_observation', 'ca_certificate'},
    'fresh_utc_offset_restoration': {'source_guard_verification'},
    'complete_dual_archive_before_dispatch': {'source_guard_verification'},
    'bounded_completion_and_unknown_reconciliation': {'source_guard_verification'},
    'saved_history_preserved': {'source_guard_verification'},
}
PROMOTION_CLAIMS = {'actual_clear_completion_readback', 'actual_final_dual_archive_verified',
                    'saved_history_preserved_after_action', 'subsequent_collection_verified'}
CLOCK_PROMOTION_CLAIMS = (PROMOTION_CLAIMS - {'actual_clear_completion_readback'}) | {'actual_clock_completion_readback'}


def valid_uuid(value):
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, AttributeError, TypeError):
        raise Refused('invalid_uuid') from None
    return value


def interval(approved, expires, admitted_at=None):
    try:
        start = datetime.fromisoformat(approved.replace('Z', '+00:00'))
        end = datetime.fromisoformat(expires.replace('Z', '+00:00'))
        if start.tzinfo is None or end.tzinfo is None or not start <= (admitted_at if admitted_at is not None else datetime.now(timezone.utc)) < end:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise Refused('invalid_record_identity_or_expiry') from None


# TRACEWEAVER: entrypoint=validate_registry; req=REQ-SEL-003,REQ-SEL-004,REQ-SEL-005; trace=TRACE-SEL-003,TRACE-SEL-004,TRACE-SEL-005; ver=VER-SEL-003,VER-SEL-004,VER-SEL-005
def validate_registry(value, files, identity, *, admitted_at=None):
    registry = strict_json(value)
    fields(registry, {'schema', 'records'})
    if registry.get('schema') == 'sel-device-qualification/1':
        return validate_registry_v1(value, files, identity)
    fields(registry, {'schema', 'records'})
    if registry['schema'] != 'sel-device-qualification/2' or type(registry['records']) is not list:
        raise Refused('invalid_registry')
    seen, scopes, referenced = set(), set(), set()
    for record in registry['records']:
        fields(record, {'record_id', 'fingerprint', 'test_only', 'reviewer', 'approved_at', 'expires_at',
            'firmware_identity_scope', 'actions', 'evidence_artifacts', 'runtime_identity'},
            {'clock_semantics', 'ntp_probe'})
        valid_uuid(record['record_id'])
        interval(record['approved_at'], record['expires_at'], admitted_at)
        fp = record['fingerprint']
        fields(fp, {'manufacturer', 'product', 'firmware', 'device_id_reply', 'aux_firmware_present',
            'aux_firmware', 'firmware_identity_capability', 'guid', 'log', 'adapter', 'transport'})
        if (record['record_id'] in seen or record['test_only'] is not False or
                type(record['reviewer']) is not str or not record['reviewer'].strip() or
                record['runtime_identity'] != identity or
                record['firmware_identity_scope'] != fp['firmware_identity_capability'] or
                type(fp['aux_firmware_present']) is not bool or
                (fp['aux_firmware'] is not None and type(fp['aux_firmware']) is not str) or
                any(type(v) is not str or not v for k, v in fp.items() if k not in {'aux_firmware_present', 'aux_firmware'}) or
                fp['adapter'] != identity['adapter_version'] or fp['transport'] not in SUPPORTED_RECORD_TRANSPORTS or
                fp['log'] != 'ipmi:sel'):
            raise Refused('invalid_record_applicability')
        seen.add(record['record_id'])
        if type(record['actions']) is not dict or not record['actions'] or set(record['actions']) - {'clear', 'clock'}:
            raise Refused('invalid_action')
        if type(record['evidence_artifacts']) is not list or not record['evidence_artifacts']:
            raise Refused('missing_evidence')
        artifacts = {}
        common = {'schema', 'record_id', 'fingerprint', 'runtime_identity', 'action', 'kind', 'provenance'}
        extra = {
            'owner_scope': {'target_id', 'commission_id', 'max_attempts', 'approved_at', 'expires_at', 'owner_instruction'},
            'vendor_semantics': {'evidence'},
            'native_guard_observation': {'observed_at', 'probe_id', 'raw_receipts', 'evidence'},
            'source_guard_verification': {'evidence'},
            'clock_ownership': {'evidence'},
            'commissioning_result': {'target_id', 'commission_id', 'operation_id', 'evidence'},
        }
        for artifact in record['evidence_artifacts']:
            fields(artifact, {'path', 'sha256', 'kind'})
            path, digest, kind = artifact['path'], hex_digest(artifact['sha256']), artifact['kind']
            relative_path(path)
            if path not in files or path in referenced or sha(files[path]) != digest or digest in artifacts:
                raise Refused('evidence_digest_mismatch')
            referenced.add(path)
            if kind == 'ca_certificate':
                try:
                    pem = files[path].decode('ascii')
                    if not re.fullmatch(r'(?:-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*)+', pem):
                        raise ValueError()
                    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=pem)
                except (ValueError, UnicodeError, ssl.SSLError):
                    raise Refused('invalid_public_ca') from None
                artifacts[digest] = {'kind': kind, 'path': path}
                continue
            if kind not in extra:
                raise Refused('invalid_evidence_kind')
            body = strict_json(files[path])
            fields(body, common | extra[kind])
            if (body['schema'] != 'sel-typed-evidence/2' or body['record_id'] != record['record_id'] or
                    body['fingerprint'] != fp or body['runtime_identity'] != identity or
                    body['action'] not in record['actions'] or body['kind'] != kind or
                    type(body['provenance']) is not str or not body['provenance'].strip()):
                raise Refused('evidence_identity_mismatch')
            if kind == 'owner_scope':
                valid_uuid(body['target_id']); valid_uuid(body['commission_id'])
                interval(body['approved_at'], body['expires_at'], admitted_at)
                if type(body['max_attempts']) is not int or body['max_attempts'] != 1 or type(body['owner_instruction']) is not str or not body['owner_instruction'].strip():
                    raise Refused('invalid_owner_scope')
            else:
                if type(body['evidence']) is not dict or not body['evidence']:
                    raise Refused('invalid_typed_evidence')
                if kind == 'vendor_semantics':
                    fields(body['evidence'], {'source_sha256', 'section', 'applicability'})
                    hex_digest(body['evidence']['source_sha256'])
                    if type(body['evidence']['section']) is not str or not body['evidence']['section'].strip() or body['evidence']['applicability'] != fp:
                        raise Refused('invalid_vendor_applicability')
                if kind == 'source_guard_verification':
                    fields(body['evidence'], {'environment', 'tests', 'log_sha256'})
                    hex_digest(body['evidence']['log_sha256'])
                    if (type(body['evidence']['environment']) is not str or not body['evidence']['environment'] or
                            type(body['evidence']['tests']) is not list or not body['evidence']['tests'] or
                            any(type(v) is not str or not v for v in body['evidence']['tests'])):
                        raise Refused('invalid_source_verification')
                if kind == 'native_guard_observation':
                    valid_uuid(body['probe_id'])
                    try:
                        observed = datetime.fromisoformat(body['observed_at'].replace('Z', '+00:00'))
                        if observed.tzinfo is None or observed > datetime.now(timezone.utc):
                            raise ValueError()
                    except (ValueError, TypeError, AttributeError):
                        raise Refused('invalid_native_observation') from None
                    if type(body['raw_receipts']) is not list or not body['raw_receipts']:
                        raise Refused('invalid_raw_receipt')
                    for receipt in body['raw_receipts']:
                        fields(receipt, {'command', 'response'})
                        if (type(receipt['command']) is not list or not 2 <= len(receipt['command']) <= 32 or
                                any(type(v) is not int or not 0 <= v <= 255 for v in receipt['command']) or
                                type(receipt['response']) is not str or not re.fullmatch('[0-9a-f]{2,1024}', receipt['response']) or len(receipt['response']) % 2):
                            raise Refused('invalid_raw_receipt')
                if kind == 'commissioning_result':
                    valid_uuid(body['target_id']); valid_uuid(body['commission_id']); valid_uuid(body['operation_id'])
            artifacts[digest] = {'kind': kind, 'path': path, 'body': body}
        used = set()
        for action, admission in record['actions'].items():
            scope = (json.dumps(fp, sort_keys=True), action)
            if scope in scopes:
                raise Refused('ambiguous_action_qualification')
            scopes.add(scope)
            fields(admission, {'phase', 'commission_id', 'owner_scope_sha256', 'claims'}, {'parent_commission'})
            valid_uuid(admission['commission_id'])
            if admission['phase'] not in {'manual_commissioning', 'automatic_qualified'}:
                raise Refused('invalid_action_phase')
            owner = hex_digest(admission['owner_scope_sha256'])
            if (owner not in artifacts or artifacts[owner]['kind'] != 'owner_scope' or
                    artifacts[owner]['body']['action'] != action or
                    artifacts[owner]['body']['commission_id'] != admission['commission_id']):
                raise Refused('owner_scope_not_admitted')
            used.add(owner)
            required = dict(CLEAR_CLAIMS if action == 'clear' else CLOCK_CLAIMS)
            if admission['phase'] == 'automatic_qualified':
                required.update({name: {'commissioning_result'} for name in (PROMOTION_CLAIMS if action == 'clear' else CLOCK_PROMOTION_CLAIMS)})
                parent = admission.get('parent_commission')
                fields(parent, {'envelope_sha256', 'pointer_sha256', 'commission_id', 'operation_id', 'result_sha256'})
                valid_uuid(parent['commission_id']); valid_uuid(parent['operation_id'])
                for name in ('envelope_sha256', 'pointer_sha256', 'result_sha256'):
                    hex_digest(parent[name])
                if parent['commission_id'] != admission['commission_id']:
                    raise Refused('promotion_commission_mismatch')
            elif 'parent_commission' in admission:
                raise Refused('unexpected_promotion_parent')
            fields(admission['claims'], required)
            for claim, digests in admission['claims'].items():
                if type(digests) is not list or not digests or len(digests) != len(set(digests)):
                    raise Refused('invalid_claim_evidence')
                kinds = set()
                for digest in digests:
                    hex_digest(digest)
                    artifact = artifacts.get(digest)
                    if not artifact or artifact['kind'] not in required[claim] or artifact.get('body', {}).get('action', action) != action:
                        raise Refused('misclassified_claim_evidence')
                    used.add(digest); kinds.add(artifact['kind'])
                if kinds != required[claim]:
                    raise Refused('missing_claim_evidence_kind')
            if action == 'clock':
                if record.get('clock_semantics') not in {'local_epoch_with_utc_offset', 'utc_epoch'}:
                    raise Refused('clock_mapping_unknown')
                probe = record.get('ntp_probe')
                fields(probe, {'path', 'ca_file', 'ca_sha256'})
                if (any(type(v) is not str or not v for v in probe.values()) or
                        not re.fullmatch(r'/redfish/v1/Managers/[A-Za-z0-9_.-]+/NetworkProtocol', probe['path'])):
                    raise Refused('invalid_time_management_probe')
                relative_path(probe['ca_file']); ca = hex_digest(probe['ca_sha256'])
                if ca not in artifacts or artifacts[ca]['kind'] != 'ca_certificate' or artifacts[ca]['path'] != probe['ca_file']:
                    raise Refused('ca_not_admitted')
                used.add(ca)
        if used != artifacts.keys():
            raise Refused('unreferenced_evidence')
        record['_owner_scopes'] = {digest: artifact['body'] for digest, artifact in artifacts.items() if artifact['kind'] == 'owner_scope'}
        record['_results'] = {digest: artifact['body'] for digest, artifact in artifacts.items() if artifact['kind'] == 'commissioning_result'}
    if referenced != files.keys():
        raise Refused('unreferenced_files')
    return registry['records']


# TRACEWEAVER: entrypoint=verify_promotions; req=REQ-SEL-003,REQ-SEL-004,REQ-SEL-005; trace=TRACE-SEL-003,TRACE-SEL-004,TRACE-SEL-005; ver=VER-SEL-003,VER-SEL-004,VER-SEL-005
def verify_promotions(records, current_pointer_sha256=None, connection=None):
    """Admission requires durable local facts, never a result JSON assertion alone."""
    promotions = [(record, action, admission) for record in records
                  for action, admission in record['actions'].items()
                  if admission.get('phase') == 'automatic_qualified']
    if not promotions:
        return []
    proofs = []
    data = Path(os.environ.get('DATA_DIR', ''))
    if not data.is_absolute():
        raise Refused('explicit_data_directory_required')
    own = connection is None
    if own:
        # No app import, migration or creation. Read the existing local ledger only.
        parent_fd = directory(data)
        try:
            database_fd = os.open('ipmi_events.db', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
            try:
                custody(os.fstat(database_fd))
            finally:
                os.close(database_fd)
        finally:
            os.close(parent_fd)
        connection = sqlite3.connect((data / 'ipmi_events.db').as_uri() + '?mode=ro', uri=True, timeout=3)
    previous_factory = connection.row_factory
    connection.row_factory = sqlite3.Row
    try:
        for record, action, admission in promotions:
            parent = admission['parent_commission']
            if current_pointer_sha256 is not None and parent['pointer_sha256'] != current_pointer_sha256:
                raise Refused('promotion_parent_not_current')
            operation = connection.execute('SELECT * FROM sel_operation WHERE id=?', (parent['operation_id'],)).fetchone()
            if not operation:
                raise Refused('promotion_local_operation_mismatch')
            claimed_at = datetime.fromisoformat(operation['created_at'])
            if claimed_at.tzinfo is None:
                claimed_at = claimed_at.replace(tzinfo=timezone.utc)
            base = data / 'sel-qualifications'
            pointer_bytes = read_file(base / 'pointers' / (parent['pointer_sha256'] + '.json'), POINTER_LIMIT, private=True)
            pointer = strict_json(pointer_bytes)
            if sha(pointer_bytes) != parent['pointer_sha256'] or pointer.get('envelope_sha256') != parent['envelope_sha256']:
                raise Refused('promotion_parent_mismatch')
            envelope, _files, old_records = read_bundle(base / 'bundles' / parent['envelope_sha256'], parent['envelope_sha256'], record['runtime_identity'], admitted_at=claimed_at)
            # Runtime selection hashes the exact parent's resolved CA path.
            # Structural acceptance hashes remain based on raw bundle records.
            resolve_trust(old_records, base / 'bundles' / parent['envelope_sha256'])
            old = [r for r in old_records if r['fingerprint'] == record['fingerprint'] and action in r['actions']]
            if len(old) != 1 or old[0]['actions'][action].get('phase') != 'manual_commissioning' or old[0]['actions'][action]['commission_id'] != admission['commission_id']:
                raise Refused('promotion_parent_mismatch')
            result = record['_results'].get(parent['result_sha256'])
            if (not result or result['operation_id'] != parent['operation_id'] or result['commission_id'] != admission['commission_id'] or
                    result['action'] != action):
                raise Refused('promotion_result_not_admitted')
            for name in (PROMOTION_CLAIMS if action == 'clear' else CLOCK_PROMOTION_CLAIMS):
                if admission['claims'][name] != [parent['result_sha256']]:
                    raise Refused('promotion_result_not_admitted')
            evidence = result['evidence']
            fields(evidence, {'original_qualification_binding', 'archive_id', 'archive_sha256',
                'dispatch_audit_id', 'completion_audit_id', 'collection_audit_id', 'collection_receipt_digest'})
            for name in ('original_qualification_binding', 'archive_sha256', 'collection_receipt_digest'):
                hex_digest(evidence[name])
            valid_uuid(evidence['archive_id'])
            if any(type(evidence[k]) is not int or evidence[k] <= 0 for k in ('dispatch_audit_id', 'completion_audit_id', 'collection_audit_id')):
                raise Refused('invalid_promotion_audit')
            target = connection.execute('SELECT * FROM sel_target WHERE id=?', (result['target_id'],)).fetchone()
            source = sha(json.dumps({'mode': 'operator', 'registry_sha256': envelope['registry_sha256'],
                'envelope_sha256': parent['envelope_sha256']}, sort_keys=True).encode())
            original_binding = sha(json.dumps({'source': source,
                'record': sha(json.dumps(old[0], sort_keys=True, separators=(',', ':')).encode()),
                'action': sha(json.dumps(old[0]['actions'][action], sort_keys=True, separators=(',', ':')).encode())},
                sort_keys=True, separators=(',', ':')).encode())
            if (not operation or not target or operation['target_id'] != target['id'] or
                    operation['commission_id'] != admission['commission_id'] or operation['automatic'] != 0 or
                    operation['action'] != action or operation['state'] != 'complete' or
                    operation['outcome'] != ('clear_verified' if action == 'clear' else 'clock_verified') or
                    operation['qualification_binding'] != original_binding or original_binding != evidence['original_qualification_binding'] or
                    strict_json(target['fingerprint']) != record['fingerprint'] or
                    operation['identity_revision'] != target['revision'] or
                    operation['archive_id'] != evidence['archive_id']):
                raise Refused('promotion_local_operation_mismatch')
            consumed = connection.execute("SELECT * FROM sel_audit WHERE operation_id=? AND action='commission_consumed'", (operation['id'],)).fetchall()
            if len(consumed) != 1 or consumed[0]['target_id'] != target['id']:
                raise Refused('promotion_consumed_claim_missing')
            consumed_body = strict_json(consumed[0]['evidence'])
            if (consumed_body.get('commission_id') != admission['commission_id'] or
                    consumed_body.get('qualification_binding') != original_binding or consumed_body.get('action') != action):
                raise Refused('promotion_consumed_claim_mismatch')
            op_evidence = strict_json(operation['evidence'])
            archive = connection.execute('SELECT * FROM sel_archive WHERE id=?', (evidence['archive_id'],)).fetchone()
            if not archive:
                raise Refused('promotion_archive_missing')
            payload = archive['payload'].encode()
            archive_file = data / 'sel-archives' / (archive['id'] + '.json')
            metadata = os.stat(archive_file, follow_symlinks=False)
            if (stat.S_IMODE(metadata.st_mode) != 0o600 or archive['sha256'] != sha(payload) or
                    archive['sha256'] != evidence['archive_sha256'] or
                    op_evidence.get('archive_sha256') != archive['sha256'] or
                    read_file(archive_file, EVIDENCE_LIMIT) != payload or
                    archive['operation_id'] != operation['id'] or archive['target_id'] != target['id']):
                raise Refused('promotion_archive_mismatch')
            snapshot = strict_json(payload)
            if (snapshot.get('operation_id') != operation['id'] or snapshot.get('target_id') != target['id'] or
                    snapshot.get('fingerprint') != record['fingerprint'] or
                    snapshot.get('qualification_binding') != original_binding or
                    snapshot.get('generation') != archive['generation'] or snapshot.get('snapshot_epoch') != operation['epoch'] or
                    snapshot.get('reservation') != op_evidence.get('archive_reservation') or snapshot.get('complete') is not True or
                    snapshot.get('info', {}).get('entries') != len(snapshot.get('records', []))):
                raise Refused('promotion_archive_mismatch')
            audits = {}
            for name, audit_id in [('dispatch', evidence['dispatch_audit_id']), ('complete', evidence['completion_audit_id']), ('collection', evidence['collection_audit_id'])]:
                audit = connection.execute('SELECT * FROM sel_audit WHERE id=?', (audit_id,)).fetchone()
                if not audit or audit['target_id'] != target['id']:
                    raise Refused('promotion_audit_mismatch')
                audits[name] = (audit, strict_json(audit['evidence']))
            dispatch, dispatch_body = audits['dispatch']
            complete, complete_body = audits['complete']
            collection, collected = audits['collection']
            if (dispatch['operation_id'] != operation['id'] or dispatch['action'] != ('dispatch_intent' if action == 'clear' else 'clock_dispatch_intent') or
                    dispatch_body.get('dual_archive', {}).get('sha256') != archive['sha256'] or
                    dispatch_body.get('dual_archive', {}).get('receipt') != archive['id'] or
                    complete['operation_id'] != operation['id'] or complete['action'] != 'operation_complete' or
                    complete_body.get('outcome') != operation['outcome'] or
                    collection['operation_id'] is not None or collection['action'] != 'collection_persisted' or
                    collected.get('fingerprint') != record['fingerprint'] or
                    collected.get('receipt_digest') != evidence['collection_receipt_digest'] or
                    collected.get('expected') != collected.get('persisted') or
                    type(collected.get('persisted')) is not int or collected['persisted'] < 0 or
                    type(collected.get('generation')) is not int or
                    collected['generation'] < archive['generation'] + (1 if action == 'clear' else 0) or
                    datetime.fromisoformat(collection['created_at']) < datetime.fromisoformat(operation['updated_at'])):
                raise Refused('promotion_audit_mismatch')
            receipts = op_evidence.get('raw_receipts', [])
            mutation = [r for r in receipts if r.get('command', [])[:2] == [10, 0x47 if action == 'clear' else 0x49]]
            if (not mutation or (action == 'clear' and not any(r.get('response') == '01' for r in mutation)) or
                    type(op_evidence.get('saved_history_count_before')) is not int or
                    op_evidence.get('saved_history_count_after') != op_evidence['saved_history_count_before'] or
                    (action == 'clear' and not isinstance(op_evidence.get('after'), dict)) or
                    (action == 'clock' and not isinstance(op_evidence.get('after'), dict))):
                raise Refused('promotion_completion_missing')
            proofs.append({'record_id': record['record_id'], 'action': action,
                'target_id': target['id'], 'identity_revision': target['revision'],
                'operation_id': operation['id'], 'operation_sha256': canonical_sha(dict(operation)),
                'original_qualification_binding': original_binding,
                'audits': [{'id': row['id'], 'sha256': canonical_sha(dict(row))}
                           for row in [consumed[0], dispatch, complete, collection]],
                'archive_proof': {'id': archive['id'], 'sha256': archive['sha256'],
                    'target_id': target['id'], 'operation_id': operation['id'],
                    'generation': archive['generation'], 'epoch': operation['epoch'],
                    'reservation': snapshot['reservation'], 'dual_payload_sha256': sha(payload)}})
        return proofs
    except Refused:
        raise
    except (sqlite3.Error, KeyError, TypeError, ValueError, OSError):
        raise Refused('promotion_local_evidence_unavailable') from None
    finally:
        connection.row_factory = previous_factory
        if own:
            connection.close()


def canonical_sha(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def promotion_binding(record, action, pointer_sha256, envelope_sha256, registry_sha256):
    admission = record['actions'][action]
    return {'candidate_pointer_sha256': pointer_sha256, 'candidate_envelope_sha256': envelope_sha256,
        'candidate_registry_sha256': registry_sha256, 'record_id': record['record_id'],
        'record_sha256': canonical_sha({k: v for k, v in record.items() if not k.startswith('_')}),
        'action': action, 'admission_sha256': canonical_sha(admission),
        'fingerprint_sha256': canonical_sha(record['fingerprint']), 'runtime_identity': record['runtime_identity'],
        'commission_id': admission['commission_id'], 'parent_commission': admission['parent_commission']}


# TRACEWEAVER: entrypoint=accepted_promotion; req=REQ-SEL-003,REQ-SEL-004,REQ-SEL-005; trace=TRACE-SEL-003,TRACE-SEL-004,TRACE-SEL-005; ver=VER-SEL-003,VER-SEL-004,VER-SEL-005
def accepted_promotion(record, action, pointer_sha256, envelope_sha256, registry_sha256, connection=None):
    """Trusted pointer-bound acceptance plus immutable local facts, not raw TTL data."""
    binding = promotion_binding(record, action, pointer_sha256, envelope_sha256, registry_sha256)
    data = data_directory()
    receipt = strict_json(read_file(data / 'sel-qualifications' / 'transitions' /
        ('accept-' + canonical_sha(binding) + '.json'), EVIDENCE_LIMIT, private=True))
    fields(receipt, {'schema', 'accepted_at', 'binding', 'proof', 'sha256'})
    if receipt['sha256'] != canonical_sha({k: v for k, v in receipt.items() if k != 'sha256'}):
        raise Refused('promotion_acceptance_corrupt')
    if receipt['schema'] != 'sel-promotion-acceptance/1' or receipt['binding'] != binding:
        raise Refused('promotion_acceptance_mismatch')
    proof = receipt['proof']
    fields(proof, {'record_id', 'action', 'target_id', 'identity_revision', 'operation_id',
        'operation_sha256', 'original_qualification_binding', 'audits', 'archive_proof'})
    own = connection is None
    if own:
        parent_fd = directory(data)
        try:
            fd = os.open('ipmi_events.db', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
            try:
                custody(os.fstat(fd))
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)
        connection = sqlite3.connect((data / 'ipmi_events.db').as_uri() + '?mode=ro', uri=True, timeout=3)
    previous_factory = connection.row_factory
    connection.row_factory = sqlite3.Row
    try:
        op = connection.execute('SELECT * FROM sel_operation WHERE id=?', (proof['operation_id'],)).fetchone()
        target = connection.execute('SELECT * FROM sel_target WHERE id=?', (proof['target_id'],)).fetchone()
        if (proof['record_id'] != record['record_id'] or proof['action'] != action or
                proof['operation_id'] != binding['parent_commission']['operation_id'] or
                not op or canonical_sha(dict(op)) != proof['operation_sha256'] or
                op['state'] != 'complete' or op['automatic'] != 0 or op['action'] != action or
                op['outcome'] != ('clear_verified' if action == 'clear' else 'clock_verified') or
                op['commission_id'] != admission_commission(record, action) or
                op['qualification_binding'] != proof['original_qualification_binding'] or
                op['target_id'] != proof['target_id'] or not target or
                target['revision'] != proof['identity_revision'] or strict_json(target['fingerprint']) != record['fingerprint']):
            raise Refused('promotion_accepted_facts_changed')
        if type(proof['audits']) is not list or len(proof['audits']) != 4:
            raise Refused('promotion_accepted_facts_changed')
        for fact in proof['audits']:
            fields(fact, {'id', 'sha256'})
            row = connection.execute('SELECT * FROM sel_audit WHERE id=?', (fact['id'],)).fetchone()
            if not row or row['target_id'] != proof['target_id'] or canonical_sha(dict(row)) != fact['sha256']:
                raise Refused('promotion_accepted_facts_changed')
        return proof
    finally:
        connection.row_factory = previous_factory
        if own:
            connection.close()


def admission_commission(record, action):
    return record['actions'][action]['commission_id']


def environment_state():
    path, expected = os.environ.get('SEL_QUALIFICATIONS_FILE'), os.environ.get('SEL_QUALIFICATIONS_SHA256')
    if not path or not expected:
        raise Refused('invalid_environment_configuration')
    hex_digest(expected)
    value = read_file(path, REGISTRY_LIMIT)
    if sha(value) != expected:
        raise Refused('registry_digest_mismatch')
    registry = strict_json(value)
    files = {}
    total = len(value)
    for record in registry.get('records', []):
        for artifact in record.get('evidence_artifacts', []):
            relative_path(artifact['path'])
            if artifact['path'] in files:
                raise Refused('duplicate_evidence_path')
            if len(files) >= 63:
                raise Refused('file_count_limit')
            content = read_file(Path(path).parent / artifact['path'], min(EVIDENCE_LIMIT, DECODED_LIMIT - total))
            total += len(content)
            files[artifact['path']] = content
    records = validate_registry(value, files, runtime_identity())
    if any(a.get('phase') == 'automatic_qualified' for r in records for a in r['actions'].values()):
        raise Refused('managed_automatic_qualification_required')
    resolve_trust(records, Path(path).parent)
    return {'mode': 'environment', 'registry_sha256': expected, 'envelope_sha256': None, 'records': records}


def resolve_trust(records, root):
    for record in records:
        if 'clock' in record['actions']:
            record['ntp_probe']['ca_file'] = os.path.abspath(root / record['ntp_probe']['ca_file'])


def qualification_state():
    mode = 'environment' if any(key in os.environ for key in ('SEL_QUALIFICATIONS_FILE', 'SEL_QUALIFICATIONS_SHA256')) else 'operator'
    try:
        state = environment_state() if mode == 'environment' else operator_state()
        state['binding'] = sha(json.dumps({key: state[key] for key in ('mode', 'registry_sha256', 'envelope_sha256')}, sort_keys=True).encode())
        return state
    except (OSError, ValueError, KeyError, TypeError, AttributeError, sqlite3.Error):
        return {'mode': mode, 'registry_sha256': None, 'envelope_sha256': None, 'records': [], 'binding': None}


def operator_state(*, admitted_at=None):
    base = data_directory() / 'sel-qualifications'
    for path in (base, base / 'bundles'):
        fd = private_directory(path)
        os.close(fd)
    pointer = strict_json(read_file(base / 'active.json', POINTER_LIMIT, private=True))
    fields(pointer, {'schema', 'envelope_sha256', 'registry_sha256', 'identity', 'previous_pointer_sha256'})
    if pointer['schema'] != 'sel-qualification-pointer/1':
        raise Refused('invalid_pointer')
    digest = hex_digest(pointer['envelope_sha256'])
    hex_digest(pointer['registry_sha256'])
    if pointer['previous_pointer_sha256'] is not None:
        hex_digest(pointer['previous_pointer_sha256'])
    identity = runtime_identity()
    if pointer['identity'] != identity:
        raise Refused('runtime_identity_mismatch')
    envelope, files, records = read_bundle(base / 'bundles' / digest, digest, identity, admitted_at=admitted_at)
    if envelope['registry_sha256'] != pointer['registry_sha256']:
        raise Refused('registry_digest_mismatch')
    for record in records:
        for action, admission in record['actions'].items():
            if admission.get('phase') == 'automatic_qualified':
                accepted_promotion(record, action, sha(read_file(base / 'active.json', POINTER_LIMIT, private=True)), digest, envelope['registry_sha256'])
    resolve_trust(records, base / 'bundles' / digest)
    return {'mode': 'operator', 'envelope_sha256': digest,
            'registry_sha256': envelope['registry_sha256'], 'records': records}


def data_directory():
    value = os.environ.get('DATA_DIR')
    if not value or not os.path.isabs(value):
        raise Refused('explicit_data_directory_required')
    path = Path(value)
    fd = directory(path)
    try:
        metadata = os.fstat(fd)
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise Refused('unsafe_storage')
    finally:
        os.close(fd)
    return path


def private_directory(path):
    fd = directory(path)
    try:
        custody(os.fstat(fd), private=True, is_dir=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def child_directory(parent, name):
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
        os.fsync(parent)
    except FileExistsError:
        pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        custody(os.fstat(fd), private=True, is_dir=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def write_exclusive(root, name, value):
    parts = relative_path(name)
    fd = os.dup(root)
    try:
        for component in parts[:-1]:
            child = child_directory(fd, component)
            os.close(fd)
            fd = child
        target = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            custody(os.fstat(target), private=True)
            view = memoryview(value)
            while view:
                written = os.write(target, view)
                if written <= 0:
                    raise Refused('durable_write_failed')
                view = view[written:]
            os.fsync(target)
        finally:
            os.close(target)
        os.fsync(fd)
    finally:
        os.close(fd)


def validate_envelope(value, expected, identity, *, admitted_at=None):
    hex_digest(expected)
    if len(value) > ENVELOPE_LIMIT:
        raise Refused('envelope_size_limit')
    if sha(value) != expected:
        raise Refused('envelope_digest_mismatch')
    envelope = strict_json(value)
    fields(envelope, {'schema', 'identity', 'registry_sha256', 'files'})
    if envelope['schema'] != 'sel-qualification-envelope/1' or envelope['identity'] != identity:
        raise Refused('runtime_identity_mismatch')
    hex_digest(envelope['registry_sha256'])
    if type(envelope['files']) is not dict or not 1 <= len(envelope['files']) <= 64:
        raise Refused('file_count_limit')
    files, total = {}, 0
    for name, encoded in envelope['files'].items():
        relative_path(name)
        if name == 'envelope.json' or type(encoded) is not str:
            raise Refused('invalid_file_value')
        limit = REGISTRY_LIMIT if name == 'registry.json' else EVIDENCE_LIMIT
        if len(encoded) > 4 * ((limit + 2) // 3):
            raise Refused('file_size_limit')
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, UnicodeError):
            raise Refused('invalid_file_encoding') from None
        total += len(decoded)
        if len(decoded) > limit or total > DECODED_LIMIT:
            raise Refused('file_size_limit')
        files[name] = decoded
    if 'registry.json' not in files or sha(files['registry.json']) != envelope['registry_sha256']:
        raise Refused('registry_digest_mismatch')
    evidence = {name: value for name, value in files.items() if name != 'registry.json'}
    records = validate_registry(files['registry.json'], evidence, identity, admitted_at=admitted_at)
    return envelope, files, records


def read_bundle(path, expected, identity, *, admitted_at=None):
    root = private_directory(path)
    os.close(root)
    value = read_file(path / 'envelope.json', ENVELOPE_LIMIT, private=True)
    envelope, files, records = validate_envelope(value, expected, identity, admitted_at=admitted_at)
    actual = set()
    for parent, dirs, names in os.walk(path, followlinks=False):
        fd = private_directory(parent)
        os.close(fd)
        if len(Path(parent).relative_to(path).parts) > 8 or len(actual) > 65:
            raise Refused('unsafe_storage')
        for child in dirs:
            fd = private_directory(Path(parent) / child)
            os.close(fd)
        for name in names:
            actual.add(str((Path(parent) / name).relative_to(path)))
    if actual != set(files) | {'envelope.json'}:
        raise Refused('unreferenced_files')
    for name, expected_value in files.items():
        limit = REGISTRY_LIMIT if name == 'registry.json' else EVIDENCE_LIMIT
        if read_file(path / name, limit, private=True) != expected_value:
            raise Refused('stored_file_mismatch')
    return envelope, files, records


def install_bundle(value, expected, expected_active_pointer=None):
    if os.geteuid() != 0:
        raise Refused('root_operator_required')
    if any(key in os.environ for key in ('SEL_QUALIFICATIONS_FILE', 'SEL_QUALIFICATIONS_SHA256')):
        raise Refused('environment_mode_selected')
    if expected_active_pointer is not None:
        hex_digest(expected_active_pointer)
    identity = runtime_identity()
    envelope, files, records = validate_envelope(value, expected, identity)
    data = data_directory()
    data_fd = directory(data)
    base_fd = bundles_fd = stage_fd = None
    published = False
    try:
        base_fd = child_directory(data_fd, 'sel-qualifications')
        bundles_fd = child_directory(base_fd, 'bundles')
        stage_name = 'staging-' + uuid.uuid4().hex
        os.mkdir(stage_name, 0o700, dir_fd=base_fd)
        stage_fd = os.open(stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=base_fd)
        for name, content in {'envelope.json': value, **files}.items():
            write_exclusive(stage_fd, name, content)
        os.fsync(stage_fd)
        base = data / 'sel-qualifications'
        read_bundle(base / stage_name, expected, identity)
        # A digest directory is created exclusively, never renamed over an
        # existing directory. Partial crash remnants are refused, not repaired.
        try:
            os.mkdir(expected, 0o700, dir_fd=bundles_fd)
            destination = os.open(expected, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=bundles_fd)
            try:
                for name, content in {'envelope.json': value, **files}.items():
                    write_exclusive(destination, name, content)
                os.fsync(destination)
            finally:
                os.close(destination)
            os.fsync(bundles_fd)
        except FileExistsError:
            pass
        read_bundle(base / 'bundles' / expected, expected, identity)
        # Existing DB only: no application import, migration or database create.
        database = data / 'ipmi_events.db'
        check = os.open(database.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=data_fd)
        try:
            custody(os.fstat(check))
            db_identity = (os.fstat(check).st_dev, os.fstat(check).st_ino)
        finally:
            os.close(check)
        deadline = time.monotonic() + 15
        connection = sqlite3.connect(database.as_uri() + '?mode=rw', uri=True, timeout=15)
        try:
            connection.execute('BEGIN IMMEDIATE')
            metadata = os.stat(database, follow_symlinks=False)
            if (metadata.st_dev, metadata.st_ino) != db_identity:
                raise Refused('database_identity_changed')
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {'sel_target', 'sel_operation'} <= tables:
                raise Refused('existing_sel_schema_required')
            columns = {row[1] for row in connection.execute('PRAGMA table_info(sel_target)')}
            if not {'auto_clear', 'auto_clock', 'active_operation'} <= columns:
                raise Refused('existing_sel_schema_required')
            if (connection.execute('SELECT 1 FROM sel_target WHERE auto_clear != 0 OR auto_clock != 0 OR auto_clear IS NULL OR auto_clock IS NULL OR active_operation IS NOT NULL LIMIT 1').fetchone() or
                    connection.execute("SELECT 1 FROM sel_operation WHERE state NOT IN ('complete','failed') OR state IS NULL LIMIT 1").fetchone()):
                raise Refused('automation_or_operation_active')
            if runtime_identity() != identity:
                raise Refused('runtime_identity_mismatch')
            previous = None
            promotion_proofs = []
            try:
                previous_bytes = read_file(base / 'active.json', POINTER_LIMIT, private=True)
            except FileNotFoundError:
                previous_bytes = None
            if expected_active_pointer is not None:
                if previous_bytes is None or sha(previous_bytes) != expected_active_pointer:
                    raise Refused('active_pointer_changed')
                envelope, files, records = validate_envelope(value, expected, identity)
                # The old pointer is validated as current authority, except a
                # consumed manual predecessor may be inspected historically.
                parents = [a['parent_commission'] for r in records for a in r['actions'].values()
                           if a.get('phase') == 'automatic_qualified' and a['parent_commission']['pointer_sha256'] == expected_active_pointer]
                historical_claim = None
                if parents:
                    claim = connection.execute('SELECT created_at FROM sel_operation WHERE id=?', (parents[0]['operation_id'],)).fetchone()
                    if not claim:
                        raise Refused('promotion_local_operation_mismatch')
                    historical_claim = datetime.fromisoformat(claim[0]).replace(tzinfo=timezone.utc)
                old_state = operator_state(admitted_at=historical_claim)
                old_records = read_bundle(base / 'bundles' / old_state['envelope_sha256'],
                    old_state['envelope_sha256'], identity, admitted_at=historical_claim)[2]
                promotion_proofs = []
                for record in records:
                    for action, admission in record['actions'].items():
                        if admission.get('phase') != 'automatic_qualified':
                            continue
                        old = next((r for r in old_records if r['record_id'] == record['record_id'] and action in r['actions']), None)
                        if (old and old['actions'][action].get('phase') == 'automatic_qualified' and
                                canonical_sha({k: v for k, v in old.items() if not k.startswith('_')}) ==
                                canonical_sha({k: v for k, v in record.items() if not k.startswith('_')})):
                            proof = accepted_promotion(old, action, expected_active_pointer,
                                old_state['envelope_sha256'], old_state['registry_sha256'], connection)
                        else:
                            # First/changed admissions require full proof now,
                            # while raw DB+file archives are still available.
                            proof = next(p for p in verify_promotions([record], expected_active_pointer, connection)
                                         if p['action'] == action)
                        promotion_proofs.append((record, action, proof))
                previous = expected_active_pointer
                history_root = base / 'pointers'
                for old in history_root.iterdir():
                    historic = strict_json(read_file(old, POINTER_LIMIT, private=True))
                    if historic.get('envelope_sha256') == expected:
                        raise Refused('retired_bundle_reactivation')
            elif previous_bytes is not None:
                current = operator_state()
                if current['envelope_sha256'] == expected:
                    return {'outcome': 'already_installed', 'stage': 'verified', 'envelope_sha256': expected,
                            'registry_sha256': envelope['registry_sha256']}
                raise Refused('replacement_not_authorized')
            elif any(admission.get('phase') == 'automatic_qualified'
                     for record in records for admission in record['actions'].values()):
                raise Refused('promotion_requires_replace')
            pointer = {'schema': 'sel-qualification-pointer/1', 'envelope_sha256': expected,
                       'registry_sha256': envelope['registry_sha256'], 'identity': identity,
                       'previous_pointer_sha256': previous}
            pointer_bytes = json.dumps(pointer, sort_keys=True, separators=(',', ':')).encode()
            if promotion_proofs:
                transitions = child_directory(base_fd, 'transitions')
                try:
                    for record, action, proof in promotion_proofs:
                        binding = promotion_binding(record, action, sha(pointer_bytes), expected, envelope['registry_sha256'])
                        receipt = {'schema': 'sel-promotion-acceptance/1',
                            'accepted_at': datetime.now(timezone.utc).isoformat(), 'binding': binding, 'proof': proof}
                        receipt['sha256'] = canonical_sha(receipt)
                        name = 'accept-' + canonical_sha(binding) + '.json'
                        payload = json.dumps(receipt, sort_keys=True, separators=(',', ':')).encode()
                        write_exclusive(transitions, name, payload)
                        if read_file(base / 'transitions' / name, EVIDENCE_LIMIT, private=True) != payload:
                            raise Refused('promotion_acceptance_readback_failed')
                finally:
                    os.close(transitions)
            temporary = 'pointer-' + uuid.uuid4().hex + '.json'
            write_exclusive(base_fd, temporary, pointer_bytes)
            # Retain independent pointer bytes; no hardlinks or automatic GC.
            history = child_directory(base_fd, 'pointers')
            try:
                write_exclusive(history, sha(pointer_bytes) + '.json', pointer_bytes)
            finally:
                os.close(history)
            if expected_active_pointer is not None:
                transition = {'schema': 'sel-qualification-transition/1', 'previous_pointer_sha256': previous,
                    'pointer_sha256': sha(pointer_bytes), 'envelope_sha256': expected,
                    'state': 'publication_intent', 'recorded_at': datetime.now(timezone.utc).isoformat()}
                transition_id = uuid.uuid4().hex
                transitions = child_directory(base_fd, 'transitions')
                try:
                    write_exclusive(transitions, transition_id + '.intent.json', json.dumps(transition, sort_keys=True).encode())
                finally:
                    os.close(transitions)
                if sha(read_file(base / 'active.json', POINTER_LIMIT, private=True)) != expected_active_pointer:
                    raise Refused('active_pointer_changed')
            if time.monotonic() >= deadline:
                raise Refused('activation_window_exceeded')
            if runtime_identity() != identity:
                raise Refused('runtime_identity_mismatch')
            os.replace(temporary, 'active.json', src_dir_fd=base_fd, dst_dir_fd=base_fd)
            published = True
            os.fsync(base_fd)
            if expected_active_pointer is not None:
                transitions = child_directory(base_fd, 'transitions')
                try:
                    write_exclusive(transitions, transition_id + '.result.json', json.dumps({
                        **transition, 'state': 'published', 'outcome': 'replaced'}, sort_keys=True).encode())
                finally:
                    os.close(transitions)
            connection.rollback()  # Authority read lock only; no policy writes.
            return {'outcome': 'replaced' if expected_active_pointer is not None else 'installed', 'stage': 'published', 'envelope_sha256': expected,
                    'registry_sha256': envelope['registry_sha256']}
        finally:
            connection.close()
    except BaseException:
        if published:
            return {'outcome': 'outcome_unknown', 'stage': 'published', 'envelope_sha256': expected}
        raise
    finally:
        for fd in (stage_fd, bundles_fd, base_fd, data_fd):
            if fd is not None:
                os.close(fd)


# TRACEWEAVER: entrypoint=main; req=REQ-SEL-003,REQ-SEL-004,REQ-SEL-005; trace=TRACE-SEL-003,TRACE-SEL-004,TRACE-SEL-005; ver=VER-SEL-003,VER-SEL-004,VER-SEL-005
def main(argv=None):
    parser = argparse.ArgumentParser(prog='qualifications')
    commands = parser.add_subparsers(dest='operation', required=True)
    install = commands.add_parser('install')
    install.add_argument('--expected-sha256', required=True)
    replace = commands.add_parser('replace')
    replace.add_argument('--expected-sha256', required=True)
    replace.add_argument('--expected-active-pointer-sha256', required=True)
    commands.add_parser('status')
    args = parser.parse_args(argv)
    result = {'outcome': 'refused', 'stage': 'preflight'}
    if args.operation == 'status':
        state = qualification_state()
        result = {'outcome': 'installed' if state['binding'] else 'refused', 'stage': 'status',
                  **{key: state[key] for key in ('mode', 'registry_sha256', 'envelope_sha256')}}
    else:
        try:
            if os.geteuid() != 0:
                raise Refused('root_operator_required')
            value = sys.stdin.buffer.read(ENVELOPE_LIMIT + 1)
            result = install_bundle(value, args.expected_sha256, args.expected_active_pointer_sha256 if args.operation == 'replace' else None)
        except Refused as exc:
            result['reason'] = str(exc)
        except sqlite3.Error:
            result['reason'] = 'existing_database_unavailable'
        except (OSError, ValueError, TypeError, KeyError):
            result['reason'] = 'unsafe_storage'
    print(json.dumps(result, sort_keys=True))
    return 0 if result['outcome'] in {'installed', 'already_installed', 'replaced'} else 1


if __name__ == '__main__':
    raise SystemExit(main())
