# TRACEWEAVER: file-role=qualification-custody-verification; req=REQ-SEL-004; trace=TRACE-SEL-004; ver=VER-SEL-004
# TRACEWEAVER: verifies=VER-SEL-004; req=REQ-SEL-004; trace=TRACE-SEL-004
"""Qualification custody/CLI contracts; all data lives in temporary test roots.

IC02/03/05/10 map to unchanged REQ-SEL-004; tests are not device evidence.
Existing real registry fixture is reused rather than a second fake store.
"""
import hashlib
import json

from click.testing import CliRunner
import pytest

from tests.test_sel_management import qualified_site, qualification_transport, sel_site


def test_fixed_qualification_cli_exposes_only_install_and_status(monkeypatch):
    from ipmi_monitor.cli import main
    monkeypatch.setattr('subprocess.run', lambda *_a, **_k: (_ for _ in ()).throw(AssertionError('CLI help must be offline')))
    result = CliRunner().invoke(main, ['qualifications', '--help'])
    assert result.exit_code == 0, result.output
    assert 'install' in result.output and 'status' in result.output
    for command in ('install', 'status'):
        help_result = CliRunner().invoke(main, ['qualifications', command, '--help'])
        assert help_result.exit_code == 0, help_result.output
        for forbidden in ('--destination', '--db-path', '--module', '--command', '--url'):
            assert forbidden not in help_result.output
    install = CliRunner().invoke(main, ['qualifications', 'install', '--help'])
    assert '--expected-sha256' in install.output


def test_registry_rejects_entire_bundle_when_one_record_is_invalid(qualified_site, monkeypatch):
    from ipmi_monitor.sel_management import qualification_records
    _site, _state, registry = qualified_site
    value = json.loads(registry.read_bytes())
    value['records'].append({'record_id': 'invalid'})
    registry.write_text(json.dumps(value))
    monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
    assert qualification_records() == []


def test_registry_and_evidence_cannot_enter_through_symlink(qualified_site, monkeypatch):
    from ipmi_monitor.sel_management import qualification_records
    _site, _state, registry = qualified_site
    link = registry.with_name('registry-link.json')
    link.symlink_to(registry)
    monkeypatch.setenv('SEL_QUALIFICATIONS_FILE', str(link))
    assert qualification_records() == []


@pytest.mark.parametrize('unsafe', ['hardlink', 'writable', 'source_mismatch', 'tool_mismatch'])
def test_real_registry_custody_and_runtime_applicability_fail_closed(qualified_site, monkeypatch, unsafe):
    from ipmi_monitor.sel_management import qualification_records
    _site, _state, registry = qualified_site
    if unsafe == 'hardlink':
        import os
        os.link(registry, registry.with_name('second-link.json'))
    elif unsafe == 'writable':
        registry.chmod(0o666)
    else:
        value = json.loads(registry.read_bytes())
        if unsafe == 'tool_mismatch':
            value['records'][0]['runtime_identity']['tool_sha256'] = '0' * 64
        else:
            value['records'][0]['runtime_identity'] = {'adapter_sha256': '0' * 64}
        registry.write_text(json.dumps(value))
        monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
    assert qualification_records() == []


def test_complete_synthetic_fixture_resolves_every_action_digest_and_operation(qualified_site):
    from ipmi_monitor.sel_management import qualification_records, qualified
    _site, _state, registry = qualified_site
    records = qualification_records()
    assert len(records) == 1
    record = records[0]
    artifacts = {artifact['sha256']: json.loads((registry.parent / artifact['path']).read_bytes())
                 for artifact in record['evidence_artifacts'] if artifact.get('kind', 'canary') == 'canary'}
    for action, evidence in record['actions'].items():
        assert qualified(record['fingerprint'], action) == record
        assert set(evidence['sha256']) <= artifacts.keys()
        admitted_ids = {operation['operation_id'] for digest in evidence['sha256']
                       for operation in artifacts[digest]['canary_operations']}
        assert set(evidence['canary_operation_ids']) <= admitted_ids


@pytest.mark.parametrize('broken_link', ['digest', 'operation_id'])
def test_action_evidence_digest_and_operation_must_resolve_independently(qualified_site, monkeypatch, broken_link):
    from ipmi_monitor.sel_management import qualified
    _site, _state, registry = qualified_site
    value = json.loads(registry.read_bytes())
    record = value['records'][0]
    if broken_link == 'digest':
        record['actions']['clear']['sha256'] = ['0' * 64]
    else:
        record['actions']['clear']['canary_operation_ids'] = ['9da61ed4-e055-4672-bc57-999999999999']
    registry.write_text(json.dumps(value))
    monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
    admitted = {artifact['sha256'] for artifact in record['evidence_artifacts']}
    if broken_link == 'digest':
        assert set(record['actions']['clear']['sha256']).isdisjoint(admitted)
    else:
        assert set(record['actions']['clear']['sha256']) <= admitted
    assert qualified(record['fingerprint'], 'clear') is None


@pytest.mark.parametrize('broken', ['ca_digest', 'ownership_reference'])
def test_clock_trust_and_supporting_evidence_must_be_admitted(qualified_site, monkeypatch, broken):
    from ipmi_monitor.sel_management import qualification_records
    _site, _state, registry = qualified_site
    value = json.loads(registry.read_bytes())
    record = value['records'][0]
    if broken == 'ca_digest':
        record['ntp_probe']['ca_sha256'] = '0' * 64
    else:
        record['supporting_evidence']['clock_ownership'] = ['0' * 64]
    registry.write_text(json.dumps(value))
    monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
    assert qualification_records() == []


def test_boolean_identity_fields_cannot_be_replaced_by_equal_json_integers(qualified_site, monkeypatch):
    from ipmi_monitor.sel_management import qualification_records
    _site, _state, registry = qualified_site
    value = json.loads(registry.read_bytes())
    # Python considers False == 0, so equality alone is not strict validation.
    value['records'][0]['fingerprint']['aux_firmware_present'] = 0
    registry.write_text(json.dumps(value))
    monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
    assert qualification_records() == []


@pytest.mark.parametrize('transport', ['lanplus-cipher3-admin', 'lanplus-cipher17-admin'])
def test_supported_transports_retain_exact_fingerprint_action_and_evidence(
        qualified_site, qualification_transport, monkeypatch, transport):
    from ipmi_monitor.sel_management import qualification_records, qualified
    record = qualification_transport(transport)
    assert len(qualification_records()) == 1
    assert qualified(record['fingerprint'], 'clear')['record_id'] == record['record_id']
    for key, wrong in [('transport', 'lanplus-cipher8-admin'), ('guid', 'ff' * 16),
                       ('aux_firmware', 'ff' * 4), ('firmware', 'different')]:
        assert qualified(dict(record['fingerprint'], **{key: wrong}), 'clear') is None
    assert qualified(record['fingerprint'], 'unsupported_action') is None
    _site, _state, registry = qualified_site
    # A truthful record cannot borrow differently bound evidence.
    value = json.loads(registry.read_bytes())
    value['records'][0]['fingerprint']['guid'] = 'ff' * 16
    registry.write_text(json.dumps(value))
    monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
    assert qualification_records() == []


def test_mixed_supported_transports_resolve_independently(qualified_site, qualification_transport):
    from ipmi_monitor.sel_management import qualification_records, qualified
    cipher3 = qualification_transport('lanplus-cipher3-admin', append=True)
    records = qualification_records()
    assert len(records) == 2
    cipher17 = next(record for record in records if record['fingerprint']['transport'] == 'lanplus-cipher17-admin')
    assert qualified(cipher3['fingerprint'], 'clear')['record_id'] == cipher3['record_id']
    assert qualified(cipher17['fingerprint'], 'clear')['record_id'] == cipher17['record_id']


@pytest.mark.parametrize('transport', ['lanplus-cipher8-admin', 'lan-cipher3-admin', 'arbitrary'])
def test_unsupported_record_transport_is_refused(qualification_transport, transport):
    from ipmi_monitor.sel_management import qualification_records
    qualification_transport(transport)
    assert qualification_records() == []



def test_cipher3_clear_evidence_cannot_authorize_other_actions(
        qualified_site, qualification_transport, monkeypatch):
    from ipmi_monitor.sel_management import qualified
    qualification_transport('lanplus-cipher3-admin')
    _site, _state, registry = qualified_site
    value = json.loads(registry.read_bytes())
    record = value['records'][0]
    record['actions'] = {'clear': record['actions']['clear']}
    record['evidence_artifacts'] = [artifact for artifact in record['evidence_artifacts']
                                    if artifact['sha256'] in record['actions']['clear']['sha256']]
    for key in ('clock_semantics', 'ntp_probe', 'supporting_evidence'):
        record.pop(key)
    registry.write_text(json.dumps(value))
    monkeypatch.setenv('SEL_QUALIFICATIONS_SHA256', hashlib.sha256(registry.read_bytes()).hexdigest())
    assert qualified(record['fingerprint'], 'clear') is not None
    assert qualified(record['fingerprint'], 'enable') is None
    assert qualified(record['fingerprint'], 'clock') is None
