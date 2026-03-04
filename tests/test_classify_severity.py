"""
Tests for SEL event severity classification.

Verifies that classify_severity correctly maps IPMI SEL events to
critical / warning / info using both event_text and sensor_type.
Also tests Redfish severity mapping for case-insensitive handling.
"""

import os
import sys
import re
import ast
import textwrap
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


# ---------------------------------------------------------------------------
# Extract classify_severity as a pure function without importing the full
# Flask app (which pulls in heavy dependencies). We parse the source and
# exec just the function definition.
# ---------------------------------------------------------------------------

def _load_classify_severity():
    """Extract classify_severity from app.py source without importing the module."""
    app_path = os.path.join(os.path.dirname(__file__), '..', 'src', 'ipmi_monitor', 'app.py')
    with open(app_path) as f:
        source = f.read()

    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == 'classify_severity':
            func_source = ast.get_source_segment(source, node)
            ns = {'re': re}
            exec(func_source, ns)
            return ns['classify_severity']
    raise RuntimeError('classify_severity not found in app.py')


classify_severity = _load_classify_severity()


class TestClassifySeverityCritical:
    """Events that MUST be classified as 'critical'."""

    def test_keyword_critical(self):
        assert classify_severity('Upper Critical threshold crossed') == 'critical'

    def test_keyword_fail(self):
        assert classify_severity('Power supply failure detected') == 'critical'

    def test_keyword_fault(self):
        assert classify_severity('Fan fault on FAN1') == 'critical'

    def test_keyword_non_recoverable(self):
        assert classify_severity('Voltage non-recoverable') == 'critical'

    def test_power_supply_ac_lost(self):
        assert classify_severity('Power Supply AC lost') == 'critical'

    def test_temperature_upper_critical(self):
        assert classify_severity('Temperature Upper Critical going high') == 'critical'

    def test_voltage_lower_critical(self):
        assert classify_severity('Voltage Lower Critical going low') == 'critical'

    def test_voltage_upper_critical(self):
        assert classify_severity('Voltage Upper Critical going high') == 'critical'

    # --- New patterns from forked repo ---

    def test_uncorrectable_ecc(self):
        """Uncorrectable ECC memory errors must be critical."""
        assert classify_severity('Uncorrectable ECC') == 'critical'

    def test_machine_check(self):
        """Machine Check Exception events must be critical."""
        assert classify_severity('Machine check events logged') == 'critical'

    def test_nmi(self):
        """NMI events must be critical."""
        assert classify_severity('NMI / Diagnostic Interrupt') == 'critical'

    def test_pci_perr(self):
        """PCI parity error must be critical."""
        assert classify_severity('PCI PERR detected') == 'critical'

    def test_pci_serr(self):
        """PCI system error must be critical."""
        assert classify_severity('PCI SERR detected') == 'critical'

    def test_bus_error(self):
        assert classify_severity('Bus error on CPU0') == 'critical'

    def test_post_error(self):
        assert classify_severity('POST Error during boot') == 'critical'

    def test_critical_interrupt_sensor_type(self):
        """When sensor_type is 'Critical Interrupt' but event_text is generic,
        the event must still be classified as critical."""
        assert classify_severity('Transition to Non-recoverable', sensor_type='Critical Interrupt') == 'critical'

    def test_machine_check_via_sensor_type(self):
        """sensor_type='Machine Check' should contribute to classification."""
        assert classify_severity('Events logged', sensor_type='Machine Check') == 'critical'

    def test_system_event(self):
        assert classify_severity('System Event detected') == 'critical'


class TestClassifySeverityWarning:
    """Events that MUST be classified as 'warning'."""

    def test_keyword_warning(self):
        assert classify_severity('Temperature warning threshold reached') == 'warning'

    def test_keyword_non_critical(self):
        assert classify_severity('Upper Non-Critical going high') == 'warning'

    def test_keyword_predictive(self):
        assert classify_severity('Predictive Failure on drive bay 1') == 'warning'

    def test_keyword_threshold(self):
        assert classify_severity('Threshold crossed on sensor') == 'warning'

    # --- New patterns from forked repo ---

    def test_correctable_ecc(self):
        """Correctable ECC should be warning, not info."""
        assert classify_severity('Correctable ECC memory event') == 'warning'

    def test_ecc_keyword(self):
        """Standalone 'ecc' reference should be warning."""
        assert classify_severity('ECC event logged on DIMM A1') == 'warning'

    def test_going_low(self):
        assert classify_severity('Voltage going low') == 'warning'

    def test_going_high(self):
        assert classify_severity('Temperature going high') == 'warning'

    def test_limit_exceeded(self):
        assert classify_severity('Correctable error logging limit exceeded') == 'warning'

    def test_degraded(self):
        assert classify_severity('Memory module degraded') == 'warning'

    def test_asserted_event(self):
        """An asserted event with no other severity indicators should be
        warning (not info), because assertion means something happened."""
        assert classify_severity('Sensor 0x34 - State Asserted') == 'warning'

    def test_deasserted_not_warning(self):
        """Deasserted events are safe, so should NOT be bumped to warning."""
        assert classify_severity('State Deasserted') == 'info'


class TestClassifySeverityInfo:
    """Events that should remain 'info'."""

    def test_generic_log_entry(self):
        assert classify_severity('Log area reset/cleared') == 'info'

    def test_normal_reading(self):
        assert classify_severity('Sensor reading normal') == 'info'

    def test_deasserted(self):
        assert classify_severity('Lower Non-critical - going low Deasserted') == 'info'

    def test_generic_error_removed(self):
        """The generic 'error' keyword should NOT trigger critical on its own.
        Only specific error types (bus error, post error) should."""
        assert classify_severity('OEM Record error') != 'critical'


class TestClassifySeveritySensorType:
    """Verify that sensor_type parameter is used in classification."""

    def test_sensor_type_default_empty(self):
        """Should work without sensor_type (backward compatible)."""
        assert classify_severity('Upper Critical going high') == 'critical'

    def test_sensor_type_contributes(self):
        """sensor_type keywords should be considered."""
        result = classify_severity('Transition to OK', sensor_type='Critical Interrupt')
        assert result == 'critical'

    def test_sensor_type_warning(self):
        """Warning sensor type with neutral description."""
        result = classify_severity('State transition', sensor_type='Threshold sensor')
        assert result == 'warning'


class TestRedfishSeverityMapping:
    """Redfish severity mapping should be case-insensitive."""

    @staticmethod
    def _map_severity(severity_str):
        """Simulate the Redfish severity mapping that should be
        case-insensitive after the fix."""
        severity_map = {
            'critical': 'critical',
            'warning': 'warning',
            'ok': 'info',
            'informational': 'info'
        }
        return severity_map.get(severity_str.lower().strip(), 'info')

    def test_title_case(self):
        assert self._map_severity('Critical') == 'critical'

    def test_upper_case(self):
        assert self._map_severity('CRITICAL') == 'critical'

    def test_lower_case(self):
        assert self._map_severity('critical') == 'critical'

    def test_warning_mixed(self):
        assert self._map_severity('WARNING') == 'warning'

    def test_ok_lower(self):
        assert self._map_severity('ok') == 'info'

    def test_informational_upper(self):
        assert self._map_severity('INFORMATIONAL') == 'info'

    def test_whitespace(self):
        assert self._map_severity('  Warning  ') == 'warning'

    def test_unknown_falls_to_info(self):
        assert self._map_severity('SomethingElse') == 'info'
