"""
NVIDIA Xid Error Recovery System

This module defines:
1. All actionable Xid error codes with severity and descriptions
2. Recovery ladders (escalation paths) for each error type
3. Recovery actions that can be enabled/disabled by clients
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from datetime import datetime


class Severity(Enum):
    """Error severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class RecoveryAction(Enum):
    """Available recovery actions"""
    MONITOR = "monitor"           # Just log and monitor, no action
    KILL_WORKLOAD = "kill"        # Kill the GPU workload (container/VM)
    SOFT_RESET = "soft_reset"     # nvidia-smi -r (soft reset)
    CLOCK_LIMIT = "clock_limit"   # Reduce GPU clocks for stability
    PCI_RESET = "pci_reset"       # PCI device reset (remove/rescan)
    REBOOT = "reboot"             # System reboot via IPMI
    POWER_CYCLE = "power_cycle"   # IPMI power cycle
    MAINTENANCE = "maintenance"   # Flag for maintenance (no auto-action)


@dataclass
class XidError:
    """Definition of an Xid error code"""
    code: int
    name: str
    description: str
    severity: Severity
    recovery_ladder: List[RecoveryAction]
    user_message: str  # User-friendly message (hides technical details)
    
    def to_dict(self) -> Dict:
        return {
            'code': self.code,
            'name': self.name,
            'description': self.description,
            'severity': self.severity.value,
            'recovery_ladder': [a.value for a in self.recovery_ladder],
            'user_message': self.user_message
        }


# ============================================================================
# ACTIONABLE XID ERRORS DATABASE
# ============================================================================

XID_ERRORS: Dict[int, XidError] = {
    # Xid 8 - GPU Reset Detected
    8: XidError(
        code=8,
        name="GPU Reset Detected",
        description="GPU has been reset by the driver",
        severity=Severity.WARNING,
        recovery_ladder=[RecoveryAction.MONITOR],
        user_message="GPU experienced a reset - monitoring for recurrence"
    ),
    
    # Xid 13 - Graphics Exception
    13: XidError(
        code=13,
        name="Graphics Exception",
        description="Graphics engine exception",
        severity=Severity.WARNING,
        recovery_ladder=[
            RecoveryAction.KILL_WORKLOAD,
            RecoveryAction.SOFT_RESET
        ],
        user_message="GPU graphics error - workload may need restart"
    ),
    
    # Xid 31 - Memory Page Fault
    31: XidError(
        code=31,
        name="Memory Page Fault",
        description="GPU memory access error (MMU fault)",
        severity=Severity.CRITICAL,
        recovery_ladder=[
            RecoveryAction.KILL_WORKLOAD,
            RecoveryAction.SOFT_RESET,
            RecoveryAction.CLOCK_LIMIT,
            RecoveryAction.REBOOT
        ],
        user_message="GPU memory error detected - may require recovery"
    ),
    
    # Xid 32 - Invalid Push Buffer
    32: XidError(
        code=32,
        name="Invalid Push Buffer",
        description="Invalid or corrupted command buffer",
        severity=Severity.WARNING,
        recovery_ladder=[
            RecoveryAction.KILL_WORKLOAD,
            RecoveryAction.SOFT_RESET
        ],
        user_message="GPU command error - workload may need restart"
    ),
    
    # Xid 43 - GPU Stopped Responding
    43: XidError(
        code=43,
        name="GPU Stopped Responding",
        description="GPU hung and stopped processing",
        severity=Severity.CRITICAL,
        recovery_ladder=[
            RecoveryAction.KILL_WORKLOAD,
            RecoveryAction.SOFT_RESET,
            RecoveryAction.CLOCK_LIMIT,
            RecoveryAction.PCI_RESET,
            RecoveryAction.REBOOT
        ],
        user_message="GPU not responding - recovery in progress"
    ),
    
    # Xid 45 - Preemptive Cleanup
    45: XidError(
        code=45,
        name="Preemptive Cleanup",
        description="Driver initiated preemptive cleanup due to error",
        severity=Severity.CRITICAL,
        recovery_ladder=[
            RecoveryAction.KILL_WORKLOAD,
            RecoveryAction.SOFT_RESET
        ],
        user_message="GPU cleanup required - recovering"
    ),
    
    # Xid 48 - Double-Bit ECC Error
    48: XidError(
        code=48,
        name="Double-Bit ECC Error",
        description="Uncorrectable memory error (DBE)",
        severity=Severity.CRITICAL,
        recovery_ladder=[
            RecoveryAction.KILL_WORKLOAD,
            RecoveryAction.REBOOT,
            RecoveryAction.MAINTENANCE
        ],
        user_message="GPU memory hardware error - may need maintenance"
    ),
    
    # Xid 61 - Microcontroller Breakpoint
    61: XidError(
        code=61,
        name="Microcontroller Breakpoint",
        description="GPU microcontroller hit breakpoint",
        severity=Severity.CRITICAL,
        recovery_ladder=[
            RecoveryAction.POWER_CYCLE,
            RecoveryAction.MAINTENANCE
        ],
        user_message="GPU firmware error - power cycle required"
    ),
    
    # Xid 62 - Microcontroller Halt
    62: XidError(
        code=62,
        name="Microcontroller Halt",
        description="GPU microcontroller halted",
        severity=Severity.CRITICAL,
        recovery_ladder=[
            RecoveryAction.POWER_CYCLE,
            RecoveryAction.MAINTENANCE
        ],
        user_message="GPU firmware halted - power cycle required"
    ),
    
    # Xid 63 - ECC Page Retirement
    63: XidError(
        code=63,
        name="ECC Page Retirement",
        description="Memory page retired due to ECC errors",
        severity=Severity.WARNING,
        recovery_ladder=[RecoveryAction.MONITOR],
        user_message="GPU memory page retired - monitoring"
    ),
    
    # Xid 64 - ECC DBE Retirement Failure
    64: XidError(
        code=64,
        name="ECC DBE Retirement",
        description="Failed to retire page with double-bit error",
        severity=Severity.CRITICAL,
        recovery_ladder=[
            RecoveryAction.REBOOT,
            RecoveryAction.MAINTENANCE
        ],
        user_message="GPU memory error - reboot required"
    ),
    
    # Xid 69 - Video Processor Exception
    69: XidError(
        code=69,
        name="Video Processor Exception",
        description="Video processor/decoder exception",
        severity=Severity.WARNING,
        recovery_ladder=[
            RecoveryAction.KILL_WORKLOAD,
            RecoveryAction.SOFT_RESET
        ],
        user_message="Video processing error - recovering"
    ),
    
    # Xid 74 - GPU Exception
    74: XidError(
        code=74,
        name="GPU Exception",
        description="General GPU exception",
        severity=Severity.CRITICAL,
        recovery_ladder=[
            RecoveryAction.KILL_WORKLOAD,
            RecoveryAction.SOFT_RESET,
            RecoveryAction.CLOCK_LIMIT,
            RecoveryAction.PCI_RESET,
            RecoveryAction.REBOOT
        ],
        user_message="GPU error detected - recovery in progress"
    ),
    
    # Xid 79 - GPU Fell Off Bus
    79: XidError(
        code=79,
        name="GPU Fell Off Bus",
        description="GPU disconnected from PCI bus",
        severity=Severity.CRITICAL,
        recovery_ladder=[
            RecoveryAction.PCI_RESET,
            RecoveryAction.REBOOT,
            RecoveryAction.POWER_CYCLE
        ],
        user_message="GPU disconnected - hardware recovery needed"
    ),
    
    # Xid 92 - High Single-Bit ECC Rate
    92: XidError(
        code=92,
        name="High SBE Rate",
        description="High rate of correctable ECC errors",
        severity=Severity.WARNING,
        recovery_ladder=[
            RecoveryAction.CLOCK_LIMIT,
            RecoveryAction.MAINTENANCE
        ],
        user_message="GPU memory showing wear - reduced performance"
    ),
    
    # Xid 94 - Contained ECC Error
    94: XidError(
        code=94,
        name="Contained ECC Error",
        description="ECC error contained/handled by hardware",
        severity=Severity.WARNING,
        recovery_ladder=[RecoveryAction.MONITOR],
        user_message="GPU memory error corrected - monitoring"
    ),
    
    # Xid 95 - Uncontained ECC Error
    95: XidError(
        code=95,
        name="Uncontained ECC Error",
        description="ECC error could not be contained",
        severity=Severity.CRITICAL,
        recovery_ladder=[
            RecoveryAction.REBOOT,
            RecoveryAction.MAINTENANCE
        ],
        user_message="GPU memory failure - reboot required"
    ),
    
    # Xid 119 - GSP Error
    119: XidError(
        code=119,
        name="GSP Error",
        description="GPU System Processor error",
        severity=Severity.CRITICAL,
        recovery_ladder=[
            RecoveryAction.SOFT_RESET,
            RecoveryAction.PCI_RESET,
            RecoveryAction.REBOOT
        ],
        user_message="GPU processor error - recovery in progress"
    ),
    
    # Xid 154 - Recovery Action Required
    154: XidError(
        code=154,
        name="Recovery Required",
        description="Driver indicates recovery action needed",
        severity=Severity.CRITICAL,
        recovery_ladder=[
            RecoveryAction.SOFT_RESET,
            RecoveryAction.REBOOT,
            RecoveryAction.POWER_CYCLE
        ],
        user_message="GPU requires recovery - automated recovery in progress"
    ),
}


@dataclass
class RecoveryPermissions:
    """
    Client-configurable recovery permissions.
    Each permission can be enabled/disabled system-wide or per-server.
    """
    # Monitor-only (always enabled, can't disable)
    allow_monitor: bool = True
    
    # Soft recovery actions (low risk)
    allow_kill_workload: bool = True    # Kill GPU container/VM
    allow_soft_reset: bool = True       # nvidia-smi reset
    allow_clock_limit: bool = True      # Reduce GPU clocks
    
    # Moderate recovery (may affect other workloads briefly)
    allow_pci_reset: bool = False       # PCI device reset
    
    # Aggressive recovery (affects all workloads)
    allow_reboot: bool = False          # System reboot
    allow_power_cycle: bool = False     # IPMI power cycle
    
    # Maintenance flagging (always enabled)
    allow_maintenance_flag: bool = True
    
    def to_dict(self) -> Dict:
        return {
            'allow_monitor': self.allow_monitor,
            'allow_kill_workload': self.allow_kill_workload,
            'allow_soft_reset': self.allow_soft_reset,
            'allow_clock_limit': self.allow_clock_limit,
            'allow_pci_reset': self.allow_pci_reset,
            'allow_reboot': self.allow_reboot,
            'allow_power_cycle': self.allow_power_cycle,
            'allow_maintenance_flag': self.allow_maintenance_flag
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'RecoveryPermissions':
        return cls(
            allow_monitor=data.get('allow_monitor', True),
            allow_kill_workload=data.get('allow_kill_workload', True),
            allow_soft_reset=data.get('allow_soft_reset', True),
            allow_clock_limit=data.get('allow_clock_limit', True),
            allow_pci_reset=data.get('allow_pci_reset', False),
            allow_reboot=data.get('allow_reboot', False),
            allow_power_cycle=data.get('allow_power_cycle', False),
            allow_maintenance_flag=data.get('allow_maintenance_flag', True)
        )
    
    def is_action_allowed(self, action: RecoveryAction) -> bool:
        """Check if a recovery action is allowed"""
        mapping = {
            RecoveryAction.MONITOR: self.allow_monitor,
            RecoveryAction.KILL_WORKLOAD: self.allow_kill_workload,
            RecoveryAction.SOFT_RESET: self.allow_soft_reset,
            RecoveryAction.CLOCK_LIMIT: self.allow_clock_limit,
            RecoveryAction.PCI_RESET: self.allow_pci_reset,
            RecoveryAction.REBOOT: self.allow_reboot,
            RecoveryAction.POWER_CYCLE: self.allow_power_cycle,
            RecoveryAction.MAINTENANCE: self.allow_maintenance_flag
        }
        return mapping.get(action, False)


@dataclass
class RecoveryState:
    """
    Tracks the current recovery state for a specific GPU/device.
    Used to determine where we are in the recovery ladder.
    """
    bmc_ip: str
    gpu_pci_address: str
    xid_code: int
    current_stage: int = 0  # Index in recovery ladder
    attempts_at_stage: int = 0
    max_attempts_per_stage: int = 2
    started_at: datetime = field(default_factory=datetime.utcnow)
    last_action_at: Optional[datetime] = None
    last_action: Optional[RecoveryAction] = None
    cooldown_until: Optional[datetime] = None
    is_resolved: bool = False
    flagged_for_maintenance: bool = False
    actions_taken: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            'bmc_ip': self.bmc_ip,
            'gpu_pci_address': self.gpu_pci_address,
            'xid_code': self.xid_code,
            'current_stage': self.current_stage,
            'attempts_at_stage': self.attempts_at_stage,
            'started_at': self.started_at.isoformat(),
            'last_action_at': self.last_action_at.isoformat() if self.last_action_at else None,
            'last_action': self.last_action.value if self.last_action else None,
            'is_resolved': self.is_resolved,
            'flagged_for_maintenance': self.flagged_for_maintenance,
            'actions_taken': self.actions_taken
        }


def get_xid_info(xid_code: int) -> Optional[XidError]:
    """Get information about an Xid error code"""
    return XID_ERRORS.get(xid_code)


def get_all_xid_errors() -> List[Dict]:
    """Get all Xid errors as a list of dicts (for API)"""
    return [xid.to_dict() for xid in XID_ERRORS.values()]


def get_recovery_ladder(xid_code: int) -> List[RecoveryAction]:
    """Get the recovery ladder for an Xid error"""
    xid = XID_ERRORS.get(xid_code)
    if xid:
        return xid.recovery_ladder
    return [RecoveryAction.MONITOR]  # Default to monitor only


def get_next_allowed_action(
    xid_code: int,
    current_stage: int,
    permissions: RecoveryPermissions
) -> Optional[RecoveryAction]:
    """
    Get the next allowed recovery action based on:
    - The Xid error's recovery ladder
    - Current stage in the ladder
    - Client's enabled permissions
    
    Returns None if no more actions are available/allowed.
    """
    ladder = get_recovery_ladder(xid_code)
    
    # Find next allowed action starting from current stage
    for i in range(current_stage, len(ladder)):
        action = ladder[i]
        if permissions.is_action_allowed(action):
            return action
    
    return None


def get_user_friendly_message(xid_code: int) -> str:
    """Get a user-friendly message for an Xid error (hides technical details)"""
    xid = XID_ERRORS.get(xid_code)
    if xid:
        return xid.user_message
    return f"GPU error detected (code {xid_code})"


def get_action_description(action: RecoveryAction) -> str:
    """Get human-readable description of a recovery action"""
    descriptions = {
        RecoveryAction.MONITOR: "Monitoring GPU status",
        RecoveryAction.KILL_WORKLOAD: "Stopping affected workload",
        RecoveryAction.SOFT_RESET: "Performing GPU soft reset",
        RecoveryAction.CLOCK_LIMIT: "Applying GPU clock limit for stability",
        RecoveryAction.PCI_RESET: "Performing PCI bus reset",
        RecoveryAction.REBOOT: "Initiating system reboot",
        RecoveryAction.POWER_CYCLE: "Performing power cycle",
        RecoveryAction.MAINTENANCE: "Flagged for maintenance review"
    }
    return descriptions.get(action, str(action.value))


# ============================================================================
# DEFAULT PERMISSION PRESETS
# ============================================================================

PERMISSION_PRESETS = {
    'conservative': RecoveryPermissions(
        allow_kill_workload=True,
        allow_soft_reset=True,
        allow_clock_limit=True,
        allow_pci_reset=False,
        allow_reboot=False,
        allow_power_cycle=False
    ),
    'moderate': RecoveryPermissions(
        allow_kill_workload=True,
        allow_soft_reset=True,
        allow_clock_limit=True,
        allow_pci_reset=True,
        allow_reboot=False,
        allow_power_cycle=False
    ),
    'aggressive': RecoveryPermissions(
        allow_kill_workload=True,
        allow_soft_reset=True,
        allow_clock_limit=True,
        allow_pci_reset=True,
        allow_reboot=True,
        allow_power_cycle=True
    ),
    'monitor_only': RecoveryPermissions(
        allow_kill_workload=False,
        allow_soft_reset=False,
        allow_clock_limit=False,
        allow_pci_reset=False,
        allow_reboot=False,
        allow_power_cycle=False
    )
}


def get_preset(name: str) -> RecoveryPermissions:
    """Get a permission preset by name"""
    return PERMISSION_PRESETS.get(name, PERMISSION_PRESETS['conservative'])


