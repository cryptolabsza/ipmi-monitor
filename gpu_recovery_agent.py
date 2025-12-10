"""
GPU Recovery Agent

Autonomous agent that:
1. Detects GPU errors (Xid codes) via SSH/dmesg
2. Executes recovery ladder based on client permissions
3. Logs all actions and escalates when needed
4. Tracks recovery state per device

The agent follows a recovery ladder approach:
- Start with least disruptive action
- If issue persists, escalate to next action
- Stop when issue is resolved or all allowed actions exhausted
"""

import subprocess
import threading
import time
import re
import json
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Callable, Tuple
from enum import Enum

from xid_recovery import (
    XID_ERRORS, XidError, RecoveryAction, RecoveryPermissions,
    RecoveryState, Severity, get_xid_info, get_recovery_ladder,
    get_next_allowed_action, get_user_friendly_message, get_action_description
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ActionResult(Enum):
    """Result of a recovery action"""
    SUCCESS = "success"           # Action completed, GPU recovered
    PARTIAL = "partial"           # Action completed, but issue may persist
    FAILED = "failed"             # Action failed to execute
    SKIPPED = "skipped"           # Action skipped (not allowed or cooldown)
    ESCALATE = "escalate"         # Need to try next action in ladder


@dataclass
class RecoveryActionLog:
    """Log entry for a recovery action"""
    timestamp: datetime
    bmc_ip: str
    server_name: str
    gpu_pci_address: str
    xid_code: int
    action: RecoveryAction
    result: ActionResult
    message: str
    details: Dict = field(default_factory=dict)


class GPURecoveryAgent:
    """
    Agent that handles GPU error recovery.
    
    Usage:
        agent = GPURecoveryAgent(
            on_log_event=my_event_logger,
            on_maintenance_flag=my_maintenance_handler
        )
        
        # Handle a detected Xid error
        agent.handle_xid_error(
            bmc_ip="88.0.43.0",
            server_name="brickbox-43",
            gpu_pci="0000:01:00.0",
            xid_code=43,
            permissions=RecoveryPermissions(allow_reboot=True),
            ssh_credentials={'host': '88.0.43.1', 'user': 'root', 'key': '/path/to/key'},
            ipmi_credentials={'user': 'admin', 'password': 'password'}
        )
    """
    
    # Cooldown periods after actions (in seconds)
    COOLDOWNS = {
        RecoveryAction.MONITOR: 60,
        RecoveryAction.KILL_WORKLOAD: 30,
        RecoveryAction.SOFT_RESET: 60,
        RecoveryAction.CLOCK_LIMIT: 120,
        RecoveryAction.PCI_RESET: 120,
        RecoveryAction.REBOOT: 300,
        RecoveryAction.POWER_CYCLE: 600,
        RecoveryAction.MAINTENANCE: 0
    }
    
    # Time to wait for GPU to come back after action
    VERIFICATION_DELAYS = {
        RecoveryAction.KILL_WORKLOAD: 10,
        RecoveryAction.SOFT_RESET: 15,
        RecoveryAction.CLOCK_LIMIT: 5,
        RecoveryAction.PCI_RESET: 30,
        RecoveryAction.REBOOT: 120,
        RecoveryAction.POWER_CYCLE: 180
    }
    
    def __init__(
        self,
        on_log_event: Optional[Callable[[RecoveryActionLog], None]] = None,
        on_maintenance_flag: Optional[Callable[[str, str, str, int], None]] = None,
        on_state_change: Optional[Callable[[RecoveryState], None]] = None
    ):
        """
        Initialize the GPU Recovery Agent.
        
        Args:
            on_log_event: Callback to log recovery events
            on_maintenance_flag: Callback when device needs maintenance (bmc_ip, server_name, gpu_pci, xid)
            on_state_change: Callback when recovery state changes
        """
        self.on_log_event = on_log_event
        self.on_maintenance_flag = on_maintenance_flag
        self.on_state_change = on_state_change
        
        # Track recovery states per device
        self._recovery_states: Dict[str, RecoveryState] = {}  # key = "bmc_ip:gpu_pci"
        
        # Lock for thread safety
        self._lock = threading.Lock()
    
    def _get_state_key(self, bmc_ip: str, gpu_pci: str) -> str:
        """Generate unique key for device state"""
        return f"{bmc_ip}:{gpu_pci}"
    
    def _get_or_create_state(
        self,
        bmc_ip: str,
        gpu_pci: str,
        xid_code: int
    ) -> RecoveryState:
        """Get existing recovery state or create new one"""
        key = self._get_state_key(bmc_ip, gpu_pci)
        
        with self._lock:
            if key not in self._recovery_states:
                self._recovery_states[key] = RecoveryState(
                    bmc_ip=bmc_ip,
                    gpu_pci_address=gpu_pci,
                    xid_code=xid_code
                )
            return self._recovery_states[key]
    
    def _clear_state(self, bmc_ip: str, gpu_pci: str):
        """Clear recovery state after successful recovery"""
        key = self._get_state_key(bmc_ip, gpu_pci)
        with self._lock:
            if key in self._recovery_states:
                del self._recovery_states[key]
    
    def _log_action(
        self,
        bmc_ip: str,
        server_name: str,
        gpu_pci: str,
        xid_code: int,
        action: RecoveryAction,
        result: ActionResult,
        message: str,
        details: Dict = None
    ):
        """Log a recovery action"""
        log_entry = RecoveryActionLog(
            timestamp=datetime.utcnow(),
            bmc_ip=bmc_ip,
            server_name=server_name,
            gpu_pci_address=gpu_pci,
            xid_code=xid_code,
            action=action,
            result=result,
            message=message,
            details=details or {}
        )
        
        logger.info(
            f"[{server_name}] GPU {gpu_pci} Xid {xid_code}: "
            f"{action.value} -> {result.value} | {message}"
        )
        
        if self.on_log_event:
            self.on_log_event(log_entry)
    
    def handle_xid_error(
        self,
        bmc_ip: str,
        server_name: str,
        gpu_pci: str,
        xid_code: int,
        permissions: RecoveryPermissions,
        ssh_credentials: Optional[Dict] = None,
        ipmi_credentials: Optional[Dict] = None,
        force_action: Optional[RecoveryAction] = None
    ) -> Dict:
        """
        Handle a detected Xid error.
        
        This is the main entry point for the agent.
        
        Args:
            bmc_ip: BMC IP address
            server_name: Human-readable server name
            gpu_pci: GPU PCI address (e.g., "0000:01:00.0")
            xid_code: The Xid error code detected
            permissions: Client's enabled recovery permissions
            ssh_credentials: SSH creds for soft recovery {'host', 'user', 'key' or 'password'}
            ipmi_credentials: IPMI creds for hard recovery {'user', 'password'}
            force_action: Force a specific action (for manual override)
            
        Returns:
            Dict with recovery status and actions taken
        """
        xid_info = get_xid_info(xid_code)
        if not xid_info:
            # Unknown Xid - just log and monitor
            self._log_action(
                bmc_ip, server_name, gpu_pci, xid_code,
                RecoveryAction.MONITOR, ActionResult.SUCCESS,
                f"Unknown Xid {xid_code} - logging only"
            )
            return {
                'status': 'unknown_xid',
                'xid_code': xid_code,
                'message': f'Unknown Xid error code {xid_code}',
                'action_taken': 'monitor'
            }
        
        # Get or create recovery state
        state = self._get_or_create_state(bmc_ip, gpu_pci, xid_code)
        
        # Check if we're in cooldown
        if state.cooldown_until and datetime.utcnow() < state.cooldown_until:
            cooldown_remaining = (state.cooldown_until - datetime.utcnow()).total_seconds()
            return {
                'status': 'cooldown',
                'cooldown_remaining': int(cooldown_remaining),
                'message': f'In cooldown, {int(cooldown_remaining)}s remaining'
            }
        
        # Determine next action
        if force_action:
            next_action = force_action
        else:
            next_action = get_next_allowed_action(
                xid_code, state.current_stage, permissions
            )
        
        if not next_action:
            # No more allowed actions - flag for maintenance
            self._flag_for_maintenance(state, bmc_ip, server_name, gpu_pci, xid_code)
            return {
                'status': 'exhausted',
                'message': 'All allowed recovery actions exhausted',
                'flagged_for_maintenance': True,
                'recovery_state': state.to_dict()
            }
        
        # Execute the action
        result = self._execute_action(
            next_action, bmc_ip, server_name, gpu_pci, xid_code,
            ssh_credentials, ipmi_credentials
        )
        
        # Update state
        state.last_action = next_action
        state.last_action_at = datetime.utcnow()
        state.actions_taken.append({
            'action': next_action.value,
            'result': result.value,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        # Set cooldown
        cooldown_seconds = self.COOLDOWNS.get(next_action, 60)
        state.cooldown_until = datetime.utcnow() + timedelta(seconds=cooldown_seconds)
        
        # Handle result
        if result == ActionResult.SUCCESS:
            state.is_resolved = True
            self._clear_state(bmc_ip, gpu_pci)
            return {
                'status': 'resolved',
                'action': next_action.value,
                'message': f'GPU recovered after {get_action_description(next_action)}'
            }
        
        elif result in [ActionResult.FAILED, ActionResult.ESCALATE]:
            # Move to next stage
            state.current_stage += 1
            state.attempts_at_stage = 0
            
            # Check if we've exhausted all actions
            ladder = get_recovery_ladder(xid_code)
            if state.current_stage >= len(ladder):
                self._flag_for_maintenance(state, bmc_ip, server_name, gpu_pci, xid_code)
                return {
                    'status': 'exhausted',
                    'last_action': next_action.value,
                    'message': 'All recovery actions attempted',
                    'flagged_for_maintenance': True
                }
            
            return {
                'status': 'escalating',
                'action': next_action.value,
                'result': result.value,
                'next_stage': state.current_stage,
                'message': f'{get_action_description(next_action)} did not resolve issue, will escalate'
            }
        
        else:  # PARTIAL or SKIPPED
            state.attempts_at_stage += 1
            return {
                'status': 'in_progress',
                'action': next_action.value,
                'result': result.value,
                'message': get_action_description(next_action)
            }
    
    def _execute_action(
        self,
        action: RecoveryAction,
        bmc_ip: str,
        server_name: str,
        gpu_pci: str,
        xid_code: int,
        ssh_creds: Optional[Dict],
        ipmi_creds: Optional[Dict]
    ) -> ActionResult:
        """Execute a specific recovery action"""
        
        try:
            if action == RecoveryAction.MONITOR:
                return self._action_monitor(bmc_ip, server_name, gpu_pci, xid_code)
            
            elif action == RecoveryAction.KILL_WORKLOAD:
                return self._action_kill_workload(bmc_ip, server_name, gpu_pci, xid_code, ssh_creds)
            
            elif action == RecoveryAction.SOFT_RESET:
                return self._action_soft_reset(bmc_ip, server_name, gpu_pci, xid_code, ssh_creds)
            
            elif action == RecoveryAction.CLOCK_LIMIT:
                return self._action_clock_limit(bmc_ip, server_name, gpu_pci, xid_code, ssh_creds)
            
            elif action == RecoveryAction.PCI_RESET:
                return self._action_pci_reset(bmc_ip, server_name, gpu_pci, xid_code, ssh_creds)
            
            elif action == RecoveryAction.REBOOT:
                return self._action_reboot(bmc_ip, server_name, gpu_pci, xid_code, ipmi_creds)
            
            elif action == RecoveryAction.POWER_CYCLE:
                return self._action_power_cycle(bmc_ip, server_name, gpu_pci, xid_code, ipmi_creds)
            
            elif action == RecoveryAction.MAINTENANCE:
                return ActionResult.SUCCESS  # Just flag, no action
            
            else:
                logger.warning(f"Unknown action: {action}")
                return ActionResult.SKIPPED
                
        except Exception as e:
            logger.error(f"Action {action.value} failed: {e}")
            self._log_action(
                bmc_ip, server_name, gpu_pci, xid_code,
                action, ActionResult.FAILED,
                f"Action failed with error: {str(e)}"
            )
            return ActionResult.FAILED
    
    def _run_ssh_command(self, ssh_creds: Dict, command: str) -> Tuple[bool, str]:
        """Run a command via SSH"""
        if not ssh_creds:
            return False, "No SSH credentials provided"
        
        host = ssh_creds.get('host')
        user = ssh_creds.get('user', 'root')
        key = ssh_creds.get('key')
        password = ssh_creds.get('password')
        
        if key:
            cmd = ['ssh', '-o', 'StrictHostKeyChecking=no', '-i', key, f'{user}@{host}', command]
        else:
            # Would need sshpass for password auth
            return False, "SSH key required"
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return result.returncode == 0, result.stdout + result.stderr
        except Exception as e:
            return False, str(e)
    
    def _run_ipmi_command(self, bmc_ip: str, ipmi_creds: Dict, command: List[str]) -> Tuple[bool, str]:
        """Run an IPMI command"""
        if not ipmi_creds:
            return False, "No IPMI credentials provided"
        
        cmd = [
            'ipmitool', '-I', 'lanplus', '-H', bmc_ip,
            '-U', ipmi_creds.get('user', 'admin'),
            '-P', ipmi_creds.get('password')
        ] + command
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.returncode == 0, result.stdout + result.stderr
        except Exception as e:
            return False, str(e)
    
    def _check_gpu_health(self, ssh_creds: Dict, gpu_pci: str) -> bool:
        """Check if GPU is healthy via nvidia-smi"""
        success, output = self._run_ssh_command(
            ssh_creds,
            f'nvidia-smi -i {gpu_pci} --query-gpu=name,temperature.gpu --format=csv,noheader'
        )
        return success and 'Unable to determine' not in output and 'Error' not in output
    
    def _action_monitor(
        self, bmc_ip: str, server_name: str, gpu_pci: str, xid_code: int
    ) -> ActionResult:
        """Monitor-only action - just log"""
        self._log_action(
            bmc_ip, server_name, gpu_pci, xid_code,
            RecoveryAction.MONITOR, ActionResult.SUCCESS,
            f"Logged Xid {xid_code} for monitoring"
        )
        return ActionResult.SUCCESS
    
    def _action_kill_workload(
        self, bmc_ip: str, server_name: str, gpu_pci: str, xid_code: int, ssh_creds: Dict
    ) -> ActionResult:
        """Kill workload using the problematic GPU"""
        if not ssh_creds:
            self._log_action(
                bmc_ip, server_name, gpu_pci, xid_code,
                RecoveryAction.KILL_WORKLOAD, ActionResult.SKIPPED,
                "No SSH credentials - cannot kill workload"
            )
            return ActionResult.SKIPPED
        
        # Find and kill processes using the GPU
        # Get GPU index from PCI address
        success, output = self._run_ssh_command(
            ssh_creds,
            f"nvidia-smi -i {gpu_pci} --query-compute-apps=pid --format=csv,noheader 2>/dev/null || echo ''"
        )
        
        if not success:
            self._log_action(
                bmc_ip, server_name, gpu_pci, xid_code,
                RecoveryAction.KILL_WORKLOAD, ActionResult.FAILED,
                f"Failed to query GPU processes: {output}"
            )
            return ActionResult.FAILED
        
        pids = [p.strip() for p in output.strip().split('\n') if p.strip() and p.strip().isdigit()]
        
        if not pids:
            self._log_action(
                bmc_ip, server_name, gpu_pci, xid_code,
                RecoveryAction.KILL_WORKLOAD, ActionResult.SUCCESS,
                "No active workloads on GPU"
            )
            return ActionResult.SUCCESS
        
        # Kill the processes
        for pid in pids:
            self._run_ssh_command(ssh_creds, f"kill -9 {pid} 2>/dev/null || true")
        
        time.sleep(self.VERIFICATION_DELAYS[RecoveryAction.KILL_WORKLOAD])
        
        # Verify GPU is healthy
        if self._check_gpu_health(ssh_creds, gpu_pci):
            self._log_action(
                bmc_ip, server_name, gpu_pci, xid_code,
                RecoveryAction.KILL_WORKLOAD, ActionResult.SUCCESS,
                f"Killed {len(pids)} processes, GPU recovered"
            )
            return ActionResult.SUCCESS
        
        self._log_action(
            bmc_ip, server_name, gpu_pci, xid_code,
            RecoveryAction.KILL_WORKLOAD, ActionResult.ESCALATE,
            f"Killed {len(pids)} processes but GPU still unhealthy"
        )
        return ActionResult.ESCALATE
    
    def _action_soft_reset(
        self, bmc_ip: str, server_name: str, gpu_pci: str, xid_code: int, ssh_creds: Dict
    ) -> ActionResult:
        """Perform nvidia-smi soft reset"""
        if not ssh_creds:
            return ActionResult.SKIPPED
        
        # Get GPU index
        success, output = self._run_ssh_command(
            ssh_creds,
            f"nvidia-smi -i {gpu_pci} --query-gpu=index --format=csv,noheader"
        )
        
        if not success:
            self._log_action(
                bmc_ip, server_name, gpu_pci, xid_code,
                RecoveryAction.SOFT_RESET, ActionResult.FAILED,
                "Failed to get GPU index"
            )
            return ActionResult.FAILED
        
        gpu_index = output.strip()
        
        # Attempt soft reset
        success, output = self._run_ssh_command(
            ssh_creds,
            f"nvidia-smi -i {gpu_index} --gpu-reset"
        )
        
        time.sleep(self.VERIFICATION_DELAYS[RecoveryAction.SOFT_RESET])
        
        if self._check_gpu_health(ssh_creds, gpu_pci):
            self._log_action(
                bmc_ip, server_name, gpu_pci, xid_code,
                RecoveryAction.SOFT_RESET, ActionResult.SUCCESS,
                "GPU soft reset successful"
            )
            return ActionResult.SUCCESS
        
        self._log_action(
            bmc_ip, server_name, gpu_pci, xid_code,
            RecoveryAction.SOFT_RESET, ActionResult.ESCALATE,
            f"Soft reset did not recover GPU: {output[:100]}"
        )
        return ActionResult.ESCALATE
    
    def _action_clock_limit(
        self, bmc_ip: str, server_name: str, gpu_pci: str, xid_code: int, ssh_creds: Dict
    ) -> ActionResult:
        """Apply clock limit for stability"""
        if not ssh_creds:
            return ActionResult.SKIPPED
        
        # Get max clocks and reduce by 20%
        success, output = self._run_ssh_command(
            ssh_creds,
            f"nvidia-smi -i {gpu_pci} --query-gpu=clocks.max.graphics --format=csv,noheader,nounits"
        )
        
        if not success:
            self._log_action(
                bmc_ip, server_name, gpu_pci, xid_code,
                RecoveryAction.CLOCK_LIMIT, ActionResult.FAILED,
                "Failed to query GPU clocks"
            )
            return ActionResult.FAILED
        
        try:
            max_clock = int(output.strip())
            limited_clock = int(max_clock * 0.8)  # 20% reduction
        except:
            limited_clock = 1400  # Default safe value
        
        # Apply clock limit
        success, output = self._run_ssh_command(
            ssh_creds,
            f"nvidia-smi -i {gpu_pci} -lgc 300,{limited_clock}"
        )
        
        if success:
            # Make persistent via crontab
            cron_cmd = f"nvidia-smi -i {gpu_pci} -lgc 300,{limited_clock}"
            self._run_ssh_command(
                ssh_creds,
                f'(crontab -l 2>/dev/null | grep -v "{gpu_pci}.*-lgc"; echo "@reboot {cron_cmd}") | crontab -'
            )
            
            self._log_action(
                bmc_ip, server_name, gpu_pci, xid_code,
                RecoveryAction.CLOCK_LIMIT, ActionResult.SUCCESS,
                f"Applied clock limit: {limited_clock}MHz (was {max_clock}MHz)"
            )
            return ActionResult.PARTIAL  # Mitigation, not full fix
        
        self._log_action(
            bmc_ip, server_name, gpu_pci, xid_code,
            RecoveryAction.CLOCK_LIMIT, ActionResult.FAILED,
            f"Failed to apply clock limit: {output}"
        )
        return ActionResult.FAILED
    
    def _action_pci_reset(
        self, bmc_ip: str, server_name: str, gpu_pci: str, xid_code: int, ssh_creds: Dict
    ) -> ActionResult:
        """Perform PCI bus reset"""
        if not ssh_creds:
            return ActionResult.SKIPPED
        
        # Get the PCI address in the correct format
        pci_addr = gpu_pci.lstrip('0000:')
        
        # Remove and rescan
        commands = [
            f'echo 1 > /sys/bus/pci/devices/{gpu_pci}/remove 2>/dev/null || true',
            'sleep 2',
            'echo 1 > /sys/bus/pci/rescan'
        ]
        
        success, output = self._run_ssh_command(ssh_creds, ' && '.join(commands))
        
        time.sleep(self.VERIFICATION_DELAYS[RecoveryAction.PCI_RESET])
        
        if self._check_gpu_health(ssh_creds, gpu_pci):
            self._log_action(
                bmc_ip, server_name, gpu_pci, xid_code,
                RecoveryAction.PCI_RESET, ActionResult.SUCCESS,
                "PCI reset successful, GPU recovered"
            )
            return ActionResult.SUCCESS
        
        self._log_action(
            bmc_ip, server_name, gpu_pci, xid_code,
            RecoveryAction.PCI_RESET, ActionResult.ESCALATE,
            "PCI reset did not recover GPU"
        )
        return ActionResult.ESCALATE
    
    def _action_reboot(
        self, bmc_ip: str, server_name: str, gpu_pci: str, xid_code: int, ipmi_creds: Dict
    ) -> ActionResult:
        """Perform system reboot via IPMI"""
        if not ipmi_creds:
            return ActionResult.SKIPPED
        
        success, output = self._run_ipmi_command(bmc_ip, ipmi_creds, ['chassis', 'power', 'reset'])
        
        if success:
            self._log_action(
                bmc_ip, server_name, gpu_pci, xid_code,
                RecoveryAction.REBOOT, ActionResult.SUCCESS,
                "System reboot initiated"
            )
            return ActionResult.SUCCESS
        
        self._log_action(
            bmc_ip, server_name, gpu_pci, xid_code,
            RecoveryAction.REBOOT, ActionResult.FAILED,
            f"Reboot failed: {output}"
        )
        return ActionResult.FAILED
    
    def _action_power_cycle(
        self, bmc_ip: str, server_name: str, gpu_pci: str, xid_code: int, ipmi_creds: Dict
    ) -> ActionResult:
        """Perform power cycle via IPMI"""
        if not ipmi_creds:
            return ActionResult.SKIPPED
        
        success, output = self._run_ipmi_command(bmc_ip, ipmi_creds, ['chassis', 'power', 'cycle'])
        
        if success:
            self._log_action(
                bmc_ip, server_name, gpu_pci, xid_code,
                RecoveryAction.POWER_CYCLE, ActionResult.SUCCESS,
                "Power cycle initiated"
            )
            return ActionResult.SUCCESS
        
        self._log_action(
            bmc_ip, server_name, gpu_pci, xid_code,
            RecoveryAction.POWER_CYCLE, ActionResult.FAILED,
            f"Power cycle failed: {output}"
        )
        return ActionResult.FAILED
    
    def _flag_for_maintenance(
        self, state: RecoveryState, bmc_ip: str, server_name: str, gpu_pci: str, xid_code: int
    ):
        """Flag device for maintenance"""
        state.flagged_for_maintenance = True
        
        self._log_action(
            bmc_ip, server_name, gpu_pci, xid_code,
            RecoveryAction.MAINTENANCE, ActionResult.SUCCESS,
            f"GPU flagged for maintenance - recovery exhausted after {len(state.actions_taken)} actions"
        )
        
        if self.on_maintenance_flag:
            self.on_maintenance_flag(bmc_ip, server_name, gpu_pci, xid_code)
    
    def get_recovery_states(self) -> Dict[str, Dict]:
        """Get all current recovery states"""
        with self._lock:
            return {k: v.to_dict() for k, v in self._recovery_states.items()}
    
    def clear_recovery_state(self, bmc_ip: str, gpu_pci: str):
        """Manually clear a recovery state"""
        self._clear_state(bmc_ip, gpu_pci)


