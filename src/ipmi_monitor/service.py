"""
IPMI Monitor Service Manager - systemd service installation
"""

import os
import subprocess
from pathlib import Path
from typing import Dict, Any

SYSTEMD_SERVICE_TEMPLATE = """[Unit]
Description=IPMI Monitor - Server Monitoring with AI Insights
Documentation=https://github.com/cryptolabsza/ipmi-monitor
After=network.target

[Service]
Type=simple
User={user}
Group={group}
WorkingDirectory={config_dir}
Environment="IPMI_MONITOR_CONFIG={config_dir}"
ExecStart={python_path} -m ipmi_monitor.cli daemon
Restart=on-failure
RestartSec=10

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={config_dir}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""


class ServiceManager:
    """Manage systemd service for IPMI Monitor."""
    
    SERVICE_NAME = "ipmi-monitor"
    SERVICE_FILE = f"/etc/systemd/system/{SERVICE_NAME}.service"
    
    def install(self, config: Dict[str, Any], user: str = None, group: str = None):
        """Install systemd service."""
        import sys
        
        if os.geteuid() != 0:
            raise PermissionError("Installing service requires root privileges")
        
        # Determine user/group
        if user is None:
            user = os.environ.get("SUDO_USER", "root")
        if group is None:
            group = user
        
        # Get config directory from config or default
        config_dir = config.get("_config_dir", Path.home() / ".config" / "ipmi-monitor")
        
        # Generate service file
        service_content = SYSTEMD_SERVICE_TEMPLATE.format(
            user=user,
            group=group,
            config_dir=str(config_dir),
            python_path=sys.executable,
        )
        
        # Write service file
        with open(self.SERVICE_FILE, "w") as f:
            f.write(service_content)
        
        # Reload systemd
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        
        # Enable service
        subprocess.run(["systemctl", "enable", self.SERVICE_NAME], check=True)
        
        print(f"Service installed: {self.SERVICE_FILE}")
        print(f"Start with: sudo systemctl start {self.SERVICE_NAME}")
    
    def uninstall(self):
        """Remove systemd service."""
        if os.geteuid() != 0:
            raise PermissionError("Uninstalling service requires root privileges")
        
        # Stop and disable
        subprocess.run(["systemctl", "stop", self.SERVICE_NAME], check=False)
        subprocess.run(["systemctl", "disable", self.SERVICE_NAME], check=False)
        
        # Remove service file
        if os.path.exists(self.SERVICE_FILE):
            os.remove(self.SERVICE_FILE)
        
        # Reload systemd
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        
        print(f"Service uninstalled")
    
    def status(self) -> str:
        """Get service status."""
        if not os.path.exists(self.SERVICE_FILE):
            return "Not installed"
        
        try:
            result = subprocess.run(
                ["systemctl", "is-active", self.SERVICE_NAME],
                capture_output=True,
                text=True
            )
            status = result.stdout.strip()
            
            if status == "active":
                return "✓ Running"
            elif status == "inactive":
                return "○ Stopped"
            elif status == "failed":
                return "✗ Failed"
            else:
                return status
        except Exception:
            return "Unknown"
    
    def start(self):
        """Start the service."""
        subprocess.run(["systemctl", "start", self.SERVICE_NAME], check=True)
    
    def stop(self):
        """Stop the service."""
        subprocess.run(["systemctl", "stop", self.SERVICE_NAME], check=True)
    
    def restart(self):
        """Restart the service."""
        subprocess.run(["systemctl", "restart", self.SERVICE_NAME], check=True)
    
    def logs(self, follow: bool = False, lines: int = 50):
        """View service logs."""
        cmd = ["journalctl", "-u", self.SERVICE_NAME, "-n", str(lines)]
        if follow:
            cmd.append("-f")
        subprocess.run(cmd)
