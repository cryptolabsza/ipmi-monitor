"""
IPMI Monitor QuickStart - One command setup

The client runs:
    pip install ipmi-monitor
    sudo ipmi-monitor quickstart

And answers a few questions. That's it.
"""

import os
import subprocess
import sys
from pathlib import Path
from typing import Optional, List, Dict

import questionary
from questionary import Style
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.prompt import Prompt
import yaml

console = Console()

custom_style = Style([
    ('qmark', 'fg:cyan bold'),
    ('question', 'bold'),
    ('answer', 'fg:cyan'),
    ('pointer', 'fg:cyan bold'),
    ('highlighted', 'fg:cyan bold'),
    ('selected', 'fg:green'),
])


def check_root():
    """Check if running as root."""
    if os.geteuid() != 0:
        console.print("[red]Error:[/red] This command requires root privileges.")
        console.print("Run with: [cyan]sudo ipmi-monitor quickstart[/cyan]")
        sys.exit(1)


def get_local_ip() -> str:
    """Get the local IP address."""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def run_quickstart():
    """Main quickstart wizard - does everything."""
    check_root()
    
    console.print()
    console.print(Panel(
        "[bold cyan]IPMI Monitor - Quick Setup[/bold cyan]\n\n"
        "Monitor your servers' IPMI/BMC health, temperatures, and sensors.\n"
        "Just answer a few questions and everything will be configured.\n\n"
        "[dim]Press Ctrl+C to cancel at any time.[/dim]",
        border_style="cyan"
    ))
    console.print()
    
    # Detect environment
    local_ip = get_local_ip()
    hostname = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()
    
    console.print(f"[dim]Detected: {hostname} ({local_ip})[/dim]\n")
    
    # ============ Step 1: Add servers ============
    console.print("[bold]Step 1: Add Servers to Monitor[/bold]\n")
    
    # Ask how many servers
    server_count = questionary.select(
        "How many servers do you want to monitor?",
        choices=[
            questionary.Choice("Just one server", value="single"),
            questionary.Choice("Multiple servers (same credentials)", value="bulk"),
        ],
        style=custom_style
    ).ask()
    
    servers = []
    
    if server_count == "single":
        server = add_server_interactive()
        if server:
            servers.append(server)
            console.print(f"[green]✓[/green] Added {server['name']}")
    else:
        servers = add_servers_bulk()
    
    if not servers:
        console.print("[yellow]No servers added. Run again to add servers.[/yellow]")
        return
    
    # ============ Step 2: Web Interface Settings ============
    console.print("\n[bold]Step 2: Web Interface Settings[/bold]\n")
    
    web_port = questionary.text(
        "Web interface port:",
        default="5000",
        validate=lambda x: x.isdigit() and 1 <= int(x) <= 65535,
        style=custom_style
    ).ask()
    
    # ============ Step 3: AI Features (Optional) ============
    console.print("\n[bold]Step 3: AI Features (Optional)[/bold]\n")
    console.print("[dim]AI Insights analyzes server issues and suggests fixes.[/dim]")
    console.print("[dim]Requires a CryptoLabs AI account (free tier available).[/dim]\n")
    
    enable_ai = questionary.confirm(
        "Enable AI Insights?",
        default=False,
        style=custom_style
    ).ask()
    
    license_key = None
    if enable_ai:
        console.print("\n[dim]Get your license key at: https://www.cryptolabs.co.za/my-account/[/dim]")
        license_key = questionary.text(
            "CryptoLabs License Key:",
            validate=lambda x: len(x) > 0 or "Key required",
            style=custom_style
        ).ask()
    
    # ============ Step 4: Save Config & Start Service ============
    console.print("\n[bold]Step 4: Starting IPMI Monitor[/bold]\n")
    
    config_dir = Path("/etc/ipmi-monitor")
    config_dir.mkdir(parents=True, exist_ok=True)
    
    # Save config
    config = {
        "web": {
            "port": int(web_port),
            "host": "0.0.0.0"
        },
        "database": "/var/lib/ipmi-monitor/ipmi_monitor.db"
    }
    
    if license_key:
        config["ai"] = {
            "enabled": True,
            "license_key": license_key
        }
    
    with open(config_dir / "config.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False)
    
    # Save servers
    servers_config = {"servers": servers}
    with open(config_dir / "servers.yaml", "w") as f:
        yaml.dump(servers_config, f, default_flow_style=False)
    
    console.print(f"[green]✓[/green] Configuration saved to {config_dir}")
    
    # Create data directory
    Path("/var/lib/ipmi-monitor").mkdir(parents=True, exist_ok=True)
    
    # Install and start service
    install_service()
    
    # Show summary
    show_summary(servers, local_ip, int(web_port), license_key is not None)


def add_servers_bulk() -> List[Dict]:
    """Add multiple servers with the same credentials."""
    console.print(Panel(
        "[bold]Adding Multiple Servers[/bold]\n\n"
        "You'll provide:\n"
        "  • ONE set of BMC/IPMI credentials (used for all servers)\n"
        "  • A list of BMC IP addresses\n"
        "  • Optionally: SSH credentials for detailed monitoring",
        border_style="cyan"
    ))
    console.print()
    
    # BMC credentials (same for all)
    console.print("[bold]IPMI/BMC Credentials[/bold] (used for all servers)\n")
    
    bmc_user = questionary.text(
        "BMC username:",
        default="ADMIN",
        style=custom_style
    ).ask()
    
    bmc_pass = questionary.password(
        "BMC password:",
        style=custom_style
    ).ask()
    
    # Get BMC IPs
    console.print("\n[bold]BMC IP Addresses[/bold]")
    console.print("[dim]Enter one IP per line. Press Enter on blank line when done.[/dim]\n")
    
    bmc_ips = []
    while True:
        ip = questionary.text(
            f"  BMC {len(bmc_ips)+1}:",
            style=custom_style
        ).ask()
        
        if not ip or ip.strip() == "":
            break
        
        # Handle comma/space separated
        for single_ip in ip.replace(",", " ").split():
            single_ip = single_ip.strip()
            if single_ip:
                bmc_ips.append(single_ip)
    
    if not bmc_ips:
        return []
    
    # Optional SSH access
    console.print("\n[bold]SSH Access (Optional)[/bold]")
    console.print("[dim]SSH enables: CPU info, storage details, system logs, GPU errors[/dim]\n")
    
    add_ssh = questionary.confirm(
        "Add SSH access for detailed monitoring?",
        default=True,
        style=custom_style
    ).ask()
    
    ssh_user = None
    ssh_pass = None
    ssh_key = None
    
    if add_ssh:
        ssh_user = questionary.text(
            "SSH username:",
            default="root",
            style=custom_style
        ).ask()
        
        auth_method = questionary.select(
            "SSH authentication:",
            choices=["Password", "SSH Key"],
            style=custom_style
        ).ask()
        
        if auth_method == "Password":
            ssh_pass = questionary.password(
                "SSH password:",
                style=custom_style
            ).ask()
        else:
            ssh_key = questionary.text(
                "SSH key path:",
                default="/root/.ssh/id_rsa",
                style=custom_style
            ).ask()
    
    # Build server list
    console.print(f"\n[dim]Testing {len(bmc_ips)} servers...[/dim]\n")
    
    servers = []
    for i, bmc_ip in enumerate(bmc_ips):
        name = f"server-{i+1:02d}"
        
        server = {
            "name": name,
            "bmc_ip": bmc_ip,
            "bmc_user": bmc_user,
            "bmc_password": bmc_pass
        }
        
        # Test IPMI
        if test_ipmi_connection(bmc_ip, bmc_user, bmc_pass):
            console.print(f"[green]✓[/green] {name} ({bmc_ip}) - IPMI OK")
        else:
            console.print(f"[yellow]⚠[/yellow] {name} ({bmc_ip}) - IPMI failed (check credentials)")
        
        # Add SSH if configured
        if add_ssh and ssh_user:
            # Assume server IP is BMC IP with different last octet or same network
            # User can edit this in the web UI later
            server["ssh_user"] = ssh_user
            if ssh_pass:
                server["ssh_password"] = ssh_pass
            if ssh_key:
                server["ssh_key"] = ssh_key
            server["ssh_port"] = 22
            # Server IP will need to be set per-server in UI
        
        servers.append(server)
    
    return servers


def add_server_interactive() -> Optional[Dict]:
    """Interactively add a server."""
    console.print()
    
    name = questionary.text(
        "Server name (e.g., gpu-server-01):",
        validate=lambda x: len(x) > 0,
        style=custom_style
    ).ask()
    
    if not name:
        return None
    
    # BMC/IPMI settings
    console.print("\n[dim]Enter IPMI/BMC credentials for out-of-band management[/dim]")
    
    bmc_ip = questionary.text(
        "BMC IP address:",
        validate=lambda x: len(x) > 0,
        style=custom_style
    ).ask()
    
    bmc_user = questionary.text(
        "BMC username:",
        default="ADMIN",
        style=custom_style
    ).ask()
    
    bmc_pass = questionary.password(
        "BMC password:",
        style=custom_style
    ).ask()
    
    server = {
        "name": name,
        "bmc_ip": bmc_ip,
        "bmc_user": bmc_user,
        "bmc_password": bmc_pass
    }
    
    # Test IPMI connection
    console.print("[dim]Testing IPMI connection...[/dim]")
    
    if test_ipmi_connection(bmc_ip, bmc_user, bmc_pass):
        console.print(f"[green]✓[/green] IPMI connection successful")
    else:
        console.print(f"[yellow]⚠[/yellow] Could not connect to IPMI (check credentials later)")
    
    # Optional SSH access
    add_ssh = questionary.confirm(
        "Add SSH access for detailed monitoring (CPU, storage, logs)?",
        default=True,
        style=custom_style
    ).ask()
    
    if add_ssh:
        ssh_host = questionary.text(
            "Server IP (for SSH):",
            default=bmc_ip.rsplit('.', 1)[0] + ".100" if '.' in bmc_ip else "",
            style=custom_style
        ).ask()
        
        ssh_user = questionary.text(
            "SSH username:",
            default="root",
            style=custom_style
        ).ask()
        
        ssh_method = questionary.select(
            "SSH authentication:",
            choices=["Password", "SSH Key"],
            style=custom_style
        ).ask()
        
        if ssh_method == "Password":
            ssh_pass = questionary.password(
                "SSH password:",
                style=custom_style
            ).ask()
            server["ssh_password"] = ssh_pass
        else:
            ssh_key = questionary.text(
                "SSH key path:",
                default="/root/.ssh/id_rsa",
                style=custom_style
            ).ask()
            server["ssh_key"] = ssh_key
        
        server["server_ip"] = ssh_host
        server["ssh_user"] = ssh_user
        server["ssh_port"] = 22
    
    return server


def test_ipmi_connection(ip: str, user: str, password: str) -> bool:
    """Test IPMI connectivity."""
    try:
        result = subprocess.run(
            ["ipmitool", "-I", "lanplus", "-H", ip, "-U", user, "-P", password, "chassis", "status"],
            capture_output=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def install_service():
    """Install and start systemd service."""
    service = """[Unit]
Description=IPMI Monitor - Server Health Monitoring
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ipmi-monitor daemon
WorkingDirectory=/etc/ipmi-monitor
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    
    service_path = Path("/etc/systemd/system/ipmi-monitor.service")
    service_path.write_text(service)
    
    with Progress(SpinnerColumn(), TextColumn("Starting IPMI Monitor service..."), console=console) as progress:
        progress.add_task("", total=None)
        
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "enable", "ipmi-monitor"], capture_output=True)
        subprocess.run(["systemctl", "start", "ipmi-monitor"], capture_output=True)
    
    # Check if running
    result = subprocess.run(["systemctl", "is-active", "ipmi-monitor"], capture_output=True, text=True)
    
    if result.stdout.strip() == "active":
        console.print("[green]✓[/green] IPMI Monitor service started")
    else:
        console.print("[yellow]⚠[/yellow] Service may need manual start: sudo systemctl start ipmi-monitor")


def show_summary(servers: List[Dict], local_ip: str, port: int, ai_enabled: bool):
    """Show setup summary."""
    console.print()
    console.print(Panel(
        "[bold green]✓ Setup Complete![/bold green]",
        border_style="green"
    ))
    
    table = Table(title="Your IPMI Monitor Setup", show_header=False)
    table.add_column("", style="dim")
    table.add_column("")
    
    table.add_row("Web Interface", f"http://{local_ip}:{port}")
    table.add_row("Servers Monitored", str(len(servers)))
    table.add_row("AI Insights", "Enabled ✓" if ai_enabled else "Not configured")
    table.add_row("Config Directory", "/etc/ipmi-monitor")
    
    console.print(table)
    
    console.print("\n[bold]Monitored Servers:[/bold]")
    for srv in servers:
        ssh_info = f" + SSH" if srv.get("server_ip") else ""
        console.print(f"  • {srv['name']} - BMC: {srv['bmc_ip']}{ssh_info}")
    
    console.print("\n[bold]Commands:[/bold]")
    console.print("  [cyan]ipmi-monitor status[/cyan]        - Check service status")
    console.print("  [cyan]ipmi-monitor add-server[/cyan]    - Add another server")
    console.print("  [cyan]ipmi-monitor logs[/cyan]          - View logs")
    console.print(f"\n[bold]Open your browser:[/bold] [cyan]http://{local_ip}:{port}[/cyan]")


if __name__ == "__main__":
    run_quickstart()
