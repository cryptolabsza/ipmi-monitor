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
    
    # Handle cancellation
    if server_count is None:
        console.print("[yellow]Cancelled.[/yellow]")
        return
    
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
    console.print("[dim]Port 5000 is the default. Only change if you have a conflict.[/dim]\n")
    
    web_port = questionary.text(
        "Web interface port:",
        default="5000",
        validate=lambda x: x.isdigit() and 1 <= int(x) <= 65535,
        style=custom_style
    ).ask()
    
    # Handle cancellation - use default
    if web_port is None:
        web_port = "5000"
    
    # ============ Step 3: Web Admin Password ============
    console.print("\n[bold]Step 3: Web Admin Password[/bold]\n")
    console.print("[dim]Set a password for the web interface. Default: admin/admin[/dim]\n")
    
    change_password = questionary.confirm(
        "Set a custom admin password? (recommended)",
        default=True,
        style=custom_style
    ).ask()
    
    admin_password = "admin"  # Default
    if change_password:
        admin_password = questionary.password(
            "Admin password:",
            validate=lambda x: len(x) >= 4 or "Password must be at least 4 characters",
            style=custom_style
        ).ask()
        
        if admin_password:
            confirm_password = questionary.password(
                "Confirm password:",
                style=custom_style
            ).ask()
            
            if admin_password != confirm_password:
                console.print("[yellow]⚠[/yellow] Passwords don't match. Using default: admin")
                admin_password = "admin"
        else:
            admin_password = "admin"
    
    # ============ Step 4: AI Features (Optional) ============
    console.print("\n[bold]Step 4: AI Features (Optional)[/bold]\n")
    console.print("[dim]AI Insights analyzes server issues and suggests fixes.[/dim]")
    console.print("[dim]Requires a CryptoLabs AI account (free tier available).[/dim]\n")
    
    enable_ai = questionary.confirm(
        "Enable AI Insights?",
        default=False,
        style=custom_style
    ).ask()
    
    # Handle cancellation
    if enable_ai is None:
        enable_ai = False
    
    license_key = None
    if enable_ai:
        console.print("\n[dim]Get your license key at: https://www.cryptolabs.co.za/my-account/[/dim]")
        license_key = questionary.text(
            "CryptoLabs License Key:",
            validate=lambda x: len(x) > 0 or "Key required",
            style=custom_style
        ).ask()
    
    # ============ Step 5: Save Config & Start Service ============
    console.print("\n[bold]Step 5: Starting IPMI Monitor[/bold]\n")
    
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
    
    # Create data directory first (needed for database operations)
    data_dir = Path("/var/lib/ipmi-monitor")
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "ipmi_events.db"
    
    # Process SSH keys - read from file paths and store in database
    # Track unique SSH keys to avoid duplicates
    ssh_key_map = {}  # path -> key_name
    ssh_key_counter = 0
    
    for srv in servers:
        if srv.get("ssh_key"):
            key_path = srv["ssh_key"]
            if key_path not in ssh_key_map:
                # Read key content from file
                key_content = read_ssh_key_file(key_path)
                if key_content:
                    ssh_key_counter += 1
                    key_name = f"quickstart-key-{ssh_key_counter}" if ssh_key_counter > 1 else "default-key"
                    key_id = create_ssh_key_in_database(key_name, key_content, db_path)
                    if key_id:
                        ssh_key_map[key_path] = key_name
    
    # Save servers in the format Flask's parse_yaml_servers() expects
    # Convert from quickstart format to Flask format
    flask_servers = []
    for srv in servers:
        flask_srv = {
            "name": srv.get("name", f"server-{srv.get('bmc_ip', 'unknown')}"),
            "bmc_ip": srv.get("bmc_ip"),
        }
        # Map credential fields to Flask's expected names
        if srv.get("bmc_user"):
            flask_srv["ipmi_user"] = srv["bmc_user"]
        if srv.get("bmc_password"):
            flask_srv["ipmi_pass"] = srv["bmc_password"]
        if srv.get("server_ip"):
            flask_srv["server_ip"] = srv["server_ip"]
        if srv.get("ssh_user"):
            flask_srv["ssh_user"] = srv["ssh_user"]
        if srv.get("ssh_password"):
            flask_srv["ssh_pass"] = srv["ssh_password"]
        # SSH key - use key_name reference instead of path
        if srv.get("ssh_key") and srv["ssh_key"] in ssh_key_map:
            flask_srv["ssh_key_name"] = ssh_key_map[srv["ssh_key"]]
        if srv.get("ssh_port"):
            flask_srv["ssh_port"] = srv["ssh_port"]
        flask_servers.append(flask_srv)
    
    # Write servers.yaml manually to ensure 'name' comes first (Flask parser requires it)
    # Filter out servers without bmc_ip (Flask requires it)
    valid_servers = [srv for srv in flask_servers if srv.get('bmc_ip')]
    skipped = len(flask_servers) - len(valid_servers)
    if skipped > 0:
        console.print(f"[yellow]⚠[/yellow] Skipped {skipped} server(s) without BMC IP (IPMI monitoring requires BMC)")
    
    with open(config_dir / "servers.yaml", "w") as f:
        f.write("servers:\n")
        for srv in valid_servers:
            # name must come first for Flask's parse_yaml_servers()
            f.write(f"  - name: {srv.get('name', 'unknown')}\n")
            f.write(f"    bmc_ip: {srv.get('bmc_ip')}\n")
            if srv.get('ipmi_user'):
                f.write(f"    ipmi_user: {srv['ipmi_user']}\n")
            if srv.get('ipmi_pass'):
                f.write(f"    ipmi_pass: {srv['ipmi_pass']}\n")
            if srv.get('server_ip'):
                f.write(f"    server_ip: {srv['server_ip']}\n")
            if srv.get('ssh_user'):
                f.write(f"    ssh_user: {srv['ssh_user']}\n")
            if srv.get('ssh_pass'):
                f.write(f"    ssh_pass: {srv['ssh_pass']}\n")
            if srv.get('ssh_key_name'):
                f.write(f"    ssh_key_name: {srv['ssh_key_name']}\n")
            if srv.get('ssh_port'):
                f.write(f"    ssh_port: {srv['ssh_port']}\n")
    
    console.print(f"[green]✓[/green] Configuration saved to {config_dir}")
    
    # Always create admin user with proper schema (even for default password)
    # This ensures Flask has a properly structured user table on startup
    set_admin_password(admin_password, db_path)
    
    # Install and start service
    install_service()
    
    # ============ Step 6: HTTPS Access (Optional) ============
    console.print("\n[bold]Step 6: HTTPS Access (Optional)[/bold]\n")
    console.print("[dim]Set up nginx reverse proxy with SSL for secure remote access.[/dim]\n")
    
    setup_ssl = questionary.confirm(
        "Set up HTTPS reverse proxy?",
        default=True,
        style=custom_style
    ).ask()
    
    # Handle cancellation
    if setup_ssl is None:
        setup_ssl = False
    
    domain = None
    if setup_ssl:
        domain = setup_https_access(local_ip)
    
    # Show summary (use servers with bmc_ip only - those that were actually saved)
    saved_servers = [s for s in servers if s.get("bmc_ip")]
    show_summary(saved_servers, local_ip, int(web_port), license_key is not None, domain)


def add_servers_bulk() -> List[Dict]:
    """Add multiple servers - import file or manual entry."""
    console.print(Panel(
        "[bold]Adding Multiple Servers[/bold]\n\n"
        "Choose how to add servers:\n"
        "  • [cyan]Import file[/cyan] - Paste a simple text file\n"
        "  • [cyan]Enter manually[/cyan] - Type IPs one by one",
        border_style="cyan"
    ))
    console.print()
    
    method = questionary.select(
        "How do you want to add servers?",
        choices=[
            questionary.Choice("Import from file/paste (recommended)", value="import"),
            questionary.Choice("Enter manually", value="manual"),
        ],
        style=custom_style
    ).ask()
    
    if method == "import":
        return import_servers_from_text()
    else:
        return add_servers_manual()


def import_servers_from_text() -> List[Dict]:
    """Import servers from a simple text format."""
    console.print(Panel(
        "[bold]Import Format[/bold]\n\n"
        "[cyan]Option 1: SSH only (Grafana monitoring)[/cyan]\n"
        "  global:root,sshpassword\n"
        "  192.168.1.101\n"
        "  192.168.1.102\n\n"
        "[cyan]Option 2: SSH + IPMI (full monitoring)[/cyan]\n"
        "  globalSSH:root,sshpassword\n"
        "  globalIPMI:ADMIN,ipmipassword\n"
        "  192.168.1.101,192.168.1.80\n"
        "  192.168.1.102,192.168.1.82\n\n"
        "[cyan]Option 3: Per-server credentials[/cyan]\n"
        "  192.168.1.101,root,sshpass,ADMIN,ipmipass,192.168.1.80\n"
        "  192.168.1.102,root,sshpass,ADMIN,ipmipass,192.168.1.82\n\n"
        "[dim]Format: serverIP,sshUser,sshPass,ipmiUser,ipmiPass,bmcIP[/dim]\n"
        "[dim]Paste your list below, then press Enter twice.[/dim]",
        border_style="cyan"
    ))
    
    console.print("\n[bold]Paste your server list:[/bold]")
    
    lines = []
    while True:
        line = questionary.text("", style=custom_style).ask()
        if not line or line.strip() == "":
            break
        lines.append(line.strip())
    
    if not lines:
        return []
    
    return parse_ipmi_server_list(lines)


def parse_ipmi_server_list(lines: List[str]) -> List[Dict]:
    """Parse server list supporting SSH and IPMI credentials."""
    servers = []
    global_ssh_user = None
    global_ssh_pass = None
    global_ipmi_user = None
    global_ipmi_pass = None
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        # Check for global SSH credentials
        if line.lower().startswith("globalssh:") or line.lower().startswith("global:"):
            prefix = "globalssh:" if line.lower().startswith("globalssh:") else "global:"
            parts = line[len(prefix):].split(",")
            if len(parts) >= 2:
                global_ssh_user = parts[0].strip()
                global_ssh_pass = parts[1].strip()
            continue
        
        # Check for global IPMI credentials
        if line.lower().startswith("globalipmi:"):
            parts = line[11:].split(",")
            if len(parts) >= 2:
                global_ipmi_user = parts[0].strip()
                global_ipmi_pass = parts[1].strip()
            continue
        
        # Parse server line
        parts = [p.strip() for p in line.split(",")]
        
        server = {"name": f"server-{len(servers)+1:02d}"}
        
        if len(parts) == 1:
            # Just server IP - use globals
            server["server_ip"] = parts[0]
            if global_ssh_user:
                server["ssh_user"] = global_ssh_user
                server["ssh_password"] = global_ssh_pass
            if global_ipmi_user:
                server["bmc_user"] = global_ipmi_user
                server["bmc_password"] = global_ipmi_pass
                # BMC IP often same network as server, different last octet
                # Will need to be configured in UI
                
        elif len(parts) == 2:
            # serverIP, bmcIP - use globals
            server["server_ip"] = parts[0]
            server["bmc_ip"] = parts[1]
            if global_ssh_user:
                server["ssh_user"] = global_ssh_user
                server["ssh_password"] = global_ssh_pass
            if global_ipmi_user:
                server["bmc_user"] = global_ipmi_user
                server["bmc_password"] = global_ipmi_pass
                
        elif len(parts) == 3:
            # serverIP, sshUser, sshPass
            server["server_ip"] = parts[0]
            server["ssh_user"] = parts[1]
            server["ssh_password"] = parts[2]
            if global_ipmi_user:
                server["bmc_user"] = global_ipmi_user
                server["bmc_password"] = global_ipmi_pass
                
        elif len(parts) == 5:
            # serverIP, sshUser, sshPass, ipmiUser, ipmiPass
            server["server_ip"] = parts[0]
            server["ssh_user"] = parts[1]
            server["ssh_password"] = parts[2]
            server["bmc_user"] = parts[3]
            server["bmc_password"] = parts[4]
            
        elif len(parts) >= 6:
            # serverIP, sshUser, sshPass, ipmiUser, ipmiPass, bmcIP
            server["server_ip"] = parts[0]
            server["ssh_user"] = parts[1]
            server["ssh_password"] = parts[2]
            server["bmc_user"] = parts[3]
            server["bmc_password"] = parts[4]
            server["bmc_ip"] = parts[5]
        else:
            continue
        
        # Validate has at least server_ip
        if not server.get("server_ip"):
            continue
        
        # Test IPMI if configured
        if server.get("bmc_ip") and server.get("bmc_user"):
            if test_ipmi_connection(server["bmc_ip"], server["bmc_user"], server["bmc_password"]):
                console.print(f"[green]✓[/green] {server['name']} - IPMI OK ({server['bmc_ip']})")
            else:
                console.print(f"[yellow]⚠[/yellow] {server['name']} - IPMI failed ({server['bmc_ip']})")
        else:
            console.print(f"[blue]•[/blue] {server['name']} - SSH only ({server['server_ip']})")
        
        server["ssh_port"] = 22
        servers.append(server)
    
    return servers


def add_servers_manual() -> List[Dict]:
    """Add multiple servers manually with shared credentials."""
    
    # Get BMC IPs first
    console.print("[bold]BMC IP Addresses[/bold]")
    console.print("[dim]Enter one IP per line. Blank line to finish.[/dim]\n")
    
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
    
    # BMC credentials with retry loop
    while True:
        console.print("\n[bold]IPMI/BMC Credentials[/bold] (used for all servers)\n")
        
        bmc_user = questionary.text(
            "BMC username:",
            default="ADMIN",
            style=custom_style
        ).ask()
        
        if bmc_user is None:
            return []
        
        bmc_pass = questionary.password(
            "BMC password:",
            style=custom_style
        ).ask()
        
        if bmc_pass is None:
            return []
        
        # Test all servers
        console.print(f"\n[dim]Testing {len(bmc_ips)} servers...[/dim]\n")
        
        failed_servers = []
        success_servers = []
        
        for i, bmc_ip in enumerate(bmc_ips):
            name = f"server-{i+1:02d}"
            if test_ipmi_connection(bmc_ip, bmc_user, bmc_pass):
                console.print(f"[green]✓[/green] {name} ({bmc_ip}) - IPMI OK")
                success_servers.append((name, bmc_ip))
            else:
                console.print(f"[yellow]⚠[/yellow] {name} ({bmc_ip}) - IPMI failed")
                failed_servers.append((name, bmc_ip))
        
        # If any failed, offer retry
        if failed_servers:
            console.print(f"\n[yellow]{len(failed_servers)} server(s) failed IPMI test.[/yellow]")
            
            retry_choice = questionary.select(
                "What would you like to do?",
                choices=[
                    questionary.Choice("Re-enter credentials and try again", value="retry"),
                    questionary.Choice("Continue anyway (add all servers)", value="continue"),
                    questionary.Choice("Continue with only working servers", value="working_only"),
                    questionary.Choice("Cancel", value="cancel"),
                ],
                style=custom_style
            ).ask()
            
            if retry_choice == "retry":
                continue
            elif retry_choice == "cancel":
                return []
            elif retry_choice == "working_only":
                bmc_ips = [ip for name, ip in success_servers]
                if not bmc_ips:
                    console.print("[yellow]No working servers. Please check your credentials.[/yellow]")
                    continue
        
        # All tests passed or user chose to continue
        break
    
    # Optional SSH access
    console.print("\n[bold]SSH Access (Optional)[/bold]")
    console.print("[dim]SSH enables: CPU info, storage, system logs, GPU errors[/dim]\n")
    
    add_ssh = questionary.confirm(
        "Add SSH access for detailed monitoring?",
        default=True,
        style=custom_style
    ).ask()
    
    ssh_user = None
    ssh_pass = None
    ssh_key = None
    server_ips = {}  # bmc_ip -> server_ip mapping
    
    if add_ssh:
        # Ask how server IPs relate to BMC IPs
        console.print("\n[dim]SSH connects to the server OS IP (not the BMC IP).[/dim]")
        
        ip_pattern = questionary.select(
            "How do server IPs relate to BMC IPs?",
            choices=[
                questionary.Choice("Same network, different last octet (e.g., BMC .0 -> Server .1)", value="offset"),
                questionary.Choice("Same IP as BMC", value="same"),
                questionary.Choice("Enter each server IP manually", value="manual"),
            ],
            style=custom_style
        ).ask()
        
        if ip_pattern == "offset":
            offset = questionary.text(
                "Server IP offset from BMC (e.g., BMC ends in .83 -> Server ends in .84, offset=1):",
                default="1",
                validate=lambda x: x.lstrip('-').isdigit(),
                style=custom_style
            ).ask()
            offset = int(offset) if offset else 1
            
            for bmc_ip in bmc_ips:
                parts = bmc_ip.rsplit('.', 1)
                if len(parts) == 2 and parts[1].isdigit():
                    server_ip = f"{parts[0]}.{int(parts[1]) + offset}"
                    server_ips[bmc_ip] = server_ip
                else:
                    server_ips[bmc_ip] = bmc_ip
                    
        elif ip_pattern == "same":
            for bmc_ip in bmc_ips:
                server_ips[bmc_ip] = bmc_ip
                
        else:  # manual
            console.print("\n[bold]Enter server IP for each BMC:[/bold]")
            for bmc_ip in bmc_ips:
                server_ip = questionary.text(
                    f"  Server IP for BMC {bmc_ip}:",
                    default=bmc_ip,
                    style=custom_style
                ).ask()
                server_ips[bmc_ip] = server_ip if server_ip else bmc_ip
        
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
    servers = []
    for i, bmc_ip in enumerate(bmc_ips):
        name = f"server-{i+1:02d}"
        
        server = {
            "name": name,
            "bmc_ip": bmc_ip,
            "bmc_user": bmc_user,
            "bmc_password": bmc_pass
        }
        
        # Add SSH if configured
        if add_ssh and ssh_user:
            server["server_ip"] = server_ips.get(bmc_ip, bmc_ip)
            server["ssh_user"] = ssh_user
            if ssh_pass:
                server["ssh_password"] = ssh_pass
            if ssh_key:
                server["ssh_key"] = ssh_key
            server["ssh_port"] = 22
        
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


def set_admin_password(password: str, db_path: Path):
    """Set the admin password in the database.
    
    Creates user table matching Flask's User model schema exactly.
    Also handles upgrading existing tables that may have missing columns.
    """
    import sqlite3
    from datetime import datetime
    from werkzeug.security import generate_password_hash
    
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Create user table matching Flask's User model exactly
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(50) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) NOT NULL DEFAULT 'readonly',
                enabled BOOLEAN DEFAULT 1,
                password_changed BOOLEAN DEFAULT 0,
                created_at DATETIME,
                updated_at DATETIME,
                last_login DATETIME,
                wp_user_id INTEGER,
                wp_email VARCHAR(100),
                wp_linked_at DATETIME
            )
        """)
        
        # Ensure all columns exist (handle partial/old table schemas)
        # Get existing columns
        cursor.execute("PRAGMA table_info(user)")
        existing_cols = {row[1] for row in cursor.fetchall()}
        
        required_cols = {
            'last_login': 'DATETIME',
            'wp_user_id': 'INTEGER', 
            'wp_email': 'VARCHAR(100)',
            'wp_linked_at': 'DATETIME'
        }
        
        for col, col_type in required_cols.items():
            if col not in existing_cols:
                try:
                    cursor.execute(f"ALTER TABLE user ADD COLUMN {col} {col_type}")
                except sqlite3.OperationalError:
                    pass  # Column might already exist
        
        now = datetime.now().isoformat()
        password_hash = generate_password_hash(password)
        
        # Check if admin user exists
        cursor.execute("SELECT id FROM user WHERE username = 'admin'")
        existing = cursor.fetchone()
        
        # Set password_changed based on whether it's a custom password
        is_custom = password != "admin"
        
        if existing:
            # Update existing admin
            cursor.execute("""
                UPDATE user SET password_hash = ?, password_changed = ?, role = 'admin', updated_at = ?
                WHERE username = 'admin'
            """, (password_hash, 1 if is_custom else 0, now))
        else:
            # Insert new admin user
            cursor.execute("""
                INSERT INTO user (username, password_hash, role, enabled, password_changed, created_at, updated_at)
                VALUES ('admin', ?, 'admin', 1, ?, ?, ?)
            """, (password_hash, 1 if is_custom else 0, now, now))
        
        conn.commit()
        conn.close()
        
        if is_custom:
            console.print("[green]✓[/green] Admin password set")
        else:
            console.print("[green]✓[/green] Admin user created (default: admin/admin)")
        
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] Could not set admin password: {e}")


def read_ssh_key_file(key_path: str) -> Optional[str]:
    """Read SSH key content from a file path."""
    try:
        key_path = os.path.expanduser(key_path)
        if os.path.exists(key_path):
            with open(key_path, 'r') as f:
                content = f.read().strip()
            # Validate it looks like an SSH key
            if content.startswith('-----BEGIN') and 'PRIVATE KEY' in content:
                return content
            else:
                console.print(f"[yellow]⚠[/yellow] File {key_path} doesn't appear to be a valid SSH private key")
                return None
        else:
            console.print(f"[yellow]⚠[/yellow] SSH key file not found: {key_path}")
            return None
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] Could not read SSH key: {e}")
        return None


def create_ssh_key_in_database(name: str, key_content: str, db_path: Path) -> Optional[int]:
    """Create an SSH key entry in the database and return its ID."""
    import sqlite3
    import hashlib
    import base64
    from datetime import datetime
    
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Create ssh_key table if needed (matching Flask's SSHKey model)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ssh_key (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(50) NOT NULL UNIQUE,
                key_content TEXT NOT NULL,
                fingerprint VARCHAR(100),
                created_at DATETIME,
                updated_at DATETIME
            )
        """)
        
        # Generate fingerprint
        fingerprint = None
        try:
            # Extract the base64 part of the key for fingerprint
            lines = key_content.strip().split('\n')
            key_data = ''.join(line for line in lines if not line.startswith('-----'))
            key_bytes = base64.b64decode(key_data)
            fingerprint = hashlib.sha256(key_bytes).hexdigest()[:32]
        except:
            pass
        
        now = datetime.now().isoformat()
        
        # Check if key with this name exists
        cursor.execute("SELECT id FROM ssh_key WHERE name = ?", (name,))
        existing = cursor.fetchone()
        
        if existing:
            # Update existing key
            cursor.execute("""
                UPDATE ssh_key SET key_content = ?, fingerprint = ?, updated_at = ?
                WHERE name = ?
            """, (key_content, fingerprint, now, name))
            key_id = existing[0]
        else:
            # Insert new key
            cursor.execute("""
                INSERT INTO ssh_key (name, key_content, fingerprint, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
            """, (name, key_content, fingerprint, now, now))
            key_id = cursor.lastrowid
        
        conn.commit()
        conn.close()
        
        console.print(f"[green]✓[/green] SSH key '{name}' stored in database")
        return key_id
        
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] Could not store SSH key: {e}")
        return None


def setup_https_access(local_ip: str) -> Optional[str]:
    """Set up HTTPS reverse proxy with optional domain."""
    from .reverse_proxy import setup_reverse_proxy
    
    # Ask about domain
    use_domain = questionary.confirm(
        "Do you have a domain name pointing to this server?",
        default=False,
        style=custom_style
    ).ask()
    
    domain = None
    email = None
    use_letsencrypt = False
    
    if use_domain:
        domain = questionary.text(
            "Domain name (e.g., ipmi.example.com):",
            validate=lambda x: True if (len(x) > 0 and '.' in x) else "Please enter a valid domain (e.g., ipmi.example.com)",
            style=custom_style
        ).ask()
        
        use_letsencrypt = questionary.confirm(
            "Use Let's Encrypt for a free trusted certificate?",
            default=True,
            style=custom_style
        ).ask()
        
        if use_letsencrypt:
            console.print("[dim]Let's Encrypt requires ports 80 and 443 to be open.[/dim]")
            email = questionary.text(
                "Email for Let's Encrypt notifications:",
                validate=lambda x: '@' in x,
                style=custom_style
            ).ask()
    
    # Check if dc-overview/grafana is installed
    grafana_enabled = False
    prometheus_enabled = False
    try:
        import subprocess
        result = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True)
        if "grafana" in result.stdout:
            grafana_enabled = True
            prometheus_enabled = True
            console.print("[dim]Detected DC Overview (Grafana/Prometheus) - will include in reverse proxy[/dim]")
    except Exception:
        pass
    
    # Set up reverse proxy
    console.print("\n[dim]Setting up reverse proxy...[/dim]")
    
    try:
        setup_reverse_proxy(
            domain=domain,
            email=email,
            site_name="IPMI Monitor",
            grafana_enabled=grafana_enabled,
            prometheus_enabled=prometheus_enabled,
            use_letsencrypt=use_letsencrypt,
        )
        return domain
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] Reverse proxy setup failed: {e}")
        console.print("[dim]You can set it up later with: sudo ipmi-monitor setup-ssl[/dim]")
        return None


def install_service():
    """Install and start systemd service."""
    service = """[Unit]
Description=IPMI Monitor - Server Health Monitoring
After=network.target

[Service]
Type=simple
User=root
Environment=IPMI_MONITOR_CONFIG=/etc/ipmi-monitor
Environment=SERVERS_CONFIG_FILE=/etc/ipmi-monitor/servers.yaml
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


def show_summary(servers: List[Dict], local_ip: str, port: int, ai_enabled: bool, domain: Optional[str] = None):
    """Show setup summary."""
    console.print()
    console.print(Panel(
        "[bold green]✓ Setup Complete![/bold green]",
        border_style="green"
    ))
    
    table = Table(title="Your IPMI Monitor Setup", show_header=False)
    table.add_column("", style="dim")
    table.add_column("")
    
    if domain:
        table.add_row("Web Interface", f"https://{domain}/ipmi/")
    else:
        table.add_row("Web Interface", f"https://{local_ip}/ipmi/" if Path("/etc/nginx/sites-enabled/ipmi-monitor").exists() else f"http://{local_ip}:{port}")
    table.add_row("Servers Monitored", str(len(servers)))
    table.add_row("AI Insights", "Enabled ✓" if ai_enabled else "Not configured")
    table.add_row("Config Directory", "/etc/ipmi-monitor")
    table.add_row("HTTPS", "Enabled ✓" if domain or Path("/etc/nginx/sites-enabled/ipmi-monitor").exists() else "Not configured")
    
    console.print(table)
    
    console.print("\n[bold]Monitored Servers:[/bold]")
    for srv in servers:
        ssh_info = f" + SSH" if srv.get("server_ip") else ""
        bmc_ip = srv.get('bmc_ip', srv.get('server_ip', 'unknown'))
        console.print(f"  • {srv['name']} - BMC: {bmc_ip}{ssh_info}")
    
    console.print("\n[bold]Commands:[/bold]")
    console.print("  [cyan]ipmi-monitor status[/cyan]        - Check service status")
    console.print("  [cyan]ipmi-monitor add-server[/cyan]    - Add another server")
    console.print("  [cyan]ipmi-monitor setup-ssl[/cyan]     - Set up/update HTTPS")
    
    if domain:
        console.print(f"\n[bold]Open your browser:[/bold] [cyan]https://{domain}/ipmi/[/cyan]")
    elif Path("/etc/nginx/sites-enabled/ipmi-monitor").exists():
        console.print(f"\n[bold]Open your browser:[/bold] [cyan]https://{local_ip}/ipmi/[/cyan]")
    else:
        console.print(f"\n[bold]Open your browser:[/bold] [cyan]http://{local_ip}:{port}[/cyan]")


if __name__ == "__main__":
    run_quickstart()
