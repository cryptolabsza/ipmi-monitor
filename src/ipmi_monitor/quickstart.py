"""
IPMI Monitor QuickStart - One command Docker deployment

The client runs:
    pip install ipmi-monitor
    sudo ipmi-monitor quickstart

And answers a few questions. Docker containers are deployed automatically.
"""

import os
import subprocess
import sys
import secrets
import shutil
from pathlib import Path
from typing import Optional, List, Dict

import questionary
from questionary import Style
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
import yaml
from jinja2 import Environment, PackageLoader, select_autoescape

from ipmi_monitor import __git_branch__

console = Console()

def get_default_docker_tag() -> str:
    """Determine default Docker image tag - always defaults to 'latest' (stable).
    
    Users who want dev should explicitly select it. The stable/latest channel
    is the recommended default for production use.
    """
    # Always default to stable/latest - users can opt-in to dev if desired
    return 'latest'

custom_style = Style([
    ('qmark', 'fg:cyan bold'),
    ('question', 'bold'),
    ('answer', 'fg:cyan'),
    ('pointer', 'fg:cyan bold'),
    ('highlighted', 'fg:cyan bold'),
    ('selected', 'fg:green'),
])

# Config directory for Docker deployment
CONFIG_DIR = Path("/etc/ipmi-monitor")


def get_jinja_env():
    """Get Jinja2 environment for templates"""
    return Environment(
        loader=PackageLoader("ipmi_monitor", "templates"),
        autoescape=select_autoescape(["html", "xml"]),
    )


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


def check_docker_installed() -> bool:
    """Check if Docker is installed and running."""
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
        if result.returncode != 0:
            return False
        
        # Check if Docker daemon is running
        result = subprocess.run(["docker", "info"], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def install_docker():
    """Install Docker using the official convenience script."""
    console.print("\n[bold]Installing Docker...[/bold]\n")
    
    try:
        # Download and run Docker install script
        with Progress(SpinnerColumn(), TextColumn("Downloading Docker installer..."), console=console) as progress:
            progress.add_task("", total=None)
            subprocess.run(
                ["curl", "-fsSL", "https://get.docker.com", "-o", "/tmp/get-docker.sh"],
                check=True, capture_output=True
            )
        
        with Progress(SpinnerColumn(), TextColumn("Installing Docker (this may take a few minutes)..."), console=console) as progress:
            progress.add_task("", total=None)
            subprocess.run(["sh", "/tmp/get-docker.sh"], check=True, capture_output=True)
        
        # Start Docker service
        subprocess.run(["systemctl", "start", "docker"], capture_output=True)
        subprocess.run(["systemctl", "enable", "docker"], capture_output=True)
        
        console.print("[green]✓[/green] Docker installed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        console.print(f"[red]✗[/red] Docker installation failed: {e}")
        console.print("[dim]Please install Docker manually: https://docs.docker.com/engine/install/[/dim]")
        return False


def check_docker_compose_installed() -> bool:
    """Check if Docker Compose is available."""
    try:
        # Try docker compose (v2)
        result = subprocess.run(["docker", "compose", "version"], capture_output=True, text=True)
        if result.returncode == 0:
            return True
        
        # Try docker-compose (v1)
        result = subprocess.run(["docker-compose", "--version"], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def run_docker_compose(config_dir: Path, command: str = "up -d"):
    """Run docker compose command."""
    # Try docker compose (v2) first, then docker-compose (v1)
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(config_dir / "docker-compose.yml")] + command.split(),
            capture_output=True, text=True, cwd=str(config_dir)
        )
        if result.returncode == 0:
            return True, result.stdout
        
        # Try v1 syntax
        result = subprocess.run(
            ["docker-compose", "-f", str(config_dir / "docker-compose.yml")] + command.split(),
            capture_output=True, text=True, cwd=str(config_dir)
        )
        return result.returncode == 0, result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return False, str(e)


def generate_secret_key() -> str:
    """Generate a secure random secret key."""
    return secrets.token_hex(32)


def looks_like_ip(s: str) -> bool:
    """Check if string looks like an IP address."""
    if not s:
        return False
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def detect_dc_overview() -> Optional[Dict]:
    """Detect if DC Overview is installed."""
    dc_config_dir = Path("/etc/dc-overview")
    
    if not dc_config_dir.exists():
        return None
    
    # Check for config file or running container
    config_file = dc_config_dir / "config.json"
    prometheus_file = dc_config_dir / "prometheus.yml"
    
    # Check for running container
    try:
        result = subprocess.run(
            ["docker", "inspect", "dc-overview"],
            capture_output=True
        )
        container_running = result.returncode == 0
    except:
        container_running = False
    
    if not (config_file.exists() or prometheus_file.exists() or container_running):
        return None
    
    return {
        "config_dir": dc_config_dir,
        "config_file": config_file if config_file.exists() else None,
        "prometheus_file": prometheus_file if prometheus_file.exists() else None,
        "ssh_keys_dir": dc_config_dir / "ssh_keys" if (dc_config_dir / "ssh_keys").exists() else None,
        "container_running": container_running
    }


def detect_existing_proxy() -> Optional[Dict]:
    """Detect if cryptolabs-proxy is already running and get its config."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "cryptolabs-proxy", "--format", "{{.State.Status}}"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip() == "running":
            config = {"running": True}
            
            # Try to get domain from nginx config
            nginx_conf = CONFIG_DIR / "nginx.conf"
            if nginx_conf.exists():
                import re
                content = nginx_conf.read_text()
                match = re.search(r'server_name\s+([^;]+);', content)
                if match:
                    domain = match.group(1).strip()
                    # Filter out placeholder values
                    if domain and domain not in ('_', 'localhost', ''):
                        config["domain"] = domain
                
                # Check SSL mode
                if '/etc/letsencrypt/' in content:
                    config["ssl_mode"] = "letsencrypt"
                elif '/etc/nginx/ssl/' in content or 'ssl_certificate' in content:
                    config["ssl_mode"] = "self_signed"
            
            # Check if SSL certs exist
            ssl_dir = CONFIG_DIR / "ssl"
            if ssl_dir.exists():
                config["ssl_dir"] = str(ssl_dir)
            
            return config
    except Exception:
        pass
    return None


def add_ipmi_route_to_proxy():
    """Add /ipmi/ route to existing cryptolabs-proxy nginx config."""
    import re
    
    # Find the nginx config
    nginx_paths = [
        CONFIG_DIR / "nginx.conf",
        Path("/etc/dc-overview/nginx.conf"),
        Path("/etc/cryptolabs-proxy/nginx.conf"),
    ]
    
    nginx_path = None
    for path in nginx_paths:
        if path.exists():
            nginx_path = path
            break
    
    if not nginx_path:
        console.print("[yellow]⚠[/yellow] Could not find proxy nginx config")
        return
    
    content = nginx_path.read_text()
    
    # Check if /ipmi/ route already exists
    if '/ipmi/' in content:
        console.print("[green]✓[/green] IPMI route already configured in proxy")
        return
    
    # Add /ipmi/ location block
    ipmi_location = '''
        # IPMI Monitor
        location /ipmi/ {
            proxy_pass http://ipmi-monitor:5000/;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Script-Name /ipmi;
            proxy_read_timeout 300s;
            proxy_connect_timeout 10s;
        }
'''
    
    # Find insertion point - before the root location / block
    root_location_pattern = r'(\s+# Fleet Management Landing Page.*?\n\s+location / \{)'
    match = re.search(root_location_pattern, content, re.DOTALL)
    
    if match:
        insert_pos = match.start()
        new_content = content[:insert_pos] + ipmi_location + content[insert_pos:]
    else:
        # Try simpler pattern
        alt_pattern = r'(\s+location / \{[^}]+\})\s*\n\s*\}\s*\n\}'
        match = re.search(alt_pattern, content, re.DOTALL)
        if match:
            insert_pos = match.start()
            new_content = content[:insert_pos] + ipmi_location + content[insert_pos:]
        else:
            # Try to insert before "# Default" or last location block
            default_pattern = r'(\s+# Default.*?\n\s+location / \{)'
            match = re.search(default_pattern, content, re.DOTALL)
            if match:
                insert_pos = match.start()
                new_content = content[:insert_pos] + ipmi_location + content[insert_pos:]
            else:
                console.print("[yellow]⚠[/yellow] Could not find insertion point in nginx.conf")
                return
    
    # Write updated config
    nginx_path.write_text(new_content)
    console.print(f"[green]✓[/green] Added /ipmi/ route to proxy")
    
    # Reload nginx in the proxy container
    try:
        result = subprocess.run(
            ["docker", "exec", "cryptolabs-proxy", "nginx", "-t"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            subprocess.run(
                ["docker", "exec", "cryptolabs-proxy", "nginx", "-s", "reload"],
                capture_output=True, text=True, timeout=10
            )
            console.print("[green]✓[/green] Proxy configuration reloaded")
        else:
            console.print(f"[yellow]⚠[/yellow] Nginx config test failed")
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] Could not reload proxy: {e}")


def import_dc_overview_config(dc_config: Dict) -> tuple:
    """Import SSH credentials and server IPs from DC Overview.
    
    Returns:
        Tuple of (ssh_keys, servers)
        - servers have server_ip but need BMC IP to be added by user
    """
    import yaml
    
    ssh_keys = []
    servers = []
    
    # Try to read from prometheus.yml for server targets
    prometheus_file = dc_config.get("prometheus_file")
    if prometheus_file and prometheus_file.exists():
        try:
            with open(prometheus_file) as f:
                prom_config = yaml.safe_load(f)
            
            # Extract targets from scrape configs
            for job in prom_config.get("scrape_configs", []):
                job_name = job.get("job_name", "")
                if job_name in ["prometheus", "local"]:
                    continue  # Skip internal targets
                
                for static_config in job.get("static_configs", []):
                    labels = static_config.get("labels", {})
                    instance_name = labels.get("instance", job_name)
                    
                    for target in static_config.get("targets", []):
                        # Extract IP from target (format: ip:port)
                        ip = target.split(":")[0]
                        if looks_like_ip(ip):
                            # Check if we already have this server
                            if not any(s.get("server_ip") == ip for s in servers):
                                servers.append({
                                    "name": instance_name,
                                    "server_ip": ip,
                                    "ssh_user": "root",
                                    "ssh_port": 22
                                })
            
            if servers:
                console.print(f"[green]✓[/green] Found {len(servers)} servers from DC Overview")
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Could not parse prometheus.yml: {e}")
    
    # Try to read from config.json
    config_file = dc_config.get("config_file")
    if config_file and config_file.exists():
        try:
            import json
            with open(config_file) as f:
                config = json.load(f)
            console.print(f"[dim]DC Overview config loaded[/dim]")
        except Exception as e:
            pass
    
    # Copy SSH keys if available
    ssh_keys_dir = dc_config.get("ssh_keys_dir")
    if ssh_keys_dir and ssh_keys_dir.exists():
        ipmi_ssh_dir = CONFIG_DIR / "ssh_keys"
        ipmi_ssh_dir.mkdir(parents=True, exist_ok=True)
        
        key_count = 0
        for key_file in ssh_keys_dir.iterdir():
            if key_file.is_file() and not key_file.name.endswith('.pub'):
                try:
                    dest = ipmi_ssh_dir / key_file.name
                    shutil.copy2(key_file, dest)
                    os.chmod(dest, 0o600)
                    ssh_keys.append({
                        "name": key_file.stem,
                        "path": str(dest)
                    })
                    key_count += 1
                except Exception as e:
                    pass
        
        if key_count > 0:
            console.print(f"[green]✓[/green] Copied {key_count} SSH keys from DC Overview")
    
    return ssh_keys, servers


def run_quickstart():
    """Main quickstart wizard - deploys via Docker."""
    check_root()
    
    console.print()
    console.print(Panel(
        "[bold cyan]IPMI Monitor - Quick Setup[/bold cyan]\n\n"
        "Monitor your servers' IPMI/BMC health, temperatures, and sensors.\n"
        "Just answer a few questions and everything will be configured.\n\n"
        "[dim]Deploys via Docker with automatic updates via Watchtower.[/dim]\n"
        "[dim]Press Ctrl+C to cancel at any time.[/dim]",
        border_style="cyan"
    ))
    console.print()
    
    # Check Docker
    if not check_docker_installed():
        console.print("[yellow]Docker is not installed.[/yellow]")
        install = questionary.confirm(
            "Install Docker now?",
            default=True,
            style=custom_style
        ).ask()
        
        if install:
            if not install_docker():
                console.print("[red]Cannot continue without Docker.[/red]")
                return
        else:
            console.print("[red]Cannot continue without Docker.[/red]")
            console.print("[dim]Install Docker manually: https://docs.docker.com/engine/install/[/dim]")
            return
    else:
        console.print("[green]✓[/green] Docker is installed")
    
    # Detect environment
    local_ip = get_local_ip()
    hostname = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()
    
    console.print(f"[dim]Detected: {hostname} ({local_ip})[/dim]\n")
    
    # ============ Check for DC Overview ============
    dc_config = detect_dc_overview()
    imported_servers = []
    imported_ssh_keys = []
    
    if dc_config:
        console.print("[green]✓[/green] DC Overview detected!\n")
        
        import_from_dc = questionary.confirm(
            "Import server IPs and SSH keys from DC Overview?",
            default=True,
            style=custom_style
        ).ask()
        
        if import_from_dc:
            imported_ssh_keys, imported_servers = import_dc_overview_config(dc_config)
            
            if imported_servers:
                console.print(f"\n[bold]Link BMC IPs to Imported Servers[/bold]")
                console.print("[dim]For each server, provide the BMC/IPMI IP address.[/dim]\n")
                
                # Ask for BMC IP for each imported server
                for srv in imported_servers:
                    bmc_ip = questionary.text(
                        f"BMC IP for {srv['name']} (Server: {srv.get('server_ip', 'N/A')}):",
                        validate=lambda x: looks_like_ip(x) or x == "" or "Invalid IP format",
                        style=custom_style
                    ).ask()
                    
                    if bmc_ip and looks_like_ip(bmc_ip):
                        srv["bmc_ip"] = bmc_ip
                        console.print(f"  [green]✓[/green] {srv['name']}: {bmc_ip}")
                    else:
                        console.print(f"  [yellow]⚠[/yellow] {srv['name']}: Skipped (no BMC IP)")
                
                # Filter servers that have BMC IPs
                imported_servers = [s for s in imported_servers if s.get("bmc_ip")]
                console.print(f"\n[green]✓[/green] {len(imported_servers)} servers linked with BMC IPs")
    
    # ============ Step 1: Add servers ============
    console.print("\n[bold]Step 1: Add Servers to Monitor[/bold]\n")
    
    # Build choices based on whether we have imported servers
    add_choices = []
    if imported_servers:
        add_choices.append(questionary.Choice(
            f"Use imported servers only ({len(imported_servers)} servers)", 
            value="imported"
        ))
        add_choices.append(questionary.Choice(
            "Add more servers (in addition to imported)", 
            value="add_more"
        ))
    
    add_choices.extend([
        questionary.Choice("Just one server", value="single"),
        questionary.Choice("Multiple servers (same credentials)", value="bulk"),
    ])
    
    server_count = questionary.select(
        "How do you want to add servers?",
        choices=add_choices,
        style=custom_style
    ).ask()
    
    if server_count is None:
        console.print("[yellow]Cancelled.[/yellow]")
        return
    
    servers = []
    
    if server_count == "imported":
        # Use only imported servers
        servers = imported_servers
    elif server_count == "add_more":
        # Start with imported, then add more
        servers = imported_servers.copy()
        more_servers = add_servers_bulk()
        servers.extend(more_servers)
    elif server_count == "single":
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
    
    admin_password = "admin"
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
    
    # ============ Step 5: Auto-Updates ============
    console.print("\n[bold]Step 5: Auto-Updates[/bold]\n")
    console.print("[dim]Watchtower automatically updates IPMI Monitor when new versions are released.[/dim]\n")
    
    enable_watchtower = questionary.confirm(
        "Enable automatic updates? (recommended)",
        default=True,
        style=custom_style
    ).ask()
    
    if enable_watchtower is None:
        enable_watchtower = True
    
    # ============ Step 5b: SSH Log Collection ============
    # Only ask if servers have SSH configured
    has_ssh_servers = any(s.get('server_ip') for s in servers)
    enable_ssh_logs = False
    
    if has_ssh_servers:
        console.print("\n[bold]Step 5b: SSH Log Collection (Optional)[/bold]\n")
        console.print("[dim]Collect system logs from servers via SSH (dmesg, syslog, GPU errors).[/dim]")
        console.print("[dim]Useful for troubleshooting hardware issues.[/dim]\n")
        
        enable_ssh_logs = questionary.confirm(
            "Enable SSH log collection?",
            default=False,
            style=custom_style
        ).ask()
        
        if enable_ssh_logs is None:
            enable_ssh_logs = False
    
    # ============ Step 6: Image Channel ============
    console.print("\n[bold]Step 6: Image Channel[/bold]\n")
    console.print("[dim]Choose which Docker image channel to use.[/dim]\n")
    
    image_tag = questionary.select(
        "Docker image channel:",
        choices=[
            questionary.Choice("stable (latest) - Production ready [recommended]", value="latest"),
            questionary.Choice("dev - Latest development features", value="dev"),
        ],
        default="latest",
        style=custom_style
    ).ask()
    
    if image_tag is None:
        image_tag = default_tag
    
    # ============ Step 7: HTTPS Access (Optional) ============
    console.print("\n[bold]Step 7: HTTPS Access (Optional)[/bold]\n")
    console.print("[dim]Set up reverse proxy with SSL for secure remote access.[/dim]")
    console.print("[dim]Uses CryptoLabs Proxy with Fleet Management landing page.[/dim]\n")
    
    # Check for existing proxy
    existing_proxy = detect_existing_proxy()
    proxy_already_running = existing_proxy and existing_proxy.get("running")
    
    domain = None
    letsencrypt_email = None
    use_letsencrypt = False
    setup_proxy = False
    
    if proxy_already_running:
        console.print("[bold green]✓ CryptoLabs Proxy Already Running![/bold green]")
        console.print("[dim]Using existing proxy configuration.[/dim]\n")
        
        # Show detected config
        if existing_proxy.get("domain"):
            console.print(f"  Domain: [cyan]{existing_proxy['domain']}[/cyan]")
            domain = existing_proxy["domain"]
        
        ssl_mode = existing_proxy.get("ssl_mode", "self_signed")
        if ssl_mode == "letsencrypt":
            console.print("  SSL: [cyan]Let's Encrypt[/cyan]")
            use_letsencrypt = True
        else:
            console.print("  SSL: [cyan]Self-signed certificate[/cyan]")
        
        console.print("\n[dim]No additional proxy configuration needed.[/dim]")
        setup_proxy = True  # Mark as using proxy, but won't create new one
    else:
        setup_proxy = questionary.confirm(
            "Set up HTTPS reverse proxy?",
            default=True,
            style=custom_style
        ).ask()
        
        if setup_proxy is None:
            setup_proxy = False
        
        if setup_proxy:
            use_domain = questionary.confirm(
                "Do you have a domain name pointing to this server?",
                default=False,
                style=custom_style
            ).ask()
            
            if use_domain:
                domain = questionary.text(
                    "Domain name (e.g., ipmi.example.com):",
                    validate=lambda x: True if (len(x) > 0 and '.' in x) else "Please enter a valid domain",
                    style=custom_style
                ).ask()
                
                use_letsencrypt = questionary.confirm(
                    "Use Let's Encrypt for a free trusted certificate?",
                    default=True,
                    style=custom_style
                ).ask()
                
                if use_letsencrypt:
                    console.print("[dim]Let's Encrypt requires ports 80 and 443 to be open.[/dim]")
                    letsencrypt_email = questionary.text(
                        "Email for Let's Encrypt notifications:",
                        validate=lambda x: '@' in x,
                        style=custom_style
                    ).ask()
    
    # ============ Step 8: Deploy ============
    console.print("\n[bold]Step 8: Deploying IPMI Monitor[/bold]\n")
    
    # Create config directory
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    
    # Extract default IPMI credentials from first server (if available)
    default_ipmi_user = "admin"
    default_ipmi_pass = ""
    for srv in servers:
        if srv.get("bmc_user"):
            default_ipmi_user = srv["bmc_user"]
        if srv.get("bmc_password"):
            default_ipmi_pass = srv["bmc_password"]
            break
    
    # Handle SSH keys - copy to config directory
    ssh_keys_dir = CONFIG_DIR / "ssh_keys"
    ssh_key_map = {}  # original_path -> key_name
    ssh_key_counter = 0
    
    for srv in servers:
        if srv.get("ssh_key"):
            key_path = srv["ssh_key"]
            if key_path not in ssh_key_map:
                key_content = read_ssh_key_file(key_path)
                if key_content:
                    ssh_keys_dir.mkdir(parents=True, exist_ok=True)
                    ssh_key_counter += 1
                    key_name = f"key-{ssh_key_counter}" if ssh_key_counter > 1 else "default-key"
                    key_file = ssh_keys_dir / f"{key_name}.pem"
                    key_file.write_text(key_content)
                    os.chmod(key_file, 0o600)
                    ssh_key_map[key_path] = key_name
                    console.print(f"[green]✓[/green] SSH key copied: {key_name}")
    
    # Generate servers.yaml
    generate_servers_yaml(servers, CONFIG_DIR, ssh_key_map)
    console.print(f"[green]✓[/green] Server configuration saved")
    
    # Generate .env file
    env_content = f"""# IPMI Monitor Environment Configuration
# Generated by quickstart

# Admin credentials
ADMIN_PASS={admin_password}
SECRET_KEY={generate_secret_key()}

# Default IPMI credentials
IPMI_USER={default_ipmi_user}
IPMI_PASS={default_ipmi_pass}

# SSH Log Collection
ENABLE_SSH_LOGS={str(enable_ssh_logs).lower()}
"""
    if license_key:
        env_content += f"\n# AI Features\nAI_LICENSE_KEY={license_key}\n"
    
    (CONFIG_DIR / ".env").write_text(env_content)
    os.chmod(CONFIG_DIR / ".env", 0o600)  # Protect credentials
    console.print(f"[green]✓[/green] Environment configuration saved")
    
    # Generate docker-compose.yml
    env = get_jinja_env()
    template = env.get_template("docker-compose.yml.j2")
    
    # Determine proxy image tag (use dev if ipmi-monitor is using dev)
    proxy_tag = 'dev' if image_tag == 'dev' else 'latest'
    
    # image_tag is already set by user selection in Step 6
    # Get certbot email (might be set even if LE initially failed due to rate limiting)
    certbot_email = letsencrypt_email if 'letsencrypt_email' in dir() and letsencrypt_email else None
    
    # Only include proxy in docker-compose if we're setting up a new one
    start_new_proxy = setup_proxy and not proxy_already_running
    
    compose_content = template.render(
        image_tag=image_tag,
        proxy_tag=proxy_tag,
        web_port=web_port,
        app_name="IPMI Monitor",
        poll_interval=300,
        ai_enabled=enable_ai,
        enable_watchtower=enable_watchtower,
        enable_proxy=start_new_proxy,
        use_existing_proxy=proxy_already_running,  # Use external network if proxy exists
        use_letsencrypt=use_letsencrypt,
        letsencrypt_domain=domain if use_letsencrypt else None,
        domain=domain,
        certbot_email=certbot_email,  # For auto-renewal/retry
        ssh_keys_dir=bool(ssh_key_map),
        network_mode=None,  # Use bridge network
    )
    
    (CONFIG_DIR / "docker-compose.yml").write_text(compose_content)
    console.print(f"[green]✓[/green] Docker Compose configuration saved")
    
    # Generate nginx config if proxy enabled (and not already running)
    if setup_proxy and not proxy_already_running:
        # Always generate self-signed cert first (nginx needs certs to start)
        generate_self_signed_cert(CONFIG_DIR / "ssl", domain or local_ip)
        
        # Create certbot directories (needed even for self-signed, for future LE)
        (CONFIG_DIR / "certbot" / "conf").mkdir(parents=True, exist_ok=True)
        (CONFIG_DIR / "certbot" / "www").mkdir(parents=True, exist_ok=True)
        
        # Generate nginx config for cryptolabs-proxy
        nginx_content = generate_proxy_nginx_config(
            domain=domain or local_ip,
            use_letsencrypt=use_letsencrypt,
        )
        (CONFIG_DIR / "nginx.conf").write_text(nginx_content)
        
        console.print(f"[green]✓[/green] Proxy configuration saved (self-signed)")
    elif proxy_already_running:
        console.print(f"[green]✓[/green] Using existing proxy configuration")
        # Add /ipmi/ route to existing proxy
        add_ipmi_route_to_proxy()
    
    # Pull Docker images
    with Progress(SpinnerColumn(), TextColumn(f"Pulling IPMI Monitor image ({image_tag})..."), console=console) as progress:
        progress.add_task("", total=None)
        result = subprocess.run(
            ["docker", "pull", f"ghcr.io/cryptolabsza/ipmi-monitor:{image_tag}"],
            capture_output=True, text=True
        )
    
    if result.returncode == 0:
        console.print(f"[green]✓[/green] IPMI Monitor image pulled")
    else:
        console.print(f"[yellow]⚠[/yellow] Image pull warning: {result.stderr[:100]}")
    
    # Pull proxy image if proxy is enabled and not already running
    if setup_proxy and not proxy_already_running:
        with Progress(SpinnerColumn(), TextColumn(f"Pulling CryptoLabs Proxy image ({proxy_tag})..."), console=console) as progress:
            progress.add_task("", total=None)
            result = subprocess.run(
                ["docker", "pull", f"ghcr.io/cryptolabsza/cryptolabs-proxy:{proxy_tag}"],
                capture_output=True, text=True
            )
        
        if result.returncode == 0:
            console.print(f"[green]✓[/green] CryptoLabs Proxy image pulled")
        else:
            console.print(f"[yellow]⚠[/yellow] Proxy image pull warning: {result.stderr[:100]}")
    
    # Start containers
    with Progress(SpinnerColumn(), TextColumn("Starting containers..."), console=console) as progress:
        progress.add_task("", total=None)
        success, output = run_docker_compose(CONFIG_DIR, "up -d")
    
    if success:
        console.print(f"[green]✓[/green] IPMI Monitor started")
    else:
        console.print(f"[red]✗[/red] Failed to start: {output}")
        return
    
    # Handle Let's Encrypt certificate (only for new proxy setup)
    if setup_proxy and not proxy_already_running and use_letsencrypt and domain and letsencrypt_email:
        console.print("\n[dim]Obtaining Let's Encrypt certificate...[/dim]")
        obtain_letsencrypt_cert(CONFIG_DIR, domain, letsencrypt_email)
    
    # Show summary
    saved_servers = [s for s in servers if s.get("bmc_ip")]
    show_summary(saved_servers, local_ip, int(web_port), license_key is not None, domain, setup_proxy)


def generate_servers_yaml(servers: List[Dict], config_dir: Path, ssh_key_map: Dict[str, str]):
    """Generate servers.yaml for Docker volume mount."""
    
    # Convert to Flask format
    flask_servers = []
    for srv in servers:
        flask_srv = {
            "name": srv.get("name", f"server-{srv.get('bmc_ip', 'unknown')}"),
        }
        
        if srv.get("bmc_ip"):
            flask_srv["bmc_ip"] = srv["bmc_ip"]
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
        if srv.get("ssh_key") and srv["ssh_key"] in ssh_key_map:
            # Reference the key name (Flask will look in /app/ssh_keys/)
            flask_srv["ssh_key_name"] = ssh_key_map[srv["ssh_key"]]
        if srv.get("ssh_port"):
            flask_srv["ssh_port"] = srv["ssh_port"]
        
        flask_servers.append(flask_srv)
    
    # Filter servers without bmc_ip
    valid_servers = [srv for srv in flask_servers if srv.get('bmc_ip')]
    skipped = len(flask_servers) - len(valid_servers)
    if skipped > 0:
        console.print(f"[yellow]⚠[/yellow] Skipped {skipped} server(s) without BMC IP")
    
    # Write YAML with name first (Flask parser requirement)
    with open(config_dir / "servers.yaml", "w") as f:
        f.write("servers:\n")
        for srv in valid_servers:
            f.write(f"  - name: {srv.get('name', 'unknown')}\n")
            if srv.get('bmc_ip'):
                f.write(f"    bmc_ip: {srv['bmc_ip']}\n")
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


def generate_self_signed_cert(ssl_dir: Path, domain: str):
    """Generate self-signed SSL certificate."""
    ssl_dir.mkdir(parents=True, exist_ok=True)
    
    cert_path = ssl_dir / "server.crt"
    key_path = ssl_dir / "server.key"
    
    cmd = [
        "openssl", "req", "-x509", "-nodes",
        "-days", "365",
        "-newkey", "rsa:2048",
        "-keyout", str(key_path),
        "-out", str(cert_path),
        "-subj", f"/CN={domain}/O=CryptoLabs/C=ZA",
    ]
    
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        os.chmod(key_path, 0o600)
        console.print(f"[green]✓[/green] Self-signed certificate generated")
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] Could not generate certificate: {e}")


def generate_proxy_nginx_config(domain: str, use_letsencrypt: bool = False) -> str:
    """Generate nginx config for cryptolabs-proxy.
    
    This config routes /ipmi/ to the ipmi-monitor container and serves
    the Fleet Management landing page at /.
    
    Note: Only IPMI Monitor is included. Other services (dc-overview, grafana, 
    prometheus) will be added by dc-overview quickstart when installed.
    """
    
    ssl_cert = f"/etc/letsencrypt/live/{domain}/fullchain.pem" if use_letsencrypt else "/etc/nginx/ssl/server.crt"
    ssl_key = f"/etc/letsencrypt/live/{domain}/privkey.pem" if use_letsencrypt else "/etc/nginx/ssl/server.key"
    
    return f'''# CryptoLabs Proxy - Nginx Configuration
# Generated by: ipmi-monitor quickstart
# Note: Only IPMI Monitor routes are configured. Other services will be added
# when dc-overview is installed.

worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {{
    worker_connections 1024;
}}

http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent"';

    access_log /var/log/nginx/access.log main;
    sendfile on;
    keepalive_timeout 65;
    client_max_body_size 100M;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/json application/xml;

    # HTTP server - redirect to HTTPS
    server {{
        listen 80;
        server_name {domain};
        
        # Let's Encrypt ACME challenge
        location /.well-known/acme-challenge/ {{
            root /var/www/certbot;
        }}
        
        location / {{
            return 301 https://$host$request_uri;
        }}
    }}

    # HTTPS server
    server {{
        listen 443 ssl;
        http2 on;
        server_name {domain};

        ssl_certificate {ssl_cert};
        ssl_certificate_key {ssl_key};
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
        ssl_prefer_server_ciphers off;
        ssl_session_cache shared:SSL:10m;

        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Strict-Transport-Security "max-age=31536000" always;

        # Health check endpoint
        location /api/health {{
            default_type application/json;
            return 200 '{{"status":"ok","proxy":"running"}}';
        }}

        # Services health (for landing page) - only show installed services
        location /api/services {{
            default_type application/json;
            return 200 '{{"ipmi-monitor":{{"running":true,"url":"/ipmi/"}}}}';
        }}

        # IPMI Monitor at /ipmi/
        location /ipmi/ {{
            proxy_pass http://ipmi-monitor:5000/;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Script-Name /ipmi;
            proxy_read_timeout 300s;
            proxy_connect_timeout 10s;
            proxy_send_timeout 300s;
        }}

        # Fleet Management Landing Page at /
        location / {{
            root /usr/share/nginx/html;
            try_files $uri $uri/ /index.html;
        }}
    }}
}}
'''


def obtain_letsencrypt_cert(config_dir: Path, domain: str, email: str):
    """Obtain Let's Encrypt certificate using webroot method.
    
    This uses the already-running cryptolabs-proxy to serve ACME challenges,
    avoiding port conflicts with standalone mode.
    """
    certbot_dir = config_dir / "certbot"
    certbot_dir.mkdir(parents=True, exist_ok=True)
    (certbot_dir / "conf").mkdir(exist_ok=True)
    (certbot_dir / "www").mkdir(exist_ok=True)
    
    try:
        # Use webroot method - nginx serves the challenge files
        console.print("[dim]Running certbot with webroot method...[/dim]")
        result = subprocess.run([
            "docker", "run", "--rm",
            "-v", f"{certbot_dir}/conf:/etc/letsencrypt",
            "-v", f"{certbot_dir}/www:/var/www/certbot",
            "certbot/certbot", "certonly",
            "--webroot",
            "--webroot-path=/var/www/certbot",
            "-d", domain,
            "--email", email,
            "--agree-tos",
            "--non-interactive",
        ], capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            console.print(f"[green]✓[/green] Let's Encrypt certificate obtained")
            
            # Update nginx config to use Let's Encrypt certs
            nginx_content = generate_proxy_nginx_config(
                domain=domain,
                use_letsencrypt=True,
            )
            (config_dir / "nginx.conf").write_text(nginx_content)
            console.print(f"[green]✓[/green] Proxy config updated for Let's Encrypt")
            
            # Restart proxy to use new certs
            subprocess.run(["docker", "restart", "cryptolabs-proxy"], capture_output=True)
            console.print(f"[green]✓[/green] Proxy restarted with Let's Encrypt")
        else:
            error_msg = result.stderr[:300] if result.stderr else result.stdout[:300]
            console.print(f"[yellow]⚠[/yellow] Let's Encrypt failed: {error_msg}")
            console.print("[dim]Using self-signed certificate instead.[/dim]")
            console.print("[dim]You can retry later with: sudo ipmi-monitor setup-ssl[/dim]")
            
            # Fallback: Update nginx config to use self-signed certs
            nginx_content = generate_proxy_nginx_config(domain=domain, use_letsencrypt=False)
            (config_dir / "nginx.conf").write_text(nginx_content)
            subprocess.run(["docker", "restart", "cryptolabs-proxy"], capture_output=True)
            
    except subprocess.TimeoutExpired:
        console.print("[yellow]⚠[/yellow] Let's Encrypt timed out - using self-signed certificate")
        # Fallback: Update nginx config to use self-signed certs
        nginx_content = generate_proxy_nginx_config(domain=domain, use_letsencrypt=False)
        (config_dir / "nginx.conf").write_text(nginx_content)
        subprocess.run(["docker", "restart", "cryptolabs-proxy"], capture_output=True)
    except Exception as e:
        console.print(f"[yellow]⚠[/yellow] Let's Encrypt error: {e}")
        console.print("[dim]Using self-signed certificate instead.[/dim]")
        # Fallback: Update nginx config to use self-signed certs
        nginx_content = generate_proxy_nginx_config(domain=domain, use_letsencrypt=False)
        (config_dir / "nginx.conf").write_text(nginx_content)
        subprocess.run(["docker", "restart", "cryptolabs-proxy"], capture_output=True)


# ============================================================================
# Server Input Functions (kept from original - these are valuable)
# ============================================================================

def add_servers_bulk() -> List[Dict]:
    """Add multiple servers - import file or manual entry."""
    console.print(Panel(
        "[bold]Adding Multiple Servers[/bold]\n\n"
        "Choose how to add servers:\n"
        "  • [cyan]Import from file[/cyan] - Load from a text file\n"
        "  • [cyan]Paste text[/cyan] - Paste server list directly\n"
        "  • [cyan]Enter manually[/cyan] - Type IPs one by one",
        border_style="cyan"
    ))
    console.print()
    
    method = questionary.select(
        "How do you want to add servers?",
        choices=[
            questionary.Choice("Import from file (e.g., servers.txt)", value="file"),
            questionary.Choice("Paste text directly", value="paste"),
            questionary.Choice("Enter manually", value="manual"),
        ],
        style=custom_style
    ).ask()
    
    if method == "file":
        return import_servers_from_file()
    elif method == "paste":
        return import_servers_from_text()
    else:
        return add_servers_manual()


def import_servers_from_file() -> List[Dict]:
    """Import servers from a text file."""
    console.print(Panel(
        "[bold]Import from File[/bold]\n\n"
        "Enter the path to your server list file.\n"
        "The file should contain one server per line.\n\n"
        "[dim]Example: /root/servers.txt or ./servers.txt[/dim]",
        border_style="cyan"
    ))
    
    file_path = questionary.path(
        "Server list file:",
        style=custom_style
    ).ask()
    
    if not file_path:
        console.print("[yellow]No file selected[/yellow]")
        return []
    
    file_path = os.path.expanduser(file_path)
    
    if not os.path.exists(file_path):
        console.print(f"[red]File not found: {file_path}[/red]")
        return []
    
    try:
        with open(file_path, 'r') as f:
            lines = [line.strip() for line in f.readlines() if line.strip() and not line.strip().startswith('#')]
        
        if not lines:
            console.print("[yellow]File is empty or contains only comments[/yellow]")
            return []
        
        console.print(f"[green]✓[/green] Loaded {len(lines)} lines from {file_path}")
        return parse_ipmi_server_list(lines)
        
    except Exception as e:
        console.print(f"[red]Error reading file: {e}[/red]")
        return []


def import_servers_from_text() -> List[Dict]:
    """Import servers from pasted text."""
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
            server["server_ip"] = parts[0]
            if global_ssh_user:
                server["ssh_user"] = global_ssh_user
                server["ssh_password"] = global_ssh_pass
            if global_ipmi_user:
                server["bmc_user"] = global_ipmi_user
                server["bmc_password"] = global_ipmi_pass
                
        elif len(parts) == 2:
            server["server_ip"] = parts[0]
            server["bmc_ip"] = parts[1]
            if global_ssh_user:
                server["ssh_user"] = global_ssh_user
                server["ssh_password"] = global_ssh_pass
            if global_ipmi_user:
                server["bmc_user"] = global_ipmi_user
                server["bmc_password"] = global_ipmi_pass
                
        elif len(parts) == 3:
            server["server_ip"] = parts[0]
            server["ssh_user"] = parts[1]
            server["ssh_password"] = parts[2]
            if global_ipmi_user:
                server["bmc_user"] = global_ipmi_user
                server["bmc_password"] = global_ipmi_pass
                
        elif len(parts) == 5:
            server["server_ip"] = parts[0]
            server["ssh_user"] = parts[1]
            server["ssh_password"] = parts[2]
            server["bmc_user"] = parts[3]
            server["bmc_password"] = parts[4]
            
        elif len(parts) >= 6:
            server["server_ip"] = parts[0]
            server["ssh_user"] = parts[1]
            server["ssh_password"] = parts[2]
            server["bmc_user"] = parts[3]
            server["bmc_password"] = parts[4]
            server["bmc_ip"] = parts[5]
        else:
            continue
        
        if not server.get("server_ip"):
            continue
        
        server["ssh_port"] = 22
        
        # Test SSH and get hostname
        if server.get("server_ip") and server.get("ssh_user"):
            success, hostname, error = test_ssh_connection(
                server["server_ip"],
                server["ssh_user"],
                password=server.get("ssh_password"),
                key_path=server.get("ssh_key"),
                port=22
            )
            if success and hostname:
                server["name"] = hostname
        
        # Test IPMI if configured
        if server.get("bmc_ip") and server.get("bmc_user"):
            if test_ipmi_connection(server["bmc_ip"], server["bmc_user"], server["bmc_password"]):
                console.print(f"[green]✓[/green] {server['name']} - IPMI OK ({server['bmc_ip']})")
            else:
                console.print(f"[yellow]⚠[/yellow] {server['name']} - IPMI failed ({server['bmc_ip']})")
        elif server.get("server_ip"):
            ssh_status = "[green]SSH OK[/green]" if (server.get("ssh_user") and server.get("name") != f"server-{len(servers)+1:02d}") else "[yellow]SSH?[/yellow]"
            console.print(f"[blue]•[/blue] {server['name']} - {ssh_status} ({server['server_ip']})")
        
        servers.append(server)
    
    return servers


def add_servers_manual() -> List[Dict]:
    """Add multiple servers manually with shared credentials."""
    
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
    server_ips = {}
    
    if add_ssh:
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
                "Server IP offset from BMC:",
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
                
        else:
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
        
        if auth_method is None:
            add_ssh = False
        elif auth_method == "Password":
            ssh_pass = questionary.password(
                "SSH password:",
                style=custom_style
            ).ask()
            if not ssh_pass:
                add_ssh = False
        else:
            # Use improved SSH key prompt with auto-detection
            ssh_key = prompt_ssh_key(custom_style)
            if not ssh_key:
                add_ssh = False
    
    # Build server list
    servers = []
    console.print("\n[dim]Building server list...[/dim]\n")
    
    for i, bmc_ip in enumerate(bmc_ips):
        server_ip = server_ips.get(bmc_ip, bmc_ip) if add_ssh else None
        default_name = f"server-{i+1:02d}"
        
        server = {
            "name": default_name,
            "bmc_ip": bmc_ip,
            "bmc_user": bmc_user,
            "bmc_password": bmc_pass
        }
        
        if add_ssh and ssh_user and server_ip:
            server["server_ip"] = server_ip
            server["ssh_user"] = ssh_user
            if ssh_pass:
                server["ssh_password"] = ssh_pass
            if ssh_key:
                server["ssh_key"] = ssh_key
            server["ssh_port"] = 22
            
            # Test SSH with retry options
            while True:
                console.print(f"[dim]Testing SSH to {server_ip}...[/dim]", end=" ")
                success, hostname, error = test_ssh_connection(
                    server_ip, ssh_user, 
                    password=ssh_pass, 
                    key_path=ssh_key,
                    port=22
                )
                
                if success:
                    if hostname:
                        server["name"] = hostname
                        console.print(f"[green]✓[/green] {hostname}")
                    else:
                        console.print(f"[green]✓[/green] Connected (using {default_name})")
                    break
                else:
                    console.print(f"[yellow]⚠[/yellow] Failed: {error}")
                    
                    # Ask what to do about the failure
                    action = questionary.select(
                        f"SSH to {server_ip} failed. What would you like to do?",
                        choices=[
                            questionary.Choice("Enter a different IP address", value="change_ip"),
                            questionary.Choice("Retry connection", value="retry"),
                            questionary.Choice("Skip SSH for this server (BMC only)", value="skip"),
                            questionary.Choice("Remove this server entirely", value="remove"),
                        ],
                        style=custom_style
                    ).ask()
                    
                    if action == "change_ip":
                        new_ip = questionary.text(
                            f"New server IP for BMC {bmc_ip}:",
                            default=server_ip,
                            style=custom_style
                        ).ask()
                        if new_ip:
                            server_ip = new_ip
                            server["server_ip"] = new_ip
                        continue
                    elif action == "retry":
                        continue
                    elif action == "skip":
                        # Remove SSH config from this server
                        server.pop("server_ip", None)
                        server.pop("ssh_user", None)
                        server.pop("ssh_password", None)
                        server.pop("ssh_key", None)
                        server.pop("ssh_port", None)
                        console.print(f"[dim]SSH skipped for {default_name} - BMC monitoring only[/dim]")
                        break
                    elif action == "remove":
                        server = None  # Mark for removal
                        break
        
        if server:  # Only add if not removed
            servers.append(server)
    
    return servers


def add_server_interactive() -> Optional[Dict]:
    """Interactively add a single server."""
    console.print()
    
    name = questionary.text(
        "Server name (e.g., gpu-server-01):",
        validate=lambda x: len(x) > 0,
        style=custom_style
    ).ask()
    
    if not name:
        return None
    
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
    
    console.print("[dim]Testing IPMI connection...[/dim]")
    
    if test_ipmi_connection(bmc_ip, bmc_user, bmc_pass):
        console.print(f"[green]✓[/green] IPMI connection successful")
    else:
        console.print(f"[yellow]⚠[/yellow] Could not connect to IPMI (check credentials later)")
    
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
        
        if not ssh_host:
            return server
        
        ssh_user = questionary.text(
            "SSH username:",
            default="root",
            style=custom_style
        ).ask()
        
        if not ssh_user:
            return server
        
        ssh_method = questionary.select(
            "SSH authentication:",
            choices=["Password", "SSH Key"],
            style=custom_style
        ).ask()
        
        if ssh_method is None:
            return server
        elif ssh_method == "Password":
            ssh_pass = questionary.password(
                "SSH password:",
                style=custom_style
            ).ask()
            if ssh_pass:
                server["ssh_password"] = ssh_pass
            else:
                return server
        else:
            # Use improved SSH key prompt with auto-detection
            ssh_key = prompt_ssh_key(custom_style)
            if ssh_key:
                server["ssh_key"] = ssh_key
            else:
                return server
        
        server["server_ip"] = ssh_host
        server["ssh_user"] = ssh_user
        server["ssh_port"] = 22
        
        console.print("[dim]Testing SSH connection...[/dim]")
        success, hostname, error = test_ssh_connection(
            ssh_host, ssh_user,
            password=server.get("ssh_password"),
            key_path=server.get("ssh_key"),
            port=22
        )
        
        if success:
            if hostname:
                use_hostname = questionary.confirm(
                    f"Use retrieved hostname '{hostname}' as server name?",
                    default=True,
                    style=custom_style
                ).ask()
                if use_hostname:
                    server["name"] = hostname
                console.print(f"[green]✓[/green] SSH connection successful")
            else:
                console.print(f"[green]✓[/green] SSH connection successful")
        else:
            console.print(f"[yellow]⚠[/yellow] SSH test failed: {error}")
    
    return server


# ============================================================================
# Testing Functions (kept from original)
# ============================================================================

def test_ssh_connection(ip: str, user: str, password: str = None, key_path: str = None, port: int = 22) -> tuple:
    """Test SSH connectivity and retrieve hostname."""
    try:
        ssh_opts = [
            "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-p", str(port)
        ]
        
        if key_path:
            key_path = os.path.expanduser(key_path)
            if not os.path.exists(key_path):
                return (False, None, f"SSH key not found: {key_path}")
            ssh_opts.extend(["-i", key_path])
        
        cmd = ["ssh"] + ssh_opts + [f"{user}@{ip}", "hostname"]
        
        if password and not key_path:
            try:
                subprocess.run(["which", "sshpass"], capture_output=True, check=True)
                cmd = ["sshpass", "-p", password] + cmd
                cmd = [c for c in cmd if c != "BatchMode=yes"]
            except subprocess.CalledProcessError:
                return (False, None, "sshpass not installed (needed for password auth)")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            hostname = result.stdout.strip()
            return (True, hostname if hostname else None, None)
        else:
            error = result.stderr.strip() if result.stderr else "Connection failed"
            return (False, None, error)
            
    except subprocess.TimeoutExpired:
        return (False, None, "Connection timed out")
    except Exception as e:
        return (False, None, str(e))


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


def read_ssh_key_file(key_path: str) -> Optional[str]:
    """Read SSH key content from a file path."""
    try:
        key_path = os.path.expanduser(key_path)
        if os.path.exists(key_path):
            with open(key_path, 'r') as f:
                content = f.read().strip()
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


def get_ssh_key_fingerprint(key_path: str) -> Optional[str]:
    """Get SSH key fingerprint for display."""
    try:
        key_path = os.path.expanduser(key_path)
        # Try to get fingerprint from public key first
        pub_key_path = key_path + '.pub'
        target_path = pub_key_path if os.path.exists(pub_key_path) else key_path
        
        result = subprocess.run(
            ['ssh-keygen', '-lf', target_path],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            # Format: "256 SHA256:xxx... comment (ED25519)"
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                return f"{parts[1]} ({parts[-1].strip('()')})" if len(parts) >= 4 else parts[1]
        return None
    except Exception:
        return None


def detect_ssh_keys() -> List[Dict]:
    """Detect available SSH keys in common locations."""
    keys = []
    home = os.path.expanduser("~")
    ssh_dir = os.path.join(home, ".ssh")
    
    # Common key names
    key_names = [
        "id_ed25519",
        "id_rsa", 
        "id_ecdsa",
        "id_dsa",
        "ubuntu_key",
        "server_key",
        "deploy_key"
    ]
    
    for key_name in key_names:
        key_path = os.path.join(ssh_dir, key_name)
        if os.path.exists(key_path):
            # Verify it's a private key
            try:
                with open(key_path, 'r') as f:
                    first_line = f.readline()
                if 'PRIVATE KEY' in first_line or '-----BEGIN' in first_line:
                    fingerprint = get_ssh_key_fingerprint(key_path)
                    keys.append({
                        'path': key_path,
                        'name': key_name,
                        'fingerprint': fingerprint
                    })
            except:
                pass
    
    # Also check for any .pem files
    if os.path.exists(ssh_dir):
        for f in os.listdir(ssh_dir):
            if f.endswith('.pem'):
                key_path = os.path.join(ssh_dir, f)
                if key_path not in [k['path'] for k in keys]:
                    fingerprint = get_ssh_key_fingerprint(key_path)
                    keys.append({
                        'path': key_path,
                        'name': f,
                        'fingerprint': fingerprint
                    })
    
    return keys


def generate_ssh_key() -> Optional[Dict]:
    """Generate a new SSH key pair and return path and public key."""
    home = os.path.expanduser("~")
    ssh_dir = os.path.join(home, ".ssh")
    os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
    
    # Find unused key name
    base_name = "ipmi_monitor_key"
    key_path = os.path.join(ssh_dir, base_name)
    counter = 1
    while os.path.exists(key_path):
        key_path = os.path.join(ssh_dir, f"{base_name}_{counter}")
        counter += 1
    
    try:
        console.print(f"\n[dim]Generating ED25519 key pair...[/dim]")
        result = subprocess.run(
            ['ssh-keygen', '-t', 'ed25519', '-f', key_path, '-N', '', '-C', 'ipmi-monitor'],
            capture_output=True, text=True, timeout=30
        )
        
        if result.returncode == 0:
            # Read public key
            pub_key_path = key_path + '.pub'
            with open(pub_key_path, 'r') as f:
                pub_key = f.read().strip()
            
            fingerprint = get_ssh_key_fingerprint(key_path)
            
            return {
                'path': key_path,
                'pub_key': pub_key,
                'fingerprint': fingerprint
            }
        else:
            console.print(f"[red]✗[/red] Key generation failed: {result.stderr}")
            return None
    except Exception as e:
        console.print(f"[red]✗[/red] Key generation error: {e}")
        return None


def prompt_ssh_key(custom_style) -> Optional[str]:
    """
    Interactive SSH key selection with multiple options:
    - Select from detected keys
    - Enter path manually  
    - Paste key content
    - Generate new key
    
    Returns the key path to use (or None if cancelled).
    """
    console.print()
    
    # Detect existing keys
    detected_keys = detect_ssh_keys()
    
    # Build choices
    choices = []
    
    if detected_keys:
        console.print("[dim]Detected SSH keys:[/dim]")
        for key in detected_keys:
            fp_str = f" ({key['fingerprint']})" if key['fingerprint'] else ""
            console.print(f"  • {key['name']}: {key['path']}{fp_str}")
        console.print()
        
        for key in detected_keys:
            fp_str = f" - {key['fingerprint'][:20]}..." if key['fingerprint'] else ""
            choices.append(questionary.Choice(f"Use {key['name']}{fp_str}", value=('select', key['path'])))
    
    choices.extend([
        questionary.Choice("📁 Enter key path manually", value=('manual', None)),
        questionary.Choice("📋 Paste private key content", value=('paste', None)),
        questionary.Choice("🔑 Generate new SSH key", value=('generate', None)),
    ])
    
    action = questionary.select(
        "SSH Key Authentication:",
        choices=choices,
        style=custom_style
    ).ask()
    
    if action is None:
        return None
    
    action_type, value = action
    
    if action_type == 'select':
        key_path = value
        # Show key details
        content = read_ssh_key_file(key_path)
        if content:
            fingerprint = get_ssh_key_fingerprint(key_path)
            console.print(f"[green]✓[/green] Key loaded: {key_path}")
            if fingerprint:
                console.print(f"  Fingerprint: {fingerprint}")
            return key_path
        return None
    
    elif action_type == 'manual':
        key_path = questionary.text(
            "SSH key path:",
            default="/root/.ssh/id_rsa",
            style=custom_style
        ).ask()
        
        if not key_path:
            return None
        
        # Verify and show details
        content = read_ssh_key_file(key_path)
        if content:
            fingerprint = get_ssh_key_fingerprint(key_path)
            console.print(f"[green]✓[/green] Key loaded: {key_path}")
            if fingerprint:
                console.print(f"  Fingerprint: {fingerprint}")
            return key_path
        
        # Key not found or invalid - offer to retry or cancel
        retry = questionary.confirm(
            "Key not found or invalid. Try another path?",
            default=True,
            style=custom_style
        ).ask()
        
        if retry:
            return prompt_ssh_key(custom_style)
        return None
    
    elif action_type == 'paste':
        console.print("\n[dim]Paste your private key below (press Enter twice when done):[/dim]")
        console.print("[dim]The key should start with '-----BEGIN' and end with 'PRIVATE KEY-----'[/dim]\n")
        
        lines = []
        empty_count = 0
        while True:
            try:
                line = input()
                if line == '':
                    empty_count += 1
                    if empty_count >= 2:
                        break
                    lines.append(line)
                else:
                    empty_count = 0
                    lines.append(line)
            except EOFError:
                break
        
        key_content = '\n'.join(lines).strip()
        
        if not key_content.startswith('-----BEGIN') or 'PRIVATE KEY' not in key_content:
            console.print("[red]✗[/red] Invalid key format. Must be a PEM-encoded private key.")
            return None
        
        # Save to temp file for validation and use
        home = os.path.expanduser("~")
        ssh_dir = os.path.join(home, ".ssh")
        os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
        
        key_path = os.path.join(ssh_dir, "ipmi_monitor_pasted_key")
        counter = 1
        while os.path.exists(key_path):
            key_path = os.path.join(ssh_dir, f"ipmi_monitor_pasted_key_{counter}")
            counter += 1
        
        with open(key_path, 'w') as f:
            f.write(key_content)
        os.chmod(key_path, 0o600)
        
        fingerprint = get_ssh_key_fingerprint(key_path)
        console.print(f"[green]✓[/green] Key saved to: {key_path}")
        if fingerprint:
            console.print(f"  Fingerprint: {fingerprint}")
        
        return key_path
    
    elif action_type == 'generate':
        result = generate_ssh_key()
        if not result:
            return None
        
        console.print(f"\n[green]✓[/green] New SSH key generated!")
        console.print(f"  Private key: {result['path']}")
        console.print(f"  Fingerprint: {result['fingerprint']}")
        
        console.print("\n[bold yellow]━━━ PUBLIC KEY ━━━[/bold yellow]")
        console.print(f"\n[cyan]{result['pub_key']}[/cyan]\n")
        console.print("[bold yellow]━━━━━━━━━━━━━━━━━━[/bold yellow]")
        
        console.print("\n[bold]To allow SSH access, add this public key to your servers:[/bold]")
        console.print("  1. Copy the public key above")
        console.print("  2. On each server, add it to: [cyan]~/.ssh/authorized_keys[/cyan]")
        console.print("  3. Ensure permissions: [cyan]chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys[/cyan]")
        console.print("\n[dim]Or use: ssh-copy-id -i {}.pub root@<server-ip>[/dim]".format(result['path']))
        
        # Confirm they've added the key
        proceed = questionary.confirm(
            "\nHave you added the public key to your servers?",
            default=False,
            style=custom_style
        ).ask()
        
        if not proceed:
            console.print("[dim]You can add the key later and re-run quickstart.[/dim]")
        
        return result['path']
    
    return None


# ============================================================================
# Summary and Display
# ============================================================================

def show_summary(servers: List[Dict], local_ip: str, port: int, ai_enabled: bool, domain: Optional[str] = None, https_enabled: bool = False):
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
        table.add_row("Web Interface", f"https://{domain}/")
    elif https_enabled:
        table.add_row("Web Interface", f"https://{local_ip}/")
    else:
        table.add_row("Web Interface", f"http://{local_ip}:{port}")
    
    table.add_row("Servers Monitored", str(len(servers)))
    table.add_row("AI Insights", "Enabled ✓" if ai_enabled else "Not configured")
    table.add_row("Config Directory", str(CONFIG_DIR))
    table.add_row("HTTPS", "Enabled ✓" if https_enabled else "Not configured")
    table.add_row("Auto-Updates", "Enabled ✓ (Watchtower)")
    
    console.print(table)
    
    console.print("\n[bold]Monitored Servers:[/bold]")
    for srv in servers:
        ssh_info = " + SSH" if srv.get("server_ip") else ""
        bmc_ip = srv.get('bmc_ip', srv.get('server_ip', 'unknown'))
        console.print(f"  • {srv['name']} - BMC: {bmc_ip}{ssh_info}")
    
    console.print("\n[bold]Docker Commands:[/bold]")
    console.print(f"  [cyan]docker logs ipmi-monitor[/cyan]     - View logs")
    console.print(f"  [cyan]docker restart ipmi-monitor[/cyan]  - Restart")
    console.print(f"  [cyan]cd {CONFIG_DIR} && docker compose down[/cyan] - Stop")
    console.print(f"  [cyan]cd {CONFIG_DIR} && docker compose up -d[/cyan] - Start")
    
    console.print("\n[bold]CLI Commands:[/bold]")
    console.print("  [cyan]ipmi-monitor status[/cyan]   - Check container status")
    console.print("  [cyan]ipmi-monitor logs[/cyan]     - View logs")
    console.print("  [cyan]ipmi-monitor upgrade[/cyan]  - Pull latest image")
    
    if domain:
        console.print(f"\n[bold]Open your browser:[/bold] [cyan]https://{domain}/[/cyan]")
    elif https_enabled:
        console.print(f"\n[bold]Open your browser:[/bold] [cyan]https://{local_ip}/[/cyan]")
    else:
        console.print(f"\n[bold]Open your browser:[/bold] [cyan]http://{local_ip}:{port}[/cyan]")


if __name__ == "__main__":
    run_quickstart()
