"""
IPMI Monitor Setup Wizard - Interactive text UI for configuration
"""

import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any

import questionary
from questionary import Style
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.markup import escape as rich_escape
from rich import print as rprint
import yaml

console = Console()

# Custom style for questionary prompts
custom_style = Style([
    ('qmark', 'fg:cyan bold'),
    ('question', 'bold'),
    ('answer', 'fg:cyan'),
    ('pointer', 'fg:cyan bold'),
    ('highlighted', 'fg:cyan bold'),
    ('selected', 'fg:green'),
    ('separator', 'fg:gray'),
    ('instruction', 'fg:gray'),
    ('text', ''),
    ('disabled', 'fg:gray italic'),
])


class SetupWizard:
    """Interactive setup wizard for IPMI Monitor."""
    
    def __init__(self, config_dir: Optional[str] = None, non_interactive: bool = False):
        self.non_interactive = non_interactive
        
        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            xdg_config = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
            self.config_dir = Path(xdg_config) / "ipmi-monitor"
        
        self.config: Dict[str, Any] = {
            "servers": [],
            "settings": {
                "web_port": 5000,
                "refresh_interval": 60,
                "enable_prometheus": True,
            },
            "ai": {
                "enabled": False,
                "license_key": None,
            }
        }
        
        # Load existing servers.yaml if present
        self._load_servers_file()
    
    def _load_servers_file(self):
        """Load servers from servers.yaml if it exists."""
        servers_file = self.config_dir / "servers.yaml"
        if servers_file.exists():
            try:
                with open(servers_file) as f:
                    data = yaml.safe_load(f) or {}
                    servers = data.get("servers", [])
                    if servers:
                        self.config["servers"] = servers
                        console.print(f"[dim]Loaded {len(servers)} servers from {servers_file}[/dim]")
            except Exception as e:
                console.print(f"[yellow]Warning:[/yellow] Could not load {servers_file}: {e}")
    
    def run(self) -> Dict[str, Any]:
        """Run the setup wizard and return configuration."""
        
        # Step 1: Welcome
        self._show_welcome()
        
        # Step 2: Configuration directory
        self._setup_config_dir()
        
        # Step 3: Add first server
        self._setup_first_server()
        
        # Step 4: Web interface settings
        self._setup_web_settings()
        
        # Step 5: AI Features (optional)
        self._setup_ai_features()
        
        # Step 6: Save and summary
        self._save_config()
        self._show_summary()
        
        return self.config
    
    def _show_welcome(self):
        """Display welcome message."""
        console.print()
        console.print(Panel(
            "[bold]Welcome to IPMI Monitor![/bold]\n\n"
            "This wizard will help you configure:\n"
            "  • BMC/IPMI server connections\n"
            "  • SSH access for system monitoring\n"
            "  • Web interface settings\n"
            "  • AI-powered diagnostics (optional)\n\n"
            "[dim]Press Ctrl+C at any time to cancel.[/dim]",
            title="[cyan]Setup Wizard[/cyan]",
            border_style="cyan",
        ))
        console.print()
        
        if not self.non_interactive:
            questionary.press_any_key_to_continue(
                message="Press any key to continue...",
                style=custom_style
            ).ask()
    
    def _setup_config_dir(self):
        """Set up configuration directory."""
        console.print(Panel(
            f"[bold]Step 1: Configuration Directory[/bold]\n\n"
            f"Configuration will be stored in:\n"
            f"[cyan]{self.config_dir}[/cyan]",
            border_style="blue"
        ))
        
        if not self.non_interactive:
            custom_dir = questionary.confirm(
                "Use a different directory?",
                default=False,
                style=custom_style
            ).ask()
            
            if custom_dir:
                new_dir = questionary.path(
                    "Enter configuration directory:",
                    style=custom_style
                ).ask()
                if new_dir:
                    self.config_dir = Path(new_dir)
        
        # Create directory
        self.config_dir.mkdir(parents=True, exist_ok=True)
        console.print(f"[green]✓[/green] Config directory: {self.config_dir}\n")
    
    def _setup_first_server(self):
        """Configure the first BMC/IPMI server."""
        # If servers already loaded from config file, show them and ask to add more
        if self.config["servers"]:
            console.print(Panel(
                f"[bold]Step 2: Server Configuration[/bold]\n\n"
                f"[green]✓[/green] {len(self.config['servers'])} servers loaded from servers.yaml",
                border_style="blue"
            ))
            
            # Show loaded servers
            table = Table(title="Loaded Servers", show_header=True)
            table.add_column("Name", style="cyan")
            table.add_column("BMC IP")
            table.add_column("SSH IP", style="dim")
            
            for server in self.config["servers"]:
                table.add_row(
                    server.get("name", "—"),
                    server.get("bmc_ip", "—"),
                    server.get("server_ip", "—"),
                )
            console.print(table)
            
            if self.non_interactive:
                console.print()
                return
            
            add_more = questionary.confirm(
                "Add more servers?",
                default=False,
                style=custom_style
            ).ask()
            
            if not add_more:
                console.print()
                return
        else:
            console.print(Panel(
                "[bold]Step 2: Add Your First Server[/bold]\n\n"
                "Enter the BMC/IPMI details for your first server.\n"
                "You can add more servers later with [cyan]ipmi-monitor add-server[/cyan]\n\n"
                "[dim]Tip: Create ~/.config/ipmi-monitor/servers.yaml to pre-configure servers[/dim]",
                border_style="blue"
            ))
            
            if self.non_interactive:
                console.print("[yellow]Skipping server setup in non-interactive mode.[/yellow]")
                return
        
        add_server = questionary.confirm(
            "Add a server now?",
            default=True,
            style=custom_style
        ).ask()
        
        if not add_server:
            console.print("[dim]Skipping server setup. Add servers later with ipmi-monitor add-server[/dim]\n")
            return
        
        while True:
            server = self._prompt_server_details()
            if server:
                self.config["servers"].append(server)
                console.print(f"[green]✓[/green] Added: {server['name']} ({server['bmc_ip']})")
                
                # Test connection
                if questionary.confirm("Test BMC connection?", default=True, style=custom_style).ask():
                    self._test_bmc_connection(server)
            
            add_another = questionary.confirm(
                "Add another server?",
                default=False,
                style=custom_style
            ).ask()
            
            if not add_another:
                break
        
        console.print()
    
    def _prompt_server_details(self) -> Optional[Dict[str, Any]]:
        """Prompt for server details."""
        console.print()
        
        # BMC/IPMI details
        bmc_ip = questionary.text(
            "BMC/IPMI IP Address:",
            validate=lambda x: len(x) > 0 or "IP address is required",
            style=custom_style
        ).ask()
        
        if not bmc_ip:
            return None
        
        username = questionary.text(
            "BMC Username:",
            default="admin",
            style=custom_style
        ).ask()
        
        password = questionary.password(
            "BMC Password:",
            style=custom_style
        ).ask()
        
        name = questionary.text(
            "Server Name (optional):",
            default=bmc_ip,
            style=custom_style
        ).ask()
        
        # SSH details (optional)
        console.print("\n[dim]SSH access enables OS-level monitoring (CPU, memory, storage, GPUs)[/dim]")
        setup_ssh = questionary.confirm(
            "Configure SSH access?",
            default=True,
            style=custom_style
        ).ask()
        
        server = {
            "name": name or bmc_ip,
            "bmc_ip": bmc_ip,
            "username": username,
            "password": password,
        }
        
        if setup_ssh:
            server_ip = questionary.text(
                "Server IP (for SSH):",
                default=bmc_ip.rsplit(".", 1)[0] + ".1" if "." in bmc_ip else "",
                style=custom_style
            ).ask()
            
            ssh_user = questionary.text(
                "SSH Username:",
                default="root",
                style=custom_style
            ).ask()
            
            ssh_port = questionary.text(
                "SSH Port:",
                default="22",
                validate=lambda x: x.isdigit() or "Must be a number",
                style=custom_style
            ).ask()
            
            server["server_ip"] = server_ip
            server["ssh_user"] = ssh_user
            server["ssh_port"] = int(ssh_port)
            
            # SSH auth method
            auth_method = questionary.select(
                "SSH Authentication:",
                choices=["Password", "SSH Key"],
                style=custom_style
            ).ask()
            
            if auth_method == "Password":
                ssh_password = questionary.password(
                    "SSH Password:",
                    style=custom_style
                ).ask()
                server["ssh_password"] = ssh_password
            else:
                key_path = questionary.path(
                    "SSH Key Path:",
                    default=os.path.expanduser("~/.ssh/id_rsa"),
                    style=custom_style
                ).ask()
                server["ssh_key"] = key_path
        
        return server
    
    def _test_bmc_connection(self, server: Dict[str, Any]):
        """Test BMC connection."""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Testing BMC connection...", total=None)
            
            try:
                import subprocess
                result = subprocess.run(
                    ["ipmitool", "-I", "lanplus", "-H", server["bmc_ip"],
                     "-U", server["username"], "-P", server["password"],
                     "chassis", "status"],
                    capture_output=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    console.print("[green]✓[/green] BMC connection successful!")
                else:
                    console.print(f"[yellow]⚠[/yellow] BMC connection failed: {result.stderr.decode()[:100]}")
            except FileNotFoundError:
                console.print("[yellow]⚠[/yellow] ipmitool not installed. Install with: [cyan]apt install ipmitool[/cyan]")
            except subprocess.TimeoutExpired:
                console.print("[yellow]⚠[/yellow] Connection timed out")
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] Error: {e}")
    
    def _setup_web_settings(self):
        """Configure web interface settings."""
        console.print(Panel(
            "[bold]Step 3: Web Interface Settings[/bold]",
            border_style="blue"
        ))
        
        if self.non_interactive:
            console.print("[dim]Using default web settings[/dim]\n")
            return
        
        port = questionary.text(
            "Web interface port:",
            default="5000",
            validate=lambda x: x.isdigit() and 1 <= int(x) <= 65535 or "Invalid port",
            style=custom_style
        ).ask()
        
        self.config["settings"]["web_port"] = int(port)
        
        refresh = questionary.text(
            "Sensor refresh interval (seconds):",
            default="60",
            validate=lambda x: x.isdigit() and int(x) >= 10 or "Minimum 10 seconds",
            style=custom_style
        ).ask()
        
        self.config["settings"]["refresh_interval"] = int(refresh)
        
        prometheus = questionary.confirm(
            "Enable Prometheus metrics endpoint?",
            default=True,
            style=custom_style
        ).ask()
        
        self.config["settings"]["enable_prometheus"] = prometheus
        
        console.print()
    
    def _setup_ai_features(self):
        """Configure AI features (optional)."""
        console.print(Panel(
            "[bold]Step 4: AI-Powered Diagnostics (Optional)[/bold]\n\n"
            "Link your CryptoLabs account to enable:\n"
            "  • AI chat for troubleshooting\n"
            "  • Automatic root cause analysis\n"
            "  • Predictive maintenance alerts\n\n"
            "[dim]Get your license key at https://cryptolabs.co.za/my-account/[/dim]",
            border_style="blue"
        ))
        
        if self.non_interactive:
            console.print("[dim]Skipping AI setup in non-interactive mode[/dim]\n")
            return
        
        enable_ai = questionary.confirm(
            "Enable AI features?",
            default=False,
            style=custom_style
        ).ask()
        
        if not enable_ai:
            console.print("[dim]AI features disabled. Enable later in web interface.[/dim]\n")
            return
        
        license_key = questionary.text(
            "CryptoLabs License Key (sk-ipmi-...):",
            validate=lambda x: x.startswith("sk-ipmi-") or "Key should start with sk-ipmi-",
            style=custom_style
        ).ask()
        
        if license_key:
            self.config["ai"]["enabled"] = True
            self.config["ai"]["license_key"] = license_key
            
            # Test connection
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                progress.add_task("Validating license key...", total=None)
                
                try:
                    import requests
                    resp = requests.post(
                        "https://www.cryptolabs.co.za/wp-json/ipmi-monitor/v1/validate-key",
                        json={"api_key": license_key},
                        timeout=10
                    )
                    if resp.status_code == 200 and resp.json().get("valid"):
                        user = resp.json().get("user_email", "Unknown")
                        console.print(f"[green]✓[/green] License valid! Connected as: {user}")
                    else:
                        console.print("[yellow]⚠[/yellow] License validation failed. Check your key.")
                except Exception as e:
                    console.print(f"[yellow]⚠[/yellow] Could not validate: {e}")
        
        console.print()
    
    def _save_config(self):
        """Save configuration to file."""
        config_file = self.config_dir / "config.yaml"
        
        with open(config_file, "w") as f:
            yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)
        
        # Secure the file (contains passwords)
        os.chmod(config_file, 0o600)
        
        console.print(f"[green]✓[/green] Configuration saved to: {config_file}")
    
    def _show_summary(self):
        """Display setup summary."""
        console.print()
        console.print(Panel(
            "[bold green]Setup Complete![/bold green]",
            border_style="green"
        ))
        
        table = Table(title="Configuration Summary", show_header=False)
        table.add_column("Setting", style="dim")
        table.add_column("Value")
        
        table.add_row("Config Directory", str(self.config_dir))
        table.add_row("Servers Configured", str(len(self.config["servers"])))
        table.add_row("Web Port", str(self.config["settings"]["web_port"]))
        table.add_row("AI Features", "Enabled" if self.config["ai"]["enabled"] else "Disabled")
        table.add_row("Prometheus Metrics", "Enabled" if self.config["settings"]["enable_prometheus"] else "Disabled")
        
        console.print(table)
        
        console.print("\n[bold]Next Steps:[/bold]")
        console.print("  1. Start the web interface: [cyan]ipmi-monitor run[/cyan]")
        console.print("  2. Open in browser: [cyan]http://localhost:{port}[/cyan]".format(
            port=self.config["settings"]["web_port"]
        ))
        console.print("  3. Add more servers: [cyan]ipmi-monitor add-server[/cyan]")
        console.print()
