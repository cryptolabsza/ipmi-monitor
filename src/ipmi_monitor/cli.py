"""
IPMI Monitor CLI - Command line interface with setup wizard
"""

import click
import os
import sys
import subprocess
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

from . import __version__, get_version_info
from .wizard import SetupWizard
from .service import ServiceManager
from .quickstart import run_quickstart

console = Console()

# Docker config directory (where quickstart puts files)
DOCKER_CONFIG_DIR = Path("/etc/ipmi-monitor")


@click.group()
@click.version_option(version=__version__, prog_name="ipmi-monitor", message=get_version_info())
def main():
    """
    IPMI Monitor - Server Monitoring with AI-Powered Insights
    
    Monitor your servers' BMC/IPMI interfaces with a beautiful web dashboard
    and optional AI-powered diagnostics.
    
    \b
    Quick Start:
        pip install ipmi-monitor
        sudo ipmi-monitor quickstart
    
    \b
    Commands:
        quickstart   ⚡ One-command setup (recommended)
        add-server   Add another server to monitor
        status       Check service status
        version      Show detailed version info
    """
    pass


@main.command()
def version():
    """Show detailed version information."""
    from . import __version__, __git_commit__, __git_branch__, __build_time__
    
    console.print(Panel.fit(
        f"[bold cyan]IPMI Monitor[/bold cyan] v{__version__}",
        border_style="cyan"
    ))
    
    table = Table(show_header=False, box=None)
    table.add_column("", style="dim")
    table.add_column("")
    
    table.add_row("Version", __version__)
    table.add_row("Branch", __git_branch__ or "[dim]unknown[/dim]")
    table.add_row("Commit", __git_commit__[:7] if __git_commit__ else "[dim]unknown[/dim]")
    table.add_row("Built", __build_time__ or "[dim]unknown[/dim]")
    table.add_row("Python", sys.version.split()[0])
    
    console.print(table)


@main.command()
def quickstart():
    """
    ⚡ One-command setup - does everything!
    
    Just answer a few questions and your IPMI monitoring will be set up.
    
    \b
    WHAT IT DOES:
        - Prompts for your server's BMC/IPMI credentials
        - Optionally configures SSH for detailed monitoring
        - Sets up AI Insights (if you have a license)
        - Installs and starts the service
    
    \b
    EXAMPLE:
        sudo ipmi-monitor quickstart
    """
    run_quickstart()


@main.command()
@click.option("--install-service", is_flag=True, help="Install as systemd service")
@click.option("--config-dir", default=None, help="Configuration directory")
@click.option("--non-interactive", is_flag=True, help="Use defaults, no prompts")
def setup(install_service: bool, config_dir: str, non_interactive: bool):
    """
    Run the interactive setup wizard.
    
    This will guide you through:
    
    \b
    - Configuring your first BMC/IPMI server
    - Setting up SSH access for system monitoring
    - Optionally linking your CryptoLabs account for AI features
    - Installing as a system service (optional)
    
    Example:
    
        sudo ipmi-monitor setup --install-service
    """
    console.print()
    console.print(Panel.fit(
        "[bold cyan]IPMI Monitor Setup Wizard[/bold cyan]\n"
        f"[dim]Version {__version__}[/dim]",
        border_style="cyan"
    ))
    console.print()
    
    wizard = SetupWizard(
        config_dir=config_dir,
        non_interactive=non_interactive
    )
    
    try:
        config = wizard.run()
        
        if install_service:
            if os.geteuid() != 0:
                console.print("[red]Error:[/red] Installing service requires root. Run with sudo.")
                sys.exit(1)
            
            service_mgr = ServiceManager()
            service_mgr.install(config)
            console.print("\n[green]✓[/green] Service installed! Start with: [cyan]sudo systemctl start ipmi-monitor[/cyan]")
        else:
            console.print("\n[green]✓[/green] Setup complete! Start with: [cyan]ipmi-monitor run[/cyan]")
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Setup cancelled.[/yellow]")
        sys.exit(1)


@main.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=5000, help="Port to listen on")
@click.option("--debug", is_flag=True, help="Enable debug mode")
@click.option("--config-dir", default=None, help="Configuration directory")
def run(host: str, port: int, debug: bool, config_dir: str):
    """
    Start the IPMI Monitor web interface.
    
    This starts the Flask web server. Open http://localhost:5000 in your browser.
    
    Example:
    
        ipmi-monitor run --port 8080
    """
    from .app import create_app
    
    config_path = Path(config_dir) if config_dir else get_config_dir()
    
    if not (config_path / "config.yaml").exists():
        console.print("[yellow]Warning:[/yellow] No configuration found. Run [cyan]ipmi-monitor setup[/cyan] first.")
        console.print("Starting with default configuration...\n")
    
    console.print(Panel.fit(
        f"[bold green]IPMI Monitor[/bold green]\n"
        f"[dim]Starting web interface on http://{host}:{port}[/dim]",
        border_style="green"
    ))
    
    app = create_app(config_dir=config_path)
    
    if debug:
        app.run(host=host, port=port, debug=True)
    else:
        # Use gunicorn for production
        from gunicorn.app.base import BaseApplication
        
        class StandaloneApplication(BaseApplication):
            def __init__(self, app, options=None):
                self.options = options or {}
                self.application = app
                super().__init__()

            def load_config(self):
                for key, value in self.options.items():
                    if key in self.cfg.settings and value is not None:
                        self.cfg.set(key.lower(), value)

            def load(self):
                return self.application
        
        options = {
            "bind": f"{host}:{port}",
            "workers": 2,
            "threads": 4,
            "accesslog": "-",
            "errorlog": "-",
        }
        StandaloneApplication(app, options).run()


@main.command()
@click.option("--config-dir", default=None, help="Configuration directory")
def daemon(config_dir: str):
    """
    Run IPMI Monitor as a daemon (for systemd).
    
    This is used by the systemd service. For manual use, prefer 'run'.
    """
    import yaml
    from .app import create_app
    from gunicorn.app.base import BaseApplication
    
    config_path = Path(config_dir) if config_dir else get_config_dir()
    
    # Read port from config file (default 5000)
    port = 5000
    config_file = config_path / "config.yaml"
    if config_file.exists():
        try:
            with open(config_file) as f:
                cfg = yaml.safe_load(f) or {}
                port = cfg.get("web", {}).get("port", 5000)
        except Exception:
            pass  # Use default if config read fails
    
    app = create_app(config_dir=config_path)
    
    class DaemonApplication(BaseApplication):
        def __init__(self, app, options=None):
            self.options = options or {}
            self.application = app
            super().__init__()

        def load_config(self):
            for key, value in self.options.items():
                if key in self.cfg.settings and value is not None:
                    self.cfg.set(key.lower(), value)

        def load(self):
            return self.application
    
    options = {
        "bind": f"0.0.0.0:{port}",
        "workers": 2,
        "threads": 4,
        "daemon": False,  # systemd manages the daemon
    }
    DaemonApplication(app, options).run()


@main.command()
def status():
    """
    Show IPMI Monitor status and configuration.
    
    Checks both Docker container status and systemd service status.
    """
    config_path = DOCKER_CONFIG_DIR if DOCKER_CONFIG_DIR.exists() else get_config_dir()
    
    console.print(Panel.fit(
        "[bold cyan]IPMI Monitor Status[/bold cyan]",
        border_style="cyan"
    ))
    
    table = Table(show_header=False, box=None)
    table.add_column("Key", style="dim")
    table.add_column("Value")
    
    table.add_row("Version", __version__)
    table.add_row("Config Dir", str(config_path))
    
    # Check Docker deployment
    docker_status = get_docker_container_status()
    if docker_status:
        table.add_row("Docker Container", docker_status)
        table.add_row("Compose File", "✓" if (config_path / "docker-compose.yml").exists() else "✗")
    
    # Check if systemd service exists (legacy)
    service_mgr = ServiceManager()
    service_status = service_mgr.status()
    if service_status and "not installed" not in service_status.lower():
        table.add_row("Systemd Service", service_status)
    
    console.print(table)
    
    # Show helpful commands
    if docker_status:
        console.print("\n[bold]Commands:[/bold]")
        console.print("  [cyan]ipmi-monitor logs[/cyan]     - View container logs")
        console.print("  [cyan]ipmi-monitor stop[/cyan]     - Stop containers")
        console.print("  [cyan]ipmi-monitor start[/cyan]    - Start containers")
        console.print("  [cyan]ipmi-monitor upgrade[/cyan]  - Pull latest image & restart")


def get_docker_container_status() -> str:
    """Get status of ipmi-monitor Docker container."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Status}}", "ipmi-monitor"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            status = result.stdout.strip()
            if status == "running":
                return "[green]running ✓[/green]"
            elif status == "exited":
                return "[red]stopped[/red]"
            else:
                return f"[yellow]{status}[/yellow]"
        return None
    except Exception:
        return None


@main.command()
@click.option("-f", "--follow", is_flag=True, help="Follow log output")
@click.option("-n", "--lines", default=100, help="Number of lines to show")
def logs(follow: bool, lines: int):
    """
    View IPMI Monitor container logs.
    
    Example:
    
        ipmi-monitor logs -f          # Follow logs
        ipmi-monitor logs -n 50       # Last 50 lines
    """
    cmd = ["docker", "logs"]
    if follow:
        cmd.append("-f")
    cmd.extend(["--tail", str(lines), "ipmi-monitor"])
    
    try:
        subprocess.run(cmd)
    except FileNotFoundError:
        console.print("[red]Error:[/red] Docker is not installed")
        sys.exit(1)
    except KeyboardInterrupt:
        pass


@main.command()
def stop():
    """
    Stop IPMI Monitor containers.
    
    Stops the Docker containers defined in docker-compose.yml.
    """
    if not DOCKER_CONFIG_DIR.exists():
        console.print("[red]Error:[/red] Config directory not found. Run quickstart first.")
        sys.exit(1)
    
    compose_file = DOCKER_CONFIG_DIR / "docker-compose.yml"
    if not compose_file.exists():
        console.print("[red]Error:[/red] docker-compose.yml not found. Run quickstart first.")
        sys.exit(1)
    
    success, output = run_docker_compose_cmd("down")
    if success:
        console.print("[green]✓[/green] IPMI Monitor stopped")
    else:
        console.print(f"[red]Error:[/red] {output}")


@main.command()
def start():
    """
    Start IPMI Monitor containers.
    
    Starts the Docker containers defined in docker-compose.yml.
    """
    if not DOCKER_CONFIG_DIR.exists():
        console.print("[red]Error:[/red] Config directory not found. Run quickstart first.")
        sys.exit(1)
    
    compose_file = DOCKER_CONFIG_DIR / "docker-compose.yml"
    if not compose_file.exists():
        console.print("[red]Error:[/red] docker-compose.yml not found. Run quickstart first.")
        sys.exit(1)
    
    success, output = run_docker_compose_cmd("up -d")
    if success:
        console.print("[green]✓[/green] IPMI Monitor started")
    else:
        console.print(f"[red]Error:[/red] {output}")


@main.command()
def upgrade():
    """
    Upgrade IPMI Monitor to the latest version.
    
    Pulls the latest Docker image and restarts the containers.
    """
    console.print("[dim]Pulling latest image...[/dim]")
    
    try:
        result = subprocess.run(
            ["docker", "pull", "ghcr.io/cryptolabsza/ipmi-monitor:latest"],
            capture_output=True, text=True
        )
        
        if result.returncode != 0:
            console.print(f"[red]Error pulling image:[/red] {result.stderr}")
            sys.exit(1)
        
        console.print("[green]✓[/green] Image updated")
        
        # Restart containers
        if DOCKER_CONFIG_DIR.exists() and (DOCKER_CONFIG_DIR / "docker-compose.yml").exists():
            console.print("[dim]Restarting containers...[/dim]")
            success, output = run_docker_compose_cmd("up -d")
            if success:
                console.print("[green]✓[/green] IPMI Monitor upgraded and restarted")
            else:
                console.print(f"[yellow]Warning:[/yellow] Container restart failed: {output}")
        else:
            console.print("[yellow]Note:[/yellow] No docker-compose.yml found. Manual restart required.")
            
    except FileNotFoundError:
        console.print("[red]Error:[/red] Docker is not installed")
        sys.exit(1)


@main.command()
def restart():
    """
    Restart IPMI Monitor containers.
    """
    if not DOCKER_CONFIG_DIR.exists():
        console.print("[red]Error:[/red] Config directory not found. Run quickstart first.")
        sys.exit(1)
    
    success, output = run_docker_compose_cmd("restart")
    if success:
        console.print("[green]✓[/green] IPMI Monitor restarted")
    else:
        console.print(f"[red]Error:[/red] {output}")


def run_docker_compose_cmd(command: str):
    """Run a docker compose command in the config directory."""
    compose_file = DOCKER_CONFIG_DIR / "docker-compose.yml"
    
    # Try docker compose (v2) first
    try:
        result = subprocess.run(
            ["docker", "compose", "-f", str(compose_file)] + command.split(),
            capture_output=True, text=True, cwd=str(DOCKER_CONFIG_DIR)
        )
        if result.returncode == 0:
            return True, result.stdout
    except Exception:
        pass
    
    # Try docker-compose (v1)
    try:
        result = subprocess.run(
            ["docker-compose", "-f", str(compose_file)] + command.split(),
            capture_output=True, text=True, cwd=str(DOCKER_CONFIG_DIR)
        )
        return result.returncode == 0, result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return False, str(e)


@main.command("add-server")
@click.option("--bmc-ip", prompt="BMC/IPMI IP", help="BMC/IPMI IP address")
@click.option("--username", prompt="Username", help="BMC username")
@click.option("--password", prompt="Password", hide_input=True, help="BMC password")
@click.option("--name", default=None, help="Server name (optional)")
def add_server(bmc_ip: str, username: str, password: str, name: str):
    """
    Add a new server to monitor.
    
    Example:
    
        ipmi-monitor add-server --bmc-ip 192.168.1.100 --username admin
    """
    from .config import Config
    
    config = Config.load(get_config_dir())
    config.add_server(
        bmc_ip=bmc_ip,
        username=username,
        password=password,
        name=name or bmc_ip
    )
    config.save()
    
    console.print(f"[green]✓[/green] Added server: {name or bmc_ip} ({bmc_ip})")


@main.command("list-servers")
def list_servers():
    """
    List all configured servers.
    """
    from .config import Config
    
    config = Config.load(get_config_dir())
    
    if not config.servers:
        console.print("[yellow]No servers configured.[/yellow] Run [cyan]ipmi-monitor add-server[/cyan]")
        return
    
    table = Table(title="Configured Servers")
    table.add_column("Name", style="cyan")
    table.add_column("BMC IP")
    table.add_column("Username")
    table.add_column("SSH IP", style="dim")
    
    for server in config.servers:
        table.add_row(
            server.get("name", "—"),
            server.get("bmc_ip", "—"),
            server.get("username", "—"),
            server.get("server_ip", "—"),
        )
    
    console.print(table)


@main.command("setup-ssl")
@click.option("--domain", "-d", help="Domain name (e.g., ipmi.example.com)")
@click.option("--email", "-e", help="Email for Let's Encrypt certificate")
@click.option("--letsencrypt", is_flag=True, help="Use Let's Encrypt instead of self-signed")
@click.option("--site-name", default="IPMI Monitor", help="Name shown on landing page")
@click.option("--dc-overview/--no-dc-overview", default=False, help="Include DC Overview (Grafana/Prometheus) in reverse proxy")
@click.option("--vastai/--no-vastai", default=False, help="Show Vast.ai link on landing page")
def setup_ssl(domain: str, email: str, letsencrypt: bool, site_name: str, dc_overview: bool, vastai: bool):
    """
    Set up reverse proxy with SSL (nginx).
    
    Creates a branded landing page with links to all services.
    
    \b
    MODES:
        Self-signed (default): Works immediately, browser shows warning
        Let's Encrypt: Requires valid domain and ports 80/443 open
    
    \b
    EXAMPLES:
        sudo ipmi-monitor setup-ssl                         # Self-signed for IP access
        sudo ipmi-monitor setup-ssl -d ipmi.example.com    # Self-signed with domain
        sudo ipmi-monitor setup-ssl -d ipmi.example.com --letsencrypt -e admin@example.com
    
    \b
    DNS SETUP (for domain):
        Add these DNS records:
          A    ipmi.example.com        → <server-ip>
          A    grafana.ipmi.example.com → <server-ip>  (if --dc-overview)
    
    \b
    CROSS-PROMOTION:
        If you also have dc-overview installed, add --dc-overview to include Grafana/Prometheus links.
        The landing page will promote dc-overview if not enabled, helping users discover the full suite.
    """
    if os.geteuid() != 0:
        console.print("[red]Error:[/red] Setting up SSL requires root. Run with sudo.")
        sys.exit(1)
    
    if letsencrypt and not email:
        console.print("[red]Error:[/red] Let's Encrypt requires --email")
        sys.exit(1)
    
    if letsencrypt and not domain:
        console.print("[red]Error:[/red] Let's Encrypt requires --domain")
        sys.exit(1)
    
    from .reverse_proxy import setup_reverse_proxy
    
    setup_reverse_proxy(
        domain=domain,
        email=email,
        site_name=site_name,
        grafana_enabled=dc_overview,
        vastai_enabled=vastai,
        use_letsencrypt=letsencrypt,
    )


def get_config_dir() -> Path:
    """Get the configuration directory."""
    # Check environment variable first
    if "IPMI_MONITOR_CONFIG" in os.environ:
        return Path(os.environ["IPMI_MONITOR_CONFIG"])
    
    # Use XDG_CONFIG_HOME or default
    xdg_config = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    return Path(xdg_config) / "ipmi-monitor"


if __name__ == "__main__":
    main()
