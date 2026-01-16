"""
IPMI Monitor CLI - Command line interface with setup wizard
"""

import click
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

from . import __version__
from .wizard import SetupWizard
from .service import ServiceManager
from .quickstart import run_quickstart

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="ipmi-monitor")
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
    """
    pass


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
    from .app import create_app
    from gunicorn.app.base import BaseApplication
    
    config_path = Path(config_dir) if config_dir else get_config_dir()
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
        "bind": "0.0.0.0:5000",
        "workers": 2,
        "threads": 4,
        "daemon": False,  # systemd manages the daemon
    }
    DaemonApplication(app, options).run()


@main.command()
def status():
    """
    Show IPMI Monitor status and configuration.
    """
    config_path = get_config_dir()
    
    console.print(Panel.fit(
        "[bold cyan]IPMI Monitor Status[/bold cyan]",
        border_style="cyan"
    ))
    
    table = Table(show_header=False, box=None)
    table.add_column("Key", style="dim")
    table.add_column("Value")
    
    table.add_row("Version", __version__)
    table.add_row("Config Dir", str(config_path))
    table.add_row("Config Exists", "✓" if (config_path / "config.yaml").exists() else "✗")
    table.add_row("Database", str(config_path / "ipmi_monitor.db"))
    
    # Check if service is installed
    service_mgr = ServiceManager()
    service_status = service_mgr.status()
    table.add_row("Service", service_status)
    
    console.print(table)


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
