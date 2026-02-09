"""
IPMI Monitor Configuration Module

Handles configuration loading from environment variables and config files.
Provides a centralized configuration object for all settings.
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class NotificationConfig:
    """Configuration for CryptoLabs Alert System notifications.
    
    This prepares IPMI Monitor for future integration with the CryptoLabs
    Alert API, allowing push notifications to the CryptoLabs app, email,
    and web browser.
    """
    # Master enable/disable for notifications
    enabled: bool = False
    
    # CryptoLabs API key for authentication with Alert API
    # Users will link their CryptoLabs account to get this key
    cryptolabs_api_key: str = ""
    
    # Alert API endpoint
    alert_endpoint: str = "https://ipmi-ai.cryptolabs.co.za/api/v1/alerts/send"
    
    # Rate limiting - minimum minutes between alerts of same type for same server
    rate_limit_minutes: int = 5
    
    # Maximum alerts per day per user (0 = unlimited)
    max_alerts_per_day: int = 100
    
    # Which alert types to send
    alert_types: Dict[str, bool] = field(default_factory=lambda: {
        'server_down': True,
        'server_up': True,
        'temperature': True,
        'power': True,
        'disk': True,
        'memory': True,
        'critical_event': True,
        'warning_event': True,
        'sel_event': True,
    })
    
    # Temperature thresholds (Celsius) - for future threshold-based alerts
    thresholds: Dict[str, int] = field(default_factory=lambda: {
        'cpu_temp_warning': 80,
        'cpu_temp_critical': 90,
        'gpu_temp_warning': 85,
        'gpu_temp_critical': 95,
        'ambient_temp_warning': 35,
        'ambient_temp_critical': 45,
    })
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NotificationConfig':
        """Create NotificationConfig from dictionary."""
        if not data:
            return cls()
        
        config = cls()
        config.enabled = data.get('enabled', False)
        config.cryptolabs_api_key = data.get('cryptolabs_api_key', '')
        config.alert_endpoint = data.get('alert_endpoint', config.alert_endpoint)
        config.rate_limit_minutes = data.get('rate_limit_minutes', 5)
        config.max_alerts_per_day = data.get('max_alerts_per_day', 100)
        
        # Merge alert types
        if 'alert_types' in data:
            config.alert_types.update(data['alert_types'])
        
        # Merge thresholds
        if 'thresholds' in data:
            config.thresholds.update(data['thresholds'])
        
        return config
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'enabled': self.enabled,
            'cryptolabs_api_key': self.cryptolabs_api_key,
            'alert_endpoint': self.alert_endpoint,
            'rate_limit_minutes': self.rate_limit_minutes,
            'max_alerts_per_day': self.max_alerts_per_day,
            'alert_types': self.alert_types,
            'thresholds': self.thresholds,
        }
    
    def is_alert_type_enabled(self, alert_type: str) -> bool:
        """Check if a specific alert type is enabled."""
        return self.enabled and self.alert_types.get(alert_type, False)


@dataclass  
class IPMIMonitorConfig:
    """Main configuration class for IPMI Monitor.
    
    Loads configuration from:
    1. Environment variables (highest priority)
    2. Config file (config.yaml in data directory)
    3. Defaults (lowest priority)
    """
    # Data directory
    data_dir: str = ""
    
    # IPMI credentials
    ipmi_user: str = "admin"
    ipmi_pass: str = ""
    
    # Application settings
    app_name: str = "IPMI Monitor"
    secret_key: str = ""
    
    # Rate limiting
    rate_limit_window_seconds: int = 300
    rate_limit_max_attempts: int = 5
    rate_limit_lockout_seconds: int = 900
    
    # Session settings
    session_cookie_secure: bool = False
    
    # API settings
    api_key: str = ""
    
    # Notifications (future CryptoLabs Alert System integration)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    
    @classmethod
    def load(cls, data_dir: Optional[str] = None) -> 'IPMIMonitorConfig':
        """Load configuration from environment and config file."""
        config = cls()
        
        # Determine data directory
        if data_dir:
            config.data_dir = data_dir
        elif os.environ.get('DATA_DIR'):
            config.data_dir = os.environ['DATA_DIR']
        elif os.geteuid() == 0:
            config.data_dir = '/var/lib/ipmi-monitor'
        else:
            config.data_dir = os.path.expanduser('~/.config/ipmi-monitor')
        
        # Load from config file if exists
        config_file = Path(config.data_dir) / 'config.yaml'
        if config_file.exists():
            try:
                with open(config_file) as f:
                    file_config = yaml.safe_load(f) or {}
                config._apply_dict(file_config)
                logger.info(f"Loaded config from {config_file}")
            except Exception as e:
                logger.warning(f"Failed to load config file: {e}")
        
        # Override with environment variables (highest priority)
        config._apply_env()
        
        return config
    
    def _apply_dict(self, data: Dict[str, Any]):
        """Apply configuration from dictionary."""
        self.ipmi_user = data.get('ipmi_user', self.ipmi_user)
        self.ipmi_pass = data.get('ipmi_pass', self.ipmi_pass)
        self.app_name = data.get('app_name', self.app_name)
        self.secret_key = data.get('secret_key', self.secret_key)
        self.api_key = data.get('api_key', self.api_key)
        
        self.rate_limit_window_seconds = data.get('rate_limit_window_seconds', self.rate_limit_window_seconds)
        self.rate_limit_max_attempts = data.get('rate_limit_max_attempts', self.rate_limit_max_attempts)
        self.rate_limit_lockout_seconds = data.get('rate_limit_lockout_seconds', self.rate_limit_lockout_seconds)
        
        self.session_cookie_secure = data.get('session_cookie_secure', self.session_cookie_secure)
        
        # Load notifications config
        if 'notifications' in data:
            self.notifications = NotificationConfig.from_dict(data['notifications'])
    
    def _apply_env(self):
        """Apply configuration from environment variables."""
        self.ipmi_user = os.environ.get('IPMI_USER', self.ipmi_user)
        self.ipmi_pass = os.environ.get('IPMI_PASS', self.ipmi_pass)
        self.app_name = os.environ.get('APP_NAME', self.app_name)
        self.secret_key = os.environ.get('SECRET_KEY', self.secret_key)
        self.api_key = os.environ.get('API_KEY', self.api_key)
        
        if os.environ.get('RATE_LIMIT_WINDOW_SECONDS'):
            self.rate_limit_window_seconds = int(os.environ['RATE_LIMIT_WINDOW_SECONDS'])
        if os.environ.get('RATE_LIMIT_MAX_ATTEMPTS'):
            self.rate_limit_max_attempts = int(os.environ['RATE_LIMIT_MAX_ATTEMPTS'])
        if os.environ.get('RATE_LIMIT_LOCKOUT_SECONDS'):
            self.rate_limit_lockout_seconds = int(os.environ['RATE_LIMIT_LOCKOUT_SECONDS'])
        
        if os.environ.get('SESSION_COOKIE_SECURE'):
            self.session_cookie_secure = os.environ['SESSION_COOKIE_SECURE'].lower() == 'true'
        
        # Notification settings from environment
        if os.environ.get('NOTIFICATIONS_ENABLED'):
            self.notifications.enabled = os.environ['NOTIFICATIONS_ENABLED'].lower() == 'true'
        if os.environ.get('CRYPTOLABS_API_KEY'):
            self.notifications.cryptolabs_api_key = os.environ['CRYPTOLABS_API_KEY']
        if os.environ.get('ALERT_ENDPOINT'):
            self.notifications.alert_endpoint = os.environ['ALERT_ENDPOINT']
    
    def save(self):
        """Save configuration to file."""
        config_file = Path(self.data_dir) / 'config.yaml'
        Path(self.data_dir).mkdir(parents=True, exist_ok=True)
        
        data = {
            'ipmi_user': self.ipmi_user,
            'app_name': self.app_name,
            'rate_limit_window_seconds': self.rate_limit_window_seconds,
            'rate_limit_max_attempts': self.rate_limit_max_attempts,
            'rate_limit_lockout_seconds': self.rate_limit_lockout_seconds,
            'session_cookie_secure': self.session_cookie_secure,
            'notifications': self.notifications.to_dict(),
        }
        
        # Don't save sensitive values
        # ipmi_pass, secret_key, api_key should be set via environment
        
        with open(config_file, 'w') as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        
        # Secure the file
        os.chmod(config_file, 0o600)
        logger.info(f"Saved config to {config_file}")


# Global config instance (lazy-loaded)
_config: Optional[IPMIMonitorConfig] = None


def get_config() -> IPMIMonitorConfig:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = IPMIMonitorConfig.load()
    return _config


def reload_config():
    """Reload configuration from disk."""
    global _config
    _config = IPMIMonitorConfig.load()
    return _config
