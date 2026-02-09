"""
IPMI Monitor Alerts Module

Handles sending alerts to the CryptoLabs Alert API for push notifications
to the CryptoLabs app, email, and web browser.

This module is prepared for future integration with the CryptoLabs Alert System.
Currently, it logs alerts locally. Once the Alert API is deployed, this module
will send alerts via HTTP POST to the centralized notification service.
"""

import logging
import threading
import time
import requests
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertType(Enum):
    """Supported alert types."""
    SERVER_DOWN = "server_down"
    SERVER_UP = "server_up"
    TEMPERATURE = "temperature"
    POWER = "power"
    DISK = "disk"
    MEMORY = "memory"
    CRITICAL_EVENT = "critical_event"
    WARNING_EVENT = "warning_event"
    SEL_EVENT = "sel_event"


@dataclass
class Alert:
    """Represents an alert to be sent."""
    alert_type: str
    severity: str
    title: str
    message: str
    server_id: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    source: str = "ipmi-monitor"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary for API payload."""
        return {
            "source": self.source,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "server_id": self.server_id,
            "timestamp": self.timestamp.isoformat() + "Z",
            "metadata": self.metadata,
        }


class AlertManager:
    """Manages alert sending with rate limiting and queuing.
    
    This class handles:
    - Rate limiting (prevents alert spam)
    - Alert queuing (for reliable delivery)
    - Deduplication (prevents duplicate alerts)
    - Retry logic (for transient failures)
    
    Currently operates in "log-only" mode until the CryptoLabs Alert API
    is deployed and configured.
    """
    
    def __init__(self):
        self._config = None
        self._rate_limit_cache: Dict[str, datetime] = {}
        self._alert_counts: Dict[str, int] = {}  # Daily counts per user
        self._count_reset_date: str = ""
        self._lock = threading.Lock()
        self._queue: List[Alert] = []
        self._queue_processor: Optional[threading.Thread] = None
        self._running = False
    
    def configure(self, config):
        """Configure the alert manager with notification settings.
        
        Args:
            config: NotificationConfig instance from config module
        """
        self._config = config
        
        if config.enabled:
            logger.info("Alert system enabled")
            if config.cryptolabs_api_key:
                logger.info("CryptoLabs API key configured")
            else:
                logger.warning("Alert system enabled but no API key configured")
        else:
            logger.debug("Alert system disabled")
    
    def start(self):
        """Start the background queue processor."""
        if self._running:
            return
        
        self._running = True
        self._queue_processor = threading.Thread(
            target=self._process_queue,
            daemon=True,
            name="AlertQueueProcessor"
        )
        self._queue_processor.start()
        logger.debug("Alert queue processor started")
    
    def stop(self):
        """Stop the background queue processor."""
        self._running = False
        if self._queue_processor:
            self._queue_processor.join(timeout=5)
        logger.debug("Alert queue processor stopped")
    
    def send_alert(
        self,
        alert_type: str,
        title: str,
        message: str,
        server_id: str,
        severity: str = "warning",
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Send an alert to the CryptoLabs Alert API.
        
        Args:
            alert_type: Type of alert (server_down, temperature, etc.)
            title: Short alert title
            message: Detailed alert message
            server_id: Identifier for the server/device
            severity: Alert severity (info, warning, critical)
            metadata: Additional data to include with the alert
            
        Returns:
            True if alert was queued/sent, False if rate limited or disabled
        """
        # Check if notifications are configured and enabled
        if not self._config or not self._config.enabled:
            logger.debug(f"Alert not sent (disabled): {alert_type} - {title}")
            return False
        
        # Check if this alert type is enabled
        if not self._config.is_alert_type_enabled(alert_type):
            logger.debug(f"Alert type disabled: {alert_type}")
            return False
        
        # Check rate limiting
        if self._is_rate_limited(alert_type, server_id):
            logger.debug(f"Alert rate limited: {alert_type} for {server_id}")
            return False
        
        # Check daily limit
        if self._is_daily_limit_exceeded():
            logger.warning("Daily alert limit exceeded")
            return False
        
        # Create alert
        alert = Alert(
            alert_type=alert_type,
            severity=severity,
            title=title,
            message=message,
            server_id=server_id,
            metadata=metadata or {},
        )
        
        # Log the alert (always, for debugging)
        logger.info(
            f"[ALERT] {severity.upper()}: {alert_type} - {title} "
            f"(server: {server_id})"
        )
        
        # Update rate limit cache
        self._update_rate_limit(alert_type, server_id)
        self._increment_daily_count()
        
        # Queue for sending (when API is available)
        self._queue_alert(alert)
        
        return True
    
    def send_server_down_alert(
        self,
        server_id: str,
        server_name: str,
        last_seen: Optional[datetime] = None,
        reason: str = "No response"
    ) -> bool:
        """Convenience method for server down alerts."""
        time_str = ""
        if last_seen:
            delta = datetime.utcnow() - last_seen
            time_str = f" (last seen {int(delta.total_seconds() / 60)} minutes ago)"
        
        return self.send_alert(
            alert_type=AlertType.SERVER_DOWN.value,
            severity="critical",
            title=f"Server {server_name} is DOWN",
            message=f"{reason}{time_str}",
            server_id=server_id,
            metadata={
                "server_name": server_name,
                "last_seen": last_seen.isoformat() if last_seen else None,
                "reason": reason,
            }
        )
    
    def send_server_up_alert(
        self,
        server_id: str,
        server_name: str,
        downtime_minutes: Optional[int] = None
    ) -> bool:
        """Convenience method for server recovery alerts."""
        downtime_str = ""
        if downtime_minutes:
            downtime_str = f" (was down for {downtime_minutes} minutes)"
        
        return self.send_alert(
            alert_type=AlertType.SERVER_UP.value,
            severity="info",
            title=f"Server {server_name} is UP",
            message=f"Server has recovered{downtime_str}",
            server_id=server_id,
            metadata={
                "server_name": server_name,
                "downtime_minutes": downtime_minutes,
            }
        )
    
    def send_temperature_alert(
        self,
        server_id: str,
        server_name: str,
        component: str,
        temperature: float,
        threshold: float,
        is_critical: bool = False
    ) -> bool:
        """Convenience method for temperature threshold alerts."""
        severity = "critical" if is_critical else "warning"
        
        return self.send_alert(
            alert_type=AlertType.TEMPERATURE.value,
            severity=severity,
            title=f"High temperature on {server_name}",
            message=f"{component}: {temperature}°C (threshold: {threshold}°C)",
            server_id=server_id,
            metadata={
                "server_name": server_name,
                "component": component,
                "temperature": temperature,
                "threshold": threshold,
            }
        )
    
    def send_sel_event_alert(
        self,
        server_id: str,
        server_name: str,
        event_type: str,
        event_message: str,
        is_critical: bool = False
    ) -> bool:
        """Convenience method for SEL (System Event Log) alerts."""
        alert_type = AlertType.CRITICAL_EVENT.value if is_critical else AlertType.WARNING_EVENT.value
        severity = "critical" if is_critical else "warning"
        
        return self.send_alert(
            alert_type=alert_type,
            severity=severity,
            title=f"SEL Event on {server_name}: {event_type}",
            message=event_message,
            server_id=server_id,
            metadata={
                "server_name": server_name,
                "event_type": event_type,
            }
        )
    
    def _is_rate_limited(self, alert_type: str, server_id: str) -> bool:
        """Check if an alert is rate limited."""
        if not self._config:
            return False
        
        key = f"{alert_type}:{server_id}"
        with self._lock:
            if key in self._rate_limit_cache:
                last_sent = self._rate_limit_cache[key]
                min_interval = timedelta(minutes=self._config.rate_limit_minutes)
                if datetime.utcnow() - last_sent < min_interval:
                    return True
        return False
    
    def _update_rate_limit(self, alert_type: str, server_id: str):
        """Update rate limit cache for an alert."""
        key = f"{alert_type}:{server_id}"
        with self._lock:
            self._rate_limit_cache[key] = datetime.utcnow()
    
    def _is_daily_limit_exceeded(self) -> bool:
        """Check if daily alert limit is exceeded."""
        if not self._config or self._config.max_alerts_per_day <= 0:
            return False
        
        today = datetime.utcnow().strftime("%Y-%m-%d")
        with self._lock:
            if self._count_reset_date != today:
                self._alert_counts = {}
                self._count_reset_date = today
            
            total = sum(self._alert_counts.values())
            return total >= self._config.max_alerts_per_day
    
    def _increment_daily_count(self):
        """Increment daily alert count."""
        with self._lock:
            key = "total"
            self._alert_counts[key] = self._alert_counts.get(key, 0) + 1
    
    def _queue_alert(self, alert: Alert):
        """Add alert to the send queue."""
        with self._lock:
            self._queue.append(alert)
    
    def _process_queue(self):
        """Background thread to process alert queue.
        
        Currently logs alerts. When Alert API is deployed, this will
        send alerts via HTTP POST.
        """
        while self._running:
            try:
                alerts_to_send = []
                with self._lock:
                    if self._queue:
                        alerts_to_send = self._queue[:]
                        self._queue.clear()
                
                for alert in alerts_to_send:
                    self._send_to_api(alert)
                
            except Exception as e:
                logger.error(f"Error processing alert queue: {e}")
            
            # Sleep between queue checks
            time.sleep(1)
    
    def _send_to_api(self, alert: Alert) -> bool:
        """Send alert to DC Watchdog / CryptoLabs Alert API.
        
        Sends alerts to dc-watchdog.cryptolabs.co.za/api/event which then
        forwards to WordPress for push notifications, email, etc.
        
        Returns:
            True if alert was sent successfully, False otherwise.
        """
        if not self._config or not self._config.cryptolabs_api_key:
            # No API key configured, just log
            logger.debug(f"Alert logged (no API key): {alert.to_dict()}")
            return False
        
        # Build payload for dc-watchdog /api/event endpoint
        payload = {
            "event_type": alert.alert_type,
            "server_id": alert.server_id,
            "message": alert.message,
            "severity": alert.severity,
            "source": alert.source,
            "timestamp": alert.timestamp.isoformat() + "Z",
        }
        
        # Add metadata if present
        if alert.metadata:
            payload["metadata"] = alert.metadata
        
        # Determine endpoint - default to dc-watchdog
        endpoint = getattr(self._config, 'alert_endpoint', None)
        if not endpoint:
            endpoint = "https://dc-watchdog.cryptolabs.co.za/api/event"
        
        headers = {
            "Authorization": f"Bearer {self._config.cryptolabs_api_key}",
            "Content-Type": "application/json",
            "User-Agent": "IPMI-Monitor/1.0",
        }
        
        max_retries = 3
        retry_delay = 2  # seconds
        
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    endpoint,
                    json=payload,
                    headers=headers,
                    timeout=15,
                )
                
                if response.status_code == 200:
                    logger.info(f"[ALERT SENT] {alert.alert_type} for {alert.server_id} -> {endpoint}")
                    return True
                elif response.status_code == 402:
                    # Payment required - subscription issue
                    logger.warning(f"Alert rejected (subscription inactive): {alert.alert_type} for {alert.server_id}")
                    return False
                elif response.status_code == 429:
                    # Rate limited
                    logger.warning(f"Alert rate limited: {alert.alert_type} for {alert.server_id}")
                    return False
                elif response.status_code >= 500:
                    # Server error - retry
                    logger.warning(f"Alert API returned {response.status_code}, retrying...")
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay * (attempt + 1))
                        continue
                else:
                    # Client error - don't retry
                    logger.error(f"Alert API returned {response.status_code}: {response.text[:200]}")
                    return False
                    
            except requests.exceptions.Timeout:
                logger.warning(f"Alert API timeout (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Alert API connection error (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
            except Exception as e:
                logger.error(f"Failed to send alert to API: {e}")
                return False
        
        logger.error(f"Failed to send alert after {max_retries} attempts: {alert.alert_type} for {alert.server_id}")
        return False


# Global alert manager instance
_alert_manager: Optional[AlertManager] = None


def get_alert_manager() -> AlertManager:
    """Get the global alert manager instance."""
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()
    return _alert_manager


def init_alerts(config=None):
    """Initialize the alert system.
    
    Args:
        config: NotificationConfig instance, or None to load from global config
    """
    manager = get_alert_manager()
    
    if config is None:
        # Try to load from global config
        try:
            from .config import get_config
            config = get_config().notifications
        except ImportError:
            logger.warning("Could not load notification config")
            return manager
    
    manager.configure(config)
    manager.start()
    return manager


def send_alert(
    alert_type: str,
    title: str,
    message: str,
    server_id: str,
    severity: str = "warning",
    metadata: Optional[Dict[str, Any]] = None
) -> bool:
    """Convenience function to send an alert.
    
    This is the main entry point for sending alerts from anywhere in
    the IPMI Monitor codebase.
    
    Args:
        alert_type: Type of alert (server_down, temperature, etc.)
        title: Short alert title  
        message: Detailed alert message
        server_id: Identifier for the server/device
        severity: Alert severity (info, warning, critical)
        metadata: Additional data to include with the alert
        
    Returns:
        True if alert was queued/sent, False if rate limited or disabled
        
    Example:
        from ipmi_monitor.alerts import send_alert
        
        send_alert(
            alert_type="critical_event",
            title="Power Supply Failure",
            message="PSU 1 has failed on server rack-01",
            server_id="rack-01",
            severity="critical",
            metadata={"psu_id": 1}
        )
    """
    return get_alert_manager().send_alert(
        alert_type=alert_type,
        title=title,
        message=message,
        server_id=server_id,
        severity=severity,
        metadata=metadata
    )
