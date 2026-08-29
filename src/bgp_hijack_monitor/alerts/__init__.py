"""Alert backends and dispatch manager."""

from __future__ import annotations

import logging

from ..config import AlertingConfig
from ..models import HijackEvent, Severity
from .base import AlertBackend
from .console import ConsoleAlertBackend
from .email_alert import EmailAlertBackend
from .slack_alert import SlackAlertBackend
from .webhook_alert import WebhookAlertBackend

logger = logging.getLogger("bgp_hijack_monitor.alerts")

__all__ = [
    "AlertBackend",
    "ConsoleAlertBackend",
    "EmailAlertBackend",
    "SlackAlertBackend",
    "WebhookAlertBackend",
    "AlertManager",
]


class AlertManager:
    """Fans a HijackEvent out to every configured, enabled backend."""

    def __init__(self, cfg: AlertingConfig):
        self.cfg = cfg
        self.min_severity = Severity(cfg.min_severity)
        self.backends: list[AlertBackend] = []

        if cfg.console:
            self.backends.append(ConsoleAlertBackend())
        if cfg.email.enabled:
            self.backends.append(EmailAlertBackend(cfg.email))
        if cfg.slack.enabled:
            self.backends.append(SlackAlertBackend(cfg.slack))
        if cfg.webhook.enabled:
            self.backends.append(WebhookAlertBackend(cfg.webhook))

    def dispatch(self, event: HijackEvent) -> None:
        if event.severity.rank < self.min_severity.rank:
            return
        for backend in self.backends:
            try:
                backend.send(event)
            except Exception:
                logger.exception("Alert backend %s failed", backend.name)
