"""Generic JSON webhook alert backend (Discord, PagerDuty relays, custom endpoints, etc.)."""

from __future__ import annotations

import logging

import requests

from ..config import WebhookAlertConfig
from ..models import HijackEvent
from .base import AlertBackend

logger = logging.getLogger("bgp_hijack_monitor.alerts.webhook")


class WebhookAlertBackend(AlertBackend):
    name = "webhook"

    def __init__(self, cfg: WebhookAlertConfig):
        self.cfg = cfg

    def send(self, event: HijackEvent) -> None:
        if not self.cfg.enabled:
            return
        if not self.cfg.url:
            logger.warning("Webhook alerting enabled but URL is not set")
            return
        try:
            resp = requests.post(
                self.cfg.url,
                json=event.to_dict(),
                headers=self.cfg.headers or {},
                timeout=10,
            )
            resp.raise_for_status()
        except Exception:
            logger.exception("Failed to send webhook alert")
