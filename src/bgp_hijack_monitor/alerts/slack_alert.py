"""Slack (incoming webhook) alert backend."""

from __future__ import annotations

import logging

import requests

from ..config import SlackAlertConfig
from ..models import HijackEvent
from .base import AlertBackend

logger = logging.getLogger("bgp_hijack_monitor.alerts.slack")

_SEVERITY_EMOJI = {
    "low": ":large_blue_circle:",
    "medium": ":large_yellow_circle:",
    "high": ":large_orange_circle:",
    "critical": ":red_circle:",
}


class SlackAlertBackend(AlertBackend):
    name = "slack"

    def __init__(self, cfg: SlackAlertConfig):
        self.cfg = cfg

    def send(self, event: HijackEvent) -> None:
        if not self.cfg.enabled:
            return
        url = self.cfg.webhook_url
        if not url:
            logger.warning("Slack alerting enabled but webhook URL is not set")
            return
        emoji = _SEVERITY_EMOJI.get(event.severity.value, ":warning:")
        text = (
            f"{emoji} *{event.severity.value.upper()} — {event.event_type.value}*\n"
            f"*Prefix:* `{event.prefix}` (monitored: `{event.matched_config_prefix}`)\n"
            f"*Observed origin ASN:* {event.observed_origin_asn}  "
            f"*Expected:* {event.expected_origin_asns}\n"
            f"*AS path:* {event.as_path}\n"
            f"*Peer/collector:* {event.peer} / {event.collector}\n"
            f"{event.message}"
        )
        try:
            resp = requests.post(url, json={"text": text}, timeout=10)
            resp.raise_for_status()
        except Exception:
            logger.exception("Failed to send Slack alert")
