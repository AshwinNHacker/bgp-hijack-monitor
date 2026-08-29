"""SMTP email alert backend."""

from __future__ import annotations

import datetime as dt
import logging
import smtplib
from email.mime.text import MIMEText

from ..config import EmailAlertConfig
from ..models import HijackEvent
from .base import AlertBackend

logger = logging.getLogger("bgp_hijack_monitor.alerts.email")


class EmailAlertBackend(AlertBackend):
    name = "email"

    def __init__(self, cfg: EmailAlertConfig):
        self.cfg = cfg

    def send(self, event: HijackEvent) -> None:
        if not self.cfg.enabled:
            return
        try:
            ts = dt.datetime.fromtimestamp(event.timestamp, tz=dt.timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC"
            )
            subject = (
                f"[BGP ALERT:{event.severity.value.upper()}] "
                f"{event.event_type.value} on {event.prefix}"
            )
            body = (
                f"Severity: {event.severity.value.upper()}\n"
                f"Event type: {event.event_type.value}\n"
                f"Time: {ts}\n"
                f"Prefix: {event.prefix}\n"
                f"Monitored (parent) prefix: {event.matched_config_prefix}\n"
                f"Observed origin ASN: {event.observed_origin_asn}\n"
                f"Expected origin ASN(s): {event.expected_origin_asns}\n"
                f"AS path: {event.as_path}\n"
                f"Seen via peer: {event.peer} (collector: {event.collector})\n\n"
                f"{event.message}\n"
            )
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = self.cfg.from_addr
            msg["To"] = ", ".join(self.cfg.to_addrs)

            with smtplib.SMTP(self.cfg.smtp_host, self.cfg.smtp_port, timeout=15) as server:
                if self.cfg.use_tls:
                    server.starttls()
                if self.cfg.username:
                    server.login(self.cfg.username, self.cfg.password)
                server.sendmail(self.cfg.from_addr, self.cfg.to_addrs, msg.as_string())
        except Exception:
            logger.exception("Failed to send email alert")
