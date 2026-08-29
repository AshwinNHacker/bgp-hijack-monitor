"""Console/log alert backend -- always safe, zero configuration."""

from __future__ import annotations

import datetime as dt
import logging

from ..models import HijackEvent
from .base import AlertBackend

logger = logging.getLogger("bgp_hijack_monitor.alerts.console")

_SEVERITY_COLOR = {
    "low": "\033[36m",       # cyan
    "medium": "\033[33m",    # yellow
    "high": "\033[91m",      # bright red
    "critical": "\033[41m\033[97m",  # white-on-red
}
_RESET = "\033[0m"


class ConsoleAlertBackend(AlertBackend):
    name = "console"

    def __init__(self, use_color: bool = True):
        self.use_color = use_color

    def send(self, event: HijackEvent) -> None:
        ts = dt.datetime.fromtimestamp(event.timestamp, tz=dt.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        color = _SEVERITY_COLOR.get(event.severity.value, "") if self.use_color else ""
        reset = _RESET if self.use_color else ""
        line = (
            f"{color}[{event.severity.value.upper():>8}] {ts} "
            f"{event.event_type.value}{reset} :: {event.message}"
        )
        print(line)
        logger.info(
            "%s | prefix=%s origin=%s expected=%s peer=%s",
            event.event_type.value,
            event.prefix,
            event.observed_origin_asn,
            event.expected_origin_asns,
            event.peer,
        )
