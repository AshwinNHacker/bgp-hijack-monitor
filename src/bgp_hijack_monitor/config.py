"""Configuration loading and validation for bgp-hijack-monitor."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ConfigError(Exception):
    """Raised when the configuration file is missing or invalid."""


@dataclass
class MonitoredPrefix:
    """A single prefix (or origin ASN) the operator wants watched."""

    prefix: str
    expected_origin_asns: list[int]
    description: str = ""
    # Allow a specific set of ASNs to legitimately announce more-specifics
    # of this prefix (e.g. an anycast provider, a DDoS-scrubbing partner).
    allowed_more_specific_asns: list[int] = field(default_factory=list)
    # Maximum acceptable AS-path length before it's flagged as suspicious
    # (a very short path can indicate path-prepending stripped by a hijacker).
    min_expected_path_length: int = 1

    def __post_init__(self) -> None:
        try:
            self.network = ipaddress.ip_network(self.prefix, strict=False)
        except ValueError as exc:
            raise ConfigError(f"Invalid prefix '{self.prefix}': {exc}") from exc
        if not self.expected_origin_asns:
            raise ConfigError(
                f"Prefix '{self.prefix}' must declare at least one "
                "expected_origin_asns entry"
            )


@dataclass
class EmailAlertConfig:
    enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    use_tls: bool = True
    username: str = ""
    password_env_var: str = "BGPMON_SMTP_PASSWORD"
    from_addr: str = ""
    to_addrs: list[str] = field(default_factory=list)

    @property
    def password(self) -> str:
        return os.environ.get(self.password_env_var, "")


@dataclass
class SlackAlertConfig:
    enabled: bool = False
    webhook_url_env_var: str = "BGPMON_SLACK_WEBHOOK_URL"

    @property
    def webhook_url(self) -> str:
        return os.environ.get(self.webhook_url_env_var, "")


@dataclass
class WebhookAlertConfig:
    enabled: bool = False
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class AlertingConfig:
    console: bool = True
    min_severity: str = "medium"  # low | medium | high | critical
    email: EmailAlertConfig = field(default_factory=EmailAlertConfig)
    slack: SlackAlertConfig = field(default_factory=SlackAlertConfig)
    webhook: WebhookAlertConfig = field(default_factory=WebhookAlertConfig)


@dataclass
class Config:
    org_name: str
    prefixes: list[MonitoredPrefix]
    alerting: AlertingConfig = field(default_factory=AlertingConfig)
    ris_live_url: str = "wss://ris-live.ripe.net/v1/ws/"
    ripestat_base_url: str = "https://stat.ripe.net"
    state_db_path: str = "bgp_monitor_state.sqlite3"
    reconnect_backoff_seconds: int = 5
    reconnect_backoff_max_seconds: int = 300
    heartbeat_timeout_seconds: int = 120
    client_name: str = "bgp-hijack-monitor"

    @staticmethod
    def load(path: str | Path) -> Config:
        path = Path(path)
        if not path.exists():
            raise ConfigError(f"Config file not found: {path}")

        with open(path, encoding="utf-8") as fh:
            raw: dict[str, Any] = yaml.safe_load(fh) or {}

        if "org_name" not in raw:
            raise ConfigError("Config must define 'org_name'")
        if not raw.get("prefixes"):
            raise ConfigError("Config must define at least one entry under 'prefixes'")

        prefixes = [MonitoredPrefix(**p) for p in raw["prefixes"]]

        alerting_raw = raw.get("alerting", {}) or {}
        alerting = AlertingConfig(
            console=alerting_raw.get("console", True),
            min_severity=alerting_raw.get("min_severity", "medium"),
            email=EmailAlertConfig(**alerting_raw.get("email", {}) or {}),
            slack=SlackAlertConfig(**alerting_raw.get("slack", {}) or {}),
            webhook=WebhookAlertConfig(**alerting_raw.get("webhook", {}) or {}),
        )

        return Config(
            org_name=raw["org_name"],
            prefixes=prefixes,
            alerting=alerting,
            ris_live_url=raw.get("ris_live_url", "wss://ris-live.ripe.net/v1/ws/"),
            ripestat_base_url=raw.get("ripestat_base_url", "https://stat.ripe.net"),
            state_db_path=raw.get("state_db_path", "bgp_monitor_state.sqlite3"),
            reconnect_backoff_seconds=raw.get("reconnect_backoff_seconds", 5),
            reconnect_backoff_max_seconds=raw.get("reconnect_backoff_max_seconds", 300),
            heartbeat_timeout_seconds=raw.get("heartbeat_timeout_seconds", 120),
            client_name=raw.get("client_name", "bgp-hijack-monitor"),
        )
