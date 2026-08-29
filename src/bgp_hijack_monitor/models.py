"""Shared data models."""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]


class EventType(str, enum.Enum):
    ORIGIN_MISMATCH = "origin_mismatch"
    UNAUTHORIZED_SUBPREFIX = "unauthorized_subprefix"
    MOAS_CONFLICT = "moas_conflict"
    SUSPICIOUS_PATH_LENGTH = "suspicious_path_length"
    ROUTE_LEAK_SUSPECTED = "route_leak_suspected"
    ROUTE_WITHDRAWN = "route_withdrawn"
    NEW_ANNOUNCEMENT_OK = "new_announcement_ok"


@dataclass
class BgpUpdate:
    """A normalized representation of one RIS Live UPDATE/withdrawal message."""

    raw_prefix: str
    announced: bool  # True = announcement, False = withdrawal
    as_path: list[int]
    origin_asn: int | None
    peer: str
    collector: str
    timestamp: float
    community: list[str] = field(default_factory=list)

    @property
    def age_seconds(self) -> float:
        return time.time() - self.timestamp


@dataclass
class HijackEvent:
    event_type: EventType
    severity: Severity
    prefix: str
    matched_config_prefix: str
    observed_origin_asn: int | None
    expected_origin_asns: list[int]
    as_path: list[int]
    peer: str
    collector: str
    timestamp: float
    message: str

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "prefix": self.prefix,
            "matched_config_prefix": self.matched_config_prefix,
            "observed_origin_asn": self.observed_origin_asn,
            "expected_origin_asns": self.expected_origin_asns,
            "as_path": self.as_path,
            "peer": self.peer,
            "collector": self.collector,
            "timestamp": self.timestamp,
            "message": self.message,
        }


@dataclass
class BaselineEntry:
    prefix: str
    origin_asns: list[int]
    source: str  # "ripestat" | "manual" | "config"
    last_verified: float
