"""Base interface for alert backends."""

from __future__ import annotations

import abc

from ..models import HijackEvent


class AlertBackend(abc.ABC):
    name: str = "base"

    @abc.abstractmethod
    def send(self, event: HijackEvent) -> None:
        """Deliver an alert for the given event. Must not raise on failure
        (log and swallow), so one broken backend never blocks the others."""
        raise NotImplementedError
