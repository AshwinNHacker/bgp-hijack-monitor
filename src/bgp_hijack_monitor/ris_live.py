"""
Client for RIPE RIS Live — a real-time WebSocket feed of BGP UPDATE
messages seen by RIPE NCC's Routing Information Service (RIS) route
collectors, positioned at ~25 major IXPs and transit points worldwide.

Docs: https://ris-live.ripe.net/

We subscribe with a server-side `prefix` filter so we only receive
messages relevant to the prefixes we care about, keeping bandwidth and
CPU usage low enough to comfortably run on a small VM or a Raspberry Pi.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator

import websockets
from websockets.exceptions import ConnectionClosed

from .models import BgpUpdate

logger = logging.getLogger(__name__)


def _parse_as_path(path_field) -> list[int]:
    """RIS Live encodes AS-sets as nested lists; flatten to a simple path,
    keeping only real ASNs (skips AS-SET brackets, dedups adjacent prepends
    only where needed by callers -- we keep the raw path here)."""
    out: list[int] = []
    if not path_field:
        return out
    for hop in path_field:
        if isinstance(hop, list):
            # AS_SET - take the first ASN as representative
            if hop:
                out.append(int(hop[0]))
        else:
            out.append(int(hop))
    return out


class RisLiveClient:
    """Async iterator yielding normalized BgpUpdate objects for the given prefixes."""

    def __init__(
        self,
        prefixes: list[str],
        url: str = "wss://ris-live.ripe.net/v1/ws/",
        client_name: str = "bgp-hijack-monitor",
        reconnect_backoff_seconds: int = 5,
        reconnect_backoff_max_seconds: int = 300,
        heartbeat_timeout_seconds: int = 120,
    ):
        self.prefixes = prefixes
        self.url = url
        self.client_name = client_name
        self.reconnect_backoff_seconds = reconnect_backoff_seconds
        self.reconnect_backoff_max_seconds = reconnect_backoff_max_seconds
        self.heartbeat_timeout_seconds = heartbeat_timeout_seconds
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    async def _subscribe(self, ws) -> None:
        # One subscription message per prefix (RIS Live filters server-side,
        # which means for TCP hijack-adjacent noise we never see it at all).
        for prefix in self.prefixes:
            sub = {
                "type": "ris_subscribe",
                "data": {
                    "prefix": prefix,
                    "moreSpecific": True,
                    "lessSpecific": False,
                    "type": "UPDATE",
                    "socketOptions": {"includeRaw": False},
                },
            }
            await ws.send(json.dumps(sub))
            logger.debug("Subscribed to RIS Live for prefix %s", prefix)

    async def stream(self) -> AsyncIterator[BgpUpdate]:
        """Yield BgpUpdate objects forever, reconnecting with backoff on failure."""
        backoff = self.reconnect_backoff_seconds
        query = f"?client={self.client_name}"
        while not self._stop:
            try:
                async with websockets.connect(
                    self.url + query, ping_interval=20, ping_timeout=20
                ) as ws:
                    await self._subscribe(ws)
                    backoff = self.reconnect_backoff_seconds  # reset after success
                    last_message = time.time()

                    while not self._stop:
                        try:
                            raw = await asyncio.wait_for(
                                ws.recv(), timeout=self.heartbeat_timeout_seconds
                            )
                        except asyncio.TimeoutError:
                            elapsed = time.time() - last_message
                            logger.warning(
                                "No RIS Live messages in %.0fs, reconnecting", elapsed
                            )
                            break

                        last_message = time.time()
                        for update in self._parse_message(raw):
                            yield update

            except (ConnectionClosed, OSError) as exc:
                logger.warning("RIS Live connection lost: %s. Reconnecting in %ss", exc, backoff)
            except Exception:
                logger.exception("Unexpected error in RIS Live stream loop")

            if self._stop:
                break
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, self.reconnect_backoff_max_seconds)

    def _parse_message(self, raw: str) -> list[BgpUpdate]:
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            logger.debug("Non-JSON message ignored")
            return []

        if msg.get("type") != "ris_message":
            return []

        data = msg.get("data", {})
        updates: list[BgpUpdate] = []
        peer = data.get("peer", "unknown")
        collector = data.get("host", data.get("raw", "unknown"))
        timestamp = data.get("timestamp", time.time())
        path = _parse_as_path(data.get("path"))
        origin = path[-1] if path else None
        communities = [
            f"{c[0]}:{c[1]}" for c in (data.get("community") or []) if isinstance(c, list)
        ]

        announcements = data.get("announcements") or []
        for ann in announcements:
            for prefix in ann.get("prefixes", []):
                updates.append(
                    BgpUpdate(
                        raw_prefix=prefix,
                        announced=True,
                        as_path=path,
                        origin_asn=origin,
                        peer=peer,
                        collector=str(collector),
                        timestamp=float(timestamp),
                        community=communities,
                    )
                )

        withdrawals = data.get("withdrawals") or []
        for prefix in withdrawals:
            updates.append(
                BgpUpdate(
                    raw_prefix=prefix,
                    announced=False,
                    as_path=[],
                    origin_asn=None,
                    peer=peer,
                    collector=str(collector),
                    timestamp=float(timestamp),
                    community=communities,
                )
            )

        return updates
