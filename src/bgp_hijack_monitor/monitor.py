"""The live monitoring loop: RIS Live stream -> detector -> state -> alerts."""

from __future__ import annotations

import logging

from .alerts import AlertManager
from .config import Config
from .detector import evaluate_update
from .models import EventType
from .ris_live import RisLiveClient
from .state import StateStore

logger = logging.getLogger("bgp_hijack_monitor.monitor")


async def run_monitor(config: Config, store: StateStore, alert_manager: AlertManager) -> None:
    prefixes = [mp.prefix for mp in config.prefixes]
    client = RisLiveClient(
        prefixes=prefixes,
        url=config.ris_live_url,
        client_name=config.client_name,
        reconnect_backoff_seconds=config.reconnect_backoff_seconds,
        reconnect_backoff_max_seconds=config.reconnect_backoff_max_seconds,
        heartbeat_timeout_seconds=config.heartbeat_timeout_seconds,
    )

    logger.info(
        "Starting monitor for %d prefix(es) belonging to '%s'",
        len(prefixes),
        config.org_name,
    )
    for mp in config.prefixes:
        logger.info("  watching %s (expected origin AS%s)", mp.prefix, mp.expected_origin_asns)

    async for update in client.stream():
        known_origins = store.all_known_origins()

        events = evaluate_update(update, config.prefixes, known_origins=known_origins)

        if update.announced and update.origin_asn is not None:
            store.note_observed_origin(update.raw_prefix, update.origin_asn)

        for event in events:
            if event.event_type == EventType.NEW_ANNOUNCEMENT_OK:
                # Don't spam storage/alerts for routine, expected traffic;
                # still useful for `check` command's live confirmation though.
                continue
            store.record_event(event)
            alert_manager.dispatch(event)


def run_monitor_forever(config: Config, store: StateStore, alert_manager: AlertManager) -> None:
    """Sync wrapper for CLI entrypoints."""
    import asyncio

    try:
        asyncio.run(run_monitor(config, store, alert_manager))
    except KeyboardInterrupt:
        logger.info("Monitor stopped by user")
