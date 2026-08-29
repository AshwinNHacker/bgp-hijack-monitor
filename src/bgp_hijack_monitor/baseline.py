"""Build and refresh the trusted baseline of origin ASNs for each monitored prefix."""

from __future__ import annotations

import logging
import time

from .config import Config
from .models import BaselineEntry
from .ripestat import RipeStatClient
from .state import StateStore

logger = logging.getLogger("bgp_hijack_monitor.baseline")


def build_baseline(
    config: Config, store: StateStore, verify_against_config: bool = True
) -> list[str]:
    """Query RIPEstat for each configured prefix's current origin ASN(s) and
    persist it as the trusted baseline. Returns a list of human-readable
    warnings (e.g. mismatches between config and what's live right now)."""
    client = RipeStatClient(config.ripestat_base_url)
    warnings: list[str] = []

    for mp in config.prefixes:
        try:
            overview = client.prefix_overview(mp.prefix)
        except Exception as exc:  # network error, RIPEstat outage, etc.
            logger.warning("Could not fetch RIPEstat overview for %s: %s", mp.prefix, exc)
            warnings.append(f"{mp.prefix}: RIPEstat lookup failed ({exc}); using config only")
            store.upsert_baseline(
                BaselineEntry(
                    prefix=mp.prefix,
                    origin_asns=mp.expected_origin_asns,
                    source="config",
                    last_verified=time.time(),
                )
            )
            continue

        if not overview.announced or not overview.asns:
            warnings.append(
                f"{mp.prefix}: RIPEstat shows this prefix as NOT currently announced. "
                "If this is unexpected, verify with your router/upstream immediately."
            )
            store.upsert_baseline(
                BaselineEntry(
                    prefix=mp.prefix,
                    origin_asns=mp.expected_origin_asns,
                    source="config",
                    last_verified=time.time(),
                )
            )
            continue

        live_asns = set(overview.asns)
        expected_asns = set(mp.expected_origin_asns)

        if verify_against_config and live_asns != expected_asns:
            unexpected = live_asns - expected_asns
            missing = expected_asns - live_asns
            if unexpected:
                warnings.append(
                    f"{mp.prefix}: RIPEstat currently shows origin ASN(s) {sorted(unexpected)} "
                    f"which are NOT in your configured expected_origin_asns "
                    f"{sorted(expected_asns)}. Confirm this is legitimate before baselining, "
                    "otherwise you may be baselining an active hijack."
                )
            if missing:
                warnings.append(
                    f"{mp.prefix}: configured expected ASN(s) {sorted(missing)} are not "
                    f"currently seen announcing this prefix at all."
                )

        store.upsert_baseline(
            BaselineEntry(
                prefix=mp.prefix,
                origin_asns=sorted(live_asns),
                source="ripestat",
                last_verified=time.time(),
            )
        )
        logger.info("Baselined %s -> origin ASN(s) %s", mp.prefix, sorted(live_asns))

    return warnings
