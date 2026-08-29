"""
Core detection logic.

Given a normalized BgpUpdate and the operator's configured baseline for
the matching prefix, decide whether the update represents:

1. ORIGIN_MISMATCH        - the exact prefix is now announced by an ASN
                             that is not in the expected/allowed set.
                             (Classic "type-0" hijack.)
2. UNAUTHORIZED_SUBPREFIX - a more-specific of a monitored prefix appears,
                             originated by an unexpected ASN.
                             (Classic "sub-prefix hijack" -- e.g. the 2008
                             Pakistan Telecom / YouTube incident, 2022
                             Twitter/KLAYswap-style incidents, etc.)
3. MOAS_CONFLICT           - the exact prefix is simultaneously originated
                             by more than one ASN, and at least one of them
                             is not in the expected set. Legitimate MOAS
                             (e.g. anycast) is allow-listed via
                             `allowed_more_specific_asns` /
                             `expected_origin_asns`.
4. SUSPICIOUS_PATH_LENGTH  - AS-path is implausibly short for a prefix
                             normally reached via a longer path, which can
                             indicate a hijacker who is topologically closer
                             or has stripped prepends.
5. ROUTE_WITHDRAWN         - informational: a monitored exact prefix has
                             been withdrawn everywhere we look (possible
                             precursor to a hijack, or a legitimate change;
                             kept at LOW severity).

This module is intentionally dependency-free (no network calls) so it can
be unit tested deterministically.
"""

from __future__ import annotations

from .config import MonitoredPrefix
from .models import BgpUpdate, EventType, HijackEvent, Severity
from .utils import is_strict_subprefix_of, is_subprefix_of


def match_config_prefix(
    update: BgpUpdate, configured: list[MonitoredPrefix]
) -> MonitoredPrefix | None:
    """Find the configured (parent) prefix that this update's prefix belongs to.

    Prefers an exact match; otherwise the most specific covering parent.
    """
    exact = [c for c in configured if c.prefix == update.raw_prefix]
    if exact:
        return exact[0]

    covering = [c for c in configured if is_subprefix_of(update.raw_prefix, c.prefix)]
    if not covering:
        return None
    # Most specific (longest prefix length) parent wins.
    return max(covering, key=lambda c: c.network.prefixlen)


def evaluate_update(
    update: BgpUpdate,
    configured: list[MonitoredPrefix],
    known_origins: dict[str, set[int]] | None = None,
) -> list[HijackEvent]:
    """Evaluate one BGP update against configured baselines.

    `known_origins` (optional) maps an *exact* prefix string to the set of
    ASNs currently believed to be legitimately announcing it -- this lets
    the caller fold in dynamically-learned MOAS state across multiple
    updates in the same run. If omitted, only the static config is used.
    """
    events: list[HijackEvent] = []
    parent = match_config_prefix(update, configured)
    if parent is None:
        return events  # not a prefix we care about

    if not update.announced:
        # Withdrawal of an exact monitored prefix is informational only.
        if update.raw_prefix == parent.prefix:
            events.append(
                HijackEvent(
                    event_type=EventType.ROUTE_WITHDRAWN,
                    severity=Severity.LOW,
                    prefix=update.raw_prefix,
                    matched_config_prefix=parent.prefix,
                    observed_origin_asn=None,
                    expected_origin_asns=parent.expected_origin_asns,
                    as_path=[],
                    peer=update.peer,
                    collector=update.collector,
                    timestamp=update.timestamp,
                    message=(
                        f"Monitored prefix {update.raw_prefix} was withdrawn "
                        f"by peer {update.peer} (collector {update.collector})."
                    ),
                )
            )
        return events

    origin = update.origin_asn
    expected = set(parent.expected_origin_asns)
    allowed_more_specific = expected | set(parent.allowed_more_specific_asns)

    is_exact = update.raw_prefix == parent.prefix
    is_subprefix = is_strict_subprefix_of(update.raw_prefix, parent.prefix)

    # --- Rule 1 & 3: exact-prefix origin mismatch / MOAS -----------------
    if is_exact and origin is not None and origin not in expected:
        # Distinguish "still nobody legit announcing it, only the impostor"
        # (origin mismatch) from "legit AND impostor both announcing it"
        # (MOAS conflict) using known_origins if the caller supplied it.
        others = (known_origins or {}).get(update.raw_prefix, set())
        if others & expected:
            events.append(
                HijackEvent(
                    event_type=EventType.MOAS_CONFLICT,
                    severity=Severity.CRITICAL,
                    prefix=update.raw_prefix,
                    matched_config_prefix=parent.prefix,
                    observed_origin_asn=origin,
                    expected_origin_asns=parent.expected_origin_asns,
                    as_path=update.as_path,
                    peer=update.peer,
                    collector=update.collector,
                    timestamp=update.timestamp,
                    message=(
                        f"MOAS conflict on {update.raw_prefix}: legitimate origin(s) "
                        f"{sorted(expected)} AND unexpected origin AS{origin} are "
                        f"both being announced (seen via peer {update.peer})."
                    ),
                )
            )
        else:
            events.append(
                HijackEvent(
                    event_type=EventType.ORIGIN_MISMATCH,
                    severity=Severity.CRITICAL,
                    prefix=update.raw_prefix,
                    matched_config_prefix=parent.prefix,
                    observed_origin_asn=origin,
                    expected_origin_asns=parent.expected_origin_asns,
                    as_path=update.as_path,
                    peer=update.peer,
                    collector=update.collector,
                    timestamp=update.timestamp,
                    message=(
                        f"Possible BGP hijack: {update.raw_prefix} is being announced "
                        f"by AS{origin}, which is NOT in the expected origin set "
                        f"{sorted(expected)}. Seen via peer {update.peer} "
                        f"(collector {update.collector}). AS path: {update.as_path}."
                    ),
                )
            )

    # --- Rule 2: unauthorized sub-prefix (more-specific) hijack ----------
    elif is_subprefix and origin is not None and origin not in allowed_more_specific:
        events.append(
            HijackEvent(
                event_type=EventType.UNAUTHORIZED_SUBPREFIX,
                severity=Severity.CRITICAL,
                prefix=update.raw_prefix,
                matched_config_prefix=parent.prefix,
                observed_origin_asn=origin,
                expected_origin_asns=parent.expected_origin_asns,
                as_path=update.as_path,
                peer=update.peer,
                collector=update.collector,
                timestamp=update.timestamp,
                message=(
                    f"Possible sub-prefix hijack: {update.raw_prefix} (a more-specific "
                    f"of monitored prefix {parent.prefix}) is being announced by "
                    f"AS{origin}, which is not authorized. This technique is commonly "
                    f"used to attract traffic away from the legitimate origin because "
                    f"routers prefer longer prefix matches. Seen via peer {update.peer}."
                ),
            )
        )

    # --- Rule 4: suspicious (implausibly short) AS path -------------------
    if (
        origin is not None
        and origin in expected
        and len(update.as_path) < parent.min_expected_path_length
        and len(update.as_path) > 0
    ):
        events.append(
            HijackEvent(
                event_type=EventType.SUSPICIOUS_PATH_LENGTH,
                severity=Severity.LOW,
                prefix=update.raw_prefix,
                matched_config_prefix=parent.prefix,
                observed_origin_asn=origin,
                expected_origin_asns=parent.expected_origin_asns,
                as_path=update.as_path,
                peer=update.peer,
                collector=update.collector,
                timestamp=update.timestamp,
                message=(
                    f"AS path for {update.raw_prefix} ({update.as_path}) is shorter "
                    f"than the configured minimum of {parent.min_expected_path_length} "
                    f"hops. Verify this is expected (e.g. new peering) and not "
                    f"prepend-stripping."
                ),
            )
        )

    if not events and is_exact and origin in expected:
        events.append(
            HijackEvent(
                event_type=EventType.NEW_ANNOUNCEMENT_OK,
                severity=Severity.LOW,
                prefix=update.raw_prefix,
                matched_config_prefix=parent.prefix,
                observed_origin_asn=origin,
                expected_origin_asns=parent.expected_origin_asns,
                as_path=update.as_path,
                peer=update.peer,
                collector=update.collector,
                timestamp=update.timestamp,
                message=f"Routine announcement of {update.raw_prefix} by expected AS{origin}.",
            )
        )

    return events


def filter_by_min_severity(events: list[HijackEvent], min_severity: Severity) -> list[HijackEvent]:
    return [e for e in events if e.severity.rank >= min_severity.rank]
