"""
Thin client for the RIPEstat Data API.

RIPEstat (https://stat.ripe.net) is a free, public, no-auth-required
service run by the RIPE NCC. We use two endpoints:

* /data/prefix-overview/  -> current holder ASN(s) for a prefix, used to
  build the initial trusted baseline.
* /data/routing-status/   -> a cross-check that includes visibility and
  observed origins, used for periodic baseline re-verification.

Docs: https://stat.ripe.net/docs/data_api
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import requests

logger = logging.getLogger(__name__)

USER_AGENT = "bgp-hijack-monitor/1.0 (+https://github.com/)"
REQUEST_TIMEOUT = 15


@dataclass
class PrefixOverviewResult:
    prefix: str
    is_less_specific: bool
    asns: list[int]
    holder_names: list[str]
    announced: bool


class RipeStatClient:
    def __init__(self, base_url: str = "https://stat.ripe.net"):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

    def prefix_overview(self, prefix: str) -> PrefixOverviewResult:
        """Fetch the current legitimate origin ASN(s) for a prefix."""
        url = f"{self.base_url}/data/prefix-overview/data.json"
        resp = self.session.get(url, params={"resource": prefix}, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        payload = resp.json()
        data = payload.get("data", {})

        asns: list[int] = []
        holder_names: list[str] = []
        for entry in data.get("asns", []) or []:
            asn = entry.get("asn")
            if asn is not None:
                asns.append(int(asn))
                holder_names.append(entry.get("holder", ""))

        return PrefixOverviewResult(
            prefix=prefix,
            is_less_specific=bool(data.get("is_less_specific", False)),
            asns=asns,
            holder_names=holder_names,
            announced=bool(data.get("announced", False)),
        )

    def routing_status(self, prefix: str) -> dict:
        """Fetch routing-status data (visibility, observed origins) for a prefix."""
        url = f"{self.base_url}/data/routing-status/data.json"
        resp = self.session.get(url, params={"resource": prefix}, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("data", {})

    def looking_glass(self, prefix: str) -> dict:
        """Fetch a live-ish looking-glass snapshot for a prefix (RIS collector view)."""
        url = f"{self.base_url}/data/looking-glass/data.json"
        resp = self.session.get(url, params={"resource": prefix}, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("data", {})
