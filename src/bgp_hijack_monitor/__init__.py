"""
BGP Hijack Early-Warning Tool
=============================

A lightweight BGP route-hijack monitoring tool built for small and
mid-sized organizations that cannot afford commercial route-monitoring
platforms (e.g. BGPmon, ThousandEyes BGP, Kentik).

It watches a small, explicit set of IP prefixes / origin ASNs that you
own, using two free, public RIPE NCC data sources:

* RIPEstat Data API   -> used once to build a trusted "baseline"
  (which ASN(s) legitimately originate each of your prefixes today).
* RIS Live             -> a real-time stream of BGP UPDATE messages
  seen by RIPE RIS route collectors worldwide, filtered to just your
  prefixes, used to catch changes the moment they happen.

No BGP feed, router access, or paid data source is required.
"""

__version__ = "1.0.0"
__author__ = "Ashwin N"
__license__ = "MIT"
