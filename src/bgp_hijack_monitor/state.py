"""SQLite-backed persistence for baselines, event history, and MOAS tracking."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import closing

from .models import BaselineEntry, HijackEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS baseline (
    prefix TEXT PRIMARY KEY,
    origin_asns TEXT NOT NULL,
    source TEXT NOT NULL,
    last_verified REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    prefix TEXT NOT NULL,
    matched_config_prefix TEXT NOT NULL,
    observed_origin_asn INTEGER,
    expected_origin_asns TEXT NOT NULL,
    as_path TEXT NOT NULL,
    peer TEXT NOT NULL,
    collector TEXT NOT NULL,
    timestamp REAL NOT NULL,
    message TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS observed_origins (
    prefix TEXT NOT NULL,
    asn INTEGER NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (prefix, asn)
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
"""


class StateStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # -- baseline ----------------------------------------------------
    def upsert_baseline(self, entry: BaselineEntry) -> None:
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                """
                INSERT INTO baseline (prefix, origin_asns, source, last_verified)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(prefix) DO UPDATE SET
                    origin_asns=excluded.origin_asns,
                    source=excluded.source,
                    last_verified=excluded.last_verified
                """,
                (entry.prefix, json.dumps(entry.origin_asns), entry.source, entry.last_verified),
            )
        self._conn.commit()

    def get_baseline(self, prefix: str) -> BaselineEntry | None:
        with closing(self._conn.cursor()) as cur:
            row = cur.execute(
                "SELECT * FROM baseline WHERE prefix = ?", (prefix,)
            ).fetchone()
        if row is None:
            return None
        return BaselineEntry(
            prefix=row["prefix"],
            origin_asns=json.loads(row["origin_asns"]),
            source=row["source"],
            last_verified=row["last_verified"],
        )

    def all_baselines(self) -> list[BaselineEntry]:
        with closing(self._conn.cursor()) as cur:
            rows = cur.execute("SELECT * FROM baseline").fetchall()
        return [
            BaselineEntry(
                prefix=r["prefix"],
                origin_asns=json.loads(r["origin_asns"]),
                source=r["source"],
                last_verified=r["last_verified"],
            )
            for r in rows
        ]

    # -- events --------------------------------------------------------
    def record_event(self, event: HijackEvent) -> int:
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                """
                INSERT INTO events (
                    event_type, severity, prefix, matched_config_prefix,
                    observed_origin_asn, expected_origin_asns, as_path,
                    peer, collector, timestamp, message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_type.value,
                    event.severity.value,
                    event.prefix,
                    event.matched_config_prefix,
                    event.observed_origin_asn,
                    json.dumps(event.expected_origin_asns),
                    json.dumps(event.as_path),
                    event.peer,
                    event.collector,
                    event.timestamp,
                    event.message,
                ),
            )
            self._conn.commit()
            return cur.lastrowid

    def recent_events(self, limit: int = 50, min_severity: str | None = None) -> list[sqlite3.Row]:
        query = "SELECT * FROM events"
        params: tuple = ()
        if min_severity:
            order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            allowed = [s for s, r in order.items() if r >= order.get(min_severity, 0)]
            placeholders = ",".join("?" for _ in allowed)
            query += f" WHERE severity IN ({placeholders})"
            params = tuple(allowed)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params = params + (limit,)
        with closing(self._conn.cursor()) as cur:
            return cur.execute(query, params).fetchall()

    # -- MOAS tracking ---------------------------------------------------
    def note_observed_origin(self, prefix: str, asn: int) -> None:
        with closing(self._conn.cursor()) as cur:
            cur.execute(
                """
                INSERT INTO observed_origins (prefix, asn, last_seen)
                VALUES (?, ?, ?)
                ON CONFLICT(prefix, asn) DO UPDATE SET last_seen=excluded.last_seen
                """,
                (prefix, asn, time.time()),
            )
        self._conn.commit()

    def observed_origins(self, prefix: str, within_seconds: float = 3600) -> set[int]:
        cutoff = time.time() - within_seconds
        with closing(self._conn.cursor()) as cur:
            rows = cur.execute(
                "SELECT asn FROM observed_origins WHERE prefix = ? AND last_seen >= ?",
                (prefix, cutoff),
            ).fetchall()
        return {r["asn"] for r in rows}

    def all_known_origins(self, within_seconds: float = 3600) -> dict[str, set[int]]:
        cutoff = time.time() - within_seconds
        with closing(self._conn.cursor()) as cur:
            rows = cur.execute(
                "SELECT prefix, asn FROM observed_origins WHERE last_seen >= ?", (cutoff,)
            ).fetchall()
        result: dict[str, set[int]] = {}
        for r in rows:
            result.setdefault(r["prefix"], set()).add(r["asn"])
        return result
