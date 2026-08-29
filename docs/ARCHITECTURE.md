# Architecture

## Data flow

```
config.yaml
    │
    ▼
Config.load()  ──────────────────────────────────────────────────────┐
    │                                                                  │
    ▼                                                                  │
init-baseline: RipeStatClient.prefix_overview(prefix)                 │
    │  -> BaselineEntry(prefix, origin_asns, source, last_verified)    │
    ▼                                                                  │
StateStore.upsert_baseline()  (SQLite: baseline table)                │
                                                                        │
monitor: RisLiveClient.stream()  <────────────────────────────────────┘
    │  wss://ris-live.ripe.net/v1/ws/, subscribed per-prefix
    │  yields BgpUpdate (normalized announcement/withdrawal)
    ▼
detector.evaluate_update(update, configured_prefixes, known_origins)
    │  pure function, no I/O -> list[HijackEvent]
    ▼
StateStore.record_event()  (SQLite: events table)
    │
    ▼
AlertManager.dispatch(event)
    │  filters by min_severity, fans out to enabled backends
    ├── ConsoleAlertBackend
    ├── EmailAlertBackend   (SMTP)
    ├── SlackAlertBackend   (incoming webhook)
    └── WebhookAlertBackend (generic JSON POST)
```

## Why RIS Live + RIPEstat, and not a full BGP feed

Running a real BGP session (e.g. via ExaBGP or a route reflector peering) to
get a full table requires a cooperating upstream/IXP, static infrastructure,
and meaningfully more operational overhead than a small org wants for a
detective control. RIS Live gives near-real-time visibility into the exact
same class of events (origin changes, sub-prefix announcements, path
changes) via a public WebSocket API with server-side filtering, at effectively
zero infrastructure cost. The trade-off, documented in the README's
Limitations section, is that you inherit RIS's visibility rather than your
own transit's.

## Why SQLite

The tool is designed to run as a single lightweight process on a small VM.
SQLite gives durable baseline + event history across restarts without
requiring a separate database service. `StateStore` is a thin wrapper; if a
deployment later needs multi-instance/shared state, swapping it for a
Postgres-backed implementation behind the same interface is a contained
change (see `state.py`).

## Extending detection rules

All detection logic lives in `detector.py::evaluate_update`, which is a pure
function: `(BgpUpdate, list[MonitoredPrefix], known_origins) -> list[HijackEvent]`.
It has no network or database dependency, which is what makes it possible to
unit test every rule deterministically (see `tests/test_detector.py`). To add
a new rule:

1. Add a new `EventType` in `models.py`.
2. Implement the check inside `evaluate_update`, appending a `HijackEvent`
   when it fires.
3. Add unit tests covering both the positive and negative case.

## Extending alert backends

Implement `alerts/base.py::AlertBackend` (one method: `send(event)`), add a
config dataclass in `config.py`, and wire it into `AlertManager.__init__` in
`alerts/__init__.py`. Backends must not raise on failure — `AlertManager`
also catches exceptions defensively so one broken backend never blocks the
others, but a backend should still log its own failures for debuggability.
