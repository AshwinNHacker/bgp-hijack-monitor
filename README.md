# bgp-hijack-monitor

A lightweight, self-hosted **BGP hijack early-warning tool** for organizations
that own their own IP address space but can't justify a commercial route-monitoring
platform. It watches a small, explicit list of prefixes/ASNs you configure and
raises an alert within seconds of a suspicious change — using only free, public
RIPE NCC data sources. No router access, no paid BGP feed, no vendor account.

[![CI](https://github.com/YOUR-USERNAME/bgp-hijack-monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR-USERNAME/bgp-hijack-monitor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

---

## Why this exists

A BGP hijack happens when someone — by mistake or on purpose — announces
routes to IP space they don't own, redirecting some or all of the internet's
traffic for that address block through them. Real-world incidents this class
of attack covers include the 2008 Pakistan Telecom / YouTube leak, the 2018
Amazon Route 53 / MyEtherWallet hijack, and dozens of smaller, less publicized
incidents that hit regional ISPs and hosting providers every year.

Large networks pay for commercial BGP monitoring (BGPmon-style services,
Kentik, ThousandEyes, Cloudflare Radar Alerts). Smaller orgs — a regional ISP,
a hosting company, a company with its own PA/PI space — often have none of
this, and typically hear about a hijack from an angry customer rather than
their own tooling. `bgp-hijack-monitor` is built to close that gap with
something you can run on a $5/month VM.

## How it works

1. **Baseline** — On first run, `init-baseline` asks the [RIPEstat Data
   API](https://stat.ripe.net/docs/data_api) which ASN(s) currently, legitimately
   originate each prefix you've configured, and stores that as your trusted
   baseline in a local SQLite database.
2. **Live monitoring** — `monitor` opens a WebSocket connection to
   [RIS Live](https://ris-live.ripe.net/), RIPE NCC's real-time feed of BGP
   UPDATE messages observed by ~25 route collectors (RRCs) peered with
   hundreds of networks worldwide. It subscribes with a server-side filter so
   it only receives messages that touch your configured prefixes.
3. **Detection** — every relevant update is checked against your baseline for:
   - **Origin AS mismatch** — the exact prefix is now announced by an
     unauthorized ASN (classic hijack).
   - **Unauthorized sub-prefix / more-specific hijack** — someone announces a
     more-specific of your block (e.g. your `/22` becomes a stolen `/24`)
     from an ASN you didn't authorize. Because routers prefer longer prefix
     matches, this is the technique that actually diverts traffic even when
     your legitimate announcement is still live.
   - **MOAS conflict** — your prefix is simultaneously originated by your ASN
     *and* an unexpected one.
   - **Suspicious AS-path length** — an implausibly short path, which can
     indicate prepend-stripping.
   - **Unexpected withdrawal** — informational signal that a monitored
     prefix disappeared everywhere RIS can see.
4. **Alerting** — matching events are written to the local event log and
   fanned out to any enabled backend: console/log, email (SMTP), Slack
   (incoming webhook), or a generic JSON webhook.

```
┌──────────────┐      ┌───────────────┐      ┌────────────┐      ┌───────────┐
│  RIPEstat     │      │   RIS Live     │      │  Detector   │      │  Alerts    │
│ (baseline)    │─────▶│ (live stream)  │─────▶│  (rules)    │─────▶│ console/   │
│ prefix-       │      │ WebSocket,     │      │ origin/     │      │ email/     │
│ overview API  │      │ server-side    │      │ subprefix/  │      │ slack/     │
│               │      │ prefix filter  │      │ MOAS/path   │      │ webhook    │
└──────────────┘      └───────────────┘      └────────────┘      └───────────┘
                                                     │
                                                     ▼
                                              ┌────────────┐
                                              │  SQLite     │
                                              │  baseline + │
                                              │  event log  │
                                              └────────────┘
```

## Quick start

```bash
git clone https://github.com/YOUR-USERNAME/bgp-hijack-monitor.git
cd bgp-hijack-monitor
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

cp config/config.example.yaml config.yaml
# edit config.yaml: set your org name and the prefixes/ASNs you own

bgp-hijack-monitor validate-config -c config.yaml
bgp-hijack-monitor init-baseline   -c config.yaml
bgp-hijack-monitor monitor         -c config.yaml
```

You should see console output like:

```
2026-08-13 09:00:01 INFO bgp_hijack_monitor.monitor: Starting monitor for 2 prefix(es) belonging to 'Example Corp'
2026-08-13 09:00:01 INFO bgp_hijack_monitor.monitor:   watching 203.0.113.0/24 (expected origin AS[64512])
[CRITICAL] 2026-08-13 09:14:22 UTC origin_mismatch :: Possible BGP hijack: 203.0.113.0/24 is being
announced by AS13335, which is NOT in the expected origin set [64512]. Seen via peer 192.0.2.1
(collector rrc00). AS path: [65000, 13335].
```

## CLI reference

| Command | What it does |
|---|---|
| `bgp-hijack-monitor validate-config -c config.yaml` | Parses and validates the config file without touching the network. |
| `bgp-hijack-monitor init-baseline -c config.yaml` | Queries RIPEstat and stores the current legitimate origin ASN(s) per prefix. Re-run this any time you legitimately change providers/ASNs. |
| `bgp-hijack-monitor monitor -c config.yaml` | Runs the live RIS Live monitoring loop forever (intended to run under systemd/Docker/supervisord). |
| `bgp-hijack-monitor check -c config.yaml` | One-shot comparison of current RIPEstat state vs. your config — good for a cron job as a cheap secondary check alongside `monitor`. Exits non-zero if issues are found. |
| `bgp-hijack-monitor list-alerts -c config.yaml [-n 50] [--min-severity high]` | Prints recent recorded events from the local SQLite log. |

All commands accept `-v/--verbose` for debug logging.

## Configuration

See [`config/config.example.yaml`](config/config.example.yaml) for a fully
annotated example. The essentials:

```yaml
org_name: "Example Corp"

prefixes:
  - prefix: "203.0.113.0/24"
    description: "Primary office + colo block"
    expected_origin_asns: [64512]
    allowed_more_specific_asns: []   # ASNs allowed to announce more-specifics (e.g. a scrubbing provider)
    min_expected_path_length: 1      # raise to catch prepend-stripping

alerting:
  console: true
  min_severity: "medium"             # low | medium | high | critical
  slack:
    enabled: true
    webhook_url_env_var: "BGPMON_SLACK_WEBHOOK_URL"
```

Secrets (SMTP passwords, Slack/webhook URLs) are always read from environment
variables named in the config, **never** written into the YAML file itself.

## Running continuously

### systemd

```ini
# /etc/systemd/system/bgp-hijack-monitor.service
[Unit]
Description=BGP Hijack Early-Warning Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=bgpmon
WorkingDirectory=/opt/bgp-hijack-monitor
EnvironmentFile=/opt/bgp-hijack-monitor/.env
ExecStart=/opt/bgp-hijack-monitor/.venv/bin/bgp-hijack-monitor monitor -c /opt/bgp-hijack-monitor/config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bgp-hijack-monitor
journalctl -u bgp-hijack-monitor -f
```

### Docker

```bash
docker build -t bgp-hijack-monitor .
docker run -d --name bgp-hijack-monitor \
  --restart unless-stopped \
  -v $(pwd)/config.yaml:/app/config.yaml:ro \
  -v bgp-monitor-data:/app/data \
  -e BGPMON_SLACK_WEBHOOK_URL \
  bgp-hijack-monitor
```

or `docker compose up -d` using the provided `docker-compose.yml`.

## Detection rules in detail

| Rule | Trigger | Default severity |
|---|---|---|
| `origin_mismatch` | Exact monitored prefix announced by an ASN not in `expected_origin_asns` | CRITICAL |
| `unauthorized_subprefix` | A more-specific of a monitored prefix appears, from an ASN not in `expected_origin_asns` or `allowed_more_specific_asns` | CRITICAL |
| `moas_conflict` | Both the legitimate ASN and an unexpected ASN are simultaneously observed announcing the exact prefix | CRITICAL |
| `suspicious_path_length` | AS path shorter than the configured `min_expected_path_length` | LOW |
| `route_withdrawn` | Monitored exact prefix withdrawn (informational; check whether this is expected maintenance) | LOW |

Detection logic lives entirely in
[`src/bgp_hijack_monitor/detector.py`](src/bgp_hijack_monitor/detector.py) and
has no network dependency, so it's fully unit tested — see `tests/test_detector.py`.

## Limitations — please read

This is a lightweight, best-effort tool, not a substitute for RPKI, IRR route
objects, or a commercial monitoring contract with SLAs. Be aware of these
constraints:

- **Visibility, not omniscience.** RIS collectors peer with a large but finite
  set of networks. A hijack announced only to a small, geographically
  isolated set of eyeball networks that never reaches an RIS peer may not be
  seen. In practice RIS has very broad global visibility, but 100% coverage
  is not guaranteed.
- **RIPEstat/RIS Live availability.** Both are free RIPE NCC services with no
  uptime SLA to third parties. The tool degrades gracefully (falls back to
  your configured baseline and retries with backoff) but a RIPE NCC outage
  means reduced/no coverage for that window.
- **This does not stop a hijack.** It only detects and alerts. Response
  (contacting your upstreams, filing an IRR/RPKI ROA correction, contacting
  the offending network's NOC) is still on you.
- **The best long-term defense is RPKI.** Publishing Route Origin
  Authorizations (ROAs) for your prefixes and getting your upstreams to do
  Route Origin Validation prevents most accidental leaks outright. This tool
  is a complementary detective control, not a replacement for RPKI.
- **False positives happen.** Legitimate re-numbering, new transit providers,
  anycast deployments, and traffic-engineering prepending changes will all
  trigger alerts unless you update `expected_origin_asns` /
  `allowed_more_specific_asns` first. Treat every alert as "verify," not
  "panic."

## Project layout

```
bgp-hijack-monitor/
├── src/bgp_hijack_monitor/
│   ├── cli.py            # argparse CLI entrypoints
│   ├── config.py          # YAML config loading/validation
│   ├── models.py           # dataclasses: BgpUpdate, HijackEvent, etc.
│   ├── ripestat.py         # RIPEstat API client (baseline)
│   ├── ris_live.py         # RIS Live WebSocket client (live stream)
│   ├── baseline.py         # baseline builder
│   ├── detector.py         # pure detection logic (network-free, fully tested)
│   ├── monitor.py          # ties stream -> detector -> state -> alerts together
│   ├── state.py            # SQLite persistence
│   └── alerts/              # console, email, slack, generic webhook backends
├── tests/                   # pytest suite, 44+ tests, no network required
├── config/config.example.yaml
├── Dockerfile / docker-compose.yml
├── .github/workflows/ci.yml
└── scripts/install.sh
```

## Development

```bash
pip install -e ".[dev]"
pytest -v                 # run the test suite
ruff check src/ tests/    # lint
mypy src/                 # type-check
```

## Data sources & credits

- [RIPE NCC RIS Live](https://ris-live.ripe.net/) — real-time BGP update stream.
- [RIPEstat Data API](https://stat.ripe.net/docs/data_api) — prefix/origin lookups.

This project is not affiliated with or endorsed by the RIPE NCC. Please read
and respect RIPE NCC's [acceptable use terms](https://www.ripe.net/analyse/archived-projects/ris/docs)
for these free public services — this tool uses lightweight, server-side-filtered
subscriptions specifically to keep its footprint on their infrastructure small.

## License

MIT — see [LICENSE](LICENSE).

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
