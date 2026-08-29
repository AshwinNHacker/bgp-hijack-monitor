"""Command-line interface for bgp-hijack-monitor."""

from __future__ import annotations

import argparse
import datetime as dt
import logging
import sys

from . import __version__
from .alerts import AlertManager
from .baseline import build_baseline
from .config import Config, ConfigError
from .state import StateStore


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def cmd_init_baseline(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    store = StateStore(config.state_db_path)
    warnings = build_baseline(config, store)
    print(f"Baseline built for {len(config.prefixes)} prefix(es) -> {config.state_db_path}")
    for w in warnings:
        print(f"  WARNING: {w}")
    store.close()
    return 0


def cmd_monitor(args: argparse.Namespace) -> int:
    from .monitor import run_monitor_forever

    config = Config.load(args.config)
    store = StateStore(config.state_db_path)

    if not store.all_baselines():
        print("No baseline found -- run 'bgp-hijack-monitor init-baseline' first.")
        return 1

    alert_manager = AlertManager(config.alerting)
    run_monitor_forever(config, store, alert_manager)
    store.close()
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """One-shot check: compare current RIPEstat state against baseline/config."""
    config = Config.load(args.config)
    store = StateStore(config.state_db_path)
    warnings = build_baseline(config, store, verify_against_config=True)
    if warnings:
        print("Issues found:")
        for w in warnings:
            print(f"  - {w}")
        store.close()
        return 2
    print("All monitored prefixes match their expected origin ASN(s). No issues found.")
    store.close()
    return 0


def cmd_list_alerts(args: argparse.Namespace) -> int:
    config = Config.load(args.config)
    store = StateStore(config.state_db_path)
    rows = store.recent_events(limit=args.limit, min_severity=args.min_severity)
    if not rows:
        print("No events recorded yet.")
        store.close()
        return 0
    for r in rows:
        ts = dt.datetime.fromtimestamp(r["timestamp"], tz=dt.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        print(
            f"[{r['severity'].upper():>8}] {ts}  {r['event_type']:<24} "
            f"{r['prefix']:<20} origin={r['observed_origin_asn']}  {r['message']}"
        )
    store.close()
    return 0


def cmd_validate_config(args: argparse.Namespace) -> int:
    try:
        config = Config.load(args.config)
    except ConfigError as exc:
        print(f"Config INVALID: {exc}")
        return 1
    print(f"Config OK: org='{config.org_name}', {len(config.prefixes)} prefix(es) configured")
    for mp in config.prefixes:
        print(
            f"  - {mp.prefix}  expected_origin_asns={mp.expected_origin_asns}  "
            f"({mp.description})"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bgp-hijack-monitor",
        description="Lightweight BGP hijack early-warning tool for small/mid-size orgs.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser(
        "init-baseline", help="Build the trusted origin-ASN baseline via RIPEstat"
    )
    p_init.add_argument("-c", "--config", default="config.yaml", help="path to config.yaml")
    p_init.set_defaults(func=cmd_init_baseline)

    p_monitor = sub.add_parser("monitor", help="Run the live RIS Live monitoring loop")
    p_monitor.add_argument("-c", "--config", default="config.yaml", help="path to config.yaml")
    p_monitor.set_defaults(func=cmd_monitor)

    p_check = sub.add_parser(
        "check", help="One-shot check of current state vs. config (good for cron)"
    )
    p_check.add_argument("-c", "--config", default="config.yaml", help="path to config.yaml")
    p_check.set_defaults(func=cmd_check)

    p_list = sub.add_parser("list-alerts", help="Show recently recorded alert events")
    p_list.add_argument("-c", "--config", default="config.yaml", help="path to config.yaml")
    p_list.add_argument("-n", "--limit", type=int, default=50)
    p_list.add_argument(
        "--min-severity", default=None, choices=["low", "medium", "high", "critical"]
    )
    p_list.set_defaults(func=cmd_list_alerts)

    p_validate = sub.add_parser("validate-config", help="Validate a config.yaml file")
    p_validate.add_argument("-c", "--config", default="config.yaml", help="path to config.yaml")
    p_validate.set_defaults(func=cmd_validate_config)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"File not found: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
