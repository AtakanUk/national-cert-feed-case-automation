"""Command line.

python -m national_cert_feed_case_automation collect        # from cron, e.g. every 10 minutes
python -m national_cert_feed_case_automation repair         # restore missing attachments
python -m national_cert_feed_case_automation healthcheck    # weekly end-to-end check
python -m national_cert_feed_case_automation show 12345     # inspect one notification
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from dataclasses import asdict
from typing import Any

from .client import ClientConfig, NationalCertClient
from .normalization import parse_notification
from .pipeline import Options, collect, healthcheck, repair_attachments
from .soar import SoarCases


def _env_bool(name: str, default: str = "true") -> bool:
    return os.environ.get(name, default).lower() in {"1", "true", "yes", "on"}


def cert_client() -> NationalCertClient:
    token = os.environ.get("NATIONAL_CERT_API_TOKEN", "").strip()
    if not token:
        raise SystemExit("NATIONAL_CERT_API_TOKEN is required")
    return NationalCertClient(
        ClientConfig(
            base_url=os.environ.get("NATIONAL_CERT_BASE_URL", "https://cert-api.example.com/v1"),
            api_token=token,
            verify_ssl=_env_bool("NATIONAL_CERT_VERIFY_SSL"),
            http_proxy_url=os.environ.get("HTTP_PROXY_URL") or None,
            https_proxy_url=os.environ.get("HTTPS_PROXY_URL") or None,
        )
    )


def soar_cases() -> SoarCases:
    import resilient

    options: dict[str, Any] = {
        "host": os.environ["SOAR_HOST"],
        "port": int(os.environ.get("SOAR_PORT", "443")),
        "org": os.environ["SOAR_ORG"],
        "api_key_id": os.environ["SOAR_API_KEY_ID"],
        "api_key_secret": os.environ["SOAR_API_KEY_SECRET"],
    }
    if os.environ.get("SOAR_CAFILE"):
        options["cafile"] = os.environ["SOAR_CAFILE"]
    return SoarCases(resilient.get_client(options))


def options_from_env() -> Options:
    types = [
        int(t) if t.strip().isdigit() else t.strip()
        for t in os.environ.get("SOAR_INCIDENT_TYPES", "").split(",")
        if t.strip()
    ]
    return Options(
        lookback_seconds=int(os.environ.get("LOOKBACK_SECONDS", "3600")),
        dedup_days=int(os.environ.get("DEDUP_DAYS", "30")),
        portal_case_url=os.environ.get("CERT_PORTAL_CASE_URL") or None,
        incident_type_ids=types,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="national_cert_feed_case_automation",
        description="National CERT notifications to SOAR incidents",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("collect", help="create incidents for new notifications")
    commands.add_parser("repair", help="restore missing evidence attachments")
    health = commands.add_parser("healthcheck", help="end-to-end check of the integration")
    health.add_argument("--days", type=int, default=7)
    show = commands.add_parser("show", help="print a parsed notification")
    show.add_argument("notification_id", type=int)
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    cert = cert_client()
    if args.command == "show":
        notification = parse_notification(cert.notification(args.notification_id))
        print(json.dumps(asdict(notification), indent=2, default=str))
        return 0

    soar, options = soar_cases(), options_from_env()
    if args.command == "collect":
        result = collect(cert, soar, options)
        print(json.dumps(asdict(result), indent=2))
        return 1 if result.failed else 0
    if args.command == "repair":
        print(json.dumps({"repaired_incidents": repair_attachments(cert, soar, options)}, indent=2))
        return 0

    checks = healthcheck(cert, soar, options, window_days=args.days)
    for check in checks:
        print(f"[{'OK' if check.ok else 'FAIL'}] {check.name}: {check.detail}")
    return 0 if all(check.ok for check in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
