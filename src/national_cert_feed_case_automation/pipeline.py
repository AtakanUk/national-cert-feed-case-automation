"""Collector, attachment repair and health check."""

from __future__ import annotations

import logging
import mimetypes
import socket
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from .client import NationalCertClient
from .excel import address_workbook
from .normalization import Notification, build_incident, ip_artifacts, parse_notification
from .soar import SoarCases

log = logging.getLogger(__name__)
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


@dataclass
class Options:
    lookback_seconds: int = 3600
    dedup_days: int = 30
    portal_case_url: str | None = None
    incident_type_ids: list[Any] = field(default_factory=list)


@dataclass
class CollectResult:
    seen: int = 0
    existing: int = 0
    created: list[int] = field(default_factory=list)
    failed: list[int] = field(default_factory=list)


def attach_evidence(
    cert: NationalCertClient, soar: SoarCases, incident_id: int, notification: Notification
) -> str:
    """Address list as Excel, or the notification's own report file. Returns what was attached."""
    if notification.addresses:
        soar.attach(
            incident_id,
            f"cert_{notification.code}_addresses.xlsx",
            address_workbook(notification),
            XLSX,
        )
        return "xlsx"
    if notification.files:
        info = notification.files[0]
        name = info.get("name") or f"cert_{notification.code}.pdf"
        soar.attach(
            incident_id,
            name,
            cert.file(info["id"]),
            mimetypes.guess_type(name)[0] or "application/octet-stream",
        )
        return "file"
    return "none"


def collect(
    cert: NationalCertClient, soar: SoarCases, options: Options, now: datetime | None = None
) -> CollectResult:
    now = now or datetime.now(UTC)
    result = CollectResult()
    known = soar.cases_since(options.dedup_days)
    since = int(now.timestamp()) - options.lookback_seconds

    for summary in cert.notifications_since(since):
        result.seen += 1
        notification_id = int(summary["id"])
        if notification_id in known:
            result.existing += 1
            continue
        try:
            notification = parse_notification(cert.notification(notification_id))
            incident = soar.create_incident(
                build_incident(
                    notification, options.portal_case_url, options.incident_type_ids, now
                )
            )
            for artifact in ip_artifacts(notification):
                soar.add_artifact(incident["id"], artifact)
            attached = attach_evidence(cert, soar, incident["id"], notification)
            log.info(
                "Notification %s (%s) -> incident %s: %d IP(s), attachment=%s",
                notification.code,
                notification.shape,
                incident["id"],
                len(notification.ips),
                attached,
            )
            result.created.append(incident["id"])
        except Exception as exc:
            result.failed.append(notification_id)
            log.error("Notification %s could not be processed: %s", notification_id, exc)
    return result


def repair_attachments(cert: NationalCertClient, soar: SoarCases, options: Options) -> list[int]:
    """Re-create the evidence attachment of incidents that ended up without one."""
    repaired = []
    for case_id, incident in soar.cases_since(options.dedup_days).items():
        if incident.get("num_attachments"):
            continue
        notification = parse_notification(cert.notification(case_id))
        if attach_evidence(cert, soar, incident["id"], notification) != "none":
            repaired.append(incident["id"])
            log.info(
                "Attachment restored on incident %s (notification %s)",
                incident["id"],
                notification.code,
            )
    return repaired


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


def healthcheck(
    cert: NationalCertClient, soar: SoarCases, options: Options, window_days: int = 7
) -> list[Check]:
    """End-to-end checks: API reachable, latest notification imported with evidence."""
    checks: list[Check] = []
    host = urlsplit(cert.base_url)
    started = time.monotonic()
    try:
        socket.create_connection((host.hostname, host.port or 443), timeout=10).close()
        checks.append(
            Check(
                "API TCP connection",
                True,
                f"{host.hostname} reachable in {time.monotonic() - started:.2f}s",
            )
        )
    except OSError as exc:
        checks.append(Check("API TCP connection", False, str(exc)))
        return checks

    try:
        notifications = list(cert.notifications_since(int(time.time()) - window_days * 86400))
        checks.append(
            Check(
                "API query",
                True,
                f"{len(notifications)} notification(s) in the last {window_days} days",
            )
        )
    except Exception as exc:
        checks.append(Check("API query", False, str(exc)))
        return checks
    if not notifications:
        return checks

    latest = max(notifications, key=lambda item: int(item["id"]))
    incident = soar.cases_since(window_days + options.dedup_days).get(int(latest["id"]))
    if incident is None:
        checks.append(
            Check(
                "Latest notification imported",
                False,
                f"no incident for notification {latest['id']}",
            )
        )
        return checks
    checks.append(
        Check(
            "Latest notification imported",
            True,
            f"notification {latest['id']} -> incident {incident['id']}",
        )
    )
    has_attachment = bool(incident.get("num_attachments"))
    checks.append(
        Check(
            "Evidence attached",
            has_attachment,
            f"{incident.get('num_attachments', 0)} attachment(s)",
        )
    )
    return checks
