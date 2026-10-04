"""Turns a notification into a SOAR incident, artifacts and an attachment.

Notifications arrive in three shapes:

* a structured list of affected addresses (IP, port, protocol, time seen),
* only a PDF report attached to the notification,
* a free-text ``address`` field with IPs somewhere in it.
"""

from __future__ import annotations

import html
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

TAG_RE = re.compile(r"<[^>]+>")
SPACE_RE = re.compile(r"\s+")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PROTOCOLS = {1: "TCP", 2: "UDP", 3: "HTTP"}


@dataclass(frozen=True)
class AffectedAddress:
    address: str
    port: int | None = None
    protocol: str = ""
    seen_at: datetime | None = None
    record_id: int | None = None


@dataclass
class Notification:
    notification_id: int
    code: str
    description: str
    explanation: str
    action: str
    addresses: list[AffectedAddress] = field(default_factory=list)
    files: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ips(self) -> list[str]:
        result: list[str] = []
        for item in self.addresses:
            try:
                ipaddress.ip_address(item.address)
            except ValueError:
                continue
            if item.address not in result:
                result.append(item.address)
        return result

    @property
    def shape(self) -> str:
        if self.addresses:
            return "addresses"
        return "file" if self.files else "text"


def strip_html(value: str | None) -> str:
    text = html.unescape(TAG_RE.sub(" ", value or ""))
    return SPACE_RE.sub(" ", text).strip()


def _ms_to_datetime(value: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(int(value) / 1000, tz=UTC)
    except (TypeError, ValueError):
        return None


def parse_notification(data: dict[str, Any]) -> Notification:
    addresses = [
        AffectedAddress(
            address=str(item.get("address", "")).strip(),
            port=item.get("port"),
            protocol=PROTOCOLS.get(item.get("protocol_id"), str(item.get("protocol_id") or "")),
            seen_at=_ms_to_datetime(item.get("time_stamp")),
            record_id=item.get("id"),
        )
        for item in data.get("vulnerabilityAddresses") or []
        if item.get("address")
    ]
    if not addresses and not data.get("files") and data.get("address"):
        # Free-text address field: keep every valid IPv4 that appears in it.
        found = []
        for candidate in IPV4_RE.findall(str(data["address"])):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if candidate not in found:
                found.append(candidate)
        addresses = [AffectedAddress(address=ip) for ip in found]

    return Notification(
        notification_id=int(data["id"]),
        code=str(data.get("code") or data["id"]),
        description=data.get("description") or "",
        explanation=data.get("explanation") or "",
        action=data.get("action") or "",
        addresses=addresses,
        files=list(data.get("files") or []),
    )


def address_table_html(notification: Notification) -> str:
    rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{html.escape(str(value))}</td>"
            for value in (
                a.address,
                a.port if a.port is not None else "",
                a.protocol,
                f"{a.seen_at:%Y-%m-%d %H:%M:%S} UTC" if a.seen_at else "",
            )
        )
        + "</tr>"
        for a in notification.addresses
    )
    return (
        f"<table><tr><th>Address</th><th>Port</th><th>Protocol</th><th>Seen</th></tr>{rows}</table>"
        if rows
        else ""
    )


def build_incident(
    notification: Notification,
    portal_case_url: str | None,
    incident_type_ids: list[Any],
    now: datetime,
) -> dict[str, Any]:
    link = (
        f"<a href='{html.escape(portal_case_url.format(id=notification.notification_id))}'>Open the notification in the CERT portal</a>"
        if portal_case_url
        else f"National CERT notification {html.escape(notification.code)}"
    )
    properties: dict[str, Any] = {
        "cert_case_id": notification.notification_id,
        "cert_code": notification.code,
        "cert_description": notification.description,
        "cert_explanation": notification.explanation,
        "cert_action": notification.action,
    }
    if notification.addresses:
        properties["cert_address_table"] = address_table_html(notification)
        properties["cert_ip_list"] = ",".join(notification.ips)
    incident: dict[str, Any] = {
        "name": f"National CERT Vulnerability Notification | {notification.code}",
        "description": {"format": "html", "content": link},
        "discovered_date": int(now.timestamp() * 1000),
        "properties": properties,
    }
    if incident_type_ids:
        incident["incident_type_ids"] = incident_type_ids
    return incident


def ip_artifacts(notification: Notification) -> list[dict[str, Any]]:
    return [
        {
            "type": "IP Address",
            "value": ip,
            "description": "Address reported by the national CERT",
            "properties": [{"name": "source", "value": "true"}],
        }
        for ip in notification.ips
    ]
