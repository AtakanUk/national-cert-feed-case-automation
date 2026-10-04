"""Excel attachment listing the affected addresses (handy for the network team)."""

from __future__ import annotations

import io

from openpyxl import Workbook
from openpyxl.styles import Font

from .normalization import Notification


def address_workbook(notification: Notification) -> bytes:
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Affected addresses"
    detailed = any(a.port is not None or a.protocol or a.seen_at for a in notification.addresses)
    headers = ["Record", "Seen (UTC)", "Address", "Port", "Protocol"] if detailed else ["Address"]
    sheet.append(headers)
    for cell in sheet[1]:
        cell.font = Font(bold=True)
    for item in notification.addresses:
        if detailed:
            seen = item.seen_at.strftime("%Y-%m-%d %H:%M:%S") if item.seen_at else ""
            sheet.append([item.record_id, seen, item.address, item.port, item.protocol])
        else:
            sheet.append([item.address])
    for column, width in zip("ABCDE", (10, 20, 40, 8, 10) if detailed else (40,), strict=False):
        sheet.column_dimensions[column].width = width
    buffer = io.BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()
