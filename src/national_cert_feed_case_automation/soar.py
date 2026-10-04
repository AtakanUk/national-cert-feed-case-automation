"""IBM QRadar SOAR operations used by the collector."""

from __future__ import annotations

import io
import time
from typing import Any


class SoarCases:
    def __init__(self, rest_client: Any, page_size: int = 500):
        self.client = rest_client
        self.page_size = page_size

    def cases_since(self, days: int) -> dict[int, dict[str, Any]]:
        """Incidents of the last ``days`` days that carry a CERT case ID, keyed by that ID."""
        query = {
            "filters": [
                {
                    "conditions": [
                        {
                            "field_name": "create_date",
                            "method": "gte",
                            "value": int(time.time() * 1000) - days * 86_400_000,
                        },
                        {"field_name": "properties.cert_case_id", "method": "has_a_value"},
                    ]
                }
            ],
            "start": 0,
            "length": self.page_size,
        }
        cases: dict[int, dict[str, Any]] = {}
        while True:
            page = (self.client.post("/incidents/query_paged?return_level=full", query) or {}).get(
                "data"
            ) or []
            for incident in page:
                case_id = (incident.get("properties") or {}).get("cert_case_id")
                if case_id is not None:
                    cases[int(case_id)] = incident
            if len(page) < self.page_size:
                return cases
            query["start"] += self.page_size

    def create_incident(self, incident: dict[str, Any]) -> dict[str, Any]:
        return self.client.post("/incidents", incident)

    def add_artifact(self, incident_id: int, artifact: dict[str, Any]) -> None:
        self.client.post(f"/incidents/{incident_id}/artifacts", artifact)

    def attach(self, incident_id: int, filename: str, content: bytes, mimetype: str) -> None:
        self.client.post_attachment(
            f"/incidents/{incident_id}/attachments",
            None,
            filename=filename,
            mimetype=mimetype,
            bytes_handle=io.BytesIO(content),
        )
