"""REST client for the national CERT vulnerability notification API."""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import requests

log = logging.getLogger(__name__)


@dataclass
class ClientConfig:
    base_url: str
    api_token: str
    verify_ssl: bool = True
    http_proxy_url: str | None = None
    https_proxy_url: str | None = None
    page_size: int = 20

    @property
    def proxies(self) -> dict[str, str] | None:
        if not self.http_proxy_url and not self.https_proxy_url:
            return None
        return {
            "http": self.http_proxy_url or self.https_proxy_url or "",
            "https": self.https_proxy_url or self.http_proxy_url or "",
        }


class NationalCertClient:
    def __init__(self, config: ClientConfig, session: requests.Session | None = None):
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        self.session = session or requests.Session()
        self.session.verify = config.verify_ssl
        if config.proxies:
            self.session.proxies.update(config.proxies)
        # The API expects the bare token in the Authorization header.
        self.session.headers.update(
            {"Accept": "application/json", "Authorization": config.api_token}
        )

    def _get(self, path: str, **params: Any) -> requests.Response:
        response = self.session.get(f"{self.base_url}{path}", params=params or None, timeout=60)
        response.raise_for_status()
        return response

    def notifications_since(self, since_epoch: int) -> Iterator[dict[str, Any]]:
        """Summaries of notifications created after ``since_epoch`` (seconds), all pages."""
        page = 0
        while True:
            body = self._get(
                "/vulnerabilities",
                filter_start_date=since_epoch,
                page=page,
                count=self.config.page_size,
            ).json()
            models = (body.get("data") or {}).get("models") or []
            yield from models
            if len(models) < self.config.page_size:
                return
            page += 1

    def notification(self, notification_id: int) -> dict[str, Any]:
        return self._get(f"/vulnerabilities/{notification_id}").json().get("data") or {}

    def file(self, file_id: int) -> bytes:
        return self._get(f"/vulnerabilities/file/{file_id}").content
