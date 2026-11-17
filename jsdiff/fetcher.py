"""Download JavaScript files from URLs using httpx."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import httpx


@dataclass
class FetchResult:
    url: str
    status_code: Optional[int]
    content: str
    error: Optional[str] = None
    final_url: str = ""

    @property
    def ok(self) -> bool:
        return self.error is None and self.content != ""


def fetch_js_urls(
    urls: list[str],
    timeout: float = 15.0,
    user_agent: str = "js-endpoint-diff/1.0 (+authorized security research)",
    verify: bool = True,
) -> list[FetchResult]:
    results: list[FetchResult] = []
    headers = {"User-Agent": user_agent, "Accept": "*/*"}
    limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)
    with httpx.Client(headers=headers, timeout=timeout, follow_redirects=True, verify=verify, limits=limits) as client:
        for url in urls:
            try:
                resp = client.get(url)
                text = resp.text if resp.text is not None else ""
                err = None
                if resp.status_code >= 400:
                    err = f"HTTP {resp.status_code}"
                results.append(FetchResult(
                    url=url,
                    status_code=resp.status_code,
                    content=text,
                    error=err,
                    final_url=str(resp.url),
                ))
            except Exception as e:
                results.append(FetchResult(url=url, status_code=None, content="", error=str(e)))
    return results
