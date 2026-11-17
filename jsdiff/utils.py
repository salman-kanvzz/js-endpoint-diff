"""Utility helpers."""

from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path
from typing import Iterable


API_PATH_PATTERNS = [
    re.compile(r"^/(?:api|v\d+|graphql|rest|auth|oauth|admin|internal|_next/data|wp-json)(?:/|$|\?|#)", re.I),
    re.compile(r"^/(?:[A-Za-z0-9._~-]+/)*[A-Za-z0-9._~-]*\.(?:json|php|aspx?|jsp|cgi)(?:$|\?)", re.I),
    re.compile(r"^/[^ \t\r\n\"'<>]*\{[^}]+\}[^ \t\r\n\"'<>]*$"),  # templated paths
]

URL_LIKE_API = re.compile(r"https?://[^\s\"'<>]+/(?:api|v\d+|graphql|rest)(?:/|[^\s\"'<>]*)", re.I)
RELATIVE_PATH = re.compile(r"^\.{0,2}/[A-Za-z0-9._~\-/%?=&+#{}]+$")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    ent = 0.0
    length = len(s)
    for c in freq.values():
        p = c / length
        ent -= p * math.log2(p)
    return ent


def is_high_entropy_string(value: str, min_length: int = 20, threshold: float = 3.5) -> bool:
    """Heuristic for secrets/tokens/keys: long, high-entropy, not simple words/paths."""
    if len(value) < min_length:
        return False
    if value.startswith("/") and " " not in value and len(value) < 120:
        # likely a path, not a secret token (handled separately)
        pass
    # exclude obvious benign long strings
    if re.fullmatch(r"[a-z\-_/\.]+", value):
        return False
    if re.search(r"\s", value):
        # long sentences unlikely to be tokens; allow compact strings
        if len(value.split()) > 4:
            return False
    ent = shannon_entropy(value)
    if ent < threshold:
        return False
    # prefer strings with mixed classes or token-like chars
    classes = 0
    if re.search(r"[a-z]", value): classes += 1
    if re.search(r"[A-Z]", value): classes += 1
    if re.search(r"[0-9]", value): classes += 1
    if re.search(r"[^A-Za-z0-9]", value): classes += 1
    if classes < 2 and len(value) < 28:
        return False
    return True


def normalize_endpoint(value: str) -> str | None:
    v = value.strip()
    if not v or len(v) > 500:
        return None
    # full URL API endpoints -> keep as-is if clearly API-like
    if v.startswith("data:") or v.startswith("javascript:") or v.startswith("mailto:"):
        return None
    if re.match(r"^[A-Za-z]{2,10}:\/\/", v):
        if URL_LIKE_API.search(v):
            return v
        return None
    is_path = v.startswith("/") or v.startswith("./") or v.startswith("../")
    if not is_path:
        return None
    # must look like an API/path of interest
    if any(p.search(v) for p in API_PATH_PATTERNS):
        return v
    # generic heuristic: paths with segments and not static assets
    if re.search(r"\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map)(?:$|\?)", v, re.I):
        return None
    if v.count("/") >= 1 and re.search(r"(api|auth|user|admin|token|session|graphql|query|search|upload|download|config|internal|v\d)", v, re.I):
        return v
    # keep plausible fetch-style paths with placeholders or params
    if "?" in v or "{" in v or v.count("/") >= 2:
        if not re.search(r"\.(?:html?)$", v, re.I):
            return v
    return None


def redact_secret(value: str, keep: int = 4) -> str:
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]


def read_urls(urls: list[str] | None, urls_file: str | None) -> list[str]:
    out: list[str] = []
    if urls:
        out.extend(urls)
    if urls_file:
        p = Path(urls_file)
        if not p.exists():
            raise FileNotFoundError(f"URLs file not found: {urls_file}")
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            out.append(line)
    # dedupe preserve order
    seen = set()
    uniq = []
    for u in out:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq
