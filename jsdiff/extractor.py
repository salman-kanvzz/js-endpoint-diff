"""Extract API paths and high-entropy strings from JavaScript using esprima."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

import esprima

from .utils import is_high_entropy_string, normalize_endpoint


@dataclass
class ExtractionResult:
    endpoints: set[str] = field(default_factory=set)
    high_entropy_strings: set[str] = field(default_factory=set)
    parse_error: str | None = None


def _walk(node: Any, visit) -> None:
    if node is None:
        return
    if isinstance(node, list):
        for item in node:
            _walk(item, visit)
        return
    # esprima nodes are objects with .type or dict-like in some cases
    ntype = getattr(node, "type", None)
    if ntype is None and isinstance(node, dict):
        ntype = node.get("type")
    if ntype is None:
        return
    visit(node)
    # traverse attributes
    if isinstance(node, dict):
        items = node.items()
    else:
        try:
            items = vars(node).items()
        except TypeError:
            return
    for k, v in items:
        if k in ("type", "loc", "range", "leadingComments", "trailingComments"):
            continue
        _walk(v, visit)


def _get_string_value(node: Any) -> str | None:
    ntype = getattr(node, "type", None)
    if ntype is None and isinstance(node, dict):
        ntype = node.get("type")
    if ntype == "Literal":
        val = getattr(node, "value", None)
        if val is None and isinstance(node, dict):
            val = node.get("value")
        if isinstance(val, str):
            return val
    if ntype == "TemplateLiteral":
        quasis = getattr(node, "quasis", None)
        if quasis is None and isinstance(node, dict):
            quasis = node.get("quasis", [])
        parts = []
        for q in quasis or []:
            # q.value.cooked or raw
            v = getattr(q, "value", None)
            if v is None and isinstance(q, dict):
                v = q.get("value", {})
            if isinstance(v, dict):
                cooked = v.get("cooked")
                raw = v.get("raw")
                parts.append(cooked if cooked is not None else (raw or ""))
            else:
                cooked = getattr(v, "cooked", None)
                raw = getattr(v, "raw", None)
                parts.append(cooked if cooked is not None else (raw or ""))
        if parts:
            # join with placeholder marker for expressions
            s = "${}".join(parts)
            return s
    return None


# regex fallback for minified/parse-failed JS
REGEX_API = re.compile(r"""(?:"|')((?:https?:\/\/[^"']+)?(?:/|\.\.?/)[^"'\s<>]{2,300})(?:"|')""")
REGEX_FETCH_PATH = re.compile(r"""\b(?:fetch|axios(?:\.[a-z]+)?|open|request|get|post|put|delete|patch)\s*\(\s*(?:"|')([^"']+)(?:"|')""")


def _regex_extract(source: str) -> ExtractionResult:
    endpoints: set[str] = set()
    secrets: set[str] = set()
    candidates = set()
    for m in REGEX_API.finditer(source):
        candidates.add(m.group(1))
    for m in REGEX_FETCH_PATH.finditer(source):
        candidates.add(m.group(1))
    # also quoted strings generally for secrets/endpoints
    for m in re.finditer(r"""(?:"|')([^"'\r\n]{8,500})(?:"|')""", source):
        candidates.add(m.group(1))
    for c in candidates:
        ep = normalize_endpoint(c)
        if ep:
            endpoints.add(ep)
        elif is_high_entropy_string(c):
            secrets.add(c)
    return ExtractionResult(endpoints=endpoints, high_entropy_strings=secrets)


def extract_from_js(source: str, url: str = "") -> ExtractionResult:
    """Extract endpoints and high-entropy strings from JS source.

    Uses esprima AST parsing with regex fallback/supplement for robustness.
    """
    endpoints: set[str] = set()
    secrets: set[str] = set()
    parse_error: str | None = None
    try:
        tree = esprima.parseScript(source, tolerant=True, jsx=True)
    except Exception:
        try:
            tree = esprima.parseModule(source, tolerant=True, jsx=True)
        except Exception as e:
            parse_error = str(e)
            fb = _regex_extract(source)
            fb.parse_error = parse_error
            return fb

    def visit(node: Any) -> None:
        s = _get_string_value(node)
        if s is None:
            return
        ep = normalize_endpoint(s)
        if ep:
            endpoints.add(ep)
            return
        # also consider full http URLs as endpoints of interest
        if s.startswith("http://") or s.startswith("https://"):
            if any(x in s.lower() for x in ("/api", "/graphql", "/rest", "/v1", "/v2", "/v3")):
                endpoints.add(s)
                return
        if is_high_entropy_string(s):
            secrets.add(s)

    _walk(tree, visit)

    # supplement with regex to catch things tolerant parsing may structure oddly
    fb = _regex_extract(source)
    endpoints |= fb.endpoints
    secrets |= fb.high_entropy_strings
    return ExtractionResult(endpoints=endpoints, high_entropy_strings=secrets, parse_error=parse_error)
