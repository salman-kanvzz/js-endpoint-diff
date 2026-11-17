"""Diff and report generation."""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from typing import Any

from .utils import redact_secret


@dataclass
class DiffReport:
    baseline_scan_id: int | None
    baseline_created_at: str | None
    current_scan_id: int | None
    current_created_at: str | None
    new_endpoints: list[str]
    removed_endpoints: list[str]
    new_high_entropy_strings: list[str]
    removed_high_entropy_strings: list[str]
    summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_diff(baseline, current) -> DiffReport:
    b_eps = baseline.endpoints if baseline else set()
    c_eps = current.endpoints if current else set()
    b_hes = baseline.high_entropy if baseline else set()
    c_hes = current.high_entropy if current else set()

    new_eps = sorted(c_eps - b_eps)
    removed_eps = sorted(b_eps - c_eps)
    new_hes = sorted(c_hes - b_hes)
    removed_hes = sorted(b_hes - c_hes)

    summary = {
        "baseline_endpoints": len(b_eps),
        "current_endpoints": len(c_eps),
        "new_endpoints_count": len(new_eps),
        "removed_endpoints_count": len(removed_eps),
        "baseline_high_entropy_strings": len(b_hes),
        "current_high_entropy_strings": len(c_hes),
        "new_high_entropy_strings_count": len(new_hes),
        "removed_high_entropy_strings_count": len(removed_hes),
    }
    return DiffReport(
        baseline_scan_id=baseline.scan_id if baseline else None,
        baseline_created_at=baseline.created_at if baseline else None,
        current_scan_id=current.scan_id if current else None,
        current_created_at=current.created_at if current else None,
        new_endpoints=new_eps,
        removed_endpoints=removed_eps,
        new_high_entropy_strings=new_hes,
        removed_high_entropy_strings=removed_hes,
        summary=summary,
    )


def render_json(report: DiffReport, redact_secrets: bool = True) -> str:
    data = report.to_dict()
    if redact_secrets:
        data["new_high_entropy_strings"] = [redact_secret(s) for s in data["new_high_entropy_strings"]]
        data["removed_high_entropy_strings"] = [redact_secret(s) for s in data["removed_high_entropy_strings"]]
    return json.dumps(data, indent=2, ensure_ascii=False)


def render_markdown(report: DiffReport, redact_secrets: bool = True) -> str:
    lines: list[str] = []
    lines.append("# JS Endpoint Diff Report")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    s = report.summary
    lines.append(f"- **Baseline scan:** {report.baseline_scan_id} ({report.baseline_created_at or 'N/A'})")
    lines.append(f"- **Current scan:** {report.current_scan_id} ({report.current_created_at or 'N/A'})")
    lines.append(f"- **Endpoints:** {s['current_endpoints']} current | **{s['new_endpoints_count']} newly introduced** | {s['removed_endpoints_count']} removed (baseline {s['baseline_endpoints']})")
    lines.append(f"- **High-entropy strings:** {s['current_high_entropy_strings']} current | {s['new_high_entropy_strings_count']} new | {s['removed_high_entropy_strings_count']} removed (baseline {s['baseline_high_entropy_strings']})")
    lines.append("")

    lines.append("## Newly Introduced Endpoints")
    lines.append("")
    if report.new_endpoints:
        for ep in report.new_endpoints:
            lines.append(f"- `{ep}`")
    else:
        lines.append("_None_")
    lines.append("")

    lines.append("## Removed Endpoints")
    lines.append("")
    if report.removed_endpoints:
        for ep in report.removed_endpoints:
            lines.append(f"- `{ep}`")
    else:
        lines.append("_None_")
    lines.append("")

    lines.append("## Newly Introduced High-Entropy Strings")
    lines.append("")
    if report.new_high_entropy_strings:
        vals = [redact_secret(v) if redact_secrets else v for v in report.new_high_entropy_strings]
        for v in vals:
            lines.append(f"- `{v}`")
    else:
        lines.append("_None_")
    lines.append("")

    lines.append("## Removed High-Entropy Strings")
    lines.append("")
    if report.removed_high_entropy_strings:
        vals = [redact_secret(v) if redact_secrets else v for v in report.removed_high_entropy_strings]
        for v in vals:
            lines.append(f"- `{v}`")
    else:
        lines.append("_None_")
    lines.append("")
    return "\n".join(lines)
