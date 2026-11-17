"""Command-line interface for js-endpoint-diff."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .db import Database
from .diffing import compute_diff, render_json, render_markdown
from .extractor import extract_from_js
from .fetcher import fetch_js_urls
from .utils import read_urls, shannon_entropy


APP_DESC = "Download JS files, extract API paths/high-entropy strings, store baseline in SQLite, and output JSON/Markdown diffs."


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="js-endpoint-diff", description=APP_DESC)
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Fetch JS URLs, extract findings, store scan in SQLite, and output diff vs baseline.")
    scan.add_argument("--urls", nargs="*", default=[], help="One or more JS URLs to fetch.")
    scan.add_argument("--urls-file", help="Path to text file with JS URLs (one per line, # comments allowed).")
    scan.add_argument("--db", default="jsdiff.db", help="SQLite database path (default: jsdiff.db).")
    scan.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout in seconds (default: 15).")
    scan.add_argument("--format", choices=["json", "markdown", "both"], default="both", help="Diff output format.")
    scan.add_argument("--output", help="Output file path (for json/markdown) or base path for 'both' (writes .json and .md).")
    scan.add_argument("--baseline-id", type=int, help="Compare against specific scan ID as baseline (default: latest scan before this run).")
    scan.add_argument("--no-update-baseline", action="store_true", help="Do not persist this scan (compare only against existing baseline).")
    scan.add_argument("--show-secrets", action="store_true", help="Do not redact high-entropy strings in output (use with caution).")
    scan.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification (not recommended).")

    scans = sub.add_parser("scans", help="List stored scan IDs/timestamps.")
    scans.add_argument("--db", default="jsdiff.db", help="SQLite database path.")

    show = sub.add_parser("show", help="Show stored findings for a scan.")
    show.add_argument("--db", default="jsdiff.db", help="SQLite database path.")
    show.add_argument("--scan-id", type=int, help="Scan ID (default: latest).")
    show.add_argument("--format", choices=["json", "markdown"], default="json")

    diff = sub.add_parser("diff", help="Diff two stored scans without fetching.")
    diff.add_argument("--db", default="jsdiff.db", help="SQLite database path.")
    diff.add_argument("--from-id", type=int, help="Baseline scan ID (default: previous/latest-1 depending on context).")
    diff.add_argument("--to-id", type=int, help="Current scan ID (default: latest).")
    diff.add_argument("--format", choices=["json", "markdown", "both"], default="both")
    diff.add_argument("--output", help="Output file/base path.")
    diff.add_argument("--show-secrets", action="store_true", help="Do not redact high-entropy strings.")

    return p


def cmd_scans(args) -> int:
    with Database(args.db) as db:
        ids = db.get_scan_ids()
        if not ids:
            print("No scans found.")
            return 0
        for sid in ids:
            b = db.load_baseline(sid)
            if b:
                print(f"id={b.scan_id} created_at={b.created_at} endpoints={len(b.endpoints)} high_entropy={len(b.high_entropy)} sources={len(b.sources)}")
    return 0


def cmd_show(args) -> int:
    with Database(args.db) as db:
        b = db.load_baseline(args.scan_id)
        if not b:
            print("No scan found.", file=sys.stderr)
            return 1
        data = {
            "scan_id": b.scan_id,
            "created_at": b.created_at,
            "sources": b.sources,
            "endpoints": sorted(b.endpoints),
            "high_entropy_strings_count": len(b.high_entropy),
        }
        if args.format == "json":
            print(json.dumps(data, indent=2))
        else:
            print(f"# Scan {b.scan_id} ({b.created_at})\n")
            print(f"Sources: {len(b.sources)} | Endpoints: {len(b.endpoints)} | High-entropy strings: {len(b.high_entropy)}\n")
            print("## Endpoints")
            for e in sorted(b.endpoints):
                print(f"- `{e}`")
    return 0


def _emit_diff(report, fmt: str, output: str | None, show_secrets: bool) -> None:
    redact = not show_secrets
    outputs = {}
    if fmt in ("json", "both"):
        outputs["json"] = render_json(report, redact_secrets=redact)
    if fmt in ("markdown", "both"):
        outputs["markdown"] = render_markdown(report, redact_secrets=redact)

    if output:
        out = Path(output)
        if fmt == "both":
            out.parent.mkdir(parents=True, exist_ok=True)
            base = out.with_suffix("") if out.suffix in (".json", ".md") else out
            Path(str(base) + ".json").write_text(outputs["json"], encoding="utf-8")
            Path(str(base) + ".md").write_text(outputs["markdown"], encoding="utf-8")
            print(f"Wrote: {base}.json and {base}.md")
        else:
            out.parent.mkdir(parents=True, exist_ok=True)
            content = outputs["json"] if fmt == "json" else outputs["markdown"]
            out.write_text(content, encoding="utf-8")
            print(f"Wrote: {out}")
    else:
        if fmt == "both":
            print(outputs["json"])
            print("\n---\n")
            print(outputs["markdown"])
        elif fmt == "json":
            print(outputs["json"])
        else:
            print(outputs["markdown"])


def cmd_diff(args) -> int:
    with Database(args.db) as db:
        to_id = args.to_id or db.get_latest_scan_id()
        if to_id is None:
            print("No scans available.", file=sys.stderr)
            return 1
        ids = db.get_scan_ids()
        from_id = args.from_id
        if from_id is None:
            # previous scan relative to to_id
            prev = None
            for sid in ids:
                if sid < to_id:
                    prev = sid
            from_id = prev
        baseline = db.load_baseline(from_id) if from_id is not None else None
        current = db.load_baseline(to_id)
        if current is None:
            print("Target scan not found.", file=sys.stderr)
            return 1
        report = compute_diff(baseline, current)
        _emit_diff(report, args.format, args.output, args.show_secrets)
    return 0


def cmd_scan(args) -> int:
    try:
        urls = read_urls(args.urls, args.urls_file)
    except Exception as e:
        print(f"Error reading URLs: {e}", file=sys.stderr)
        return 2
    if not urls:
        print("Error: provide --urls and/or --urls-file with at least one URL.", file=sys.stderr)
        return 2

    print(f"[*] Fetching {len(urls)} JS URL(s)...")
    fetches = fetch_js_urls(urls, timeout=args.timeout, verify=not args.insecure)

    # Extract from fetched content
    current_data = {"endpoints": {}, "high_entropy": {}, "endpoints_set": set(), "hes_set": set()}  # by source
    for fr in fetches:
        status = fr.status_code if fr.status_code is not None else "ERR"
        msg = fr.error or "ok"
        print(f"  - {fr.url} [{status}] {msg if fr.error else ''}".rstrip())
        if not fr.content:
            continue
        ext = extract_from_js(fr.content, fr.url)
        eps = sorted(ext.endpoints)
        hes = sorted(ext.high_entropy_strings)
        current_data["endpoints"][fr.url] = eps
        current_data["high_entropy"][fr.url] = hes
        current_data["endpoints_set"].update(eps)
        current_data["hes_set"].update(hes)
        if ext.parse_error:
            print(f"    (parse warning: esprima fallback/partial parse used)")

    with Database(args.db) as db:
        # determine baseline: explicit, else latest before this run (or none)
        baseline = db.load_baseline(args.baseline_id) if args.baseline_id else db.load_baseline(db.get_latest_scan_id())

        if args.no_update_baseline:
            # create ephemeral-like comparison via temp in-memory? easier: build temp scan object not persisted
            from .db import BaselineData
            temp = BaselineData(
                scan_id=None,
                created_at=utc_now_iso(),
                endpoints=current_data["endpoints_set"],
                endpoints_by_source={k: set(v) for k, v in current_data["endpoints"].items()},
                high_entropy=current_data["hes_set"],
                sources=[],
            )
            report = compute_diff(baseline, temp)
            _emit_diff(report, args.format, args.output, args.show_secrets)
            print("\n[!] --no-update-baseline set: scan not stored.")
            return 0

        scan_id = db.create_scan(utc_now_iso(), len(urls), notes=None)
        for fr in fetches:
            db.add_source(scan_id, fr.url, fr.final_url, fr.status_code, fr.error)
        for src, eps in current_data["endpoints"].items():
            for ep in eps:
                db.add_endpoint(scan_id, src, ep)
        for src, hes in current_data["high_entropy"].items():
            for val in hes:
                db.add_high_entropy(scan_id, src, val, entropy=round(shannon_entropy(val), 4))
        db.commit()

        current = db.load_baseline(scan_id)
        report = compute_diff(baseline, current)
        print(f"\n[*] Stored scan id={scan_id} in {args.db}")
        _emit_diff(report, args.format, args.output, args.show_secrets)
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "scans":
        return cmd_scans(args)
    if args.command == "show":
        return cmd_show(args)
    if args.command == "diff":
        return cmd_diff(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
