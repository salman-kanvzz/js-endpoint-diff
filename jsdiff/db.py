"""SQLite baseline storage."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    source_count INTEGER NOT NULL,
    notes TEXT
);
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    final_url TEXT,
    status_code INTEGER,
    error TEXT,
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    source_url TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    UNIQUE(scan_id, source_url, endpoint),
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS high_entropy_strings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    source_url TEXT NOT NULL,
    value TEXT NOT NULL,
    entropy REAL,
    UNIQUE(scan_id, source_url, value),
    FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE INDEX IF NOT EXISTS idx_endpoints_scan ON endpoints(scan_id);
CREATE INDEX IF NOT EXISTS idx_hes_scan ON high_entropy_strings(scan_id);
"""


@dataclass
class BaselineData:
    scan_id: int
    created_at: str
    endpoints: set[str]
    endpoints_by_source: dict[str, set[str]]
    high_entropy: set[str]
    sources: list[dict]


class Database:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self._init()

    def _init(self) -> None:
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def create_scan(self, created_at: str, source_count: int, notes: str | None = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans(created_at, source_count, notes) VALUES (?,?,?)",
            (created_at, source_count, notes),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def add_source(self, scan_id: int, url: str, final_url: str | None, status_code: int | None, error: str | None) -> None:
        self.conn.execute(
            "INSERT INTO sources(scan_id, url, final_url, status_code, error) VALUES (?,?,?,?,?)",
            (scan_id, url, final_url, status_code, error),
        )

    def add_endpoint(self, scan_id: int, source_url: str, endpoint: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO endpoints(scan_id, source_url, endpoint) VALUES (?,?,?)",
            (scan_id, source_url, endpoint),
        )

    def add_high_entropy(self, scan_id: int, source_url: str, value: str, entropy: float | None = None) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO high_entropy_strings(scan_id, source_url, value, entropy) VALUES (?,?,?,?)",
            (scan_id, source_url, value, entropy),
        )

    def commit(self) -> None:
        self.conn.commit()

    def get_latest_scan_id(self) -> Optional[int]:
        row = self.conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        return int(row["id"]) if row else None

    def get_scan_ids(self) -> list[int]:
        rows = self.conn.execute("SELECT id FROM scans ORDER BY id ASC").fetchall()
        return [int(r["id"]) for r in rows]

    def load_baseline(self, scan_id: Optional[int] = None) -> Optional[BaselineData]:
        if scan_id is None:
            scan_id = self.get_latest_scan_id()
        if scan_id is None:
            return None
        scan = self.conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan:
            return None
        endpoints: set[str] = set()
        by_source: dict[str, set[str]] = {}
        for r in self.conn.execute("SELECT source_url, endpoint FROM endpoints WHERE scan_id=?", (scan_id,)).fetchall():
            ep = r["endpoint"]
            src = r["source_url"]
            endpoints.add(ep)
            by_source.setdefault(src, set()).add(ep)
        hes: set[str] = set()
        for r in self.conn.execute("SELECT value FROM high_entropy_strings WHERE scan_id=?", (scan_id,)).fetchall():
            hes.add(r["value"])
        sources = [dict(r) for r in self.conn.execute("SELECT * FROM sources WHERE scan_id=?", (scan_id,)).fetchall()]
        return BaselineData(
            scan_id=scan_id,
            created_at=scan["created_at"],
            endpoints=endpoints,
            endpoints_by_source=by_source,
            high_entropy=hes,
            sources=sources,
        )
