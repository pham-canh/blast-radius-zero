"""Persistent run history for the demo.

A security product that forgets every run on restart looks like a toy. The
history is a small JSONL file with a hard cap: enough for a demo, no database
server. A failed write never breaks the agent loop — history is a convenience,
not evidence (the attestation file is the evidence).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LIMIT = 50


def default_path() -> Path:
    """Where runs are stored. Override with BLAST_RADIUS_HISTORY."""
    override = os.environ.get("BLAST_RADIUS_HISTORY", "").strip()
    if override:
        return Path(override)
    return Path(__file__).resolve().parent.parent / "out" / "history.jsonl"


class RunHistory:
    """Append-only run history with a bounded in-memory view."""

    def __init__(self, path: str | Path | None = None, limit: int = DEFAULT_LIMIT):
        self.path = Path(path) if path else default_path()
        self.limit = max(1, int(limit))
        self._records = self._load()

    def _load(self) -> list[dict]:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        records: list[dict] = []
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                records.append(record)
        return records[-self.limit:]

    def _rewrite(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(
                "\n".join(json.dumps(r, ensure_ascii=False) for r in self._records) + "\n",
                encoding="utf-8",
            )
            os.replace(tmp, self.path)
        except OSError:
            pass

    def append(self, record: dict) -> dict:
        stored = dict(record)
        stored.setdefault("at", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        self._records.append(stored)
        del self._records[:-self.limit]
        self._rewrite()
        return stored

    def recent(self, n: int = 10) -> list[dict]:
        return self._records[-max(1, int(n)):]

    def __len__(self) -> int:
        return len(self._records)
