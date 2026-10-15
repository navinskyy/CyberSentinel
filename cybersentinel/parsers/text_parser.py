"""Plain-text log parser: one event per line, fields found by regex."""

from __future__ import annotations

import re
from datetime import datetime, timezone

import pandas as pd

_TS_PATTERNS: list[tuple[re.Pattern, str | None]] = [
    # 2026-01-15T10:00:00(.123)(Z|+00:00) or 2026-01-15 10:00:00
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), None),
    # 1/15/2026 10:00:00 AM (US-style, as Windows writes it)
    (re.compile(r"\d{1,2}/\d{1,2}/\d{4},?\s+\d{1,2}:\d{2}:\d{2}(?:\s*[AP]M)?", re.I), None),
    # syslog: Jan 15 10:00:00 (no year)
    (re.compile(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"), "%b %d %H:%M:%S"),
]
_EVENT_ID_RE = re.compile(r"\b(?:event\s*id|eventid|event_id|eid)\s*[=:#]?\s*(\d{1,5})\b", re.I)
_HOST_RE = re.compile(r"\b(?:host|computer|hostname)\s*[=:]\s*([\w.-]+)", re.I)
_LEVEL_RE = re.compile(r"\b(CRITICAL|ERROR|WARN(?:ING)?|INFO(?:RMATION)?|DEBUG|AUDIT (?:SUCCESS|FAILURE))\b", re.I)


def _parse_ts(line: str, year: int) -> pd.Timestamp | None:
    """Timestamps without a timezone are treated as UTC."""
    for pattern, fmt in _TS_PATTERNS:
        m = pattern.search(line)
        if not m:
            continue
        raw = m.group(0).replace(",", "")
        try:
            if fmt:
                return pd.Timestamp(datetime.strptime(f"{year} {' '.join(raw.split())}", f"%Y {fmt}"), tz="UTC")
            ts = pd.Timestamp(raw)
            return ts.tz_localize("UTC") if ts.tzinfo is None else ts.tz_convert("UTC")
        except (ValueError, TypeError):
            continue
    return None


def parse_text(data: bytes, default_year: int | None = None) -> tuple[pd.DataFrame, list[str]]:
    text = data.decode("utf-8-sig", errors="replace")
    year = default_year or datetime.now(timezone.utc).year
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        eid = _EVENT_ID_RE.search(line)
        host = _HOST_RE.search(line)
        level = _LEVEL_RE.search(line)
        rows.append({
            "timestamp": _parse_ts(line, year),
            "event_id": eid.group(1) if eid else None,
            "host": host.group(1) if host else None,
            "level": level.group(1).title() if level else None,
            "message": line.strip(),
            "raw": line.rstrip(),
        })
    warnings: list[str] = []
    df = pd.DataFrame(rows)
    if df.empty:
        warnings.append("Text file contains no log lines.")
    elif df["timestamp"].isna().all():
        warnings.append("No timestamps recognised; time-window rules will be skipped.")
    elif df["timestamp"].isna().any():
        warnings.append(f"{int(df['timestamp'].isna().sum())} line(s) had no recognisable timestamp.")
    return df, warnings
