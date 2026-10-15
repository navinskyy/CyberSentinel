"""CSV log parser. Handles Event Viewer "Save As CSV", PowerShell
Get-WinEvent | Export-Csv, and generic CSVs by mapping column-name aliases."""

from __future__ import annotations

import csv
import io

import pandas as pd

# canonical column -> accepted header names (compared case-insensitively, alphanumerics only)
COLUMN_ALIASES: dict[str, list[str]] = {
    "timestamp": ["timestamp", "timecreated", "dateandtime", "datetime", "eventtime", "time", "date"],
    "event_id": ["eventid", "id", "eventcode"],
    "source": ["source", "providername", "provider", "logname", "channel"],
    "level": ["level", "leveldisplayname", "severity", "keywords"],
    "user": ["user", "username", "targetusername", "accountname", "account"],
    "host": ["host", "computer", "machinename", "computername", "hostname"],
    "ip": ["ip", "ipaddress", "sourceip", "srcip", "sourcenetworkaddress", "clientaddress"],
    "logon_type": ["logontype"],
    "process": ["process", "processname", "image", "newprocessname"],
    "command_line": ["commandline", "processcommandline", "cmdline"],
    "message": ["message", "description", "details", "msg"],
}


def _key(name) -> str:
    return "".join(ch for ch in str(name).lower() if ch.isalnum())


def map_columns(columns) -> dict[str, str]:
    """Return {original_column: canonical_column}; first matching column wins."""
    lookup = {alias: canon for canon, aliases in COLUMN_ALIASES.items() for alias in aliases}
    mapping: dict[str, str] = {}
    for col in columns:
        canon = lookup.get(_key(col))
        if canon and canon not in mapping.values():
            mapping[col] = canon
    return mapping


def parse_csv(data: bytes) -> tuple[pd.DataFrame, list[str]]:
    warnings: list[str] = []
    text = data.decode("utf-8-sig", errors="replace")
    rows = list(csv.reader(io.StringIO(text)))
    rows = [r for r in rows if any(cell.strip() for cell in r)]
    if len(rows) < 2:
        return pd.DataFrame(), ["CSV file has no data rows."]

    header, body = rows[0], rows[1:]
    # Event Viewer exports put the message in extra, unlabeled trailing fields.
    width = len(header)
    extra = [" ".join(r[width:]).strip() for r in body]
    df = pd.DataFrame([(r + [""] * width)[:width] for r in body], columns=header)

    mapping = map_columns(header)
    out = df[list(mapping)].rename(columns=mapping)
    if any(extra):
        trailing = pd.Series(extra, index=out.index)
        out["message"] = (out["message"] + " " + trailing).str.strip() if "message" in out else trailing

    if "timestamp" not in out:
        warnings.append("No timestamp column recognised; time-window rules will be skipped.")
    if "event_id" not in out and "message" not in out:
        warnings.append("No Event ID or message column recognised; few detections will be possible.")
    ignored = [c for c in header if c not in mapping]
    if ignored:
        warnings.append(f"Ignored columns: {', '.join(ignored)}")
    out["raw"] = [",".join(r) for r in body]
    return out, warnings
