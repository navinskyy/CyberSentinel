"""Core data model shared by parsers, the detection engine, and reporting.

Parsers produce a pandas DataFrame with the columns in EVENT_COLUMNS.
The detection engine produces a list of Finding objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

import pandas as pd

# Normalized event schema. Every parser must return exactly these columns.
EVENT_COLUMNS = [
    "timestamp",     # tz-aware UTC datetime
    "event_id",      # nullable Int64 (Windows Event ID) or <NA> for free text
    "action",        # normalized action, e.g. "logon_failure" (see parsers.fields)
    "source",        # provider / channel / log file name
    "level",         # original level text, e.g. "Information", "Error"
    "user",          # target account name, if known
    "host",          # computer name
    "ip",            # source IP address, if known
    "logon_type",    # Windows logon type, if known
    "process",       # process / image name, if known
    "parent_process",  # creator / parent process image, if known (4688)
    "command_line",  # process command line, if known
    "message",       # human-readable summary
    "raw",           # original record text for evidence
]


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.title()


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    description: str
    first_seen: pd.Timestamp | None
    last_seen: pd.Timestamp | None
    count: int
    entities: dict[str, str] = field(default_factory=dict)  # e.g. {"user": "bob", "ip": "1.2.3.4"}
    recommendation: str = ""
    mitre: str = ""                                           # ATT&CK technique ID
    evidence_index: list[int] = field(default_factory=list)  # row indexes into the events frame

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "description": self.description,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "count": self.count,
            "entities": ", ".join(f"{k}={v}" for k, v in self.entities.items()),
            "mitre": self.mitre,
            "recommendation": self.recommendation,
        }


def empty_events() -> pd.DataFrame:
    return normalize_frame(pd.DataFrame(columns=EVENT_COLUMNS))


def normalize_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Coerce a partially-filled frame to the canonical schema and dtypes."""
    df = df.copy()
    for col in EVENT_COLUMNS:
        if col not in df.columns:
            df[col] = None
    df = df[EVENT_COLUMNS]
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True, format="mixed")
    df["event_id"] = pd.to_numeric(df["event_id"], errors="coerce").astype("Int64")
    for col in EVENT_COLUMNS:
        if col not in ("timestamp", "event_id"):
            df[col] = df[col].astype("string").str.strip().replace({"": pd.NA, "-": pd.NA, "nan": pd.NA, "None": pd.NA})
    return df.sort_values("timestamp", na_position="last").reset_index(drop=True)
