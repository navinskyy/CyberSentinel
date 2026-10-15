"""File-type detection and the entry points used by the app: load_file() / load_files()."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from ..models import empty_events, normalize_frame
from .csv_parser import parse_csv
from .fields import enrich
from .text_parser import parse_text

EVTX_MAGIC = b"ElfFile\x00"
SUPPORTED_EXTENSIONS = ("evtx", "csv", "txt", "log")


def detect_format(filename: str, data: bytes) -> str:
    if data[:8] == EVTX_MAGIC or Path(filename).suffix.lower() == ".evtx":
        return "evtx"
    if Path(filename).suffix.lower() == ".csv":
        return "csv"
    return "text"


def load_file(filename: str, data: bytes) -> tuple[pd.DataFrame, list[str]]:
    """Parse uploaded bytes into the normalized event frame. File content is only read, never executed."""
    fmt = detect_format(filename, data)
    try:
        if fmt == "evtx":
            from .evtx_parser import parse_evtx
            df, warnings = parse_evtx(data)
        elif fmt == "csv":
            df, warnings = parse_csv(data)
        else:
            df, warnings = parse_text(data)
        df = normalize_frame(df)
        if not df.empty:
            df = normalize_frame(enrich(df))
    except Exception as exc:  # malformed input must never crash the app
        return empty_events(), [f"{filename}: could not parse as {fmt.upper()} ({type(exc).__name__}: {exc})"]
    df["source"] = df["source"].fillna(Path(filename).name)
    return df, [f"{filename}: {w}" for w in warnings]


def load_files(files: list[tuple[str, bytes]]) -> tuple[pd.DataFrame, list[str]]:
    frames, warnings = [], []
    for name, data in files:
        df, w = load_file(name, data)
        warnings.extend(w)
        if not df.empty:
            frames.append(df)
    if not frames:
        return empty_events(), warnings
    return normalize_frame(pd.concat(frames, ignore_index=True)), warnings
