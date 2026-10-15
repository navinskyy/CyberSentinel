"""Native Windows .evtx parser (read-only, via pyevtx-rs).

EVTX files store structured EventData but not the rendered message text (that lives
in provider DLLs on the source machine), so the message is built from a short
description plus the record's named fields.
"""

from __future__ import annotations

import io
import xml.etree.ElementTree as ET

import pandas as pd

from .fields import id_matches_provider

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
LEVELS = {"0": "Information", "1": "Critical", "2": "Error", "3": "Warning", "4": "Information", "5": "Verbose"}
DESCRIPTIONS = {
    4624: "An account was successfully logged on.",
    4625: "An account failed to log on.",
    4672: "Special privileges assigned to new logon.",
    4688: "A new process has been created.",
    4697: "A service was installed in the system.",
    4698: "A scheduled task was created.",
    4719: "System audit policy was changed.",
    4720: "A user account was created.",
    4726: "A user account was deleted.",
    4728: "A member was added to a security-enabled global group.",
    4732: "A member was added to a security-enabled local group.",
    4740: "A user account was locked out.",
    4756: "A member was added to a security-enabled universal group.",
    4771: "Kerberos pre-authentication failed.",
    7045: "A service was installed in the system.",
    1102: "The audit log was cleared.",
    104: "The event log was cleared.",
}
GROUP_EVENTS = {4728, 4732, 4756}
MAX_RECORDS = 500_000
_PLACEHOLDER = {"", "-", "::1", "127.0.0.1"}


def _real(*values) -> str | None:
    for v in values:
        if v and v.strip() not in _PLACEHOLDER and not v.endswith("$"):
            return v.strip()
    return None


def record_to_row(xml: str) -> dict:
    """Convert one EVTX record's XML into a normalized-event dict."""
    root = ET.fromstring(xml)
    system = root.find("e:System", NS)
    text = lambda path: (system.findtext(path, default="", namespaces=NS) or "").strip()
    provider = system.find("e:Provider", NS)
    created = system.find("e:TimeCreated", NS)
    eid = int(text("e:EventID") or 0)

    data: dict[str, str] = {}
    for i, node in enumerate(root.iterfind(".//e:EventData/e:Data", NS)):
        data[node.get("Name") or f"Data{i}"] = (node.text or "").strip()
    for node in root.iterfind(".//e:UserData//*", NS):  # e.g. 1102 LogFileCleared
        if node.text and node.text.strip() and not list(node):
            data.setdefault(node.tag.split("}")[-1], node.text.strip())

    if eid in GROUP_EVENTS:
        user = _real(data.get("MemberName"), data.get("MemberSid"))
        group = data.get("TargetUserName")
    else:
        user = _real(data.get("TargetUserName"), data.get("SubjectUserName"), data.get("AccountName"))
        group = None
    ip = _real(data.get("IpAddress"), data.get("ClientAddress"))
    if ip:
        ip = ip.removeprefix("::ffff:")
    command = data.get("CommandLine") or data.get("ImagePath") or data.get("ServiceFileName")

    source = (provider.get("Name") if provider is not None else None) or text("e:Channel")
    details = "; ".join(f"{k}={v}" for k, v in data.items() if v and v != "-")
    message = " ".join(filter(None, [
        DESCRIPTIONS.get(eid, "") if id_matches_provider(eid, source) else "",
        f"Group Name: {group}." if group else "",
        details,
    ]))
    return {
        "timestamp": created.get("SystemTime") if created is not None else None,
        "event_id": eid,
        "source": source,
        "level": LEVELS.get(text("e:Level"), text("e:Level")),
        "user": user,
        "host": text("e:Computer") or None,
        "ip": ip,
        "logon_type": data.get("LogonType"),
        "process": data.get("NewProcessName") or data.get("ProcessName") or data.get("ServiceName"),
        "parent_process": data.get("ParentProcessName"),
        "command_line": command,
        "message": message,
        "raw": xml,
    }


def parse_evtx(data: bytes, max_records: int = MAX_RECORDS) -> tuple[pd.DataFrame, list[str]]:
    # pyevtx-rs (PyPI "evtx"). Not python-evtx: on Windows the two packages' folders
    # ("evtx" / "Evtx") collide and cannot be installed side by side.
    from evtx import PyEvtxParser

    if data[:8] != b"ElfFile\x00":
        raise ValueError("file does not have an EVTX header")
    records = iter(PyEvtxParser(io.BytesIO(data)).records())
    rows, bad, warnings = [], 0, []
    while True:
        if len(rows) >= max_records:
            warnings.append(f"Stopped after {max_records:,} records; the remainder was not analysed.")
            break
        try:
            record = next(records)
        except StopIteration:
            break
        except Exception:  # corrupt record: skip it, keep going
            bad += 1
            continue
        try:
            rows.append(record_to_row(record["data"]))
        except Exception:
            bad += 1
    if bad:
        warnings.append(f"Skipped {bad} unreadable record(s).")
    if not rows:
        warnings.append("EVTX file contains no readable records.")
    return pd.DataFrame(rows), warnings
