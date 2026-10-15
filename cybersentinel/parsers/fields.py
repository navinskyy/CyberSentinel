"""Shared helpers: pull structured fields out of Windows event message text
and classify events into normalized actions used by the detection rules."""

from __future__ import annotations

import re

import pandas as pd

# Windows Event ID -> normalized action.
EVENT_ID_ACTIONS: dict[int, str] = {
    4624: "logon_success",
    4625: "logon_failure",
    4771: "logon_failure",       # Kerberos pre-auth failed
    4740: "account_lockout",
    4720: "user_created",
    4726: "user_deleted",
    4728: "group_member_added",  # global group
    4732: "group_member_added",  # local group
    4756: "group_member_added",  # universal group
    4688: "process_created",
    4697: "service_installed",
    7045: "service_installed",
    4698: "scheduled_task_created",
    1102: "log_cleared",
    104: "log_cleared",
    4719: "audit_policy_changed",
}

# Free-text keyword patterns -> action, checked in order (first match wins).
TEXT_ACTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("account_lockout", re.compile(r"\baccount\b(?:\s+\S+)?\s+(?:was\s+|has been\s+|is\s+)?locked|lockout", re.I)),
    ("logon_failure", re.compile(
        r"fail(?:ed|ure)?\s+(?:to\s+)?(?:log ?[io]n|sign[- ]?in|authenticat\w*|password)"
        r"|(?:log ?[io]n|login|authentication|sign[- ]?in)\s+fail\w*"
        r"|invalid (?:user|password|credentials)|bad password", re.I)),
    ("logon_success", re.compile(
        r"(?:log ?[io]n|login|sign[- ]?in|authentication)\s+(?:succe\w+|ok)"
        r"|accepted password|successfully logged on", re.I)),
    ("log_cleared", re.compile(r"(?:audit |event |security )?log (?:was |file )?cleared", re.I)),
    ("service_installed", re.compile(r"service (?:was )?installed|new service", re.I)),
    ("user_created", re.compile(r"user account (?:was )?created", re.I)),
]

_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_PLACEHOLDERS = {"", "-", "::1", "127.0.0.1", "localhost", "n/a", "null", "none", "0.0.0.0"}


def _all(label: str, text: str) -> list[str]:
    """All values after 'Label:' in Windows event message text."""
    return [v.strip() for v in re.findall(rf"{label}:[ \t]*([^\r\n\t|]*)", text, re.I)]


def _last_real(values: list[str]) -> str | None:
    for v in reversed(values):
        v = v.strip()
        if v.lower() not in _PLACEHOLDERS and not v.endswith("$"):  # skip machine accounts
            return v
    return None


def extract_fields(message) -> dict[str, str]:
    """Best-effort extraction from a Windows event message or a free-text line."""
    if not isinstance(message, str) or not message:
        return {}
    out: dict[str, str | None] = {}
    # Windows messages list the Subject first and the target account last, so the
    # last non-placeholder "Account Name" is the account the event is about.
    out["user"] = _last_real(_all("Account Name", message)) or _last_real(_all("Target User Name", message))
    if not out["user"]:
        m = re.search(r"(?:for (?:invalid )?user|\buser(?:name)?\s*[=:]|\baccount\s*[=:])\s*['\"]?([\w.\\@-]+)",
                      message, re.I)
        if m:
            out["user"] = m.group(1)
    ip = _last_real(_all("Source Network Address", message)) or _last_real(_all("Client Address", message))
    if ip:
        ip = ip.removeprefix("::ffff:")
    else:
        found = [i for i in _IP_RE.findall(message) if i not in _PLACEHOLDERS]
        ip = found[0] if found else None
    out["ip"] = ip
    out["logon_type"] = _last_real(_all("Logon Type", message))
    out["process"] = (_last_real(_all("New Process Name", message))
                      or _last_real(_all("Service File Name", message))
                      or _last_real(_all("Process Name", message)))
    out["command_line"] = _last_real(_all("Process Command Line", message))
    if not out["command_line"] and out["process"] and " " in out["process"]:
        out["command_line"] = out["process"]  # 7045 "Service File Name" often holds a full command
    return {k: v for k, v in out.items() if v}


def classify(event_id, message) -> str | None:
    if pd.notna(event_id) and int(event_id) in EVENT_ID_ACTIONS:
        return EVENT_ID_ACTIONS[int(event_id)]
    if isinstance(message, str):
        for action, pattern in TEXT_ACTION_PATTERNS:
            if pattern.search(message):
                return action
    return None


def enrich(df: pd.DataFrame) -> pd.DataFrame:
    """Fill empty structured columns from message text and set `action`.
    Values a parser already set are never overwritten."""
    df = df.copy()
    extracted = df["message"].map(extract_fields)
    for col in ("user", "ip", "logon_type", "process", "command_line"):
        fill = extracted.map(lambda d, c=col: d.get(c))
        df[col] = df[col].astype("object").where(df[col].notna(), fill)
    actions = pd.Series([classify(e, m) for e, m in zip(df["event_id"], df["message"])], index=df.index)
    df["action"] = df["action"].astype("object").where(df["action"].notna(), actions)
    return df
