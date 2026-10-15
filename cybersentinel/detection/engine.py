"""Runs the rule set over normalized events and assigns per-event severity."""

from __future__ import annotations

from dataclasses import dataclass, field

import pandas as pd

from ..models import Finding, Severity
from .rules import ALL_RULES, DetectionConfig

# Baseline severity of an event by its normalized action and by its Windows level.
ACTION_SEVERITY = {
    "logon_failure": Severity.LOW,
    "account_lockout": Severity.MEDIUM,
    "user_created": Severity.MEDIUM,
    "group_member_added": Severity.MEDIUM,
    "service_installed": Severity.MEDIUM,
    "scheduled_task_created": Severity.MEDIUM,
    "log_cleared": Severity.HIGH,
    "audit_policy_changed": Severity.HIGH,
}
LEVEL_SEVERITY = {"critical": Severity.HIGH, "error": Severity.MEDIUM, "warning": Severity.LOW,
                  "warn": Severity.LOW, "audit failure": Severity.LOW}


@dataclass
class AnalysisResult:
    events: pd.DataFrame                       # normalized events + "severity" column
    findings: list[Finding]
    errors: list[str] = field(default_factory=list)

    def severity_counts(self) -> dict[str, int]:
        counts = {s.label: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            counts[f.severity.label] += 1
        return counts

    def findings_frame(self) -> pd.DataFrame:
        return pd.DataFrame([f.to_dict() for f in self.findings])


def event_severity(events: pd.DataFrame, findings: list[Finding]) -> pd.Series:
    """Highest of: action baseline, Windows level, and any finding the event is evidence for."""
    sev = events["action"].map(lambda a: ACTION_SEVERITY.get(a, Severity.INFO)).astype(int)
    lvl = events["level"].str.lower().map(lambda v: LEVEL_SEVERITY.get(v, Severity.INFO)).fillna(0).astype(int)
    sev = sev.where(sev >= lvl, lvl)
    for f in findings:
        idx = [i for i in f.evidence_index if i in sev.index]
        sev.loc[idx] = sev.loc[idx].clip(lower=int(f.severity))
    return sev.map(lambda v: Severity(v).label)


def analyze(events: pd.DataFrame, config: DetectionConfig | None = None) -> AnalysisResult:
    config = config or DetectionConfig()
    findings: list[Finding] = []
    errors: list[str] = []
    for rule in ALL_RULES:
        try:
            findings.extend(rule(events, config))
        except Exception as exc:  # one broken rule must not hide the others' results
            errors.append(f"Rule {rule.__name__} failed: {type(exc).__name__}: {exc}")
    far_future = pd.Timestamp.max.tz_localize("UTC")
    findings.sort(key=lambda f: (-int(f.severity), f.first_seen if f.first_seen is not None else far_future))
    out = events.copy()
    out["severity"] = event_severity(events, findings) if len(events) else pd.Series(dtype="string")
    return AnalysisResult(out, findings, errors)
