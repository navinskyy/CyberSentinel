"""Local, rule-based detections. No network access, no AI, no system changes:
every rule is a pure function of the normalized events frame.

Two kinds of rules:
  - SINGLE_EVENT_RULES: declarative table, one finding per matching event (or per entity).
  - Correlation rules: functions that look at many events over time windows.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

import numpy as np
import pandas as pd

from ..models import Finding, Severity


@dataclass
class DetectionConfig:
    brute_force_threshold: int = 5        # failed logons for one account ...
    brute_force_window_min: int = 10      # ... within this many minutes
    spray_user_threshold: int = 5         # distinct accounts failed from one IP ...
    spray_window_min: int = 30            # ... within this many minutes
    success_after_fail_min: int = 15      # success within N min after a brute-force burst
    flag_external_logons: bool = True     # successful logons from public IP addresses
    discovery_threshold: int = 4          # distinct recon commands by one user on one host ...
    discovery_window_min: int = 10        # ... within this many minutes


PRIVILEGED_GROUPS = ("administrators", "domain admins", "enterprise admins", "schema admins",
                     "backup operators", "remote desktop users", "account operators", "server operators")

# Suspicious command-line patterns: (name, regex, severity, ATT&CK technique)
SUSPICIOUS_COMMANDS: list[tuple[str, re.Pattern, Severity, str]] = [
    ("Encoded PowerShell command", re.compile(r"powershell.*\s-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{16,}", re.I),
     Severity.HIGH, "T1059.001"),
    ("Hidden PowerShell window", re.compile(r"powershell.*-w(?:indowstyle)?\s+hidden", re.I), Severity.MEDIUM, "T1564.003"),
    ("PowerShell download cradle", re.compile(r"downloadstring|downloadfile|invoke-webrequest|\biwr\b.*\|\s*iex|\biex\b|invoke-expression", re.I),
     Severity.HIGH, "T1105"),
    ("Credential dumping tool", re.compile(r"mimikatz|sekurlsa|lsadump|procdump.*lsass|comsvcs\.dll.*minidump", re.I),
     Severity.CRITICAL, "T1003"),
    ("Shadow copy deletion", re.compile(r"vssadmin.*delete\s+shadows|wmic.*shadowcopy.*delete", re.I), Severity.CRITICAL, "T1490"),
    ("Recovery disabled", re.compile(r"bcdedit.*recoveryenabled\s+no", re.I), Severity.HIGH, "T1490"),
    ("Event log cleared via command", re.compile(r"wevtutil(?:\.exe)?\s+cl\b|clear-eventlog", re.I), Severity.HIGH, "T1070.001"),
    ("Certutil download", re.compile(r"certutil.*-urlcache", re.I), Severity.HIGH, "T1105"),
    ("User added via net.exe", re.compile(r"\bnet1?(?:\.exe)?\s+(?:user\s+\S+\s+\S+\s+/add|localgroup\s+administrators\s+\S+\s+/add)", re.I),
     Severity.MEDIUM, "T1136.001"),
]


@dataclass(frozen=True)
class SingleEventRule:
    rule_id: str
    action: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    mitre: str = ""
    group_by: str | None = None  # aggregate into one finding per value of this column


SINGLE_EVENT_RULES: list[SingleEventRule] = [
    SingleEventRule("LOG_CLEARED", "log_cleared", "Event log cleared", Severity.HIGH,
                    "An event log was cleared. Attackers clear logs to hide activity.",
                    "Confirm whether the clear was authorised; review activity just before it and on other log sources.",
                    "T1070.001"),
    SingleEventRule("AUDIT_POLICY_CHANGED", "audit_policy_changed", "Audit policy changed", Severity.HIGH,
                    "System audit policy was modified, which can disable security logging.",
                    "Verify the change against change records; confirm required auditing is still enabled.", "T1562.002"),
    SingleEventRule("SERVICE_INSTALLED", "service_installed", "New service installed", Severity.MEDIUM,
                    "A new service was installed. Services are a common persistence and privilege-escalation method.",
                    "Check the service binary path and signer; confirm it belongs to approved software.", "T1543.003"),
    SingleEventRule("SCHEDULED_TASK", "scheduled_task_created", "Scheduled task created", Severity.MEDIUM,
                    "A scheduled task was created, a common persistence mechanism.",
                    "Review the task's action and author; confirm it is expected.", "T1053.005"),
    SingleEventRule("USER_CREATED", "user_created", "User account created", Severity.MEDIUM,
                    "A new local or domain user account was created.",
                    "Confirm the account was requested and approved.", "T1136"),
    SingleEventRule("ACCOUNT_LOCKOUT", "account_lockout", "Account locked out", Severity.MEDIUM,
                    "An account was locked out after repeated failed logons.",
                    "Contact the account owner; check the failed-logon sources for this account.", "T1110",
                    group_by="user"),
]


# ---------------------------------------------------------------- helpers

def _span(rows: pd.DataFrame) -> tuple[pd.Timestamp | None, pd.Timestamp | None]:
    ts = rows["timestamp"].dropna()
    return (ts.min(), ts.max()) if len(ts) else (None, None)


def _top(values: pd.Series, n: int = 5) -> str:
    vc = values.dropna().value_counts()
    text = ", ".join(vc.index[:n].astype(str))
    return text + (f" (+{len(vc) - n} more)" if len(vc) > n else "")


def _bursts(times: pd.Series, window: pd.Timedelta, threshold: int,
            distinct: pd.Series | None = None) -> list[np.ndarray]:
    """Split time-sorted events into clusters (gap > window starts a new one) and return the
    positional indexes of clusters where some window-sized span holds >= threshold events
    (or >= threshold distinct values of `distinct`)."""
    t = times.to_numpy()
    if len(t) == 0:
        return []
    gaps = np.diff(t) > window.to_timedelta64()
    starts = np.r_[0, np.nonzero(gaps)[0] + 1]
    ends = np.r_[starts[1:], len(t)]
    hits = []
    for s, e in zip(starts, ends):
        if e - s < threshold:
            continue
        lo = s
        for hi in range(s, e):  # two-pointer sliding window
            while t[hi] - t[lo] > window.to_timedelta64():
                lo += 1
            count = (hi - lo + 1) if distinct is None else distinct.iloc[lo:hi + 1].nunique()
            if count >= threshold:
                hits.append(np.arange(s, e))
                break
    return hits


def _is_public(ip) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return addr.is_global


# ---------------------------------------------------------------- single-event rules

def single_event_findings(df: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    out = []
    for rule in SINGLE_EVENT_RULES:
        hits = df[df["action"] == rule.action]
        if hits.empty:
            continue
        groups = hits.groupby(hits[rule.group_by].fillna("unknown"), sort=False) if rule.group_by \
            else ((None, hits.loc[[i]]) for i in hits.index)
        for key, rows in groups:
            first, last = _span(rows)
            row = rows.iloc[0]
            entities = {k: str(row[k]) for k in ("user", "host", "process") if pd.notna(row[k])}
            if rule.group_by:
                entities[rule.group_by] = str(key)
            out.append(Finding(rule.rule_id, rule.title, rule.severity,
                               rule.description + (f" ({len(rows)} events)" if len(rows) > 1 else ""),
                               first, last, len(rows), entities, rule.recommendation, rule.mitre, list(rows.index)))
    return out


def privileged_group_additions(df: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    out = []
    for i, row in df[df["action"] == "group_member_added"].iterrows():
        msg = str(row["message"]).lower()
        group = next((g for g in PRIVILEGED_GROUPS if g in msg), None)
        sev = Severity.HIGH if group else Severity.LOW
        entities = {"member": str(row["user"]) if pd.notna(row["user"]) else "unknown"}
        if group:
            entities["group"] = group.title()
        out.append(Finding("GROUP_MEMBER_ADDED",
                           f"Account added to privileged group ({group.title()})" if group else "Account added to group",
                           sev, "A security group membership changed." +
                           (" Membership of this group grants elevated rights." if group else ""),
                           row["timestamp"], row["timestamp"], 1, entities,
                           "Confirm the change was approved; remove the member if not.", "T1098", [i]))
    return out


def suspicious_commands(df: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    text = df["command_line"].fillna("") + " " + df["message"].fillna("")
    out = []
    for name, pattern, sev, mitre in SUSPICIOUS_COMMANDS:
        hits = df[text.str.contains(pattern, na=False)]
        for (host, cmd), rows in hits.groupby([hits["host"].fillna("unknown"),
                                               hits["command_line"].fillna(hits["message"]).str[:300]], sort=False):
            first, last = _span(rows)
            out.append(Finding("SUSPICIOUS_COMMAND", f"Suspicious command: {name}", sev,
                               f"Command line matches a known attacker technique: {cmd}",
                               first, last, len(rows), {"host": host} | ({"user": rows["user"].dropna().iloc[0]}
                                                                        if rows["user"].notna().any() else {}),
                               "Identify the parent process and user; isolate the host if the activity is not explained.",
                               mitre, list(rows.index)))
    return out


# ---------------------------------------------------------------- correlation rules

def brute_force(df: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    """Repeated failed logons for one account (or one IP when the account is unknown),
    escalated to CRITICAL when a successful logon for that account follows."""
    window = pd.Timedelta(minutes=cfg.brute_force_window_min)
    follow = pd.Timedelta(minutes=cfg.success_after_fail_min)
    fails = df[(df["action"] == "logon_failure") & df["timestamp"].notna()]
    successes = df[(df["action"] == "logon_success") & df["timestamp"].notna()]
    key = fails["user"].fillna("ip:" + fails["ip"].fillna("unknown"))
    out = []
    for target, rows in fails.groupby(key, sort=False):
        for pos in _bursts(rows["timestamp"], window, cfg.brute_force_threshold):
            burst = rows.iloc[pos]
            first, last = _span(burst)
            entities = {"user" if not target.startswith("ip:") else "ip": target.removeprefix("ip:"),
                        "source_ips": _top(burst["ip"]), "hosts": _top(burst["host"])}
            entities = {k: v for k, v in entities.items() if v}
            out.append(Finding("BRUTE_FORCE", f"Repeated failed logons for {target.removeprefix('ip:')}",
                               Severity.HIGH,
                               f"{len(burst)} failed logons within {cfg.brute_force_window_min} min "
                               f"(threshold {cfg.brute_force_threshold}).",
                               first, last, len(burst), entities,
                               "Verify with the account owner; block the source IPs if not legitimate; "
                               "consider MFA and an account lockout policy.", "T1110.001", list(burst.index)))
            if target.startswith("ip:"):
                continue
            ok = successes[(successes["user"] == target) & (successes["timestamp"] >= first)
                           & (successes["timestamp"] <= last + follow)]
            burst_ips = set(burst["ip"].dropna())
            if burst_ips:  # require the same source when IPs are known
                ok = ok[ok["ip"].isin(burst_ips) | ok["ip"].isna()]
            if not ok.empty:
                s = ok.iloc[0]
                out.append(Finding("BRUTE_FORCE_SUCCESS", f"Successful logon after brute force: {target}",
                                   Severity.CRITICAL,
                                   f"Account {target} logged on successfully at {s['timestamp']} after "
                                   f"{len(burst)} failed attempts. The password may be compromised.",
                                   first, s["timestamp"], len(burst) + 1,
                                   {"user": target, "ip": str(s["ip"]) if pd.notna(s["ip"]) else "unknown"},
                                   "Treat as a likely compromise: reset the password, review the session's activity, "
                                   "and check the source host.", "T1110", list(burst.index) + [ok.index[0]]))
    return out


def password_spray(df: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    """One source IP failing against many different accounts."""
    window = pd.Timedelta(minutes=cfg.spray_window_min)
    fails = df[(df["action"] == "logon_failure") & df["timestamp"].notna() & df["ip"].notna() & df["user"].notna()]
    out = []
    for ip, rows in fails.groupby("ip", sort=False):
        for pos in _bursts(rows["timestamp"], window, cfg.spray_user_threshold, distinct=rows["user"]):
            burst = rows.iloc[pos]
            first, last = _span(burst)
            n_users = burst["user"].nunique()
            out.append(Finding("PASSWORD_SPRAY", f"Password spray from {ip}", Severity.HIGH,
                               f"{n_users} different accounts failed to log on from {ip} "
                               f"within {cfg.spray_window_min} min (threshold {cfg.spray_user_threshold}).",
                               first, last, len(burst), {"ip": ip, "accounts": _top(burst["user"], 8)},
                               "Block the source IP; check whether any targeted account later logged on successfully.",
                               "T1110.003", list(burst.index)))
    return out


def external_logons(df: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    if not cfg.flag_external_logons:
        return []
    ok = df[(df["action"] == "logon_success") & df["ip"].notna()]
    ok = ok[ok["ip"].map(_is_public).astype(bool)]
    if ok.empty:
        return []
    out = []
    for (user, ip), rows in ok.groupby([ok["user"].fillna("unknown"), "ip"], sort=False):
        rdp = rows["logon_type"].eq("10").any()
        first, last = _span(rows)
        out.append(Finding("EXTERNAL_LOGON", f"{'RDP l' if rdp else 'L'}ogon from public IP {ip}",
                           Severity.HIGH if rdp else Severity.MEDIUM,
                           f"Account {user} logged on {len(rows)} time(s) from an Internet address.",
                           first, last, len(rows), {"user": user, "ip": ip},
                           "Confirm the user and location are expected; restrict remote access to VPN.",
                           "T1133", list(rows.index)))
    return out


# ---------------------------------------------------------------- process creation (4688)

_SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
           "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "schtasks.exe", "bash.exe"}
_OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe",
           "mspub.exe", "visio.exe"}
_WEB = {"w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "tomcat9.exe", "php-cgi.exe", "sqlservr.exe"}

# (parent images, child images, title, severity, ATT&CK, recommendation)
PARENT_CHILD_RULES: list[tuple[set[str], set[str], str, Severity, str, str]] = [
    (_OFFICE, _SHELLS, "Office application spawned {child}", Severity.HIGH, "T1204.002",
     "Likely a malicious document or macro: identify the opened file, check the child's command line, "
     "and isolate the host if the activity is not explained."),
    (_WEB, _SHELLS, "Web/database server spawned {child}", Severity.HIGH, "T1505.003",
     "Possible web shell: review the web root for recently changed files and the server's request logs."),
    ({"wmiprvse.exe"}, _SHELLS, "WMI spawned {child}", Severity.MEDIUM, "T1047",
     "Possible remote execution via WMI: identify the originating host and account."),
]

# Executables launched from user-writable folders: (pattern, severity). Temp/Downloads are
# Low because installers routinely run there; Public/Recycle Bin/PerfLogs rarely have a legitimate reason.
USER_WRITABLE_PATHS: list[tuple[re.Pattern, Severity]] = [
    (re.compile(r"\\users\\public\\|\\\$recycle\.bin\\|\\perflogs\\", re.I), Severity.MEDIUM),
    (re.compile(r"\\appdata\\local\\temp\\|\\windows\\temp\\|\\downloads\\", re.I), Severity.LOW),
]

# Reconnaissance commands, matched against the command line (or image when no command line).
DISCOVERY_COMMANDS: list[tuple[str, re.Pattern]] = [(k, re.compile(p, re.I)) for k, p in [
    ("whoami", r"\bwhoami(?:\.exe)?\b"),
    ("net user", r"\bnet1?(?:\.exe)?\s+user\b"),
    ("net group", r"\bnet1?(?:\.exe)?\s+(?:local)?group\b"),
    ("net view/share", r"\bnet1?(?:\.exe)?\s+(?:view|share|session|accounts)\b"),
    ("ipconfig", r"\bipconfig(?:\.exe)?\b"),
    ("systeminfo", r"\bsysteminfo(?:\.exe)?\b"),
    ("nltest", r"\bnltest(?:\.exe)?\b"),
    ("query user", r"\bquser(?:\.exe)?\b|\bquery(?:\.exe)?\s+user\b"),
    ("tasklist", r"\btasklist(?:\.exe)?\b"),
    ("netstat", r"\bnetstat(?:\.exe)?\b"),
    ("arp", r"\barp(?:\.exe)?\s+-a\b"),
    ("route print", r"\broute(?:\.exe)?\s+print\b"),
    ("AD query", r"\bdsquery(?:\.exe)?\b|\bget-ad(?:user|group|computer)\b"),
    ("klist", r"\bklist(?:\.exe)?\b"),
    ("wmic recon", r"\bwmic(?:\.exe)?\b.*\b(?:useraccount|group|qfe|computersystem)\b"),
]]


def _image(path) -> str:
    return str(path).replace("/", "\\").rsplit("\\", 1)[-1].strip().lower() if pd.notna(path) else ""


def _processes(df: pd.DataFrame) -> pd.DataFrame:
    return df[(df["action"] == "process_created") & df["process"].notna()]


def suspicious_parent_child(df: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    procs = _processes(df)
    if procs.empty:
        return []
    child, parent = procs["process"].map(_image), procs["parent_process"].map(_image)
    out = []
    for parents, children, title, sev, mitre, rec in PARENT_CHILD_RULES:
        hits = procs[parent.isin(parents) & child.isin(children)]
        for (host, p, c), rows in hits.groupby([hits["host"].fillna("unknown"), parent[hits.index],
                                                child[hits.index]], sort=False):
            first, last = _span(rows)
            cmd = rows["command_line"].dropna()
            entities = {"host": host, "parent": p, "child": c}
            if rows["user"].notna().any():
                entities["user"] = rows["user"].dropna().iloc[0]
            out.append(Finding("SUSPICIOUS_PARENT_CHILD", title.format(child=c), sev,
                               f"{p} started {c} {len(rows)} time(s)."
                               + (f" Command line: {cmd.iloc[0][:300]}" if len(cmd) else ""),
                               first, last, len(rows), entities, rec, mitre, list(rows.index)))
    return out


def user_writable_execution(df: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    procs = _processes(df)
    out = []
    for pattern, sev in USER_WRITABLE_PATHS:
        hits = procs[procs["process"].str.contains(pattern, na=False)]
        procs = procs.drop(hits.index)  # each event counts once, at the highest matching severity
        for (host, path), rows in hits.groupby([hits["host"].fillna("unknown"), hits["process"]], sort=False):
            first, last = _span(rows)
            entities = {"host": host, "process": path}
            if rows["user"].notna().any():
                entities["user"] = rows["user"].dropna().iloc[0]
            out.append(Finding("USER_PATH_EXECUTION", f"Process run from user-writable folder: {_image(path)}", sev,
                               f"{path} was executed {len(rows)} time(s). Malware is commonly dropped and run "
                               "from folders any user can write to.",
                               first, last, len(rows), entities,
                               "Check the file's hash, signer and origin; quarantine it if unknown.",
                               "T1204.002", list(rows.index)))
    return out


def discovery_burst(df: pd.DataFrame, cfg: DetectionConfig) -> list[Finding]:
    """Several different reconnaissance commands by one user on one host in a short time."""
    procs = _processes(df)
    procs = procs[procs["timestamp"].notna()]
    if procs.empty:
        return []
    text = procs["command_line"].fillna(procs["process"])
    kind = text.map(lambda t: next((k for k, p in DISCOVERY_COMMANDS if p.search(str(t))), None))
    recon = procs[kind.notna()].assign(recon=kind.dropna())
    window = pd.Timedelta(minutes=cfg.discovery_window_min)
    out = []
    for (host, user), rows in recon.groupby([recon["host"].fillna("unknown"), recon["user"].fillna("unknown")],
                                            sort=False):
        for pos in _bursts(rows["timestamp"], window, cfg.discovery_threshold, distinct=rows["recon"]):
            burst = rows.iloc[pos]
            first, last = _span(burst)
            kinds = list(dict.fromkeys(burst["recon"]))
            out.append(Finding("DISCOVERY_BURST", f"Reconnaissance commands by {user} on {host}", Severity.MEDIUM,
                               f"{len(kinds)} different discovery commands within {cfg.discovery_window_min} min "
                               f"(threshold {cfg.discovery_threshold}): {', '.join(kinds)}. Attackers enumerate "
                               "users, groups and the network right after gaining access.",
                               first, last, len(burst), {"user": user, "host": host},
                               "Confirm whether this was an administrator's work; if not, review the logon session "
                               "that ran these commands.", "T1087", list(burst.index)))
    return out


ALL_RULES = [single_event_findings, privileged_group_additions, suspicious_commands,
             brute_force, password_spray, external_logons,
             suspicious_parent_child, user_writable_execution, discovery_burst]
