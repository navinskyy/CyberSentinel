"""Generate synthetic sample logs in sample_data/ for demos and tests.

All hosts, users and IPs are fictional (IPs from RFC 5737 documentation ranges).
Scenario on WS-FINANCE01, 2026-03-02 (UTC):
  - normal workday logons
  - 09:15 brute force on 'administrator' from 203.0.113.50, ending in a success
  - 11:00 password spray from 198.51.100.7 across 8 accounts
  - 13:30 new user 'svc_backup2' created and added to Administrators
  - 13:42 service installed running encoded PowerShell
  - 13:50 Security log cleared
"""

from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "sample_data"
HOST = "WS-FINANCE01.corp.example"
DAY = datetime(2026, 3, 2, tzinfo=timezone.utc)
rng = random.Random(42)

LOGON_TYPES = {"2": "Interactive", "3": "Network", "10": "RemoteInteractive"}


def msg_4624(user: str, ip: str, ltype: str) -> str:
    return ("An account was successfully logged on.\n\nSubject:\n\tAccount Name:\t\tWS-FINANCE01$\n"
            f"\nLogon Information:\n\tLogon Type:\t\t{ltype}\n\nNew Logon:\n\tAccount Name:\t\t{user}\n"
            f"\tAccount Domain:\t\tCORP\n\nNetwork Information:\n\tSource Network Address:\t{ip}\n")


def msg_4625(user: str, ip: str, ltype: str) -> str:
    return ("An account failed to log on.\n\nSubject:\n\tAccount Name:\t\t-\n"
            f"\nLogon Type:\t\t\t{ltype}\n\nAccount For Which Logon Failed:\n\tAccount Name:\t\t{user}\n"
            "\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n"
            f"\nNetwork Information:\n\tSource Network Address:\t{ip}\n")


def build_events() -> list[dict]:
    ev: list[dict] = []

    def add(ts, eid, msg, level="Information", provider="Microsoft-Windows-Security-Auditing"):
        ev.append({"ts": ts, "id": eid, "provider": provider, "level": level, "msg": msg})

    staff = ["jdoe", "asmith", "mlee", "kpatel", "rgarcia"]
    for i in range(60):  # normal activity
        t = DAY + timedelta(hours=8, minutes=rng.randint(0, 600), seconds=rng.randint(0, 59))
        user = rng.choice(staff)
        add(t, 4624, msg_4624(user, f"10.0.0.{rng.randint(20, 80)}", rng.choice(["2", "3"])))
        if rng.random() < 0.08:  # occasional typo
            add(t - timedelta(seconds=5), 4625, msg_4625(user, "10.0.0.31", "2"), level="Information")

    t = DAY + timedelta(hours=9, minutes=15)  # brute force
    for i in range(14):
        add(t + timedelta(seconds=8 * i), 4625, msg_4625("administrator", "203.0.113.50", "3"))
    add(t + timedelta(seconds=8 * 14 + 3), 4624, msg_4624("administrator", "203.0.113.50", "3"))
    add(t + timedelta(seconds=8 * 14 + 4), 4672,
        "Special privileges assigned to new logon.\n\nSubject:\n\tAccount Name:\t\tadministrator\n")

    t = DAY + timedelta(hours=11)  # password spray
    for i, user in enumerate(["jdoe", "asmith", "mlee", "kpatel", "rgarcia", "tnguyen", "bwilson", "hr_admin"]):
        add(t + timedelta(seconds=20 * i), 4625, msg_4625(user, "198.51.100.7", "3"))
    add(t + timedelta(minutes=4), 4740,
        "A user account was locked out.\n\nSubject:\n\tAccount Name:\t\tDC01$\n\n"
        "Account That Was Locked Out:\n\tAccount Name:\t\thr_admin\n")

    t = DAY + timedelta(hours=13, minutes=30)  # persistence
    add(t, 4720, "A user account was created.\n\nSubject:\n\tAccount Name:\t\tadministrator\n\n"
                 "New Account:\n\tAccount Name:\t\tsvc_backup2\n")
    add(t + timedelta(minutes=1), 4732,
        "A member was added to a security-enabled local group.\n\nSubject:\n\tAccount Name:\t\tadministrator\n\n"
        "Member:\n\tAccount Name:\t\tsvc_backup2\n\nGroup:\n\tGroup Name:\t\tAdministrators\n")
    add(t + timedelta(minutes=12), 7045,
        "A service was installed in the system.\n\nService Name:  WinUpdateHelper\n"
        "Service File Name:  powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\n"
        "Service Type:  user mode service\nService Start Type:  auto start\nService Account:  LocalSystem",
        provider="Service Control Manager")
    add(t + timedelta(minutes=20), 1102,
        "The audit log was cleared.\nSubject:\n\tAccount Name:\tadministrator\n",
        provider="Microsoft-Windows-Eventlog")
    return sorted(ev, key=lambda e: e["ts"])


def write_powershell_csv(events: list[dict], path: Path) -> None:
    """Shape of: Get-WinEvent ... | Select TimeCreated,Id,ProviderName,LevelDisplayName,MachineName,Message | Export-Csv"""
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["TimeCreated", "Id", "ProviderName", "LevelDisplayName", "MachineName", "Message"])
        for e in events:
            w.writerow([e["ts"].strftime("%Y-%m-%dT%H:%M:%SZ"), e["id"], e["provider"], e["level"], HOST, e["msg"]])


def write_eventviewer_csv(events: list[dict], path: Path) -> None:
    """Shape of Event Viewer 'Save All Events As... CSV': 5 headers, message in an unlabeled 6th field."""
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Keywords", "Date and Time", "Source", "Event ID", "Task Category"])
        for e in events:
            kw = "Audit Failure" if e["id"] == 4625 else "Audit Success"
            w.writerow([kw, e["ts"].strftime("%Y-%m-%d %H:%M:%S"), e["provider"], e["id"], "Logon", e["msg"]])


def write_text_log(path: Path) -> None:
    """A generic application / VPN gateway auth log."""
    lines = []
    t = DAY + timedelta(hours=7)
    for i in range(20):
        lines.append(f"{(t + timedelta(minutes=17 * i)).isoformat()} INFO vpn-gw01 "
                     f"Login successful for user {rng.choice(['jdoe', 'mlee', 'asmith'])} from 10.0.0.{40 + i}")
    t = DAY + timedelta(hours=22, minutes=3)
    for i in range(9):
        lines.append(f"{(t + timedelta(seconds=11 * i)).isoformat()} WARN vpn-gw01 "
                     f"Authentication failed for user svc_sql from 192.0.2.66 (bad password)")
    lines.append(f"{(t + timedelta(minutes=3)).isoformat()} WARN vpn-gw01 Account svc_sql locked after repeated failures")
    lines.append(f"{(t + timedelta(minutes=5)).isoformat()} INFO vpn-gw01 Config reload completed")
    lines.sort()
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    OUT.mkdir(exist_ok=True)
    events = build_events()
    write_powershell_csv(events, OUT / "security_powershell_export.csv")
    write_eventviewer_csv(events, OUT / "security_eventviewer_export.csv")
    write_text_log(OUT / "vpn_auth.log")
    print(f"Wrote {len(events)} Windows events and a text log to {OUT}")


if __name__ == "__main__":
    main()
