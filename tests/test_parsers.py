from pathlib import Path

import pandas as pd
import pytest

from cybersentinel.models import EVENT_COLUMNS
from cybersentinel.parsers import detect_format, load_file, load_files
from cybersentinel.parsers.fields import classify, extract_fields

SAMPLES = Path(__file__).resolve().parent.parent / "sample_data"

MSG_4625 = ("An account failed to log on.\n\nSubject:\n\tAccount Name:\t\t-\n\nLogon Type:\t\t\t3\n\n"
            "Account For Which Logon Failed:\n\tAccount Name:\t\tadministrator\n\n"
            "Network Information:\n\tSource Network Address:\t203.0.113.50\n")


def test_extract_fields_from_windows_message():
    f = extract_fields(MSG_4625)
    assert f["user"] == "administrator"  # target account, not the "-" subject
    assert f["ip"] == "203.0.113.50"
    assert f["logon_type"] == "3"


def test_extract_skips_machine_accounts_and_reads_service_command():
    f = extract_fields("Subject:\n\tAccount Name:\tWS01$\nService File Name:  powershell.exe -enc AAAA\n")
    assert "user" not in f
    assert f["command_line"] == "powershell.exe -enc AAAA"


def test_extract_fields_from_free_text():
    f = extract_fields("2026-03-02T22:03:00 WARN Authentication failed for user svc_sql from 192.0.2.66")
    assert f == {"user": "svc_sql", "ip": "192.0.2.66"}


@pytest.mark.parametrize("eid,msg,expected", [
    (4625, "", "logon_failure"),
    (1102, "", "log_cleared"),
    (None, "Authentication failed for user bob", "logon_failure"),
    (None, "Login successful for user bob", "logon_success"),
    (None, "Account svc_sql locked after repeated failures", "account_lockout"),
    (None, "Config reload completed", None),
])
def test_classify(eid, msg, expected):
    assert classify(pd.NA if eid is None else eid, msg) == expected


def test_detect_format():
    assert detect_format("x.bin", b"ElfFile\x00rest") == "evtx"
    assert detect_format("a.CSV", b"a,b") == "csv"
    assert detect_format("a.log", b"hello") == "text"


def test_powershell_csv_sample():
    df, warnings = load_file("ps.csv", (SAMPLES / "security_powershell_export.csv").read_bytes())
    assert list(df.columns) == EVENT_COLUMNS
    assert warnings == []
    assert df["timestamp"].notna().all()
    assert df["host"].eq("WS-FINANCE01.corp.example").all()
    brute = df[(df["action"] == "logon_failure") & (df["ip"] == "203.0.113.50")]
    assert len(brute) == 14 and brute["user"].eq("administrator").all()


def test_eventviewer_csv_sample_has_unlabeled_message_column():
    df, _ = load_file("ev.csv", (SAMPLES / "security_eventviewer_export.csv").read_bytes())
    ps, _ = load_file("ps.csv", (SAMPLES / "security_powershell_export.csv").read_bytes())
    assert len(df) == len(ps)
    assert df["message"].notna().all()
    assert (df["action"] == "logon_failure").sum() == (ps["action"] == "logon_failure").sum()


def test_text_log_sample():
    df, warnings = load_file("vpn_auth.log", (SAMPLES / "vpn_auth.log").read_bytes())
    assert warnings == []
    assert df["timestamp"].notna().all()
    fails = df[df["action"] == "logon_failure"]
    assert len(fails) == 9 and set(fails["user"]) == {"svc_sql"} and set(fails["ip"]) == {"192.0.2.66"}
    assert (df["action"] == "account_lockout").sum() == 1


def test_text_timestamp_formats():
    data = b"Jan 15 10:00:00 host sshd: Failed password for root from 192.0.2.1\n" \
           b"1/15/2026 10:00:05 AM login failed for user bob\nno timestamp here\n"
    df, warnings = load_file("t.txt", data)
    assert df["timestamp"].notna().sum() == 2
    assert any("no recognisable timestamp" in w for w in warnings)


def test_generic_csv_with_aliases_and_ignored_columns():
    data = b"Date,EventCode,Computer,UserName,SrcIP,Extra\n2026-01-01 10:00:00,4625,PC1,bob,192.0.2.9,zzz\n"
    df, warnings = load_file("g.csv", data)
    row = df.iloc[0]
    assert (row["event_id"], row["host"], row["user"], row["ip"], row["action"]) == \
           (4625, "PC1", "bob", "192.0.2.9", "logon_failure")
    assert any("Ignored columns: Extra" in w for w in warnings)


@pytest.mark.parametrize("name,data", [
    ("bad.evtx", b"not really an evtx file"),
    ("empty.csv", b""),
    ("empty.log", b"\n\n"),
])
def test_bad_input_never_raises(name, data):
    df, warnings = load_file(name, data)
    assert list(df.columns) == EVENT_COLUMNS
    assert df.empty and warnings


def test_load_files_merges_and_sorts():
    df, _ = load_files([
        ("ps.csv", (SAMPLES / "security_powershell_export.csv").read_bytes()),
        ("vpn_auth.log", (SAMPLES / "vpn_auth.log").read_bytes()),
    ])
    assert df["timestamp"].is_monotonic_increasing
    assert set(df["source"].dropna()) >= {"Microsoft-Windows-Security-Auditing"}


@pytest.mark.parametrize("eid,source,expected", [
    (4625, "Microsoft-Windows-Security-Auditing", "logon_failure"),
    (4625, "Microsoft-Windows-EventSystem", None),   # same ID, unrelated provider
    (4625, None, "logon_failure"),                    # unknown provider: trust the ID
    (7045, "Service Control Manager", "service_installed"),
    (7045, "SomeApp", None),
    (104, "Microsoft-Windows-Eventlog", "log_cleared"),
])
def test_classify_is_provider_aware(eid, source, expected):
    assert classify(eid, "An account failed to log on.", source) == expected


def test_4688_parent_process_from_csv_message_and_alias():
    msg = ("A new process has been created.\n\nCreator Subject:\n\tAccount Name:\t\tbob\n\nTarget Subject:\n"
           "\tAccount Name:\t\t-\n\nProcess Information:\n\tNew Process Name:\tC:\\Windows\\System32\\cmd.exe\n"
           "\tCreator Process Name:\tC:\\Office\\WINWORD.EXE\n\tProcess Command Line:\tcmd /c whoami\n")
    f = extract_fields(msg)
    assert (f["user"], f["process"], f["parent_process"], f["command_line"]) == \
           ("bob", "C:\\Windows\\System32\\cmd.exe", "C:\\Office\\WINWORD.EXE", "cmd /c whoami")
    df, _ = load_file("g.csv", b"Date,EventID,Image,ParentImage\n2026-01-01 10:00:00,4688,a.exe,b.exe\n")
    assert (df["process"].iloc[0], df["parent_process"].iloc[0]) == ("a.exe", "b.exe")
