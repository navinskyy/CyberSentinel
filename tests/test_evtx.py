import os
from pathlib import Path

import pytest

from cybersentinel.parsers import load_file
from cybersentinel.parsers.evtx_parser import record_to_row

NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'


def _xml(eid, data, level="0"):
    fields = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (f'<Event {NS}><System><Provider Name="Microsoft-Windows-Security-Auditing"/>'
            f"<EventID>{eid}</EventID><Level>{level}</Level>"
            f'<TimeCreated SystemTime="2026-03-02T09:15:00.123456Z"/>'
            f"<Channel>Security</Channel><Computer>WS01.corp.example</Computer></System>"
            f"<EventData>{fields}</EventData></Event>")


def test_failed_logon_record():
    row = record_to_row(_xml(4625, {"SubjectUserName": "-", "TargetUserName": "administrator",
                                    "LogonType": "3", "IpAddress": "::ffff:203.0.113.50"}))
    assert row["event_id"] == 4625
    assert row["user"] == "administrator"
    assert row["ip"] == "203.0.113.50"
    assert row["logon_type"] == "3"
    assert row["host"] == "WS01.corp.example"
    assert row["source"] == "Microsoft-Windows-Security-Auditing"
    assert row["message"].startswith("An account failed to log on.")


def test_group_member_added_uses_member_not_group():
    row = record_to_row(_xml(4732, {"MemberName": "-", "MemberSid": "S-1-5-21-1-2-3-1105",
                                    "TargetUserName": "Administrators", "SubjectUserName": "admin"}))
    assert row["user"] == "S-1-5-21-1-2-3-1105"
    assert "Group Name: Administrators." in row["message"]


def test_service_install_command_line():
    row = record_to_row(_xml(7045, {"ServiceName": "Evil", "ImagePath": "powershell -enc AAAA"}))
    assert row["process"] == "Evil"
    assert row["command_line"] == "powershell -enc AAAA"


def test_machine_account_and_localhost_ignored():
    row = record_to_row(_xml(4624, {"SubjectUserName": "WS01$", "TargetUserName": "WS01$", "IpAddress": "127.0.0.1"}))
    assert row["user"] is None and row["ip"] is None


def test_truncated_evtx_does_not_crash():
    df, warnings = load_file("cut.evtx", b"ElfFile\x00" + b"\x00" * 100)
    assert df.empty and warnings


# Optional integration test against a real exported log:
#   wevtutil epl Application <path>.evtx   then   set CYBERSENTINEL_EVTX=<path>.evtx
REAL = os.environ.get("CYBERSENTINEL_EVTX")


@pytest.mark.skipif(not REAL or not Path(REAL).exists(), reason="set CYBERSENTINEL_EVTX to a real .evtx file")
def test_real_evtx_file():
    df, warnings = load_file(Path(REAL).name, Path(REAL).read_bytes())
    assert not df.empty, warnings
    assert df["timestamp"].notna().all()
    assert df["event_id"].notna().all()


def test_colliding_event_id_from_other_provider_is_not_a_logon():
    xml = _xml(4625, {"param1": "86400"}).replace("Microsoft-Windows-Security-Auditing", "Microsoft-Windows-EventSystem")
    row = record_to_row(xml)
    assert not row["message"].startswith("An account failed")


def test_process_creation_record():
    row = record_to_row(_xml(4688, {"SubjectUserName": "bob", "TargetUserName": "-",
                                    "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                                    "ParentProcessName": "C:\\Office\\WINWORD.EXE", "CommandLine": "cmd /c whoami"}))
    assert (row["user"], row["process"], row["parent_process"], row["command_line"]) == \
           ("bob", "C:\\Windows\\System32\\cmd.exe", "C:\\Office\\WINWORD.EXE", "cmd /c whoami")
