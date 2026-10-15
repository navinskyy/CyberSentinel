import io
from pathlib import Path

import pandas as pd
import pytest

from cybersentinel.detection import analyze
from cybersentinel.models import normalize_frame
from cybersentinel.parsers import load_files
from cybersentinel.reporting import ReportMeta, events_csv, findings_csv, to_html, to_markdown

SAMPLES = Path(__file__).resolve().parent.parent / "sample_data"


@pytest.fixture(scope="module")
def result():
    df, _ = load_files([(p.name, p.read_bytes()) for p in (SAMPLES / "security_powershell_export.csv",)])
    return analyze(df)


def test_markdown_report_contents(result):
    md = to_markdown(result, ReportMeta(sources=["security.csv"], warnings=["a note"]))
    assert md.startswith("# CyberSentinel Security Report")
    assert "| Critical | 1 |" in md
    assert "Successful logon after brute force: administrator" in md
    assert "T1110" in md and "**Recommended next step:**" in md
    assert "## Processing notes" in md and "a note" in md
    # findings appear most-severe first
    assert md.index("[Critical]") < md.index("[High]") < md.index("[Medium]")


def test_html_report_is_self_contained(result):
    page = to_html(result)
    assert page.startswith("<!doctype html>")
    assert "<script" not in page and "http://" not in page and "https://" not in page
    assert page.count("class='finding'") == len(result.findings)


def test_html_escapes_attacker_controlled_values():
    evil = "<script>alert(1)</script>"
    df = normalize_frame(pd.DataFrame({
        "timestamp": pd.date_range("2026-01-01", periods=6, freq="10s", tz="UTC"),
        "action": ["logon_failure"] * 6, "user": [evil] * 6, "ip": ["192.0.2.1"] * 6, "message": [evil] * 6,
    }))
    page = to_html(analyze(df))
    assert "<script>" not in page
    assert "&lt;script&gt;" in page


def test_csv_exports_and_formula_injection():
    df = normalize_frame(pd.DataFrame({
        "timestamp": pd.date_range("2026-01-01", periods=6, freq="10s", tz="UTC"),
        "action": ["logon_failure"] * 6, "user": ["=HYPERLINK(\"x\")"] * 6, "ip": ["192.0.2.1"] * 6,
    }))
    r = analyze(df)
    findings = pd.read_csv(io.BytesIO(findings_csv(r)))
    events = pd.read_csv(io.BytesIO(events_csv(r)))
    assert len(findings) == len(r.findings) and "severity" in findings
    assert "raw" not in events and "severity" in events
    assert events["user"].iloc[0].startswith("'=")


def test_reports_on_empty_result():
    r = analyze(normalize_frame(pd.DataFrame()))
    assert "No findings" in to_markdown(r)
    assert "No findings" in to_html(r)
    assert pd.read_csv(io.BytesIO(findings_csv(r))).empty
