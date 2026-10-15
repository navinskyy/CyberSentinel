"""CyberSentinel Streamlit dashboard. UI only: parsing, detection and reporting
live in the cybersentinel package. Nothing here executes commands or changes the system.

Run:  .venv\\Scripts\\streamlit run app.py
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from cybersentinel import __version__
from cybersentinel.detection import AnalysisResult, DetectionConfig, analyze
from cybersentinel.models import Severity
from cybersentinel.parsers import SUPPORTED_EXTENSIONS, load_files
from cybersentinel.reporting import ReportMeta, events_csv, findings_csv, to_html, to_markdown

SAMPLE_DIR = Path(__file__).parent / "sample_data"
SAMPLE_FILES = ["security_powershell_export.csv", "vpn_auth.log"]
BADGE_COLORS = {"Critical": "red", "High": "orange", "Medium": "yellow", "Low": "blue", "Info": "gray"}
# Validated two-series palette (light and dark): routine vs flagged events.
ROUTINE_COLOR, FLAGGED_COLOR = "#3f7fd6", "#d03b3b"
FLAGGED = {"Critical", "High", "Medium"}

st.set_page_config(page_title="CyberSentinel", page_icon="🛡️", layout="wide")


# ---------------------------------------------------------------- cached pipeline

@st.cache_data(show_spinner="Parsing logs…", max_entries=8)
def parse(files: tuple[tuple[str, bytes], ...]):
    return load_files(list(files))


@st.cache_data(show_spinner="Running detections…", max_entries=16)
def run_analysis(events: pd.DataFrame, config: dict) -> AnalysisResult:
    return analyze(events, DetectionConfig(**config))


# ---------------------------------------------------------------- sidebar

def sidebar() -> tuple[list[tuple[str, bytes]], dict]:
    st.sidebar.title("🛡️ CyberSentinel")
    st.sidebar.caption(f"v{__version__} · local, rule-based analysis")
    uploads = st.sidebar.file_uploader("Upload logs", type=list(SUPPORTED_EXTENSIONS), accept_multiple_files=True,
                                       help="Windows .evtx, CSV exports, or plain-text logs. Files are parsed in "
                                            "memory on this machine and never executed.")
    use_sample = st.sidebar.toggle("Use sample data", value=not uploads,
                                   help="Synthetic logs with a planted attack scenario.")
    files = [(f.name, f.getvalue()) for f in uploads or []]
    if use_sample:
        files += [(name, (SAMPLE_DIR / name).read_bytes()) for name in SAMPLE_FILES]

    with st.sidebar.expander("Detection thresholds"):
        d = DetectionConfig()
        cfg = {
            "brute_force_threshold": st.number_input("Failed logons per account", 2, 1000, d.brute_force_threshold),
            "brute_force_window_min": st.number_input("…within minutes", 1, 1440, d.brute_force_window_min),
            "spray_user_threshold": st.number_input("Accounts per source IP (spray)", 2, 1000, d.spray_user_threshold),
            "spray_window_min": st.number_input("…within minutes ", 1, 1440, d.spray_window_min),
            "success_after_fail_min": st.number_input("Success after burst, minutes", 1, 1440, d.success_after_fail_min),
            "flag_external_logons": st.checkbox("Flag logons from public IPs", d.flag_external_logons),
            "discovery_threshold": st.number_input("Distinct recon commands (4688)", 2, 50, d.discovery_threshold),
            "discovery_window_min": st.number_input("…within minutes  ", 1, 1440, d.discovery_window_min),
        }
    st.sidebar.caption("CyberSentinel only reads logs. It never runs remediation or changes system settings.")
    return files, cfg


def welcome() -> None:
    st.title("CyberSentinel")
    st.write("Upload Windows Event Logs, CSV exports, or text logs in the sidebar, "
             "or switch on **Use sample data** to explore a demo scenario.")
    st.subheader("How to export logs from Windows")
    st.markdown(
        "Run these yourself; CyberSentinel never runs commands on your system.\n\n"
        "- **EVTX** (elevated prompt for Security): `wevtutil epl Security C:\\temp\\security.evtx`\n"
        "- **Event Viewer**: right-click a log → *Save All Events As…* → `.evtx` or `.csv`\n"
        "- **PowerShell CSV**: `Get-WinEvent -LogName Security -MaxEvents 50000 | "
        "Select TimeCreated,Id,ProviderName,LevelDisplayName,MachineName,Message | "
        "Export-Csv C:\\temp\\security.csv -NoTypeInformation`")


# ---------------------------------------------------------------- views

def kpis(result: AnalysisResult) -> None:
    ev, counts = result.events, result.severity_counts()
    ts = ev["timestamp"].dropna()
    cols = st.columns(6)
    cols[0].metric("Events", f"{len(ev):,}")
    cols[1].metric("Findings", len(result.findings))
    cols[2].metric("🔴 Critical", counts["Critical"])
    cols[3].metric("🟠 High", counts["High"])
    cols[4].metric("🟡 Medium", counts["Medium"])
    span = ts.max() - ts.min() if len(ts) else None
    cols[5].metric("Time span", f"{span.days}d {span.seconds // 3600}h" if span is not None else "—",
                   help=f"{ts.min():%Y-%m-%d %H:%M} → {ts.max():%Y-%m-%d %H:%M} UTC" if len(ts) else None)


def severity_badge(label: str) -> None:
    st.badge(label, color=BADGE_COLORS[label])


def findings_view(result: AnalysisResult) -> None:
    if not result.findings:
        st.success("No findings from the current rule set.")
        return
    levels = [s.label for s in sorted(Severity, reverse=True)]
    chosen = st.pills("Severity", levels, selection_mode="multi", default=["Critical", "High", "Medium", "Low"])
    shown = [f for f in result.findings if f.severity.label in chosen]
    st.caption(f"Showing {len(shown)} of {len(result.findings)} findings, most severe first.")
    for f in shown:
        when = f"{f.first_seen:%Y-%m-%d %H:%M:%S}" if f.first_seen is not None else "time unknown"
        with st.expander(f"**[{f.severity.label}]** {f.title} · {when} · {f.count} event(s)",
                         expanded=f.severity >= Severity.CRITICAL):
            severity_badge(f.severity.label)
            st.write(f.description)
            left, right = st.columns([1, 1])
            with left:
                st.markdown("**Entities**")
                for k, v in f.entities.items():
                    st.markdown(f"- {k}: `{v}`")
            with right:
                st.markdown(f"**Rule** `{f.rule_id}`" + (f" · MITRE ATT&CK `{f.mitre}`" if f.mitre else ""))
                st.markdown(f"**Window** {when} → "
                            f"{f.last_seen:%Y-%m-%d %H:%M:%S} UTC" if f.last_seen is not None else "")
            st.info(f"**Recommended next step:** {f.recommendation}")
            idx = [i for i in f.evidence_index if i in result.events.index]
            st.dataframe(result.events.loc[idx, ["timestamp", "event_id", "action", "user", "ip", "host", "message"]],
                         hide_index=True, width="stretch",
                         column_config={"timestamp": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss")})


def _bucket(ts: pd.Series) -> tuple[str, str]:
    span = ts.max() - ts.min()
    for freq, label, limit in [("1min", "minute", "3h"), ("5min", "5 minutes", "12h"), ("15min", "15 minutes", "2D"),
                               ("1h", "hour", "10D"), ("6h", "6 hours", "45D")]:
        if span <= pd.Timedelta(limit):
            return freq, label
    return "1D", "day"


def timeline_view(result: AnalysisResult) -> None:
    ev = result.events.dropna(subset=["timestamp"])
    if ev.empty:
        st.info("No timestamps available for a timeline.")
        return
    freq, label = _bucket(ev["timestamp"])
    ev = ev.assign(kind=ev["severity"].map(lambda s: "Flagged (Medium+)" if s in FLAGGED else "Routine"),
                   bucket=ev["timestamp"].dt.floor(freq).dt.tz_localize(None))
    counts = ev.groupby(["bucket", "kind"]).size().reset_index(name="events")
    st.markdown(f"**Events per {label}** (UTC)")
    chart = alt.Chart(counts).mark_bar(cornerRadiusTopLeft=2, cornerRadiusTopRight=2, stroke=None).encode(
        x=alt.X("bucket:T", title=None),
        y=alt.Y("events:Q", title="Events", stack="zero"),
        color=alt.Color("kind:N", title=None, sort=["Routine", "Flagged (Medium+)"],
                        scale=alt.Scale(domain=["Routine", "Flagged (Medium+)"], range=[ROUTINE_COLOR, FLAGGED_COLOR]),
                        legend=alt.Legend(orient="top")),
        order=alt.Order("kind:N", sort="descending"),
        tooltip=[alt.Tooltip("bucket:T", title="From", format="%Y-%m-%d %H:%M"),
                 alt.Tooltip("kind:N", title="Type"), alt.Tooltip("events:Q", title="Events")],
    ).properties(height=280).configure_axis(grid=False).configure_view(stroke=None)
    st.altair_chart(chart, width="stretch")

    fails = result.events[result.events["action"] == "logon_failure"]
    left, right = st.columns(2)
    for col, field, title in [(left, "ip", "Top failed-logon sources"), (right, "user", "Most-targeted accounts")]:
        top = fails[field].dropna().value_counts().head(10).rename_axis(field).reset_index(name="failures")
        with col:
            st.markdown(f"**{title}**")
            if top.empty:
                st.caption("No failed logons with this field.")
                continue
            bars = alt.Chart(top).mark_bar(color=ROUTINE_COLOR, cornerRadiusTopRight=4, cornerRadiusBottomRight=4) \
                .encode(x=alt.X("failures:Q", title="Failed logons"), y=alt.Y(f"{field}:N", sort="-x", title=None),
                        tooltip=[alt.Tooltip(f"{field}:N"), alt.Tooltip("failures:Q", title="Failed logons")])
            labels = bars.mark_text(align="left", dx=4).encode(text="failures:Q")
            st.altair_chart((bars + labels).properties(height=28 * len(top) + 20)
                            .configure_axis(grid=False).configure_view(stroke=None), width="stretch")


def events_view(result: AnalysisResult) -> None:
    ev = result.events
    c1, c2, c3 = st.columns([1, 1, 2])
    sev = c1.multiselect("Severity", [s.label for s in sorted(Severity, reverse=True)])
    actions = c2.multiselect("Action", sorted(ev["action"].dropna().unique()))
    query = c3.text_input("Search user, IP, host or message", placeholder="e.g. administrator or 203.0.113.50")
    view = ev
    if sev:
        view = view[view["severity"].isin(sev)]
    if actions:
        view = view[view["action"].isin(actions)]
    if query:
        hay = view[["user", "ip", "host", "message"]].fillna("").astype(str).agg(" ".join, axis=1)
        view = view[hay.str.contains(query, case=False, regex=False)]
    st.caption(f"{len(view):,} of {len(ev):,} events · select a row to see the original record")
    picked = st.dataframe(
        view[["timestamp", "severity", "event_id", "action", "user", "ip", "host", "source", "message"]],
        hide_index=True, width="stretch", height=420, on_select="rerun", selection_mode="single-row",
        column_config={"timestamp": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss"),
                       "message": st.column_config.TextColumn(width="large")})
    rows = picked.selection.rows if picked else []
    if rows:
        st.code(str(view.iloc[rows[0]]["raw"]), language="xml" if str(view.iloc[rows[0]]["raw"]).startswith("<")
                else None, wrap_lines=True)


def report_view(result: AnalysisResult, sources: list[str], warnings: list[str]) -> None:
    meta = ReportMeta(sources=sources, warnings=warnings)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    c = st.columns(4)
    c[0].download_button("HTML report", to_html(result, meta), f"cybersentinel-report-{stamp}.html", "text/html",
                         width="stretch", type="primary")
    c[1].download_button("Markdown report", to_markdown(result, meta), f"cybersentinel-report-{stamp}.md",
                         "text/markdown", width="stretch")
    c[2].download_button("Findings CSV", findings_csv(result), f"cybersentinel-findings-{stamp}.csv", "text/csv",
                         width="stretch")
    c[3].download_button("Events CSV", events_csv(result), f"cybersentinel-events-{stamp}.csv", "text/csv",
                         width="stretch")
    with st.container(border=True):
        st.markdown(to_markdown(result, meta))


# ---------------------------------------------------------------- main

def main() -> None:
    files, cfg = sidebar()
    if not files:
        welcome()
        return
    events, warnings = parse(tuple(files))
    if events.empty:
        st.error("No events could be read from the selected files.")
        for w in warnings:
            st.warning(w)
        return
    result = run_analysis(events, cfg)

    st.title("Security overview")
    st.caption("Sources: " + ", ".join(name for name, _ in files) + " · all times UTC")
    if warnings or result.errors:
        with st.expander(f"⚠️ {len(warnings) + len(result.errors)} processing note(s)"):
            for w in warnings + result.errors:
                st.write(f"- {w}")
    kpis(result)
    tabs = st.tabs([f"Findings ({len(result.findings)})", "Timeline", "Events", "Report"])
    with tabs[0]:
        findings_view(result)
    with tabs[1]:
        timeline_view(result)
    with tabs[2]:
        events_view(result)
    with tabs[3]:
        report_view(result, [name for name, _ in files], warnings)


if __name__ == "__main__":
    main()
