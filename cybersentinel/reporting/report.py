"""Security report generation: Markdown, self-contained HTML, and CSV exports.

Log content is attacker-controlled (usernames, command lines...), so every value
written into HTML goes through html.escape.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pandas as pd

from .. import __version__
from ..detection.engine import AnalysisResult
from ..models import Finding

EVIDENCE_COLUMNS = ["timestamp", "event_id", "action", "user", "ip", "host", "message"]
MAX_EVIDENCE_ROWS = 5
SEVERITY_COLORS = {"Critical": "#b3261e", "High": "#d9480f", "Medium": "#b08800", "Low": "#2b6cb0", "Info": "#5f6b7a"}
DISCLAIMER = ("Findings are produced by local, rule-based detections and indicate activity worth investigating, "
              "not confirmed compromise. Validate each finding before acting. CyberSentinel does not modify "
              "systems or perform remediation.")


@dataclass
class ReportMeta:
    title: str = "CyberSentinel Security Report"
    sources: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    generated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _fmt_ts(ts) -> str:
    return "" if ts is None or pd.isna(ts) else pd.Timestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")


def _overview(result: AnalysisResult) -> dict[str, str]:
    ev = result.events
    ts = ev["timestamp"].dropna() if len(ev) else pd.Series(dtype="datetime64[ns, UTC]")
    return {
        "Events analysed": f"{len(ev):,}",
        "Time range": f"{_fmt_ts(ts.min())} to {_fmt_ts(ts.max())}" if len(ts) else "unknown",
        "Hosts": str(ev["host"].nunique()) if len(ev) else "0",
        "Accounts seen": str(ev["user"].nunique()) if len(ev) else "0",
        "Findings": str(len(result.findings)),
    }


def _evidence(result: AnalysisResult, f: Finding) -> pd.DataFrame:
    idx = [i for i in f.evidence_index if i in result.events.index][:MAX_EVIDENCE_ROWS]
    ev = result.events.loc[idx, EVIDENCE_COLUMNS].copy()
    ev["timestamp"] = ev["timestamp"].map(_fmt_ts)
    ev["message"] = ev["message"].fillna("").str.replace(r"\s+", " ", regex=True).str[:160]
    return ev.astype(object).where(ev.notna(), "")


def _top_table(result: AnalysisResult, col: str, n: int = 10) -> pd.DataFrame:
    if result.events.empty:
        return pd.DataFrame(columns=[col, "events"])
    vc = result.events[col].dropna().astype(str).value_counts().head(n)
    return vc.rename_axis(col).reset_index(name="events")


# ---------------------------------------------------------------- Markdown

def _md_escape(v) -> str:
    return str(v).replace("|", "\\|").replace("\n", " ")


def _md_table(df: pd.DataFrame) -> str:
    if df.empty:
        return "_None._\n"
    lines = ["| " + " | ".join(map(str, df.columns)) + " |", "|" + "---|" * len(df.columns)]
    lines += ["| " + " | ".join(_md_escape(v) for v in row) + " |" for row in df.itertuples(index=False)]
    return "\n".join(lines) + "\n"


def to_markdown(result: AnalysisResult, meta: ReportMeta | None = None) -> str:
    meta = meta or ReportMeta()
    out = [f"# {meta.title}", "",
           f"Generated {_fmt_ts(meta.generated)} by CyberSentinel {__version__}.", ""]
    if meta.sources:
        out += ["**Sources:** " + ", ".join(meta.sources), ""]
    out += ["## Summary", ""]
    out += [f"- **{k}:** {v}" for k, v in _overview(result).items()]
    out += ["", "| Severity | Findings |", "|---|---|"]
    out += [f"| {k} | {v} |" for k, v in result.severity_counts().items()]
    out += ["", "## Findings", ""]
    if not result.findings:
        out += ["No findings were produced by the current rule set.", ""]
    for n, f in enumerate(result.findings, 1):
        out += [f"### {n}. [{f.severity.label}] {f.title}", "",
                f"- **Rule:** `{f.rule_id}`" + (f" (MITRE ATT&CK {f.mitre})" if f.mitre else ""),
                f"- **When:** {_fmt_ts(f.first_seen)} to {_fmt_ts(f.last_seen)}",
                f"- **Events:** {f.count}"]
        if f.entities:
            out.append("- **Entities:** " + ", ".join(f"{k}=`{_md_escape(v)}`" for k, v in f.entities.items()))
        out += ["", _md_escape(f.description), "",
                f"**Recommended next step:** {f.recommendation}", "",
                "Evidence (first events):", "", _md_table(_evidence(result, f))]
    out += ["## Activity overview", "", "### Top accounts", "", _md_table(_top_table(result, "user")),
            "### Top source IPs", "", _md_table(_top_table(result, "ip")),
            "### Event types", "", _md_table(_top_table(result, "action"))]
    notes = meta.warnings + result.errors
    if notes:
        out += ["## Processing notes", ""] + [f"- {_md_escape(w)}" for w in notes] + [""]
    out += ["---", "", f"_{DISCLAIMER}_", ""]
    return "\n".join(out)


# ---------------------------------------------------------------- HTML

def _h(v) -> str:
    return html.escape("" if v is None or (not isinstance(v, str) and pd.isna(v)) else str(v))


def _html_table(df: pd.DataFrame) -> str:
    if df.empty:
        return "<p class='muted'>None.</p>"
    head = "".join(f"<th>{_h(c)}</th>" for c in df.columns)
    body = "".join("<tr>" + "".join(f"<td>{_h(v)}</td>" for v in row) + "</tr>" for row in df.itertuples(index=False))
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _badge(label: str) -> str:
    return f"<span class='badge' style='background:{SEVERITY_COLORS.get(label, '#5f6b7a')}'>{_h(label)}</span>"


def to_html(result: AnalysisResult, meta: ReportMeta | None = None) -> str:
    meta = meta or ReportMeta()
    overview = "".join(f"<div class='kpi'><div class='k'>{_h(k)}</div><div class='v'>{_h(v)}</div></div>"
                       for k, v in _overview(result).items())
    sev = "".join(f"<div class='kpi'><div class='k'>{_badge(k)}</div><div class='v'>{v}</div></div>"
                  for k, v in result.severity_counts().items())
    cards = []
    for n, f in enumerate(result.findings, 1):
        ents = "".join(f"<li><b>{_h(k)}</b>: <code>{_h(v)}</code></li>" for k, v in f.entities.items())
        cards.append(
            f"<section class='finding' style='border-left-color:{SEVERITY_COLORS[f.severity.label]}'>"
            f"<h3>{n}. {_badge(f.severity.label)} {_h(f.title)}</h3>"
            f"<p class='muted'>Rule <code>{_h(f.rule_id)}</code>"
            + (f" · MITRE ATT&amp;CK <code>{_h(f.mitre)}</code>" if f.mitre else "")
            + f" · {_h(_fmt_ts(f.first_seen))} → {_h(_fmt_ts(f.last_seen))} · {f.count} event(s)</p>"
            f"<p>{_h(f.description)}</p>" + (f"<ul>{ents}</ul>" if ents else "")
            + f"<p><b>Recommended next step:</b> {_h(f.recommendation)}</p>"
            f"<details><summary>Evidence</summary>{_html_table(_evidence(result, f))}</details></section>")
    notes = meta.warnings + result.errors
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_h(meta.title)}</title>
<style>
body{{font:14px/1.5 system-ui,Segoe UI,sans-serif;color:#1f2328;background:#fff;max-width:1100px;margin:0 auto;padding:24px}}
h1{{margin:0 0 4px}} h2{{margin-top:32px;border-bottom:1px solid #d0d7de;padding-bottom:4px}} h3{{margin:0 0 6px;font-size:16px}}
.muted{{color:#59636e}} .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}}
.kpi{{border:1px solid #d0d7de;border-radius:8px;padding:10px}} .kpi .k{{font-size:12px;color:#59636e}} .kpi .v{{font-size:20px;font-weight:600}}
.badge{{color:#fff;border-radius:4px;padding:1px 7px;font-size:12px;font-weight:600}}
.finding{{border:1px solid #d0d7de;border-left:5px solid;border-radius:6px;padding:12px 16px;margin:12px 0;break-inside:avoid}}
table{{border-collapse:collapse;width:100%;font-size:12px;margin:8px 0}} th,td{{border:1px solid #d0d7de;padding:4px 6px;text-align:left;vertical-align:top;word-break:break-word}}
th{{background:#f6f8fa}} code{{background:#f6f8fa;padding:0 3px;border-radius:3px}} .cols{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px}}
@media print{{details{{display:block}} details>summary{{display:none}}}}
</style></head><body>
<h1>{_h(meta.title)}</h1>
<p class="muted">Generated {_h(_fmt_ts(meta.generated))} by CyberSentinel {_h(__version__)}{
    ' · Sources: ' + _h(', '.join(meta.sources)) if meta.sources else ''}</p>
<h2>Summary</h2><div class="grid">{overview}</div><div class="grid" style="margin-top:10px">{sev}</div>
<h2>Findings</h2>{''.join(cards) or "<p>No findings were produced by the current rule set.</p>"}
<h2>Activity overview</h2><div class="cols">
<div><h3>Top accounts</h3>{_html_table(_top_table(result, 'user'))}</div>
<div><h3>Top source IPs</h3>{_html_table(_top_table(result, 'ip'))}</div>
<div><h3>Event types</h3>{_html_table(_top_table(result, 'action'))}</div></div>
{('<h2>Processing notes</h2><ul>' + ''.join(f'<li>{_h(w)}</li>' for w in notes) + '</ul>') if notes else ''}
<hr><p class="muted"><i>{_h(DISCLAIMER)}</i></p>
</body></html>"""


# ---------------------------------------------------------------- CSV

def findings_csv(result: AnalysisResult) -> bytes:
    df = result.findings_frame()
    if df.empty:
        df = pd.DataFrame(columns=["rule_id", "title", "severity", "description", "first_seen", "last_seen",
                                   "count", "entities", "mitre", "recommendation"])
    return _safe_csv(df)


def events_csv(result: AnalysisResult) -> bytes:
    return _safe_csv(result.events.drop(columns=["raw"], errors="ignore"))


def _safe_csv(df: pd.DataFrame) -> bytes:
    """Neutralise spreadsheet formula injection: log text starting with = + - @ would
    otherwise be evaluated when the CSV is opened in Excel."""
    df = df.copy()
    for col in df.columns:
        if df[col].dtype == object or str(df[col].dtype) == "string":
            df[col] = df[col].map(lambda v: "'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@") else v)
    return df.to_csv(index=False).encode("utf-8-sig")
