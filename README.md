# CyberSentinel

Local, rule-based analysis of Windows Event Logs, CSV exports and text logs, with a Streamlit dashboard and
exportable security reports.

- **Offline and local.** No API keys, no AI services, no network calls. The dashboard binds to `localhost`.
- **Read-only.** It parses uploaded files in memory. It never executes file content, runs remediation
  commands, or changes system settings. Recommendations are text for a human analyst.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\streamlit run app.py
```

> Use the `evtx` package (pyevtx-rs), **not** `python-evtx`. On Windows their folders (`evtx` / `Evtx`)
> collide and the two cannot be installed in the same environment.

## Getting logs

| Format | How to export (run it yourself) |
|---|---|
| `.evtx` | `wevtutil epl Security C:\temp\security.evtx` (elevated prompt) or Event Viewer → *Save All Events As* |
| CSV | Event Viewer → *Save All Events As… CSV*, or `Get-WinEvent -LogName Security \| Select TimeCreated,Id,ProviderName,LevelDisplayName,MachineName,Message \| Export-Csv security.csv -NoTypeInformation` |
| Text | Any line-based log (`.log`, `.txt`); timestamps, IPs, users and Event IDs are found by pattern |

Timestamps without a timezone are treated as UTC.

## Architecture

```
upload ─► parsers ─► normalized events ─► detection engine ─► findings ─► dashboard / reports
          evtx | csv | text   (+ "action" column)    rules.py               report.py
```

| Module | Role |
|---|---|
| `cybersentinel/models.py` | Event schema (`EVENT_COLUMNS`), `Finding`, `Severity` |
| `cybersentinel/parsers/` | `load_file()` picks a parser by magic bytes and extension. `fields.py` extracts users, IPs and logon types from message text and maps Event IDs to normalized actions, checking the provider |
| `cybersentinel/detection/rules.py` | `DetectionConfig` thresholds, the declarative single-event rules, and the correlation rules |
| `cybersentinel/detection/engine.py` | Runs all rules, isolates rule failures, assigns per-event severity |
| `cybersentinel/reporting/report.py` | Markdown, HTML and CSV exports. HTML escapes all values, and CSV neutralizes formula injection |
| `app.py` | Streamlit UI only |

## Detections

| Rule | Trigger | Severity |
|---|---|---|
| `BRUTE_FORCE` | ≥ 5 failed logons (4625/4771 or text) for one account in 10 min | High |
| `BRUTE_FORCE_SUCCESS` | A successful logon from the same source within 15 min of a brute-force burst | Critical |
| `PASSWORD_SPRAY` | One IP fails against ≥ 5 distinct accounts in 30 min | High |
| `EXTERNAL_LOGON` | Successful logon from a public IP (RDP = High) | Medium/High |
| `GROUP_MEMBER_ADDED` | 4728/4732/4756. Privileged groups (Administrators, Domain Admins, …) = High | Low/High |
| `SUSPICIOUS_COMMAND` | Encoded/hidden PowerShell, download cradles, credential dumping, shadow-copy deletion, … | Medium–Critical |
| `LOG_CLEARED`, `AUDIT_POLICY_CHANGED` | 1102 / 104, 4719 | High |
| `SERVICE_INSTALLED`, `SCHEDULED_TASK`, `USER_CREATED`, `ACCOUNT_LOCKOUT` | 7045/4697, 4698, 4720, 4740 | Medium |

You can change the thresholds in the dashboard sidebar. Event IDs count only when they come from the expected
provider, because IDs are unique only per provider (`Microsoft-Windows-EventSystem` also logs 4625, for example).

## Tests

```powershell
.\.venv\Scripts\python -m pytest -q
# optional: also test against a real exported log
$env:CYBERSENTINEL_EVTX = "C:\temp\application.evtx"; .\.venv\Scripts\python -m pytest -q
```

`sample_data/` holds synthetic logs (fictional hosts, RFC 5737 IPs) with a planted attack scenario.
`python scripts/generate_samples.py` regenerates them.

## Limitations

- Rule-based: it detects known patterns only, and thresholds need tuning per environment.
- EVTX files have no rendered message text, so messages are built from the event's structured fields.
- One file's events are analyzed together. There is no persistence between sessions.
