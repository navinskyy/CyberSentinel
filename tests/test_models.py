import pandas as pd

from cybersentinel.models import EVENT_COLUMNS, Severity, normalize_frame, empty_events


def test_normalize_fills_missing_columns_and_types():
    df = normalize_frame(pd.DataFrame({
        "timestamp": ["2026-01-01 10:00:05", "2026-01-01 10:00:00"],
        "event_id": ["4625", "x"],
        "user": ["alice", "-"],
    }))
    assert list(df.columns) == EVENT_COLUMNS
    assert isinstance(df["timestamp"].dtype, pd.DatetimeTZDtype) and str(df["timestamp"].dt.tz) == "UTC"
    # sorted by time
    assert df["timestamp"].is_monotonic_increasing
    assert df["event_id"].tolist()[1] == 4625
    assert pd.isna(df["event_id"].iloc[0])
    assert pd.isna(df["user"].iloc[0])  # "-" placeholder becomes NA


def test_empty_events_schema():
    assert list(empty_events().columns) == EVENT_COLUMNS
    assert len(empty_events()) == 0


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW
    assert Severity.HIGH.label == "High"
