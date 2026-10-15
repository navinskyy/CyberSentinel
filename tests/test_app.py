"""Headless smoke tests of the Streamlit dashboard via streamlit.testing."""

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parent.parent / "app.py")


@pytest.fixture
def app():
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    return at


def test_sample_mode_renders_without_errors(app):
    assert not app.exception
    assert app.title[0].value == "Security overview"
    metrics = {m.label: m.value for m in app.metric}
    assert metrics["Findings"] == "12"
    assert metrics["🔴 Critical"] == "1"
    assert len(app.tabs) == 4
    assert any("Successful logon after brute force" in e.label for e in app.expander)


def test_threshold_change_reruns_detection(app):
    app.number_input[0].set_value(20).run()  # brute-force threshold above every burst in the sample
    assert not app.exception
    labels = " ".join(e.label for e in app.expander)
    assert "Repeated failed logons" not in labels
    assert "Password spray" in labels


def test_welcome_screen_without_data(app):
    app.toggle[0].set_value(False).run()
    assert not app.exception
    assert app.title[0].value == "CyberSentinel"


def test_events_search_filter(app):
    app.text_input[0].set_value("203.0.113.50").run()
    assert not app.exception
    assert len(app.dataframe[-1].value) == 15  # 14 failures + 1 success from the attacker
