"""Stage C tests: lab containment mode.

Covers:
  - trigger_daemon dual gate: live only when BRDS_LIVE_CONTAINMENT=1 AND valid arm token
  - trigger_daemon passes -Armed to PS1 only when armed; -DryRunOverride otherwise
  - trigger_daemon writes containment audit log entry per action
  - trigger_daemon skips pre-existing alerts on startup
  - POST /api/containment/status updates Incident.status in DB
  - POST /api/containment/status rejects invalid status values
  - POST /api/containment/status returns 404 for unknown incident
  - PS1 DryRunOverride path (no actual network/process changes)
"""

from __future__ import annotations

import json
import os
import joblib
import numpy as np
import pandas as pd
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from scripts.train_baseline import train


# ── Helpers ───────────────────────────────────────────────────────────────────

FEATURE_NAMES = ["event_count", "file_activity_count", "registry_activity_count"]


def _build_baseline(tmp_path: Path) -> Path:
    rows = []
    for label, prefix, offset in ((0, "benign", 0), (1, "attack", 10)):
        for si in range(3):
            for ri in range(4):
                rows.append({
                    "source": f"{prefix}-{si}", "label": label,
                    "computer": "host-a", "process_key": f"p-{ri}",
                    "window_start": f"2026-01-01T00:00:{ri:02d}Z",
                    "event_count": offset + ri,
                    "file_activity_count": offset + ri,
                    "registry_activity_count": ri,
                })
    artifacts, _ = train(pd.DataFrame(rows))
    path = tmp_path / "baseline_models.joblib"
    joblib.dump(artifacts, path)
    return path


def _make_signed_alert(tmp_path: Path, window_start: str = "2026-01-01T00:00:00Z") -> Path:
    """Write a single HMAC-signed alert file and return its path."""
    os.environ["BRDS_ALLOW_INSECURE_DEV_HMAC"] = "1"
    from containment.alert_integrity import sign_alerts
    alert = {
        "computer": "host-a",
        "process_key": "wannacry.exe:1234",
        "window_start": window_start,
        "timestamp": window_start,
        "risk_score": 0.97,
        "technique_id": "T1486",
    }
    path = tmp_path / "alerts.json"
    path.write_text(sign_alerts([alert]), encoding="utf-8")
    return path


def _make_arm_token(path: Path) -> None:
    os.environ["BRDS_ALLOW_INSECURE_DEV_HMAC"] = "1"
    from containment.alert_integrity import create_arm_token
    path.write_text(create_arm_token(), encoding="utf-8")


@pytest.fixture(autouse=True)
def _insecure_hmac(monkeypatch):
    monkeypatch.setenv("BRDS_ALLOW_INSECURE_DEV_HMAC", "1")


# ── Dual-gate tests ───────────────────────────────────────────────────────────

def test_c1_no_live_containment_env_means_dry_run(tmp_path, monkeypatch):
    """Without BRDS_LIVE_CONTAINMENT=1, dual gate must return False."""
    monkeypatch.setenv("BRDS_LAB_ENVIRONMENT_APPROVED", "1")
    monkeypatch.delenv("BRDS_LIVE_CONTAINMENT", raising=False)
    arm = tmp_path / ".arm_token"
    _make_arm_token(arm)

    from containment.trigger_daemon import _is_live_containment_allowed
    assert _is_live_containment_allowed(arm) is False


def test_c2_no_arm_token_means_dry_run(tmp_path, monkeypatch):
    """Without a valid arm token, dual gate must return False even with env set."""
    monkeypatch.setenv("BRDS_LAB_ENVIRONMENT_APPROVED", "1")
    monkeypatch.setenv("BRDS_LIVE_CONTAINMENT", "1")
    missing_token = tmp_path / ".arm_token"  # does not exist

    from containment.trigger_daemon import _is_live_containment_allowed
    assert _is_live_containment_allowed(missing_token) is False


def test_c2b_no_lab_environment_means_dry_run(tmp_path, monkeypatch):
    """Without BRDS_LAB_ENVIRONMENT_APPROVED=1, dual gate must return False."""
    monkeypatch.delenv("BRDS_LAB_ENVIRONMENT_APPROVED", raising=False)
    monkeypatch.setenv("BRDS_LIVE_CONTAINMENT", "1")
    arm = tmp_path / ".arm_token"
    _make_arm_token(arm)

    from containment.trigger_daemon import _is_live_containment_allowed
    assert _is_live_containment_allowed(arm) is False


def test_c3_both_conditions_met_means_armed(tmp_path, monkeypatch):
    """When ALL conditions met (LAB + LIVE + TOKEN), gate returns True."""
    monkeypatch.setenv("BRDS_LAB_ENVIRONMENT_APPROVED", "1")
    monkeypatch.setenv("BRDS_LIVE_CONTAINMENT", "1")
    arm = tmp_path / ".arm_token"
    _make_arm_token(arm)

    from containment.trigger_daemon import _is_live_containment_allowed
    assert _is_live_containment_allowed(arm) is True


def test_c4_daemon_passes_dry_run_override_when_not_armed(tmp_path, monkeypatch):
    """In dry-run mode the daemon must pass -DryRunOverride (not -Armed) to PS1."""
    monkeypatch.delenv("BRDS_LIVE_CONTAINMENT", raising=False)
    alerts_path = _make_signed_alert(tmp_path)
    arm = tmp_path / ".arm_token"  # missing
    audit_log = tmp_path / "audit.jsonl"
    processed: set[str] = set()

    ps_calls: list[list[str]] = []

    def fake_run_ps(script_path, args, timeout=30):
        ps_calls.append(list(args))
        return 0, "[DRY-RUN] logged"

    from containment import trigger_daemon
    with patch.object(trigger_daemon, "run_powershell", side_effect=fake_run_ps):
        with patch.object(trigger_daemon, "_notify_backend"):
            trigger_daemon.poll_alerts(alerts_path, arm, audit_log, processed)

    assert len(ps_calls) >= 1
    for call_args in ps_calls:
        assert "-DryRunOverride" in call_args
        assert "-Armed" not in call_args


def test_c5_daemon_passes_armed_flag_when_gate_open(tmp_path, monkeypatch):
    """In live mode the daemon must pass -Armed (not -DryRunOverride) to PS1."""
    monkeypatch.setenv("BRDS_LAB_ENVIRONMENT_APPROVED", "1")
    monkeypatch.setenv("BRDS_LIVE_CONTAINMENT", "1")
    alerts_path = _make_signed_alert(tmp_path)
    arm = tmp_path / ".arm_token"
    _make_arm_token(arm)
    audit_log = tmp_path / "audit.jsonl"
    processed: set[str] = set()

    ps_calls: list[list[str]] = []

    def fake_run_ps(script_path, args, timeout=30):
        ps_calls.append(list(args))
        return 0, "[CONTAINMENT] done"

    from containment import trigger_daemon
    with patch.object(trigger_daemon, "run_powershell", side_effect=fake_run_ps):
        with patch.object(trigger_daemon, "_notify_backend"):
            trigger_daemon.poll_alerts(alerts_path, arm, audit_log, processed)

    assert len(ps_calls) >= 1
    for call_args in ps_calls:
        assert "-Armed" in call_args
        assert "-DryRunOverride" not in call_args


def test_c6_audit_log_written_per_action(tmp_path, monkeypatch):
    """trigger_daemon must write a JSONL audit entry for every processed alert."""
    monkeypatch.delenv("BRDS_LIVE_CONTAINMENT", raising=False)
    alerts_path = _make_signed_alert(tmp_path, "2026-01-01T01:00:00Z")
    arm = tmp_path / ".arm_token"
    audit_log = tmp_path / "audit.jsonl"
    processed: set[str] = set()

    from containment import trigger_daemon
    with patch.object(trigger_daemon, "run_powershell", return_value=(0, "ok")):
        with patch.object(trigger_daemon, "_notify_backend"):
            trigger_daemon.poll_alerts(alerts_path, arm, audit_log, processed)

    assert audit_log.exists(), "Audit log must be created"
    lines = audit_log.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["alert_id"] == "2026-01-01T01:00:00Z"
    assert record["computer"] == "host-a"
    assert "actions" in record
    assert record["mode"] == "DRY-RUN"


def test_c7_pre_existing_alerts_skipped(tmp_path, monkeypatch):
    """Alerts already in processed_alerts at startup must not trigger containment."""
    monkeypatch.delenv("BRDS_LIVE_CONTAINMENT", raising=False)
    alerts_path = _make_signed_alert(tmp_path, "2026-01-01T02:00:00Z")
    arm = tmp_path / ".arm_token"
    audit_log = tmp_path / "audit.jsonl"
    # Pre-seed the alert ID as already processed
    processed = {"2026-01-01T02:00:00Z"}

    from containment import trigger_daemon
    with patch.object(trigger_daemon, "run_powershell", return_value=(0, "ok")) as mock_ps:
        with patch.object(trigger_daemon, "_notify_backend"):
            trigger_daemon.poll_alerts(alerts_path, arm, audit_log, processed)

    mock_ps.assert_not_called()
    assert not audit_log.exists()


# ── Backend containment status endpoint ───────────────────────────────────────

@pytest.fixture
def app_with_incident(tmp_path):
    """App with one ACTIVE incident pre-seeded."""
    from backend.app import create_app
    from backend.models import db
    from backend.models.incidents import Incident

    baseline_path = _build_baseline(tmp_path)
    app = create_app({
        "TESTING": True,
        "MODEL_PATH": baseline_path,
        "LSTM_MODEL_PATH": tmp_path / "missing.pth",
        "ALERTS_PATH": tmp_path / "alerts.json",
        "TELEMETRY_PATH": tmp_path / "telemetry.csv",
        "REPORT_PATH": tmp_path / "report.json",
    })
    with app.app_context():
        inc = Incident(
            timestamp="2026-01-01T00:00:30Z",
            computer="host-lab",
            ransomware_family="T1486",
            risk_score=0.97,
            process_id=1234,
            status="ACTIVE",
        )
        db.session.add(inc)
        db.session.commit()

    os.environ["BRDS_API_KEY"] = "test-key"
    yield app
    os.environ.pop("BRDS_API_KEY", None)


def test_c8_containment_status_endpoint_updates_incident(app_with_incident):
    """POST /api/containment/status must flip Incident.status in the database."""
    from backend.models.incidents import Incident

    app = app_with_incident
    with app.test_client() as client:
        res = client.post(
            "/api/containment/status",
            json={
                "window_start": "2026-01-01T00:00:30Z",
                "computer": "host-lab",
                "status": "CONTAINED",
            },
            headers={"X-BRDS-API-Key": "test-key"},
        )
    assert res.status_code == 200
    body = res.get_json()
    assert body["new_status"] == "CONTAINED"

    with app.app_context():
        inc = Incident.query.filter_by(computer="host-lab").one()
        assert inc.status == "CONTAINED"


def test_c9_containment_status_rejects_invalid_status(app_with_incident):
    app = app_with_incident
    with app.test_client() as client:
        res = client.post(
            "/api/containment/status",
            json={
                "window_start": "2026-01-01T00:00:30Z",
                "computer": "host-lab",
                "status": "HACKED",
            },
            headers={"X-BRDS-API-Key": "test-key"},
        )
    assert res.status_code == 400
    assert "Invalid status" in res.get_json()["error"]


def test_c10_containment_status_returns_404_for_unknown_incident(app_with_incident):
    app = app_with_incident
    with app.test_client() as client:
        res = client.post(
            "/api/containment/status",
            json={
                "window_start": "2099-01-01T00:00:00Z",
                "computer": "ghost-host",
                "status": "CONTAINED",
            },
            headers={"X-BRDS-API-Key": "test-key"},
        )
    assert res.status_code == 404
