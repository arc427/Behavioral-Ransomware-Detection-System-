"""BRDS-PEC Automated Containment Trigger Daemon.

Polls the HMAC-signed alert file.  For each new alert with risk >= 0.85 it:
  1. Checks the dual containment gate (see below).
  2. Invokes kill_process_tree.ps1 and ContainHost.ps1 with the appropriate mode.
  3. Writes a containment audit entry to containment_audit.jsonl.
  4. Notifies the backend API to update the Incident status.

Dual containment gate (BOTH must be true for live action):
  a. BRDS_LIVE_CONTAINMENT=1 is set in the daemon's environment.
  b. A valid HMAC-signed .arm_token file exists at the configured path.

If either condition is missing the scripts run in dry-run mode (log only).
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
import argparse
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("trigger_daemon")

DEFAULT_ALERTS_PATH = ROOT / "data" / "processed" / "dry_run_alerts.json"
DEFAULT_ARM_TOKEN_PATH = Path(__file__).parent / ".arm_token"
DEFAULT_AUDIT_LOG_PATH = ROOT / "data" / "processed" / "containment_audit.jsonl"
CONTAIN_HOST_SCRIPT = Path(__file__).parent / "ContainHost.ps1"
KILL_PROCESS_SCRIPT = Path(__file__).parent / "kill_process_tree.ps1"
ROLLBACK_HOST_SCRIPT = Path(__file__).parent / "RollbackHost.ps1"

ALERT_THRESHOLD = 0.85


def _is_live_containment_allowed(arm_token_path: Path) -> bool:
    """Return True only when ALL containment conditions are satisfied:
    1. BRDS_LAB_ENVIRONMENT_APPROVED=1 in the environment (Lab safety).
    2. BRDS_LIVE_CONTAINMENT=1 in the environment.
    3. A valid HMAC-signed arm token file exists.
    """
    if os.environ.get("BRDS_LAB_ENVIRONMENT_APPROVED", "0") != "1":
        return False
    if os.environ.get("BRDS_LIVE_CONTAINMENT", "0") != "1":
        return False
    from containment.alert_integrity import verify_arm_token
    return verify_arm_token(arm_token_path)


class PowerShellResult(str):
    """String subclass representing command output that also allows tuple unpacking: rc, out = ..."""
    returncode: int

    def __new__(cls, text: str, returncode: int = 0):
        obj = super().__new__(cls, text)
        obj.returncode = returncode
        return obj

    def __iter__(self):
        return iter((self.returncode, str(self)))


def run_powershell(script_path: Path, args: list[str], timeout: int = 30) -> PowerShellResult:
    """Execute a PowerShell containment script; return PowerShellResult (unpacks to rc, output)."""
    cmd = [
        "powershell.exe",
        "-ExecutionPolicy", "Bypass",
        "-NonInteractive",
        "-File", str(script_path),
    ] + args
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        output = res.stdout + (("\n" + res.stderr) if res.stderr.strip() else "")
        return PowerShellResult(output.strip(), res.returncode)
    except subprocess.TimeoutExpired:
        return PowerShellResult(f"[ERROR] Script timed out after {timeout}s: {script_path}", -1)
    except FileNotFoundError:
        return PowerShellResult("[ERROR] powershell.exe not found — containment scripts cannot run", -1)


def _write_audit(audit_path: Path, record: dict) -> None:
    """Append one JSON line to the containment audit log."""
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, separators=(",", ":")) + "\n")


def _notify_backend(alert: dict, status: str, backend_url: str) -> None:
    """POST containment result to the backend API to update incident status."""
    api_key = os.environ.get("BRDS_API_KEY")
    if not api_key:
        logger.warning("Could not notify backend of containment status: BRDS_API_KEY is not set.")
        return
    try:
        import urllib.request
        payload = json.dumps({
            "window_start": alert.get("window_start") or alert.get("timestamp"),
            "computer": alert.get("computer"),
            "status": status,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{backend_url}/api/containment/status",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-BRDS-API-Key": api_key,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            logger.info("Backend status update: HTTP %s", resp.status)
    except Exception as exc:
        logger.warning("Could not notify backend of containment status: %s", exc)


def poll_alerts(
    alerts_path: Path,
    arm_token_path: Path,
    arg3: set[str] | Path,
    arg4: set[str] | Path | None = None,
    backend_url: str = "http://127.0.0.1:5000",
) -> None:
    """Read the alerts file and act on new high-risk alerts.

    Supports both signatures:
      poll_alerts(alerts_path, arm_token_path, processed_alerts)
      poll_alerts(alerts_path, arm_token_path, audit_log_path, processed_alerts, backend_url)
    """
    if isinstance(arg3, set):
        processed_alerts = arg3
        audit_log_path = Path(arg4) if arg4 is not None else DEFAULT_AUDIT_LOG_PATH
    else:
        audit_log_path = Path(arg3)
        processed_alerts = arg4 if isinstance(arg4, set) else set()
    if not alerts_path.exists():
        return

    from containment.alert_integrity import verify_and_load
    try:
        alerts = verify_and_load(alerts_path)
    except Exception as exc:
        logger.error("Alert file verification failed: %s", exc)
        return

    live = _is_live_containment_allowed(arm_token_path)
    ps_mode_args = ["-Armed"] if live else ["-DryRunOverride"]
    mode_label = "LIVE" if live else "DRY-RUN"

    for alert in alerts:
        alert_id = alert.get("window_start") or alert.get("timestamp")
        if not alert_id or alert_id in processed_alerts:
            continue

        risk_score = float(alert.get("risk_score", 0.0))
        if risk_score < ALERT_THRESHOLD:
            processed_alerts.add(alert_id)
            continue

        computer = alert.get("computer", "unknown")
        logger.warning(
            "[%s] Alert: id=%s computer=%s risk=%.3f",
            mode_label, alert_id, computer, risk_score,
        )

        audit: dict = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_id,
            "computer": computer,
            "risk_score": risk_score,
            "mode": mode_label,
            "actions": [],
        }

        # ── Process tree termination ──────────────────────────────────────────
        proc_key = alert.get("process_key", "")
        pid: int | None = None
        if ":" in proc_key:
            try:
                pid = int(proc_key.split(":")[-1])
            except ValueError:
                pass

        if pid:
            logger.info("[%s] Kill process tree PID=%s", mode_label, pid)
            rc, out = run_powershell(
                KILL_PROCESS_SCRIPT,
                ["-ParentPid", str(pid)] + ps_mode_args,
            )
            logger.info("kill_process_tree exit=%s\n%s", rc, out)
            audit["actions"].append({
                "action": "kill_process_tree",
                "pid": pid,
                "exit_code": rc,
                "output": out,
            })
        else:
            logger.warning("No valid PID in process_key=%r — skipping process termination", proc_key)
            audit["actions"].append({"action": "kill_process_tree", "skipped": "no_valid_pid"})

        # ── Network isolation ─────────────────────────────────────────────────
        logger.info("[%s] Host network isolation", mode_label)
        rc, out = run_powershell(CONTAIN_HOST_SCRIPT, ps_mode_args)
        logger.info("ContainHost exit=%s\n%s", rc, out)
        audit["actions"].append({
            "action": "contain_host",
            "exit_code": rc,
            "output": out,
        })

        # ── Audit log + backend notification ─────────────────────────────────
        _write_audit(audit_log_path, audit)
        status = "CONTAINED" if live else "DRY_RUN_CONTAINED"
        _notify_backend(alert, status, backend_url)

        processed_alerts.add(alert_id)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alerts-path", type=Path, default=DEFAULT_ALERTS_PATH)
    parser.add_argument("--arm-token-path", type=Path, default=DEFAULT_ARM_TOKEN_PATH)
    parser.add_argument("--audit-log", type=Path, default=DEFAULT_AUDIT_LOG_PATH)
    parser.add_argument("--backend-url", default="http://127.0.0.1:5000")
    parser.add_argument(
        "--create-arm-token",
        action="store_true",
        help="Generate a signed arm token and exit (requires BRDS_ALERT_HMAC_KEY)",
    )
    parser.add_argument("--interval", type=float, default=1.5)
    parser.add_argument("--one-shot", action="store_true", help="Poll once and exit")
    args = parser.parse_args()

    # ── Arm token generation ──────────────────────────────────────────────────
    if args.create_arm_token:
        from containment.alert_integrity import create_arm_token
        token = create_arm_token()
        args.arm_token_path.write_text(token, encoding="utf-8")
        logger.info("Arm token written to %s", args.arm_token_path)
        return

    if not os.environ.get("BRDS_API_KEY"):
        logger.error("BRDS_API_KEY environment variable is missing. The daemon cannot communicate with the API.")
        sys.exit(1)

    # ── Startup banner ────────────────────────────────────────────────────────
    live = _is_live_containment_allowed(args.arm_token_path)
    if live:
        logger.warning(
            "*** LAB ARMED MODE *** BRDS_LAB_ENVIRONMENT_APPROVED=1 + BRDS_LIVE_CONTAINMENT=1 + valid arm token. "
            "Process termination and network isolation WILL execute."
        )
    else:
        lab_ok = os.environ.get("BRDS_LAB_ENVIRONMENT_APPROVED", "0") == "1"
        env_set = os.environ.get("BRDS_LIVE_CONTAINMENT", "0") == "1"
        token_ok = Path(args.arm_token_path).exists()
        reason = []
        if not lab_ok:
            reason.append("BRDS_LAB_ENVIRONMENT_APPROVED != 1")
        if not env_set:
            reason.append("BRDS_LIVE_CONTAINMENT != 1")
        if not token_ok:
            reason.append("arm token missing")
        logger.info("DRY-RUN mode (%s). No host actions will execute.", " + ".join(reason) or "flags not met")

    # ── Seed processed set from existing alerts (ignore pre-startup alerts) ───
    processed_alerts: set[str] = set()
    if args.alerts_path.exists():
        from containment.alert_integrity import verify_and_load
        try:
            for alert in verify_and_load(args.alerts_path):
                aid = alert.get("window_start") or alert.get("timestamp")
                if aid:
                    processed_alerts.add(aid)
        except Exception as exc:
            logger.warning("Could not pre-seed processed alerts: %s", exc)

    logger.info(
        "Daemon ready. alerts=%s interval=%.1fs pre-existing=%d",
        args.alerts_path, args.interval, len(processed_alerts),
    )

    if args.one_shot:
        poll_alerts(args.alerts_path, args.arm_token_path, args.audit_log, processed_alerts, args.backend_url)
        logger.info("One-shot run complete.")
        return

    try:
        while True:
            poll_alerts(args.alerts_path, args.arm_token_path, args.audit_log, processed_alerts, args.backend_url)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        logger.info("Daemon shut down.")


if __name__ == "__main__":
    main()
