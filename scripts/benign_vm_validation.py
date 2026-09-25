"""
BRDS Benign VM Validation — Collects real endpoint telemetry, sends through
the full two-stage pipeline, and records IF score distribution + LSTM results.

Usage:
    1. Start the Flask backend:
       $env:BRDS_IF_SCREENING_THRESHOLD = "-0.188196"
       python backend/app.py

    2. Run this script:
       python scripts/benign_vm_validation.py --windows 50 --interval 5

    3. Results are saved to data/validation/benign_vm_results.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import statistics
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pipeline.watchdog import TelemetryWatchdog, fetch_live_sysmon_events, fetch_live_system_process_windows
from pipeline.temporal_aggregator import aggregate_process_windows


def collect_benign_windows(
    n_windows: int = 50,
    interval: float = 5.0,
    api_url: str = "http://127.0.0.1:5000/api/score/live",
) -> dict:
    """Collect n_windows of live benign telemetry and score through the pipeline."""

    watchdog = TelemetryWatchdog(api_url=api_url)
    results: list[dict] = []
    errors: list[str] = []
    sysmon_available = False
    source_kind = "unknown"

    print("=" * 70)
    print("  BRDS BENIGN VM VALIDATION")
    print(f"  Target windows: {n_windows}")
    print(f"  Collection interval: {interval}s")
    print(f"  API endpoint: {api_url}")
    print(f"  IF threshold (env): {os.environ.get('BRDS_IF_SCREENING_THRESHOLD', 'not set')}")
    print("=" * 70)

    collected = 0
    attempt = 0

    while collected < n_windows:
        attempt += 1

        # Try Sysmon first
        events = fetch_live_sysmon_events()
        if events:
            sysmon_available = True
            source_kind = "live-sysmon"
            df_windows = aggregate_process_windows(events, window_seconds=5)
            if not df_windows.empty:
                for _, row in df_windows.iterrows():
                    if collected >= n_windows:
                        break
                    feat_dict = {col: float(row[col]) for col in row.index if col in [
                        "event_count", "unique_images", "unique_files", "unique_extensions",
                        "unique_destination_ips", "suspicious_path_count", "file_activity_count",
                        "registry_activity_count", "network_activity_count", "event_1_count",
                        "event_3_count", "event_7_count", "event_11_count", "event_12_count",
                        "event_13_count", "event_23_count", "event_26_count"
                    ]}
                    payload = {
                        "computer": str(row.get("computer", os.environ.get("COMPUTERNAME", "BRDS-VM"))),
                        "process_key": str(row.get("process_key", "system:1000")),
                        "window_start": str(row.get("window_start", datetime.now(timezone.utc).isoformat())),
                        "label": 0,
                        "technique_id": "benign",
                        "scenario": "benign-vm-validation",
                        "source": "live-sysmon",
                        "features": feat_dict,
                    }
                    resp = watchdog.post_window_to_api(payload)
                    if resp:
                        collected += 1
                        results.append({
                            "window_index": collected,
                            "window_start": payload["window_start"],
                            "computer": payload["computer"],
                            "process_key": payload["process_key"],
                            "source": "live-sysmon",
                            "features": feat_dict,
                            "api_response": resp,
                        })
                        pipe = resp.get("pipeline", {})
                        print(
                            f"  [{collected:3d}/{n_windows}] "
                            f"IF={pipe.get('anomaly_score', 'N/A'):>9} "
                            f"thr={pipe.get('if_screening_threshold', 'N/A')} "
                            f"anom={pipe.get('isolation_forest_anomalous', '?')} "
                            f"lstm={pipe.get('lstm_invoked', '?')} "
                            f"risk={resp.get('risk_score', 0.0):.4f} "
                            f"alert={resp.get('alert_created', False)}"
                        )
                    else:
                        errors.append(f"attempt {attempt}: API post failed for sysmon window")
        else:
            # Fallback: process polling
            source_kind = "process-polling-fallback"
            windows = fetch_live_system_process_windows()
            for payload in windows[:3]:
                if collected >= n_windows:
                    break
                payload["scenario"] = "benign-vm-validation"
                payload["label"] = 0
                payload["technique_id"] = "benign"
                resp = watchdog.post_window_to_api(payload)
                if resp:
                    collected += 1
                    results.append({
                        "window_index": collected,
                        "window_start": payload["window_start"],
                        "computer": payload.get("computer", "unknown"),
                        "process_key": payload.get("process_key", "unknown"),
                        "source": payload.get("source", "process-polling"),
                        "source_kind": payload.get("source_kind", "process_polling_heuristic"),
                        "features": payload.get("features", {}),
                        "api_response": resp,
                    })
                    pipe = resp.get("pipeline", {})
                    print(
                        f"  [{collected:3d}/{n_windows}] "
                        f"IF={pipe.get('anomaly_score', 'N/A'):>9} "
                        f"thr={pipe.get('if_screening_threshold', 'N/A')} "
                        f"anom={pipe.get('isolation_forest_anomalous', '?')} "
                        f"lstm={pipe.get('lstm_invoked', '?')} "
                        f"risk={resp.get('risk_score', 0.0):.4f} "
                        f"alert={resp.get('alert_created', False)}"
                    )
                else:
                    errors.append(f"attempt {attempt}: API post failed for process polling window")

        time.sleep(interval)

    # Compute summary statistics
    if_scores = []
    lstm_scores = []
    lstm_invoked_count = 0
    alert_count = 0
    inference_errors = []

    for r in results:
        resp = r.get("api_response", {})
        pipe = resp.get("pipeline", {})

        if_score = pipe.get("anomaly_score")
        if if_score is not None:
            if_scores.append(float(if_score))

        if pipe.get("lstm_invoked"):
            lstm_invoked_count += 1
            ls = pipe.get("lstm_score")
            if ls is not None:
                lstm_scores.append(float(ls))

        if resp.get("alert_created"):
            alert_count += 1

        if resp.get("inference_error"):
            inference_errors.append(resp["inference_error"])

    summary = {
        "validation_type": "benign_vm_validation",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "computer": os.environ.get("COMPUTERNAME", "unknown"),
            "python_version": sys.version,
            "sysmon_available": sysmon_available,
            "telemetry_source": source_kind,
            "if_screening_threshold_env": os.environ.get("BRDS_IF_SCREENING_THRESHOLD", "not set"),
        },
        "collection": {
            "windows_requested": n_windows,
            "windows_collected": len(results),
            "collection_errors": len(errors),
            "error_messages": errors[:10],
        },
        "if_score_distribution": {
            "count": len(if_scores),
            "min": round(min(if_scores), 6) if if_scores else None,
            "max": round(max(if_scores), 6) if if_scores else None,
            "mean": round(statistics.mean(if_scores), 6) if if_scores else None,
            "median": round(statistics.median(if_scores), 6) if if_scores else None,
            "stdev": round(statistics.stdev(if_scores), 6) if len(if_scores) > 1 else None,
            "p05": round(sorted(if_scores)[max(0, int(len(if_scores)*0.05))], 6) if if_scores else None,
            "p95": round(sorted(if_scores)[min(len(if_scores)-1, int(len(if_scores)*0.95))], 6) if if_scores else None,
        },
        "screening_results": {
            "total_windows": len(results),
            "windows_passed_to_lstm": lstm_invoked_count,
            "windows_screened_out": len(results) - lstm_invoked_count,
            "lstm_invocation_rate_pct": round(100.0 * lstm_invoked_count / len(results), 2) if results else 0,
        },
        "lstm_results": {
            "windows_scored": len(lstm_scores),
            "min_score": round(min(lstm_scores), 6) if lstm_scores else None,
            "max_score": round(max(lstm_scores), 6) if lstm_scores else None,
            "mean_score": round(statistics.mean(lstm_scores), 6) if lstm_scores else None,
        },
        "alerts": {
            "total_alerts": alert_count,
            "false_alerts_on_benign": alert_count,  # all activity is benign
        },
        "inference_errors": inference_errors[:10],
        "threshold_status": {
            "value": os.environ.get("BRDS_IF_SCREENING_THRESHOLD", "default (-0.167461)"),
            "status": "provisional_vm_validation_candidate",
            "note": "NOT a validated production threshold",
        },
    }

    # Historical comparison placeholder
    summary["historical_comparison"] = {
        "note": "Compare if_score_distribution against historical benign range [-0.291173, +0.099285]",
        "historical_benign_min": -0.291173,
        "historical_benign_max": 0.099285,
        "vm_min": summary["if_score_distribution"]["min"],
        "vm_max": summary["if_score_distribution"]["max"],
    }

    # Save
    out_dir = ROOT / "data" / "validation"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "benign_vm_results.json"
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)

    # Also save raw per-window data
    raw_path = out_dir / "benign_vm_raw_windows.json"
    with open(raw_path, "w") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 70)
    print("  BENIGN VM VALIDATION SUMMARY")
    print("=" * 70)
    print(f"  Windows collected:    {len(results)}")
    print(f"  Sysmon available:     {sysmon_available}")
    print(f"  Telemetry source:     {source_kind}")
    print(f"  IF scores:            min={summary['if_score_distribution']['min']}  "
          f"max={summary['if_score_distribution']['max']}  "
          f"mean={summary['if_score_distribution']['mean']}")
    print(f"  LSTM invocations:     {lstm_invoked_count}/{len(results)} "
          f"({summary['screening_results']['lstm_invocation_rate_pct']}%)")
    if lstm_scores:
        print(f"  LSTM scores:          min={min(lstm_scores):.6f}  max={max(lstm_scores):.6f}")
    print(f"  False alerts:         {alert_count}")
    print(f"  Inference errors:     {len(inference_errors)}")
    print(f"\n  Results: {out_path}")
    print(f"  Raw data: {raw_path}")
    print("=" * 70)

    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BRDS Benign VM Validation")
    parser.add_argument("--windows", type=int, default=50, help="Number of windows to collect")
    parser.add_argument("--interval", type=float, default=5.0, help="Seconds between collection rounds")
    parser.add_argument("--api-url", default="http://127.0.0.1:5000/api/score/live", help="API endpoint")
    args = parser.parse_args()
    collect_benign_windows(n_windows=args.windows, interval=args.interval, api_url=args.api_url)
