import tempfile
import json
import subprocess
import os
from pathlib import Path
from containment.trigger_daemon import poll_alerts, run_powershell, CONTAIN_HOST_SCRIPT, KILL_PROCESS_SCRIPT

def test_powershell_contain_host_dryrun():
    # Run the real PowerShell script in dry-run mode
    # Ensure BRDS_DRY_RUN is set to 1 for safety
    os.environ["BRDS_DRY_RUN"] = "1"
    
    output = run_powershell(CONTAIN_HOST_SCRIPT, ["-DryRun"])
    
    assert "Executing Host Isolation" in output
    assert "Host isolation completed" in output
    # Since dry-run is active, it should log safety warnings
    assert "[SAFETY]" in output or "[DRY-RUN]" in output or "No active network adapters" in output

def test_powershell_kill_process_tree_dryrun():
    os.environ["BRDS_DRY_RUN"] = "1"
    
    # Run the recursive killer on dummy PID 9999 in dry run
    output = run_powershell(KILL_PROCESS_SCRIPT, ["-ParentPid", "9999", "-DryRun"])
    
    assert "Initiating process tree collapse for PID: 9999" in output
    assert "Would terminate process" in output
    assert "Process tree collapse completed" in output

def test_poll_alerts_trigger():
    os.environ["BRDS_DRY_RUN"] = "1"
    
    # Create a mock alert JSON file
    with tempfile.TemporaryDirectory() as tmpdir:
        alerts_path = Path(tmpdir) / "alerts.json"
        
        # 1. Write benign alert and verify it is skipped
        mock_alerts = [
            {
                "window_start": "2026-07-19T00:00:01Z",
                "risk_score": 0.12,
                "process_key": "explorer.exe:1200"
            },
            {
                "window_start": "2026-07-19T00:00:02Z",
                "risk_score": 0.95,
                "process_key": "lockbit.exe:4920"
            }
        ]
        
        with open(alerts_path, "w", encoding="utf-8") as f:
            json.dump(mock_alerts, f)
            
        processed = set()
        
        # Run polling
        poll_alerts(alerts_path, processed)
        
        # Verify both alert IDs were added to processed set
        assert "2026-07-19T00:00:01Z" in processed
        assert "2026-07-19T00:00:02Z" in processed
        assert len(processed) == 2
