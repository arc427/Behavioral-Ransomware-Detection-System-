import time
from datetime import datetime, timezone
from pathlib import Path

class TelemetryWatchdog:
    """Monitors telemetry stream heartbeats to detect ETW/Sysmon log suppression attacks."""
    
    def __init__(self, silence_threshold_seconds: float = 30.0):
        self.silence_threshold = silence_threshold_seconds
        self._last_event_time = time.time()
        self._last_event_iso = datetime.now(timezone.utc).isoformat()
        self._total_events_ingested = 0

    def ping(self, count: int = 1) -> None:
        """Record the arrival of one or more valid telemetry events."""
        self._last_event_time = time.time()
        self._last_event_iso = datetime.now(timezone.utc).isoformat()
        self._total_events_ingested += count

    def get_status(self) -> dict:
        """Evaluate sensor health and return status metrics."""
        elapsed = time.time() - self._last_event_time
        is_healthy = elapsed <= self.silence_threshold
        
        status_label = "HEALTHY" if is_healthy else "SENSOR_SILENCED"
        
        return {
            "status": status_label,
            "sensor_healthy": is_healthy,
            "elapsed_seconds": round(elapsed, 1),
            "silence_threshold_seconds": self.silence_threshold,
            "last_event_timestamp": self._last_event_iso,
            "total_events_ingested": self._total_events_ingested
        }
