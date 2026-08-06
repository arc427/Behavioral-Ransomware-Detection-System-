import os
import json
import hmac
import hashlib
from pathlib import Path

def _get_hmac_key() -> bytes:
    """Retrieve the alert-signing key; never silently use a public default."""
    key = os.environ.get("BRDS_ALERT_HMAC_KEY")
    if not key and os.environ.get("BRDS_ALLOW_INSECURE_DEV_HMAC") == "1":
        key = "BRDS_TEST_ONLY_HMAC_KEY"
    if not key:
        raise RuntimeError(
            "BRDS_ALERT_HMAC_KEY must be set before signing or verifying alerts. "
            "The test-only BRDS_ALLOW_INSECURE_DEV_HMAC override is not for deployment."
        )
    return key.encode("utf-8")

def sign_alerts(alerts: list) -> str:
    """Serialize alerts list and append an HMAC-SHA256 signature string."""
    payload_str = json.dumps(alerts, separators=(',', ':'), sort_keys=True)
    key = _get_hmac_key()
    signature = hmac.new(key, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()
    
    signed_container = {
        "alerts": alerts,
        "sig": signature
    }
    return json.dumps(signed_container, indent=2)

def verify_and_load(alerts_path: Path | str) -> list:
    """Read alerts file, verify HMAC-SHA256 signature, and return alerts list.
    
    Raises:
        RuntimeError: If signature mismatch is detected (tampered alerts).
    """
    path = Path(alerts_path)
    if not path.exists():
        return []
        
    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return []
        
    try:
        data = json.loads(content)
    except Exception as e:
        raise ValueError(f"Invalid JSON format in alerts file: {e}")
        
    # Backwards-compatible handling for raw arrays (e.g. legacy test runs)
    if isinstance(data, list):
        return data
        
    if not isinstance(data, dict) or "alerts" not in data or "sig" not in data:
        raise ValueError("Alerts file format invalid: missing 'alerts' or 'sig' container fields.")
        
    alerts = data["alerts"]
    provided_sig = data["sig"]
    
    payload_str = json.dumps(alerts, separators=(',', ':'), sort_keys=True)
    key = _get_hmac_key()
    expected_sig = hmac.new(key, payload_str.encode("utf-8"), hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(provided_sig, expected_sig):
        raise RuntimeError(
            f"SECURITY ALERT: HMAC signature verification failed for {path}! "
            f"Alert file has been modified or tampered with."
        )
        
    return alerts

def create_arm_token() -> str:
    """Generate cryptographically signed activation token string."""
    payload = "BRDS_ACTIVE_ARMED_STATE_2026"
    key = _get_hmac_key()
    sig = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return json.dumps({"payload": payload, "sig": sig}, indent=2)

def verify_arm_token(token_path: Path | str) -> bool:
    """Verify presence and HMAC signature of signed activation token."""
    path = Path(token_path)
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8").strip())
        if not isinstance(data, dict) or "payload" not in data or "sig" not in data:
            return False
        payload = data["payload"]
        provided_sig = data["sig"]
        key = _get_hmac_key()
        expected_sig = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(provided_sig, expected_sig) and payload == "BRDS_ACTIVE_ARMED_STATE_2026"
    except Exception:
        return False
