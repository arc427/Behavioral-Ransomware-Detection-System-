import os
import hmac
from functools import wraps
from flask import request, jsonify, current_app

def _get_api_key() -> str | None:
    """Retrieve API key from environment variable or Flask configuration."""
    return os.environ.get("BRDS_API_KEY") or current_app.config.get("BRDS_API_KEY")

def require_api_key(f):
    """Decorator to enforce constant-time API key authentication on sensitive endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        expected_key = _get_api_key()
        
        # If no key is configured in env or config, pass through (e.g. dev/testing mode)
        if not expected_key:
            return f(*args, **kwargs)
            
        provided_key = request.headers.get("X-BRDS-API-Key", "")
        
        if not provided_key or not hmac.compare_digest(provided_key.encode("utf-8"), expected_key.encode("utf-8")):
            return jsonify({
                "error": "Unauthorized",
                "message": "Invalid or missing X-BRDS-API-Key authentication header."
            }), 401
            
        return f(*args, **kwargs)
        
    return decorated
