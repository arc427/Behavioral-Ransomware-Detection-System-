# Behavioral Ransomware Detection System (BRDS-PEC)
## Backend Architecture & Database Schema Specification

**Framework:** Flask 2.3+ (WSGI Application Factory)  
**ORM & Database:** SQLAlchemy 3.0+ / SQLite (`data/brds.db`)  
**Security Protocols:** HMAC-SHA256, `@require_api_key`, CORS Domain Allowlists, SQL `_safe_like` Escaping  

---

## 1. Relational Database Schema (`data/brds.db`)

### 1.1 `incidents` Table
Stores active threat alerts and containment state.

```sql
CREATE TABLE incidents (
    id VARCHAR(64) PRIMARY KEY,
    timestamp VARCHAR(64) NOT NULL,
    computer VARCHAR(128) NOT NULL,
    ransomware_family VARCHAR(64) NOT NULL,
    risk_score FLOAT NOT NULL,
    process_id INTEGER NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE'
);
```

### 1.2 `feature_vectors` Table
Stores 5-second windowed feature telemetry extracted from Sysmon event streams.

```sql
CREATE TABLE feature_vectors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    computer VARCHAR(128) NOT NULL,
    process_key VARCHAR(256) NOT NULL,
    window_start VARCHAR(64) NOT NULL,
    label INTEGER NOT NULL DEFAULT 0,
    technique_id VARCHAR(64) DEFAULT 'benign',
    scenario VARCHAR(64) DEFAULT 'benign',
    source VARCHAR(256),
    risk_score FLOAT NOT NULL DEFAULT 0.0,
    anomaly_score FLOAT NOT NULL DEFAULT 0.0,
    features_json TEXT NOT NULL
);
```

### 1.3 `explainability_logs` Table
Caches feature attributions computed by `LSTMSHAPExplainer`.

```sql
CREATE TABLE explainability_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id VARCHAR(64) NOT NULL,
    feature_name VARCHAR(128) NOT NULL,
    importance_value FLOAT NOT NULL,
    FOREIGN KEY(alert_id) REFERENCES incidents(id)
);
```

---

## 2. REST API Blueprint Specification

### 2.1 Telemetry Blueprints (`backend/routes/telemetry_routes.py`)

#### `POST /api/score/live`
- **Description:** Receives windowed telemetry sequence, pings watchdog, scores probability via `LSTMInfer`, and writes signed alerts.
- **Security:** Requires `X-BRDS-API-Key` header verified via `@require_api_key`.
- **Request Body:**
  ```json
  {
    "computer": "BRDS-WIN11-SEC",
    "sequence": [
      {
        "process_key": "vssadmin.exe:2020",
        "window_start": "2026-07-19T04:00:00Z",
        "event_count": 12,
        "event_1_count": 1,
        "event_23_count": 1
      }
    ]
  }
  ```
- **Response:** `200 OK` with `risk_score`, `containment_triggered`, and `alert_id`.

#### `GET /api/telemetry`
- **Description:** Returns paginated telemetry feature vectors for SOC stream rendering.
- **Query Parameters:** `host`, `technique`, `source`, `limit`, `offset`.
- **SQL Safeguard:** Values are sanitized using `_safe_like()` escaping `%` and `_` wildcards with `escape="\\"`.

---

### 2.2 Incident Blueprints (`backend/routes/incident_routes.py`)

#### `GET /api/alerts`
- **Description:** Queries active ransomware alerts.
- **Query Parameters:** `host`, `technique`, `min_risk`.
- **Response:** JSON list of incidents from `brds.db` or fallback parsing of HMAC-verified `dry_run_alerts.json`.

---

### 2.3 Explainable AI Blueprints (`backend/routes/xai_routes.py`)

#### `GET /api/explanations/<alert_id>`
- **Description:** Computes neural gradient attributions for specified alert ID.
- **Response Payload:**
  ```json
  {
    "alert_id": "2026-07-19T04:10:00Z",
    "available": true,
    "explanation_source": "lstm_gradient",
    "attributions": [
      { "feature_name": "event_23_count", "importance_value": 0.49 },
      { "feature_name": "file_activity_count", "importance_value": 0.46 }
    ]
  }
  ```
- **Error Sanitization:** Returns generic user message (`"Explanation computation failed. Contact your SOC administrator."`) while logging tracebacks server-side only.

---

### 2.4 Health & Monitoring Blueprints (`backend/app.py`)

#### `GET /api/health`
- **Description:** Exposes system sensor and API health status.
- **Response:**
  ```json
  {
    "status": "healthy",
    "sensor_status": "ACTIVE",
    "watchdog_silenced": false,
    "lstm_model_loaded": true
  }
  ```
