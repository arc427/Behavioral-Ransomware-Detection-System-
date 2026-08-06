# Behavioral Ransomware Detection System (BRDS-PEC)
## UI/UX Specification & SOC Dashboard Design Guide

**Design Aesthetics:** Premium Cyberpunk Dark Mode (High-Contrast SOC Operations)  
**Frontend Stack:** HTML5, CSS3 (Vanilla), JavaScript (ES6+), Chart.js (v4.x CDN), Lucide Icons (CDN)  
**Layout Model:** 3-Column Responsive Grid Architecture  

---

## 1. Design System & Token Tokens

```css
:root {
    --bg-dark: #080c10;
    --panel-bg: rgba(13, 20, 28, 0.85);
    --border-color: rgba(0, 242, 254, 0.15);
    --text-main: #e0fbfc;
    --text-muted: #8a9a97;
    
    /* Threat Status Accents */
    --accent-mint: #0df5af;        /* System Healthy / Contained */
    --accent-amber: #fca311;       /* Warning Threshold (0.60 - 0.84) */
    --accent-crimson: #ff2a5f;     /* High Risk Containment (>= 0.85) */
    --accent-cyan: #00f2fe;        /* Telemetry Stream Highlight */
}
```

---

## 2. Dashboard Layout & Component Architecture (`frontend/index.html`)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          HEADER & BRANDING BAR                              │
│  [Shield Icon] BRDS-PEC | Sysmon Agent: Active | Containment: Active       │
├───────────────────┬─────────────────────────────────────┬───────────────────┤
│  LEFT PANEL       │         CENTER PANEL                │    RIGHT PANEL    │
│                   │                                     │                   │
│  Sysmon           │  Metrics Cards Row                  │  Active           │
│  Telemetry        │  (Events • Avg Risk • Anomalies)    │  Incident         │
│  Stream           │                                     │  Log              │
│  (Live Process    │  Real-Time Threat Profile           │  (Threat Cards •  │
│   Event Feed)     │  Risk Curve (Chart.js Canvas)       │   Isolate Button) │
└───────────────────┴─────────────────────────────────────┴───────────────────┘
```

---

## 3. Component Details & Interactive Behavior

### 3.1 Live Telemetry Stream (`frontend/js/telemetry_stream.js`)
- **Panel Location:** Left column.
- **Behavior:** Polls `GET /api/telemetry` every 2 seconds. Dynamically prepends process activity cards displaying timestamp, host ID, process key (`image.exe:PID`), and active event badges (`PROC`, `FILE`, `REG`, `NET`).

### 3.2 Real-Time Threat Profile Chart (`frontend/js/risk_timeline.js`)
- **Panel Location:** Middle column.
- **Behavior:** Renders a 30-window rolling Chart.js linear spline area chart with gradient fills. Displays two reference threshold lines:
  - **Warning Line (Amber Dashed):** $0.60$ risk threshold.
  - **Containment Line (Crimson Dashed):** $0.85$ risk threshold.

### 3.3 Active Incident Log (`frontend/js/incident_log.js`)
- **Panel Location:** Right column.
- **Behavior:** Polls `GET /api/alerts`. Displays high-risk incident cards with ransomware family tag (`WANNACRY`, `LOCKBIT`, `RYUK`, `SODINOKIBI`), target PID, host ID, and action buttons:
  - **`SHAP Analysis` Button:** Opens XAI modal displaying neural gradient feature attributions.
  - **`Isolate Host` Button:** Triggers manual host containment.

### 3.4 Explainable AI (XAI) Modal (`frontend/js/xai_modal.js`)
- **Behavior:** Triggered via `SHAP Analysis` button. Queries `GET /api/explanations/<alert_id>` receiving `data.attributions`.
- **Bar Visualization:** Dynamically formats and renders feature attributions as horizontal percentage bars (Mint green for positive contribution to risk, Crimson red for negative contribution).
