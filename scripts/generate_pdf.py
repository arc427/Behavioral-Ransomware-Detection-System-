import os
import sys
from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """Canvas that computes total pages dynamically and adds page numbers & header/footer."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        
        # We don't draw running header/footer on page 1 (Title cover)
        if self._pageNumber > 1:
            # Header
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor("#1e293b"))
            self.drawString(54, 750, "BRDS-PEC: Behavioral Ransomware Detection System")
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748b"))
            self.drawRightString(612 - 54, 750, "Technical Documentation & Review")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 742, 612 - 54, 742)

            # Footer
            self.line(54, 48, 612 - 54, 48)
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748b"))
            self.drawString(54, 34, "CONFIDENTIAL & PROPRIETARY — BEHAVIORAL SECURITY RESEARCH")
            page_text = f"Page {self._pageNumber} of {page_count}"
            self.drawRightString(612 - 54, 34, page_text)
            
        self.restoreState()

def build_pdf(filename):
    pdf_path = Path(filename)
    pdf_path.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0284c7"),
        spaceAfter=15
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=18,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#0369a1"),
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#334155"),
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=colors.HexColor("#334155"),
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=4
    )

    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderColor=colors.HexColor("#cbd5e1"),
        borderWidth=0.5,
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=6
    )

    callout_style = ParagraphStyle(
        'Callout_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
        backColor=colors.HexColor("#f0f9ff"),
        borderColor=colors.HexColor("#0284c7"),
        borderWidth=0.8,
        borderPadding=8,
        spaceBefore=6,
        spaceAfter=8
    )

    story = []

    # Title & Metadata
    story.append(Paragraph("BRDS-PEC: Behavioral Ransomware Detection System", title_style))
    story.append(Paragraph("Pre-Encryption Containment Prototype — Technical Architecture & Codebase Review", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceBefore=0, spaceAfter=12))

    # Executive Overview
    story.append(Paragraph("1. Executive Overview & Core Concept", h1_style))
    story.append(Paragraph(
        "The <b>Behavioral Ransomware Detection System with Pre-Encryption Containment (BRDS-PEC)</b> "
        "is a specialized security research prototype designed to detect and halt zero-day ransomware attacks "
        "before widespread file encryption takes place. Rather than relying on static file hashes or known signatures—which "
        "are easily bypassed by code obfuscation, re-packing, or minor binary mutations—BRDS-PEC continuously monitors "
        "Windows System Monitor (Sysmon) event telemetry. It evaluates behavioral sequences (process creation, "
        "file modifications, registry changes, network socket connections, and shadow copy deletions) to answer the critical question: "
        "<i>'Is this process behaving like ransomware before encryption completes?'</i>",
        body_style
    ))

    # Flow Diagram / Text
    story.append(Paragraph("2. End-to-End Execution Flow", h1_style))
    flow_box = (
        "Windows Sysmon / Exported EVTX or XML Logs<br/>"
        "&nbsp;&nbsp;↓ Parse and Normalize Event Data (evtx_reader.py)<br/>"
        "&nbsp;&nbsp;↓ Filter Relevant Security Events (event_filter.py)<br/>"
        "&nbsp;&nbsp;↓ Aggregate per Process in 5-Second Windows (temporal_aggregator.py)<br/>"
        "&nbsp;&nbsp;↓ Produce 17 Numeric Behavioral Features (vectorizer.py)<br/>"
        "&nbsp;&nbsp;↓ Baseline Model & PyTorch LSTM Produce Risk Scores (ml_engine/)<br/>"
        "&nbsp;&nbsp;↓ Alert Stored, Signed with HMAC-SHA256, and Displayed in Dashboard<br/>"
        "&nbsp;&nbsp;↓ Containment Daemon Acts Only When Explicitly Armed (-Armed Switch)"
    )
    story.append(Paragraph(flow_box, code_style))

    # Root Files
    story.append(Paragraph("3. Core Root Files", h1_style))
    story.append(Paragraph("<b>• README.md:</b> Describes high-level architecture, goals, and setup. Serves as design intent.", bullet_style))
    story.append(Paragraph("<b>• requirements.txt:</b> Outlines core dependencies: <code>pandas</code>, <code>numpy</code>, <code>python-evtx</code>, <code>scikit-learn</code>, <code>joblib</code>, <code>torch</code>, <code>shap</code>, <code>Flask</code>, <code>Flask-SQLAlchemy</code>, <code>Flask-Cors</code>, <code>python-dotenv</code>, <code>requests</code>.", bullet_style))
    story.append(Paragraph("<b>• .env.example:</b> Production template defining key safe configurations: <code>BRDS_DRY_RUN=1</code> (safe dry-run mode), <code>BRDS_API_KEY</code> (ingestion auth), <code>BRDS_ALERT_HMAC_KEY</code> (alert signature key), and <code>BRDS_CORS_ORIGINS</code> (dashboard domain allowlist).", bullet_style))

    # Datasets Breakdown
    story.append(Paragraph("4. Data Folder & Datasets Breakdown (<code>data/</code>)", h1_style))
    story.append(Paragraph(
        "The <code>data/</code> folder is structured into three sub-directories: <code>data/datasets/</code> (immutable research data), "
        "<code>data/processed/</code> (generated feature windows & alerts), and <code>data/models/</code> (trained models & scalers).",
        body_style
    ))

    dataset_table_data = [
        [Paragraph("<b>Dataset / Artifact</b>", body_style), Paragraph("<b>Key Contents</b>", body_style), Paragraph("<b>Role & Limitations in Live Pipeline</b>", body_style)],
        [
            Paragraph("<b>CSU Ransomware</b><br/><code>data/datasets/csu_ransomware/</code>", body_style),
            Paragraph("352k rows, 20 behavior columns (File_created, Process_Create, entropy, etc.).", body_style),
            Paragraph("Useful for offline anomaly baselines. Not directly plugged into live Sysmon pipeline due to schema mismatch.", body_style)
        ],
        [
            Paragraph("<b>RansomSet</b><br/><code>data/datasets/ransomset/</code>", body_style),
            Paragraph("API frequency CSVs (NtCreateFile, NtWriteFile, registry APIs) for 7 families.", body_style),
            Paragraph("Auxiliary multiclass benchmark for family comparison. Contains sandbox API calls, not raw Sysmon logs.", body_style)
        ],
        [
            Paragraph("<b>MLRan</b><br/><code>data/datasets/mlran/</code>", body_style),
            Paragraph("Sample metadata, Cuckoo parsers, goodware descriptions, feature-selected CSVs.", body_style),
            Paragraph("Informs static/dynamic hybrid classification research. Selected features reflect sandbox Cuckoo reports.", body_style)
        ],
        [
            Paragraph("<b>OTRF Security</b><br/><code>data/datasets/otrf_security_datasets/</code>", body_style),
            Paragraph("Defensive-evasion scenarios (disabling event logs, command line, PowerShell).", body_style),
            Paragraph("Tests preparatory behavior (defense impairment). Supporting scenarios, not a complete ransomware dataset.", body_style)
        ],
        [
            Paragraph("<b>Splunk ATT&CK Data</b><br/><code>data/datasets/splunk_attack_data/</code>", body_style),
            Paragraph("Raw Sysmon logs for T1059.001, T1105, T1486 (encryption), T1490 (shadow copy deletion).", body_style),
            Paragraph("<b>Primary source for live pipeline.</b> Raw timestamped telemetry parsed directly into behavioral windows.", body_style)
        ]
    ]

    t = Table(dataset_table_data, colWidths=[110, 180, 214])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))

    # Pipeline Modules
    story.append(Paragraph("5. Telemetry Engineering (<code>pipeline/</code>)", h1_style))
    story.append(Paragraph("<b>• evtx_reader.py:</b> Reads native <code>.evtx</code> files via <code>python-evtx</code> or Splunk XML. Extracts Event ID, process GUID/PID, image, parent image, command line, target file, registry target, and destination IP/port.", bullet_style))
    story.append(Paragraph("<b>• event_filter.py:</b> Filters Sysmon Event IDs 1 (process creation), 3 (network), 7 (DLL load), 11 (file create), 12/13 (registry), 23/26 (file delete). Rejects events lacking timestamps or process GUIDs.", bullet_style))
    story.append(Paragraph("<b>• flatten_encode.py:</b> Path normalization, extension extraction, and suspicious path flag (e.g., <code>Temp</code>, <code>AppData</code>, <code>Downloads</code>, <code>Public</code>).", bullet_style))
    story.append(Paragraph("<b>• temporal_aggregator.py:</b> Core windowing engine. Groups by <code>computer + process_key + 5-second UTC window</code>. Computes 17 features including event counts, unique file/extension/IP counts, and per-Event-ID metrics.", bullet_style))
    story.append(Paragraph("<b>• vectorizer.py:</b> Strips metadata columns, produces numeric feature matrices, and fills missing values with zero.", bullet_style))
    story.append(Paragraph("<b>• watchdog.py:</b> Tracks event arrival intervals. If telemetry stalls for >30 seconds, raises a <code>SENSOR_SILENCED</code> security alert.", bullet_style))

    # Scripts
    story.append(Paragraph("6. Workflow Entry Points (<code>scripts/</code>)", h1_style))
    story.append(Paragraph("<b>• run_pipeline.py:</b> Builds windowed CSV datasets from raw Sysmon log folders. Assigns <code>label=1</code> to attack windows and <code>label=0</code> to benign windows.", bullet_style))
    story.append(Paragraph("<b>• train_baseline.py:</b> Trains baseline models using <b>source-level splits</b> (preventing scenario leakage). Trains Isolation Forest (anomaly screening) and Logistic Regression (class_weight='balanced', max_iter=2000). Reports Precision, Recall, F1, ROC-AUC, FPR, and lead times.", bullet_style))
    story.append(Paragraph("<b>• score_windows.py:</b> Loads baseline artifacts, evaluates sequence windows against the 0.85 risk threshold, and writes HMAC-signed alert containers.", bullet_style))
    story.append(Paragraph("<b>• prepare_live_data.py:</b> Demonstration generator mixing Splunk attack windows with 2,000 synthetic benign windows, training models, creating alerts, and seeding SQLite.", bullet_style))
    story.append(Paragraph("<b>• extract_goodware.py:</b> Utility extracting benign telemetry from CSU, MLRan, and RansomSet.", bullet_style))

    # ML Engine & XAI
    story.append(Paragraph("7. Detection & Explanation Engine (<code>ml_engine/</code>)", h1_style))
    story.append(Paragraph("<b>• risk_engine.py:</b> Scores incoming vectors, computes supervised probability and Isolation Forest anomaly scores, and determines alert triggers.", bullet_style))
    story.append(Paragraph("<b>• lstm/dataset.py:</b> Formats 30-step sequence tensors (150 seconds of history) per process, enabling sequence distinction between isolated commands and full ransomware execution chains.", bullet_style))
    story.append(Paragraph("<b>• lstm/model.py:</b> Bidirectional 2-layer LSTM featuring hidden projection, concatenated Mean + Max pooling across 30 timesteps, and Sigmoid risk output.", bullet_style))
    story.append(Paragraph("<b>• lstm/infer.py:</b> Real-time inference wrapper enforcing <code>weights_only=True</code>, verifying SHA-256 model checksums, restoring scalers, and applying feature mean-padding on short sequences.", bullet_style))
    story.append(Paragraph("<b>• xai/shap_explainer.py:</b> Provides SHAP and PyTorch autograd integrated gradient attributions (<code>|∇x y * x|</code>) to explain feature drivers to SOC analysts.", bullet_style))

    # Backend & Frontend
    story.append(Paragraph("8. Backend API, Persistence & SOC Dashboard", h1_style))
    story.append(Paragraph("<b>• Backend (<code>backend/</code>):</b> Flask application factory (<code>app.py</code>), SQLite ORM models (<code>brds.db</code>), constant-time <code>@require_api_key</code> authentication (<code>auth.py</code>), and REST routes (<code>telemetry_routes</code>, <code>incident_routes</code>, <code>xai_routes</code>).", bullet_style))
    story.append(Paragraph("<b>• Frontend (<code>frontend/</code>):</b> Dark-mode SOC dashboard (<code>index.html</code>, <code>dashboard.css</code>) with real-time Chart.js rolling risk curves (<code>risk_timeline.js</code>), live Sysmon event streams (<code>telemetry_stream.js</code>), active incident logs (<code>incident_log.js</code>), and XAI attribution modals (<code>xai_modal.js</code>).", bullet_style))

    # Containment
    story.append(Paragraph("9. Containment Response Mechanism (<code>containment/</code>)", h1_style))
    story.append(Paragraph("<b>• alert_integrity.py:</b> Generates HMAC-SHA256 digests for alerts and issues single-use <code>.arm_token</code> files.", bullet_style))
    story.append(Paragraph("<b>• trigger_daemon.py:</b> Polls signed alerts every 1.5s, verifies signatures, checks 0.85 risk threshold, validates arm tokens, and invokes PowerShell scripts.", bullet_style))
    story.append(Paragraph("<b>• ContainHost.ps1:</b> Disables active NICs, clears ARP/DNS caches, and applies Windows Firewall block rules. Operates in dry-run mode unless executed with <code>-Armed</code>.", bullet_style))
    story.append(Paragraph("<b>• kill_process_tree.ps1:</b> Recursively terminates ransomware process trees while checking the <code>$PROTECTED_PROCESSES</code> denylist (<code>lsass</code>, <code>csrss</code>, <code>svchost</code>, <code>services</code>, etc.) to prevent BSOD crashes.", bullet_style))

    # Critical Submission Guidelines
    story.append(Spacer(1, 5))
    story.append(Paragraph("10. Important Guidelines & Pre-Submission Review Checklist", h1_style))

    checklist_items = [
        "<b>1. Accuracy & FPR Evaluation:</b> Do not claim operational real-world accuracy or false-positive rates unless evaluated against genuine, clean endpoint Sysmon logs and held-out ransomware scenarios.",
        "<b>2. Synthetic Benign Data Transparency:</b> <code>prepare_live_data.py</code> uses synthetic benign windows for demonstration purposes. Clearly state that synthetic data is for integration testing, not operational benchmark claims.",
        "<b>3. Model Report Requirements:</b> Submissions must specify exact data sources, ransomware families, benign collection methods, source-level split strategies, confusion matrices, and encryption-start lead times.",
        "<b>4. Frontend Simulation Fallbacks:</b> Disclose when demo UI components fall back to simulated data when live backend APIs are disconnected.",
        "<b>5. Disconnected VM Safety Rules:</b> Never test active containment on daily-use host machines. Execute exclusively within isolated virtual machines with snapshots, disabled network bridging, and no shared folders.",
        "<b>6. HMAC Secret Security:</b> Never deploy default HMAC secret keys in production. Set a strong, unique <code>BRDS_ALERT_HMAC_KEY</code> in environment settings.",
        "<b>7. Resolving Inconsistencies:</b> Note that <code>ContainHost.ps1</code> and <code>kill_process_tree.ps1</code> rely on the <code>-Armed</code> parameter switch; verify arm token validation logic prior to live deployment.",
        "<b>8. Recommended Submission Package:</b> Include concise architecture diagrams, dataset governance tables, clean setup commands, virtual environment test reports, dashboard screenshots, dry-run demo recordings, and safety documentation."
    ]

    for item in checklist_items:
        story.append(Paragraph(f"• {item}", bullet_style))

    # Build Document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Successfully generated PDF report at: {pdf_path}")

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "docs/BRDS_System_Technical_Report.pdf"
    build_pdf(target)
    # Also save copy in explanations/ folder
    exp_target = "explanations/BRDS_System_Technical_Report.pdf"
    import shutil
    shutil.copy(target, exp_target)
    print(f"Successfully synced PDF report to: {exp_target}")
