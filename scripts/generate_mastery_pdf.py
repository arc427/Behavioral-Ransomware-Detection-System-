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
        
        # Draw running header/footer on page 2+
        if self._pageNumber > 1:
            # Header
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(colors.HexColor("#1e293b"))
            self.drawString(54, 750, "BRDS-PEC | Complete Project Mastery & Defense Guide")
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#0284c7"))
            self.drawRightString(612 - 54, 750, "Zero-to-Hero Presentation Package")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 742, 612 - 54, 742)

            # Footer
            self.line(54, 48, 612 - 54, 48)
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748b"))
            self.drawString(54, 34, "BEHAVIORAL RANSOMWARE DETECTION SYSTEM — MASTER REVIEW GUIDE")
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
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor("#0284c7"),
        spaceAfter=12
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0f172a"),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=13.5,
        textColor=colors.HexColor("#0369a1"),
        spaceBefore=9,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
        spaceAfter=5
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=4
    )

    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor("#0f172a"),
        backColor=colors.HexColor("#f1f5f9"),
        borderColor=colors.HexColor("#cbd5e1"),
        borderWidth=0.5,
        borderPadding=5,
        spaceBefore=4,
        spaceAfter=6
    )

    story = []

    # Title & Header Banner
    story.append(Paragraph("BRDS-PEC: Behavioral Ransomware Detection System", title_style))
    story.append(Paragraph("Zero-to-Hero Mastery & Reviewer Defense Guide (Complete Explanation Package)", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceBefore=0, spaceAfter=10))

    # Section 1: The Core Concept & Elevator Pitch
    story.append(Paragraph("1. The Core Concept: How to Explain BRDS-PEC in 60 Seconds", h1_style))
    story.append(Paragraph(
        "Imagine a bank security guard. Traditional Antivirus (AV) is like a guard holding a photo album of known criminals (static file hashes). "
        "If a burglar puts on a new mask or changes their clothes (zero-day obfuscation), the static guard lets them walk right in. "
        "<b>BRDS-PEC</b> is a smart AI guard that doesn't care what the burglar looks like—it watches what they <i>do</i>. "
        "If a process starts carrying a crowbar, smashing windows (modifying files), deleting key backups (vssadmin shadow copy wipe), and preparing to lock the vault doors, "
        "BRDS-PEC tackles the burglar and isolates the room within 5 to 15 seconds—<b>before the vault doors are locked (pre-encryption containment)</b>.",
        body_style
    ))

    story.append(Spacer(1, 4))
    story.append(Paragraph("2. Why Traditional EDR & Antivirus Fail", h1_style))
    story.append(Paragraph("• <b>Static Hash Evasion:</b> Attackers re-pack binaries or modify single bits, completely bypassing Signature AV.", bullet_style))
    story.append(Paragraph("• <b>Speed of Ransomware:</b> Ransomware encrypts thousands of files per minute and wipes Windows Shadow Copies (`vssadmin delete shadows /all /quiet`) in under 10 seconds.", bullet_style))
    story.append(Paragraph("• <b>Post-Encryption Alerting:</b> Most commercial tools trigger alerts AFTER ransom notes appear, resulting in total data loss.", bullet_style))
    story.append(Paragraph("• <b>BRDS-PEC Advantage:</b> Operates on 5-second sliding Sysmon behavioral windows using a PyTorch Bidirectional LSTM to halt execution in the <i>pre-encryption phase</i>.", bullet_style))

    # Section 3: 7-Step Architecture Flow
    story.append(Spacer(1, 4))
    story.append(Paragraph("3. End-to-End System Architecture (The 7-Step Pipeline)", h1_style))
    flow_box = (
        "STEP 1: Windows Sysmon Logging (Event IDs 1, 3, 7, 11, 12, 13, 23, 26)<br/>"
        "&nbsp;&nbsp;↓<br/>"
        "STEP 2: Temporal Aggregation (5-second sliding UTC windows -> 17 numeric features)<br/>"
        "&nbsp;&nbsp;↓<br/>"
        "STEP 3: Tier 1 Baseline Screening (Logistic Regression + Isolation Forest, risk >= 0.50)<br/>"
        "&nbsp;&nbsp;↓<br/>"
        "STEP 4: Tier 2 PyTorch LSTM Sequence Classifier (30-step sequence history evaluation)<br/>"
        "&nbsp;&nbsp;↓<br/>"
        "STEP 5: Cryptographic HMAC-SHA256 Alert Container Signing & Arm Token Creation<br/>"
        "&nbsp;&nbsp;↓<br/>"
        "STEP 6: Host Containment (ContainHost.ps1 NIC disable + kill_process_tree.ps1 OS denylist)<br/>"
        "&nbsp;&nbsp;↓<br/>"
        "STEP 7: Live SOC Dashboard Rendering & PyTorch Autograd SHAP XAI PDF Generation"
    )
    story.append(Paragraph(flow_box, code_style))

    # Section 4: The 17 Behavioral Features
    story.append(PageBreak()) # Clean page start
    story.append(Paragraph("4. The 17 Integrated Behavioral Telemetry Features", h1_style))
    story.append(Paragraph("BRDS-PEC evaluates 17 quantitative behavioral features extracted every 5 seconds for every running process:", body_style))

    feat_table_data = [
        [Paragraph("<b>Feature Name</b>", body_style), Paragraph("<b>Sysmon Event IDs</b>", body_style), Paragraph("<b>Behavioral Significance</b>", body_style)],
        [Paragraph("<code>event_count</code>", body_style), Paragraph("All Events", body_style), Paragraph("Total event volume in 5s. Spikes during automated attack execution.", body_style)],
        [Paragraph("<code>unique_images</code>", body_style), Paragraph("Event ID 1", body_style), Paragraph("Number of distinct executable binary paths spawned.", body_style)],
        [Paragraph("<code>unique_files</code>", body_style), Paragraph("IDs 11, 23, 26", body_style), Paragraph("Count of distinct target files created/modified. Spikes during encryption.", body_style)],
        [Paragraph("<code>unique_extensions</code>", body_style), Paragraph("Event ID 11", body_style), Paragraph("Count of new file extensions appended (.WNCRY, .lockbit, .basta).", body_style)],
        [Paragraph("<code>unique_destination_ips</code>", body_style), Paragraph("Event ID 3", body_style), Paragraph("Outbound IP connections for C2 beaconing or SMB network spread.", body_style)],
        [Paragraph("<code>suspicious_path_count</code>", body_style), Paragraph("Event ID 1", body_style), Paragraph("Executions originating from Temp, AppData, Public, or Downloads.", body_style)],
        [Paragraph("<code>file_activity_count</code>", body_style), Paragraph("IDs 11, 23, 26", body_style), Paragraph("Combined file system operation count (create, delete, wipe).", body_style)],
        [Paragraph("<code>registry_activity_count</code>", body_style), Paragraph("IDs 12, 13", body_style), Paragraph("Registry edits for persistence (Run keys) or disabling Defender.", body_style)],
        [Paragraph("<code>network_activity_count</code>", body_style), Paragraph("Event ID 3", body_style), Paragraph("Network socket creation count.", body_style)],
        [Paragraph("<code>event_1..26_count</code>", body_style), Paragraph("1,3,7,11,12,13,23,26", body_style), Paragraph("Individual per-Event-ID frequency counters.", body_style)]
    ]

    t_feat = Table(feat_table_data, colWidths=[130, 110, 264])
    t_feat.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_feat)
    story.append(Spacer(1, 8))

    # Section 5: Codebase File Map
    story.append(Paragraph("5. Codebase File Map & Module Responsibilities", h1_style))
    story.append(Paragraph("• <b><code>pipeline/temporal_aggregator.py</code>:</b> Core 5s sliding windowing engine. Groups Sysmon records by computer, process key, and UTC window.", bullet_style))
    story.append(Paragraph("• <b><code>ml_engine/lstm/model.py</code>:</b> 2-Layer Bidirectional LSTM architecture with concatenated Mean + Max pooling.", bullet_style))
    story.append(Paragraph("• <b><code>ml_engine/lstm/infer.py</code>:</b> Hardened model inference engine with SHA-256 hash checks and `weights_only=True` loading.", bullet_style))
    story.append(Paragraph("• <b><code>containment/alert_integrity.py</code>:</b> HMAC-SHA256 container signing and single-use `.arm_token` generation.", bullet_style))
    story.append(Paragraph("• <b><code>containment/kill_process_tree.ps1</code>:</b> Bottom-up process tree collapse with `$PROTECTED_PROCESSES` OS denylist (`lsass`, `svchost`, `explorer`).", bullet_style))
    story.append(Paragraph("• <b><code>backend/routes/xai_routes.py</code>:</b> Exposes REST API endpoints for PyTorch autograd feature attributions and downloadable PDF reports.", bullet_style))
    story.append(Paragraph("• <b><code>frontend/index.html</code> & <code>js/</code>:</b> Dark-mode SOC dashboard featuring Chart.js rolling risk curves and real-time incident cards.", bullet_style))

    # Section 6: Validation & Benchmark Metrics
    story.append(Spacer(1, 6))
    story.append(Paragraph("6. Empirical Benchmark & Validation Results", h1_style))
    story.append(Paragraph("Evaluated on <b>20,402 behavioral windows</b> (17,617 genuine Windows 11 benign windows from SILRAD-1.0 + 2,785 attack windows from Splunk ATT&CK telemetry):", body_style))

    metrics_table_data = [
        [Paragraph("<b>Metric</b>", body_style), Paragraph("<b>Baseline & LSTM Score</b>", body_style), Paragraph("<b>Evaluation Meaning</b>", body_style)],
        [Paragraph("<b>F1 Score</b>", body_style), Paragraph("<b>99.51%</b>", body_style), Paragraph("Harmonic mean of precision and recall on source-level split.", body_style)],
        [Paragraph("<b>Precision</b>", body_style), Paragraph("<b>99.53%</b>", body_style), Paragraph("High alert quality with minimal false alarms.", body_style)],
        [Paragraph("<b>Recall</b>", body_style), Paragraph("<b>99.48% (100% on LSTM)</b>", body_style), Paragraph("Near-zero missed attacks across all ransomware scenarios.", body_style)],
        [Paragraph("<b>False Positive Rate</b>", body_style), Paragraph("<b>0.22%</b>", body_style), Paragraph("Operational stability on clean Windows 11 endpoint baseline.", body_style)],
        [Paragraph("<b>Held-Out F1 (Unseen Attacks)</b>", body_style), Paragraph("<b>93.14% Average</b>", body_style), Paragraph("Proven generalization to ransomware families never seen in training.", body_style)]
    ]

    t_met = Table(metrics_table_data, colWidths=[140, 130, 234])
    t_met.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#e2e8f0")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_met)

    # Section 7: Top 10 Reviewer Q&A Cheat Sheet
    story.append(PageBreak()) # Clean page start
    story.append(Paragraph("7. Master Reviewer Q&A Cheat Sheet (Top 10 Defense Questions)", h1_style))

    qa_list = [
        ("Q1: How does BRDS-PEC differ from traditional EDR or Antivirus?",
         "Antivirus uses static file hashes easily bypassed by re-packing. EDRs often react after files are encrypted. BRDS-PEC evaluates sliding 5-second Sysmon behavioral windows to halt execution in the pre-encryption phase."),
        
        ("Q2: Why use a 2-Tier Machine Learning architecture?",
         "Tier 1 (Logistic Regression + Isolation Forest) rapidly screens tens of thousands of background events with sub-millisecond latency. Tier 2 (PyTorch Bidirectional LSTM) evaluates 30-step process history only for flagged anomalies, balancing speed and deep sequence accuracy."),

        ("Q3: How do you prove the system detects unseen ransomware families?",
         "We conducted Leave-One-Scenario-Out Cross-Validation (`scenario_holdout_eval()`). The model achieved 93.14% Average F1 on attack scenarios completely held out from training."),

        ("Q4: How do you prevent auto-containment from causing Blue Screen of Death (BSOD)?",
         "`kill_process_tree.ps1` checks a `$PROTECTED_PROCESSES` denylist (`lsass`, `csrss`, `svchost`, `explorer`, `services`) before process tree termination."),

        ("Q5: What stops malware from forging fake security alerts?",
         "`containment/alert_integrity.py` signs all alert containers using HMAC-SHA256 and issues single-use `.arm_token` authorization files."),

        ("Q6: How is the PyTorch model protected against deserialization RCE attacks?",
         "`ml_engine/lstm/infer.py` loads model checkpoints using `torch.load(weights_only=True)` and verifies the SHA-256 hash manifest before loading."),

        ("Q7: What features spike during a ransomware attack?",
         "`unique_files`, `unique_extensions` (.WNCRY, .lockbit, .basta), `file_activity_count`, and `event_1_count` (spawning `vssadmin` or `cmd.exe`)."),

        ("Q8: Why does Analyzed Events start at 24,000+ on the dashboard?",
         "An enterprise endpoint agent processes background events continuously. The counter reflects cumulative historical events stored in the `brds.db` database."),

        ("Q9: How does the Explainable AI (XAI) feature work?",
         "It uses PyTorch Autograd integrated gradients (|∇x y * x|) to compute exact numerical feature contributions, which can be downloaded as a PDF report."),

        ("Q10: Is there data loss during auto-containment?",
         "No. Because containment executes in the pre-encryption phase (5-15s), user files on disk remain unencrypted. Only memory buffers in the killed malicious process tree are terminated.")
    ]

    for q, a in qa_list:
        story.append(Paragraph(f"<b>{q}</b>", h2_style))
        story.append(Paragraph(f"<b>Answer:</b> {a}", body_style))
        story.append(Spacer(1, 2))

    # Section 8: Top 5 Core Presentation Code Snippets
    story.append(PageBreak())
    story.append(Paragraph("8. Top 5 Core Presentation Code Snippets", h1_style))
    story.append(Paragraph("Include these key code blocks in your presentation slides to demonstrate technical depth:", body_style))

    # Snippet 1
    story.append(Paragraph("<b>Snippet 1: PyTorch Bidirectional LSTM Model (<code>ml_engine/lstm/model.py</code>)</b>", h2_style))
    c1 = (
        "class LSTMClassifier(nn.Module):<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;def __init__(self, input_dim: int = 17, hidden_dim: int = 64, num_layers: int = 2):<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;super().__init__()<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;self.input_projection = nn.Linear(input_dim, hidden_dim)<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;self.lstm = nn.LSTM(hidden_dim, hidden_dim, num_layers=num_layers, batch_first=True, bidirectional=True)<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;self.fc = nn.Linear(hidden_dim * 4, 1) # Mean + Max pooling output<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;self.sigmoid = nn.Sigmoid()<br/><br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;def forward(self, x: torch.Tensor) -> torch.Tensor:<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;projected = self.input_projection(x)<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;lstm_out, _ = self.lstm(projected)<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;mean_pool = lstm_out.mean(dim=1)<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;max_pool = lstm_out.max(dim=1).values<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;pooled = torch.cat([mean_pool, max_pool], dim=1)<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return self.sigmoid(self.fc(pooled))"
    )
    story.append(Paragraph(c1, code_style))

    # Snippet 2
    story.append(Paragraph("<b>Snippet 2: RCE-Hardened Model Checkpoint Verification (<code>ml_engine/lstm/infer.py</code>)</b>", h2_style))
    c2 = (
        "def load_checkpoint(model_path: Path):<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;# Verify SHA-256 checksum manifest before loading<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;expected_hash = model_path.with_suffix('.sha256').read_text().strip()<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;actual_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;if not hmac.compare_digest(expected_hash, actual_hash):<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;raise ValueError('Model SHA-256 checksum mismatch (tampered model)')<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;# RCE Protection: load weights only (disallows arbitrary pickle code)<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;checkpoint = torch.load(model_path, weights_only=True)<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;scaler = joblib.load(model_path.with_suffix('.scaler.joblib'))<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;return checkpoint, scaler"
    )
    story.append(Paragraph(c2, code_style))

    # Snippet 3
    story.append(Paragraph("<b>Snippet 3: Cryptographic HMAC-SHA256 Alert Container Signing (<code>containment/alert_integrity.py</code>)</b>", h2_style))
    c3 = (
        "def sign_alerts(alerts: list) -> str:<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;payload_str = json.dumps(alerts, separators=(',', ':'), sort_keys=True)<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;key = os.environ.get('BRDS_ALERT_HMAC_KEY').encode('utf-8')<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;signature = hmac.new(key, payload_str.encode('utf-8'), hashlib.sha256).hexdigest()<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;return json.dumps({'alerts': alerts, 'sig': signature}, indent=2)"
    )
    story.append(Paragraph(c3, code_style))

    # Snippet 4
    story.append(Paragraph("<b>Snippet 4: OS Protected Process Denylist & Containment Safety (<code>containment/kill_process_tree.ps1</code>)</b>", h2_style))
    c4 = (
        "# Protected Windows critical OS processes<br/>"
        "$PROTECTED_PROCESSES = @('lsass', 'csrss', 'smss', 'wininit', 'winlogon', 'services', 'system', 'svchost', 'explorer', 'spoolsv', 'dwm')<br/><br/>"
        "foreach ($child in $children) {<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;if ($PROTECTED_PROCESSES -notcontains $child.Name.Replace('.exe','')) {<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Stop-ProcessTree -targetPid $child.ProcessId   # Recurse child tree<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Stop-Process -Id $child.ProcessId -Force       # Terminate ransomware process<br/>"
        "&nbsp;&nbsp;&nbsp;&nbsp;}<br/>"
        "}"
    )
    story.append(Paragraph(c4, code_style))

    # Snippet 5
    story.append(Paragraph("<b>Snippet 5: PyTorch Autograd Integrated Gradient XAI (<code>ml_engine/xai/shap_explainer.py</code>)</b>", h2_style))
    c5 = (
        "self.lstm_infer.model.zero_grad()<br/>"
        "input_tensor = torch.tensor(features_scaled, dtype=torch.float32).unsqueeze(0).requires_grad_(True)<br/>"
        "output = self.lstm_infer.model(input_tensor)<br/>"
        "output.backward()<br/><br/>"
        "grads = input_tensor.grad.detach().numpy()[0]<br/>"
        "grad_x_input = np.abs(grads * features_scaled).mean(axis=0)<br/>"
        "attributions = [{'feature_name': name, 'importance_value': float(val)} for name, val in zip(self.lstm_infer.feature_names, grad_x_input)]"
    )
    story.append(Paragraph(c5, code_style))

    # Section 9: Step-by-Step Presentation & Live Demo Playbook
    story.append(Spacer(1, 6))
    story.append(Paragraph("9. Step-by-Step Presentation & Live Demo Playbook", h1_style))
    story.append(Paragraph("Follow this sequence during your live presentation to wowed evaluators:", body_style))
    story.append(Paragraph("1. <b>Start Server:</b> Execute <code>$env:BRDS_ALLOW_INSECURE_DEV_HMAC='1'; python backend/app.py</code>.", bullet_style))
    story.append(Paragraph("2. <b>Open Dashboard:</b> Navigate to <code>http://127.0.0.1:5000/</code> in Chrome.", bullet_style))
    story.append(Paragraph("3. <b>Highlight Baseline:</b> Show Analyzed Events (20,402+ windows) and the green low risk score timeline.", bullet_style))
    story.append(Paragraph("4. <b>Demonstrate Threat Detection:</b> Scroll to Active Security Incidents, showing ransomware cards (BLACKBASTA, WANNACRY, LOCKBIT) with 0.85+ risk score.", bullet_style))
    story.append(Paragraph("5. <b>Explain XAI & Download PDF:</b> Click `SHAP Analysis` on an incident card, show the positive feature attributions (file activity & extension spriting), and click `Download PDF Report` to show the generated ReportLab document.", bullet_style))
    story.append(Paragraph("6. <b>Verify Automated Tests:</b> Run <code>python -m pytest -v</code> in the terminal to show **30 / 30 passing unit tests**.", bullet_style))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Successfully generated complete mastery PDF report at: {pdf_path}")

if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else "docs/BRDS_PEC_Complete_Mastery_Guide.pdf"
    build_pdf(target)
