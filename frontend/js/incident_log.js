// Active Security Incidents Log & Response Actions
document.addEventListener("DOMContentLoaded", () => {
    const listContainer = document.getElementById('incident-list');
    const metricIncidents = document.getElementById('metric-incidents');
    const containmentDot = document.getElementById('containment-dot');
    const containmentStatusText = document.getElementById('containment-status-text');
    const clearIncidentsBtn = document.getElementById('clear-incidents-btn');
    
    let activeIncidents = [];
    let threatSpikeDetected = false;
    let warningSpikeDetected = false;
    let currentActiveIncident = null;
    
    function createIncidentCard(incident) {
        const card = document.createElement('div');
        const isAmber = incident.risk_score < 0.85;
        card.className = `incident-card ${isAmber ? 'amber-alert' : ''}`;
        card.setAttribute('data-id', incident.id);
        
        const timestamp = new Date(incident.timestamp || Date.now()).toLocaleTimeString();
        const score = (incident.risk_score || 0.88).toFixed(2);
        
        card.innerHTML = `
            <div class="incident-header">
                <span class="incident-family">${incident.ransomware_family ? incident.ransomware_family.toUpperCase() : 'UNKNOWN'}</span>
                <span class="incident-score">${score} RISK</span>
            </div>
            <div class="incident-details">
                <div><span class="detail-label">Time:</span> <span class="detail-val">${timestamp}</span></div>
                <div><span class="detail-label">Host:</span> <span class="detail-val">${incident.computer || 'BRDS-WIN11-SEC'}</span></div>
                <div><span class="detail-label">Status:</span> <span id="status-${incident.id}" class="detail-val" style="color: ${incident.status === 'CONTAINED' ? 'var(--accent-mint)' : 'var(--accent-crimson)'}">${incident.status || 'ACTIVE'}</span></div>
                <div><span class="detail-label">Process ID:</span> <span class="detail-val">${incident.process_id || '9024'}</span></div>
            </div>
            <div class="incident-actions">
                <button class="btn btn-primary xai-btn">SHAP Analysis</button>
                ${incident.status !== 'CONTAINED' ? `<button class="btn btn-danger isolate-btn">Isolate Host</button>` : ''}
            </div>
        `;
        
        // Bind click events
        card.querySelector('.xai-btn').addEventListener('click', (e) => {
            e.stopPropagation();
            if (window.showXAI) {
                window.showXAI(incident);
            }
        });
        
        const isolateBtn = card.querySelector('.isolate-btn');
        if (isolateBtn) {
            isolateBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                isolateHost(incident.id);
            });
        }
        
        return card;
    }

    function isolateHost(id, isAuto = false) {
        // Find incident
        const idx = activeIncidents.findIndex(inc => inc.id === id);
        if (idx !== -1) {
            activeIncidents[idx].status = isAuto ? 'CONTAINED (AUTO)' : 'CONTAINED';
            
            // Visual feedback
            const statusVal = document.getElementById(`status-${id}`);
            if (statusVal) {
                statusVal.innerText = activeIncidents[idx].status;
                statusVal.style.color = 'var(--accent-mint)';
            }
            
            // Remove Isolate button
            const card = listContainer.querySelector(`[data-id="${id}"]`);
            if (card) {
                const isolateBtn = card.querySelector('.isolate-btn');
                if (isolateBtn) isolateBtn.remove();
            }
            
            // Pulse status engine active
            containmentDot.className = 'dot danger';
            containmentStatusText.innerText = isAuto ? 'Host Isolated (Auto Containment)' : 'Host Isolated (Manual Containment)';
            containmentStatusText.style.color = 'var(--accent-crimson)';
            
            setTimeout(() => {
                containmentDot.className = 'dot pulse';
                containmentStatusText.innerText = 'Containment Engine: Active';
                containmentStatusText.style.color = 'var(--text-white)';
            }, 5000);
        }
    }

    function renderIncidents() {
        if (activeIncidents.length === 0) {
            listContainer.innerHTML = `
                <div class="telemetry-item" style="text-align: center; color: var(--text-muted); padding: 2rem 0;">
                    <i data-lucide="shield-check" style="color: var(--accent-mint); width: 36px; height: 36px; margin-bottom: 0.5rem;"></i>
                    <p>No active threats detected.</p>
                </div>
            `;
            metricIncidents.innerText = '0';
            lucide.createIcons();
            return;
        }
        
        listContainer.innerHTML = '';
        activeIncidents.forEach(inc => {
            const card = createIncidentCard(inc);
            listContainer.appendChild(card);
        });
        
        metricIncidents.innerText = activeIncidents.length;
    }

    async function fetchAlerts() {
        try {
            const response = await fetch('/api/alerts');
            const data = await response.json();
            
            if (data.items && data.items.length > 0) {
                activeIncidents = data.items.map(item => ({
                    id: item.window_start || item.timestamp,
                    timestamp: item.timestamp || Date.now(),
                    computer: item.computer || 'BRDS-WIN11-SEC',
                    ransomware_family: item.technique_id || 'Ransomware',
                    risk_score: item.risk_score || 0.90,
                    process_id: item.process_key ? item.process_key.split(':').pop() : '9024',
                    status: item.status || 'ACTIVE'
                }));
                renderIncidents();
                return;
            }
        } catch (e) {
            // API offline - continue to simulation
        }
        
        checkSimulatedThreats();
    }

    function showToast(incident) {
        const toastContainer = document.getElementById('toast-container');
        if (!toastContainer) return;
        
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.innerHTML = `
            <div style="font-weight: bold; margin-bottom: 0.25rem; display: flex; align-items: center; gap: 0.5rem;">
                <i data-lucide="shield-alert" style="color: var(--accent-crimson); width: 16px; height: 16px;"></i>
                [AUTOMATIC CONTAINMENT TRIGGERED]
            </div>
            <div style="font-size: 0.85rem; color: var(--text-white);">
                Ransomware threat <strong>${incident.ransomware_family.toUpperCase()}</strong> (Risk: ${incident.risk_score.toFixed(2)}) detected on host <strong>${incident.computer}</strong>.
            </div>
            <div style="font-size: 0.8rem; color: var(--accent-mint); margin-top: 0.5rem; font-weight: 500;">
                ✓ Network adapter disabled.<br>
                ✓ Malicious process tree (PID: ${incident.process_id}) terminated.
            </div>
        `;
        toastContainer.appendChild(toast);
        
        // Initialize lucide inside toast
        lucide.createIcons();
        
        // Auto remove toast after 6 seconds
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.5s ease';
            setTimeout(() => toast.remove(), 500);
        }, 6000);
    }

    // Monitor the chart dataset to inject simulated threats when risk score spikes
    const families = ['wannacry', 'lockbit', 'ryuk', 'sodinokibi', 'blackbasta'];
    function checkSimulatedThreats() {
        if (!window.riskChart) return;
        
        const currentScores = window.riskChart.data.datasets[0].data;
        const latestScore = currentScores[currentScores.length - 1];
        
        // 1. Escalate to Warning Zone (>= 0.60 but < 0.85)
        if (latestScore >= 0.60 && latestScore < 0.85 && !warningSpikeDetected) {
            warningSpikeDetected = true;
            
            // Spawn a warning incident
            const randFamily = families[Math.floor(Math.random() * families.length)];
            currentActiveIncident = {
                id: 'INC-' + Math.floor(100000 + Math.random() * 900000),
                timestamp: new Date().toISOString(),
                computer: 'BRDS-WIN11-SEC',
                ransomware_family: randFamily,
                risk_score: latestScore,
                process_id: Math.floor(3000 + Math.random() * 6000),
                status: 'MONITORING'
            };
            
            activeIncidents.unshift(currentActiveIncident);
            renderIncidents();
            
            // Set Amber UI Warning
            containmentDot.className = 'dot warning';
            containmentStatusText.innerText = 'Warning: Anomalous Activity Detected (Host Monitored)';
            containmentStatusText.style.color = 'var(--accent-amber)';
        }
        
        // 2. Escalate to Critical Containment Zone (>= 0.85)
        else if (latestScore >= 0.85 && !threatSpikeDetected) {
            threatSpikeDetected = true;
            
            if (currentActiveIncident) {
                // Upgrade the warning incident to critical
                const idx = activeIncidents.findIndex(inc => inc.id === currentActiveIncident.id);
                if (idx !== -1 && activeIncidents[idx].status === 'MONITORING') {
                    activeIncidents[idx].status = 'ACTIVE';
                    activeIncidents[idx].risk_score = latestScore;
                    currentActiveIncident = activeIncidents[idx];
                }
            } else {
                // If warning was skipped, create a new critical incident
                const randFamily = families[Math.floor(Math.random() * families.length)];
                currentActiveIncident = {
                    id: 'INC-' + Math.floor(100000 + Math.random() * 900000),
                    timestamp: new Date().toISOString(),
                    computer: 'BRDS-WIN11-SEC',
                    ransomware_family: randFamily,
                    risk_score: latestScore,
                    process_id: Math.floor(3000 + Math.random() * 6000),
                    status: 'ACTIVE'
                };
                activeIncidents.unshift(currentActiveIncident);
            }
            
            renderIncidents();
            
            // Check Auto-Containment Toggle
            const autoContainToggle = document.getElementById('auto-contain-toggle');
            if (autoContainToggle && autoContainToggle.checked) {
                // Trigger auto containment
                setTimeout(() => {
                    showToast(currentActiveIncident);
                    isolateHost(currentActiveIncident.id, true);
                }, 1000);
            } else {
                // Set Crimson UI Danger (Manual contain required)
                containmentDot.className = 'dot danger';
                containmentStatusText.innerText = 'Critical: Active Threat Detected (Containment Required)';
                containmentStatusText.style.color = 'var(--accent-crimson)';
            }
        }
        
        // 3. Reset state when threat level returns to normal (< 0.20)
        else if (latestScore < 0.20 && (threatSpikeDetected || warningSpikeDetected)) {
            threatSpikeDetected = false;
            warningSpikeDetected = false;
            currentActiveIncident = null;
            
            // Reset header indicators
            containmentDot.className = 'dot pulse';
            containmentStatusText.innerText = 'Containment Engine: Active';
            containmentStatusText.style.color = 'var(--text-white)';
        }
    }

    clearIncidentsBtn.addEventListener('click', () => {
        activeIncidents = [];
        renderIncidents();
    });

    // Poll/Monitor every 1.5 seconds
    setInterval(fetchAlerts, 1500);
});
