// Live Telemetry Event Stream Handler
document.addEventListener("DOMContentLoaded", () => {
    const logContainer = document.getElementById('telemetry-log');
    const rateBadge = document.getElementById('telemetry-rate');
    const totalEventsEl = document.getElementById('metric-total-events');
    const anomaliesEl = document.getElementById('metric-anomalies');
    
    let totalProcessed = 24150;
    let anomalyCount = 142;
    
    // Formats ISO or Epoch timestamp into local HH:MM:SS
    function formatTime(val) {
        if (!val) return new Date().toLocaleTimeString();
        let d;
        if (typeof val === 'number') {
            d = new Date(val * 1000);
        } else {
            d = new Date(val);
        }
        return d.toLocaleTimeString();
    }

    function createTelemetryRow(item) {
        const row = document.createElement('div');
        row.className = 'telemetry-item';
        
        const timestamp = formatTime(item.window_start || item.timestamp);
        const host = item.computer || 'BRDS-WIN11-SEC';
        
        // Highlight active event kinds
        const hasFile = item.file_activity_count > 0;
        const hasReg = item.registry_activity_count > 0;
        const hasNet = item.network_activity_count > 0;
        const hasProc = item.event_1_count > 0;
        
        // Shorten image path
        let imageName = item.process_key || 'system_idle';
        if (imageName.includes('\\')) {
            imageName = imageName.substring(imageName.lastIndexOf('\\') + 1);
        }
        
        row.innerHTML = `
            <div class="telemetry-meta">
                <span>[${timestamp}]</span>
                <span>${host}</span>
            </div>
            <div class="telemetry-process">
                <i data-lucide="terminal" style="width: 12px; height: 12px; display: inline; vertical-align: middle; margin-right: 4px; color: var(--accent-mint);"></i>
                ${imageName}
            </div>
            <div class="telemetry-counts">
                <span class="count-badge ${hasProc ? 'active' : ''}">PROC:${item.event_1_count || 0}</span>
                <span class="count-badge ${hasFile ? 'active' : ''}">FILE:${item.file_activity_count || 0}</span>
                <span class="count-badge ${hasReg ? 'active' : ''}">REG:${item.registry_activity_count || 0}</span>
                <span class="count-badge ${hasNet ? 'active' : ''}">NET:${item.network_activity_count || 0}</span>
            </div>
        `;
        
        return row;
    }

    function appendTelemetry(item) {
        // Remove empty state
        const emptyState = logContainer.querySelector('[data-lucide="loader-2"]');
        if (emptyState) {
            logContainer.innerHTML = '';
        }
        
        const row = createTelemetryRow(item);
        logContainer.insertBefore(row, logContainer.firstChild);
        
        // Keep only top 40 events in memory
        if (logContainer.children.length > 40) {
            logContainer.removeChild(logContainer.lastChild);
        }
        
        lucide.createIcons({attrs: {style: 'width: 12px; height: 12px; display: inline; vertical-align: middle; margin-right: 4px; color: var(--accent-mint);'}});
    }

    // Fetch telemetry from backend
    async function updateTelemetryStream() {
        try {
            const response = await fetch('/api/telemetry?limit=15');
            const data = await response.json();
            
            if (data.items && data.items.length > 0) {
                // Clear and repopulate to represent latest sliding window
                logContainer.innerHTML = '';
                
                // Telemetry rate: calculate events processed
                rateBadge.innerText = `${(data.total / 10).toFixed(1)} ev/s`;
                totalEventsEl.innerText = data.total;
                
                // Count anomalies (where anomaly score is high or risk score is elevated)
                let anomalies = 0;
                data.items.forEach(item => {
                    appendTelemetry(item);
                    if (item.anomaly_score > 0.0 || item.risk_score >= 0.5) {
                        anomalies++;
                    }
                });
                
                anomaliesEl.innerText = Math.max(anomalies, parseInt(anomaliesEl.innerText || 0));
                return;
            }
        } catch (e) {
            // API offline - continue to simulation fallback
        }
        
        simulateLiveTelemetry();
    }

    // Simulated Event Log Generator
    const mockProcesses = [
        'C:\\Windows\\System32\\svchost.exe',
        'C:\\Windows\\explorer.exe',
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
        'C:\\Windows\\System32\\lsass.exe',
        'C:\\Windows\\System32\\services.exe',
        'C:\\Program Files\\Windows Defender\\MsMpEng.exe',
        'C:\\Windows\\System32\\cmd.exe',
        'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
    ];

    function simulateLiveTelemetry() {
        totalProcessed++;
        totalEventsEl.innerText = totalProcessed;
        
        // Update rate badge
        rateBadge.innerText = `${(0.5 + Math.random() * 2.5).toFixed(1)} ev/s`;
        
        // Randomly pick a process
        const randomProc = mockProcesses[Math.floor(Math.random() * mockProcesses.length)];
        
        const isMaliciousScenario = window.riskChart && window.riskChart.data.datasets[0].data[29] >= 0.5;
        
        let item;
        if (isMaliciousScenario) {
            // Spiking ransomware-like counts
            item = {
                timestamp: new Date().toISOString(),
                computer: 'BRDS-WIN11-SEC',
                process_key: 'C:\\Users\\victim\\AppData\\Local\\Temp\\wannacry.exe',
                event_1_count: 1,
                file_activity_count: 12 + Math.floor(Math.random() * 25),
                registry_activity_count: 5 + Math.floor(Math.random() * 10),
                network_activity_count: Math.random() > 0.5 ? 1 : 0
            };
            
            anomalyCount++;
            anomaliesEl.innerText = anomalyCount;
        } else {
            // Regular system traffic
            item = {
                timestamp: new Date().toISOString(),
                computer: 'BRDS-WIN11-SEC',
                process_key: randomProc,
                event_1_count: Math.random() > 0.7 ? 1 : 0,
                file_activity_count: Math.random() > 0.85 ? Math.floor(Math.random() * 3) : 0,
                registry_activity_count: Math.random() > 0.6 ? Math.floor(Math.random() * 4) : 0,
                network_activity_count: Math.random() > 0.8 ? 1 : 0
            };
        }
        
        appendTelemetry(item);
    }

    // Initial fetch
    updateTelemetryStream();
    
    // Poll/Simulate every 1 second
    setInterval(updateTelemetryStream, 1000);
});
