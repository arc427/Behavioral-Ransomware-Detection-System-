// Explainable AI (XAI) Modal handler
document.addEventListener("DOMContentLoaded", () => {
    const modal = document.getElementById('xai-modal');
    const closeBtn = document.getElementById('modal-close-btn');
    const container = document.getElementById('shap-bars-container');
    
    // Elements to populate
    const idVal = document.getElementById('xai-incident-id');
    const hostVal = document.getElementById('xai-host');
    const familyVal = document.getElementById('xai-family');
    const scoreVal = document.getElementById('xai-score');
    
    // Close modal
    closeBtn.addEventListener('click', () => {
        modal.classList.remove('show');
    });
    
    // Close on click outside modal container
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.remove('show');
        }
    });

    // Custom features based on ransomware family
    const familySHAPData = {
        wannacry: [
            { feature: 'file_activity_count (mass writes)', value: 0.48, isPositive: true },
            { feature: 'unique_extensions (new .WNCRY extensions)', value: 0.35, isPositive: true },
            { feature: 'event_1_count (vssadmin delete shadows)', value: 0.32, isPositive: true },
            { feature: 'suspicious_path_count (executes from Temp)', value: 0.28, isPositive: true },
            { feature: 'network_activity_count (connection to port 445)', value: 0.15, isPositive: true },
            { feature: 'system_executable (not a system folder)', value: -0.12, isPositive: false }
        ],
        lockbit: [
            { feature: 'file_activity_count (mass file writes)', value: 0.52, isPositive: true },
            { feature: 'event_11_count (writes of .lockbit extension)', value: 0.44, isPositive: true },
            { feature: 'registry_activity_count (disabling defender)', value: 0.31, isPositive: true },
            { feature: 'event_1_count (powershell commands executed)', value: 0.24, isPositive: true },
            { feature: 'network_activity_count (IP transfer)', value: 0.12, isPositive: true },
            { feature: 'system_executable (non-system path)', value: -0.09, isPositive: false }
        ],
        ryuk: [
            { feature: 'event_1_count (vssadmin shadow copy deletion)', value: 0.49, isPositive: true },
            { feature: 'file_activity_count (encrypting files)', value: 0.46, isPositive: true },
            { feature: 'registry_activity_count (run registry persistence)', value: 0.28, isPositive: true },
            { feature: 'suspicious_path_count (Appdata/Local temp execution)', value: 0.22, isPositive: true },
            { feature: 'unique_images (non-whitelisted executable)', value: 0.18, isPositive: true },
            { feature: 'system_executable (non-system directory)', value: -0.14, isPositive: false }
        ],
        sodinokibi: [
            { feature: 'file_activity_count (encryption rate)', value: 0.54, isPositive: true },
            { feature: 'unique_extensions (unique random extensions)', value: 0.39, isPositive: true },
            { feature: 'event_1_count (process spawning cmd.exe)', value: 0.29, isPositive: true },
            { feature: 'registry_activity_count (modifying user settings)', value: 0.25, isPositive: true },
            { feature: 'network_activity_count (command & control callback)', value: 0.14, isPositive: true },
            { feature: 'system_executable (unregistered binary)', value: -0.10, isPositive: false }
        ]
    };

    const defaultSHAPData = [
        { feature: 'file_activity_count (high file system modifications)', value: 0.42, isPositive: true },
        { feature: 'event_1_count (suspicious subprocess creation)', value: 0.35, isPositive: true },
        { feature: 'suspicious_path_count (executes from local temp)', value: 0.27, isPositive: true },
        { feature: 'registry_activity_count (persistence creation)', value: 0.19, isPositive: true },
        { feature: 'system_executable (binary path verification)', value: -0.11, isPositive: false }
    ];

    function renderSHAPBars(features) {
        container.innerHTML = '';
        
        features.forEach(feat => {
            const row = document.createElement('div');
            row.className = 'shap-bar-row';
            
            const pct = Math.abs(feat.value * 100).toFixed(0) + '%';
            const displayVal = (feat.isPositive ? '+' : '-') + feat.value.toFixed(2);
            const valClass = feat.isPositive ? 'positive' : 'negative';
            const barClass = feat.isPositive ? 'positive' : 'negative';
            
            row.innerHTML = `
                <div class="shap-feature-name" title="${feat.feature}">${feat.feature}</div>
                <div class="shap-bar-container">
                    <div class="shap-bar ${barClass}" style="width: ${pct}; float: ${feat.isPositive ? 'left' : 'right'}"></div>
                </div>
                <div class="shap-val ${valClass}">${displayVal}</div>
            `;
            
            container.appendChild(row);
        });
    }

    // Expose function globally to trigger from incident_log
    window.showXAI = async (incident) => {
        // Populate header details
        idVal.innerText = incident.id;
        hostVal.innerText = incident.computer || 'BRDS-WIN11-SEC';
        familyVal.innerText = (incident.ransomware_family || 'UNKNOWN').toUpperCase();
        scoreVal.innerText = (incident.risk_score || 0.88).toFixed(2);
        
        // Show modal
        modal.classList.add('show');
        
        // Try fetching explanation from backend
        try {
            const response = await fetch(`/api/explanations/${incident.id}`);
            if (response.ok) {
                const data = await response.json();
                if (data.available && data.features) {
                    renderSHAPBars(data.features);
                    return;
                }
            }
        } catch (e) {
            // Backend offline or error - use simulated SHAP
        }
        
        // Simulation fallback based on ransomware family
        const familyName = (incident.ransomware_family || '').toLowerCase();
        const shapData = familySHAPData[familyName] || defaultSHAPData;
        renderSHAPBars(shapData);
    };
});
