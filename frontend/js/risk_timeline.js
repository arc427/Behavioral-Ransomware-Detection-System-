// Real-time Risk Timeline Chart using Chart.js
document.addEventListener("DOMContentLoaded", () => {
    const ctx = document.getElementById('riskChart').getContext('2d');
    
    // Gradient for the risk area chart
    const mintGradient = ctx.createLinearGradient(0, 0, 0, 400);
    mintGradient.addColorStop(0, 'rgba(13, 245, 175, 0.25)');
    mintGradient.addColorStop(1, 'rgba(13, 245, 175, 0.00)');

    const chartConfig = {
        type: 'line',
        data: {
            labels: Array(30).fill(''), // 30 rolling windows
            datasets: [
                {
                    label: 'Risk Score',
                    data: Array(30).fill(0.05), // Start low
                    borderColor: '#0df5af',
                    borderWidth: 2,
                    backgroundColor: mintGradient,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 5,
                    pointBackgroundColor: '#0df5af',
                    pointBorderColor: '#e0fbfc'
                },
                {
                    label: 'Warning Threshold (0.60)',
                    data: Array(30).fill(0.60),
                    borderColor: '#fca311',
                    borderWidth: 1.2,
                    borderDash: [5, 5],
                    fill: false,
                    pointRadius: 0,
                    pointHoverRadius: 0
                },
                {
                    label: 'Containment Threshold (0.85)',
                    data: Array(30).fill(0.85),
                    borderColor: '#ff2a5f',
                    borderWidth: 1.5,
                    borderDash: [5, 5],
                    fill: false,
                    pointRadius: 0,
                    pointHoverRadius: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    labels: {
                        color: '#8a9a97',
                        font: { family: 'Outfit', size: 11 }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(8, 14, 13, 0.95)',
                    titleColor: '#e0fbfc',
                    bodyColor: '#e0fbfc',
                    borderColor: 'rgba(13, 245, 175, 0.2)',
                    borderWidth: 1,
                    titleFont: { family: 'Outfit', weight: 'bold' },
                    bodyFont: { family: 'Outfit' },
                    displayColors: false,
                    callbacks: {
                        label: function(context) {
                            return `Risk: ${context.parsed.y.toFixed(2)}`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { display: false }
                },
                y: {
                    min: 0,
                    max: 1.0,
                    ticks: {
                        color: '#8a9a97',
                        font: { family: 'Outfit', size: 10 },
                        stepSize: 0.2
                    },
                    grid: {
                        color: 'rgba(138, 154, 151, 0.08)'
                    }
                }
            }
        }
    };

    const riskChart = new Chart(ctx, chartConfig);
    window.riskChart = riskChart; // Make accessible to other modules

    let timeIndex = 0;
    
    // Fetch live telemetry from the backend API
    async function fetchTelemetry() {
        try {
            const response = await fetch('/api/telemetry?limit=30');
            const data = await response.json();
            
            if (data.items && data.items.length > 0) {
                // Reverse items if they are returned newest-first, to show chronologically
                const items = [...data.items].reverse();
                
                // Get risk scores
                const riskData = items.map(item => item.risk_score !== undefined ? item.risk_score : 0.05);
                const labels = items.map((_, i) => `W-${items.length - i}`);
                
                // Update chart
                riskChart.data.labels = labels;
                riskChart.data.datasets[0].data = riskData;
                riskChart.data.datasets[1].data = Array(riskData.length).fill(0.60);
                riskChart.data.datasets[2].data = Array(riskData.length).fill(0.85);
                riskChart.update();
                
                // Update metrics summary
                document.getElementById('metric-total-events').innerText = data.total || items.length;
                const avgRisk = riskData.reduce((a, b) => a + b, 0) / riskData.length;
                document.getElementById('metric-avg-risk').innerText = avgRisk.toFixed(2);
                
                // Update average risk color class
                const avgRiskEl = document.getElementById('metric-avg-risk');
                avgRiskEl.className = 'metric-value ' + (avgRisk >= 0.85 ? 'crimson' : avgRisk >= 0.60 ? 'amber' : 'mint');
                
                return;
            }
        } catch (e) {
            // Backend offline or error; fallback to simulation
        }
        
        // Simulation Fallback
        simulateLiveUpdate();
    }

    // High fidelity simulator for dry-run threat profiling
    function simulateLiveUpdate() {
        const currentData = riskChart.data.datasets[0].data;
        currentData.shift();
        
        timeIndex++;
        
        // Normal background noise (0.01 - 0.15)
        let newScore = 0.02 + Math.random() * 0.08;
        
        // Generate mock spike scenarios every 40-50 intervals to showcase containment
        const cycle = timeIndex % 60;
        if (cycle > 25 && cycle <= 30) {
            // Scenario escalates
            newScore = 0.3 + (cycle - 25) * 0.12 + Math.random() * 0.05;
        } else if (cycle > 30 && cycle <= 34) {
            // Ransomware behavior starts, crosses containment threshold
            newScore = 0.88 + Math.random() * 0.08;
        } else if (cycle === 35) {
            // Containment event triggered, threat terminated, drops back
            newScore = 0.05;
        }
        
        currentData.push(newScore);
        
        // Shift labels
        riskChart.data.labels.shift();
        riskChart.data.labels.push(`T-${30 - currentData.length + timeIndex}`);
        riskChart.update();
        
        // Calculate dynamic summary stats
        const avg = currentData.reduce((a, b) => a + b, 0) / currentData.length;
        document.getElementById('metric-avg-risk').innerText = avg.toFixed(2);
        const avgRiskEl = document.getElementById('metric-avg-risk');
        avgRiskEl.className = 'metric-value ' + (avg >= 0.85 ? 'crimson' : avg >= 0.60 ? 'amber' : 'mint');
    }

    // Initial load
    fetchTelemetry();
    
    // Poll every 2 seconds
    setInterval(fetchTelemetry, 2000);
});
