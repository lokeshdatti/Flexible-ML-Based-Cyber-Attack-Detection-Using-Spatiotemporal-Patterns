// Global variables
let sessionId = null;
let totalRows = 0;
let currentRow = 0;
let isPaused = false;
let speed = 1;
let threatCount = 0;
let confidenceSum = 0;
let processedCount = 0;
let attackCounts = {};
let dowData = [0, 0, 0, 0, 0, 0, 0]; // Mon-Sun
let dowChart = null;

// Attack type configurations - matches attack_mapping.json
const ATTACK_CONFIG = {
    // Main attacks from mapping
    'BENIGN': { color: '#10b981', severity: 'low' },
    'Bot': { color: '#8b5cf6', severity: 'high' },
    'DDoS': { color: '#dc2626', severity: 'critical' },
    'DoS GoldenEye': { color: '#dc2626', severity: 'critical' },
    'DoS Hulk': { color: '#ef4444', severity: 'critical' },
    'DoS Slowhttptest': { color: '#991b1b', severity: 'critical' },
    'DoS slowloris': { color: '#b91c1c', severity: 'critical' },
    'FTP-Patator': { color: '#f87171', severity: 'medium' },
    'PortScan': { color: '#f59e0b', severity: 'medium' },
    'SSH-Patator': { color: '#fca5a5', severity: 'medium' },
    'Web Attack - Brute Force': { color: '#f97316', severity: 'high' },
    'Web Attack - XSS': { color: '#fb923c', severity: 'high' },
    
    // Case variations
    'Benign': { color: '#10b981', severity: 'low' },
    'benign': { color: '#10b981', severity: 'low' },
    'bot': { color: '#8b5cf6', severity: 'high' },
    'BOT': { color: '#8b5cf6', severity: 'high' },
    'ddos': { color: '#dc2626', severity: 'critical' },
    'DDOS': { color: '#dc2626', severity: 'critical' },
    
    // Generic variants
    'DoS': { color: '#ef4444', severity: 'critical' },
    'DOS': { color: '#ef4444', severity: 'critical' },
    'dos': { color: '#ef4444', severity: 'critical' },
    'Port Scan': { color: '#f59e0b', severity: 'medium' },
    'Portscan': { color: '#f59e0b', severity: 'medium' },
    'portscan': { color: '#f59e0b', severity: 'medium' },
    
    // Web attacks
    'Web Attack': { color: '#f97316', severity: 'high' },
    'WebAttack': { color: '#f97316', severity: 'high' },
    'Web Attack � Brute Force': { color: '#f97316', severity: 'high' },
    'Web Attack � XSS': { color: '#fb923c', severity: 'high' },
    'Web Attack � Sql Injection': { color: '#ea580c', severity: 'high' },
    
    // Other attacks
    'Infiltration': { color: '#ec4899', severity: 'critical' },
    'infiltration': { color: '#ec4899', severity: 'critical' },
    'Infilteration': { color: '#ec4899', severity: 'critical' },
    'Brute Force': { color: '#ef4444', severity: 'high' },
    'BruteForce': { color: '#ef4444', severity: 'high' },
    'brute force': { color: '#ef4444', severity: 'high' },
    'Heartbleed': { color: '#be123c', severity: 'critical' },
    'heartbleed': { color: '#be123c', severity: 'critical' }
};

// Function to get config with fallback and normalization
function getAttackConfig(attackType) {
    // Try exact match first
    if (ATTACK_CONFIG[attackType]) {
        return ATTACK_CONFIG[attackType];
    }
    
    // Try case-insensitive match
    const normalized = attackType.toLowerCase();
    for (const [key, config] of Object.entries(ATTACK_CONFIG)) {
        if (key.toLowerCase() === normalized) {
            return config;
        }
    }
    
    // Try partial match (for unknown variants)
    for (const [key, config] of Object.entries(ATTACK_CONFIG)) {
        if (normalized.includes(key.toLowerCase()) || key.toLowerCase().includes(normalized)) {
            return config;
        }
    }
    
    // Default fallback
    return { color: '#ef4444', severity: 'high' };
}

// Mitigation advice database - matches attack_mapping.json
const MITIGATION_ADVICE = {
    'DoS Hulk': {
        title: 'DoS Hulk Attack',
        description: 'A volumetric DoS attack that attempts to overwhelm the server with HTTP GET and POST requests.',
        actions: [
            'Implement rate limiting on all public endpoints',
            'Configure firewall rules to block suspicious IPs',
            'Enable DDoS protection services (Cloudflare, AWS Shield)',
            'Set up traffic monitoring and alerting systems',
            'Deploy web application firewall (WAF) with DoS rules'
        ]
    },
    'DoS GoldenEye': {
        title: 'DoS GoldenEye Attack',
        description: 'An HTTP DoS attack that keeps sockets open by sending partial HTTP requests.',
        actions: [
            'Set aggressive connection timeouts',
            'Limit maximum concurrent connections per IP',
            'Deploy reverse proxy with connection pooling',
            'Enable SYN cookies on the server',
            'Use load balancer to distribute connections'
        ]
    },
    'DoS Slowhttptest': {
        title: 'Slow HTTP DoS Attack',
        description: 'Slowloris-type attack that slowly sends HTTP headers to exhaust server connections.',
        actions: [
            'Configure short timeouts for slow requests',
            'Limit request header size and count',
            'Deploy mod_reqtimeout or similar protection',
            'Use reverse proxy with request buffering',
            'Monitor connection states actively'
        ]
    },
    'DoS slowloris': {
        title: 'Slowloris Attack',
        description: 'Classic slowloris attack keeping many connections open with incomplete requests.',
        actions: [
            'Enable aggressive connection timeout settings',
            'Limit connections per source IP',
            'Deploy Apache mod_antiloris or nginx limit_conn',
            'Use connection rate limiting',
            'Implement request completion monitoring'
        ]
    },
    'DDoS': {
        title: 'Distributed Denial of Service',
        description: 'DDoS attacks use multiple compromised systems to flood the target with traffic from various sources.',
        actions: [
            'Deploy CDN and load balancers to distribute traffic',
            'Implement geo-blocking for suspicious regions',
            'Use anycast network routing to absorb attack traffic',
            'Configure automatic traffic filtering and black-holing',
            'Enable cloud-based DDoS mitigation services'
        ]
    },
    'PortScan': {
        title: 'Port Scanning Activity',
        description: 'Attackers are probing your network to identify open ports and potential vulnerabilities.',
        actions: [
            'Close unnecessary open ports immediately',
            'Implement intrusion detection/prevention systems (IDS/IPS)',
            'Configure firewall to drop packets from scanning IPs',
            'Enable stealth mode on critical services',
            'Set up honeypots to detect and track scanners'
        ]
    },
    'Bot': {
        title: 'Botnet Activity Detected',
        description: 'Automated bot traffic detected, potentially part of a larger botnet operation.',
        actions: [
            'Implement CAPTCHA on suspicious endpoints',
            'Deploy bot management solutions',
            'Analyze and block bot user agents and patterns',
            'Monitor for credential stuffing attempts',
            'Enable behavioral analysis for bot detection'
        ]
    },
    'Web Attack - Brute Force': {
        title: 'Web Application Brute Force',
        description: 'Automated attempts to guess credentials through repeated login attempts on web forms.',
        actions: [
            'Enable account lockout after failed attempts',
            'Implement progressive delays between login attempts',
            'Require strong password policies',
            'Enable two-factor authentication (2FA)',
            'Deploy CAPTCHA after 3 failed attempts'
        ]
    },
    'Web Attack - XSS': {
        title: 'Cross-Site Scripting (XSS) Attack',
        description: 'Attackers are attempting to inject malicious scripts into your web application.',
        actions: [
            'Implement strict Content Security Policy (CSP)',
            'Sanitize and validate all user inputs',
            'Encode output data before rendering',
            'Use HTTP-only cookies for sensitive data',
            'Deploy Web Application Firewall (WAF) with XSS rules'
        ]
    },
    'FTP-Patator': {
        title: 'FTP Brute Force Attack',
        description: 'Attacker is attempting to gain FTP access through credential brute forcing.',
        actions: [
            'Disable FTP if not essential, use SFTP instead',
            'Implement IP whitelisting for FTP access',
            'Use key-based authentication instead of passwords',
            'Monitor and log all FTP connection attempts',
            'Enable fail2ban for FTP protection'
        ]
    },
    'SSH-Patator': {
        title: 'SSH Brute Force Attack',
        description: 'Repeated attempts to gain SSH access through password guessing.',
        actions: [
            'Disable password authentication, use SSH keys only',
            'Change default SSH port from 22',
            'Implement fail2ban or similar protection',
            'Restrict SSH access by IP whitelist',
            'Enable two-factor authentication for SSH'
        ]
    }
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initializeNavigation();
    initializeFileUploads();
    initializeControls();
    initializeDoWChart();
    updateTime();
    setInterval(updateTime, 1000);
});

// Navigation
function initializeNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const section = item.dataset.section;
            switchSection(section);
            
            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');
        });
    });
}

function switchSection(section) {
    document.querySelectorAll('.section').forEach(s => s.style.display = 'none');
    
    const titles = {
        dashboard: 'Network Threat Intelligence',
        analysis: 'Real-Time Analysis',
        threats: 'Threat Intelligence & Mitigation'
    };
    
    const subtitles = {
        dashboard: 'Real-time intrusion detection and analysis',
        analysis: 'Live packet inspection and classification',
        threats: 'Detailed threat breakdown and remediation'
    };
    
    document.getElementById('pageTitle').textContent = titles[section] || titles.dashboard;
    document.getElementById('pageSubtitle').textContent = subtitles[section] || subtitles.dashboard;
    
    document.getElementById(`${section}Section`).style.display = 'block';
}

function updateTime() {
    const now = new Date();
    const timeStr = now.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
    document.getElementById('currentTime').textContent = timeStr;
}

// Initialize DoW Chart
function initializeDoWChart() {
    const ctx = document.getElementById('dowChart').getContext('2d');
    dowChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'],
            datasets: [{
                label: 'Packets Analyzed',
                data: dowData,
                backgroundColor: 'rgba(59, 130, 246, 0.5)',
                borderColor: 'rgba(59, 130, 246, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: '#94a3b8' },
                    grid: { color: 'rgba(51, 65, 85, 0.3)' }
                },
                x: {
                    ticks: { color: '#94a3b8' },
                    grid: { display: false }
                }
            },
            plugins: {
                legend: {
                    labels: { color: '#cbd5e1' }
                }
            }
        }
    });
}

// File Upload Handlers
function initializeFileUploads() {
    const csvFile = document.getElementById('csvFile');
    const pcapFile = document.getElementById('pcapFile');

    csvFile.addEventListener('change', (e) => handleFileSelect(e, 'csv'));
    pcapFile.addEventListener('change', (e) => handleFileSelect(e, 'pcap'));

    document.getElementById('csvAnalyzeBtn').addEventListener('click', () => startAnalysis());
    document.getElementById('pcapAnalyzeBtn').addEventListener('click', () => startAnalysis());
    
    setupDragDrop('csvFile');
    setupDragDrop('pcapFile');
}

function setupDragDrop(fileId) {
    const input = document.getElementById(fileId);
    const zone = input.nextElementSibling;
    
    zone.addEventListener('dragover', (e) => {
        e.preventDefault();
        zone.classList.add('active');
    });
    
    zone.addEventListener('dragleave', () => {
        zone.classList.remove('active');
    });
    
    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('active');
        if (e.dataTransfer.files.length) {
            input.files = e.dataTransfer.files;
            handleFileSelect({ target: input }, fileId.includes('csv') ? 'csv' : 'pcap');
        }
    });
}

function handleFileSelect(e, type) {
    const file = e.target.files[0];
    if (!file) return;

    const zone = e.target.nextElementSibling;
    const text = zone.querySelector('.upload-text');
    const btn = document.getElementById(`${type}AnalyzeBtn`);

    text.textContent = `✓ ${file.name}`;
    btn.disabled = false;

    showLoading(`Uploading ${file.name}...`);

    const formData = new FormData();
    formData.append('file', file);

    const endpoint = type === 'csv' ? '/upload_csv' : '/upload_pcap';

    fetch(endpoint, {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        hideLoading();
        if (data.error) {
            alert('Error: ' + data.error);
            resetUpload(type);
        } else {
            sessionId = data.session_id;
            totalRows = data.total_rows;
            alert(`✓ Uploaded! ${totalRows} packets ready.`);
        }
    })
    .catch(error => {
        hideLoading();
        alert('Upload failed: ' + error.message);
        resetUpload(type);
    });
}

function resetUpload(type) {
    const input = document.getElementById(`${type}File`);
    const zone = input.nextElementSibling;
    const text = zone.querySelector('.upload-text');
    const btn = document.getElementById(`${type}AnalyzeBtn`);
    
    text.textContent = type === 'csv' ? 'Drop CSV or click to browse' : 'Drop PCAP or click to browse';
    btn.disabled = true;
    input.value = '';
}

// Analysis Control
function startAnalysis() {
    if (!sessionId) {
        alert('No file uploaded!');
        return;
    }

    switchSection('analysis');
    document.querySelector('[data-section="analysis"]').classList.add('active');
    document.querySelector('[data-section="dashboard"]').classList.remove('active');

    currentRow = 0;
    threatCount = 0;
    confidenceSum = 0;
    processedCount = 0;
    attackCounts = {};
    dowData = [0, 0, 0, 0, 0, 0, 0];

    document.getElementById('logContainer').innerHTML = '<div class="empty-state">Analyzing packets...</div>';

    processNextRow();
}

function processNextRow() {
    if (isPaused) return;
    
    if (currentRow >= totalRows) {
        stopAnalysis();
        updateMitigationAdvice();
        alert('✓ Analysis complete!');
        return;
    }

    fetch('/predict_row', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            session_id: sessionId,
            row_index: currentRow
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert('Error: ' + data.error);
            stopAnalysis();
        } else {
            updateDisplay(data);
            currentRow++;
            
            const delay = 1000 / speed;
            setTimeout(processNextRow, delay);
        }
    })
    .catch(error => {
        alert('Prediction failed: ' + error.message);
        stopAnalysis();
    });
}

function updateDisplay(data) {
    processedCount++;
    
    // CRITICAL: Ensure attack_type is a string, not a number
    let attackType = data.attack_type;
    
    // Debug logging
    console.log('Raw data received:', data);
    console.log('Attack type (raw):', attackType, 'Type:', typeof attackType);
    
    // If attack_type is a number, it means the backend didn't decode properly
    if (typeof attackType === 'number' || !isNaN(attackType)) {
        console.warn('⚠️ Attack type is numeric! Backend label decoding failed.');
        attackType = `Attack_Type_${attackType}`;
    }
    
    // Convert to string and trim
    attackType = String(attackType).trim();
    
    console.log('Attack type (processed):', attackType);
    
    // Update DoW data (simulated - use actual timestamp if available)
    const dayIndex = new Date().getDay();
    dowData[dayIndex === 0 ? 6 : dayIndex - 1]++;
    if (dowChart) {
        dowChart.data.datasets[0].data = dowData;
        dowChart.update('none');
    }
    
    // Update attack counts
    attackCounts[attackType] = (attackCounts[attackType] || 0) + 1;
    updateAttackDistribution();
    
    // Update stats
    document.getElementById('totalPackets').textContent = totalRows;
    document.getElementById('processedPackets').textContent = processedCount;
    
    if (attackType !== 'BENIGN' && !attackType.toLowerCase().includes('benign')) {
        threatCount++;
    }
    document.getElementById('threatsDetected').textContent = threatCount;
    
    confidenceSum += data.confidence;
    const avgConfidence = (confidenceSum / processedCount * 100).toFixed(1);
    document.getElementById('avgConfidence').textContent = avgConfidence + '%';

    // Update current analysis
    document.getElementById('rowNumber').textContent = data.row_index + 1;
    
    const badge = document.getElementById('predictionBadge');
    const config = getAttackConfig(attackType); // Use helper function for better matching
    
    console.log('Config found:', config);
    
    // Update badge with attack name and class number
    const badgeText = badge.querySelector('.badge-text');
    const badgeClass = badge.querySelector('.badge-class');
    
    badgeText.textContent = attackType;
    
    if (data.predicted_class !== undefined && data.predicted_class !== null) {
        badgeClass.textContent = `Class ${data.predicted_class}`;
        badgeClass.style.display = 'inline-block';
    } else {
        badgeClass.style.display = 'none';
    }
    
    badge.style.background = `${config.color}20`;
    badge.style.color = config.color;
    badge.style.borderColor = config.color;

    console.log(`✅ Display Update - Attack: ${attackType}, Color: ${config.color}, Class: ${data.predicted_class}`);

    // Update features
    const featuresContainer = document.getElementById('rowFeatures');
    featuresContainer.innerHTML = '';
    
    const features = Object.entries(data.row_data).slice(0, 6);
    features.forEach(([key, value]) => {
        const featureItem = document.createElement('div');
        featureItem.className = 'feature-item';
        featureItem.style.borderLeftColor = config.color;
        featureItem.innerHTML = `
            <div class="feature-label">${key}</div>
            <div class="feature-value">${typeof value === 'number' ? value.toFixed(4) : value}</div>
        `;
        featuresContainer.appendChild(featureItem);
    });

    // Update confidence
    const confidencePct = (data.confidence * 100).toFixed(1);
    document.getElementById('confidenceFill').style.width = confidencePct + '%';
    document.getElementById('confidenceFill').style.background = config.color;
    document.getElementById('confidenceText').textContent = confidencePct + '%';

    // Add to log
    addLogEntry(data, config, attackType);
}

function updateAttackDistribution() {
    const container = document.getElementById('attackDistribution');
    container.innerHTML = '';
    
    const sortedAttacks = Object.entries(attackCounts)
        .sort((a, b) => b[1] - a[1]);
    
    const maxCount = Math.max(...Object.values(attackCounts));
    
    sortedAttacks.forEach(([type, count]) => {
        const config = getAttackConfig(type);
        const percentage = (count / maxCount) * 100;
        
        const item = document.createElement('div');
        item.className = 'attack-item';
        item.style.borderLeftColor = config.color;
        item.innerHTML = `
            <div class="attack-item-label">${type}</div>
            <div class="attack-item-count">${count}</div>
            <div class="attack-item-bar">
                <div class="attack-item-fill" style="width: ${percentage}%; background: ${config.color};"></div>
            </div>
        `;
        container.appendChild(item);
    });
}

function addLogEntry(data, config, attackType) {
    const logContainer = document.getElementById('logContainer');
    
    const emptyMsg = logContainer.querySelector('.empty-state');
    if (emptyMsg) emptyMsg.remove();

    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.style.borderLeftColor = config.color;
    
    const now = new Date();
    const timeStr = now.toLocaleTimeString();
    
    entry.innerHTML = `
        <div class="log-entry-header">
            <span class="log-packet">PACKET #${data.row_index + 1}</span>
            <span class="log-time">${timeStr}</span>
        </div>
        <div class="log-attack" style="color: ${config.color};">
            ${attackType}
        </div>
        <div class="log-confidence">
            Confidence: ${(data.confidence * 100).toFixed(1)}% | Class ${data.predicted_class !== undefined ? data.predicted_class : 'N/A'}
        </div>
    `;
    
    logContainer.insertBefore(entry, logContainer.firstChild);
    
    while (logContainer.children.length > 50) {
        logContainer.removeChild(logContainer.lastChild);
    }
}

function updateMitigationAdvice() {
    const container = document.getElementById('mitigationAdvice');
    container.innerHTML = '';
    
    const detectedAttacks = Object.keys(attackCounts).filter(type => type !== 'BENIGN');
    
    if (detectedAttacks.length === 0) {
        container.innerHTML = '<div class="empty-state">No threats detected. System is secure.</div>';
        return;
    }
    
    detectedAttacks.forEach(attackType => {
        const advice = MITIGATION_ADVICE[attackType];
        if (!advice) return;
        
        const config = getAttackConfig(attackType);
        
        const item = document.createElement('div');
        item.className = 'mitigation-item';
        item.style.borderLeftColor = config.color;
        item.innerHTML = `
            <div class="mitigation-header">
                <div class="mitigation-icon" style="background: ${config.color}20; color: ${config.color};">
                    ⚠️
                </div>
                <div class="mitigation-title">${advice.title}</div>
            </div>
            <div class="mitigation-description">${advice.description}</div>
            <div class="mitigation-actions">
                ${advice.actions.map(action => `<div class="mitigation-action">${action}</div>`).join('')}
            </div>
        `;
        container.appendChild(item);
    });
    
    // Update detailed stats
    updateDetailedStats();
}

function updateDetailedStats() {
    const container = document.getElementById('detailedStats');
    container.innerHTML = '';
    
    const stats = Object.entries(attackCounts).map(([type, count]) => {
        const config = getAttackConfig(type);
        const percentage = ((count / processedCount) * 100).toFixed(1);
        
        return { type, count, percentage, config };
    }).sort((a, b) => b.count - a.count);
    
    stats.forEach(({ type, count, percentage, config }) => {
        const item = document.createElement('div');
        item.className = 'detailed-stat-item';
        item.style.borderLeftColor = config.color;
        item.innerHTML = `
            <div class="detailed-stat-label">${type}</div>
            <div class="detailed-stat-value">${count} (${percentage}%)</div>
        `;
        container.appendChild(item);
    });
}

function stopAnalysis() {
    // Analysis complete
}

// Controls
function initializeControls() {
    const pauseBtn = document.getElementById('pauseBtn');
    const speedBtn = document.getElementById('speedBtn');

    pauseBtn.addEventListener('click', () => {
        isPaused = !isPaused;
        document.getElementById('pauseText').textContent = isPaused ? 'Resume' : 'Pause';
        if (!isPaused) processNextRow();
    });

    speedBtn.addEventListener('click', () => {
        const speeds = [0.5, 1, 2, 5];
        const currentIndex = speeds.indexOf(speed);
        speed = speeds[(currentIndex + 1) % speeds.length];
        document.getElementById('speedValue').textContent = speed + 'x';
    });
}

// UI Helpers
function showLoading(message) {
    const overlay = document.getElementById('loadingOverlay');
    const text = document.getElementById('loadingText');
    text.textContent = message;
    overlay.classList.add('active');
}

function hideLoading() {
    document.getElementById('loadingOverlay').classList.remove('active');
}