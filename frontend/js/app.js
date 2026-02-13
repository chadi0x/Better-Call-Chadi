document.addEventListener('DOMContentLoaded', () => {

    console.log("App initializing...");

    // --- 1. Intro Animation with Failsafe ---
    const introOverlay = document.getElementById('intro-overlay');
    const introText = introOverlay.querySelector('.intro-text');
    const app = document.getElementById('app');

    // Failsafe: Force show dashboard after 4 seconds if animation hangs
    const failsafeTimeout = setTimeout(() => {
        forceShowDashboard();
    }, 4000);

    function forceShowDashboard() {
        if (introOverlay) {
            introOverlay.style.opacity = '0';
            introOverlay.style.pointerEvents = 'none';
            setTimeout(() => {
                introOverlay.style.display = 'none';
            }, 1000);
        }
        if (app) app.style.opacity = '1';
    }

    try {
        if (introText) {
            typeWriter("Welcome back, Neo...", introText, () => {
                clearTimeout(failsafeTimeout); // Cancel failsafe
                setTimeout(() => {
                    forceShowDashboard();
                    initDashboard();
                }, 500);
            });
        } else {
            forceShowDashboard();
            initDashboard();
        }
    } catch (e) {
        console.error("Intro animation error:", e);
        forceShowDashboard();
        initDashboard();
    }

    // --- 2. Clock ---
    setInterval(() => {
        const now = new Date();
        const timeEl = document.getElementById('system-time');
        if (timeEl) timeEl.innerText = now.toLocaleTimeString('en-US', { hour12: false });
    }, 1000);

    // --- 3. Tab Switching ---
    const navLinks = document.querySelectorAll('.nav-link');
    const tabPanes = document.querySelectorAll('.tab-pane');
    const pageTitle = document.getElementById('page-title');

    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            navLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');

            const tabId = link.getAttribute('data-tab');
            const targetPane = document.getElementById(`tab-${tabId}`);

            tabPanes.forEach(pane => pane.classList.add('d-none'));
            if (targetPane) targetPane.classList.remove('d-none');

            // Update Title
            if (pageTitle) pageTitle.innerText = link.innerText.trim().toUpperCase();
        });
    });

    // --- 4. Real Scanner Logic (Python Backend) ---
    setInterval(pollActiveScans, 2000);

    // Form Submission (Scanner)
    const scanForm = document.getElementById('scan-form');
    if (scanForm) {
        scanForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const btn = e.target.querySelector('button[type="submit"]');
            const originalText = btn.innerText;

            // Visual Feedback
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> INITIATING...';
            btn.disabled = true;
            btn.style.opacity = "0.7";

            const targetInput = e.target.querySelector('input[type="text"]');
            const target = targetInput ? (targetInput.value || "http://testphp.vulnweb.com") : "http://testphp.vulnweb.com";
            const profileInput = e.target.querySelector('select');
            const profile = profileInput ? profileInput.value : "quick";

            // Scope collection
            const scopeCheckboxes = e.target.querySelectorAll('input[name="scope"]:checked');
            const scope = Array.from(scopeCheckboxes).map(cb => cb.value);

            await startRealScan(target, profile, scope);

            // Reset Button
            btn.innerText = originalText;
            btn.disabled = false;
            btn.style.opacity = "1";
        });
    }

    async function startRealScan(target, profile, scope) {
        try {
            const response = await fetch('/api/python/api/scanner/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target, profile: profile, scope: scope })
            });
            const data = await response.json();
            if (data.scan_id) {
                console.log("Scan started:", data.scan_id);
                pollActiveScans();
            } else {
                alert("Failed to start scan: " + (data.error || "Unknown error"));
            }
        } catch (err) {
            console.error("Error starting scan:", err);
            alert("Error contacting backend. Please verify Docker status.");
        }
    }

    let lastScansHash = "";

    async function pollActiveScans() {
        try {
            const response = await fetch('/api/python/api/scanner/scans');
            if (!response.ok) return;

            const scans = await response.json();
            const currentHash = JSON.stringify(scans);

            if (currentHash !== lastScansHash) {
                lastScansHash = currentHash;
                updateActiveScansTable(scans);
                updateScanCount(scans);
            }
        } catch (e) {
            // console.warn("Polling failed", e);
        }
    }

    function updateActiveScansTable(scans) {
        const tbody = document.getElementById('active-scans-body');
        if (!tbody) return;

        scans.sort((a, b) => b.timestamp - a.timestamp);

        let html = "";
        scans.forEach(scan => {
            html += `
                <tr>
                    <td class="font-mono text-cyan">${scan.target}</td>
                    <td style="text-transform:uppercase;">${scan.profile}</td>
                    <td>
                        <span class="badge ${scan.status === 'RUNNING' ? 'status-running' : scan.status === 'COMPLETED' ? 'text-cyan' : 'text-magenta'}">
                            ${scan.status} ${scan.status === 'RUNNING' ? '<i class="fas fa-spinner fa-spin"></i>' : ''}
                        </span>
                    </td>
                    <td class="font-mono">${scan.findings ? scan.findings.length : 0}</td>
                    <td>
                        <button class="neo-btn" onclick="viewScanResults('${scan.id}')" style="padding:2px 8px; font-size:0.7rem;">VIEW</button>
                    </td>
                </tr>
            `;
        });

        tbody.innerHTML = html;
    }

    let currentFindings = [];

    window.viewScanResults = async function (scanId) {
        try {
            const response = await fetch(`/api/python/api/scanner/scan/${scanId}/results`);
            const findings = await response.json();
            currentFindings = findings;
            updateFindingsTable(findings);
        } catch (e) {
            console.error("Error fetching results:", e);
        }
    }

    function updateScanCount(scans) {
        const countEl = document.getElementById('active-scans-count');
        if (countEl && scans) {
            const running = scans.filter(s => s.status === 'RUNNING').length;
            countEl.innerText = running;
        }
    }

    function updateFindingsTable(findings) {
        const tbody = document.getElementById('findings-body');
        if (!tbody) return;

        if (findings.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="text-center text-secondary">No findings available.</td></tr>';
            return;
        }

        let html = "";
        findings.forEach((f, index) => {
            html += `
                <tr>
                    <td><span class="severity-chip severity-${f.severity || 'low'}">${f.severity || 'info'}</span></td>
                    <td>${f.title}</td>
                    <td class="font-mono text-secondary">${f.endpoint}</td>
                    <td>
                        <i class="fas fa-eye text-cyan" style="cursor:pointer;" onclick="openFindingModal(${index})"></i>
                    </td>
                </tr>
            `;
        });

        tbody.innerHTML = html;
    }

    // --- Tool Modal Logic ---
    window.openToolModal = function (toolType) {
        const modal = document.getElementById('tool-modal');
        const title = document.getElementById('tool-modal-title');
        const controls = document.getElementById('tool-controls');
        const results = document.getElementById('tool-results');

        results.innerHTML = "Waiting for input...";
        document.getElementById('tool-modal').style.display = 'block';

        let innerHTML = '';
        if (['subdomain', 'crawler', 'ports', 'whois', 'dns', 'headers', 'ssl', 'tech'].includes(toolType)) {
            let label = "Target";
            let button = "RUN";
            if (toolType === 'subdomain') { title.innerText = "SUBDOMAIN ENUMERATION"; button = "START ENUMERATION"; }
            if (toolType === 'crawler') { title.innerText = "WEB CRAWLER"; button = "START CRAWL"; }
            if (toolType === 'ports') { title.innerText = "PORT SCANNER"; button = "SCAN PORTS"; }
            if (toolType === 'whois') { title.innerText = "WHOIS LOOKUP"; button = "GET WHOIS"; }
            if (toolType === 'dns') { title.innerText = "DNS RECORDS"; button = "GET RECORDS"; }
            if (toolType === 'headers') { title.innerText = "HEADER SECURITY"; button = "ANALYZE HEADERS"; }
            if (toolType === 'ssl') { title.innerText = "SSL INSPECTOR"; button = "CHECK CERT"; }
            if (toolType === 'tech') { title.innerText = "TECH STACK"; button = "DETECT STACK"; }

            innerHTML = `
                <div class="mb-2">
                    <label>${label}</label>
                    <input type="text" id="tool-target" class="neo-input" placeholder="example.com">
                </div>
                <button class="neo-btn" onclick="runTool('${toolType}')">${button}</button>
            `;
        } else if (toolType === 'payloads') {
            title.innerText = "PAYLOAD GENERATOR";
            innerHTML = `
                <div class="mb-2">
                    <label>Type</label>
                    <select id="tool-type" class="neo-select">
                        <option value="xss">Cross-Site Scripting (XSS)</option>
                        <option value="sql">SQL Injection</option>
                        <option value="rce">Remote Code Execution (RCE)</option>
                        <option value="lfi">Local File Inclusion (LFI)</option>
                    </select>
                </div>
                <button class="neo-btn" onclick="generatePayloads()">GENERATE</button>
            `;
        }
        controls.innerHTML = innerHTML;
    }

    window.closeToolModal = function () {
        document.getElementById('tool-modal').style.display = 'none';
    }

    window.runTool = async function (toolType) {
        const target = document.getElementById('tool-target').value;
        const resultsDiv = document.getElementById('tool-results');

        if (!target) {
            resultsDiv.innerText = "Error: Input required.";
            return;
        }

        resultsDiv.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';

        // Map toolType to API endpoint
        // crawler -> crawl, others match 1:1 usually
        let endpoint = toolType;
        if (toolType === 'subdomain') endpoint = 'subdomains';
        if (toolType === 'crawler') endpoint = 'crawl';


        try {
            const response = await fetch(`/api/python/api/scanner/${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target: target })
            });
            const data = await response.json();
            resultsDiv.innerText = JSON.stringify(data, null, 2);
        } catch (e) {
            resultsDiv.innerText = "Error: " + e.message;
        }
    }

    window.generatePayloads = async function () {
        const type = document.getElementById('tool-type').value;
        const resultsDiv = document.getElementById('tool-results');

        try {
            const response = await fetch(`/api/python/api/scanner/payloads/${type}`);
            const data = await response.json();
            resultsDiv.innerText = data.join("\n");
        } catch (e) {
            resultsDiv.innerText = "Error fetching payloads";
        }
    }

    // --- Detail Modal Logic ---
    window.openFindingModal = function (index) {
        const f = currentFindings[index];
        if (!f) return;

        document.getElementById('modal-title').innerText = f.title;
        document.getElementById('modal-severity').innerHTML = `<span class="severity-chip severity-${f.severity}">${f.severity}</span>`;
        document.getElementById('modal-endpoint').innerText = f.endpoint;
        document.getElementById('modal-desc').innerText = f.description || "No description provided.";
        // Use evidence if available, else parameter
        document.getElementById('modal-evidence').innerText = f.evidence ? f.evidence : (f.parameter ? `Parameter: ${f.parameter}` : "No specific evidence.");

        document.getElementById('details-modal').style.display = 'block';
    }

    window.closeModal = function () {
        document.getElementById('details-modal').style.display = 'none';
    }

    // --- 5. System Status Checks ---
    checkServiceStatus('python', 8000, 'status-python');
    checkServiceStatus('rust', 8001, 'status-rust');
    checkServiceStatus('java', 8002, 'status-java');

});

function typeWriter(text, element, callback) {
    if (!element) {
        if (callback) callback();
        return;
    }

    let i = 0;
    element.innerHTML = '';
    function type() {
        if (i < text.length) {
            element.innerHTML += text.charAt(i);
            i++;
            setTimeout(type, 50); // Typing speed
        } else {
            if (callback) callback();
        }
    }
    type();
}

async function checkServiceStatus(serviceName, port, elementId) {
    const element = document.getElementById(elementId);
    if (!element) return;

    const url = `/api/${serviceName}/api/status`;
    try {
        const response = await fetch(url);
        if (response.ok) {
            element.innerHTML = "ONLINE";
            element.classList.remove('text-secondary');
            element.classList.add('text-lime');
        } else {
            throw new Error('Unreachable');
        }
    } catch (error) {
        element.innerHTML = "OFFLINE";
        element.classList.remove('text-lime');
        element.classList.add('text-magenta');
    }
}


// --- 6. Threat Groups Logic ---
let currentGroups = [];

window.searchGroups = async function () {
    const query = document.getElementById('group-search').value;
    const country = document.getElementById('group-country').value;
    const category = document.getElementById('group-category').value;
    const grid = document.getElementById('groups-grid');

    // Show Loading
    grid.innerHTML = `
        <div class="neo-card text-center p-4" style="grid-column: 1 / -1;">
            <i class="fas fa-circle-notch fa-spin text-cyan fa-2x"></i>
            <p class="mt-3 text-secondary">Scanning Threat Databases...</p>
        </div>
    `;

    try {
        const params = new URLSearchParams();
        if (query) params.append('q', query);
        if (country) params.append('country', country);
        if (category) params.append('category', category);

        const response = await fetch(`/api/python/api/threat-groups?${params.toString()}`);
        const groups = await response.json();
        currentGroups = groups;
        renderGroups(groups);
    } catch (e) {
        grid.innerHTML = `<p class="text-magenta">Error fetching threat data: ${e.message}</p>`;
    }
}

function renderGroups(groups) {
    const grid = document.getElementById('groups-grid');
    if (!grid) return;

    if (groups.length === 0) {
        grid.innerHTML = `
            <div class="neo-card text-center p-4" style="grid-column: 1 / -1;">
                <p class="text-secondary">No threat groups found matching your criteria.</p>
            </div>
        `;
        return;
    }

    let html = "";
    groups.forEach((g, index) => {
        // Flag emoji mapping (simple fallback)
        let flag = "🏳️";
        if (g.flag_code && g.flag_code !== 'xx') {
            // Convert country code to flag emoji
            const codePoints = g.flag_code
                .toUpperCase()
                .split('')
                .map(char => 127397 + char.charCodeAt());
            flag = String.fromCodePoint(...codePoints);
        } else {
            flag = "🏴‍☠️";
        }

        html += `
            <div class="neo-card group-card" onclick="openGroupDetail(${index})" style="cursor:pointer; transition: transform 0.2s;">
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <div style="font-size:2rem;">${flag}</div>
                    <span class="severity-chip ${g.category === 'State-Sponsored' ? 'severity-critical' : 'severity-high'}">${g.category || 'Unknown'}</span>
                </div>
                <h3 class="card-title mt-2 mb-1 text-cyan">${g.name}</h3>
                <p class="text-secondary font-mono" style="font-size:0.8rem; margin-bottom:10px;">${g.country}</p>
                <div style="display:flex; gap:5px; flex-wrap:wrap;">
                    ${(g.tools || []).slice(0, 3).map(t => `<span class="severity-chip severity-low" style="font-size:0.65rem;">${t}</span>`).join('')}
                    ${(g.tools || []).length > 3 ? `<span class="severity-chip severity-low" style="font-size:0.65rem;">+${g.tools.length - 3}</span>` : ''}
                </div>
            </div>
        `;
    });
    grid.innerHTML = html;
}

window.openGroupDetail = function (index) {
    const g = currentGroups[index];
    if (!g) return;

    document.getElementById('group-modal-title').innerText = g.name.toUpperCase();
    document.getElementById('group-name-large').innerText = g.name;
    document.getElementById('group-aliases').innerText = "Aliases: " + (g.aliases || []).join(", ");
    document.getElementById('group-category-tag').innerText = g.category;
    document.getElementById('group-country-tag').innerText = g.country;

    // Flag
    let flag = "🏳️";
    if (g.flag_code && g.flag_code !== 'xx') {
        const codePoints = g.flag_code.toUpperCase().split('').map(char => 127397 + char.charCodeAt());
        flag = String.fromCodePoint(...codePoints);
    } else {
        flag = "🏴‍☠️";
    }
    document.getElementById('group-flag-large').innerText = flag;

    document.getElementById('group-description').innerText = g.description;

    // Tools
    const toolsDiv = document.getElementById('group-tools');
    toolsDiv.innerHTML = (g.tools || []).map(t =>
        `<span class="severity-chip severity-low">${t}</span>`
    ).join('');

    // Targets
    const targetsList = document.getElementById('group-targets');
    targetsList.innerHTML = (g.targets || []).map(t =>
        `<li>${t}</li>`
    ).join('');

    // TTPs
    const ttpsDiv = document.getElementById('group-ttps');
    ttpsDiv.innerHTML = (g.primary_attack_types || []).map(t =>
        `<span style="border:1px solid #ffa500; color:#ffa500; padding:4px 8px; border-radius:4px; font-size:0.8rem;">${t}</span>`
    ).join('');

    document.getElementById('group-modal').style.display = 'block';
}

window.closeGroupModal = function () {
    document.getElementById('group-modal').style.display = 'none';
}


// --- 7. Intel Feed Logic ---
let currentFeed = [];
let feedFilter = 'all';

window.refreshIntelFeed = async function () {
    const container = document.getElementById('intel-feed-container');
    const btn = document.querySelector('button[onclick="refreshIntelFeed()"]');

    // Animation
    if (btn) btn.innerHTML = '<i class="fas fa-sync-alt fa-spin"></i> REFRESHING';

    try {
        const response = await fetch('/api/python/api/intel/feed?limit=100');
        const feed = await response.json();
        currentFeed = feed;
        renderFeed();

        // Update Timestamp
        const now = new Date();
        document.getElementById('feed-last-updated').innerText = now.toLocaleTimeString();

    } catch (e) {
        container.innerHTML = `<p class="text-magenta">Error fetching intel feed: ${e.message}</p>`;
    } finally {
        if (btn) btn.innerHTML = '<i class="fas fa-sync-alt"></i> REFRESH';
    }
}

window.filterFeed = function (type, btnElement) {
    feedFilter = type;

    // Update active button state
    document.querySelectorAll('.neo-btn.active-filter').forEach(b => b.classList.remove('active-filter'));
    if (btnElement) btnElement.classList.add('active-filter');

    renderFeed();
}

function renderFeed() {
    const container = document.getElementById('intel-feed-container');
    if (!container) return;

    let displayData = currentFeed;

    if (feedFilter !== 'all') {
        // Filter by type or tag logic
        // The buttons send: exploit, cve, ransomware, advisory
        // Our backend types: exploit, news, advisory
        // Our tags: CVE, Ransomware, Zero-Day, Exploit

        if (feedFilter === 'exploit') {
            displayData = currentFeed.filter(x => x.type === 'exploit' || x.tags.includes('Exploit'));
        } else if (feedFilter === 'cve') {
            displayData = currentFeed.filter(x => x.tags.includes('CVE'));
        } else if (feedFilter === 'ransomware') {
            displayData = currentFeed.filter(x => x.tags.includes('Ransomware'));
        } else if (feedFilter === 'advisory') {
            displayData = currentFeed.filter(x => x.type === 'advisory');
        }
    }

    if (displayData.length === 0) {
        container.innerHTML = `
            <div class="text-center p-5">
                <p class="text-secondary">No intelligence found for this filter.</p>
            </div>
        `;
        return;
    }

    let html = "";
    displayData.forEach(item => {
        // Badge color based on type/tag
        let badgeClass = "severity-low";
        let icon = "fa-newspaper";

        if (item.type === 'exploit') { badgeClass = "severity-critical"; icon = "fa-radiation"; }
        if (item.type === 'advisory') { badgeClass = "severity-high"; icon = "fa-exclamation-triangle"; }
        if (item.tags.includes('Ransomware')) { badgeClass = "severity-critical"; icon = "fa-skull"; }
        if (item.tags.includes('CVE')) { badgeClass = "severity-medium"; icon = "fa-bug"; }

        html += `
            <div class="neo-card" style="margin-bottom: 10px; padding: 15px; border-left: 3px solid var(--c-${badgeClass === 'severity-critical' ? 'magenta' : badgeClass === 'severity-high' ? 'orange' : 'cyan'});">
                <div style="display: flex; justify-content: space-between;">
                    <span class="severity-chip ${badgeClass}"><i class="fas ${icon}"></i> ${item.type.toUpperCase()}</span>
                    <span class="text-secondary font-mono" style="font-size: 0.75rem;">${item.published}</span>
                </div>
                <h4 class="text-white mt-2 mb-1"><a href="${item.link}" target="_blank" style="color:white; text-decoration:none;" class="hover-cyan">${item.title}</a></h4>
                <div style="font-size: 0.85rem; color: #aaa; margin-bottom: 10px;">${item.summary}</div>
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="display: flex; gap: 5px;">
                        ${item.tags.map(t => `<span style="font-size: 0.7rem; color: var(--c-cyan); border: 1px solid var(--c-cyan); padding: 1px 5px; border-radius: 3px;">${t}</span>`).join('')}
                    </div>
                    <div class="font-mono text-secondary" style="font-size: 0.7rem;">SOURCE: ${item.source}</div>
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}


// --- 8. Forensics Logic ---

window.uploadAPK = async function () {
    const input = document.getElementById('apk-file-input');
    const file = input.files[0];
    if (!file) return;

    // UI Feedback
    const area = document.getElementById('apk-upload-area');
    const originalContent = area.innerHTML;
    area.innerHTML = `<i class="fas fa-circle-notch fa-spin fa-3x text-lime"></i><p class="text-white mt-3">Decompiling & Analyzing...</p>`;

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/api/python/api/forensics/apk', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const text = await response.text();
            throw new Error(`Server Error (${response.status}): ${text.substring(0, 100)}...`);
        }

        const report = await response.json();

        if (report.error) throw new Error(report.error);

        renderAPKReport(report);

    } catch (e) {
        alert("Analysis Failed: " + e.message);
    } finally {
        area.innerHTML = originalContent;
        input.value = ''; // Reset
    }
}

function renderAPKReport(report) {
    const resultsArea = document.getElementById('forensics-results');
    const content = document.getElementById('report-content');
    resultsArea.classList.remove('d-none');

    // Risk Badge Logic
    let riskClass = "severity-low";
    if (report.risk_score > 30) riskClass = "severity-medium";
    if (report.risk_score > 60) riskClass = "severity-high";
    if (report.risk_score > 80) riskClass = "severity-critical";

    let html = `
        <!-- Header / Risk Score -->
        <div class="row">
            <div class="col-md-9">
                <h4 class="text-cyan font-tech mb-3"><i class="fab fa-android"></i> APK ANALYSIS REPORT</h4>
                <div class="grid-2-col" style="display:grid; grid-template-columns: 1fr 1fr; gap:10px;">
                    <div><span class="text-secondary">Package:</span> <span class="font-mono text-white">${report.package_name}</span></div>
                    <div><span class="text-secondary">Ver:</span> <span class="font-mono">${report.version_name} (${report.version_code})</span></div>
                    <div><span class="text-secondary">SDK:</span> <span class="font-mono">Min ${report.min_sdk} / Target ${report.target_sdk}</span></div>
                    <div><span class="text-secondary">Filename:</span> <span class="font-mono">${report.filename}</span></div>
                </div>
            </div>
            <div class="col-md-3 text-center">
                <div class="neo-card p-2" style="border-color: var(--c-${riskClass.split('-')[1]})">
                    <h6 class="text-secondary mb-1">RISK SCORE</h6>
                    <div style="font-size: 2.5rem; font-weight: bold;" class="${riskClass}">${report.risk_score}/100</div>
                </div>
            </div>
        </div>

        <hr style="border-color: var(--c-border); margin: 15px 0;">

        <!-- Findings Summary -->
        ${report.findings.length > 0 ? `
            <h5 class="text-orange font-tech mb-2"><i class="fas fa-exclamation-circle"></i> KEY FINDINGS (${report.findings.length})</h5>
            <div class="neo-card p-3 mb-4" style="max-height: 200px; overflow-y: auto;">
                ${report.findings.map(f => `
                    <div style="margin-bottom: 8px; border-left: 2px solid var(--c-${f.severity === 'Critical' ? 'magenta' : f.severity === 'High' ? 'orange' : 'cyan'}); padding-left: 10px;">
                        <div><span class="severity-chip severity-${f.severity.toLowerCase()}">${f.severity}</span> <strong class="text-white">${f.title}</strong></div>
                        <div class="text-secondary font-mono" style="font-size: 0.8rem;">${f.desc}</div>
                    </div>
                `).join('')}
            </div>
        ` : ''}

        <!-- Tab Navigation -->
        <ul class="nav nav-tabs neo-tabs mb-3" id="apkTabs" role="tablist">
            <li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#apk-perms" role="tab">Permissions</a></li>
            <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#apk-secrets" role="tab">Secrets & URLs</a></li>
            <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#apk-components" role="tab">Components</a></li>
            <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#apk-security" role="tab">Security</a></li>
        </ul>

        <div class="tab-content" id="apkTabsContent">
            
            <!-- Permissions Tab -->
            <div class="tab-pane fade show active" id="apk-perms" role="tabpanel">
                <div class="neo-card p-3">
                    <h6 class="text-magenta font-tech mb-3">DANGEROUS (${report.dangerous_permissions.length})</h6>
                    ${report.dangerous_permissions.map(p => `
                        <div class="mb-2">
                             <span class="severity-chip severity-high">${p.permission.split('.').pop()}</span>
                             <span class="text-secondary font-mono" style="font-size:0.8rem"> - ${p.description}</span>
                        </div>
                    `).join('')}
                    
                    <h6 class="text-secondary font-tech mt-4 mb-2">ALL PERMISSIONS (${report.permissions.length})</h6>
                    <div style="max-height: 150px; overflow-y: auto; font-size: 0.75rem;" class="font-mono text-secondary">
                        ${report.permissions.join('<br>')}
                    </div>
                </div>
            </div>

            <!-- Secrets Tab -->
            <div class="tab-pane fade" id="apk-secrets" role="tabpanel">
                <div class="row">
                    <div class="col-md-6">
                        <div class="neo-card p-3 h-100">
                             <h6 class="text-orange font-tech mb-3"><i class="fas fa-key"></i> HARDCODED SECRETS</h6>
                             ${report.secrets.length > 0 ? report.secrets.map(s => `
                                <div class="mb-1 text-break">
                                    <span class="text-orange">${s.type}:</span> <span class="font-mono text-white">${s.value}</span>
                                </div>
                             `).join('') : '<p class="text-secondary">No secrets found matching patterns.</p>'}
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="neo-card p-3 h-100">
                             <h6 class="text-cyan font-tech mb-3"><i class="fas fa-link"></i> EXTRACTED URLS</h6>
                             <div style="max-height: 250px; overflow-y: auto; font-size: 0.75rem;" class="font-mono text-secondary text-break">
                                ${report.urls.length > 0 ? report.urls.join('<br>') : 'No URLs found.'}
                             </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Components Tab -->
            <div class="tab-pane fade" id="apk-components" role="tabpanel">
                <div class="neo-card p-3">
                    <div class="grid-2-col" style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                        <div>
                            <h6 class="text-lime font-tech">ACTIVITIES (${report.activities.length})</h6>
                            <div class="scroll-box-sm font-mono text-secondary">${report.activities.map(a => a.split('.').pop()).join('<br>')}</div>
                        </div>
                        <div>
                            <h6 class="text-lime font-tech">SERVICES (${report.services.length})</h6>
                            <div class="scroll-box-sm font-mono text-secondary">${report.services.map(s => s.split('.').pop()).join('<br>')}</div>
                        </div>
                        <div>
                            <h6 class="text-lime font-tech">RECEIVERS (${report.receivers.length})</h6>
                            <div class="scroll-box-sm font-mono text-secondary">${report.receivers.map(r => r.split('.').pop()).join('<br>')}</div>
                        </div>
                        <div>
                            <h6 class="text-lime font-tech">PROVIDERS (${report.providers.length})</h6>
                            <div class="scroll-box-sm font-mono text-secondary">${report.providers.map(p => p.split('.').pop()).join('<br>')}</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Security Tab -->
            <div class="tab-pane fade" id="apk-security" role="tabpanel">
                <div class="row">
                    <div class="col-md-6">
                        <div class="neo-card p-3">
                            <h6 class="text-cyan font-tech mb-3">SECURITY CONFIG</h6>
                            <table class="neo-table">
                                <tr>
                                    <td>Debuggable</td>
                                    <td>${report.security_config.debuggable ? '<span class="severity-chip severity-critical">TRUE</span>' : '<span class="text-lime">FALSE</span>'}</td>
                                </tr>
                                <tr>
                                    <td>Allow Backup</td>
                                    <td>${report.security_config.allow_backup ? '<span class="severity-chip severity-high">TRUE</span>' : '<span class="text-lime">FALSE</span>'}</td>
                                </tr>
                                <tr>
                                    <td>Cleartext Traffic</td>
                                    <td>${report.security_config.uses_cleartext_traffic ? '<span class="severity-chip severity-high">ALLOWED</span>' : '<span class="text-lime">BLOCKED</span>'}</td>
                                </tr>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    content.innerHTML = html;
}

window.clearEngineerResults = function () {
    document.getElementById('engineer-results').classList.add('d-none');
    document.getElementById('engineer-report-content').innerHTML = '';
    document.getElementById('engineer-file-input').value = '';
}

window.uploadEngineerFile = async function () {
    const input = document.getElementById('engineer-file-input');
    const file = input.files[0];
    if (!file) return;

    // UI Feedback
    const area = document.getElementById('engineer-upload-area');
    const originalContent = area.innerHTML;
    area.innerHTML = `<i class="fas fa-cog fa-spin fa-4x text-cyan"></i><h4 class="text-white mt-3">ANALYZING ARTIFACT...</h4>`;
    area.style.borderColor = 'var(--c-cyan)';

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/api/python/api/engineer/scan', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Server Error: ${response.status}`);
        }

        const result = await response.json();
        renderEngineerReport(result);

    } catch (e) {
        alert("Scan Failed: " + e.message);
    } finally {
        area.innerHTML = originalContent;
        area.style.borderColor = 'var(--c-border)';
    }
}

function renderEngineerReport(result) {
    const resultsDiv = document.getElementById('engineer-results');
    const contentDiv = document.getElementById('engineer-report-content');

    resultsDiv.classList.remove('d-none');

    let statusColor = "lime";
    let icon = "fa-check-circle";

    if (result.status === "suspicious") { statusColor = "orange"; icon = "fa-exclamation-circle"; }
    if (result.status === "malicious") { statusColor = "magenta"; icon = "fa-biohazard"; }

    let html = `
        <div class="row mb-4">
            <div class="col-md-9">
                <div style="display:flex; flex-direction:column; gap:8px;">
                     <h3 class="text-white font-tech mb-0" style="letter-spacing:1px;">
                        <i class="fas fa-file-code text-cyan"></i> ${result.filename}
                     </h3>
                     <div style="display:flex; align-items:center; gap:10px;">
                        <span class="font-mono text-secondary" style="font-size:0.85rem; background:rgba(255,255,255,0.05); padding:2px 8px; border-radius:4px;">
                            <i class="fas fa-fingerprint"></i> ${result.file_hash.substring(0, 16)}...
                        </span>
                        <span class="font-mono text-cyan" style="font-size:0.85rem; border:1px solid var(--c-cyan); padding:2px 8px; border-radius:4px;">
                            ${result.file_type}
                        </span>
                        ${result.files_scanned > 1 ? `<span class="font-mono text-lime" style="font-size:0.85rem;"><i class="fas fa-layer-group"></i> ${result.files_scanned} FILES</span>` : ''}
                     </div>
                </div>
            </div>
            <div class="col-md-3 text-end">
                <span class="severity-chip severity-${result.status === 'clean' ? 'low' : result.status === 'suspicious' ? 'high' : 'critical'}" 
                      style="font-size: 1.1rem; padding: 8px 16px; display: inline-flex; align-items: center; gap: 8px;">
                    <i class="fas ${icon}"></i> ${result.status.toUpperCase()}
                </span>
            </div>
        </div>
        
        <div class="neo-card p-4 mb-4" style="border-left: 4px solid var(--c-${statusColor}); background: linear-gradient(90deg, rgba(5,8,16,1) 0%, rgba(${result.status === 'clean' ? '0,255,0' : result.status === 'suspicious' ? '255,165,0' : '255,0,255'
        },0.05) 100%);">
            <h5 class="font-tech text-${statusColor} mb-2">TACTICAL SUMMARY</h5>
            <p class="text-white mb-1" style="font-size:1.1rem;">${result.recommendation}</p>
            ${result.detection_source ? `<div class="font-mono text-secondary"><i class="fas fa-crosshairs"></i> DETECTED BY: <span class="text-${statusColor}">${result.detection_source}</span></div>` : ''}
        </div>
    `;

    if (result.findings.length > 0) {
        html += `
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5 class="font-tech text-white mb-0">DETAILED FORENSICS</h5>
                <span class="font-mono text-secondary">${result.findings.length} THREATS IDENTIFIED</span>
            </div>
            <div class="neo-card p-0" style="overflow:hidden;">
                <table class="neo-table mb-0">
                    <thead>
                        <tr>
                            <th width="15%">SEVERITY</th>
                            <th width="20%">SOURCE</th>
                            <th>DETAILS</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

        result.findings.forEach(f => {
            // Parse finding string to extract source if possible, or guess
            // Format usually: "Rule Match: X", "ClamAV: X", "Suspicious Pattern: X"
            let source = "Unknown";
            let detail = f;
            let severity = "HIGH";

            if (f.startsWith("Rule Match:")) { source = "YARA"; detail = f.replace("Rule Match:", "").trim(); }
            else if (f.startsWith("ClamAV:")) { source = "CLAMAV"; detail = f.replace("ClamAV:", "").trim(); }
            else if (f.startsWith("Suspicious Pattern:")) { source = "HEURISTIC"; detail = f.replace("Suspicious Pattern:", "").trim(); severity = "MEDIUM"; }
            else if (f.startsWith("Known Malware:")) { source = "INTEL DB"; detail = f.replace("Known Malware:", "").trim(); severity = "CRITICAL"; }

            html += `
                <tr>
                    <td><span class="severity-chip severity-${severity === 'CRITICAL' ? 'critical' : severity === 'HIGH' ? 'high' : 'medium'}">${severity}</span></td>
                    <td class="font-mono text-cyan">${source}</td>
                    <td class="font-mono text-white">${detail}</td>
                </tr>
            `;
        });

        html += `
                    </tbody>
                </table>
            </div>
        `;
    } else {
        html += `
            <div class="neo-card p-4 text-center border-lime">
                <i class="fas fa-shield-alt fa-3x text-lime mb-3"></i>
                <h4 class="text-lime font-tech">SYSTEM SECURE</h4>
                <p class="text-secondary font-mono">No known threats or anomalies detected in this artifact.</p>
            </div>
        `;
    }

    contentDiv.innerHTML = html;
}

window.downloadJSON = function (report) {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(report, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", report.filename + "_report.json");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
}

window.downloadScript = function (os) {
    window.location.href = `/api/python/api/forensics/scripts/${os}`;
}

window.uploadTriage = async function () {
    const input = document.getElementById('triage-file-input');
    const file = input.files[0];
    if (!file) return;

    const area = document.getElementById('triage-upload-area');
    const originalContent = area.innerHTML;
    area.innerHTML = `<i class="fas fa-magic fa-spin fa-3x text-cyan"></i><p class="text-white mt-3">Parsing Forensic Data...</p>`;

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/api/python/api/forensics/triage', {
            method: 'POST',
            body: formData
        });
        const report = await response.json();
        if (report.error) throw new Error(report.error);

        renderTriageReport(report);

    } catch (e) {
        alert("Triage Parsing Failed: " + e.message);
    } finally {
        area.innerHTML = originalContent;
        input.value = '';
    }
}

function renderTriageReport(report) {
    const resultsArea = document.getElementById('forensics-results');
    const content = document.getElementById('report-content');
    resultsArea.classList.remove('d-none');

    let html = `
        <h4 class="text-cyan font-tech mb-3"><i class="fab fa-${report.os_type === 'Windows' ? 'windows' : 'linux'}"></i> ${report.os_type || 'Unknown OS'} TRIAGE REPORT</h4>
        
        ${report.anomalies.length > 0 ?
            `<div class="neo-card p-3 mb-3" style="border-left: 4px solid var(--c-magenta);">
                <h5 class="text-magenta"><i class="fas fa-exclamation-triangle"></i> ANOMALIES DETECTED</h5>
                ${report.anomalies.map(a => `
                    <div style="margin-top: 10px;">
                        <span class="severity-chip severity-${a.severity.toLowerCase()}">${a.severity}</span>
                        <strong class="text-white ml-2">${a.title}</strong>
                        <p class="text-secondary mt-1 font-mono" style="font-size: 0.9rem;">${a.desc}</p>
                    </div>
                `).join('')}
            </div>` :
            `<div class="neo-card p-3 mb-3 border-lime">
                <h5 class="text-lime"><i class="fas fa-check-circle"></i> NO OVERT ANOMALIES DETECTED</h5>
                <p class="text-secondary">Automated checks passed. Manual review recommended.</p>
            </div>`
        }

        <p class="text-secondary font-mono">Raw data processing complete. Check original logs for full process list.</p>
    `;

    content.innerHTML = html;
}

window.clearForensicsResults = function () {
    document.getElementById('forensics-results').classList.add('d-none');
    document.getElementById('report-content').innerHTML = '';
}

function initDashboard() {
    console.log("Dashboard Loaded");

    // Auto-load groups if on tab
    const groupsTabBtn = document.querySelector('a[data-tab="groups"]');
    if (groupsTabBtn) {
        groupsTabBtn.addEventListener('click', () => {
            if (currentGroups.length === 0) searchGroups();
        });
    }

    // Auto-load feed if on tab
    const newsTabBtn = document.querySelector('a[data-tab="news"]');
    if (newsTabBtn) {
        newsTabBtn.addEventListener('click', () => {
            if (currentFeed.length === 0) refreshIntelFeed();
        });
    }

    // Auto-refresh feed every 5 minutes
    setInterval(() => {
        refreshIntelFeed();
    }, 5 * 60 * 1000);

    // Engineer Mode Buttons
    const btnScanner = document.getElementById('btn-eng-scanner');
    if (btnScanner) btnScanner.addEventListener('click', () => switchEngineerTab('scanner'));

    const btnWordlist = document.getElementById('btn-eng-wordlist');
    if (btnWordlist) btnWordlist.addEventListener('click', () => switchEngineerTab('wordlist'));

    const btnPcap = document.getElementById('btn-eng-pcap');
    if (btnPcap) btnPcap.addEventListener('click', () => switchEngineerTab('pcap'));
}


// --- Engineer Mode Tools ---

window.switchEngineerTab = function (tabName) {
    // Hide all sub-tabs
    document.querySelectorAll('.eng-subtab').forEach(el => el.classList.add('d-none'));
    document.getElementById(`eng-sub-${tabName}`).classList.remove('d-none');

    // Update buttons
    document.querySelectorAll('#tab-engineer .neo-btn').forEach(btn => btn.classList.remove('active'));
    document.getElementById(`btn-eng-${tabName}`).classList.add('active');
}

window.generateWordlist = async function () {
    const btn = document.querySelector('#eng-sub-wordlist button');
    const originalText = btn.innerText;
    btn.innerText = "GENERATING...";
    btn.disabled = true;

    const options = {
        charset: [],
        min_len: parseInt(document.getElementById('wl-min').value),
        max_len: parseInt(document.getElementById('wl-max').value),
        pattern: document.getElementById('wl-pattern').value,
        base_words: document.getElementById('wl-base').value.split('\n').filter(w => w.trim() !== ''),
        leetspeak: document.getElementById('wl-leet').checked
    };

    if (document.getElementById('wl-lower').checked) options.charset.push('lower');
    if (document.getElementById('wl-upper').checked) options.charset.push('upper');
    if (document.getElementById('wl-digits').checked) options.charset.push('digits');
    if (document.getElementById('wl-symbols').checked) options.charset.push('symbols');

    try {
        const response = await fetch('/api/python/api/engineer/wordlist', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(options)
        });
        const result = await response.json();

        if (result.error) throw new Error(result.error);

        // Update Preview
        const previewDiv = document.getElementById('wl-preview');
        previewDiv.innerHTML = result.preview.join('<br>') + (result.count ? `<br><br><span class="text-lime">Total Generated: ${result.count}</span>` : '');

        // Setup Download
        const downloadBtn = document.getElementById('wl-download-btn');
        downloadBtn.href = result.download_url;
        document.getElementById('wl-actions').classList.remove('d-none');

    } catch (e) {
        alert("Generation Failed: " + e.message);
    } finally {
        btn.innerText = originalText;
        btn.disabled = false;
    }
}

window.uploadPcapFile = async function () {
    const input = document.getElementById('pcap-file-input');
    const file = input.files[0];
    if (!file) return;

    const area = document.getElementById('pcap-upload-area');
    const originalContent = area.innerHTML;
    area.innerHTML = `<i class="fas fa-satellite-dish fa-spin fa-3x text-magenta"></i><p class="text-white mt-3">Analyzing Traffic...</p>`;

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/api/python/api/engineer/pcap', {
            method: 'POST',
            body: formData
        });
        const result = await response.json();

        if (result.error) throw new Error(result.error);

        renderPcapReport(result);

    } catch (e) {
        alert("PCAP Analysis Failed: " + e.message);
    } finally {
        area.innerHTML = originalContent;
    }
}

function renderPcapReport(result) {
    document.getElementById('pcap-upload-card').classList.add('d-none');
    document.getElementById('pcap-results').classList.remove('d-none');

    document.getElementById('pcap-count').innerText = result.packet_count.toLocaleString();
    document.getElementById('pcap-alerts-count').innerText = result.suspicious.length;

    // --- Protocol Distribution (Bar Chart) ---
    let protoHtml = "";
    let maxCount = Math.max(...Object.values(result.protocols));
    for (const [proto, count] of Object.entries(result.protocols)) {
        let percent = (count / result.packet_count) * 100;
        protoHtml += `
            <div class="mb-2">
                <div class="d-flex justify-content-between font-mono small text-secondary">
                    <span>${proto}</span>
                    <span>${count}</span>
                </div>
                <div class="progress" style="height: 6px; background: rgba(255,255,255,0.1);">
                    <div class="progress-bar bg-cyan" style="width: ${percent}%"></div>
                </div>
            </div>`;
    }
    document.getElementById('pcap-protos').innerHTML = protoHtml;

    // --- Conversations Table ---
    const talkersBody = document.getElementById('pcap-talkers-body');
    // Clear previous headers if needed, or assume table structure is generic enough
    // Ideally we'd update table headers too, but let's fit into existing "Top Talkers" slot for now or rebuild it.
    // Let's rebuild the table row content to match "Source -> Dest | Proto | Count"
    talkersBody.innerHTML = "";

    if (result.conversations && result.conversations.length > 0) {
        result.conversations.forEach(c => {
            talkersBody.innerHTML += `
                <tr>
                    <td class="font-mono text-white small">${c.pair}</td>
                    <td class="font-mono text-secondary small">${c.proto === 6 ? 'TCP' : c.proto === 17 ? 'UDP' : c.proto}</td>
                    <td class="font-mono text-cyan">${c.count}</td>
                </tr>`;
        });
    } else {
        // Fallback to top talkers if conversations not available
        result.top_talkers.forEach(([ip, count]) => {
            talkersBody.innerHTML += `<tr><td class="font-mono text-cyan" colspan="2">${ip}</td><td class="font-mono text-white">${count}</td></tr>`;
        });
    }


    // --- Extracted Data Panel ---
    const extractedDiv = document.getElementById('pcap-extracted');
    extractedDiv.innerHTML = "";

    // Files
    if (result.files_detected && result.files_detected.length > 0) {
        extractedDiv.innerHTML += `<div class="mb-2"><strong class="text-magenta"><i class="fas fa-file-download"></i> FILES DETECTED</strong></div>`;
        result.files_detected.forEach(f => {
            extractedDiv.innerHTML += `<div class="alert alert-dark border-magenta font-mono small p-2 mb-1">
                <span class="text-white">${f.type}</span> <span class="text-secondary">(${f.src} &rarr; ${f.dst})</span>
            </div>`;
        });
    }

    // TLS SNI
    if (result.tls_sni && result.tls_sni.length > 0) {
        extractedDiv.innerHTML += `<div class="mt-3 mb-2"><strong class="text-lime"><i class="fas fa-lock"></i> ENCRYPTED DOMAINS (SNI)</strong></div>`;
        result.tls_sni.forEach(s => extractedDiv.innerHTML += `<div class="font-mono text-white small mb-1"><i class="fas fa-caret-right text-secondary"></i> ${s}</div>`);
    }

    // HTTP Requests
    if (result.http_requests && result.http_requests.length > 0) {
        extractedDiv.innerHTML += `<div class="mt-3 mb-2"><strong class="text-cyan"><i class="fas fa-globe"></i> HTTP REQUESTS</strong></div>`;
        result.http_requests.forEach(r => {
            extractedDiv.innerHTML += `<div class="font-mono small mb-1 border-bottom border-secondary pb-1">
                <span class="text-lime">${r.method}</span> <span class="text-white">${r.host}</span><br>
                <span class="text-secondary text-truncate d-block" style="max-width: 300px;">${r.uri}</span>
            </div>`;
        });
    }

    // User Agents
    if (result.user_agents.length > 0) {
        extractedDiv.innerHTML += `<div class="mt-3 mb-2"><strong class="text-secondary">USER AGENTS</strong></div>`;
        result.user_agents.forEach(ua => extractedDiv.innerHTML += `<div class="font-mono text-white small mb-1 p-1 bg-dark text-break">${ua}</div>`);
    }

    // DNS
    if (result.dns_queries.length > 0) {
        extractedDiv.innerHTML += `<div class="mt-3 mb-2"><strong class="text-secondary">DNS QUERIES</strong></div>`;
        result.dns_queries.forEach(q => extractedDiv.innerHTML += `<div class="font-mono text-lime small mb-1">${q}</div>`);
    }

    // Suspicious
    const suspiciousDiv = document.getElementById('pcap-suspicious');
    suspiciousDiv.innerHTML = "";
    if (result.suspicious.length > 0) {
        result.suspicious.forEach(s => {
            suspiciousDiv.innerHTML += `<div class="alert alert-danger font-mono p-2 mb-1"><i class="fas fa-exclamation-triangle"></i> ${s}</div>`;
        });
        document.getElementById('pcap-alerts-count').classList.remove('bg-secondary');
        document.getElementById('pcap-alerts-count').classList.add('bg-danger');
    } else {
        suspiciousDiv.innerHTML = `<div class="text-secondary">No obvious anomalies detected.</div>`;
        document.getElementById('pcap-alerts-count').classList.remove('bg-danger');
        document.getElementById('pcap-alerts-count').classList.add('bg-secondary');
    }
}

window.resetPcap = function () {
    document.getElementById('pcap-upload-card').classList.remove('d-none');
    document.getElementById('pcap-results').classList.add('d-none');
    document.getElementById('pcap-file-input').value = "";
}


// --- BEHIND THE WALL TOOLS ---

// Tool 1: Malware Evasion
window.evadeMalware = async function () {
    const fileInput = document.getElementById('evade-file');
    if (!fileInput.files[0]) {
        alert("Please select a payload file first.");
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    const btn = document.querySelector('button[onclick="evadeMalware()"]');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-cog fa-spin"></i> OBFUSCATING...';
    btn.disabled = true;

    try {
        const response = await fetch('/api/wall/evade', {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            // Get filename from header or default
            const contentDisposition = response.headers.get('Content-Disposition');
            let filename = 'obfuscated_payload.bin';
            if (contentDisposition) {
                const filenameMatch = contentDisposition.match(/filename="?(.+)"?/);
                if (filenameMatch.length === 2)
                    filename = filenameMatch[1];
            }
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        } else {
            const errorText = await response.text();
            alert("Obfuscation failed: " + errorText);
        }
    } catch (error) {
        console.error('Error:', error);
        alert("An error occurred during obfuscation.");
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

// Tool 2: Phishing Campaign
let phishData = {};

async function initPhishing() {
    try {
        const response = await fetch('/api/wall/phish/options');
        phishData = await response.json();

        const platformSelect = document.getElementById('phish-platform');
        platformSelect.innerHTML = '<option value="">Select Platform...</option>';

        Object.keys(phishData).sort().forEach(platform => {
            platformSelect.innerHTML += `<option value="${platform}">${platform}</option>`;
        });
    } catch (e) {
        console.error("Failed to load phishing options", e);
    }
}

// Store globally
window.initPhishing = initPhishing;
// Call on load (or rely on tab click)
document.addEventListener('DOMContentLoaded', () => {
    setTimeout(initPhishing, 2000);
});

window.updatePhishScenarios = function () {
    const platform = document.getElementById('phish-platform').value;
    const scenarioSelect = document.getElementById('phish-scenario');

    scenarioSelect.innerHTML = '<option value="">Select Scenario...</option>';
    scenarioSelect.disabled = true;

    if (platform && phishData[platform]) {
        phishData[platform].scenarios.forEach(s => {
            scenarioSelect.innerHTML += `<option value="${s.name}">${s.name}</option>`;
        });
        scenarioSelect.disabled = false;
    }
}

window.generatePhish = async function () {
    const platform = document.getElementById('phish-platform').value;
    const scenario = document.getElementById('phish-scenario').value;
    const target = document.getElementById('phish-target').value;
    const link = document.getElementById('phish-link').value;

    if (!platform || !scenario || !target || !link) {
        alert("Please fill in all fields.");
        return;
    }

    const btn = document.querySelector('button[onclick="generatePhish()"]');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-cog fa-spin"></i> GENERATING...';
    btn.disabled = true;

    try {
        const response = await fetch('/api/wall/phish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ platform, scenario, target, link })
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${platform}_${scenario}.html`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        } else {
            alert("Generation failed.");
        }
    } catch (error) {
        console.error('Error:', error);
        alert("An error occurred.");
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

// Tool 3: Proxy Scraper
window.scrapeProxies = async function () {
    const listBody = document.getElementById('proxy-list');
    listBody.innerHTML = '<tr><td colspan="4" class="text-center text-secondary"><i class="fas fa-circle-notch fa-spin"></i> Scraping (Limit: 60)...</td></tr>';

    try {
        const response = await fetch('/api/wall/proxies');
        const proxies = await response.json();

        listBody.innerHTML = "";
        if (proxies.error) {
            listBody.innerHTML = `<tr><td colspan="4" class="text-danger">${proxies.error}</td></tr>`;
            return;
        }

        if (proxies.length === 0) {
            listBody.innerHTML = '<tr><td colspan="4" class="text-center text-secondary">No live proxies found.</td></tr>';
            return;
        }

        proxies.forEach(p => {
            // Assume p.country is a 2-letter code e.g. 'us'
            const flagClass = p.country ? `flag-icon flag-icon-${p.country.toLowerCase()}` : 'fas fa-globe';
            const flagHtml = p.country ? `<span class="${flagClass}"></span>` : `<i class="${flagClass}"></i>`;

            listBody.innerHTML += `
                <tr>
                    <td class="text-center">${flagHtml} <span class="small text-secondary">${p.country ? p.country.toUpperCase() : 'UNK'}</span></td>
                    <td class="font-mono text-white">${p.ip}</td>
                    <td class="font-mono text-cyan">${p.type}</td>
                    <td class="font-mono text-lime">${p.latency}</td>
                </tr>
            `;
        });
    } catch (error) {
        console.error('Error:', error);
        listBody.innerHTML = '<tr><td colspan="4" class="text-danger">Failed to fetch proxies.</td></tr>';
    }
}

// Tool 4: VPN Grabber
window.fetchVpnConfigs = async function () {
    const country = document.getElementById('vpn-country').value;
    const vpnList = document.getElementById('vpn-list');

    vpnList.innerHTML = '<div class="text-center text-secondary p-3"><i class="fas fa-circle-notch fa-spin"></i> Fetching from VPN Gate...</div>';

    try {
        const response = await fetch(`/api/wall/vpn?country=${encodeURIComponent(country)}`);
        const configs = await response.json();

        vpnList.innerHTML = "";
        if (configs.error) {
            vpnList.innerHTML = `<div class="text-danger p-2">${configs.error}</div>`;
            return;
        }

        if (configs.length === 0) {
            vpnList.innerHTML = '<div class="text-secondary p-3">No VPN configs found for this criteria.</div>';
            return;
        }

        configs.forEach(c => {
            vpnList.innerHTML += `
                <div class="neo-card p-2 mb-2 d-flex justify-content-between align-items-center">
                    <div>
                        <div class="font-mono text-white small"><i class="fas fa-flag"></i> ${c.country}</div>
                        <div class="font-mono text-secondary small">${c.ip} • Score: ${c.score}</div>
                    </div>
                    <button class="neo-btn" onclick="downloadVpnConfig('${c.config_b64}', '${c.hostname}')">
                        <i class="fas fa-download"></i> .OVPN
                    </button>
                </div>
            `;
        });
    } catch (error) {
        console.error('Error:', error);
        vpnList.innerHTML = '<div class="text-danger p-3">Failed to fetch VPN configs.</div>';
    }
}

window.downloadVpnConfig = function (b64, hostname) {
    const link = document.createElement('a');
    link.href = `data:application/x-openvpn-profile;base64,${b64}`;
    link.download = `vpngate_${hostname}.ovpn`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// --- Live Globe Logic ---
window.worldGlobe = null;

async function initGlobe() {
    // Force re-init if context was lost or broken
    const container = document.getElementById('globe-viz');
    if (!container) return;

    if (window.worldGlobe) {
        // cleanup if possible -> globe.gl doesn't have an easy destroy, so we wipe container
        // actually, re-using the instance is better if it exists and is valid.
        // But "Error creating WebGL context" suggests the instance is dead.
        // Let's wipe and recreate.
        window.worldGlobe = null;
        container.innerHTML = "";
    }

    // Critical: Check if container has dimensions. WebGL fails on 0x0.
    if (container.clientWidth === 0 || container.clientHeight === 0) {
        console.warn("Globe container has 0 dimensions. Retrying in 100ms...");
        setTimeout(initGlobe, 100);
        return;
    }

    console.log(`Initializing 3D Globe in ${container.clientWidth}x${container.clientHeight} container...`);

    if (typeof Globe === 'undefined') {
        console.error("Globe.gl library not loaded!");
        container.innerHTML = '<div class="text-danger p-5">ERROR: Globe.gl library failed to load. Check internet connection.</div>';
        return;
    }

    try {
        // Explicitly set width/height to match container
        window.worldGlobe = Globe()
            (container)
            .width(container.clientWidth)
            .height(container.clientHeight)
            .globeImageUrl('//unpkg.com/three-globe/example/img/earth-dark.jpg')
            // Minimal props to start
            .pointAltitude(0.01)
            .pointRadius('size') // Use data property
            .pointColor('color') // Use data property
            .pointLabel('label') // Tooltips
            .arcColor('color')
            .arcDashLength(0.4)
            .arcDashGap(0.2)
            .arcDashAnimateTime(2000);

        // Add colors safely (Backup if data prop fails, though usually not needed with string accessors above)
        // if (window.worldGlobe.pointColor) window.worldGlobe.pointColor(() => '#ff3333');
        // if (window.worldGlobe.arcColor) window.worldGlobe.arcColor(() => '#00f3ff');


        // Initial controls
        if (window.worldGlobe.controls) {
            const controls = window.worldGlobe.controls();
            if (controls) {
                controls.autoRotate = true;
                controls.autoRotateSpeed = 0.5;
            }
        }

        // Handle Resize
        window.addEventListener('resize', () => {
            if (window.worldGlobe && container) {
                window.worldGlobe.width(container.clientWidth);
                window.worldGlobe.height(container.clientHeight);
            }
        });

        console.log("Globe initialized successfully.");
    } catch (e) {
        console.error("Failed to init Globe:", e);
        container.innerHTML = `<div class="text-danger p-5">Globe Init Error: ${e.message}</div>`;
    }

    // Start Polling
    pollThreatData();
    setInterval(pollThreatData, 60000);
}

// --- Streaming Logic ---
const eventQueue = [];
let isStreaming = false;

function startEventStream() {
    if (isStreaming) return;
    isStreaming = true;

    // Process queue every 200ms-800ms (randomized for realism)
    const process = () => {
        const feedList = document.getElementById('live-feed-list');
        if (feedList && eventQueue.length > 0) {
            const evt = eventQueue.shift(); // Get next event

            // Deduplicate visually (check last item)
            // if (feedList.firstElementChild && feedList.firstElementChild.innerText.includes(evt.ip)) ...

            let colorClass = "text-white";
            if (evt.type.includes("Malware")) colorClass = "text-danger";
            else if (evt.type.includes("Attack")) colorClass = "text-cyan";

            const item = document.createElement('li');
            item.className = "d-flex justify-content-between mb-1";
            item.style.animation = "slideInRight 0.3s ease";
            item.innerHTML = `
                <div>
                    <span class="flag-icon flag-icon-${evt.flag}"></span>
                    <span class="${colorClass} font-mono">${evt.ip}</span>
                </div>
                <span class="text-secondary x-small font-mono">${evt.type}</span>
            `;

            feedList.prepend(item);

            // Keep list clean
            if (feedList.children.length > 15) {
                feedList.removeChild(feedList.lastElementChild);
            }
        }

        // Loop with random delay
        setTimeout(process, Math.random() * 600 + 200);
    };
    process();
}

async function pollThreatData() {
    const tab = document.getElementById('tab-live');
    if (!tab || tab.classList.contains('d-none')) return;

    try {
        // 1. Fetch Globe Data (Points & Arcs)
        const mapRes = await fetch('/api/live/map');
        if (!mapRes.ok) throw new Error("Backend Error");
        const data = await mapRes.json();
        console.log(`LiveMap: Received ${data.points.length} points, ${data.arcs.length} arcs`); // DEBUG

        // Update Globe
        if (window.worldGlobe) {
            window.worldGlobe
                .pointsData(data.points || [])
                .arcsData(data.arcs || [])
                .pointAltitude(0.01)
                .pointRadius(0.5)
                .pointColor(d => d.color || 'red')
                .arcColor(d => d.color || ['magenta', 'cyan']);
        }

        // 2. Push Events to Queue (Don't render directly)
        if (data.events && data.events.length > 0) {
            // Add unique events to queue
            data.events.forEach(evt => {
                // Simple duplication check in queue not strictly needed if backend randomizes
                // taking a subset. We just push all and let the stream flow.
                if (eventQueue.length < 50) { // Safety cap
                    eventQueue.push(evt);
                }
            });
            // Ensure stream is running
            startEventStream();
        }

        // 3. Fetch Trending Tools (Sidebar) - Update less frequently or just overwrite
        const toolsRes = await fetch('/api/live/tools');
        if (toolsRes.ok) {
            const tools = await toolsRes.json();
            const toolsList = document.getElementById('live-tools-list');
            if (toolsList) {
                toolsList.innerHTML = "";

                tools.forEach(t => {
                    let color = "text-white";
                    if (t.count > 1000) color = "text-danger"; // High threat
                    else if (t.count > 500) color = "text-warning";

                    toolsList.innerHTML += `
                        <div class="d-flex justify-content-between mb-2 p-2" style="background:rgba(255,255,255,0.05); border-radius:4px;">
                            <span class="${color} fw-bold">${t.name}</span>
                            <span class="text-secondary font-mono">${t.count} hits</span>
                        </div>
                    `;
                });
            }
        }
    } catch (e) {
        console.error("Globe Error:", e);
    }
}

// Hook into tab switching
document.addEventListener('click', function (e) {
    if (e.target.closest('[data-tab="live"]')) {
        // Wait for removal of d-none class and layout reflow
        setTimeout(() => {
            initGlobe();
        }, 300);
    }
});
