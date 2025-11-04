// Main Application Controller
class FootprintApp {
    constructor() {
        this.currentView = 'scan';
        this.scanData = null;
        this.settings = this.loadSettings();
        this.init();
        async exportPDF() {
    const generator = new ReportGenerator(this.scanData);
    await generator.generatePDF();
    }

    init() {
        this.setupEventListeners();
        this.loadSavedReports();
        console.log('FootprintAI Pro initialized');
    }

    setupEventListeners() {
        // Navigation
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const view = e.currentTarget.dataset.view;
                this.switchView(view);
            });
        });

        // Tab switching
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const tab = e.currentTarget.dataset.tab;
                this.switchTab(tab);
            });
        });

        // Start Scan
        document.getElementById('start-scan').addEventListener('click', () => {
            this.startScan();
        });

        // Stop Scan
        document.getElementById('stop-scan').addEventListener('click', () => {
            this.stopScan();
        });

        // Generate Report
        document.getElementById('generate-report').addEventListener('click', () => {
            this.generateReport();
        });

        // Export JSON
        document.getElementById('export-json').addEventListener('click', () => {
            this.exportJSON();
        });
        
        // Export PDF (add this after the export-json listener)
        document.getElementById('export-pdf').addEventListener('click', () => {
            this.exportPDF();
        });

        // Save Settings
        document.getElementById('save-settings').addEventListener('click', () => {
            this.saveSettings();
        });

        // Scan type change
        document.getElementById('scan-type').addEventListener('change', (e) => {
            const advanced = document.getElementById('advanced-options');
            if (e.target.value === 'custom') {
                advanced.style.display = 'block';
            }
        });
    }

    switchView(viewName) {
        // Update navigation
        document.querySelectorAll('.nav-btn').forEach(btn => {
            btn.classList.remove('active');
            if (btn.dataset.view === viewName) {
                btn.classList.add('active');
            }
        });

        // Update views
        document.querySelectorAll('.view').forEach(view => {
            view.classList.remove('active');
        });
        document.getElementById(`${viewName}-view`).classList.add('active');
        this.currentView = viewName;
    }

    switchTab(tabName) {
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('active');
            if (btn.dataset.tab === tabName) {
                btn.classList.add('active');
            }
        });
        this.updateResultsContent(tabName);
    }

    async startScan() {
        const target = document.getElementById('target').value.trim();
        
        if (!target) {
            alert('Please enter a target domain or IP address');
            return;
        }

        // Validate target
        if (!this.validateTarget(target)) {
            alert('Invalid target format. Please enter a valid domain or IP address.');
            return;
        }

        // Get scan configuration
        const config = this.getScanConfig();
        
        // Show progress section
        document.querySelector('.scan-card').style.display = 'none';
        document.getElementById('scan-progress').style.display = 'block';

        // Initialize scanner
        const scanner = new FootprintScanner(target, config);
        
        // Start scanning
        try {
            this.scanData = await scanner.scan();
            
            // Perform AI analysis
            if (config.aiAnalysis) {
                await this.performAIAnalysis();
            }

            // Show results
            this.displayResults();
            this.switchView('results');
            
            // Save scan to history
            this.saveScanToHistory();
            
        } catch (error) {
            console.error('Scan error:', error);
            alert('Scan failed: ' + error.message);
            this.resetScanUI();
        }
    }

    stopScan() {
        // Stop the scan
        if (window.currentScanner) {
            window.currentScanner.stop();
        }
        this.resetScanUI();
    }

    resetScanUI() {
        document.querySelector('.scan-card').style.display = 'block';
        document.getElementById('scan-progress').style.display = 'none';
        document.getElementById('progress-fill').style.width = '0%';
        document.getElementById('progress-text').textContent = '0%';
    }

    validateTarget(target) {
        // IP address pattern
        const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        // Domain pattern
        const domainPattern = /^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
        // URL pattern
        const urlPattern = /^https?:\/\//;

        // Remove protocol if present
        target = target.replace(urlPattern, '');

        return ipPattern.test(target) || domainPattern.test(target);
    }

    getScanConfig() {
        const scanType = document.getElementById('scan-type').value;
        
        const config = {
            target: document.getElementById('target').value.trim(),
            scanType: scanType,
            companyName: document.getElementById('company-name').value,
            testerName: document.getElementById('tester-name').value,
            timestamp: new Date().toISOString(),
            options: {}
        };

        // If custom, get individual options
        if (scanType === 'custom') {
            config.options = {
                whoisLookup: document.getElementById('whois-lookup').checked,
                dnsEnum: document.getElementById('dns-enum').checked,
                subdomainEnum: document.getElementById('subdomain-enum').checked,
                portScan: document.getElementById('port-scan').checked,
                serviceDetect: document.getElementById('service-detect').checked,
                sslAnalysis: document.getElementById('ssl-analysis').checked,
                headerAnalysis: document.getElementById('header-analysis').checked,
                techDetect: document.getElementById('tech-detect').checked,
                emailHarvest: document.getElementById('email-harvest').checked,
                metadataExtract: document.getElementById('metadata-extract').checked,
                socialFootprint: document.getElementById('social-footprint').checked,
                aiVulnPredict: document.getElementById('ai-vuln-predict').checked
            };
        } else {
            // Predefined profiles
            config.options = this.getProfileOptions(scanType);
        }

        config.aiAnalysis = document.getElementById('auto-ai-analysis')?.checked || true;

        return config;
    }

    getProfileOptions(profile) {
        const profiles = {
            quick: {
                whoisLookup: true,
                dnsEnum: true,
                subdomainEnum: false,
                portScan: false,
                serviceDetect: false,
                sslAnalysis: true,
                headerAnalysis: true,
                techDetect: true,
                emailHarvest: false,
                metadataExtract: false,
                socialFootprint: false,
                aiVulnPredict: true
            },
            standard: {
                whoisLookup: true,
                dnsEnum: true,
                subdomainEnum: true,
                portScan: true,
                serviceDetect: true,
                sslAnalysis: true,
                headerAnalysis: true,
                techDetect: true,
                emailHarvest: true,
                metadataExtract: false,
                socialFootprint: false,
                aiVulnPredict: true
            },
            comprehensive: {
                whoisLookup: true,
                dnsEnum: true,
                subdomainEnum: true,
                portScan: true,
                serviceDetect: true,
                sslAnalysis: true,
                headerAnalysis: true,
                techDetect: true,
                emailHarvest: true,
                metadataExtract: true,
                socialFootprint: true,
                aiVulnPredict: true
            },
            stealth: {
                whoisLookup: true,
                dnsEnum: true,
                subdomainEnum: true,
                portScan: true,
                serviceDetect: true,
                sslAnalysis: true,
                headerAnalysis: true,
                techDetect: true,
                emailHarvest: true,
                metadataExtract: true,
                socialFootprint: true,
                aiVulnPredict: true
            }
        };

        return profiles[profile] || profiles.standard;
    }

    async performAIAnalysis() {
        const aiEngine = new AIAnalysisEngine(this.scanData);
        const analysis = await aiEngine.analyze();
        this.scanData.aiAnalysis = analysis;
        
        // Show AI insights in real-time
        const insightsDiv = document.getElementById('ai-insights');
        const contentDiv = document.getElementById('ai-insights-content');
        insightsDiv.style.display = 'block';
        contentDiv.innerHTML = this.formatAIInsights(analysis);
    }

    formatAIInsights(analysis) {
        return `
            <div style="margin-bottom: 15px;">
                <strong>🎯 Risk Score:</strong> <span style="color: ${this.getRiskColor(analysis.riskScore)}">${analysis.riskScore}/100</span>
            </div>
            <div style="margin-bottom: 15px;">
                <strong>🔍 Key Findings:</strong>
                <ul style="margin-left: 20px; margin-top: 8px;">
                    ${analysis.keyFindings.map(f => `<li>${f}</li>`).join('')}
                </ul>
            </div>
            <div>
                <strong>💡 Recommendations:</strong>
                <ul style="margin-left: 20px; margin-top: 8px;">
                    ${analysis.recommendations.map(r => `<li>${r}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    getRiskColor(score) {
        if (score < 30) return 'var(--success)';
        if (score < 70) return 'var(--warning)';
        return 'var(--danger)';
    }

    displayResults() {
        // Display summary cards
        this.displaySummaryCards();
        
        // Display detailed results
        this.updateResultsContent('overview');
    }

    displaySummaryCards() {
        const summary = document.getElementById('results-summary');
        const data = this.scanData;

        summary.innerHTML = `
            <div class="summary-card">
                <h3>Total Ports Found</h3>
                <div class="value">
                    <i class="fas fa-network-wired"></i>
                    ${data.ports?.open?.length || 0}
                </div>
            </div>
            <div class="summary-card">
                <h3>Subdomains Discovered</h3>
                <div class="value">
                    <i class="fas fa-sitemap"></i>
                    ${data.subdomains?.length || 0}
                </div>
            </div>
            <div class="summary-card ${this.getRiskClass(data.aiAnalysis?.riskScore)}">
                <h3>Risk Score</h3>
                <div class="value">
                    <i class="fas fa-exclamation-triangle"></i>
                    ${data.aiAnalysis?.riskScore || 0}
                </div>
            </div>
            <div class="summary-card warning">
                <h3>Vulnerabilities</h3>
                <div class="value">
                    <i class="fas fa-bug"></i>
                    ${data.vulnerabilities?.length || 0}
                </div>
            </div>
        `;
    }

    getRiskClass(score) {
        if (score < 30) return 'success';
        if (score < 70) return 'warning';
        return 'danger';
    }

    updateResultsContent(tab) {
        const content = document.getElementById('results-content');
        const data = this.scanData;

        if (!data) {
            content.innerHTML = '<p>No scan data available</p>';
            return;
        }

        switch(tab) {
            case 'overview':
                content.innerHTML = this.generateOverviewHTML(data);
                break;
            case 'network':
                content.innerHTML = this.generateNetworkHTML(data);
                break;
            case 'dns':
                content.innerHTML = this.generateDNSHTML(data);
                break;
            case 'ports':
                content.innerHTML = this.generatePortsHTML(data);
                break;
            case 'vulnerabilities':
                content.innerHTML = this.generateVulnerabilitiesHTML(data);
                break;
            case 'ai-analysis':
                content.innerHTML = this.generateAIAnalysisHTML(data);
                break;
        }
    }

    generateOverviewHTML(data) {
        return `
            <h3><i class="fas fa-info-circle"></i> Scan Overview</h3>
            <table style="width: 100%; margin-top: 20px; border-collapse: collapse;">
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid rgba(0,212,255,0.1);"><strong>Target:</strong></td>
                    <td style="padding: 10px; border-bottom: 1px solid rgba(0,212,255,0.1);">${data.target}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid rgba(0,212,255,0.1);"><strong>Scan Type:</strong></td>
                    <td style="padding: 10px; border-bottom: 1px solid rgba(0,212,255,0.1);">${data.scanType}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid rgba(0,212,255,0.1);"><strong>Timestamp:</strong></td>
                    <td style="padding: 10px; border-bottom: 1px solid rgba(0,212,255,0.1);">${new Date(data.timestamp).toLocaleString()}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid rgba(0,212,255,0.1);"><strong>Duration:</strong></td>
                    <td style="padding: 10px; border-bottom: 1px solid rgba(0,212,255,0.1);">${data.duration || 'N/A'}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border-bottom: 1px solid rgba(0,212,255,0.1);"><strong>IP Address:</strong></td>
                    <td style="padding: 10px; border-bottom: 1px solid rgba(0,212,255,0.1);">${data.ipAddress || 'N/A'}</td>
                </tr>
            </table>
        `;
    }

    generateNetworkHTML(data) {
        return `
            <h3><i class="fas fa-network-wired"></i> Network Information</h3>
            <div style="margin-top: 20px;">
                <h4>WHOIS Information</h4>
                <pre style="background: var(--dark-bg); padding: 15px; border-radius: 8px; overflow-x: auto;">
${JSON.stringify(data.whois, null, 2)}
                </pre>
            </div>
        `;
    }

    generateDNSHTML(data) {
        return `
            <h3><i class="fas fa-server"></i> DNS Records</h3>
            <div style="margin-top: 20px;">
                ${data.dns ? Object.entries(data.dns).map(([type, records]) => `
                    <h4>${type} Records</h4>
                    <ul style="list-style: none; padding: 0;">
                        ${Array.isArray(records) ? records.map(r => `
                            <li style="padding: 8px; background: var(--dark-bg); margin: 5px 0; border-radius: 6px;">
                                ${typeof r === 'object' ? JSON.stringify(r) : r}
                            </li>
                        `).join('') : `<li>${records}</li>`}
                    </ul>
                `).join('') : '<p>No DNS data available</p>'}
            </div>
        `;
    }

    generatePortsHTML(data) {
        return `
            <h3><i class="fas fa-door-open"></i> Open Ports & Services</h3>
            <div style="margin-top: 20px;">
                ${data.ports?.open?.length ? `
                    <table style="width: 100%; border-collapse: collapse;">
                        <thead>
                            <tr style="background: var(--dark-bg);">
                                <th style="padding: 12px; text-align: left;">Port</th>
                                <th style="padding: 12px; text-align: left;">Protocol</th>
                                <th style="padding: 12px; text-align: left;">Service</th>
                                <th style="padding: 12px; text-align: left;">Version</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${data.ports.open.map(port => `
                                <tr style="border-bottom: 1px solid rgba(0,212,255,0.1);">
                                    <td style="padding: 10px;">${port.port}</td>
                                    <td style="padding: 10px;">${port.protocol}</td>
                                    <td style="padding: 10px;">${port.service}</td>
                                    <td style="padding: 10px;">${port.version || 'Unknown'}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                ` : '<p>No open ports found</p>'}
            </div>
        `;
    }

    generateVulnerabilitiesHTML(data) {
        return `
            <h3><i class="fas fa-shield-virus"></i> Potential Vulnerabilities</h3>
            <div style="margin-top: 20px;">
                ${data.vulnerabilities?.length ? data.vulnerabilities.map(vuln => `
                    <div style="background: var(--dark-bg); padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid ${this.getSeverityColor(vuln.severity)};">
                        <h4 style="color: ${this.getSeverityColor(vuln.severity)};">${vuln.title}</h4>
                        <p><strong>Severity:</strong> ${vuln.severity}</p>
                        <p><strong>Description:</strong> ${vuln.description}</p>
                        <p><strong>Recommendation:</strong> ${vuln.recommendation}</p>
                    </div>
                `).join('') : '<p>No vulnerabilities detected</p>'}
            </div>
        `;
    }

    getSeverityColor(severity) {
        const colors = {
            'Critical': 'var(--danger)',
            'High': '#ff6b35',
            'Medium': 'var(--warning)',
            'Low': '#90e0ef',
            'Info': 'var(--primary)'
        };
        return colors[severity] || 'var(--primary)';
    }

    generateAIAnalysisHTML(data) {
        const ai = data.aiAnalysis;
        return `
            <h3><i class="fas fa-brain"></i> AI-Powered Analysis</h3>
            <div style="margin-top: 20px;">
                <div style="background: var(--dark-bg); padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h4>Risk Assessment</h4>
                    <div style="margin-top: 15px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                            <span>Overall Risk Score</span>
                            <span style="color: ${this.getRiskColor(ai?.riskScore || 0)}; font-weight: bold;">${ai?.riskScore || 0}/100</span>
                        </div>
                        <div style="width: 100%; height: 20px; background: var(--dark-card); border-radius: 10px; overflow: hidden;">
                            <div style="width: ${ai?.riskScore || 0}%; height: 100%; background: ${this.getRiskColor(ai?.riskScore || 0)}; transition: width 1s ease;"></div>
                        </div>
                    </div>
                </div>

                <div style="background: var(--dark-bg); padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h4>🔍 Key Findings</h4>
                    <ul style="margin-top: 10px; line-height: 1.8;">
                        ${ai?.keyFindings?.map(f => `<li>${f}</li>`).join('') || '<li>No findings available</li>'}
                    </ul>
                </div>

                <div style="background: var(--dark-bg); padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h4>💡 AI Recommendations</h4>
                    <ul style="margin-top: 10px; line-height: 1.8;">
                        ${ai?.recommendations?.map(r => `<li>${r}</li>`).join('') || '<li>No recommendations available</li>'}
                    </ul>
                </div>

                <div style="background: var(--dark-bg); padding: 20px; border-radius: 8px;">
                    <h4>🎯 Attack Surface Analysis</h4>
                    <p style="margin-top: 10px; line-height: 1.8;">
                        ${ai?.attackSurfaceAnalysis || 'Analysis not available'}
                    </p>
                </div>
            </div>
        `;
    }

    async generateReport() {
        const generator = new ReportGenerator(this.scanData);
        await generator.generateDOCX();
    }

    exportJSON() {
        const dataStr = JSON.stringify(this.scanData, null, 2);
        const dataBlob = new Blob([dataStr], {type: 'application/json'});
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `footprint-${this.scanData.target}-${Date.now()}.json`;
        link.click();
    }

    saveScanToHistory() {
        const reports = JSON.parse(localStorage.getItem('footprint-reports') || '[]');
        reports.unshift({
            id: Date.now(),
            target: this.scanData.target,
            timestamp: this.scanData.timestamp,
            scanType: this.scanData.scanType,
            riskScore: this.scanData.aiAnalysis?.riskScore || 0
        });
        
        // Keep only last 50 reports
        if (reports.length > 50) {
            reports.length = 50;
        }
        
        localStorage.setItem('footprint-reports', JSON.stringify(reports));
        localStorage.setItem(`footprint-data-${reports[0].id}`, JSON.stringify(this.scanData));
        
        this.loadSavedReports();
    }

    loadSavedReports() {
        const reports = JSON.parse(localStorage.getItem('footprint-reports') || '[]');
        const reportsList = document.getElementById('reports-list');

        if (reports.length === 0) {
            reportsList.innerHTML = '<p style="text-align: center; color: var(--text-secondary);">No saved reports</p>';
            return;
        }

        reportsList.innerHTML = reports.map(report => `
            <div class="report-item">
                <div class="report-info">
                    <h3>${report.target}</h3>
                    <p>
                        <i class="fas fa-calendar"></i> ${new Date(report.timestamp).toLocaleString()} | 
                        <i class="fas fa-shield-alt"></i> Risk: <span style="color: ${this.getRiskColor(report.riskScore)}">${report.riskScore}</span>
                    </p>
                </div>
                <div class="report-actions">
                    <button class="btn-secondary" onclick="app.loadReport(${report.id})">
                        <i class="fas fa-eye"></i> View
                    </button>
                    <button class="btn-secondary" onclick="app.deleteReport(${report.id})">
                        <i class="fas fa-trash"></i> Delete
                    </button>
                </div>
            </div>
        `).join('');
    }

    loadReport(id) {
        const data = localStorage.getItem(`footprint-data-${id}`);
        if (data) {
            this.scanData = JSON.parse(data);
            this.displayResults();
            this.switchView('results');
        }
    }

    deleteReport(id) {
        if (confirm('Are you sure you want to delete this report?')) {
            const reports = JSON.parse(localStorage.getItem('footprint-reports') || '[]');
            const filtered = reports.filter(r => r.id !== id);
            localStorage.setItem('footprint-reports', JSON.stringify(filtered));
            localStorage.removeItem(`footprint-data-${id}`);
            this.loadSavedReports();
        }
    }

    saveSettings() {
        const settings = {
            aiModel: document.getElementById('ai-model').value,
            aiApiKey: document.getElementById('ai-api-key').value,
            autoAiAnalysis: document.getElementById('auto-ai-analysis').checked,
            threadCount: document.getElementById('thread-count').value,
            timeout: document.getElementById('timeout').value,
            userAgent: document.getElementById('user-agent').value
        };

        localStorage.setItem('footprint-settings', JSON.stringify(settings));
        alert('Settings saved successfully!');
    }

    loadSettings() {
        const settings = JSON.parse(localStorage.getItem('footprint-settings') || '{}');
        
        if (Object.keys(settings).length > 0) {
            if (document.getElementById('ai-model')) document.getElementById('ai-model').value = settings.aiModel || 'gpt-analysis';
            if (document.getElementById('ai-api-key')) document.getElementById('ai-api-key').value = settings.aiApiKey || '';
            if (document.getElementById('auto-ai-analysis')) document.getElementById('auto-ai-analysis').checked = settings.autoAiAnalysis !== false;
            if (document.getElementById('thread-count')) document.getElementById('thread-count').value = settings.threadCount || 10;
            if (document.getElementById('timeout')) document.getElementById('timeout').value = settings.timeout || 30;
            if (document.getElementById('user-agent')) document.getElementById('user-agent').value = settings.userAgent || '';
        }

        return settings;
    }
}

// Toggle advanced options
function toggleAdvanced() {
    const advanced = document.getElementById('advanced-options');
    const btn = document.querySelector('.btn-toggle-advanced');
    
    if (advanced.style.display === 'none') {
        advanced.style.display = 'block';
        btn.innerHTML = '<i class="fas fa-chevron-up"></i> Hide Advanced Options';
    } else {
        advanced.style.display = 'none';
        btn.innerHTML = '<i class="fas fa-chevron-down"></i> Advanced Options';
    }
}

// Initialize app when DOM is loaded
let app;
document.addEventListener('DOMContentLoaded', () => {
    app = new FootprintApp();
});