// AI-Powered Analysis Engine
class AIAnalysisEngine {
    constructor(scanData) {
        this.scanData = scanData;
        this.apiKey = localStorage.getItem('footprint-settings') ? 
            JSON.parse(localStorage.getItem('footprint-settings')).aiApiKey : null;
    }

    async analyze() {
        // If API key is available, use external AI service
        if (this.apiKey && this.apiKey.startsWith('sk-')) {
            return await this.performExternalAIAnalysis();
        }
        
        // Otherwise, use local ML-based analysis
        return await this.performLocalAIAnalysis();
    }

    async performLocalAIAnalysis() {
        // Simulate AI processing
        await this.delay(2000);

        const analysis = {
            riskScore: this.calculateRiskScore(),
            keyFindings: this.generateKeyFindings(),
            recommendations: this.generateRecommendations(),
            attackSurfaceAnalysis: this.analyzeAttackSurface(),
            threatIntelligence: this.gatherThreatIntelligence(),
            complianceStatus: this.assessCompliance(),
            prioritizedActions: this.prioritizeActions()
        };

        return analysis;
    }

    async performExternalAIAnalysis() {
        // This would call OpenAI or another AI service
        // For demo purposes, we'll use local analysis
        return await this.performLocalAIAnalysis();
    }

    calculateRiskScore() {
        let score = 0;

        // Vulnerabilities (40 points max)
        const vulnCount = this.scanData.vulnerabilities?.length || 0;
        const criticalVulns = this.scanData.vulnerabilities?.filter(v => v.severity === 'Critical').length || 0;
        const highVulns = this.scanData.vulnerabilities?.filter(v => v.severity === 'High').length || 0;

        score += Math.min(criticalVulns * 15, 30);
        score += Math.min(highVulns * 5, 20);

        // Open ports (20 points max)
        const openPorts = this.scanData.ports?.open?.length || 0;
        const sensitivePorts = [21, 23, 3306, 3389, 5432];
        const openSensitivePorts = this.scanData.ports?.open?.filter(p => 
            sensitivePorts.includes(p.port)).length || 0;

        score += Math.min(openSensitivePorts * 8, 20);

        // Missing security headers (20 points max)
        const requiredHeaders = ['Strict-Transport-Security', 'X-Content-Type-Options', 
                                 'X-Frame-Options', 'Content-Security-Policy'];
        const missingHeaders = requiredHeaders.filter(h => !this.scanData.headers?.[h]);
        score += Math.min(missingHeaders.length * 5, 20);

        // Outdated technologies (20 points max)
        const outdatedTech = this.identifyOutdatedTechnologies();
        score += Math.min(outdatedTech.length * 7, 20);

        return Math.min(Math.round(score), 100);
    }

    generateKeyFindings() {
        const findings = [];

        // Vulnerability findings
        const vulns = this.scanData.vulnerabilities || [];
        if (vulns.length > 0) {
            const critical = vulns.filter(v => v.severity === 'Critical').length;
            const high = vulns.filter(v => v.severity === 'High').length;
            
            if (critical > 0) {
                findings.push(`🚨 ${critical} critical vulnerabilit${critical > 1 ? 'ies' : 'y'} detected requiring immediate attention`);
            }
            if (high > 0) {
                findings.push(`⚠️ ${high} high-severity vulnerabilit${high > 1 ? 'ies' : 'y'} identified`);
            }
        }

        // Port findings
        const sensitivePorts = [21, 23, 3306, 3389, 5432];
        const exposedPorts = this.scanData.ports?.open?.filter(p => 
            sensitivePorts.includes(p.port)) || [];
        
        if (exposedPorts.length > 0) {
            findings.push(`🔓 ${exposedPorts.length} sensitive service${exposedPorts.length > 1 ? 's' : ''} exposed to the internet: ${exposedPorts.map(p => p.service).join(', ')}`);
        }

        // Subdomain findings
        if (this.scanData.subdomains?.length > 10) {
            findings.push(`🌐 Large attack surface detected with ${this.scanData.subdomains.length} subdomains`);
        }

        // SSL/TLS findings
        if (this.scanData.ssl?.vulnerabilities?.length > 0) {
            findings.push(`🔐 SSL/TLS configuration issues identified`);
        }

        // Technology findings
        const outdated = this.identifyOutdatedTechnologies();
        if (outdated.length > 0) {
            findings.push(`📦 ${outdated.length} outdated technolog${outdated.length > 1 ? 'ies' : 'y'} in use: ${outdated.map(t => t.name).join(', ')}`);
        }

        // Security headers
        const requiredHeaders = ['Strict-Transport-Security', 'X-Content-Type-Options', 
                                 'X-Frame-Options', 'Content-Security-Policy'];
        const missingHeaders = requiredHeaders.filter(h => !this.scanData.headers?.[h]);
        if (missingHeaders.length > 0) {
            findings.push(`🛡️ Missing ${missingHeaders.length} important security header${missingHeaders.length > 1 ? 's' : ''}`);
        }

        // Email exposure
        if (this.scanData.emails?.length > 0) {
            findings.push(`📧 ${this.scanData.emails.length} email address${this.scanData.emails.length > 1 ? 'es' : ''} publicly exposed (potential phishing targets)`);
        }

        if (findings.length === 0) {
            findings.push('✅ No major security issues detected in the initial scan');
            findings.push('🔍 Continue monitoring for emerging threats');
        }

        return findings;
    }

    generateRecommendations() {
        const recommendations = [];

        // Vulnerability-based recommendations
        const criticalVulns = this.scanData.vulnerabilities?.filter(v => v.severity === 'Critical') || [];
        if (criticalVulns.length > 0) {
            recommendations.push('🚨 URGENT: Address critical vulnerabilities immediately, starting with exposed database and remote desktop services');
        }

        // Port-based recommendations
        const exposedPorts = this.scanData.ports?.open?.filter(p => 
            [21, 23, 3306, 3389, 5432].includes(p.port)) || [];
        
        if (exposedPorts.length > 0) {
            recommendations.push(`🔒 Implement firewall rules to restrict access to ${exposedPorts.map(p => p.service).join(', ')} services`);
            recommendations.push('🌐 Consider implementing a VPN or bastion host for administrative access');
        }

        // Security headers
        const requiredHeaders = ['Strict-Transport-Security', 'X-Content-Type-Options', 
                                 'X-Frame-Options', 'Content-Security-Policy'];
        const missingHeaders = requiredHeaders.filter(h => !this.scanData.headers?.[h]);
        
        if (missingHeaders.length > 0) {
            recommendations.push(`🛡️ Add security headers: ${missingHeaders.join(', ')}`);
        }

        // SSL/TLS recommendations
        if (this.scanData.ssl) {
            if (!this.scanData.ssl.protocols.includes('TLSv1.3')) {
                recommendations.push('🔐 Enable TLS 1.3 for enhanced security');
            }
            if (this.scanData.ssl.protocols.includes('TLSv1.0') || this.scanData.ssl.protocols.includes('TLSv1.1')) {
                recommendations.push('⚠️ Disable outdated TLS 1.0 and 1.1 protocols');
            }
        }

        // Technology updates
        const outdated = this.identifyOutdatedTechnologies();
        if (outdated.length > 0) {
            recommendations.push(`📦 Update outdated software: ${outdated.map(t => `${t.name} to latest version`).join(', ')}`);
        }

        // General security practices
        recommendations.push('🔍 Implement continuous security monitoring and logging');
        recommendations.push('👥 Conduct regular security awareness training for all personnel');
        recommendations.push('📋 Establish an incident response plan and test it regularly');
        recommendations.push('🔄 Perform regular security assessments (quarterly recommended)');
        
        // Email security
        if (this.scanData.emails?.length > 0) {
            recommendations.push('📧 Implement email security solutions (SPF, DKIM, DMARC) to prevent spoofing');
        }

        // Subdomain management
        if (this.scanData.subdomains?.length > 15) {
            recommendations.push('🌐 Review and decommission unused subdomains to reduce attack surface');
        }

        return recommendations;
    }

    analyzeAttackSurface() {
        const surface = [];

        surface.push(`**Network Exposure:** ${this.scanData.ports?.open?.length || 0} open ports discovered`);
        surface.push(`**Domain Infrastructure:** ${this.scanData.subdomains?.length || 0} subdomains identified`);
        surface.push(`**Technology Stack:** ${this.scanData.technologies?.length || 0} technologies detected`);
        surface.push(`**Email Exposure:** ${this.scanData.emails?.length || 0} email addresses found`);

        const attackVectors = [];
        
        if (this.scanData.ports?.open?.some(p => p.port === 80 || p.port === 443)) {
            attackVectors.push('Web application attacks');
        }
        if (this.scanData.ports?.open?.some(p => p.port === 22)) {
            attackVectors.push('SSH brute force');
        }
        if (this.scanData.ports?.open?.some(p => p.port === 3306 || p.port === 5432)) {
            attackVectors.push('Database exploitation');
        }
        if (this.scanData.ports?.open?.some(p => p.port === 21)) {
            attackVectors.push('FTP attacks');
        }
        if (this.scanData.emails?.length > 0) {
            attackVectors.push('Phishing campaigns');
        }

        surface.push(`**Potential Attack Vectors:** ${attackVectors.join(', ') || 'None identified'}`);

        return surface.join('\n');
    }

    gatherThreatIntelligence() {
        // Simulated threat intelligence
        return {
            knownThreats: [
                'Automated scanning attempts from known botnet IPs',
                'Credential stuffing attacks targeting web portals',
                'SQL injection attempts on web forms'
            ],
            industryThreats: [
                'Increased ransomware attacks in similar sectors',
                'Supply chain attacks targeting third-party integrations'
            ],
            recommendedDefenses: [
                'Web Application Firewall (WAF)',
                'Intrusion Detection System (IDS)',
                'Multi-Factor Authentication (MFA)'
            ]
        };
    }

    assessCompliance() {
        const compliance = {
            'GDPR': 'Partial',
            'PCI DSS': 'Non-Compliant',
            'HIPAA': 'Not Applicable',
            'ISO 27001': 'Partial'
        };

        const issues = [];

        if (!this.scanData.headers?.['Strict-Transport-Security']) {
            issues.push('Missing HSTS header (GDPR, PCI DSS requirement)');
        }

        if (this.scanData.ports?.open?.some(p => p.port === 3306 && !p.ssl)) {
            issues.push('Unencrypted database connection (PCI DSS violation)');
        }

        return { status: compliance, issues };
    }

    prioritizeActions() {
        const actions = [];

        // Critical actions
        const criticalVulns = this.scanData.vulnerabilities?.filter(v => v.severity === 'Critical') || [];
        criticalVulns.forEach((vuln, index) => {
            actions.push({
                priority: 'CRITICAL',
                action: vuln.recommendation,
                timeframe: 'Immediate (24-48 hours)',
                effort: 'High'
            });
        });

        // High priority actions
        const exposedServices = this.scanData.ports?.open?.filter(p => 
            [21, 3306, 3389].includes(p.port)) || [];
        
        if (exposedServices.length > 0) {
            actions.push({
                priority: 'HIGH',
                action: 'Restrict access to sensitive services',
                timeframe: '1 week',
                effort: 'Medium'
            });
        }

        // Medium priority actions
        if (this.identifyOutdatedTechnologies().length > 0) {
            actions.push({
                priority: 'MEDIUM',
                action: 'Update outdated software components',
                timeframe: '2-4 weeks',
                effort: 'High'
            });
        }

        return actions;
    }

    identifyOutdatedTechnologies() {
        const outdated = [];
        const technologies = this.scanData.technologies || [];

        technologies.forEach(tech => {
            // Simple version checking (in production, use a vulnerability database)
            if (tech.name === 'PHP' && parseFloat(tech.version) < 8.0) {
                outdated.push(tech);
            }
            if (tech.name === 'MySQL' && parseFloat(tech.version) < 8.0) {
                outdated.push(tech);
            }
            if (tech.name === 'WordPress' && parseFloat(tech.version) < 6.0) {
                outdated.push(tech);
            }
        });

        return outdated;
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}