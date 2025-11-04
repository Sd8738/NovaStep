// Report Generator - Creates DOCX and PDF reports WITHOUT external DOCX library
class ReportGenerator {
    constructor(scanData) {
        this.scanData = scanData;
    }

    // Generate DOCX using pure JavaScript (no external library needed)
    async generateDOCX() {
        try {
            console.log('Generating DOCX report...');

            // Create DOCX content using XML
            const docxContent = this.createDOCXContent();
            
            // Convert to blob
            const blob = new Blob([docxContent], { 
                type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' 
            });
            
            // Download
            const filename = `Security_Footprint_Report_${this.sanitizeFilename(this.scanData.target)}_${Date.now()}.docx`;
            
            if (typeof saveAs !== 'undefined') {
                saveAs(blob, filename);
            } else {
                this.downloadBlob(blob, filename);
            }
            
            alert('✅ DOCX Report generated successfully!');
            console.log('DOCX report generated:', filename);

        } catch (error) {
            console.error('Error generating DOCX:', error);
            alert('❌ Error generating DOCX report. Generating text report instead...');
            this.generateTextReport();
        }
    }

    createDOCXContent() {
        // Simple DOCX XML structure
        const content = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<?mso-application progid="Word.Document"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>
${this.createDOCXTitle('SECURITY FOOTPRINTING REPORT')}
${this.createDOCXParagraph('')}
${this.createDOCXParagraph('Report Generated: ' + new Date().toLocaleString(), true)}
${this.createDOCXParagraph('Target: ' + this.scanData.target, true)}
${this.createDOCXParagraph('Company: ' + (this.scanData.companyName || 'N/A'), true)}
${this.createDOCXParagraph('Tested By: ' + (this.scanData.testerName || 'N/A'), true)}
${this.createDOCXParagraph('Scan Duration: ' + (this.scanData.duration || 'N/A'), true)}
${this.createDOCXParagraph('')}
${this.createDOCXHeading('EXECUTIVE SUMMARY')}
${this.createDOCXParagraph(`This report presents findings of a security assessment on ${this.scanData.target}. Identified: ${this.scanData.vulnerabilities?.length || 0} vulnerabilities, ${this.scanData.ports?.open?.length || 0} open ports, ${this.scanData.subdomains?.length || 0} subdomains.`)}
${this.createDOCXParagraph('Overall Risk Score: ' + (this.scanData.aiAnalysis?.riskScore || 0) + '/100', true)}
${this.createDOCXParagraph('')}
${this.createDOCXHeading('KEY FINDINGS')}
${this.createDOCXList(this.scanData.aiAnalysis?.keyFindings || ['No findings available'])}
${this.createDOCXHeading('NETWORK INFORMATION')}
${this.createDOCXParagraph('IP Address: ' + (this.scanData.ipAddress || 'N/A'))}
${this.createDOCXParagraph('')}
${this.createDOCXHeading('OPEN PORTS & SERVICES')}
${this.createPortsList()}
${this.createDOCXHeading('DISCOVERED SUBDOMAINS')}
${this.createSubdomainsList()}
${this.createDOCXHeading('TECHNOLOGY STACK')}
${this.createTechList()}
${this.createDOCXHeading('IDENTIFIED VULNERABILITIES')}
${this.createVulnList()}
${this.createDOCXHeading('AI-POWERED SECURITY ANALYSIS')}
${this.createDOCXParagraph('Risk Score: ' + (this.scanData.aiAnalysis?.riskScore || 0) + '/100', true)}
${this.createDOCXParagraph('Attack Surface Analysis: ' + (this.scanData.aiAnalysis?.attackSurfaceAnalysis || 'N/A'))}
${this.createDOCXParagraph('')}
${this.createDOCXHeading('RECOMMENDATIONS')}
${this.createDOCXList(this.scanData.aiAnalysis?.recommendations || ['No recommendations available'])}
${this.createDOCXParagraph('')}
${this.createDOCXHeading('DISCLAIMER')}
${this.createDOCXParagraph('This report is provided for authorized security testing purposes only. The findings and recommendations are based on automated scanning and AI analysis. Manual verification is recommended for critical findings.')}
</w:body>
</w:document>`;

        return content;
    }

    createDOCXTitle(text) {
        return `<w:p><w:pPr><w:jc w:val="center"/></w:pPr><w:r><w:rPr><w:b/><w:sz w:val="32"/></w:rPr><w:t>${this.escapeXML(text)}</w:t></w:r></w:p>`;
    }

    createDOCXHeading(text) {
        return `<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:rPr><w:b/><w:sz w:val="24"/></w:rPr><w:t>${this.escapeXML(text)}</w:t></w:r></w:p>`;
    }

    createDOCXParagraph(text, bold = false) {
        const boldTag = bold ? '<w:b/>' : '';
        return `<w:p><w:r><w:rPr>${boldTag}</w:rPr><w:t>${this.escapeXML(text)}</w:t></w:r></w:p>`;
    }

    createDOCXList(items) {
        return items.map(item => {
            const cleaned = this.cleanText(item);
            return `<w:p><w:pPr><w:numPr><w:ilvl w:val="0"/></w:numPr></w:pPr><w:r><w:t>• ${this.escapeXML(cleaned)}</w:t></w:r></w:p>`;
        }).join('');
    }

    createPortsList() {
        const ports = this.scanData.ports?.open || [];
        if (ports.length === 0) {
            return this.createDOCXParagraph('No open ports detected');
        }
        return ports.map(port => 
            this.createDOCXParagraph(`• Port ${port.port}: ${port.service} (${port.version || 'Unknown'})`)
        ).join('');
    }

    createSubdomainsList() {
        const subdomains = this.scanData.subdomains || [];
        if (subdomains.length === 0) {
            return this.createDOCXParagraph('No subdomains discovered');
        }
        return subdomains.slice(0, 20).map(sub => 
            this.createDOCXParagraph(`• ${sub.subdomain} (${sub.ip})`)
        ).join('');
    }

    createTechList() {
        const technologies = this.scanData.technologies || [];
        if (technologies.length === 0) {
            return this.createDOCXParagraph('No technologies detected');
        }
        return technologies.map(tech => 
            this.createDOCXParagraph(`• ${tech.name} ${tech.version} - ${tech.category}`)
        ).join('');
    }

    createVulnList() {
        const vulns = this.scanData.vulnerabilities || [];
        if (vulns.length === 0) {
            return this.createDOCXParagraph('No vulnerabilities identified');
        }
        return vulns.map((vuln, index) => `
            ${this.createDOCXParagraph(`${index + 1}. ${vuln.title}`, true)}
            ${this.createDOCXParagraph(`Severity: ${vuln.severity}`)}
            ${this.createDOCXParagraph(`Description: ${vuln.description}`)}
            ${this.createDOCXParagraph(`Recommendation: ${vuln.recommendation}`)}
            ${this.createDOCXParagraph('')}
        `).join('');
    }

    // Generate PDF Report
    async generatePDF() {
        try {
            console.log('Generating PDF report...');

            // Check if jsPDF is loaded
            if (typeof window.jspdf === 'undefined') {
                console.error('jsPDF library not loaded');
                alert('❌ PDF library not loaded. Generating text report instead...');
                this.generateTextReport();
                return;
            }

            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();

            let y = 20;
            const lineHeight = 7;
            const pageHeight = doc.internal.pageSize.height;
            const margin = 20;
            const maxWidth = 170;

            // Helper function to check page break
            const checkPageBreak = (additionalHeight = 10) => {
                if (y + additionalHeight > pageHeight - margin) {
                    doc.addPage();
                    y = 20;
                    return true;
                }
                return false;
            };

            // Add text with word wrap
            const addText = (text, fontSize = 10, bold = false) => {
                doc.setFontSize(fontSize);
                doc.setFont(undefined, bold ? 'bold' : 'normal');
                const lines = doc.splitTextToSize(text, maxWidth);
                
                lines.forEach(line => {
                    checkPageBreak();
                    doc.text(line, margin, y);
                    y += lineHeight;
                });
            };

            // Title
            doc.setFontSize(22);
            doc.setFont(undefined, 'bold');
            doc.text('SECURITY FOOTPRINTING REPORT', 105, y, { align: 'center' });
            y += 15;

            // Metadata
            addText('Report Details:', 12, true);
            addText(`Generated: ${new Date().toLocaleString()}`);
            addText(`Target: ${this.scanData.target}`);
            addText(`Company: ${this.scanData.companyName || 'N/A'}`);
            addText(`Tester: ${this.scanData.testerName || 'N/A'}`);
            addText(`Duration: ${this.scanData.duration || 'N/A'}`);
            y += 5;

            // Executive Summary
            checkPageBreak(20);
            addText('EXECUTIVE SUMMARY', 14, true);
            addText(`This report presents findings of a security assessment on ${this.scanData.target}. Identified: ${this.scanData.vulnerabilities?.length || 0} vulnerabilities, ${this.scanData.ports?.open?.length || 0} open ports, ${this.scanData.subdomains?.length || 0} subdomains.`);
            addText(`Overall Risk Score: ${this.scanData.aiAnalysis?.riskScore || 0}/100`, 10, true);
            y += 5;

            // Key Findings
            checkPageBreak(20);
            addText('KEY FINDINGS', 14, true);
            const findings = this.scanData.aiAnalysis?.keyFindings || ['No findings available'];
            findings.forEach(finding => {
                addText(this.cleanText(`• ${finding}`));
            });
            y += 5;

            // Network Information
            checkPageBreak(15);
            addText('NETWORK INFORMATION', 14, true);
            addText(`IP Address: ${this.scanData.ipAddress || 'N/A'}`);
            y += 5;

            // Open Ports
            checkPageBreak(20);
            addText('OPEN PORTS & SERVICES', 14, true);
            const ports = this.scanData.ports?.open || [];
            if (ports.length > 0) {
                ports.slice(0, 15).forEach(port => {
                    addText(`• Port ${port.port}: ${port.service} (${port.version || 'Unknown'})`);
                });
            } else {
                addText('No open ports detected');
            }
            y += 5;

            // Subdomains
            checkPageBreak(20);
            addText('DISCOVERED SUBDOMAINS', 14, true);
            const subdomains = this.scanData.subdomains || [];
            if (subdomains.length > 0) {
                subdomains.slice(0, 10).forEach(sub => {
                    addText(`• ${sub.subdomain}`);
                });
                if (subdomains.length > 10) {
                    addText(`... and ${subdomains.length - 10} more`);
                }
            } else {
                addText('No subdomains discovered');
            }
            y += 5;

            // Technologies
            checkPageBreak(20);
            addText('TECHNOLOGY STACK', 14, true);
            const technologies = this.scanData.technologies || [];
            if (technologies.length > 0) {
                technologies.forEach(tech => {
                    addText(`• ${tech.name} ${tech.version} - ${tech.category}`);
                });
            } else {
                addText('No technologies detected');
            }
            y += 5;

            // Vulnerabilities
            checkPageBreak(20);
            addText('IDENTIFIED VULNERABILITIES', 14, true);
            const vulns = this.scanData.vulnerabilities || [];
            if (vulns.length > 0) {
                vulns.forEach((vuln, index) => {
                    checkPageBreak(25);
                    addText(`${index + 1}. ${vuln.title}`, 11, true);
                    addText(`   Severity: ${vuln.severity}`);
                    addText(`   Description: ${vuln.description}`);
                    addText(`   Recommendation: ${vuln.recommendation}`);
                    y += 3;
                });
            } else {
                addText('No vulnerabilities identified');
            }
            y += 5;

            // Recommendations
            checkPageBreak(20);
            addText('RECOMMENDATIONS', 14, true);
            const recommendations = this.scanData.aiAnalysis?.recommendations || [];
            if (recommendations.length > 0) {
                recommendations.slice(0, 10).forEach(rec => {
                    addText(this.cleanText(`• ${rec}`));
                });
            } else {
                addText('No specific recommendations');
            }

            // Footer
            checkPageBreak(30);
            y = pageHeight - 30;
            doc.setFontSize(8);
            doc.setFont(undefined, 'italic');
            doc.text('This report is for authorized security testing only. Manual verification recommended.', 105, y, { align: 'center' });

            // Save PDF
            const filename = `Security_Footprint_Report_${this.sanitizeFilename(this.scanData.target)}_${Date.now()}.pdf`;
            doc.save(filename);
            
            alert('✅ PDF Report generated successfully!');
            console.log('PDF report generated:', filename);

        } catch (error) {
            console.error('Error generating PDF:', error);
            alert('❌ Error generating PDF report: ' + error.message);
            this.generateTextReport();
        }
    }

    // Generate Text Report (Fallback)
    generateTextReport() {
        console.log('Generating text report...');

        let report = `
${'='.repeat(70)}
                SECURITY FOOTPRINTING REPORT
${'='.repeat(70)}

Generated: ${new Date().toLocaleString()}
Target: ${this.scanData.target}
Company: ${this.scanData.companyName || 'N/A'}
Tester: ${this.scanData.testerName || 'N/A'}
Duration: ${this.scanData.duration || 'N/A'}

${'='.repeat(70)}
EXECUTIVE SUMMARY
${'='.repeat(70)}

Overall Risk Score: ${this.scanData.aiAnalysis?.riskScore || 0}/100

This assessment identified:
- ${this.scanData.vulnerabilities?.length || 0} Vulnerabilities
- ${this.scanData.ports?.open?.length || 0} Open Ports
- ${this.scanData.subdomains?.length || 0} Subdomains

${'='.repeat(70)}
KEY FINDINGS
${'='.repeat(70)}

${(this.scanData.aiAnalysis?.keyFindings || ['None']).map(f => this.cleanText(`• ${f}`)).join('\n')}

${'='.repeat(70)}
NETWORK INFORMATION
${'='.repeat(70)}

IP Address: ${this.scanData.ipAddress || 'N/A'}

${'='.repeat(70)}
OPEN PORTS & SERVICES
${'='.repeat(70)}

${(this.scanData.ports?.open || []).map(p => `• Port ${p.port}: ${p.service} (${p.version || 'Unknown'})`).join('\n') || 'None detected'}

${'='.repeat(70)}
DISCOVERED SUBDOMAINS
${'='.repeat(70)}

${(this.scanData.subdomains || []).slice(0, 20).map(s => `• ${s.subdomain} (${s.ip})`).join('\n') || 'None discovered'}

${'='.repeat(70)}
TECHNOLOGY STACK
${'='.repeat(70)}

${(this.scanData.technologies || []).map(t => `• ${t.name} ${t.version} - ${t.category}`).join('\n') || 'None detected'}

${'='.repeat(70)}
IDENTIFIED VULNERABILITIES
${'='.repeat(70)}

${(this.scanData.vulnerabilities || []).map((v, i) => `
${i + 1}. ${v.title}
   Severity: ${v.severity}
   Description: ${v.description}
   Recommendation: ${v.recommendation}
`).join('\n') || 'None identified'}

${'='.repeat(70)}
AI-POWERED ANALYSIS
${'='.repeat(70)}

Risk Score: ${this.scanData.aiAnalysis?.riskScore || 0}/100
Attack Surface: ${this.scanData.aiAnalysis?.attackSurfaceAnalysis || 'N/A'}

${'='.repeat(70)}
RECOMMENDATIONS
${'='.repeat(70)}

${(this.scanData.aiAnalysis?.recommendations || ['None']).map(r => this.cleanText(`• ${r}`)).join('\n')}

${'='.repeat(70)}
DISCLAIMER
${'='.repeat(70)}

This report is provided for authorized security testing purposes only.
The findings and recommendations are based on automated scanning and 
AI analysis. Manual verification is recommended for critical findings.
The testing organization assumes no liability for actions taken based 
on this report.

${'='.repeat(70)}
        `;

        const blob = new Blob([report], { type: 'text/plain;charset=utf-8' });
        const filename = `Security_Report_${this.sanitizeFilename(this.scanData.target)}_${Date.now()}.txt`;
        
        if (typeof saveAs !== 'undefined') {
            saveAs(blob, filename);
        } else {
            this.downloadBlob(blob, filename);
        }
        
        alert('✅ Text report generated successfully!');
    }

    // Helper Methods
    cleanText(text) {
        // Remove emojis and special characters
        return text.replace(/[\u{1F300}-\u{1F9FF}]/gu, '').replace(/[🚨⚠️🔓🌐🔐📦🛡️📧🔍✅👥📋🔄🔒🥷🎯🔬⚡⚙️]/g, '').trim();
    }

    escapeXML(text) {
        return text
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&apos;');
    }

    sanitizeFilename(filename) {
        return filename.replace(/[^a-z0-9]/gi, '_').toLowerCase();
    }

    downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    }
}