const VULNERABILITY_DB = {
    sqli: { title: "SQL Injection", severity: "critical", cvss: 9.8, remediation: "Use parameterized queries/prepared statements" },
    xss: { title: "Cross-Site Scripting (XSS)", severity: "high", cvss: 8.2, remediation: "Implement output encoding and CSP headers" },
    csrf: { title: "CSRF Vulnerability", severity: "medium", cvss: 6.5, remediation: "Use anti-CSRF tokens and SameSite cookies" },
    rce: { title: "Remote Code Execution", severity: "critical", cvss: 9.9, remediation: "Strict input validation and sandboxing" },
    pathtraversal: { title: "Path Traversal", severity: "high", cvss: 7.5, remediation: "Validate file paths and use allowlists" },
    idor: { title: "Insecure Direct Object References", severity: "medium", cvss: 6.8, remediation: "Implement proper access controls" },
    misconfig: { title: "Security Misconfiguration", severity: "high", cvss: 7.8, remediation: "Harden configurations" },
    dataleak: { title: "Sensitive Data Exposure", severity: "high", cvss: 7.4, remediation: "Encrypt sensitive data" },
    xxe: { title: "XML External Entity (XXE)", severity: "critical", cvss: 9.1, remediation: "Disable XML external entity processing" },
    brokenauth: { title: "Broken Authentication", severity: "critical", cvss: 9.0, remediation: "Implement MFA and strong password policies" },
    ssrf: { title: "Server-Side Request Forgery", severity: "high", cvss: 8.5, remediation: "Validate and sanitize URLs" },
    deserialize: { title: "Insecure Deserialization", severity: "high", cvss: 8.6, remediation: "Avoid deserializing untrusted data" },
    hostheader: { title: "Host Header Injection", severity: "medium", cvss: 6.2, remediation: "Validate Host headers" },
    subdomain: { title: "Subdomain Takeover", severity: "high", cvss: 7.2, remediation: "Remove dangling DNS records" },
    clickjacking: { title: "Clickjacking", severity: "medium", cvss: 5.8, remediation: "Implement X-Frame-Options header" }
};

const vulnArray = Object.values(VULNERABILITY_DB);

function getRandomVulnerabilities(count = 5, scanType = 'quick') {
    const shuffled = [...vulnArray];
    for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    const maxCount = scanType === 'quick' ? 5 : scanType === 'full' ? 12 : 25;
    return shuffled.slice(0, Math.min(count, maxCount));
}

async function simulateScan(scanId, targetUrl, scanType, db, addVulnerabilityFn) {
    const totalSteps = scanType === 'quick' ? 20 : scanType === 'full' ? 40 : 60;
    const vulnCount = scanType === 'quick' ? 5 : scanType === 'full' ? 15 : 30;
    
    const updateProgress = async (progress) => {
        await new Promise((resolve, reject) => {
            db.run(`UPDATE scans SET progress = ? WHERE id = ?`, [progress, scanId], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    };
    
    for (let step = 1; step <= totalSteps; step++) {
        const progress = Math.floor((step / totalSteps) * 100);
        await updateProgress(progress);
        
        if (Math.random() < 0.15 && step % 3 === 0) {
            const vulns = getRandomVulnerabilities(1, scanType);
            if (vulns.length > 0) {
                const vuln = vulns[0];
                const location = `${targetUrl}/api/endpoint_${Math.floor(Math.random() * 100)}`;
                await addVulnerabilityFn(
                    scanId, 
                    vuln.title, 
                    `${vuln.title} detected in the application`,
                    vuln.severity, 
                    location, 
                    vuln.remediation
                );
            }
        }
        
        const delay = scanType === 'quick' ? 150 : scanType === 'full' ? 250 : 350;
        await new Promise(resolve => setTimeout(resolve, delay));
    }
    
    const stats = await new Promise((resolve, reject) => {
        db.get(`SELECT 
            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
            COUNT(*) as total
        FROM vulnerabilities WHERE scan_id = ?`, [scanId], (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
    
    let score = 100;
    if (stats && stats.total > 0) {
        score = Math.max(0, 100 - ((stats.critical || 0) * 20 + (stats.high || 0) * 10 + (stats.medium || 0) * 5));
    }
    
    const duration = totalSteps * (scanType === 'quick' ? 0.15 : scanType === 'full' ? 0.25 : 0.35);
    await new Promise((resolve, reject) => {
        db.run(`UPDATE scans SET status = 'completed', security_score = ?, duration_seconds = ?, completed_at = CURRENT_TIMESTAMP WHERE id = ?`,
            [Math.floor(score), Math.floor(duration), scanId], (err) => {
            if (err) reject(err);
            else resolve();
        });
    });
    await updateProgress(100);
}

module.exports = { simulateScan };
