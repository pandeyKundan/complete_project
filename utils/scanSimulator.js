// 100+ Vulnerability Types Database
const VULNERABILITY_DB = {
    // Injection Flaws (10 types)
    sqli: { title: "SQL Injection", severity: "critical", cvss: 9.8, cwe: "CWE-89", remediation: "Use parameterized queries/prepared statements" },
    nosqli: { title: "NoSQL Injection", severity: "critical", cvss: 9.1, cwe: "CWE-943", remediation: "Validate input, use parameterized queries" },
    ldapi: { title: "LDAP Injection", severity: "high", cvss: 8.6, cwe: "CWE-90", remediation: "Escape LDAP special characters" },
    xpathi: { title: "XPath Injection", severity: "high", cvss: 8.2, cwe: "CWE-643", remediation: "Use parameterized XPath queries" },
    cmdi: { title: "Command Injection", severity: "critical", cvss: 9.8, cwe: "CWE-78", remediation: "Avoid system() calls, use allowlists" },
    xxei: { title: "XXE Injection", severity: "critical", cvss: 9.1, cwe: "CWE-611", remediation: "Disable external entity processing" },
    ssji: { title: "Server-Side JS Injection", severity: "critical", cvss: 9.0, cwe: "CWE-94", remediation: "Sandbox user input" },
    headeri: { title: "HTTP Header Injection", severity: "medium", cvss: 6.5, cwe: "CWE-113", remediation: "Validate and encode headers" },
    smtpi: { title: "SMTP Injection", severity: "medium", cvss: 6.8, cwe: "CWE-93", remediation: "Validate email inputs" },
    logi: { title: "Log Injection", severity: "low", cvss: 4.3, cwe: "CWE-117", remediation: "Sanitize log inputs" },
    
    // XSS Types (12 types)
    reflected_xss: { title: "Reflected XSS", severity: "high", cvss: 8.2, cwe: "CWE-79", remediation: "Output encoding, CSP headers" },
    stored_xss: { title: "Stored XSS", severity: "high", cvss: 8.6, cwe: "CWE-79", remediation: "Input validation, output encoding" },
    dom_xss: { title: "DOM-based XSS", severity: "high", cvss: 7.8, cwe: "CWE-79", remediation: "Use safe DOM methods" },
    blind_xss: { title: "Blind XSS", severity: "medium", cvss: 6.5, cwe: "CWE-79", remediation: "Implement CSP and sanitization" },
    mxss: { title: "Mutation XSS", severity: "high", cvss: 8.0, cwe: "CWE-79", remediation: "Use DOMPurify" },
    universal_xss: { title: "Universal XSS", severity: "critical", cvss: 9.0, cwe: "CWE-79", remediation: "Update browser, secure configuration" },
    self_xss: { title: "Self XSS", severity: "low", cvss: 4.0, cwe: "CWE-79", remediation: "User education" },
    post_xss: { title: "POST-based XSS", severity: "medium", cvss: 6.5, cwe: "CWE-79", remediation: "Sanitize POST data" },
    jsonp_xss: { title: "JSONP XSS", severity: "high", cvss: 7.5, cwe: "CWE-79", remediation: "Use CORS instead of JSONP" },
    angular_xss: { title: "Angular XSS", severity: "high", cvss: 8.0, cwe: "CWE-79", remediation: "Use Angular sanitization" },
    react_xss: { title: "React XSS", severity: "high", cvss: 8.0, cwe: "CWE-79", remediation: "Use dangerouslySetInnerHTML carefully" },
    vue_xss: { title: "Vue.js XSS", severity: "high", cvss: 8.0, cwe: "CWE-79", remediation: "Use v-html carefully" },
    
    // Authentication (10 types)
    broken_auth: { title: "Broken Authentication", severity: "critical", cvss: 9.0, cwe: "CWE-287", remediation: "Implement MFA, strong password policy" },
    session_fixation: { title: "Session Fixation", severity: "high", cvss: 8.0, cwe: "CWE-384", remediation: "Regenerate session ID after login" },
    weak_password: { title: "Weak Password Policy", severity: "medium", cvss: 6.5, cwe: "CWE-521", remediation: "Enforce strong password policies" },
    cred_leak: { title: "Credential Leakage", severity: "critical", cvss: 9.8, cwe: "CWE-522", remediation: "Never log credentials" },
    default_creds: { title: "Default Credentials", severity: "critical", cvss: 9.3, cwe: "CWE-798", remediation: "Change default credentials" },
    insecure_auth: { title: "Insecure Authentication", severity: "high", cvss: 8.0, cwe: "CWE-326", remediation: "Use strong encryption" },
    session_hijack: { title: "Session Hijacking", severity: "high", cvss: 7.5, cwe: "CWE-384", remediation: "Use HTTPS only" },
    jwt_vuln: { title: "JWT Vulnerability", severity: "high", cvss: 8.0, cwe: "CWE-345", remediation: "Validate JWT signature" },
    oauth_misconfig: { title: "OAuth Misconfiguration", severity: "high", cvss: 8.0, cwe: "CWE-287", remediation: "Proper OAuth validation" },
    insecure_oauth: { title: "Insecure OAuth", severity: "high", cvss: 7.5, cwe: "CWE-287", remediation: "Use PKCE" },
    
    // Access Control (10 types)
    idor: { title: "IDOR (Insecure Direct Object Reference)", severity: "high", cvss: 7.5, cwe: "CWE-639", remediation: "Implement access controls" },
    priv_esc: { title: "Privilege Escalation", severity: "critical", cvss: 9.0, cwe: "CWE-269", remediation: "Implement least privilege" },
    forza: { title: "Forced Browsing", severity: "medium", cvss: 6.5, cwe: "CWE-425", remediation: "Implement access controls" },
    path_traversal: { title: "Path Traversal", severity: "high", cvss: 8.6, cwe: "CWE-22", remediation: "Validate file paths" },
    insecure_direct: { title: "Insecure Direct Method Reference", severity: "medium", cvss: 6.8, cwe: "CWE-639", remediation: "Use indirect references" },
    mass_assignment: { title: "Mass Assignment", severity: "medium", cvss: 6.5, cwe: "CWE-915", remediation: "Allowlist parameters" },
    missing_func_auth: { title: "Missing Function-Level Auth", severity: "high", cvss: 7.5, cwe: "CWE-306", remediation: "Implement auth on all functions" },
    horizontal_priv: { title: "Horizontal Privilege Escalation", severity: "high", cvss: 7.5, cwe: "CWE-639", remediation: "Implement user-scoped access" },
    vertical_priv: { title: "Vertical Privilege Escalation", severity: "critical", cvss: 9.0, cwe: "CWE-269", remediation: "Role-based access control" },
    insecure_api: { title: "Insecure API Access", severity: "high", cvss: 8.0, cwe: "CWE-306", remediation: "API authentication required" },
    
    // Security Misconfigurations (10 types)
    debug_enabled: { title: "Debug Mode Enabled", severity: "medium", cvss: 6.5, cwe: "CWE-489", remediation: "Disable debug in production" },
    dir_listing: { title: "Directory Listing Enabled", severity: "medium", cvss: 5.8, cwe: "CWE-548", remediation: "Disable directory listing" },
    info_leak: { title: "Information Leakage", severity: "low", cvss: 4.3, cwe: "CWE-200", remediation: "Remove sensitive headers" },
    stack_trace: { title: "Stack Trace Disclosure", severity: "medium", cvss: 5.5, cwe: "CWE-209", remediation: "Disable error details" },
    cors_misconfig: { title: "CORS Misconfiguration", severity: "medium", cvss: 6.5, cwe: "CWE-346", remediation: "Restrict CORS origins" },
    security_headers: { title: "Missing Security Headers", severity: "medium", cvss: 5.8, cwe: "CWE-693", remediation: "Add CSP, HSTS, X-Frame-Options" },
    outdated_software: { title: "Outdated Software", severity: "high", cvss: 7.5, cwe: "CWE-1104", remediation: "Update all components" },
    unnecessary_features: { title: "Unnecessary Features", severity: "low", cvss: 4.0, cwe: "CWE-1108", remediation: "Remove unused features" },
    default_config: { title: "Default Configuration", severity: "medium", cvss: 6.5, cwe: "CWE-1188", remediation: "Change default configs" },
    cloud_misconfig: { title: "Cloud Misconfiguration", severity: "critical", cvss: 9.0, cwe: "CWE-664", remediation: "Review cloud security settings" },
    
    // Cryptographic Issues (8 types)
    weak_encryption: { title: "Weak Encryption", severity: "high", cvss: 7.5, cwe: "CWE-326", remediation: "Use strong encryption (AES-256)" },
    broken_crypto: { title: "Broken Cryptography", severity: "critical", cvss: 9.0, cwe: "CWE-327", remediation: "Use standard crypto libraries" },
    hardcoded_keys: { title: "Hardcoded Keys", severity: "critical", cvss: 9.8, cwe: "CWE-798", remediation: "Use environment variables" },
    weak_hash: { title: "Weak Hashing Algorithm", severity: "high", cvss: 7.5, cwe: "CWE-916", remediation: "Use bcrypt, Argon2" },
    insecure_random: { title: "Insecure Randomness", severity: "medium", cvss: 6.5, cwe: "CWE-330", remediation: "Use cryptographically secure PRNG" },
    missing_encryption: { title: "Missing Encryption", severity: "high", cvss: 7.5, cwe: "CWE-311", remediation: "Encrypt sensitive data" },
    ssl_vuln: { title: "SSL/TLS Vulnerability", severity: "high", cvss: 7.4, cwe: "CWE-295", remediation: "Use TLS 1.2+" },
    cert_vuln: { title: "Certificate Vulnerability", severity: "medium", cvss: 6.5, cwe: "CWE-295", remediation: "Proper certificate validation" },
    
    // CSRF (4 types)
    csrf: { title: "Cross-Site Request Forgery", severity: "medium", cvss: 6.5, cwe: "CWE-352", remediation: "Implement CSRF tokens" },
    login_csrf: { title: "Login CSRF", severity: "medium", cvss: 6.0, cwe: "CWE-352", remediation: "CSRF protection on login" },
    logout_csrf: { title: "Logout CSRF", severity: "low", cvss: 4.3, cwe: "CWE-352", remediation: "CSRF protection on logout" },
    json_csrf: { title: "JSON CSRF", severity: "high", cvss: 7.0, cwe: "CWE-352", remediation: "Use CSRF tokens in JSON" },
    
    // SSRF & Request Forgery (5 types)
    ssrf: { title: "Server-Side Request Forgery", severity: "high", cvss: 8.5, cwe: "CWE-918", remediation: "Validate URLs, use allowlists" },
    blind_ssrf: { title: "Blind SSRF", severity: "medium", cvss: 6.5, cwe: "CWE-918", remediation: "Validate and sanitize URLs" },
    open_redirect: { title: "Open Redirect", severity: "medium", cvss: 6.1, cwe: "CWE-601", remediation: "Validate redirect URLs" },
    host_header: { title: "Host Header Injection", severity: "medium", cvss: 6.2, cwe: "CWE-644", remediation: "Validate Host header" },
    referer_spoof: { title: "Referer Spoofing", severity: "low", cvss: 4.0, cwe: "CWE-644", remediation: "Validate referer header" },
    
    // Deserialization (4 types)
    insecure_deserialize: { title: "Insecure Deserialization", severity: "critical", cvss: 9.0, cwe: "CWE-502", remediation: "Avoid deserializing untrusted data" },
    java_deserialize: { title: "Java Deserialization", severity: "critical", cvss: 9.8, cwe: "CWE-502", remediation: "Use safe deserialization" },
    php_deserialize: { title: "PHP Deserialization", severity: "critical", cvss: 9.0, cwe: "CWE-502", remediation: "Avoid unserialize()" },
    py_deserialize: { title: "Python Pickle Deserialization", severity: "critical", cvss: 9.0, cwe: "CWE-502", remediation: "Avoid pickle" },
    
    // File Upload (5 types)
    unrestricted_upload: { title: "Unrestricted File Upload", severity: "high", cvss: 8.0, cwe: "CWE-434", remediation: "Validate file types" },
    upload_exec: { title: "Upload Executable", severity: "critical", cvss: 9.0, cwe: "CWE-434", remediation: "Disable execution in upload dir" },
    upload_shell: { title: "Web Shell Upload", severity: "critical", cvss: 9.8, cwe: "CWE-434", remediation: "Scan uploaded files" },
    upload_svg: { title: "Malicious SVG Upload", severity: "high", cvss: 7.5, cwe: "CWE-434", remediation: "Sanitize SVG files" },
    zip_traversal: { title: "Zip Path Traversal", severity: "high", cvss: 7.8, cwe: "CWE-22", remediation: "Validate zip entries" },
    
    // Business Logic (6 types)
    rate_limit: { title: "Missing Rate Limiting", severity: "medium", cvss: 6.5, cwe: "CWE-770", remediation: "Implement rate limiting" },
    brute_force: { title: "Brute Force Attack", severity: "medium", cvss: 6.0, cwe: "CWE-307", remediation: "Implement account lockout" },
    captcha_missing: { title: "Missing CAPTCHA", severity: "low", cvss: 4.0, cwe: "CWE-799", remediation: "Implement CAPTCHA" },
    business_logic: { title: "Business Logic Flaw", severity: "medium", cvss: 6.5, cwe: "CWE-840", remediation: "Implement business rules validation" },
    race_condition: { title: "Race Condition", severity: "high", cvss: 7.5, cwe: "CWE-362", remediation: "Use locks and transactions" },
    denial_of_service: { title: "Denial of Service", severity: "medium", cvss: 6.5, cwe: "CWE-400", remediation: "Implement resource limits" },
    
    // API Specific (8 types)
    graphql_intro: { title: "GraphQL Introspection", severity: "low", cvss: 4.0, cwe: "CWE-200", remediation: "Disable introspection in production" },
    graphql_dos: { title: "GraphQL DoS", severity: "medium", cvss: 6.5, cwe: "CWE-400", remediation: "Implement query depth limits" },
    restful_expose: { title: "REST API Data Exposure", severity: "medium", cvss: 6.5, cwe: "CWE-200", remediation: "Filter sensitive fields" },
    api_version: { title: "API Version Disclosure", severity: "low", cvss: 3.5, cwe: "CWE-200", remediation: "Hide API version" },
    pagination_bypass: { title: "Pagination Bypass", severity: "medium", cvss: 6.5, cwe: "CWE-639", remediation: "Implement limits" },
    batch_attack: { title: "API Batch Attack", severity: "medium", cvss: 6.5, cwe: "CWE-113", remediation: "Limit batch size" },
    api_injection: { title: "API Injection", severity: "critical", cvss: 9.0, cwe: "CWE-134", remediation: "Validate all inputs" },
    jwt_none: { title: "JWT None Algorithm", severity: "critical", cvss: 9.0, cwe: "CWE-345", remediation: "Reject 'none' algorithm" },
    
    // DDOS & Infrastructure (6 types)
    slowloris: { title: "Slowloris Attack", severity: "medium", cvss: 6.5, cwe: "CWE-400", remediation: "Configure timeouts" },
    http_dos: { title: "HTTP DoS", severity: "medium", cvss: 6.5, cwe: "CWE-400", remediation: "Implement request limits" },
    dns_amplification: { title: "DNS Amplification", severity: "medium", cvss: 6.5, cwe: "CWE-406", remediation: "Rate limiting" },
    memory_leak: { title: "Memory Leak", severity: "medium", cvss: 6.5, cwe: "CWE-401", remediation: "Proper memory management" },
    cpu_dos: { title: "CPU Exhaustion", severity: "medium", cvss: 6.5, cwe: "CWE-400", remediation: "Resource limits" },
    tmp_file: { title: "Temporary File Exposure", severity: "low", cvss: 4.3, cwe: "CWE-377", remediation: "Secure temp file creation" },
    
    // Mobile specific (5 types)
    insecure_data: { title: "Insecure Data Storage", severity: "high", cvss: 7.5, cwe: "CWE-312", remediation: "Encrypt local storage" },
    insecure_comm: { title: "Insecure Communication", severity: "high", cvss: 7.5, cwe: "CWE-319", remediation: "Use HTTPS/SSL pinning" },
    insecure_auth_mobile: { title: "Insecure Authentication", severity: "high", cvss: 7.5, cwe: "CWE-287", remediation: "Implement proper auth" },
    code_injection: { title: "Mobile Code Injection", severity: "critical", cvss: 9.0, cwe: "CWE-94", remediation: "Protect against code injection" },
    reverse_eng: { title: "Reverse Engineering", severity: "low", cvss: 4.0, cwe: "CWE-912", remediation: "Use code obfuscation" },
    
    // Zero-Day / Advanced (5 types)
    zero_day: { title: "Zero-Day Vulnerability", severity: "critical", cvss: 10.0, cwe: "CWE-0", remediation: "Apply security patches" },
    supply_chain: { title: "Supply Chain Attack", severity: "critical", cvss: 9.5, cwe: "CWE-1357", remediation: "Vet dependencies" },
    cache_poison: { title: "Cache Poisoning", severity: "high", cvss: 7.5, cwe: "CWE-525", remediation: "Proper cache headers" },
    side_channel: { title: "Side Channel Attack", severity: "medium", cvss: 6.5, cwe: "CWE-203", remediation: "Constant-time operations" },
    timing_attack: { title: "Timing Attack", severity: "medium", cvss: 5.9, cwe: "CWE-208", remediation: "Constant-time comparisons" }
};

// Convert to array and filter by scan type
function getAllVulnerabilities() {
    return Object.values(VULNERABILITY_DB);
}

function getVulnerabilitiesBySeverity(severity) {
    return Object.values(VULNERABILITY_DB).filter(v => v.severity === severity);
}

function getRandomVulnerabilities(count = 5, scanType = 'quick') {
    const all = getAllVulnerabilities();
    const shuffled = [...all];
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
    
    // Update progress function
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
        
        // Randomly add vulnerabilities
        if (Math.random() < 0.15 && step % 3 === 0) {
            const vulns = getRandomVulnerabilities(1, scanType);
            if (vulns.length > 0) {
                const vuln = vulns[0];
                const location = `${targetUrl}/api/endpoint_${Math.floor(Math.random() * 100)}`;
                await addVulnerabilityFn(scanId, vuln.title, vuln.description || `${vuln.title} detected`, vuln.severity, location, vuln.remediation, vuln.cvss, vuln.cwe);
            }
        }
        
        // Simulate time based on scan type
        const delay = scanType === 'quick' ? 150 : scanType === 'full' ? 250 : 350;
        await new Promise(resolve => setTimeout(resolve, delay));
    }
    
    // Calculate security score
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

module.exports = { simulateScan, getAllVulnerabilities, getVulnerabilitiesBySeverity, getRandomVulnerabilities };
