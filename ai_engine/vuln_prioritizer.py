try:
    from .scanner_parsers import SecurityParser
except ImportError:
    from scanner_parsers import SecurityParser
import os
import sys

def prioritize_vulnerabilities(sast_file, dast_file):
    """
    Unified Intelligence Engine: Aggregates and prioritizes findings from 
    Semgrep (SAST) and OWASP ZAP (DAST).
    """
    all_findings = []
    
    # Step 1: Parse real scanner outputs
    if os.path.exists(sast_file):
        all_findings.extend(SecurityParser.parse_semgrep(sast_file))
    
    if os.path.exists(dast_file):
        all_findings.extend(SecurityParser.parse_zap(dast_file))

    if not all_findings:
        return {"error": "No scan results found", "prioritized_alerts": []}

    prioritized = []

    # Comprehensive AI Knowledge Base
    FIX_KB = {
        "A01-broken-access-control": {
            "recommendation": "Use ACLs or Session-based ownership checks. Never trust user-provided IDs directly in SQL.",
            "fixed_code": "const user = db.query('SELECT * FROM Users WHERE id = ? AND owner_id = ?', [req.params.id, req.user.id])",
            "category": "SECURITY", "owasp": "A01:2021 - Broken Access Control"
        },
        "A02-cryptographic-failures": {
            "recommendation": "Use argon2 or bcrypt with high salt rounds. MD5/SHA1 are deprecated and crackable.",
            "fixed_code": "const hash = await argon2.hash(password);",
            "category": "SECURITY", "owasp": "A02:2021 - Cryptographic Failures"
        },
        "A03-injection": {
            "recommendation": "A03:2021 - Use parameterized queries to prevent SQL Injection.",
            "fixed_code": "db.query('SELECT * FROM Users WHERE email = ?', [req.body.email])",
            "category": "SECURITY", "owasp": "A03:2021 - Injection"
        },
        "A04-insecure-design": {
            "recommendation": "A04:2021 - Implement safe password recovery flows (e.g., token-based email links).",
            "fixed_code": "const token = generateSecureToken(); sendResetEmail(user.email, token);",
            "category": "SECURITY", "owasp": "A04:2021 - Insecure Design"
        },
        "A05-security-misconfig": {
            "recommendation": "A05:2021 - Disable directory listing and server header exposure in middleware.",
            "fixed_code": "app.use(express.static('public', { index: 'index.html', redirect: false }));",
            "category": "SECURITY", "owasp": "A05:2021 - Security Misconfiguration"
        },
        "A06-vulnerable-components": {
            "recommendation": "A06:2021 - Update dependencies regularly using 'npm audit fix'.",
            "fixed_code": "npm install lodash@latest",
            "category": "SECURITY", "owasp": "A06:2021 - Vulnerable and Outdated Components"
        },
        "A07-auth-failures": {
            "recommendation": "A07:2021 - Implement rate-limiting and account lockout policies.",
            "fixed_code": "const limiter = rateLimit({ windowMs: 15*60*1000, max: 5 }); app.use('/login', limiter);",
            "category": "SECURITY", "owasp": "A07:2021 - Identification and Authentication Failures"
        },
        "A08-integrity-failures": {
            "recommendation": "A08:2021 - Use HTTPS for all software updates and verify signatures.",
            "fixed_code": "https.get('https://updates.juiceshop.com/latest.zip', (res) => { ... });",
            "category": "SECURITY", "owasp": "A08:2021 - Software and Data Integrity Failures"
        },
        "A09-logging-failures": {
            "recommendation": "A09:2021 - Ensure all critical state-changing actions are logged with user context.",
            "fixed_code": "logger.info(`Funds transferred by User: ${user_id}`, { amount: 100 });",
            "category": "SECURITY", "owasp": "A09:2021 - Security Logging and Monitoring Failures"
        },
        "A10-ssrf": {
            "recommendation": "A10:2021 - Use an allow-list for external domains. Never proxy untrusted URLs.",
            "fixed_code": "if (ALLOWED_DOMAINS.includes(new URL(req.query.url).hostname)) { axios.get(url); }",
            "category": "SECURITY", "owasp": "A10:2021 - Server-Side Request Forgery"
        },
        "Path-Traversal": {
            "recommendation": "A01:2021 - Sanitize file paths using 'path.basename' or use a safe allow-list for downloads.",
            "fixed_code": "const safePath = path.join('/var/www/uploads/', path.basename(req.query.file)); res.sendFile(safePath);",
            "category": "SECURITY", "owasp": "A01:2021 - Broken Access Control"
        },
        "Prototype-Pollution": {
            "recommendation": "A06:2021 - Update to lodash >= 4.17.21 or use safe object merge patterns (Object.create(null)).",
            "fixed_code": "npm install lodash@latest",
            "category": "SECURITY", "owasp": "A06:2021 - Vulnerable and Outdated Components"
        },
        "CORS": {
            "recommendation": "A08:2021 - Restrict CORS to specific, trusted domains. Never use '*'.",
            "fixed_code": "res.header('Access-Control-Allow-Origin', 'https://trusted.app.com');",
            "category": "SECURITY", "owasp": "A08:2021 - Software and Data Integrity Failures"
        },
        "n-plus-one": {
            "recommendation": "Performance - N+1 database problem. Use a single JOIN query instead of multiple queries in a loop.",
            "fixed_code": "db.query('SELECT p.*, r.* FROM products p LEFT JOIN reviews r ON p.id = r.p_id')",
            "category": "PERFORMANCE", "owasp": "Performance - Database"
        },
        "memory-leak": {
            "recommendation": "Performance - Avoid global unbounded caches. Use a TTL-based cache (e.g., node-cache or Redis).",
            "fixed_code": "myCache.set(req.id, data, 3600);",
            "category": "PERFORMANCE", "owasp": "Performance - Memory"
        }
    }

    # Scorecard Silos
    owasp_scorecard = { FIX_KB[key]["owasp"]: "PASS" for key in FIX_KB if "A" in key }
    perf_scorecard = { "Scalability": "PASS", "Efficiency": "PASS", "Stability": "PASS" }

    for issue in all_findings:
        vuln_type = "generic"
        for key in FIX_KB:
            if key.lower() in issue['type'].lower() or key.lower() in issue['message'].lower():
                vuln_type = key
                full_owasp = FIX_KB[key].get("owasp", "N/A")
                
                # Security logic for Scorecard
                if issue['severity'] in ["ERROR", "WARNING"] and full_owasp in owasp_scorecard:
                    owasp_scorecard[full_owasp] = "FAIL"
                
                # Performance logic for Scorecard
                if "performance" in issue['type'].lower() and issue['severity'] in ["ERROR", "WARNING"]:
                    if "n-plus-one" in issue['type'].lower(): perf_scorecard["Scalability"] = "FAIL"
                    if "memory-leak" in issue['type'].lower(): perf_scorecard["Efficiency"] = "FAIL"
                break

        fix_info = FIX_KB.get(vuln_type, {
            "recommendation": "General security hardening recommended.",
            "fixed_code": "// Review security at this location",
            "category": "SECURITY", "owasp": "N/A"
        })

        prioritized.append({
            "source": issue['source'],
            "alert": issue['message'],
            "priority": "CRITICAL" if issue['severity'] == "ERROR" else "HIGH" if issue['severity'] == "WARNING" else "MEDIUM",
            "file": issue['file'],
            "vulnerable_code": issue['evidence'],
            "recommendation": fix_info["recommendation"],
            "fixed_code": fix_info["fixed_code"],
            "category": fix_info["category"],
            "owasp": full_owasp if vuln_type != "generic" else "N/A",
            "cwe": issue['cwe']
        })

    # Weighted Scoring
    sec_fail_count = sum(1 for k in owasp_scorecard if owasp_scorecard[k] == "FAIL")
    security_score = max(0, 100 - (sec_fail_count * 10))
    
    perf_findings = [a for a in prioritized if a['category'] == "PERFORMANCE"]
    performance_score = max(0, 100 - (len(perf_findings) * 15))

    return {
        "total_alerts": len(prioritized),
        "prioritized_alerts": prioritized,
        "health_scores": {
            "security": security_score,
            "performance": performance_score,
            "depth": "High" if len(all_findings) > 20 else "Medium" if len(all_findings) > 5 else "Low"
        },
        "owasp_scorecard": owasp_scorecard,
        "perf_scorecard": perf_scorecard
    }

if __name__ == "__main__":
    import sys
    import json
    sast = sys.argv[1] if len(sys.argv) > 1 else "reports/scan_results.json"
    dast = sys.argv[2] if len(sys.argv) > 2 else "reports/zap_report.json"
    print(f"--- AI Intelligence Audit Starting (SAST: {sast} | DAST: {dast}) ---")
    results = prioritize_vulnerabilities(sast, dast)
    print(json.dumps(results, indent=4))
