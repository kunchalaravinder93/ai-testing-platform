import json
import os

def prioritize_vulnerabilities(sast_file):
    """
    Intensive Intelligence Engine: Analyzes Semgrep SAST results across 
    OWASP Top 10 and Performance categories.
    """
    if not os.path.exists(sast_file):
        return {"error": "Audit report not found", "prioritized_alerts": []}

    try:
        with open(sast_file, 'r') as f:
            data = json.load(f)

        results = data.get('results', [])
        prioritized = []

        # Comprehensive AI Knowledge Base (15+ categories)
        FIX_KB = {
            "A01-broken-access-control": {
                "recommendation": "Use ACLs or Session-based ownership checks. Never trust user-provided IDs directly in SQL.",
                "fix_code": "const user = db.query('SELECT * FROM Users WHERE id = ? AND owner_id = ?', [req.params.id, req.user.id])",
                "category": "SECURITY", "owasp": "A01:2021"
            },
            "A02-cryptographic-failures": {
                "recommendation": "Use argon2 or bcrypt with high salt rounds. MD5/SHA1 are deprecated and crackable.",
                "fix_code": "const hash = await argon2.hash(password);",
                "category": "SECURITY", "owasp": "A02:2021"
            },
            "A03-injection": {
                "recommendation": "A03:2021 - Use parameterized queries to prevent SQL Injection.",
                "fix_code": "db.query('SELECT * FROM Users WHERE email = ?', [req.body.email])",
                "category": "SECURITY", "owasp": "A03:2021"
            },
            "A04-insecure-design": {
                "recommendation": "A04:2021 - Implement safe password recovery flows (e.g., token-based email links).",
                "fix_code": "const token = generateSecureToken(); sendResetEmail(user.email, token);",
                "category": "SECURITY", "owasp": "A04:2021"
            },
            "A05-security-misconfig": {
                "recommendation": "A05:2021 - Disable directory listing and server header exposure in middleware.",
                "fix_code": "app.use(express.static('public', { index: 'index.html', redirect: false }));",
                "category": "SECURITY", "owasp": "A05:2021"
            },
            "A06-vulnerable-components": {
                "recommendation": "A06:2021 - Update dependencies regularly using 'npm audit fix'.",
                "fix_code": "npm install lodash@latest",
                "category": "SECURITY", "owasp": "A06:2021"
            },
            "A07-auth-failures": {
                "recommendation": "A07:2021 - Implement rate-limiting and account lockout policies.",
                "fix_code": "const limiter = rateLimit({ windowMs: 15*60*1000, max: 5 }); app.use('/login', limiter);",
                "category": "SECURITY", "owasp": "A07:2021"
            },
            "A08-integrity-failures": {
                "recommendation": "A08:2021 - Use HTTPS for all software updates and verify signatures.",
                "fix_code": "https.get('https://updates.juiceshop.com/latest.zip', (res) => { ... });",
                "category": "SECURITY", "owasp": "A08:2021"
            },
            "A09-logging-failures": {
                "recommendation": "A09:2021 - Ensure all critical state-changing actions are logged with user context.",
                "fix_code": "logger.info(`Funds transferred by User: ${user_id}`, { amount: 100 });",
                "category": "SECURITY", "owasp": "A09:2021"
            },
            "A10-ssrf": {
                "recommendation": "A10:2021 - Use an allow-list for external domains. Never proxy untrusted URLs.",
                "fix_code": "if (ALLOWED_DOMAINS.includes(new URL(req.query.url).hostname)) { axios.get(url); }",
                "category": "SECURITY", "owasp": "A10:2021"
            },
            "memory-leak": {
                "recommendation": "Performance - Avoid global unbounded caches. Use a TTL-based cache (e.g., node-cache or Redis).",
                "fix_code": "myCache.set(req.id, data, 3600);",
                "category": "PERFORMANCE", "owasp": "Performance"
            },
            "blocking-loop": {
                "recommendation": "Performance - Offload heavy computations to Worker Threads or use async iterations.",
                "fix_code": "setImmediate(() => { processItem(item); });",
                "category": "PERFORMANCE", "owasp": "Performance"
            }
        }

        # OWASP Scorecard Silos
        owasp_scorecard = { f"A{i:02}:2021": "PASS" for i in range(1, 11) }

        for issue in results:
            check_id = issue.get('check_id', '')
            extra = issue.get('extra', {})
            severity = extra.get('severity', 'LOW')
            
            # Map rule to Category/OWASP
            vuln_type = "generic"
            for key in FIX_KB:
                if key.lower() in check_id.lower():
                    vuln_type = key
                    owasp_id = FIX_KB[key].get("owasp", "N/A")
                    # Professional Logic: Fail if Medium or above
                    if severity in ["ERROR", "WARNING"] and owasp_id in owasp_scorecard:
                        owasp_scorecard[owasp_id] = "FAIL"
                    break

            fix_info = FIX_KB.get(vuln_type, {
                "recommendation": "General security hardening recommended.",
                "fix_code": "// Review security at this line",
                "category": "SECURITY", "owasp": "N/A"
            })

            prioritized.append({
                "alert": extra.get('message', ''),
                "priority": "CRITICAL" if severity == "ERROR" else "HIGH" if severity == "WARNING" else "MEDIUM",
                "score": 90 if severity == "ERROR" else 50,
                "file": f"{issue.get('path', '')}:{issue.get('start', {}).get('line', 0)}",
                "vulnerable_code": extra.get('lines', ''),
                "recommendation": fix_info["recommendation"],
                "fixed_code": fix_info["fixed_code"],
                "category": fix_info["category"],
                "owasp": fix_info.get("owasp", "N/A"),
                "cwe": extra.get('metadata', {}).get('cwe', 'N/A')
            })

        # Calculate Final Scores
        security_score = 100 - (sum(1 for k in owasp_scorecard if owasp_scorecard[k] == "FAIL") * 10)
        performance_score = 100 - (sum(1 for a in prioritized if a['category'] == "PERFORMANCE") * 15)

        return {
            "total_alerts": len(results),
            "prioritized_alerts": prioritized,
            "health_scores": {
                "security": max(0, security_score),
                "performance": max(0, performance_score),
                "confidence": "HIGH" if len(results) > 10 else "MEDIUM"
            },
            "owasp_scorecard": owasp_scorecard
        }
    except Exception as e:
        return {"error": str(e), "prioritized_alerts": []}
