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
            "large-serialization": {
                "recommendation": "Performance - Offload large dataset processing to a separate stream or worker thread.",
                "fixed_code": "readStream.pipe(JSONStream.stringify()).pipe(res);",
                "category": "PERFORMANCE", "owasp": "Performance - Event Loop"
            },
            "redos": {
                "recommendation": "Performance/Security - Inefficient regex leads to CPU exhaustion. Use a non-recursive regex pattern.",
                "fixed_code": "const regex = /^[a-z]+$/; // Linear complexity",
                "category": "PERFORMANCE", "owasp": "A04:2021 - Insecure Design"
            },
            "memory-leak": {
                "recommendation": "Performance - Avoid global unbounded caches. Use a TTL-based cache (e.g., node-cache or Redis).",
                "fixed_code": "myCache.set(req.id, data, 3600);",
                "category": "PERFORMANCE", "owasp": "Performance - Memory"
            },
            "blocking-loop": {
                "recommendation": "Performance - Offload heavy computations to Worker Threads or use async iterations.",
                "fixed_code": "setImmediate(() => { processItem(item); });",
                "category": "PERFORMANCE", "owasp": "Performance - CPU"
            },
            "database-pooling-exhaustion": {
                "recommendation": "Performance - Increase database pool size or implement query queuing to handle spikes.",
                "fixed_code": "const pool = mysql.createPool({ connectionLimit: 50 });",
                "category": "PERFORMANCE", "owasp": "Performance - DB Pool"
            },
            "synchronous-fs": {
                "recommendation": "Performance - Replace synchronous FS calls with async/await or .promises.",
                "fixed_code": "await fs.promises.writeFile('/tmp/log.txt', data);",
                "category": "PERFORMANCE", "owasp": "Performance - Sync I/O"
            },
            "excessive-logging": {
                "recommendation": "Performance - Reduce logging verbosity in production. Use a streaming logger like 'pino'.",
                "fixed_code": "logger.level = 'info'; logger.info('Transaction complete');",
                "category": "PERFORMANCE", "owasp": "Performance - Disk I/O"
            }
        }

        # Scorecard Silos
        owasp_scorecard = { FIX_KB[key]["owasp"]: "PASS" for key in FIX_KB if "A" in key }
        perf_scorecard = { "Scalability": "PASS", "Efficiency": "PASS", "Stability": "PASS" }

        for issue in results:
            check_id = issue.get('check_id', '')
            extra = issue.get('extra', {})
            severity = extra.get('severity', 'LOW')
            
            # Map rule to Category/OWASP
            vuln_type = "generic"
            for key in FIX_KB:
                if key.lower() in check_id.lower():
                    vuln_type = key
                    full_owasp = FIX_KB[key].get("owasp", "N/A")
                    
                    # Security Logic
                    if severity in ["ERROR", "WARNING"] and full_owasp in owasp_scorecard:
                        owasp_scorecard[full_owasp] = "FAIL"
                    
                    # Performance Logic
                    if "performance" in check_id.lower() and severity in ["ERROR", "WARNING"]:
                        if "n-plus-one" in check_id.lower() or "pooling" in check_id.lower(): perf_scorecard["Scalability"] = "FAIL"
                        if "memory-leak" in check_id.lower() or "serialization" in check_id.lower() or "logging" in check_id.lower(): perf_scorecard["Efficiency"] = "FAIL"
                        if "blocking-loop" in check_id.lower() or "redos" in check_id.lower() or "synchronous-fs" in check_id.lower(): perf_scorecard["Stability"] = "FAIL"
                    break

            fix_info = FIX_KB.get(vuln_type, {
                "recommendation": "General security hardening recommended.",
                "fixed_code": "// Review security at this line",
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
                "depth": "High" if len(results) > 40 else "Medium" if len(results) > 10 else "Low"
            },
            "owasp_scorecard": owasp_scorecard,
            "perf_scorecard": perf_scorecard
        }
    except Exception as e:
        return {"error": str(e), "prioritized_alerts": []}
