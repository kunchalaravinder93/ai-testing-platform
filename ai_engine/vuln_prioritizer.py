import json
import os

def prioritize_vulnerabilities(sast_file):
    """
    Parses Semgrep SAST JSON report and applies AI logic to prioritize risks
    and generate fix recommendations.
    """
    if not os.path.exists(sast_file):
        return {"error": "SAST report not found", "prioritized_alerts": []}

    try:
        with open(sast_file, 'r') as f:
            data = json.load(f)

        results = data.get('results', [])
        prioritized = []

        # Knowledge Base for AI Fix Recommendations
        FIX_KB = {
            "sql-injection": {
                "recommendation": "Use parameterized queries (e.g., MySQL '?', PosgreSQL '$1') instead of template strings.",
                "fix_code": "db.query('SELECT * FROM Users WHERE email = ? AND password = ?', [req.body.email, req.body.password])"
            },
            "xss": {
                "recommendation": "Use a templating engine with auto-escaping (like EJS or Pug) or sanitize inputs using a library like DOMPurify.",
                "fix_code": "res.render('search_results', { q: req.query.q });"
            },
            "hardcoded-secrets": {
                "recommendation": "Store secrets in environment variables or a secure Vault. Never hardcode them in source code.",
                "fix_code": "const JWT_SECRET = process.env.JWT_SECRET_KEY;"
            }
        }

        for issue in results:
            check_id = issue.get('check_id', '')
            extra = issue.get('extra', {})
            message = extra.get('message', '')
            severity = extra.get('severity', 'LOW')
            lines = extra.get('lines', 'Code snippet not available.')
            path = issue.get('path', '')
            line_num = issue.get('start', {}).get('line', 0)
            
            # AI Logic: Re-score based on severity and pattern
            score = 0
            if severity == "ERROR": score += 60
            elif severity == "WARNING": score += 30
            else: score += 10
            
            # Identify the vulnerability type for fix generation
            vuln_type = "generic"
            for key in FIX_KB:
                if key in check_id.lower():
                    vuln_type = key
                    score += 30  # Found a known high-risk pattern
                    break

            # Override for critical types (Injection, Hardcoded Secrets)
            if score >= 80:
                final_priority = "CRITICAL"
            elif score >= 50:
                final_priority = "HIGH"
            elif score >= 20:
                final_priority = "MEDIUM"
            else:
                final_priority = "LOW"

            # Get Fix Recommendation
            fix_info = FIX_KB.get(vuln_type, {
                "recommendation": "Consult OWASP Top 10 for secure coding best practices.",
                "fix_code": "// Review security at this line"
            })

            prioritized.append({
                "alert": message,
                "priority": final_priority,
                "score": score,
                "file": f"{path}:{line_num}",
                "vulnerable_code": lines,
                "recommendation": fix_info["recommendation"],
                "fixed_code": fix_info["fix_code"],
                "cwe": extra.get('metadata', {}).get('cwe', 'N/A')
            })

        # Sort by score descending
        prioritized = sorted(prioritized, key=lambda x: x['score'], reverse=True)
        
        return {
            "total_alerts": len(results),
            "prioritized_alerts": prioritized,
            "critical_count": sum(1 for a in prioritized if a['priority'] == "CRITICAL")
        }
    except Exception as e:
        return {"error": str(e), "prioritized_alerts": []}

if __name__ == "__main__":
    results = prioritize_vulnerabilities("reports/sast_report.json")
    print(results)
