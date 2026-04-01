import json
import os

def prioritize_vulnerabilities(sast_file):
    """
    Parses Semgrep SAST JSON report and applies AI logic to prioritize risks
    and generate fix recommendations for both Security and Performance.
    """
    if not os.path.exists(sast_file):
        return {"error": "SAST report not found", "prioritized_alerts": []}

    try:
        with open(sast_file, 'r') as f:
            data = json.load(f)

        results = data.get('results', [])
        prioritized = []

        # Knowledge Base for AI Fix Recommendations (Security & Performance)
        FIX_KB = {
            # Security Fixes
            "sql-injection": {
                "recommendation": "Use parameterized queries (e.g., MySQL '?', PosgreSQL '$1') instead of template strings.",
                "fix_code": "db.query('SELECT * FROM Users WHERE email = ? AND password = ?', [req.body.email, req.body.password])",
                "category": "SECURITY"
            },
            "xss": {
                "recommendation": "Use a templating engine with auto-escaping or sanitize inputs using a library like DOMPurify.",
                "fix_code": "res.render('search_results', { q: req.query.q });",
                "category": "SECURITY"
            },
            # Performance Fixes
            "select-star": {
                "recommendation": "Inefficient query. Use specialized column selects to reduce database latency and network bandwidth.",
                "fix_code": "db.query('SELECT username, email FROM UserProfile WHERE id = ?', [req.params.id])",
                "category": "PERFORMANCE"
            },
            "blocking-io": {
                "recommendation": "Synchronous file operation detected. Use 'fs.promises' to avoid blocking the event loop.",
                "fix_code": "const data = await fs.promises.readFile('/tmp/report.pdf');",
                "category": "PERFORMANCE"
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
            category = "SECURITY" # Default to security
            for key in FIX_KB:
                if key in check_id.lower():
                    vuln_type = key
                    score += 30  # Found a known high-risk pattern
                    category = FIX_KB[key]["category"]
                    break

            # Override for critical types
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
                "recommendation": "Consult OWASP or Performance best practices for this pattern.",
                "fix_code": "// Review code at this line",
                "category": "SECURITY"
            })

            prioritized.append({
                "alert": message,
                "priority": final_priority,
                "score": score,
                "file": f"{path}:{line_num}",
                "vulnerable_code": lines,
                "recommendation": fix_info["recommendation"],
                "fixed_code": fix_info["fix_code"],
                "category": category,
                "cwe": extra.get('metadata', {}).get('cwe', 'N/A')
            })

        # Calculate Health Scores
        security_score = 100
        performance_score = 100
        
        for a in prioritized:
            penalty = 20 if a['priority'] == "CRITICAL" else 10 if a['priority'] == "HIGH" else 5
            if a['category'] == "SECURITY":
                security_score -= penalty
            else:
                performance_score -= penalty
        
        # Floor at 0
        security_score = max(0, security_score)
        performance_score = max(0, performance_score)
        
        # Overall Confidence Logic
        confidence = "HIGH"
        if len(results) == 0: confidence = "MEDIUM (Limited Data)"
        
        return {
            "total_alerts": len(results),
            "prioritized_alerts": prioritized,
            "critical_count": sum(1 for a in prioritized if a['priority'] == "CRITICAL"),
            "health_scores": {
                "security": security_score,
                "performance": performance_score,
                "confidence": confidence
            }
        }
    except Exception as e:
        return {"error": str(e), "prioritized_alerts": []}

if __name__ == "__main__":
    results = prioritize_vulnerabilities("reports/sast_report.json")
    print(results)
