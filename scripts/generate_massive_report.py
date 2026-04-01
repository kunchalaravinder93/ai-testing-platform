import json
import random
import os

def generate_massive_report(output_file):
    """
    Generates a massive, enterprise-scale SAST report with 50+ findings
    distributed across a realistic project structure.
    """
    categories = [
        {"id": "A01-broken-access-control", "owasp": "A01:2021 - Broken Access Control", "severity": "ERROR", "cwe": "CWE-639"},
        {"id": "A02-cryptographic-failures", "owasp": "A02:2021 - Cryptographic Failures", "severity": "ERROR", "cwe": "CWE-327"},
        {"id": "A03-injection-sqli", "owasp": "A03:2021 - Injection", "severity": "ERROR", "cwe": "CWE-89"},
        {"id": "A03-injection-xss", "owasp": "A03:2021 - Injection", "severity": "ERROR", "cwe": "CWE-79"},
        {"id": "A04-insecure-design", "owasp": "A04:2021 - Insecure Design", "severity": "WARNING", "cwe": "CWE-640"},
        {"id": "A05-security-misconfig", "owasp": "A05:2021 - Security Misconfiguration", "severity": "WARNING", "cwe": "CWE-200"},
        {"id": "A06-vulnerable-components", "owasp": "A06:2021 - Vulnerable and Outdated Components", "severity": "WARNING", "cwe": "CWE-1321"},
        {"id": "A07-auth-failures", "owasp": "A07:2021 - Identification and Authentication Failures", "severity": "ERROR", "cwe": "CWE-307"},
        {"id": "A08-integrity-failures", "owasp": "A08:2021 - Software and Data Integrity Failures", "severity": "WARNING", "cwe": "CWE-494"},
        {"id": "A09-logging-failures", "owasp": "A09:2021 - Security Logging and Monitoring Failures", "severity": "INFO", "cwe": "CWE-778"},
        {"id": "A10-ssrf", "owasp": "A10:2021 - Server-Side Request Forgery", "severity": "ERROR", "cwe": "CWE-918"},
        {"id": "performance-n-plus-one", "owasp": "Performance - Database", "severity": "ERROR", "cwe": "CWE-1070"},
        {"id": "performance-memory-leak", "owasp": "Performance - Memory", "severity": "ERROR", "cwe": "CWE-401"},
        {"id": "performance-blocking-loop", "owasp": "Performance - CPU", "severity": "WARNING", "cwe": "CWE-834"},
        {"id": "performance-redocs", "owasp": "A04:2021 - Insecure Design", "severity": "ERROR", "cwe": "CWE-1333"}
    ]

    paths = [
        "src/api/auth.js", "src/api/users.js", "src/api/products.js",
        "lib/utils/validator.js", "lib/db/pool.js", "lib/crypto/enc.js",
        "controllers/adminController.js", "controllers/orderController.js",
        "views/templates/profile.ejs", "views/layouts/main.html",
        "config/app.js", "config/security.js", "infra/docker/env.conf"
    ]

    results = []
    # Generate 60 findings
    for i in range(60):
        cat = random.choice(categories)
        path = random.choice(paths)
        line = random.randint(10, 500)
        
        results.append({
            "check_id": f"javascript.express.{cat['id']}-{i}",
            "path": path,
            "start": {"line": line, "col": 1},
            "extra": {
                "message": f"{cat['owasp']}: Automated intelligence alert detected at scale.",
                "severity": cat['severity'],
                "lines": f"// Vulnerable code at {path}:{line}\nconst data = user_input_unchecked;",
                "metadata": {"cwe": cat['cwe'], "owasp": cat['owasp']}
            }
        })

    with open(output_file, 'w') as f:
        json.dump({"version": "1.0.0", "results": results}, f, indent=2)

if __name__ == "__main__":
    os.makedirs('reports', exist_ok=True)
    generate_massive_report('reports/sast_report.json')
    print("✅ Massive Enterprise-Scale Audit Generated (60 Findings)")
