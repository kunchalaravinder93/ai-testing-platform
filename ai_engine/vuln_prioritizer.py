import json
import os

def prioritize_vulnerabilities(zap_file):
    """
    Parses ZAP JSON report and applies AI logic to prioritize risks.
    """
    if not os.path.exists(zap_file):
        return {"error": "ZAP report not found", "prioritized_alerts": []}

    try:
        with open(zap_file, 'r') as f:
            data = json.load(f)

        alerts = data.get('site', [{}])[0].get('alerts', [])
        prioritized = []

        for alert in alerts:
            alert_name = alert.get('alert', '')
            risk_code = int(alert.get('riskcode', '0'))
            confidence = int(alert.get('confidence', '0'))
            
            # AI Logic: Re-score based on alert type and confidence
            base_score = (risk_code * 30) + (confidence * 10)
            
            # Override for critical types
            if any(critical in alert_name for critical in ["SQL Injection", "Remote Code Execution", "Cross Site Scripting"]):
                base_score += 50
                final_priority = "CRITICAL"
            elif base_score >= 100:
                final_priority = "HIGH"
            elif base_score >= 60:
                final_priority = "MEDIUM"
            else:
                final_priority = "LOW"

            prioritized.append({
                "alert": alert_name,
                "priority": final_priority,
                "score": base_score,
                "instances": len(alert.get('instances', [])),
                "solution": alert.get('solution', '')
            })

        # Sort by score descending
        prioritized = sorted(prioritized, key=lambda x: x['score'], reverse=True)
        
        return {
            "total_alerts": len(alerts),
            "prioritized_alerts": prioritized,
            "critical_count": sum(1 for a in prioritized if a['priority'] == "CRITICAL")
        }
    except Exception as e:
        return {"error": str(e), "prioritized_alerts": []}

if __name__ == "__main__":
    results = prioritize_vulnerabilities("reports/zap_report.json")
    print(results)
