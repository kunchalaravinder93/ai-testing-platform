import json
import pandas as pd
import os

class SecurityParser:
    """Unified Parser for SAST (Semgrep) and DAST (OWASP ZAP) outputs."""
    
    @staticmethod
    def parse_semgrep(file_path):
        """Parses standard Semgrep JSON output."""
        if not os.path.exists(file_path):
            return []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            results = []
            for issue in data.get('results', []):
                extra = issue.get('extra', {})
                results.append({
                    "source": "Semgrep (SAST)",
                    "type": issue.get('check_id'),
                    "message": extra.get('message'),
                    "severity": extra.get('severity', 'WARNING'),
                    "file": f"{issue.get('path')}:{issue.get('start', {}).get('line')}",
                    "evidence": extra.get('lines', '').strip(),
                    "cwe": extra.get('metadata', {}).get('cwe', 'N/A'),
                    "category": "SECURITY"
                })
            return results
        except Exception as e:
            print(f"Error parsing Semgrep: {e}")
            return []

    @staticmethod
    def parse_zap(file_path):
        """Parses OWASP ZAP Alert JSON output."""
        if not os.path.exists(file_path):
            return []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            results = []
            sites = data.get('site', [])
            for site in sites:
                for alert in site.get('alerts', []):
                    # Riskcode: 3=High, 2=Medium, 1=Low, 0=Informational
                    risk = alert.get('riskcode', '0')
                    severity = "ERROR" if risk == "3" else "WARNING" if risk == "2" else "INFO"
                    
                    for instance in alert.get('instances', []):
                        results.append({
                            "source": "ZAP (DAST)",
                            "type": alert.get('alert'),
                            "message": alert.get('alert'),
                            "severity": severity,
                            "file": f"{instance.get('method')} {instance.get('uri')}",
                            "evidence": f"Param: {instance.get('param', 'N/A')} | Evidence: {instance.get('evidence', 'N/A')}",
                            "cwe": f"CWE-{alert.get('cweid', 'N/A')}",
                            "category": "SECURITY"
                        })
            return results
        except Exception as e:
            print(f"Error parsing ZAP: {e}")
            return []

class PerformanceParser:
    """Robust parser for JMeter JTL (CSV) results."""
    
    @staticmethod
    def parse_jtl(file_path):
        """Standardizes CSV JTL into a pandas DataFrame."""
        if not os.path.exists(file_path):
            return None
        
        try:
            # Use pandas for high-fidelity parsing
            df = pd.read_csv(file_path)
            
            # Map JTL CSV headers to normalized names if needed
            # (Standard JTL headers match anomaly.py requirements)
            return df
        except Exception as e:
            print(f"Error parsing JTL: {e}")
            return None
