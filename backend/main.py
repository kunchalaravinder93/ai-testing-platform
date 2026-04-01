from fastapi import FastAPI
from ai_engine.anomaly import detect_anomalies
from ai_engine.prediction import predict_breaking_point
from ai_engine.vuln_prioritizer import prioritize_vulnerabilities
import json
import os

app = FastAPI(title="AI-Driven Testing Platform API")

# Paths to data files
JTL_PATH = "data/results.jtl"
ZAP_PATH = "reports/zap_report.json"
HISTORY_PATH = "data/history.json"

@app.get("/api/performance")
def get_performance_insights():
    """Returns AI insights for performance results."""
    return detect_anomalies(JTL_PATH)

@app.get("/api/security")
async def get_security_report():
    # Real scan files from pipeline
    sast_file = "reports/scan_results.json"
    dast_file = "reports/zap_report.json"
    jtl_file = "data/results.jtl"
    
    # AI Analysis
    security_data = prioritize_vulnerabilities(sast_file, dast_file)
    performance_data = detect_anomalies(jtl_file)
    
    # Merge results
    if "error" not in performance_data:
        security_data["health_scores"]["performance"] = 100 - (performance_data.get("anomaly_count", 0) * 10)
        security_data["perf_anomalies"] = performance_data.get("anomalies", [])
        security_data["endpoint_summary"] = performance_data.get("endpoint_summary", [])
        
    return security_data

@app.post("/api/predict")
def get_prediction(threshold: int = 1000):
    """Predicts performance degradation breaking point."""
    return predict_breaking_point(JTL_PATH, threshold_ms=threshold)

@app.get("/api/history")
def get_analysis_history():
    """Returns history of findings from the JSON store."""
    if os.path.exists(HISTORY_PATH):
        with open(HISTORY_PATH, "r") as f:
            return json.load(f)
    return {"message": "No historical data found"}

@app.get("/api/health")
def health_check():
    return {"status": "healthy", "engine": "AI-Driven Testing Platform v1.0"}
