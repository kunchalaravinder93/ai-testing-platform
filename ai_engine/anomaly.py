import pandas as pd
from sklearn.ensemble import IsolationForest
import json
import os

def detect_anomalies(jtl_file, contamination=0.05):
    """
    Detects latency anomalies and provides real performance stats from JMeter JTL files.
    """
    if not os.path.exists(jtl_file):
        return {"error": "JTL file not found", "total_samples": 0}

    try:
        # Step 1: Standardize parsing (CSV/JTL)
        df = pd.read_csv(jtl_file)
        
        # Step 2: Validate real JMeter columns (all lowercase or standard camelCase)
        # Standard columns: timeStamp,elapsed,label,responseCode,responseMessage,threadName,dataType,success,failureMessage,bytes,sentBytes,grpThreads,allThreads,Latency,IdleTime,Connect
        req_cols = ['elapsed', 'Latency', 'label']
        for col in req_cols:
            if col not in df.columns:
                return {"error": f"Missing standard JMeter column: {col}", "total_samples": 0}

        # Step 3: Anomaly Detection on Latency/Elapsed
        # Filter for success samples only for baseline
        clean_df = df[df['success'] == True].copy()
        if len(clean_df) < 5:
            return {"error": "Insufficient successful samples for AI analysis", "total_samples": len(df)}

        model = IsolationForest(contamination=contamination, random_state=42)
        clean_df['anomaly'] = model.fit_predict(clean_df[['elapsed', 'Latency']])
        
        # Step 4: Aggregate Stats (The "Real" Insights)
        # -1 = Anomaly
        anomalies = clean_df[clean_df['anomaly'] == -1]
        
        endpoint_summary = df.groupby('label').agg({
            'elapsed': ['mean', 'max', 'std'],
            'success': 'mean' # Throughput success rate
        }).reset_index()
        endpoint_summary.columns = ['label', 'mean', 'max', 'std', 'success_rate']

        return {
            "total_samples": len(df),
            "anomaly_count": len(anomalies),
            "anomalies": anomalies[['label', 'elapsed', 'Latency']].to_dict(orient='records'),
            "endpoint_summary": endpoint_summary.to_dict(orient='records'),
            "system_health": "OPTIMAL" if len(anomalies) < (0.1 * len(df)) else "STRESSED"
        }
    except Exception as e:
        return {"error": str(e), "total_samples": 0}

if __name__ == "__main__":
    results = detect_anomalies("data/results.jtl")
    print(json.dumps(results, indent=4))
