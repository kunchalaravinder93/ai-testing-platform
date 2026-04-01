import pandas as pd
from sklearn.ensemble import IsolationForest
import json
import os

def detect_anomalies(jtl_file, contamination=0.05):
    """
    Detects latency anomalies in JMeter JTL files.
    """
    if not os.path.exists(jtl_file):
        return {"error": "JTL file not found", "anomalies": []}

    try:
        df = pd.read_csv(jtl_file)
        
        # Ensure required columns exist
        required_cols = ['elapsed', 'allThreads', 'Latency']
        for col in required_cols:
            if col not in df.columns:
                return {"error": f"Missing column: {col}", "anomalies": []}

        # Select features for anomaly detection
        features = df[['elapsed', 'Latency']]
        
        # Train IsolationForest
        model = IsolationForest(contamination=contamination, random_state=42)
        df['anomaly'] = model.fit_predict(features)
        
        # -1 indicates an anomaly
        anomalies = df[df['anomaly'] == -1]
        
        # Group by label to see which endpoints are spiking
        endpoint_summary = df.groupby('label')['elapsed'].agg(['mean', 'max', 'std']).reset_index()
        
        return {
            "total_samples": len(df),
            "anomaly_count": len(anomalies),
            "anomalies": anomalies[['label', 'elapsed', 'Latency', 'timeStamp']].to_dict(orient='records'),
            "endpoint_summary": endpoint_summary.to_dict(orient='records')
        }
    except Exception as e:
        return {"error": str(e), "anomalies": []}

if __name__ == "__main__":
    # Test with dummy data if run directly
    results = detect_anomalies("data/results.jtl")
    print(json.dumps(results, indent=4))
