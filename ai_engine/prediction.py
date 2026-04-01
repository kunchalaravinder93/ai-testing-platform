import pandas as pd
from sklearn.linear_model import LinearRegression
import numpy as np
import os

def predict_breaking_point(jtl_file, threshold_ms=1000):
    """
    Predicts the user load at which the response time will breach a threshold.
    """
    if not os.path.exists(jtl_file):
        return {"error": "JTL file not found"}

    try:
        df = pd.read_csv(jtl_file)
        
        # We model elapsed (Response Time) vs allThreads (User Load)
        X = df[['allThreads']].values
        y = df['elapsed'].values
        
        if len(X) < 5:
            return {"error": "Insufficient data points for prediction"}

        model = LinearRegression()
        model.fit(X, y)
        
        # Predict at 100, 500, 1000 users
        test_loads = np.array([[100], [500], [1000]])
        predictions = model.predict(test_loads)
        
        # Calculate load at which y = threshold_ms
        # y = mx + c -> x = (y - c) / m
        intercept = model.intercept_
        coefficient = model.coef_[0]
        
        if coefficient <= 0:
            breaking_point = "N/A (Stable or improving with load)"
        else:
            breaking_point = int((threshold_ms - intercept) / coefficient)
            
        return {
            "current_mean_latency": float(df['elapsed'].mean()),
            "r_squared": float(model.score(X, y)),
            "breaking_point_users": breaking_point,
            "predictions": {
                "at_100_users": float(predictions[0]),
                "at_500_users": float(predictions[1]),
                "at_1000_users": float(predictions[2])
            }
        }
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    results = predict_breaking_point("data/results.jtl")
    print(results)
