import streamlit as st
import pandas as pd
import requests
import matplotlib.pyplot as plt
import os

# Configuration
API_URL = "http://localhost:8000/api"

# Design
st.set_page_config(page_title="AI Intelligence Testing Platform", layout="wide")

# Sidebar
st.sidebar.title("🔍 Platform Navigation")
view = st.sidebar.radio("Go to:", ["Performance Dashboard", "Security Analysis", "Predictive Failure"])

st.title("🚀 AI-Driven Testing Platform")
st.markdown("---")

if view == "Performance Dashboard":
    st.header("⚡ Performance Insights")
    
    # Check if data exists
    if not os.path.exists("data/results.jtl"):
        st.warning("No performance data found! Run the GitHub Action pipeline to generate results.")
    else:
        # Load Raw Data
        df = pd.read_csv("data/results.jtl")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Samples", len(df))
        with col2:
            st.metric("Avg Response Time", f"{df['elapsed'].mean():.2f} ms")
        with col3:
            st.metric("Max Latency", f"{df['elapsed'].max()} ms")
            
        # Charts
        st.subheader("Response Time Trends")
        st.line_chart(df[['elapsed']])
        
        # AI Findings from Backend
        st.subheader("🤖 AI Findings (Anomalies)")
        try:
            res = requests.get(f"{API_URL}/performance").json()
            if "anomalies" in res and res["anomalies"]:
                anomalies_df = pd.DataFrame(res["anomalies"])
                st.error(f"⚠️ Found {len(anomalies_df)} anomalies!")
                st.dataframe(anomalies_df)
            else:
                st.success("✅ No performance anomalies detected.")
        except:
            st.info("💡 Backend not running - showing limited view.")

elif view == "Security Analysis":
    st.header("🔐 Security Vulnerabilities")
    
    if not os.path.exists("reports/zap_report.json"):
        st.warning("No security report found! Run the GitHub Action pipeline to generate results.")
    else:
        try:
            res = requests.get(f"{API_URL}/security").json()
            if "prioritized_alerts" in res:
                st.subheader("Vulnerability Prioritization")
                
                # Critical Count Metric
                crit_count = res.get("critical_count", 0)
                if crit_count > 0:
                    st.error(f"🚨 CRITICAL ALERTS: {crit_count}")
                
                alert_df = pd.DataFrame(res["prioritized_alerts"])
                
                # Color code priority
                def highlight_priority(val):
                    color = 'red' if val == 'CRITICAL' else 'orange' if val == 'HIGH' else 'blue'
                    return f'color: {color}'
                    
                st.dataframe(alert_df.style.map(highlight_priority, subset=['priority']))
            else:
                st.info("No prioritized alerts available yet.")
        except:
            st.info("💡 Backend not running - showing limited view.")

elif view == "Predictive Failure":
    st.header("🔮 Predictive Performance Model")
    
    if not os.path.exists("data/results.jtl"):
        st.warning("No performance data found! Run the GitHub Action pipeline to generate results.")
    else:
        threshold = st.slider("Response time threshold (ms)", 500, 5000, 1000)
        
        try:
            res = requests.post(f"{API_URL}/predict?threshold={threshold}").json()
            if "breaking_point_users" in res:
                st.write(f"### Estimated System Breaking Point: **{res['breaking_point_users']}** concurrent users")
                st.info(f"Target Threshold: {threshold} ms")
                
                # Predictions DataFrame
                pred_df = pd.DataFrame([
                    {"Load": "100 Users", "Latency": res['predictions']['at_100_users']},
                    {"Load": "500 Users", "Latency": res['predictions']['at_500_users']},
                    {"Load": "1000 Users", "Latency": res['predictions']['at_1000_users']}
                ])
                st.table(pred_df)
            else:
                st.error("Model prediction failed. Insufficient data points.")
        except:
            st.info("💡 Backend not running - showing limited view.")
