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
    st.header("🔐 AI SAST Intelligence (Static Analysis)")
    
    if not os.path.exists("reports/sast_report.json"):
        st.warning("No SAST report found! Run the GitHub Action pipeline to generate results.")
    else:
        try:
            res = requests.get(f"{API_URL}/security").json()
            if "prioritized_alerts" in res:
                # Detailed Code Review Expanders
                st.subheader("🔍 AI Security Code Review")
                for _, row in alert_df.iterrows():
                    with st.expander(f"🔴 {row['priority']}: {row['alert']} (CWE: {row['cwe']})"):
                        st.markdown(f"**File:** `{row['file']}`")
                        st.markdown(f"**Recommendation:** {row.get('recommendation', 'N/A')}")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.error("⚠️ Vulnerable Code")
                            st.code(row.get('vulnerable_code', '// No code available'), language='javascript')
                            
                        with col2:
                            st.success("✅ Recommended Fix")
                            st.code(row.get('fixed_code', '// Review best practices'), language='javascript')
                
                # Summary Table (Optional for overview)
                st.markdown("---")
                st.subheader("📁 Vulnerability Summary")
                st.dataframe(alert_df[["alert", "priority", "file", "score"]].style.map(highlight_priority, subset=['priority']))
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
