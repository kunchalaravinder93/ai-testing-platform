import streamlit as st
import pandas as pd
import requests
import matplotlib.pyplot as plt
import os

# Configuration
API_URL = "http://localhost:8000/api"

# Design
st.set_page_config(page_title="AI Intelligence Testing Platform", layout="wide")

# Sidebar Navigation
st.sidebar.title("🛡️ Universal AI Hub")
view = st.sidebar.selectbox("Go to:", ["Control Center (Scorecard)", "Interactive Code Review", "Performance Analysis", "Predictive Failure"])

# Global Data Fetch
API_URL = "http://localhost:8000/api"
res = {}
try:
    response = requests.get(f"{API_URL}/security")
    res = response.json()
except:
    st.sidebar.error("⚠️ AI Backend Offline")

if view == "Control Center (Scorecard)":
    st.header("🏆 Executive Intelligence Summary")
    
    # --- UNIVERSAL HEALTH SCORE ---
    if "health_scores" in res:
        hs = res["health_scores"]
        col1, col2, col3 = st.columns(3)
        col1.metric("🛡️ Security Health", f"{hs['security']}/100")
        col2.metric("⚡ Performance Health", f"{hs['performance']}/100")
        col3.metric("🤝 AI Confidence", hs['confidence'])
        st.progress(hs['security']/100)
        
        # --- OWASP TOP 10 SCORECARD ---
        st.markdown("---")
        st.subheader("📋 OWASP Top 10 Compliance Scorecard")
        if "owasp_scorecard" in res:
            scorecard = res["owasp_scorecard"]
            # Convert to DataFrame for display
            df_scorecard = pd.DataFrame(list(scorecard.items()), columns=["Category", "Status"])
            
            # Color coding for Pass/Fail
            def color_status(val):
                color = 'green' if val == 'PASS' else 'red'
                return f'color: {color}; font-weight: bold'
            
            st.table(df_scorecard.style.map(color_status, subset=['Status']))
    else:
        st.warning("⚠️ No intelligence data available. Please run a security scan.")

elif view == "Interactive Code Review":
    st.header("🔍 Security & Performance Code Review")
    
    if "prioritized_alerts" in res:
        alerts = res["prioritized_alerts"]
        
        # Filters
        cat = st.radio("Silo:", ["All", "Security", "Performance"], horizontal=True)
        filtered = [a for a in alerts if cat == "All" or a.get("category").upper() == cat.upper()]
        
        for row in filtered:
            icon = "🔴" if row['priority'] == "CRITICAL" else "🟠" if row['priority'] == "HIGH" else "🔵"
            with st.expander(f"{icon} {row['priority']}: {row['alert']} ({row.get('owasp', 'N/A')})"):
                st.markdown(f"**Location:** `{row['file']}` | **CWE:** {row['cwe']}")
                st.info(f"**Recommendation:** {row['recommendation']}")
                
                c1, c2 = st.columns(2)
                with c1:
                    st.error("⚠️ Vulnerable Code")
                    st.code(row['vulnerable_code'], language='javascript')
                with c2:
                    st.success("✅ AI-Recommended Fix")
                    st.code(row['fixed_code'], language='javascript')
    else:
        st.info("No findings to review.")
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
        # Fetch data
        res = {}
        try:
            response = requests.get(f"{API_URL}/security")
            res = response.json()
        except Exception as e:
            st.error(f"❌ Could not connect to AI Backend: {e}")

        if "health_scores" in res:
            hs = res["health_scores"]
            st.markdown("### 🏆 Universal Health Score")
            col1, col2, col3 = st.columns(3)
            col1.metric("🛡️ Security Score", f"{hs['security']}/100")
            col2.metric("⚡ Performance Score", f"{hs['performance']}/100")
            col3.metric("🤝 Overall Confidence", hs['confidence'])
            st.progress(hs['security']/100)
        elif res:
            st.warning("⚠️ Health scores are missing from the AI results. Please ensure you have run a full pipeline scan recently.")
        
        st.markdown("---")
        st.subheader("⚡ AI Performance Code Review")
        try:
            res = requests.get(f"{API_URL}/security").json()
            perf_alerts = [a for a in res.get("prioritized_alerts", []) if a.get("category") == "PERFORMANCE"]
            
            if not perf_alerts:
                st.info("No performance bottlenecks detected. Optimization level: High.")
            else:
                for row in perf_alerts:
                    with st.expander(f"⚡ {row['priority']}: {row['alert']}"):
                        st.markdown(f"**File:** `{row['file']}`")
                        st.markdown(f"**Impact:** Performance Degradation (CWE: {row['cwe']})")
                        st.markdown(f"**Optimization:** {row.get('recommendation', 'N/A')}")
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.warning("⏱️ Bottleneck Code")
                            st.code(row.get('vulnerable_code', '// No code available'), language='javascript')
                            
                        with col2:
                            st.success("✅ Optimized Fix")
                            st.code(row.get('fixed_code', '// Suggested optimization'), language='javascript')
        except Exception as e:
            st.error(f"⚠️ Display Error (Perf): {e}")

elif view == "Security Analysis":
    st.header("🔐 AI SAST Intelligence (Static Analysis)")
    
    if not os.path.exists("reports/sast_report.json"):
        st.warning("No SAST report found! Run the GitHub Action pipeline to generate results.")
    else:
        try:
            res = requests.get(f"{API_URL}/security").json()
            if "prioritized_alerts" in res:
                # Filter for Security Only
                sec_alerts = [a for a in res["prioritized_alerts"] if a.get("category") == "SECURITY"]
                
                # Detailed Code Review Expanders
                st.subheader("🔍 AI Security Code Review")
                for row in sec_alerts:
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
                
                # Summary Table (Filtered)
                st.markdown("---")
                st.subheader("📁 Security Vulnerability Summary")
                if sec_alerts:
                    sec_df = pd.DataFrame(sec_alerts)
                    st.dataframe(sec_df[["alert", "priority", "file", "score"]])
            else:
                st.info("No prioritized alerts available yet.")
        except Exception as e:
            st.error(f"⚠️ Display Error: {e}")

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
