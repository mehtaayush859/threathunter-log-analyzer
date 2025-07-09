# streamlit_app.py
# Streamlit dashboard for ThreatHunter

import sys
import os
import tempfile
import streamlit as st
import yaml
import json
import pandas as pd

# Ensure the project root is in sys.path for absolute imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from threathunter.core.log_parser import LogParser
from threathunter.core.rule_engine import RuleEngine

st.set_page_config(page_title="ThreatHunter Dashboard", layout="wide")

# Sidebar: Settings and Info
with st.sidebar:
    st.header("Settings & Info")
    st.markdown("""
    **ThreatHunter** is a lightweight SIEM-like log analyzer for security teams, students, and professionals.
    
    - Upload Linux auth logs for analysis
    - Rule-based alerting
    - Visualize suspicious activity
    """)
    log_type = st.selectbox("Log Type", ["auth"])  # Extend for syslog/access
    rules_path = st.text_input("Alert Rules YAML", "threathunter/alerts/alert_rules.yaml")

# Main content: Centered upload and results
st.markdown("""
    <div style='display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 30vh;'>
        <h1 style='color: #2c3e50;'>ThreatHunter Log Analyzer</h1>
        <h4 style='color: #555;'>Upload your log file below to begin analysis</h4>
    </div>
    """, unsafe_allow_html=True)

uploaded_file = st.file_uploader("Upload Log File (e.g., auth.log)", type=["log", "txt"], label_visibility="visible")

if uploaded_file is not None:
    # Save uploaded file to a cross-platform temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.log', mode='w', encoding='utf-8') as tmp:
        log_text = uploaded_file.read().decode("utf-8")
        tmp.write(log_text)
        tmp_path = tmp.name
    st.success("Log file uploaded and saved!")

    # Parse log
    parser = LogParser(log_type)
    events = parser.parse(tmp_path)
    st.markdown(f"<b>Parsed {len(events)} log events.</b>", unsafe_allow_html=True)
    df = pd.DataFrame(events)
    if not df.empty:
        st.dataframe(df, use_container_width=True, hide_index=True)

    # Load rules
    with open(rules_path, "r", encoding="utf-8") as f:
        rules = yaml.safe_load(f)
    st.markdown(f"<b>Loaded {len(rules)} alert rules.</b>", unsafe_allow_html=True)

    # Run rule engine
    engine = RuleEngine(rules)
    alerts = engine.evaluate(events)
    st.markdown(f"<b>Detected {len(alerts)} alerts.</b>", unsafe_allow_html=True)
    if alerts:
        alerts_df = pd.DataFrame(alerts)
        # Filter by severity
        severities = alerts_df["severity"].unique().tolist()
        selected_sev = st.multiselect("Filter by Severity", severities, default=severities)
        filtered_alerts = alerts_df[alerts_df["severity"].isin(selected_sev)]
        st.subheader("Alert Results")
        st.dataframe(filtered_alerts, use_container_width=True, hide_index=True)

        # Top IPs
        if "src_ip" in alerts_df:
            st.subheader("Top Source IPs")
            st.bar_chart(alerts_df["src_ip"].value_counts())
        # Top Users
        if "user" in alerts_df:
            st.subheader("Top Users")
            st.bar_chart(alerts_df["user"].value_counts())
    else:
        st.info("No alerts detected.")
else:
    st.info("Please upload a log file to begin analysis.") 