# streamlit_app.py
# Streamlit dashboard for ThreatHunter

import sys
import os
import tempfile
import logging
import streamlit as st
import yaml
import json
import pandas as pd
from typing import Optional
from PIL import Image
import time

# Ensure the project root is in sys.path for absolute imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from threathunter.core.log_parser import LogParser
from threathunter.core.rule_engine import RuleEngine

logger = logging.getLogger(__name__)

# Set favicon and logo
st.set_page_config(
    page_title="ThreatHunter Dashboard",
    layout="wide",
    page_icon="🛡️"
)

# Main content: Centered upload and results
st.markdown("""
    <div style='display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 30vh;'>
""", unsafe_allow_html=True)

st.markdown("""
        <h1 style='color: #2c3e50;'>ThreatHunter Log Analyzer</h1>
        <h4 style='color: #555;'>Upload your log file and click 'Start Scan' to begin analysis</h4>
    </div>
    """, unsafe_allow_html=True)

# Sidebar: Settings and Info
with st.sidebar:
    st.header("Settings & Info")
    st.markdown("""
    <span style='color:#1abc9c; font-weight:bold;'>ThreatHunter</span> is a lightweight SIEM-like log analyzer for security teams, students, and professionals.
    
    - Upload Linux auth logs for analysis
    - Rule-based alerting
    - Visualize suspicious activity
    """, unsafe_allow_html=True)
    log_type = st.selectbox("Log Type", ["auth"], help="Currently only 'auth' logs supported.")  # Extend for syslog/access
    rules_path = st.text_input("Alert Rules YAML", "threathunter/alerts/alert_rules.yaml", help="Path to your alert rules YAML file.")


def run_dashboard() -> None:
    """
    Main function to run the Streamlit dashboard for ThreatHunter.
    Handles log upload, parsing, alerting, and visualization.
    """
    uploaded_file: Optional[st.runtime.uploaded_file_manager.UploadedFile] = st.file_uploader(
        "Upload Log File (e.g., auth.log)", type=["log", "txt"], label_visibility="visible",
        help="Upload a Linux authentication log file for analysis."
    )

    if uploaded_file is not None:
        if 'file_uploaded' not in st.session_state or st.session_state['file_uploaded'] is False:
            st.session_state['file_uploaded'] = True
        if st.session_state['file_uploaded']:
            st.success("Log file uploaded! Click 'Start Scan' to analyze.")

        scan_clicked = st.button("Start Scan", key="scan_button", help="Click to start scanning the uploaded log file.")
        if scan_clicked:
            st.session_state['file_uploaded'] = False
            with st.spinner("Scanning logs and applying detection rules..."):
                try:
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.log', mode='w', encoding='utf-8') as tmp:
                        log_text = uploaded_file.read().decode("utf-8")
                        tmp.write(log_text)
                        tmp_path = tmp.name
                    logger.info(f"Log file uploaded and saved to {tmp_path}")
                except Exception as e:
                    st.error(f"Failed to save uploaded file: {e}")
                    logger.error(f"Failed to save uploaded file: {e}")
                    return

                # Parse log
                try:
                    parser = LogParser(log_type)
                    events = parser.parse(tmp_path)
                    st.markdown(f"<b>Parsed {len(events)} log events.</b>", unsafe_allow_html=True)
                    logger.info(f"Parsed {len(events)} log events from {tmp_path}")
                except Exception as e:
                    st.error(f"Failed to parse log file: {e}")
                    logger.error(f"Failed to parse log file: {e}")
                    return
                df = pd.DataFrame(events)
                if not df.empty:
                    st.dataframe(df, use_container_width=True, hide_index=True)

                # Load rules
                try:
                    with open(rules_path, "r", encoding="utf-8") as f:
                        rules = yaml.safe_load(f)
                    st.markdown(f"<b>Loaded {len(rules)} alert rules.</b>", unsafe_allow_html=True)
                    logger.info(f"Loaded {len(rules)} alert rules from {rules_path}")
                except Exception as e:
                    st.error(f"Failed to load alert rules: {e}")
                    logger.error(f"Failed to load alert rules: {e}")
                    return

                # Run rule engine
                try:
                    engine = RuleEngine(rules)
                    alerts = engine.evaluate(events)
                    st.markdown(f"<b>Detected {len(alerts)} alerts.</b>", unsafe_allow_html=True)
                    logger.info(f"Detected {len(alerts)} alerts.")
                except Exception as e:
                    st.error(f"Failed to evaluate rules: {e}")
                    logger.error(f"Failed to evaluate rules: {e}")
                    return
                if alerts:
                    alerts_df = pd.DataFrame(alerts)
                    # Filter by severity
                    severities = alerts_df["severity"].unique().tolist()
                    selected_sev = st.multiselect("Filter by Severity", severities, default=severities, help="Filter alerts by severity level.")
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
        st.session_state['file_uploaded'] = False

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_dashboard() 