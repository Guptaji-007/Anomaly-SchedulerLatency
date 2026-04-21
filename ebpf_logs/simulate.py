import streamlit as st
import pandas as pd
import time

st.set_page_config(page_title="eBPF Scheduler Anomaly Detector", layout="wide")
st.title("🚀 Scheduler Latency Analysis Dashboard")

# Placeholder for the live charts
chart_placeholder = st.empty()

def load_data():
    try:
        # Read the dataset created by your collector.c
        df = pd.read_csv("dataset.csv")
        return df
    except:
        return pd.DataFrame()

while True:
    df = load_data()
    
    if not df.empty:
        with chart_placeholder.container():
            col1, col2 = st.columns(2)
            
            with col1:
                st.subheader("Latency Distribution (us)")
                # Plotting Avg, P95, and P99
                st.line_chart(df[['avg_lat', 'p95_lat', 'p99_lat']].tail(60))
            
            with col2:
                st.subheader("Context Switches & Priority")
                st.bar_chart(df['switch_count'].tail(60))
                st.line_chart(df['avg_prio'].tail(60))

            # Highlight Anomalies
            st.subheader("Recent System State")
            st.table(df.tail(5))

    time.sleep(1) # Refresh every second to match your window