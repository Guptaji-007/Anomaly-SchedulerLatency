import streamlit as st
import pandas as pd
import time

st.set_page_config(page_title="eBPF Scheduler Anomaly Detector", layout="wide")
st.title("🚀 Scheduler Latency Analysis Dashboard")

# ==============================
# 📌 LOAD DATA
# ==============================
def load_data():
    try:
        df = pd.read_csv("dataset.csv")
        # Fallback in case older data without labels is loaded
        if 'label' not in df.columns:
            df['label'] = 0 
        return df
    except Exception as e:
        return pd.DataFrame()

# ==============================
# 📌 ROOT CAUSE DETECTION (System View)
# ==============================
def detect_cause(row):
    if row['p99_lat'] > 100 and row['switch_count'] > 500:
        return "CPU Contention"
    elif row['p99_lat'] > 100 and row['avg_prio'] < 100:
        return "Priority Interference"
    elif row['stddev_lat'] > 50:
        return "Burst Workload"
    elif row['over100'] > 0:
        return "Severe Delay"
    elif row['p99_lat'] > 50:
        return "Moderate Spike"
    else:
        return "Normal"

# ==============================
# 📌 GROUND TRUTH MAPPER (Label View)
# ==============================
def map_label(row):
    return "🔴 Stressor Active" if row['label'] == 1 else "🟢 Baseline"

# ==============================
# 📌 STORE HISTORY
# ==============================
if "history" not in st.session_state:
    st.session_state.history = pd.DataFrame()

# ==============================
# 📌 UI PLACEHOLDER
# ==============================
chart_placeholder = st.empty()

# ==============================
# 📌 LIVE LOOP
# ==============================
while True:
    df = load_data()

    if not df.empty:
        # Apply logic
        df['cause'] = df.apply(detect_cause, axis=1)
        df['workload_state'] = df.apply(map_label, axis=1)

        latest = df.iloc[-1]

        # Update History
        st.session_state.history = pd.concat(
            [st.session_state.history, df.tail(1)],
            ignore_index=True
        )
        st.session_state.history = st.session_state.history.drop_duplicates(
            subset=["timestamp"], keep="last"
        )
        
        history = st.session_state.history

        with chart_placeholder.container():

            # ==============================
            # 🔥 TOP METRICS
            # ==============================
            col1, col2, col3, col4 = st.columns(4)

            col1.metric("P99 Latency (us)", f"{latest['p99_lat']:.2f}")
            col2.metric("Context Switches", int(latest['switch_count']))
            col3.metric("Detected Symptom", latest['cause'])
            col4.metric("Ground Truth (Label)", latest['workload_state'])

            # ==============================
            # 🚨 ALERT SYSTEM (Correlating Label & Metrics)
            # ==============================
            if latest['label'] == 1:
                st.error(f"🚨 INJECTED ANOMALY (Label 1) | Scheduler is under stress. Symptom: {latest['cause']}")
            elif latest['label'] == 0 and latest['p99_lat'] > 100:
                st.warning(f"⚠️ UNEXPECTED SPIKE (Label 0) | Baseline is running, but system detected: {latest['cause']}")
            else:
                st.success("✅ NORMAL (Label 0) | System operating within expected baseline.")

            # ==============================
            # 📊 LATENCY GRAPH
            # ==============================
            st.subheader("Latency Trends (us)")
            st.line_chart(df[['avg_lat', 'p95_lat', 'p99_lat']].tail(60))

            # ==============================
            # 📊 SWITCH GRAPH
            # ==============================
            st.subheader("Context Switch Activity")
            st.bar_chart(df['switch_count'].tail(60))

            # ==============================
            # 📋 SPIKE TABLE
            # ==============================
            st.subheader("⚠️ Detected Spikes (P99 > 50us)")
            spikes = history[history['p99_lat'] > 50]

            if not spikes.empty:
                st.dataframe(
                    spikes[['timestamp', 'p99_lat', 'switch_count', 'stddev_lat', 'cause', 'label', 'workload_state']].tail(20)
                )
            else:
                st.write("No spikes detected yet")

            # ==============================
            # 📋 FULL HISTORY TABLE
            # ==============================
            st.subheader("📜 Full History")
            st.dataframe(
                history[['timestamp', 'avg_lat', 'p99_lat', 'switch_count', 'avg_prio', 'cause', 'label']].tail(50)
            )

    time.sleep(1)