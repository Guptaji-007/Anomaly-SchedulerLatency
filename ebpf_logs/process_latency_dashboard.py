import os
import subprocess
import time

import numpy as np
import pandas as pd
import streamlit as st

try:
    import psutil
except ImportError:
    psutil = None


def list_running_processes() -> pd.DataFrame:
    rows = []

    if psutil is not None:
        for proc in psutil.process_iter(attrs=["pid", "name", "status"]):
            try:
                info = proc.info
                rows.append(
                    {
                        "pid": int(info.get("pid", -1)),
                        "name": str(info.get("name") or "unknown"),
                        "status": str(info.get("status") or "unknown"),
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    else:
        result = subprocess.run(
            ["ps", "-eo", "pid=,comm=,stat="],
            check=False,
            capture_output=True,
            text=True,
        )
        for line in result.stdout.splitlines():
            parts = line.strip().split(maxsplit=2)
            if len(parts) < 2:
                continue
            pid = int(parts[0])
            name = parts[1]
            status = parts[2] if len(parts) > 2 else "unknown"
            rows.append({"pid": pid, "name": name, "status": status})

    if not rows:
        return pd.DataFrame(columns=["pid", "name", "status"])

    df = pd.DataFrame(rows).drop_duplicates(subset=["pid"], keep="last")
    return df.sort_values(by=["name", "pid"]).reset_index(drop=True)


def load_ebpf_events(path: str) -> pd.DataFrame:
    required = ["timestamp_ns", "pid", "tgid", "comm", "cpu_id", "priority", "latency_us", "label"]

    try:
        df = pd.read_csv(path)
    except Exception:
        return pd.DataFrame(columns=required + ["timestamp_s"])

    missing = [c for c in required if c not in df.columns]
    if missing:
        return pd.DataFrame(columns=required + ["timestamp_s"])

    df = df.copy()
    for col in ["timestamp_ns", "pid", "tgid", "cpu_id", "priority", "latency_us", "label"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.dropna(subset=["timestamp_ns", "pid", "tgid", "latency_us"])
    if df.empty:
        return pd.DataFrame(columns=required + ["timestamp_s"])

    df["timestamp_ns"] = df["timestamp_ns"].astype("int64")
    df["pid"] = df["pid"].astype("int32")
    df["tgid"] = df["tgid"].astype("int32")
    df["cpu_id"] = df["cpu_id"].fillna(-1).astype("int32")
    df["priority"] = df["priority"].fillna(-1).astype("int32")
    df["label"] = df["label"].fillna(0).astype("int32")
    df["comm"] = df["comm"].astype(str)
    df["timestamp_s"] = df["timestamp_ns"] / 1e9
    return df.sort_values(by="timestamp_ns").reset_index(drop=True)


def summarize_latency(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    if df.empty:
        return pd.DataFrame(
            columns=["tgid", "comm", "events", "avg_us", "p50_us", "p95_us", "p99_us", "max_us"]
        )

    for (tgid, comm), grp in df.groupby(["tgid", "comm"], dropna=False):
        lat = grp["latency_us"].to_numpy(dtype=float)
        rows.append(
            {
                "tgid": int(tgid),
                "comm": str(comm),
                "events": int(len(lat)),
                "avg_us": float(np.mean(lat)),
                "p50_us": float(np.percentile(lat, 50)),
                "p95_us": float(np.percentile(lat, 95)),
                "p99_us": float(np.percentile(lat, 99)),
                "max_us": float(np.max(lat)),
            }
        )

    out = pd.DataFrame(rows)
    return out.sort_values(by=["p99_us", "events"], ascending=[False, False]).reset_index(drop=True)


def build_histogram(latencies_us: np.ndarray, bins: int = 20) -> pd.DataFrame:
    if latencies_us.size == 0:
        return pd.DataFrame(columns=["bucket_us", "count"])

    hist, edges = np.histogram(latencies_us, bins=bins)
    labels = [f"{edges[i]:.1f}-{edges[i + 1]:.1f}" for i in range(len(edges) - 1)]
    return pd.DataFrame({"bucket_us": labels, "count": hist})


st.set_page_config(page_title="Process Scheduling Latency Dashboard", layout="wide")
st.title("Process Scheduling Latency Dashboard")
st.caption("Select any running process and inspect scheduler runqueue latency from live eBPF events.")

with st.sidebar:
    st.header("Controls")
    events_path = st.text_input("eBPF events file", value="ebpf_logs/ebpf_events.csv")
    refresh_interval = st.slider("Auto-refresh interval (seconds)", min_value=2, max_value=20, value=5)
    auto_refresh = st.checkbox("Enable auto-refresh", value=True)
    manual_refresh = st.button("Refresh now")

if manual_refresh:
    st.rerun()

running_df = list_running_processes()

if running_df.empty:
    st.warning("No running processes could be listed. Check permissions or install psutil.")

if not os.path.exists(events_path):
    st.error(f"eBPF events file not found: {events_path}")
    st.info("Start collector first, for example: sudo ./ebpf_logs/collector 0")
    st.stop()

events_df = load_ebpf_events(events_path)
summary_df = summarize_latency(events_df)

running_pid_set = set(running_df["pid"].tolist()) if not running_df.empty else set()

if summary_df.empty:
    st.info("No eBPF latency events available yet in the current events file.")
else:
    combined_df = summary_df.copy()
    combined_df["is_running"] = combined_df["tgid"].isin(running_pid_set)
    combined_df = combined_df.merge(
        running_df[["pid", "status"]], left_on="tgid", right_on="pid", how="left"
    )

    col1, col2, col3 = st.columns(3)
    col1.metric("eBPF Events", int(len(events_df)))
    col2.metric("Processes in eBPF Stream", int(summary_df["tgid"].nunique()))
    col3.metric("Running Processes with eBPF Data", int(combined_df["is_running"].sum()))

    st.subheader("Top Processes by P99 Latency")
    st.dataframe(
        combined_df[["tgid", "comm", "events", "avg_us", "p95_us", "p99_us", "max_us", "is_running", "status"]].head(50),
        use_container_width=True,
    )

selection_df = running_df.copy()
if selection_df.empty:
    selection_df = pd.DataFrame(columns=["pid", "name", "status"])

selection_options = {f"{row.name} (PID {row.pid})": int(row.pid) for row in selection_df.itertuples()}

st.subheader("Process Selection")

selected_pid = None
if selection_options:
    chosen_label = st.selectbox("Choose a running process", options=list(selection_options.keys()))
    selected_pid = selection_options[chosen_label]

manual_pid = st.number_input("Or enter PID manually", min_value=0, step=1, value=0)
if manual_pid > 0:
    selected_pid = int(manual_pid)

if selected_pid is None:
    st.info("Select a process to view latency analytics.")
else:
    proc_df = events_df[events_df["tgid"] == selected_pid].copy()

    if proc_df.empty:
        st.warning(f"No eBPF latency samples found for PID {selected_pid} in the current events file.")
    else:
        proc_df = proc_df.sort_values(by="timestamp_s")
        lat = proc_df["latency_us"].to_numpy(dtype=float)

        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Samples", int(len(lat)))
        m2.metric("Average (us)", f"{np.mean(lat):.2f}")
        m3.metric("P95 (us)", f"{np.percentile(lat, 95):.2f}")
        m4.metric("P99 (us)", f"{np.percentile(lat, 99):.2f}")
        m5.metric("Max (us)", f"{np.max(lat):.2f}")

        st.subheader("Latency Timeline")
        timeline = proc_df[["timestamp_s", "latency_us"]].set_index("timestamp_s")
        st.line_chart(timeline)

        st.subheader("Latency Distribution")
        hist_df = build_histogram(lat, bins=24).set_index("bucket_us")
        st.bar_chart(hist_df)

        st.subheader("Per-CPU Event Contribution")
        cpu_counts = proc_df["cpu_id"].value_counts().sort_index().rename_axis("cpu").to_frame("count")
        st.bar_chart(cpu_counts)

        st.subheader("Priority Distribution")
        prio_counts = proc_df["priority"].value_counts().sort_index().rename_axis("priority").to_frame("count")
        st.bar_chart(prio_counts)

        st.subheader("Recent Events")
        st.dataframe(proc_df[["timestamp_ns", "timestamp_s", "tgid", "pid", "comm", "cpu_id", "priority", "latency_us", "label"]].tail(200), use_container_width=True)

if auto_refresh:
    time.sleep(refresh_interval)
    st.rerun()