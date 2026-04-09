import os
import re
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


WAKEUP_RE = re.compile(
    r"\s+(\d+\.\d+):\s+sched:sched_wakeup(?:_new)?:\s+(.+):(\d+)\s+\["
)
SWITCH_RE = re.compile(
    r"\s+(\d+\.\d+):\s+sched:sched_switch:\s+(.+):(\d+)\s+\[.*?\]\s+([A-Z\+]+)\s+==>\s+(.+):(\d+)\s+\["
)


def parse_perf_trace(path: str) -> pd.DataFrame:
    wait_start_ns = {}
    wait_reason = {}
    comm_by_pid = {}
    records = []

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw_line in f:
            wake = WAKEUP_RE.search(raw_line)
            if wake:
                ts_s = float(wake.group(1))
                comm = wake.group(2).strip()
                pid = int(wake.group(3))
                ts_ns = ts_s * 1e9

                wait_start_ns[pid] = ts_ns
                wait_reason[pid] = "wakeup"
                comm_by_pid[pid] = comm
                continue

            sw = SWITCH_RE.search(raw_line)
            if not sw:
                continue

            ts_s = float(sw.group(1))
            prev_comm = sw.group(2).strip()
            prev_pid = int(sw.group(3))
            prev_state = sw.group(4)
            next_comm = sw.group(5).strip()
            next_pid = int(sw.group(6))
            ts_ns = ts_s * 1e9

            comm_by_pid[prev_pid] = prev_comm
            comm_by_pid[next_pid] = next_comm

            if "R" in prev_state:
                wait_start_ns[prev_pid] = ts_ns
                wait_reason[prev_pid] = "preempted"

            start_ns = wait_start_ns.pop(next_pid, None)
            if start_ns is None:
                continue

            reason = wait_reason.pop(next_pid, "unknown")
            latency_us = (ts_ns - start_ns) / 1000.0

            if latency_us < 0:
                continue

            records.append(
                {
                    "timestamp_s": ts_s,
                    "pid": next_pid,
                    "comm": comm_by_pid.get(next_pid, next_comm),
                    "latency_us": latency_us,
                    "reason": reason,
                }
            )

    if not records:
        return pd.DataFrame(columns=["timestamp_s", "pid", "comm", "latency_us", "reason"])

    df = pd.DataFrame(records)
    return df.sort_values(by="timestamp_s").reset_index(drop=True)


def summarize_latency(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    if df.empty:
        return pd.DataFrame(
            columns=["pid", "comm", "events", "avg_us", "p50_us", "p95_us", "p99_us", "max_us"]
        )

    for (pid, comm), grp in df.groupby(["pid", "comm"], dropna=False):
        lat = grp["latency_us"].to_numpy(dtype=float)
        rows.append(
            {
                "pid": int(pid),
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
st.caption("Select any running process and inspect its scheduler runqueue latency from perf trace events.")

with st.sidebar:
    st.header("Controls")
    trace_path = st.text_input("Perf trace file", value="perf_script.txt")
    refresh_interval = st.slider("Auto-refresh interval (seconds)", min_value=2, max_value=20, value=5)
    auto_refresh = st.checkbox("Enable auto-refresh", value=True)
    manual_refresh = st.button("Refresh now")

if manual_refresh:
    st.rerun()

running_df = list_running_processes()

if running_df.empty:
    st.warning("No running processes could be listed. Check permissions or install psutil.")

if not os.path.exists(trace_path):
    st.error(f"Trace file not found: {trace_path}")
    st.stop()

trace_df = parse_perf_trace(trace_path)
summary_df = summarize_latency(trace_df)

running_pid_set = set(running_df["pid"].tolist()) if not running_df.empty else set()

if summary_df.empty:
    st.info("No sched_wakeup/sched_switch latency pairs parsed from the current trace file.")
else:
    combined_df = summary_df.copy()
    combined_df["is_running"] = combined_df["pid"].isin(running_pid_set)
    combined_df = combined_df.merge(
        running_df[["pid", "status"]], on="pid", how="left"
    )

    col1, col2, col3 = st.columns(3)
    col1.metric("Trace Events", int(len(trace_df)))
    col2.metric("Unique PIDs in Trace", int(summary_df["pid"].nunique()))
    col3.metric("Running PIDs with Trace Data", int(combined_df["is_running"].sum()))

    st.subheader("Top Processes by P99 Latency")
    st.dataframe(
        combined_df[["pid", "comm", "events", "avg_us", "p95_us", "p99_us", "max_us", "is_running", "status"]].head(50),
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
    proc_df = trace_df[trace_df["pid"] == selected_pid].copy()

    if proc_df.empty:
        st.warning(f"No latency samples found for PID {selected_pid} in the current trace file.")
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

        st.subheader("Wakeup vs Preemption Contribution")
        reason_counts = proc_df["reason"].value_counts().rename_axis("reason").to_frame("count")
        st.bar_chart(reason_counts)

        st.subheader("Recent Events")
        st.dataframe(proc_df.tail(200), use_container_width=True)

if auto_refresh:
    time.sleep(refresh_interval)
    st.rerun()