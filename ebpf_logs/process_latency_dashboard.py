import os
import signal
import subprocess
import time
from collections import deque
from io import StringIO

import numpy as np
import pandas as pd
import streamlit as st

try:
    import psutil
except ImportError:
    psutil = None


BASE_DIR = os.path.dirname(__file__)
COLLECTOR_BIN = os.path.join(BASE_DIR, "collector")
EVENTS_DEFAULT = os.path.join("ebpf_logs", "ebpf_events.csv")
DATASET_DEFAULT = os.path.join("ebpf_logs", "dataset.csv")
COLLECTOR_LOG = os.path.join(BASE_DIR, "collector_streamlit.log")


def is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def read_log_tail(path: str, max_lines: int = 30) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return "".join(deque(f, maxlen=max_lines)).strip()
    except OSError:
        return ""


def start_targeted_collector(label: int, target_pid: int, min_latency_us: int, sample_rate: int) -> tuple[bool, str]:
    if not os.path.exists(COLLECTOR_BIN):
        return False, f"Collector binary not found at: {COLLECTOR_BIN}"

    cmd = [COLLECTOR_BIN, str(label), str(target_pid), str(min_latency_us), str(sample_rate)]
    with open(COLLECTOR_LOG, "a", encoding="utf-8") as log_fp:
        proc = subprocess.Popen(
            cmd,
            cwd=BASE_DIR,
            stdout=log_fp,
            stderr=log_fp,
            start_new_session=True,
        )

    time.sleep(0.4)
    ret = proc.poll()
    if ret is not None and ret != 0:
        tail = read_log_tail(COLLECTOR_LOG)
        msg = "Collector failed to start."
        if "Operation not permitted" in tail or "RLIMIT_MEMLOCK" in tail:
            msg += (
                "\n\nPermission issue while loading eBPF. "
                "Run Streamlit with sudo, or grant capabilities to collector:\n"
                "sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+ep ./ebpf_logs/collector"
            )
        if tail:
            msg += f"\n\nRecent log:\n{tail}"
        return False, msg

    st.session_state.collector_pid = proc.pid
    st.session_state.collector_cmd = " ".join(cmd)
    return True, f"Started collector with PID {proc.pid}"


def stop_collector(pid: int) -> tuple[bool, str]:
    if not is_pid_alive(pid):
        return False, "Tracked collector process is not running."
    try:
        os.kill(pid, signal.SIGINT)
        return True, f"Sent SIGINT to collector PID {pid}"
    except OSError as e:
        return False, f"Failed to stop collector PID {pid}: {e}"


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


def resolve_events_path(path: str) -> str:
    if os.path.exists(path):
        return path

    candidates = [
        "ebpf_events.csv",
        "ebpf_logs/ebpf_events.csv",
        os.path.join(os.path.dirname(__file__), "ebpf_events.csv"),
    ]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return path


def load_ebpf_events(path: str, max_rows: int = 30000) -> pd.DataFrame:
    required = ["timestamp_ns", "pid", "tgid", "comm", "cpu_id", "priority", "latency_us", "label"]

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            header = f.readline().strip()
            tail_lines = list(deque(f, maxlen=max_rows))
        if not header:
            return pd.DataFrame(columns=required + ["timestamp_s"])
        csv_blob = header + "\n" + "".join(tail_lines)
        df = pd.read_csv(StringIO(csv_blob))
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

if "collector_pid" not in st.session_state:
    st.session_state.collector_pid = 0
if "collector_cmd" not in st.session_state:
    st.session_state.collector_cmd = ""

if st.session_state.collector_pid and not is_pid_alive(int(st.session_state.collector_pid)):
    st.session_state.collector_pid = 0

with st.sidebar:
    st.header("Controls")
    events_path = st.text_input("eBPF events file", value=EVENTS_DEFAULT)
    max_rows = st.slider("Rows loaded per refresh", min_value=2000, max_value=100000, step=2000, value=30000)
    refresh_interval = st.slider("Auto-refresh interval (seconds)", min_value=2, max_value=20, value=5)
    auto_refresh = st.checkbox("Enable auto-refresh", value=True)
    manual_refresh = st.button("Refresh now")

if manual_refresh:
    st.rerun()

running_df = list_running_processes()

if running_df.empty:
    st.warning("No running processes could be listed. Check permissions or install psutil.")

events_path = resolve_events_path(events_path)
events_available = os.path.exists(events_path)
if not events_available:
    st.info(
        "No events file yet. Select a process below and start targeted collector. "
        "Analytics will appear as soon as events are written."
    )

if events_available:
    events_df = load_ebpf_events(events_path, max_rows=max_rows)
else:
    events_df = pd.DataFrame(
        columns=["timestamp_ns", "pid", "tgid", "comm", "cpu_id", "priority", "latency_us", "label", "timestamp_s"]
    )
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

event_proc_df = summary_df.copy()
event_proc_df["is_running"] = event_proc_df["tgid"].isin(running_pid_set)

event_options = {
    f"{row.comm} (PID {row.tgid}, events {row.events}, running={row.is_running})": int(row.tgid)
    for row in event_proc_df.itertuples()
}
running_options = {f"{row.name} (PID {row.pid})": int(row.pid) for row in selection_df.itertuples()}

st.subheader("Process Selection")

selected_pid = None
selection_mode = st.radio(
    "Select from",
    options=["All running processes", "Processes with eBPF data"],
    index=0,
    horizontal=True,
)

if selection_mode == "All running processes":
    if running_options:
        chosen_label = st.selectbox("Choose a running process", options=list(running_options.keys()))
        selected_pid = running_options[chosen_label]
    else:
        st.info("No running process list available. Enter PID manually.")
else:
    if event_options:
        chosen_label = st.selectbox("Choose a process with collected latency data", options=list(event_options.keys()))
        selected_pid = event_options[chosen_label]
    else:
        st.info("No process has eBPF data yet. Start targeted collector first.")

manual_pid = st.number_input("Or enter PID manually", min_value=0, step=1, value=0)
if manual_pid > 0:
    selected_pid = int(manual_pid)

st.subheader("Collector Control")

if selected_pid is not None:
    cc1, cc2, cc3 = st.columns(3)
    label = cc1.selectbox("Label", options=[0, 1], index=0)
    min_latency_us = int(cc2.number_input("Min latency (us)", min_value=0, value=0, step=1))
    sample_rate = int(cc3.number_input("Sample rate (1/N)", min_value=1, value=1, step=1))
    collector_cmd = f"sudo ./ebpf_logs/collector {label} {selected_pid} {min_latency_us} {sample_rate}"
    st.code(collector_cmd, language="bash")

    reset_csv = st.checkbox("Reset CSV files before starting collector", value=False)
    c1, c2 = st.columns(2)

    if c1.button("Start targeted collector", use_container_width=True):
        if st.session_state.collector_pid and is_pid_alive(int(st.session_state.collector_pid)):
            st.warning("A tracked collector is already running. Stop it first.")
        else:
            if reset_csv:
                for p in [os.path.join(BASE_DIR, "ebpf_events.csv"), os.path.join(BASE_DIR, "dataset.csv")]:
                    try:
                        os.remove(p)
                    except FileNotFoundError:
                        pass
            ok, msg = start_targeted_collector(label, selected_pid, min_latency_us, sample_rate)
            if ok:
                st.success(msg)
                st.rerun()
            else:
                st.error(msg)

    if c2.button("Stop tracked collector", use_container_width=True):
        tracked_pid = int(st.session_state.collector_pid or 0)
        ok, msg = stop_collector(tracked_pid)
        if ok:
            st.session_state.collector_pid = 0
            st.success(msg)
        else:
            st.warning(msg)

    tracked_pid = int(st.session_state.collector_pid or 0)
    if tracked_pid > 0 and is_pid_alive(tracked_pid):
        st.info(f"Tracked collector running (PID {tracked_pid})")
        if st.session_state.collector_cmd:
            st.caption(st.session_state.collector_cmd)
    else:
        st.caption("No tracked collector process is currently running.")
else:
    st.info("Select a process above to build and run a targeted collector command.")

if selected_pid is None:
    st.info("Select a process to view latency analytics.")
else:
    proc_df = events_df[events_df["tgid"] == selected_pid].copy()

    if proc_df.empty:
        if events_available:
            st.warning(f"No eBPF latency samples found for PID {selected_pid} in the current events file.")
        st.info(f"Tip: run targeted collection for this process, e.g. sudo ./ebpf_logs/collector 0 {selected_pid}")
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