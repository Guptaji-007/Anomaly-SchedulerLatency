"""
Process Scheduling Latency Dashboard — Textual TUI
Install: pip install textual psutil numpy pandas
Run:     python tui_dashboard.py
         sudo python tui_dashboard.py   (needed for eBPF collector)
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import time
from collections import deque
from io import StringIO
from typing import Optional

import numpy as np
import pandas as pd
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.css.query import NoMatches
from textual.screen import ModalScreen
from textual.timer import Timer
from textual.widget import Widget
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Log,
    OptionList,
    Select,
    Static,
    TabbedContent,
    TabPane,
)
from textual.widgets.option_list import Option

try:
    import psutil
except ImportError:
    psutil = None

# ──────────────────────────────────────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
COLLECTOR_BIN   = os.path.join(BASE_DIR, "collector")
EVENTS_DEFAULT  = os.path.join("ebpf_logs", "ebpf_events.csv")
COLLECTOR_LOG   = os.path.join(BASE_DIR, "collector_tui.log")

# ──────────────────────────────────────────────────────────────────────────────
# CSS
# ──────────────────────────────────────────────────────────────────────────────
APP_CSS = """
Screen {
    background: #0d1117;
}
Header {
    background: #161b22;
    color: #58a6ff;
    text-style: bold;
    height: 3;
}
Footer {
    background: #161b22;
    color: #8b949e;
    height: 2;
}

/* ── Sidebar ── */
#sidebar {
    width: 34;
    background: #161b22;
    border-right: solid #21262d;
    padding: 1 1;
}
#sidebar-title {
    color: #58a6ff;
    text-style: bold;
    text-align: center;
    padding: 0 0 1 0;
    border-bottom: solid #21262d;
    margin-bottom: 1;
}
.sb-label {
    color: #8b949e;
    margin-top: 1;
}
.sb-input {
    width: 100%;
    background: #0d1117;
    border: solid #30363d;
    color: #c9d1d9;
}
.sb-input:focus { border: solid #58a6ff; }
.sb-btn {
    width: 100%;
    margin-top: 1;
    background: #21262d;
    color: #c9d1d9;
    border: solid #30363d;
}
.sb-btn:hover { background: #30363d; color: #58a6ff; }
.status-running { color: #3fb950; text-style: bold; }
.status-stopped { color: #8b949e; }

/* ── Main ── */
#main {
    background: #0d1117;
    padding: 1 2;
}

/* ── Metric cards ── */
#metric-bar { height: 5; margin-bottom: 1; }
.metric-card {
    background: #161b22;
    border: solid #21262d;
    padding: 0 1;
    width: 1fr;
    margin-right: 1;
    height: 5;
    content-align: center middle;
}
.metric-card:last-child { margin-right: 0; }
.metric-value { color: #58a6ff; text-style: bold; text-align: center; }
.metric-label { color: #8b949e; text-align: center; }

/* ── Section titles ── */
.section-title {
    color: #3fb950;
    text-style: bold;
    margin: 1 0 0 0;
}

/* ── Process picker panel ── */
#proc-picker {
    background: #161b22;
    border: solid #21262d;
    padding: 1;
    margin-top: 1;
    height: auto;
    max-height: 22;
}
.picker-title { color: #a5d6ff; text-style: bold; margin-bottom: 1; }

/* ── Process option list ── */
#proc-option-list {
    background: #0d1117;
    border: solid #30363d;
    height: 10;
    color: #c9d1d9;
}
OptionList > .option-list--option { padding: 0 1; }
OptionList > .option-list--option-highlighted {
    background: #1f6feb;
    color: #ffffff;
}

/* ── Selected PID display ── */
#selected-pid-display {
    background: #0d1117;
    border: solid #30363d;
    padding: 0 1;
    color: #e3b341;
    margin: 1 0;
    height: 3;
}

/* ── Collector panel ── */
#collector-panel {
    background: #161b22;
    border: solid #21262d;
    padding: 1;
    margin-top: 1;
}
.collector-title { color: #f78166; text-style: bold; margin-bottom: 1; }
.cmd-display {
    background: #0d1117;
    border: solid #30363d;
    padding: 0 1;
    color: #e3b341;
    margin: 1 0;
    height: 3;
}
#btn-start {
    background: #1a7f37;
    color: #ffffff;
    border: solid #2ea043;
    margin-right: 1;
    width: 1fr;
}
#btn-start:hover { background: #2ea043; }
#btn-stop {
    background: #6e1c1c;
    color: #ffffff;
    border: solid #f85149;
    width: 1fr;
}
#btn-stop:hover { background: #f85149; }
#lbl-collector-status { margin-top: 1; }

/* ── Tables ── */
DataTable {
    background: #0d1117;
    border: solid #21262d;
    height: auto;
    max-height: 18;
}
DataTable > .datatable--header {
    background: #161b22;
    color: #58a6ff;
    text-style: bold;
}
DataTable > .datatable--cursor { background: #1f6feb; color: #ffffff; }
DataTable > .datatable--even-row { background: #0d1117; color: #c9d1d9; }
DataTable > .datatable--odd-row  { background: #111820; color: #c9d1d9; }

/* ── ASCII chart boxes ── */
.chart-box {
    background: #161b22;
    border: solid #21262d;
    padding: 1;
    height: 16;
    margin-top: 1;
}
#chart-box-timeline {
    height: 34;
}
#chart-box-histogram {
    height: 50;
}
.chart-box Static { color: #3fb950; }

/* ── Tabs ── */
TabbedContent { margin-top: 1; }
TabPane { background: #0d1117; padding: 1; }

/* ── Log ── */
Log {
    background: #0d1117;
    border: solid #21262d;
    color: #8b949e;
    height: 14;
    margin-top: 1;
}

/* ── Modal ── */
ModalScreen { align: center middle; }
#modal-dialog {
    width: 70;
    background: #161b22;
    border: solid #58a6ff;
    padding: 2 3;
    height: auto;
    max-height: 40;
}
#modal-title { color: #58a6ff; text-style: bold; margin-bottom: 1; }
#modal-body  { color: #c9d1d9; margin-bottom: 2; }
#modal-close {
    background: #21262d;
    color: #c9d1d9;
    border: solid #30363d;
    width: 100%;
}
"""

# ──────────────────────────────────────────────────────────────────────────────
# Data helpers
# ──────────────────────────────────────────────────────────────────────────────

def is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def read_log_tail(path: str, max_lines: int = 50) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return "".join(deque(f, maxlen=max_lines)).strip()
    except OSError:
        return ""


def list_running_processes() -> pd.DataFrame:
    rows: list[dict] = []
    if psutil is not None:
        for proc in psutil.process_iter(attrs=["pid", "name", "status"]):
            try:
                info = proc.info
                rows.append({
                    "pid":    int(info.get("pid", -1)),
                    "name":   str(info.get("name") or "unknown"),
                    "status": str(info.get("status") or "unknown"),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    else:
        result = subprocess.run(
            ["ps", "-eo", "pid=,comm=,stat="],
            check=False, capture_output=True, text=True,
        )
        for line in result.stdout.splitlines():
            parts = line.strip().split(maxsplit=2)
            if len(parts) < 2:
                continue
            try:
                rows.append({
                    "pid":    int(parts[0]),
                    "name":   parts[1],
                    "status": parts[2] if len(parts) > 2 else "unknown",
                })
            except ValueError:
                continue

    if not rows:
        return pd.DataFrame(columns=["pid", "name", "status"])
    df = pd.DataFrame(rows).drop_duplicates(subset=["pid"], keep="last")
    return df.sort_values(by=["name", "pid"]).reset_index(drop=True)


def resolve_events_path(path: str) -> str:
    if os.path.exists(path):
        return path
    for candidate in [
        "ebpf_events.csv",
        "ebpf_logs/ebpf_events.csv",
        os.path.join(BASE_DIR, "ebpf_events.csv"),
    ]:
        if os.path.exists(candidate):
            return candidate
    return path


def load_ebpf_events(path: str, max_rows: int = 30000) -> pd.DataFrame:
    required = ["timestamp_ns", "pid", "tgid", "comm", "cpu_id",
                "priority", "latency_us", "label"]
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            header = f.readline().strip()
            tail_lines = list(deque(f, maxlen=max_rows))
        if not header:
            return pd.DataFrame(columns=required + ["timestamp_s"])
        df = pd.read_csv(StringIO(header + "\n" + "".join(tail_lines)))
    except Exception:
        return pd.DataFrame(columns=required + ["timestamp_s"])

    if any(c not in df.columns for c in required):
        return pd.DataFrame(columns=required + ["timestamp_s"])

    df = df.copy()
    for col in ["timestamp_ns", "pid", "tgid", "cpu_id", "priority", "latency_us", "label"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df.dropna(subset=["timestamp_ns", "pid", "tgid", "latency_us"])
    if df.empty:
        return pd.DataFrame(columns=required + ["timestamp_s"])

    df["timestamp_ns"] = df["timestamp_ns"].astype("int64")
    df["pid"]          = df["pid"].astype("int32")
    df["tgid"]         = df["tgid"].astype("int32")
    df["cpu_id"]       = df["cpu_id"].fillna(-1).astype("int32")
    df["priority"]     = df["priority"].fillna(-1).astype("int32")
    df["label"]        = df["label"].fillna(0).astype("int32")
    df["comm"]         = df["comm"].astype(str)
    df["timestamp_s"]  = df["timestamp_ns"] / 1e9
    return df.sort_values(by="timestamp_ns").reset_index(drop=True)


def summarize_latency(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame(columns=["tgid", "comm", "events", "avg_us",
                                     "p50_us", "p95_us", "p99_us", "max_us"])
    rows = []
    for (tgid, comm), grp in df.groupby(["tgid", "comm"], dropna=False):
        lat = grp["latency_us"].to_numpy(dtype=float)
        rows.append({
            "tgid":   int(tgid),
            "comm":   str(comm),
            "events": len(lat),
            "avg_us": float(np.mean(lat)),
            "p50_us": float(np.percentile(lat, 50)),
            "p95_us": float(np.percentile(lat, 95)),
            "p99_us": float(np.percentile(lat, 99)),
            "max_us": float(np.max(lat)),
        })
    out = pd.DataFrame(rows)
    return out.sort_values(["p99_us", "events"], ascending=[False, False]).reset_index(drop=True)


# ──────────────────────────────────────────────────────────────────────────────
# ASCII visualisation helpers
# ──────────────────────────────────────────────────────────────────────────────
_BLOCKS = "▁▂▃▄▅▆▇█"

def _bucket_reduce(values: np.ndarray, width: int, reducer: str = "max") -> np.ndarray:
    if values.size == 0:
        return np.array([], dtype=float)
    if values.size <= width:
        return values.astype(float)

    step = values.size / width
    reduced: list[float] = []
    for i in range(width):
        start = int(i * step)
        end = int((i + 1) * step)
        if end <= start:
            end = min(start + 1, values.size)
        bucket = values[start:end]
        if bucket.size == 0:
            continue
        if reducer == "mean":
            reduced.append(float(bucket.mean()))
        else:
            # Using max preserves short latency spikes that would otherwise disappear.
            reduced.append(float(bucket.max()))
    return np.array(reduced, dtype=float)


def sparkline(values: list[float], width: int = 60) -> str:
    if not values:
        return "─" * width

    arr = np.asarray(values, dtype=float)
    sampled = _bucket_reduce(arr, width=width, reducer="max")
    if sampled.size == 0:
        return "─" * width

    # Robust scaling keeps baseline variation visible while preserving spike peaks.
    lo = float(np.percentile(sampled, 5))
    hi = float(np.percentile(sampled, 95))
    if hi <= lo:
        lo, hi = float(sampled.min()), float(sampled.max())
    span = (hi - lo) or 1.0

    out = []
    for v in sampled:
        clipped = min(max(v, lo), hi)
        idx = int(((clipped - lo) / span) * (len(_BLOCKS) - 1))
        out.append(_BLOCKS[max(0, min(idx, len(_BLOCKS) - 1))])
    return "".join(out)


def sparkline_panel(values: list[float], width: int = 60, height: int = 6) -> str:
    if not values:
        return "\n".join([" " * width for _ in range(height)])

    arr = np.asarray(values, dtype=float)
    sampled = _bucket_reduce(arr, width=width, reducer="max")
    if sampled.size == 0:
        return "\n".join([" " * width for _ in range(height)])

    lo = float(np.percentile(sampled, 5))
    hi = float(np.percentile(sampled, 95))
    if hi <= lo:
        lo, hi = float(sampled.min()), float(sampled.max())
    span = (hi - lo) or 1.0

    norm = np.clip((sampled - lo) / span, 0.0, 1.0)
    rows: list[str] = []
    for row_idx in range(height, 0, -1):
        threshold = row_idx / height
        rows.append("".join("█" if v >= threshold else " " for v in norm))
    return "\n".join(rows)


def sparkline_panel_with_axes(values: list[float], width: int = 60, height: int = 10) -> str:
    if not values:
        return "(no data)"

    arr = np.asarray(values, dtype=float)
    sampled = _bucket_reduce(arr, width=width, reducer="max")
    if sampled.size == 0:
        return "(no data)"

    lo = float(np.percentile(sampled, 5))
    hi = float(np.percentile(sampled, 95))
    if hi <= lo:
        lo, hi = float(sampled.min()), float(sampled.max())
    span = (hi - lo) or 1.0
    norm = np.clip((sampled - lo) / span, 0.0, 1.0)

    top_row = 0
    mid_row = height // 2
    bottom_row = height - 1

    rows: list[str] = []
    for row_idx in range(height):
        threshold = 1.0 - (row_idx / max(height - 1, 1))
        bars = "".join("█" if v >= threshold else " " for v in norm)
        if row_idx == top_row:
            y_label = f"{hi:7.1f}"
        elif row_idx == mid_row:
            y_label = f"{(lo + hi) / 2:7.1f}"
        elif row_idx == bottom_row:
            y_label = f"{lo:7.1f}"
        else:
            y_label = " " * 7
        rows.append(f"{y_label} |{bars}")

    axis_len = len(sampled)
    rows.append(" " * 8 + "+" + "-" * axis_len)

    # X-axis labels show oldest, midpoint, and newest sample indices.
    start_idx = 1
    mid_idx = max(1, arr.size // 2)
    end_idx = arr.size
    label_line = [" "] * axis_len
    left = str(start_idx)
    mid = str(mid_idx)
    right = str(end_idx)

    for i, ch in enumerate(left):
        if i < axis_len:
            label_line[i] = ch
    mid_pos = max(0, min(axis_len - len(mid), (axis_len // 2) - (len(mid) // 2)))
    for i, ch in enumerate(mid):
        pos = mid_pos + i
        if 0 <= pos < axis_len:
            label_line[pos] = ch
    right_pos = max(0, axis_len - len(right))
    for i, ch in enumerate(right):
        pos = right_pos + i
        if 0 <= pos < axis_len:
            label_line[pos] = ch

    rows.append(" " * 8 + " " + "".join(label_line))
    rows.append(" " * 8 + " " + "samples (oldest -> newest)")
    rows.append(" " * 8 + " " + "y-axis unit: latency us")
    return "\n".join(rows)


def spark_spike_markers(values: list[float], width: int = 60) -> str:
    if not values:
        return ""

    arr = np.asarray(values, dtype=float)
    sampled = _bucket_reduce(arr, width=width, reducer="max")
    if sampled.size == 0:
        return ""

    p95 = float(np.percentile(arr, 95))
    p99 = float(np.percentile(arr, 99))

    markers: list[str] = []
    for v in sampled:
        if v >= p99:
            markers.append("^")
        elif v >= p95:
            markers.append("!")
        else:
            markers.append(" ")
    return "".join(markers)


def ascii_timeline(lat: np.ndarray, height: int = 8, width: int = 60) -> str:
    if lat.size == 0:
        return "(no data)"
    mn, mx = lat.min(), lat.max()
    span = (mx - mn) or 1
    step = max(1, len(lat) // width)
    sampled = lat[::step][-width:]
    rows = []
    for row_idx in range(height - 1, -1, -1):
        threshold = mn + (row_idx / max(height - 1, 1)) * span
        line = "".join("·" if v >= threshold else " " for v in sampled)
        rows.append(f"{threshold:>10.1f} |{line}")
    rows.append(" " * 11 + "+" + "-" * len(sampled))
    return "\n".join(rows)


def ascii_histogram(lat: np.ndarray, bins: int = 20, bar_width: int = 44) -> str:
    if lat.size == 0:
        return "(no data)"
    hist, edges = np.histogram(lat, bins=bins)
    max_count = hist.max() or 1
    lines = [f"{'bucket (us)':<22}  count"]
    lines.append("-" * (bar_width + 30))
    for i in range(len(hist)):
        label = f"{edges[i]:>9.1f}-{edges[i+1]:<9.1f}"
        bar = "#" * int(hist[i] / max_count * bar_width)
        lines.append(f"{label}  |{bar:<{bar_width}}  {hist[i]}")
    return "\n".join(lines)


def ascii_bar_chart(keys: list, values: list, bar_width: int = 44, title: str = "") -> str:
    if not keys:
        return "(no data)"
    max_val = max(values) or 1
    lines = [title, "-" * (bar_width + 16)] if title else ["-" * (bar_width + 16)]
    for k, v in zip(keys, values):
        bar = "#" * int(v / max_val * bar_width)
        lines.append(f"{str(k):>8}  |{bar:<{bar_width}}  {v}")
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# Widgets
# ──────────────────────────────────────────────────────────────────────────────

def _safe_id(label: str) -> str:
    """Turn an arbitrary label into a valid Textual CSS id."""
    return "mc-" + re.sub(r"[^a-zA-Z0-9_-]", "_", label)


class MetricCard(Widget):
    def __init__(self, label: str, value: str = "-"):
        super().__init__(classes="metric-card")
        self._label   = label
        self._value   = value
        self._safe_id = _safe_id(label)

    def compose(self) -> ComposeResult:
        yield Label(self._value, classes="metric-value", id=self._safe_id)
        yield Label(self._label, classes="metric-label")

    def update_value(self, value: str) -> None:
        try:
            self.query_one(f"#{self._safe_id}", Label).update(value)
        except NoMatches:
            pass


# ──────────────────────────────────────────────────────────────────────────────
# Modal
# ──────────────────────────────────────────────────────────────────────────────
class InfoModal(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Close")]

    def __init__(self, title: str, body: str):
        super().__init__()
        self._title = title
        self._body  = body

    def compose(self) -> ComposeResult:
        with Container(id="modal-dialog"):
            yield Label(self._title, id="modal-title")
            yield Label(self._body,  id="modal-body")
            yield Button("Close  [Esc]", id="modal-close")

    @on(Button.Pressed, "#modal-close")
    def _close(self) -> None:
        self.dismiss()


# ──────────────────────────────────────────────────────────────────────────────
# Main App
# ──────────────────────────────────────────────────────────────────────────────
class LatencyDashboard(App):
    TITLE     = "Process Scheduling Latency Dashboard"
    SUB_TITLE = "eBPF Runqueue Latency  -  TUI"
    CSS       = APP_CSS

    BINDINGS = [
        Binding("r",       "refresh",               "Refresh"),
        Binding("ctrl+s",  "start_collector",       "Start Collector"),
        Binding("ctrl+x",  "stop_collector_action", "Stop Collector"),
        Binding("f1",      "show_help",             "Help"),
        Binding("q",       "quit",                  "Quit"),
    ]

    # ── state ──────────────────────────────────────────────────────────────────
    _collector_pid: int                  = 0
    _collector_cmd: str                  = ""
    _selected_pid:  Optional[int]        = None
    _events_df:     pd.DataFrame         = pd.DataFrame()
    _summary_df:    pd.DataFrame         = pd.DataFrame()
    _running_df:    pd.DataFrame         = pd.DataFrame()
    _proc_options:  list[tuple[str,int]] = []
    _auto_refresh:  bool                 = True
    _refresh_secs:  int                  = 5
    _timer:         Optional[Timer]      = None

    # ── compose ────────────────────────────────────────────────────────────────
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Horizontal():
            # ── Sidebar ─────────────────────────────────────────────────────
            with ScrollableContainer(id="sidebar"):
                yield Label("  Controls", id="sidebar-title")

                yield Label("Events CSV path:", classes="sb-label")
                yield Input(value=EVENTS_DEFAULT, id="inp-events-path",
                            classes="sb-input")

                yield Label("Max rows:", classes="sb-label")
                yield Input(value="30000", id="inp-max-rows", classes="sb-input")

                yield Label("Refresh interval (s):", classes="sb-label")
                yield Input(value="5", id="inp-refresh-secs", classes="sb-input")

                yield Checkbox("Auto-refresh", value=True, id="cb-auto-refresh")

                yield Button("Refresh now",       id="btn-refresh",  classes="sb-btn")
                yield Button("Reload processes",  id="btn-reload",   classes="sb-btn")

                yield Label("-" * 28, classes="sb-label")
                yield Label("Collector PID:", classes="sb-label")
                yield Label("none", id="sb-collector-pid", classes="status-stopped")

            # ── Main panel ──────────────────────────────────────────────────
            with ScrollableContainer(id="main"):

                # Metric bar
                with Horizontal(id="metric-bar"):
                    yield MetricCard("eBPF Events",     "-")
                    yield MetricCard("Procs-in-Stream", "-")
                    yield MetricCard("Running-w-Data",  "-")
                    yield MetricCard("Collector",       "stopped")

                # Process picker
                with Container(id="proc-picker"):
                    yield Label("Process Selection", classes="picker-title")
                    yield Label("Filter (type to search):", classes="sb-label")
                    yield Input(value="", id="inp-proc-filter",
                                placeholder="name or PID...", classes="sb-input")
                    yield OptionList(id="proc-option-list")
                    yield Label("Selected:", classes="sb-label")
                    yield Label("(none)", id="selected-pid-display")
                    with Horizontal():
                        yield Input(value="", id="inp-manual-pid",
                                    placeholder="Enter PID manually",
                                    classes="sb-input")
                        yield Button("Apply", id="btn-apply-pid", classes="sb-btn")

                # Collector control
                with Container(id="collector-panel"):
                    yield Label("Collector Control", classes="collector-title")
                    with Horizontal():
                        with Vertical():
                            yield Label("Label:", classes="sb-label")
                            yield Select(
                                [("0 - normal", 0), ("1 - anomaly", 1)],
                                id="sel-label", value=0,
                            )
                        with Vertical():
                            yield Label("Min latency us:", classes="sb-label")
                            yield Input(value="0", id="inp-min-lat", classes="sb-input")
                        with Vertical():
                            yield Label("Sample rate 1/N:", classes="sb-label")
                            yield Input(value="1", id="inp-sample-rate", classes="sb-input")
                    yield Label("Command:", classes="sb-label")
                    yield Label("(select a process first)", id="lbl-cmd-preview",
                                classes="cmd-display")
                    yield Checkbox("Reset CSV before start", value=False, id="cb-reset-csv")
                    with Horizontal():
                        yield Button("Start Collector", id="btn-start")
                        yield Button("Stop  Collector", id="btn-stop")
                    yield Label("No collector running.", id="lbl-collector-status",
                                classes="collector-status status-stopped")

                # Analysis tabs
                with TabbedContent():
                    with TabPane("Summary", id="tab-summary"):
                        yield Label("Top Processes by P99 Latency", classes="section-title")
                        yield DataTable(id="tbl-summary", zebra_stripes=True,
                                        cursor_type="row")

                    with TabPane("Timeline", id="tab-timeline"):
                        yield Label("Latency Timeline", classes="section-title")
                        with Container(classes="chart-box", id="chart-box-timeline"):
                            yield Static("Select a process to view timeline.",
                                         id="chart-timeline")

                    with TabPane("Histogram", id="tab-histogram"):
                        yield Label("Latency Distribution", classes="section-title")
                        with Container(classes="chart-box", id="chart-box-histogram"):
                            yield Static("Select a process to view histogram.",
                                         id="chart-histogram")

                    with TabPane("CPU and Priority", id="tab-cpu"):
                        yield Label("Per-CPU Event Count", classes="section-title")
                        with Container(classes="chart-box"):
                            yield Static("Select a process.", id="chart-cpu")
                        yield Label("Priority Distribution", classes="section-title")
                        with Container(classes="chart-box"):
                            yield Static("Select a process.", id="chart-prio")

                    with TabPane("Recent Events", id="tab-events"):
                        yield Label("Recent Events (last 200)", classes="section-title")
                        yield DataTable(id="tbl-events", zebra_stripes=True,
                                        cursor_type="row")

                    with TabPane("Collector Log", id="tab-log"):
                        yield Label("Collector Log", classes="section-title")
                        yield Log(id="collector-log", highlight=True)

        yield Footer()

    # ── lifecycle ──────────────────────────────────────────────────────────────
    def on_mount(self) -> None:
        self._init_tables()
        self._do_refresh()
        self._timer = self.set_interval(self._refresh_secs, self._tick)

    def _tick(self) -> None:
        if self._auto_refresh:
            self._do_refresh()

    # ── table headers ──────────────────────────────────────────────────────────
    def _init_tables(self) -> None:
        t = self.query_one("#tbl-summary", DataTable)
        t.add_columns("TGID", "comm", "events",
                      "avg us", "p50 us", "p95 us", "p99 us", "max us",
                      "running", "status")

        e = self.query_one("#tbl-events", DataTable)
        e.add_columns("timestamp_ns", "ts_s", "tgid", "pid",
                      "comm", "cpu", "prio", "latency us", "label")

    # ── full refresh ───────────────────────────────────────────────────────────
    def _do_refresh(self) -> None:
        self._load_data()
        self._refresh_metrics()
        self._refresh_summary_table()
        self._refresh_proc_list()
        self._refresh_analysis()
        self._refresh_cmd_preview()
        self._refresh_collector_status()
        self._refresh_log()

    # ── data load ──────────────────────────────────────────────────────────────
    def _events_path(self) -> str:
        try:
            raw = self.query_one("#inp-events-path", Input).value.strip()
        except NoMatches:
            raw = EVENTS_DEFAULT
        return resolve_events_path(raw or EVENTS_DEFAULT)

    def _max_rows(self) -> int:
        try:
            return max(1, int(self.query_one("#inp-max-rows", Input).value or "30000"))
        except (NoMatches, ValueError):
            return 30000

    def _load_data(self) -> None:
        self._running_df = list_running_processes()
        path = self._events_path()
        if os.path.exists(path):
            self._events_df = load_ebpf_events(path, max_rows=self._max_rows())
        else:
            self._events_df = pd.DataFrame(columns=[
                "timestamp_ns", "pid", "tgid", "comm", "cpu_id",
                "priority", "latency_us", "label", "timestamp_s"
            ])
        self._summary_df = summarize_latency(self._events_df)

        if self._collector_pid and not is_pid_alive(self._collector_pid):
            self._collector_pid = 0

    # ── metrics ────────────────────────────────────────────────────────────────
    def _refresh_metrics(self) -> None:
        running_pids = (set(self._running_df["pid"].tolist())
                        if not self._running_df.empty else set())
        running_with_data = int(
            self._summary_df["tgid"].isin(running_pids).sum()
        ) if not self._summary_df.empty else 0

        vals = [
            str(len(self._events_df)),
            str(self._summary_df["tgid"].nunique()
                if not self._summary_df.empty else 0),
            str(running_with_data),
            (f"PID {self._collector_pid}"
             if self._collector_pid and is_pid_alive(self._collector_pid)
             else "stopped"),
        ]
        for card, val in zip(self.query(".metric-card").results(MetricCard), vals):
            card.update_value(val)

    # ── summary table ──────────────────────────────────────────────────────────
    def _refresh_summary_table(self) -> None:
        tbl = self.query_one("#tbl-summary", DataTable)
        tbl.clear()
        if self._summary_df.empty:
            return
        running_pids = (set(self._running_df["pid"].tolist())
                        if not self._running_df.empty else set())
        status_map = (dict(zip(self._running_df["pid"], self._running_df["status"]))
                      if not self._running_df.empty else {})
        for row in self._summary_df.head(50).itertuples():
            tbl.add_row(
                str(row.tgid), row.comm, str(row.events),
                f"{row.avg_us:.1f}", f"{row.p50_us:.1f}",
                f"{row.p95_us:.1f}", f"{row.p99_us:.1f}", f"{row.max_us:.1f}",
                "Y" if row.tgid in running_pids else "N",
                status_map.get(row.tgid, "-"),
            )

    # ── process option list ────────────────────────────────────────────────────
    def _refresh_proc_list(self, filter_text: str = "") -> None:
        ol = self.query_one("#proc-option-list", OptionList)
        ol.clear_options()

        ft = filter_text.strip().lower()
        rows: list[tuple[str, int]] = []

        if not self._running_df.empty:
            for row in self._running_df.itertuples():
                label = f"{row.name}  (PID {row.pid})"
                if ft and ft not in row.name.lower() and ft not in str(row.pid):
                    continue
                rows.append((label, int(row.pid)))

        self._proc_options = rows
        for label, pid in rows:
            ol.add_option(Option(label, id=f"pid-{pid}"))

    @on(Input.Changed, "#inp-proc-filter")
    def _on_filter_change(self, event: Input.Changed) -> None:
        self._refresh_proc_list(filter_text=event.value)

    @on(OptionList.OptionSelected, "#proc-option-list")
    def _on_proc_selected(self, event: OptionList.OptionSelected) -> None:
        opt_id = event.option_id or ""
        if opt_id.startswith("pid-"):
            try:
                self._set_selected_pid(int(opt_id[4:]))
            except ValueError:
                pass

    def _set_selected_pid(self, pid: int) -> None:
        self._selected_pid = pid
        name = "-"
        if not self._running_df.empty:
            match = self._running_df[self._running_df["pid"] == pid]
            if not match.empty:
                name = match.iloc[0]["name"]
        try:
            self.query_one("#selected-pid-display", Label).update(
                f"PID {pid}  -  {name}"
            )
        except NoMatches:
            pass
        self._refresh_cmd_preview()
        self._refresh_analysis()

    @on(Button.Pressed, "#btn-apply-pid")
    def _on_apply_pid(self) -> None:
        try:
            val = int(self.query_one("#inp-manual-pid", Input).value.strip() or "0")
            if val > 0:
                self._set_selected_pid(val)
        except (ValueError, NoMatches):
            pass

    # ── analysis panels ────────────────────────────────────────────────────────
    def _refresh_analysis(self) -> None:
        pid = self._selected_pid
        if pid is None:
            return

        proc_df = (
            self._events_df[self._events_df["tgid"] == pid].copy()
            if not self._events_df.empty else pd.DataFrame()
        )

        no_data = (
            f"No eBPF data for PID {pid}.\n"
            "Start the targeted collector, then press R to refresh."
        )

        if proc_df.empty:
            self.query_one("#chart-timeline",  Static).update(no_data)
            self.query_one("#chart-histogram", Static).update(no_data)
            self.query_one("#chart-cpu",       Static).update(no_data)
            self.query_one("#chart-prio",      Static).update(no_data)
            self.query_one("#tbl-events", DataTable).clear()
            return

        proc_df = proc_df.sort_values("timestamp_s")
        lat = proc_df["latency_us"].to_numpy(dtype=float)

        # timeline
        spark = sparkline_panel_with_axes(lat.tolist(), width=60, height=10)
        spikes = spark_spike_markers(lat.tolist(), width=60)
        tl = (
            f"PID {pid}  |  {len(lat):,} samples\n"
            f"min {lat.min():.1f}us   avg {np.mean(lat):.1f}us   "
            f"p99 {np.percentile(lat, 99):.1f}us   max {lat.max():.1f}us\n\n"
            f"Spark panel (max-per-bucket; robust scale):\n{spark}\n"
            f"Spike markers (! >= p95, ^ >= p99):\n{' ' * 8} |{spikes}\n\n"
            f"Dot-matrix timeline (newest = right):\n"
            + ascii_timeline(lat, height=8, width=60)
        )
        self.query_one("#chart-timeline", Static).update(tl)

        # histogram
        self.query_one("#chart-histogram", Static).update(
            ascii_histogram(lat, bins=20, bar_width=44)
        )

        # cpu
        cpu = proc_df["cpu_id"].value_counts().sort_index()
        self.query_one("#chart-cpu", Static).update(
            ascii_bar_chart([f"CPU {k}" for k in cpu.index],
                            cpu.values.tolist(), bar_width=40,
                            title="Per-CPU event count")
        )

        # priority
        prio = proc_df["priority"].value_counts().sort_index()
        self.query_one("#chart-prio", Static).update(
            ascii_bar_chart([f"Prio {k}" for k in prio.index],
                            prio.values.tolist(), bar_width=40,
                            title="Priority distribution")
        )

        # events table
        etbl = self.query_one("#tbl-events", DataTable)
        etbl.clear()
        for row in proc_df.tail(200).itertuples():
            etbl.add_row(
                str(row.timestamp_ns), f"{row.timestamp_s:.3f}",
                str(row.tgid), str(row.pid), str(row.comm),
                str(row.cpu_id), str(row.priority),
                f"{row.latency_us:.2f}", str(row.label),
            )

    # ── collector control ──────────────────────────────────────────────────────
    def _refresh_cmd_preview(self) -> None:
        if self._selected_pid is None:
            return
        try:
            lv  = self.query_one("#sel-label", Select).value or 0
            ml  = self.query_one("#inp-min-lat", Input).value or "0"
            sr  = self.query_one("#inp-sample-rate", Input).value or "1"
            cmd = f"sudo ./collector {lv} {self._selected_pid} {ml} {sr}"
            self._collector_cmd = cmd
            self.query_one("#lbl-cmd-preview", Label).update(cmd)
        except NoMatches:
            pass

    def _refresh_collector_status(self) -> None:
        alive = bool(self._collector_pid and is_pid_alive(self._collector_pid))
        for wid_id in ("#lbl-collector-status", "#sb-collector-pid"):
            try:
                w = self.query_one(wid_id, Label)
                if wid_id == "#sb-collector-pid":
                    w.update(str(self._collector_pid) if alive else "none")
                else:
                    w.update(f"Running - PID {self._collector_pid}" if alive
                             else "No collector running.")
                if alive:
                    w.remove_class("status-stopped")
                    w.add_class("status-running")
                else:
                    w.remove_class("status-running")
                    w.add_class("status-stopped")
            except NoMatches:
                pass

    @on(Button.Pressed, "#btn-start")
    def _on_start(self) -> None:
        self.action_start_collector()

    def action_start_collector(self) -> None:
        if self._selected_pid is None:
            self.push_screen(InfoModal("No Process", "Select a process first."))
            return
        if self._collector_pid and is_pid_alive(self._collector_pid):
            self.push_screen(InfoModal("Already Running",
                f"Collector PID {self._collector_pid} is active.\nStop it first."))
            return

        try:
            lv = int(self.query_one("#sel-label", Select).value or 0)
            ml = int(self.query_one("#inp-min-lat", Input).value or "0")
            sr = int(self.query_one("#inp-sample-rate", Input).value or "1")
        except (NoMatches, ValueError):
            lv, ml, sr = 0, 0, 1

        try:
            reset = self.query_one("#cb-reset-csv", Checkbox).value
        except NoMatches:
            reset = False

        if reset:
            for p in [os.path.join(BASE_DIR, "ebpf_events.csv"),
                      os.path.join(BASE_DIR, "dataset.csv")]:
                try:
                    os.remove(p)
                except FileNotFoundError:
                    pass

        ok, msg = self._launch_collector(lv, self._selected_pid, ml, sr)
        self.push_screen(InfoModal("Collector " + ("Started" if ok else "Error"), msg))
        self._refresh_collector_status()

    def _launch_collector(self, label: int, target_pid: int,
                           min_us: int, rate: int) -> tuple[bool, str]:
        if not os.path.exists(COLLECTOR_BIN):
            return False, (
                f"Collector binary not found:\n{COLLECTOR_BIN}\n\n"
                "Build it first with 'make', or check the path."
            )
        cmd = [COLLECTOR_BIN, str(label), str(target_pid), str(min_us), str(rate)]
        with open(COLLECTOR_LOG, "a", encoding="utf-8") as lf:
            proc = subprocess.Popen(
                cmd, cwd=BASE_DIR,
                stdout=lf, stderr=lf, start_new_session=True,
            )
        time.sleep(0.5)
        ret = proc.poll()
        if ret is not None and ret != 0:
            tail = read_log_tail(COLLECTOR_LOG)
            msg = "Collector exited with non-zero status."
            if "Operation not permitted" in tail or "RLIMIT_MEMLOCK" in tail:
                msg += (
                    "\n\neBPF permission denied.\n"
                    "Fix with one of:\n"
                    "  sudo python tui_dashboard.py\n"
                    "  sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+ep ./collector"
                )
            if tail:
                msg += f"\n\nLog tail:\n{tail[-400:]}"
            return False, msg
        self._collector_pid = proc.pid
        self._collector_cmd = " ".join(cmd)
        return True, f"Started - PID {proc.pid}\nCmd: {self._collector_cmd}"

    @on(Button.Pressed, "#btn-stop")
    def _on_stop(self) -> None:
        self.action_stop_collector_action()

    def action_stop_collector_action(self) -> None:
        if not self._collector_pid or not is_pid_alive(self._collector_pid):
            self.push_screen(InfoModal("Not Running", "No tracked collector is running."))
            return
        try:
            os.kill(self._collector_pid, signal.SIGINT)
            msg = f"Sent SIGINT to PID {self._collector_pid}."
            self._collector_pid = 0
        except OSError as e:
            msg = f"Error: {e}"
        self.push_screen(InfoModal("Collector", msg))
        self._refresh_collector_status()

    # ── collector param changes ────────────────────────────────────────────────
    @on(Input.Changed,  "#inp-min-lat")
    @on(Input.Changed,  "#inp-sample-rate")
    @on(Select.Changed, "#sel-label")
    def _on_param_change(self, _: object) -> None:
        self._refresh_cmd_preview()

    # ── sidebar controls ───────────────────────────────────────────────────────
    @on(Button.Pressed, "#btn-refresh")
    def _on_refresh(self) -> None:
        self.action_refresh()

    def action_refresh(self) -> None:
        self._do_refresh()

    @on(Button.Pressed, "#btn-reload")
    def _on_reload(self) -> None:
        self._running_df = list_running_processes()
        self._refresh_proc_list()

    @on(Checkbox.Changed, "#cb-auto-refresh")
    def _on_auto_refresh(self, ev: Checkbox.Changed) -> None:
        self._auto_refresh = ev.value

    @on(Input.Submitted, "#inp-refresh-secs")
    def _on_refresh_secs(self, ev: Input.Submitted) -> None:
        try:
            secs = int(ev.value)
            if secs >= 1:
                self._refresh_secs = secs
                if self._timer:
                    self._timer.stop()
                self._timer = self.set_interval(secs, self._tick)
        except ValueError:
            pass

    # ── log panel ──────────────────────────────────────────────────────────────
    def _refresh_log(self) -> None:
        tail = read_log_tail(COLLECTOR_LOG, max_lines=60)
        log  = self.query_one("#collector-log", Log)
        log.clear()
        log.write(tail if tail else "(no log output yet)")

    # ── help ───────────────────────────────────────────────────────────────────
    def action_show_help(self) -> None:
        self.push_screen(InfoModal("Help", (
            "Keys\n"
            "----\n"
            "R         Refresh data\n"
            "Ctrl+S    Start collector\n"
            "Ctrl+X    Stop  collector\n"
            "F1        This help screen\n"
            "Q         Quit\n\n"
            "Workflow\n"
            "--------\n"
            "1. Type in the filter box to find a process.\n"
            "2. Arrow-key / click to select it in the list.\n"
            "3. Set label, min-latency, sample-rate.\n"
            "4. Press 'Start Collector' (may need sudo).\n"
            "5. Wait a few seconds, press R to refresh.\n"
            "6. Browse tabs: Timeline / Histogram / CPU / Events.\n\n"
            "Events file default path:\n"
            "  ebpf_logs/ebpf_events.csv\n\n"
            "You can also enter any PID manually and press Apply."
        )))


# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    LatencyDashboard().run()
