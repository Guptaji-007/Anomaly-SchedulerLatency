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
    Button, Checkbox, DataTable, Footer, Header, Input,
    Label, Log, OptionList, Select, Static, TabbedContent, TabPane,
)
from textual.widgets.option_list import Option

try:
    import psutil
except ImportError:
    psutil = None

# ──────────────────────────────────────────────────────────────────────────────
# Paths  — everything is anchored to the directory of THIS script
# ──────────────────────────────────────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
COLLECTOR_BIN = os.path.join(BASE_DIR, "collector")
COLLECTOR_LOG = os.path.join(BASE_DIR, "collector_tui.log")
MAIN_EVENTS_FILE  = os.path.join(BASE_DIR, "ebpf_events_main.csv")
CMP_A_EVENTS_FILE = os.path.join(BASE_DIR, "ebpf_events_cmp_a.csv")
CMP_B_EVENTS_FILE = os.path.join(BASE_DIR, "ebpf_events_cmp_b.csv")
# Default file used by the main section
EVENTS_DEFAULT = MAIN_EVENTS_FILE

# ──────────────────────────────────────────────────────────────────────────────
# CSS
# ──────────────────────────────────────────────────────────────────────────────
APP_CSS = """
Screen { background: #0d1117; }
Header { background: #161b22; color: #58a6ff; text-style: bold; height: 3; }
Footer { background: #161b22; color: #8b949e; height: 2; }

/* ── Sidebar ── */
#sidebar { width: 34; background: #161b22; border-right: solid #21262d; padding: 1; }
#sidebar-title {
    color: #58a6ff; text-style: bold; text-align: center;
    padding: 0 0 1 0; border-bottom: solid #21262d; margin-bottom: 1;
}
.sb-label { color: #8b949e; margin-top: 1; }
.sb-input { width: 100%; background: #0d1117; border: solid #30363d; color: #c9d1d9; }
.sb-input:focus { border: solid #58a6ff; }
.sb-btn { width: 100%; margin-top: 1; background: #21262d; color: #c9d1d9; border: solid #30363d; }
.sb-btn:hover { background: #30363d; color: #58a6ff; }
.status-running { color: #3fb950; text-style: bold; }
.status-stopped { color: #8b949e; }

/* ── Main ── */
#main { background: #0d1117; padding: 1 2; }

/* ── Metric cards ── */
#metric-bar { height: 5; margin-bottom: 1; }
.metric-card {
    background: #161b22; border: solid #21262d; padding: 0 1;
    width: 1fr; margin-right: 1; height: 5; content-align: center middle;
}
.metric-card:last-child { margin-right: 0; }
.metric-value { color: #58a6ff; text-style: bold; text-align: center; }
.metric-label { color: #8b949e; text-align: center; }
.section-title { color: #3fb950; text-style: bold; margin: 1 0 0 0; }

/* ── Proc picker ── */
#proc-picker {
    background: #161b22; border: solid #21262d;
    padding: 1; margin-top: 1; height: auto; max-height: 22;
}
.picker-title { color: #a5d6ff; text-style: bold; margin-bottom: 1; }
#proc-option-list { background: #0d1117; border: solid #30363d; height: 10; color: #c9d1d9; }
OptionList > .option-list--option { padding: 0 1; }
OptionList > .option-list--option-highlighted { background: #1f6feb; color: #ffffff; }
#selected-pid-display {
    background: #0d1117; border: solid #30363d;
    padding: 0 1; color: #e3b341; margin: 1 0; height: 3;
}

/* ── Collector panel ── */
#collector-panel { background: #161b22; border: solid #21262d; padding: 1; margin-top: 1; }
.collector-title { color: #f78166; text-style: bold; margin-bottom: 1; }
.cmd-display {
    background: #0d1117; border: solid #30363d;
    padding: 0 1; color: #e3b341; margin: 1 0; height: 3;
}
#btn-start { background: #1a7f37; color: #fff; border: solid #2ea043; margin-right: 1; width: 1fr; }
#btn-start:hover { background: #2ea043; }
#btn-stop  { background: #6e1c1c; color: #fff; border: solid #f85149; width: 1fr; }
#btn-stop:hover  { background: #f85149; }
#lbl-collector-status { margin-top: 1; }

/* ── Tables ── */
DataTable { background: #0d1117; border: solid #21262d; height: auto; max-height: 18; }
DataTable > .datatable--header { background: #161b22; color: #58a6ff; text-style: bold; }
DataTable > .datatable--cursor { background: #1f6feb; color: #fff; }
DataTable > .datatable--even-row { background: #0d1117; color: #c9d1d9; }
DataTable > .datatable--odd-row  { background: #111820; color: #c9d1d9; }

/* ── Chart boxes ── */
.chart-box { background: #161b22; border: solid #21262d; padding: 1; height: 16; margin-top: 1; }
.chart-box Static { color: #3fb950; }

/* ── Tabs / Log ── */
TabbedContent { margin-top: 1; }
TabPane { background: #0d1117; padding: 1; }
Log { background: #0d1117; border: solid #21262d; color: #8b949e; height: 14; margin-top: 1; }

/* ── Modal ── */
ModalScreen { align: center middle; }
#modal-dialog {
    width: 72; background: #161b22; border: solid #58a6ff;
    padding: 2 3; height: auto; max-height: 40;
}
#modal-title { color: #58a6ff; text-style: bold; margin-bottom: 1; }
#modal-body  { color: #c9d1d9; margin-bottom: 2; }
#modal-close { background: #21262d; color: #c9d1d9; border: solid #30363d; width: 100%; }

/* ════════════════════════════════════════════
   COMPARE TAB
   ════════════════════════════════════════════ */

#cmp-header { 
    background: #161b22; 
    border: solid #21262d; 
    padding: 1; 
    margin-bottom: 1; 
}

.cmp-section-title { 
    color: #d2a8ff; 
    text-style: bold; 
    margin-bottom: 1; 
}

/* Base label styling for the new sb-label class */
.sb-label {
    color: #c9d1d9;
    margin-top: 1;
}

/* Give grid a bounded height (1fr) so child columns share the available vertical space */
#cmp-grid { 
    height: 1fr; 
    min-height: 20; 
}

/* 
  Since these are now ScrollableContainers, they just need 
  height: 1fr to fill the grid space. Textual handles the scroll natively. 
*/
.cmp-col-a {
    width: 1fr; 
    margin-right: 1;
    background: #0d1117; 
    border: solid #f78166;
    padding: 1; 
    height: 1fr; 
}
.cmp-col-b {
    width: 1fr;
    background: #0d1117; 
    border: solid #3fb950;
    padding: 1; 
    height: 1fr; 
}

.cmp-head-a { color: #f78166; text-style: bold; text-align: center; margin-bottom: 1; }
.cmp-head-b { color: #3fb950; text-style: bold; text-align: center; margin-bottom: 1; }

.cmp-input {
    background: #1c2128;
    border: solid #58a6ff;
    color: #ffffff;
    width: 100%;
}
.cmp-input:focus { border: solid #e3b341; }

.cmp-opt-list {
    background: #1c2128; 
    border: solid #444c56;
    height: 7; 
    color: #e6edf3; 
    margin-top: 1;
}

.cmp-status-a { color: #f78166; margin-top: 1; }
.cmp-status-b { color: #3fb950; margin-top: 1; }

#btn-cmp-start-a, #btn-cmp-start-b {
    background: #1a7f37; 
    color: #fff; 
    border: solid #2ea043;
    width: 1fr; 
    margin-right: 1; 
    margin-top: 1;
}
#btn-cmp-start-a:hover, #btn-cmp-start-b:hover { background: #2ea043; }

#btn-cmp-stop-a, #btn-cmp-stop-b {
    background: #6e1c1c; 
    color: #fff; 
    border: solid #f85149;
    width: 1fr; 
    margin-top: 1;
}
#btn-cmp-stop-a:hover, #btn-cmp-stop-b:hover { background: #f85149; }

/* Keep strict bounds and hidden overflow on the boxes to stop the chart bleeding */
.cmp-chart-box-a { background: #161b22; border: solid #f78166; padding: 1; height: 18; margin-top: 1; overflow: hidden; }
.cmp-chart-box-b { background: #161b22; border: solid #3fb950; padding: 1; height: 18; margin-top: 1; overflow: hidden; }

/* Force internal charts to strictly map to the bounded box */
.cmp-chart-a { color: #f78166; width: 1fr; height: 1fr; }
.cmp-chart-b { color: #3fb950; width: 1fr; height: 1fr; }

/* Diff table section */
#cmp-diff-section { 
    margin-top: 1; 
    height: auto; 
}

/* Explicit bounded height so the DataTable can calculate internal scrolling */
#cmp-diff-table { 
    background: #0d1117; 
    border: solid #d2a8ff; 
    height: 15; 
    margin-top: 1; 
}
#cmp-diff-table > .datatable--header { background: #161b22; color: #d2a8ff; text-style: bold; }
#cmp-diff-table > .datatable--cursor { background: #1f6feb; color: #fff; }
#cmp-diff-table > .datatable--even-row { background: #0d1117; color: #c9d1d9; }
#cmp-diff-table > .datatable--odd-row  { background: #111820; color: #c9d1d9; }
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


def is_system_process_name(name: str) -> bool:
    n = (name or "").strip().lower()
    if not n:
        return False
    if n.startswith("[") and n.endswith("]"):
        return True
    if n in {"swapper", "idle", "init", "systemd", "kthreadd"}:
        return True
    for pfx in ("kworker","ksoftirqd","kcompactd","kswapd","khugepaged",
                "kdevtmpfs","migration","watchdog","jbd2","rcu"):
        if n.startswith(pfx):
            return True
    return False


def is_system_process(pid: int, name: str) -> bool:
    return pid <= 1 or is_system_process_name(name)


def list_running_processes() -> pd.DataFrame:
    rows: list[dict] = []
    if psutil is not None:
        for proc in psutil.process_iter(attrs=["pid", "name", "status"]):
            try:
                info = proc.info
                pid  = int(info.get("pid", -1))
                name = str(info.get("name") or "unknown")
                if is_system_process(pid, name):
                    continue
                rows.append({"pid": pid, "name": name,
                              "status": str(info.get("status") or "unknown")})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    else:
        result = subprocess.run(["ps", "-eo", "pid=,comm=,stat="],
                                check=False, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            parts = line.strip().split(maxsplit=2)
            if len(parts) < 2:
                continue
            try:
                pid  = int(parts[0])
                name = parts[1]
                if is_system_process(pid, name):
                    continue
                rows.append({"pid": pid, "name": name,
                              "status": parts[2] if len(parts) > 2 else "unknown"})
            except ValueError:
                continue
    if not rows:
        return pd.DataFrame(columns=["pid", "name", "status"])
    df = pd.DataFrame(rows).drop_duplicates(subset=["pid"], keep="last")
    return df.sort_values(by=["name", "pid"]).reset_index(drop=True)


def resolve_events_path(path: str) -> str:
    """Try to find the events CSV by looking in several standard locations."""
    if os.path.exists(path):
        return path
    candidates = [
        MAIN_EVENTS_FILE,
        os.path.join(BASE_DIR, "ebpf_events.csv"),
        os.path.join(BASE_DIR, "ebpf_logs", "ebpf_events.csv"),
        "ebpf_events.csv",
        "ebpf_logs/ebpf_events.csv",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return path


def load_ebpf_events(path: str, max_rows: int = 30000) -> pd.DataFrame:
    required = ["timestamp_ns","pid","tgid","comm","cpu_id","priority","latency_us","label"]
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            header     = f.readline().strip()
            tail_lines = list(deque(f, maxlen=max_rows))
        if not header:
            return pd.DataFrame(columns=required + ["timestamp_s"])
        df = pd.read_csv(StringIO(header + "\n" + "".join(tail_lines)))
    except Exception:
        return pd.DataFrame(columns=required + ["timestamp_s"])

    if any(c not in df.columns for c in required):
        return pd.DataFrame(columns=required + ["timestamp_s"])

    df = df.copy()
    for col in ["timestamp_ns","pid","tgid","cpu_id","priority","latency_us","label"]:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df.dropna(subset=["timestamp_ns","pid","tgid","latency_us"])
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
        return pd.DataFrame(columns=["tgid","comm","events","avg_us",
                                     "p50_us","p95_us","p99_us","max_us"])
    rows = []
    for (tgid, comm), grp in df.groupby(["tgid","comm"], dropna=False):
        lat = grp["latency_us"].to_numpy(dtype=float)
        rows.append({"tgid": int(tgid), "comm": str(comm), "events": len(lat),
                     "avg_us": float(np.mean(lat)), "p50_us": float(np.percentile(lat, 50)),
                     "p95_us": float(np.percentile(lat, 95)),
                     "p99_us": float(np.percentile(lat, 99)),
                     "max_us": float(np.max(lat))})
    out = pd.DataFrame(rows)
    return out.sort_values(["p99_us","events"], ascending=[False,False]).reset_index(drop=True)


# ──────────────────────────────────────────────────────────────────────────────
# ASCII chart helpers
# ──────────────────────────────────────────────────────────────────────────────
_BLOCKS = "▁▂▃▄▅▆▇█"

def _bucket_reduce(values: np.ndarray, width: int) -> np.ndarray:
    if values.size == 0:
        return np.array([], dtype=float)
    if values.size <= width:
        return values.astype(float)
    step = values.size / width
    out  = []
    for i in range(width):
        s = int(i * step)
        e = min(int((i + 1) * step), values.size)
        if e <= s:
            e = s + 1
        bucket = values[s:e]
        if bucket.size:
            out.append(float(bucket.max()))
    return np.array(out, dtype=float)


def sparkline(values: list[float], width: int = 55) -> str:
    if not values:
        return "-" * width
    arr = np.asarray(values, dtype=float)
    sam = _bucket_reduce(arr, width)
    if sam.size == 0:
        return "-" * width
    lo = float(np.percentile(sam, 5))
    hi = float(np.percentile(sam, 95))
    if hi <= lo:
        lo, hi = float(sam.min()), float(sam.max())
    span = (hi - lo) or 1.0
    out = []
    for v in sam:
        idx = int(((min(max(v, lo), hi) - lo) / span) * (len(_BLOCKS) - 1))
        out.append(_BLOCKS[max(0, min(idx, len(_BLOCKS) - 1))])
    return "".join(out)


def sparkline_axes(values: list[float], width: int = 55, height: int = 10) -> str:
    if not values:
        return "(no data)"
    arr = np.asarray(values, dtype=float)
    sam = _bucket_reduce(arr, width)
    if sam.size == 0:
        return "(no data)"
    lo = float(np.percentile(sam, 5))
    hi = float(np.percentile(sam, 95))
    if hi <= lo:
        lo, hi = float(sam.min()), float(sam.max())
    span = (hi - lo) or 1.0
    norm = np.clip((sam - lo) / span, 0.0, 1.0)
    rows: list[str] = []
    for r in range(height):
        thr  = 1.0 - (r / max(height - 1, 1))
        bars = "".join("*" if v >= thr else " " for v in norm)
        if r == 0:
            yl = f"{hi:7.1f}"
        elif r == height // 2:
            yl = f"{(lo + hi) / 2:7.1f}"
        elif r == height - 1:
            yl = f"{lo:7.1f}"
        else:
            yl = " " * 7
        rows.append(f"{yl} |{bars}")
    rows.append("        +" + "-" * len(sam))
    rows.append("         samples (oldest->newest)  unit: us")
    return "\n".join(rows)


def spike_markers(values: list[float], width: int = 55) -> str:
    if not values:
        return ""
    arr = np.asarray(values, dtype=float)
    sam = _bucket_reduce(arr, width)
    if sam.size == 0:
        return ""
    p95 = float(np.percentile(arr, 95))
    p99 = float(np.percentile(arr, 99))
    return "".join("^" if v >= p99 else "!" if v >= p95 else " " for v in sam)


def ascii_timeline(lat: np.ndarray, height: int = 8, width: int = 55) -> str:
    if lat.size == 0:
        return "(no data)"
    mn, mx  = lat.min(), lat.max()
    span    = (mx - mn) or 1
    sampled = lat[::max(1, len(lat) // width)][-width:]
    rows = []
    for r in range(height - 1, -1, -1):
        thr  = mn + (r / max(height - 1, 1)) * span
        line = "".join("." if v >= thr else " " for v in sampled)
        rows.append(f"{thr:>10.1f} |{line}")
    rows.append(" " * 11 + "+" + "-" * len(sampled))
    return "\n".join(rows)


def ascii_histogram(lat: np.ndarray, bins: int = 18, bar_width: int = 38) -> str:
    if lat.size == 0:
        return "(no data)"
    hist, edges = np.histogram(lat, bins=bins)
    mx = hist.max() or 1
    lines = [f"{'bucket (us)':<22}  count", "-" * (bar_width + 28)]
    for i in range(len(hist)):
        lbl = f"{edges[i]:>9.1f}-{edges[i+1]:<9.1f}"
        bar = "#" * int(hist[i] / mx * bar_width)
        lines.append(f"{lbl}  |{bar:<{bar_width}}  {hist[i]}")
    return "\n".join(lines)


def ascii_bar(keys: list, values: list, bar_width: int = 36, title: str = "") -> str:
    if not keys:
        return "(no data)"
    mx = max(values) or 1
    lines = ([title, "-" * (bar_width + 14)] if title
             else ["-" * (bar_width + 14)])
    for k, v in zip(keys, values):
        bar = "#" * int(v / mx * bar_width)
        lines.append(f"{str(k):>6}  |{bar:<{bar_width}}  {v}")
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# CollectorSlot  —  manages ONE child collector process
# ──────────────────────────────────────────────────────────────────────────────
class CollectorSlot:
    def __init__(self) -> None:
        self.pid:        int = 0
        self.target_pid: int = 0
        self.cmd:        str = ""
        self.events_csv: str = ""

    @property
    def alive(self) -> bool:
        return bool(self.pid and is_pid_alive(self.pid))

    def stop(self) -> str:
        if not self.alive:
            self.pid = 0
            return "Collector was not running."
        try:
            os.kill(self.pid, signal.SIGINT)
            msg = f"Stopped collector PID {self.pid} (SIGINT sent)."
        except OSError as exc:
            msg = f"Could not stop PID {self.pid}: {exc}"
        self.pid        = 0
        self.target_pid = 0
        self.cmd        = ""
        self.events_csv = ""
        return msg

    def launch(self, label: int, target_pid: int,
               min_us: int, rate: int,
               events_csv: str) -> tuple[bool, str]:
        if not os.path.exists(COLLECTOR_BIN):
            return False, (
                f"Collector binary not found:\n  {COLLECTOR_BIN}\n\n"
                "Build it first with 'make'."
            )
        # Ensure output directory exists
        out_dir = os.path.join(BASE_DIR, "ebpf_logs")
        os.makedirs(out_dir, exist_ok=True)

        cmd_list = [COLLECTOR_BIN, str(label), str(target_pid),
                    str(min_us), str(rate)]
        try:
            env = os.environ.copy()
            env["SL_EVENTS_CSV"] = events_csv
            with open(COLLECTOR_LOG, "a", encoding="utf-8") as lf:
                proc = subprocess.Popen(
                    cmd_list, cwd=BASE_DIR,
                    stdout=lf, stderr=lf, start_new_session=True,
                    env=env,
                )
        except Exception as exc:
            return False, f"Failed to launch collector: {exc}"

        time.sleep(0.6)
        ret = proc.poll()
        if ret is not None and ret != 0:
            tail = read_log_tail(COLLECTOR_LOG)
            msg  = f"Collector exited immediately (code {ret})."
            if "Operation not permitted" in tail or "RLIMIT_MEMLOCK" in tail:
                msg += (
                    "\n\neBPF permission denied. Fix with one of:\n"
                    "  sudo python tui_dashboard.py\n"
                    "  sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+ep ./collector"
                )
            if tail:
                msg += f"\n\nLog tail:\n{tail[-400:]}"
            self.pid = 0
            return False, msg

        self.pid        = proc.pid
        self.target_pid = target_pid
        self.cmd        = " ".join(cmd_list)
        self.events_csv = events_csv
        return True, (
            f"Collector started.\n"
            f"  PID:    {proc.pid}\n"
            f"  Target: {target_pid}\n"
            f"  Cmd:    {self.cmd}\n\n"
            f"Events will appear in:\n  {events_csv}\n\n"
            "Press R (or wait for auto-refresh) to see live data."
        )


# ──────────────────────────────────────────────────────────────────────────────
# Widgets
# ──────────────────────────────────────────────────────────────────────────────
def _safe_id(label: str) -> str:
    return "mc-" + re.sub(r"[^a-zA-Z0-9_-]", "_", label)


class MetricCard(Widget):
    def __init__(self, label: str, value: str = "-"):
        super().__init__(classes="metric-card")
        self._label   = label
        self._value   = value
        self._sid     = _safe_id(label)

    def compose(self) -> ComposeResult:
        yield Label(self._value, classes="metric-value", id=self._sid)
        yield Label(self._label, classes="metric-label")

    def update_value(self, value: str) -> None:
        try:
            self.query_one(f"#{self._sid}", Label).update(value)
        except NoMatches:
            pass


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
# Main Application
# ──────────────────────────────────────────────────────────────────────────────
class LatencyDashboard(App):
    TITLE     = "Process Scheduling Latency Dashboard"
    SUB_TITLE = "eBPF Runqueue Latency  |  TUI"
    CSS       = APP_CSS

    BINDINGS = [
        Binding("r",      "refresh",               "Refresh"),
        Binding("ctrl+s", "start_collector",       "Start Collector"),
        Binding("ctrl+x", "stop_collector_action", "Stop Collector"),
        Binding("f1",     "show_help",             "Help"),
        Binding("q",      "quit",                  "Quit"),
    ]

    def __init__(self):
        super().__init__()
        # ── Collector slots — INSTANCE variables, not class variables ──────────
        self._slot_main  = CollectorSlot()   # main tab
        self._slot_cmp_a = CollectorSlot()   # compare column A
        self._slot_cmp_b = CollectorSlot()   # compare column B

        # ── Selection state ────────────────────────────────────────────────────
        self._selected_pid: Optional[int] = None
        self._cmp_pid_a:    Optional[int] = None
        self._cmp_pid_b:    Optional[int] = None

        # ── Data frames ────────────────────────────────────────────────────────
        self._events_df_main:  pd.DataFrame = pd.DataFrame()
        self._events_df_cmp_a: pd.DataFrame = pd.DataFrame()
        self._events_df_cmp_b: pd.DataFrame = pd.DataFrame()
        self._summary_df:       pd.DataFrame = pd.DataFrame()
        self._running_df:       pd.DataFrame = pd.DataFrame()

        # ── Refresh settings ───────────────────────────────────────────────────
        self._auto_refresh: bool          = True
        self._refresh_secs: int           = 5
        self._timer:        Optional[Timer] = None

    # ── compose ────────────────────────────────────────────────────────────────
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Horizontal():
            # ── Sidebar ──────────────────────────────────────────────────────
            with ScrollableContainer(id="sidebar"):
                yield Label("  Controls", id="sidebar-title")

                yield Label("Events CSV path:", classes="sb-label")
                yield Input(value=EVENTS_DEFAULT, id="inp-events-path", classes="sb-input")

                yield Label("Max rows:", classes="sb-label")
                yield Input(value="30000", id="inp-max-rows", classes="sb-input")

                yield Label("Refresh interval (s):", classes="sb-label")
                yield Input(value="5", id="inp-refresh-secs", classes="sb-input")

                yield Checkbox("Auto-refresh", value=True, id="cb-auto-refresh")
                yield Button("Refresh now",      id="btn-refresh", classes="sb-btn")
                yield Button("Reload processes", id="btn-reload",  classes="sb-btn")

                yield Label("-" * 28, classes="sb-label")
                yield Label("Main collector:", classes="sb-label")
                yield Label("none", id="sb-collector-pid", classes="status-stopped")
                yield Label("Cmp A:", classes="sb-label")
                yield Label("none", id="sb-cmp-a-pid", classes="status-stopped")
                yield Label("Cmp B:", classes="sb-label")
                yield Label("none", id="sb-cmp-b-pid", classes="status-stopped")

            # ── Main area ────────────────────────────────────────────────────
            with ScrollableContainer(id="main"):

                # Metric bar
                with Horizontal(id="metric-bar"):
                    yield MetricCard("eBPF Events",     "-")
                    yield MetricCard("Procs-in-Stream", "-")
                    yield MetricCard("Running-w-Data",  "-")
                    yield MetricCard("Collectors",      "0 running")

                # Process picker
                with Container(id="proc-picker"):
                    yield Label("Process Selection", classes="picker-title")
                    yield Label("Filter:", classes="sb-label")
                    yield Input(value="", id="inp-proc-filter",
                                placeholder="name or PID...", classes="sb-input")
                    yield OptionList(id="proc-option-list")
                    yield Label("Selected:", classes="sb-label")
                    yield Label("(none)", id="selected-pid-display")
                    with Horizontal():
                        yield Input(value="", id="inp-manual-pid",
                                    placeholder="Enter PID manually", classes="sb-input")
                        yield Button("Apply", id="btn-apply-pid", classes="sb-btn")

                # Main collector control
                with Container(id="collector-panel"):
                    yield Label("Collector Control", classes="collector-title")
                    with Horizontal():
                        with Vertical():
                            yield Label("Label:", classes="sb-label")
                            yield Select([("0 - normal", 0), ("1 - anomaly", 1)],
                                         id="sel-label", value=0)
                        with Vertical():
                            yield Label("Min latency us:", classes="sb-label")
                            yield Input(value="0", id="inp-min-lat", classes="sb-input")
                        with Vertical():
                            yield Label("Sample rate 1/N:", classes="sb-label")
                            yield Input(value="1", id="inp-sample-rate", classes="sb-input")
                    yield Checkbox("Monitor all processes (PID=0)", value=False, id="cb-all-procs")
                    yield Label("Command:", classes="sb-label")
                    yield Label("(select a process first)", id="lbl-cmd-preview",
                                classes="cmd-display")
                    yield Checkbox("Reset CSV before start", value=False, id="cb-reset-csv")
                    with Horizontal():
                        yield Button("Start Collector", id="btn-start")
                        yield Button("Stop  Collector", id="btn-stop")
                    yield Label("No collector running.", id="lbl-collector-status",
                                classes="status-stopped")

                # Tabs
                with TabbedContent():
                    with TabPane("Summary", id="tab-summary"):
                        yield Label("Top Processes by P99 Latency", classes="section-title")
                        yield DataTable(id="tbl-summary", zebra_stripes=True, cursor_type="row")

                    with TabPane("Timeline", id="tab-timeline"):
                        yield Label("Latency Timeline", classes="section-title")
                        with Container(classes="chart-box"):
                            yield Static("Select a process.", id="chart-timeline")

                    with TabPane("Histogram", id="tab-histogram"):
                        yield Label("Latency Distribution", classes="section-title")
                        with Container(classes="chart-box"):
                            yield Static("Select a process.", id="chart-histogram")

                    with TabPane("CPU and Priority", id="tab-cpu"):
                        yield Label("Per-CPU Event Count", classes="section-title")
                        with Container(classes="chart-box"):
                            yield Static("Select a process.", id="chart-cpu")
                        yield Label("Priority Distribution", classes="section-title")
                        with Container(classes="chart-box"):
                            yield Static("Select a process.", id="chart-prio")

                    with TabPane("Recent Events", id="tab-events"):
                        yield Label("Recent Events (last 200)", classes="section-title")
                        yield DataTable(id="tbl-events", zebra_stripes=True, cursor_type="row")

                    # ── COMPARE TAB ──────────────────────────────────────────
                    with TabPane("Compare", id="tab-compare"):
                        with Container(id="cmp-header"):
                            yield Label("Live Side-by-Side Process Comparison",
                                        classes="cmp-section-title")
                            yield Label(
                                "Each column has its own independent collector process.\n"
                                "Both run simultaneously — no need to stop one to start the other.\n"
                                "Filter + select a process, configure params, press Start.",
                                classes="sb-label",
                            )

                        with Horizontal(id="cmp-grid"):
                            # ── Column A ──────────────────────────────────────
                            with ScrollableContainer(classes="cmp-col-a"):
                                yield Label("Process A  (red border)", classes="cmp-head-a")

                                yield Label("Filter:", classes="sb-label")
                                yield Input(value="", id="inp-cmp-filter-a",
                                            placeholder="name or PID...", classes="cmp-input")
                                yield OptionList(id="cmp-opt-a", classes="cmp-opt-list")
                                yield Label("Selected A:", classes="sb-label")
                                yield Label("(none)", id="lbl-cmp-sel-a", classes="cmp-status-a")

                                yield Label("Label:", classes="sb-label")
                                yield Select([("0 - normal", 0), ("1 - anomaly", 1)],
                                             id="cmp-sel-label-a", value=0)
                                yield Label("Min latency us:", classes="sb-label")
                                yield Input(value="0", id="cmp-inp-min-a", classes="cmp-input")
                                yield Label("Sample rate 1/N:", classes="sb-label")
                                yield Input(value="1", id="cmp-inp-rate-a", classes="cmp-input")

                                with Horizontal():
                                    yield Button("Start A", id="btn-cmp-start-a")
                                    yield Button("Stop A",  id="btn-cmp-stop-a")
                                yield Label("Collector A: stopped",
                                            id="lbl-cmp-status-a", classes="cmp-status-a")

                                yield Label("Timeline A:", classes="sb-label")
                                with Container(classes="cmp-chart-box-a"):
                                    yield Static("(start collector A)", id="cmp-tl-a",
                                                 classes="cmp-chart-a")
                                yield Label("Histogram A:", classes="sb-label")
                                with Container(classes="cmp-chart-box-a"):
                                    yield Static("(start collector A)", id="cmp-hist-a",
                                                 classes="cmp-chart-a")
                                yield Label("CPU distribution A:", classes="sb-label")
                                with Container(classes="cmp-chart-box-a"):
                                    yield Static("(start collector A)", id="cmp-cpu-a",
                                                 classes="cmp-chart-a")

                            # ── Column B ──────────────────────────────────────
                            with ScrollableContainer(classes="cmp-col-b"):
                                yield Label("Process B  (green border)", classes="cmp-head-b")

                                yield Label("Filter:", classes="sb-label")
                                yield Input(value="", id="inp-cmp-filter-b",
                                            placeholder="name or PID...", classes="cmp-input")
                                yield OptionList(id="cmp-opt-b", classes="cmp-opt-list")
                                yield Label("Selected B:", classes="sb-label")
                                yield Label("(none)", id="lbl-cmp-sel-b", classes="cmp-status-b")

                                yield Label("Label:", classes="sb-label")
                                yield Select([("0 - normal", 0), ("1 - anomaly", 1)],
                                             id="cmp-sel-label-b", value=0)
                                yield Label("Min latency us:", classes="sb-label")
                                yield Input(value="0", id="cmp-inp-min-b", classes="cmp-input")
                                yield Label("Sample rate 1/N:", classes="sb-label")
                                yield Input(value="1", id="cmp-inp-rate-b", classes="cmp-input")

                                with Horizontal():
                                    yield Button("Start B", id="btn-cmp-start-b")
                                    yield Button("Stop B",  id="btn-cmp-stop-b")
                                yield Label("Collector B: stopped",
                                            id="lbl-cmp-status-b", classes="cmp-status-b")

                                yield Label("Timeline B:", classes="sb-label")
                                with Container(classes="cmp-chart-box-b"):
                                    yield Static("(start collector B)", id="cmp-tl-b",
                                                 classes="cmp-chart-b")
                                yield Label("Histogram B:", classes="sb-label")
                                with Container(classes="cmp-chart-box-b"):
                                    yield Static("(start collector B)", id="cmp-hist-b",
                                                 classes="cmp-chart-b")
                                yield Label("CPU distribution B:", classes="sb-label")
                                with Container(classes="cmp-chart-box-b"):
                                    yield Static("(start collector B)", id="cmp-cpu-b",
                                                 classes="cmp-chart-b")

                        # Stats diff table
                        with Container(id="cmp-diff-section"):
                            yield Label("Stats Comparison  (A vs B)", classes="cmp-section-title")
                            yield DataTable(id="cmp-diff-table", zebra_stripes=True,
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

    def _init_tables(self) -> None:
        t = self.query_one("#tbl-summary", DataTable)
        t.add_columns("TGID","comm","events","avg us","p50 us","p95 us","p99 us","max us",
                      "running","status")
        e = self.query_one("#tbl-events", DataTable)
        e.add_columns("timestamp_ns","ts_s","tgid","pid","comm","cpu","prio","latency us","label")
        c = self.query_one("#cmp-diff-table", DataTable)
        c.add_columns("Metric","Process A","Process B","Diff A-B","Winner")

    # ── full refresh ───────────────────────────────────────────────────────────
    def _do_refresh(self) -> None:
        self._load_data()
        self._refresh_metrics()
        self._refresh_summary_table()
        self._refresh_proc_list()
        self._refresh_cmp_option_lists()
        self._refresh_analysis()
        self._refresh_cmp_charts()
        self._refresh_cmd_preview()
        self._refresh_all_collector_status()
        self._refresh_log()

    # ── data loading ───────────────────────────────────────────────────────────
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

        def _empty_events_df() -> pd.DataFrame:
            return pd.DataFrame(columns=[
                "timestamp_ns", "pid", "tgid", "comm", "cpu_id",
                "priority", "latency_us", "label", "timestamp_s",
            ])

        def _load_slot_df(path: str) -> pd.DataFrame:
            if os.path.exists(path):
                return load_ebpf_events(path, max_rows=self._max_rows())
            return _empty_events_df()

        main_path = self._events_path()
        self._events_df_main = _load_slot_df(main_path)
        self._events_df_cmp_a = _load_slot_df(CMP_A_EVENTS_FILE)
        self._events_df_cmp_b = _load_slot_df(CMP_B_EVENTS_FILE)

        self._summary_df = summarize_latency(self._events_df_main)
        if not self._summary_df.empty:
            self._summary_df = self._summary_df[
                ~self._summary_df.apply(
                    lambda r: is_system_process(int(r["tgid"]), str(r["comm"])), axis=1)
            ].reset_index(drop=True)
        # Update alive state from OS
        for slot in (self._slot_main, self._slot_cmp_a, self._slot_cmp_b):
            if slot.pid and not is_pid_alive(slot.pid):
                slot.pid = 0

    # ── metrics ────────────────────────────────────────────────────────────────
    def _refresh_metrics(self) -> None:
        running_pids = (set(self._running_df["pid"].tolist())
                        if not self._running_df.empty else set())
        rwd = (int(self._summary_df["tgid"].isin(running_pids).sum())
               if not self._summary_df.empty else 0)
        n_alive = sum(1 for s in (self._slot_main, self._slot_cmp_a, self._slot_cmp_b) if s.alive)
        vals = [
            str(len(self._events_df_main)),
            str(self._summary_df["tgid"].nunique() if not self._summary_df.empty else 0),
            str(rwd),
            f"{n_alive} running" if n_alive else "0 running",
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
            tbl.add_row(str(row.tgid), row.comm, str(row.events),
                        f"{row.avg_us:.1f}", f"{row.p50_us:.1f}",
                        f"{row.p95_us:.1f}", f"{row.p99_us:.1f}", f"{row.max_us:.1f}",
                        "Y" if row.tgid in running_pids else "N",
                        status_map.get(row.tgid, "-"))

    # ── main process picker ────────────────────────────────────────────────────
    def _refresh_proc_list(self, ft: str = "") -> None:
        ol = self.query_one("#proc-option-list", OptionList)
        ol.clear_options()
        ft = ft.strip().lower()
        if not self._running_df.empty:
            for row in self._running_df.itertuples():
                lbl = f"{row.name}  (PID {row.pid})"
                if ft and ft not in row.name.lower() and ft not in str(row.pid):
                    continue
                ol.add_option(Option(lbl, id=f"pid-{row.pid}"))

    @on(Input.Changed, "#inp-proc-filter")
    def _on_filter(self, ev: Input.Changed) -> None:
        self._refresh_proc_list(ft=ev.value)

    @on(OptionList.OptionSelected, "#proc-option-list")
    def _on_proc_sel(self, ev: OptionList.OptionSelected) -> None:
        oid = ev.option_id or ""
        if oid.startswith("pid-"):
            try:
                self._set_selected_pid(int(oid[4:]))
            except ValueError:
                pass

    def _set_selected_pid(self, pid: int) -> None:
        self._selected_pid = pid
        try:
            self.query_one("#selected-pid-display", Label).update(
                f"PID {pid}  -  {self._name_of(pid)}")
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

    # ── compare option lists ───────────────────────────────────────────────────
    def _refresh_cmp_option_lists(self, fa: str = "", fb: str = "") -> None:
        for ol_id, ft_raw, prefix in (
            ("#cmp-opt-a", fa, "cmpa"),
            ("#cmp-opt-b", fb, "cmpb"),
        ):
            try:
                ol = self.query_one(ol_id, OptionList)
            except NoMatches:
                continue
            ol.clear_options()
            ft = ft_raw.strip().lower()
            if self._running_df.empty:
                continue
            for row in self._running_df.itertuples():
                lbl = f"{row.name}  (PID {row.pid})"
                if ft and ft not in row.name.lower() and ft not in str(row.pid):
                    continue
                ol.add_option(Option(lbl, id=f"{prefix}-{row.pid}"))

    @on(Input.Changed, "#inp-cmp-filter-a")
    def _on_cmp_fa(self, ev: Input.Changed) -> None:
        try:
            fb = self.query_one("#inp-cmp-filter-b", Input).value
        except NoMatches:
            fb = ""
        self._refresh_cmp_option_lists(fa=ev.value, fb=fb)

    @on(Input.Changed, "#inp-cmp-filter-b")
    def _on_cmp_fb(self, ev: Input.Changed) -> None:
        try:
            fa = self.query_one("#inp-cmp-filter-a", Input).value
        except NoMatches:
            fa = ""
        self._refresh_cmp_option_lists(fa=fa, fb=ev.value)

    @on(OptionList.OptionSelected, "#cmp-opt-a")
    def _on_cmp_sel_a(self, ev: OptionList.OptionSelected) -> None:
        oid = ev.option_id or ""
        if oid.startswith("cmpa-"):
            try:
                self._cmp_pid_a = int(oid[5:])
                self._update_cmp_sel_label("a")
            except ValueError:
                pass

    @on(OptionList.OptionSelected, "#cmp-opt-b")
    def _on_cmp_sel_b(self, ev: OptionList.OptionSelected) -> None:
        oid = ev.option_id or ""
        if oid.startswith("cmpb-"):
            try:
                self._cmp_pid_b = int(oid[5:])
                self._update_cmp_sel_label("b")
            except ValueError:
                pass

    def _update_cmp_sel_label(self, side: str) -> None:
        pid    = self._cmp_pid_a if side == "a" else self._cmp_pid_b
        lbl_id = "#lbl-cmp-sel-a" if side == "a" else "#lbl-cmp-sel-b"
        if pid is None:
            return
        try:
            self.query_one(lbl_id, Label).update(f"PID {pid}  -  {self._name_of(pid)}")
        except NoMatches:
            pass

    # ── compare collector buttons ─────────────────────────────────────────────
    @on(Button.Pressed, "#btn-cmp-start-a")
    def _on_cmp_start_a(self) -> None:
        self._start_cmp("a")

    @on(Button.Pressed, "#btn-cmp-stop-a")
    def _on_cmp_stop_a(self) -> None:
        msg = self._slot_cmp_a.stop()
        self._refresh_all_collector_status()
        self.push_screen(InfoModal("Collector A", msg))

    @on(Button.Pressed, "#btn-cmp-start-b")
    def _on_cmp_start_b(self) -> None:
        self._start_cmp("b")

    @on(Button.Pressed, "#btn-cmp-stop-b")
    def _on_cmp_stop_b(self) -> None:
        msg = self._slot_cmp_b.stop()
        self._refresh_all_collector_status()
        self.push_screen(InfoModal("Collector B", msg))

    def _start_cmp(self, side: str) -> None:
        pid  = self._cmp_pid_a  if side == "a" else self._cmp_pid_b
        slot = self._slot_cmp_a if side == "a" else self._slot_cmp_b

        if pid is None:
            self.push_screen(InfoModal(
                f"No Process Selected",
                f"Filter the list and select Process {side.upper()} first."))
            return
        if slot.alive:
            self.push_screen(InfoModal(
                f"Already Running",
                f"Collector {side.upper()} is already running (PID {slot.pid}).\n"
                "Press Stop first if you want to change the target."))
            return

        try:
            lv = int(self.query_one(f"#cmp-sel-label-{side}", Select).value or 0)
            ml = int(self.query_one(f"#cmp-inp-min-{side}",   Input).value  or "0")
            sr = int(self.query_one(f"#cmp-inp-rate-{side}",  Input).value  or "1")
        except (NoMatches, ValueError):
            lv, ml, sr = 0, 0, 1

        events_csv = CMP_A_EVENTS_FILE if side == "a" else CMP_B_EVENTS_FILE
        ok, msg = slot.launch(lv, pid, ml, sr, events_csv)
        self._refresh_all_collector_status()
        self.push_screen(InfoModal(f"Collector {side.upper()} " + ("Started" if ok else "Error"), msg))

    # ── compare charts refresh ────────────────────────────────────────────────
    def _refresh_cmp_charts(self) -> None:
        self._render_cmp_col("a", self._cmp_pid_a, self._slot_cmp_a)
        self._render_cmp_col("b", self._cmp_pid_b, self._slot_cmp_b)
        self._render_diff_table()

    def _render_cmp_col(self, side: str, pid: Optional[int], slot: CollectorSlot) -> None:
        tl_id   = f"#cmp-tl-{side}"
        hist_id = f"#cmp-hist-{side}"
        cpu_id  = f"#cmp-cpu-{side}"

        if pid is None:
            msg = f"Filter and select Process {side.upper()}, then press Start {side.upper()}."
            for wid in (tl_id, hist_id, cpu_id):
                self._set_static(wid, msg)
            return

        events_df = self._events_df_cmp_a if side == "a" else self._events_df_cmp_b
        df = (events_df[events_df["tgid"] == pid].copy()
              if not events_df.empty else pd.DataFrame())

        if df.empty:
            if slot.alive:
                msg = (f"Collector {side.upper()} is running for PID {pid}.\n"
                       "Waiting for first events — press R in a few seconds.")
            else:
                msg = (f"No eBPF data for PID {pid}.\n"
                       f"Press 'Start {side.upper()}' to begin collection.")
            for wid in (tl_id, hist_id, cpu_id):
                self._set_static(wid, msg)
            return

        df  = df.sort_values("timestamp_s")
        lat = df["latency_us"].to_numpy(dtype=float)
        comm = str(df["comm"].iloc[-1])

        tl_text = (
            f"PID {pid}  comm={comm}  events={len(lat):,}\n"
            f"min={lat.min():.1f}  avg={np.mean(lat):.1f}  "
            f"p99={np.percentile(lat,99):.1f}  max={lat.max():.1f}  (all us)\n\n"
            + sparkline_axes(lat.tolist(), width=50, height=8)
            + f"\nSpikes (!=p95, ^=p99):\n        |{spike_markers(lat.tolist(), width=50)}"
        )
        self._set_static(tl_id, tl_text)
        self._set_static(hist_id, ascii_histogram(lat, bins=14, bar_width=30))
        cpu = df["cpu_id"].value_counts().sort_index()
        self._set_static(cpu_id, ascii_bar([f"CPU {k}" for k in cpu.index],
                                            cpu.values.tolist(), bar_width=28))

    def _render_diff_table(self) -> None:
        tbl = self.query_one("#cmp-diff-table", DataTable)
        tbl.clear()

        def stats(pid: Optional[int], events_df: pd.DataFrame) -> dict:
            if pid is None or events_df.empty:
                return {}
            df = events_df[events_df["tgid"] == pid]
            if df.empty:
                return {}
            lat = df["latency_us"].to_numpy(dtype=float)
            return {"samples": len(lat), "avg": np.mean(lat),
                    "p50": np.percentile(lat, 50), "p95": np.percentile(lat, 95),
                    "p99": np.percentile(lat, 99), "max": np.max(lat),
                    "min": np.min(lat), "stddev": np.std(lat)}

        sa = stats(self._cmp_pid_a, self._events_df_cmp_a)
        sb = stats(self._cmp_pid_b, self._events_df_cmp_b)

        for key, label in [("samples","Samples"),("avg","Avg us"),("p50","P50 us"),
                            ("p95","P95 us"),("p99","P99 us"),("max","Max us"),
                            ("min","Min us"),("stddev","Stddev us")]:
            va = sa.get(key)
            vb = sb.get(key)
            lower_better = key != "samples"
            va_s = (f"{va:,.1f}" if isinstance(va, float) else str(va)) if va is not None else "-"
            vb_s = (f"{vb:,.1f}" if isinstance(vb, float) else str(vb)) if vb is not None else "-"
            if va is not None and vb is not None:
                diff = va - vb
                diff_s = f"{diff:+.1f}"
                winner = ("A" if (va < vb if lower_better else va > vb)
                          else "B" if (vb < va if lower_better else vb > va)
                          else "tie")
            else:
                diff_s, winner = "-", "-"
            tbl.add_row(label, va_s, vb_s, diff_s, winner)

    def _set_static(self, wid_id: str, text: str) -> None:
        try:
            self.query_one(wid_id, Static).update(text)
        except NoMatches:
            pass

    # ── main tab analysis ──────────────────────────────────────────────────────
    def _refresh_analysis(self) -> None:
        pid = self._selected_pid
        if pid is None:
            return
        df = (self._events_df_main[self._events_df_main["tgid"] == pid].copy()
              if not self._events_df_main.empty else pd.DataFrame())
        no_data = (f"No eBPF data for PID {pid}.\n"
                   "Start the collector then press R to refresh.")
        if df.empty:
            for wid in ("#chart-timeline","#chart-histogram","#chart-cpu","#chart-prio"):
                self._set_static(wid, no_data)
            try:
                self.query_one("#tbl-events", DataTable).clear()
            except NoMatches:
                pass
            return

        df  = df.sort_values("timestamp_s")
        lat = df["latency_us"].to_numpy(dtype=float)

        tl = (f"PID {pid}  |  {len(lat):,} samples\n"
              f"min={lat.min():.1f}  avg={np.mean(lat):.1f}  "
              f"p99={np.percentile(lat,99):.1f}  max={lat.max():.1f}  (us)\n\n"
              + sparkline_axes(lat.tolist(), width=60, height=10)
              + f"\nSpikes (!=p95, ^=p99): {spike_markers(lat.tolist(), width=60)}\n\n"
              + ascii_timeline(lat, height=8, width=60))
        self._set_static("#chart-timeline",  tl)
        self._set_static("#chart-histogram", ascii_histogram(lat, bins=20, bar_width=44))
        cpu = df["cpu_id"].value_counts().sort_index()
        self._set_static("#chart-cpu", ascii_bar(
            [f"CPU {k}" for k in cpu.index], cpu.values.tolist(),
            bar_width=40, title="Per-CPU events"))
        prio = df["priority"].value_counts().sort_index()
        self._set_static("#chart-prio", ascii_bar(
            [f"Prio {k}" for k in prio.index], prio.values.tolist(),
            bar_width=40, title="Priority distribution"))

        etbl = self.query_one("#tbl-events", DataTable)
        etbl.clear()
        for row in df.tail(200).itertuples():
            etbl.add_row(str(row.timestamp_ns), f"{row.timestamp_s:.3f}",
                         str(row.tgid), str(row.pid), str(row.comm),
                         str(row.cpu_id), str(row.priority),
                         f"{row.latency_us:.2f}", str(row.label))

    # ── main collector control ─────────────────────────────────────────────────
    def _refresh_cmd_preview(self) -> None:
        try:
            lv       = self.query_one("#sel-label",    Select).value or 0
            ml       = self.query_one("#inp-min-lat",  Input).value  or "0"
            sr       = self.query_one("#inp-sample-rate", Input).value or "1"
            all_mode = self.query_one("#cb-all-procs", Checkbox).value
            target   = 0 if all_mode else (self._selected_pid or 0)
            if target == 0 and not all_mode:
                self.query_one("#lbl-cmd-preview", Label).update("(select a process first)")
                return
            self.query_one("#lbl-cmd-preview", Label).update(
                f"sudo ./collector {lv} {target} {ml} {sr}")
        except NoMatches:
            pass

    def _refresh_all_collector_status(self) -> None:
        # Main slot
        self._refresh_slot_label(self._slot_main,
                                 "#lbl-collector-status", "#sb-collector-pid")
        # Compare A
        self._refresh_cmp_slot_label(self._slot_cmp_a, "a")
        # Compare B
        self._refresh_cmp_slot_label(self._slot_cmp_b, "b")

    def _refresh_slot_label(self, slot: CollectorSlot,
                             status_id: str, sidebar_id: str) -> None:
        alive = slot.alive
        try:
            w = self.query_one(status_id, Label)
            w.update(f"Running - PID {slot.pid}" if alive else "No collector running.")
            w.remove_class("status-stopped" if alive else "status-running")
            w.add_class("status-running"   if alive else "status-stopped")
        except NoMatches:
            pass
        try:
            s = self.query_one(sidebar_id, Label)
            s.update(str(slot.pid) if alive else "none")
            s.remove_class("status-stopped" if alive else "status-running")
            s.add_class("status-running"   if alive else "status-stopped")
        except NoMatches:
            pass

    def _refresh_cmp_slot_label(self, slot: CollectorSlot, side: str) -> None:
        alive = slot.alive
        lbl_id    = f"#lbl-cmp-status-{side}"
        sidebar_id = f"#sb-cmp-{side}-pid"
        try:
            w = self.query_one(lbl_id, Label)
            if alive:
                w.update(f"Running  PID {slot.pid}  "
                         f"target={slot.target_pid} ({self._name_of(slot.target_pid)})")
            else:
                w.update(f"Collector {side.upper()}: stopped")
        except NoMatches:
            pass
        try:
            s = self.query_one(sidebar_id, Label)
            s.update(str(slot.pid) if alive else "none")
        except NoMatches:
            pass

    @on(Button.Pressed, "#btn-start")
    def _on_start(self) -> None:
        self.action_start_collector()

    def action_start_collector(self) -> None:
        try:
            all_mode = self.query_one("#cb-all-procs", Checkbox).value
        except NoMatches:
            all_mode = False
        if self._selected_pid is None and not all_mode:
            self.push_screen(InfoModal("No Process", "Select a process first."))
            return
        try:
            lv = int(self.query_one("#sel-label",       Select).value or 0)
            ml = int(self.query_one("#inp-min-lat",      Input).value  or "0")
            sr = int(self.query_one("#inp-sample-rate",  Input).value  or "1")
        except (NoMatches, ValueError):
            lv, ml, sr = 0, 0, 1
        try:
            reset = self.query_one("#cb-reset-csv", Checkbox).value
        except NoMatches:
            reset = False
        if reset:
            for p in [MAIN_EVENTS_FILE,
                      CMP_A_EVENTS_FILE,
                      CMP_B_EVENTS_FILE,
                      os.path.join(BASE_DIR, "ebpf_events.csv"),
                      os.path.join(BASE_DIR, "ebpf_logs", "ebpf_events.csv"),
                      os.path.join(BASE_DIR, "dataset.csv")]:
                try:
                    os.remove(p)
                except FileNotFoundError:
                    pass
        if self._slot_main.alive:
            self._slot_main.stop()
            time.sleep(0.25)
        target = 0 if all_mode else int(self._selected_pid or 0)
        ok, msg = self._slot_main.launch(lv, target, ml, sr, self._events_path())
        self._refresh_all_collector_status()
        self.push_screen(InfoModal("Collector " + ("Started" if ok else "Error"), msg))

    @on(Button.Pressed, "#btn-stop")
    def _on_stop(self) -> None:
        self.action_stop_collector_action()

    def action_stop_collector_action(self) -> None:
        if not self._slot_main.alive:
            self.push_screen(InfoModal("Not Running", "No main collector is running."))
            return
        msg = self._slot_main.stop()
        self._refresh_all_collector_status()
        self.push_screen(InfoModal("Collector", msg))

    # ── param change listeners ─────────────────────────────────────────────────
    @on(Input.Changed,    "#inp-min-lat")
    @on(Input.Changed,    "#inp-sample-rate")
    @on(Select.Changed,   "#sel-label")
    @on(Checkbox.Changed, "#cb-all-procs")
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
        self._refresh_cmp_option_lists()

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
        try:
            log = self.query_one("#collector-log", Log)
            log.clear()
            log.write(tail if tail else "(no log output yet)")
        except NoMatches:
            pass

    # ── helpers ────────────────────────────────────────────────────────────────
    def _name_of(self, pid: Optional[int]) -> str:
        if pid is None or self._running_df.empty:
            return "-"
        m = self._running_df[self._running_df["pid"] == pid]
        return str(m.iloc[0]["name"]) if not m.empty else str(pid)

    # ── help ───────────────────────────────────────────────────────────────────
    def action_show_help(self) -> None:
        self.push_screen(InfoModal("Help", (
            "Keys\n"
            "----\n"
            "R         Refresh data\n"
            "Ctrl+S    Start main collector\n"
            "Ctrl+X    Stop  main collector\n"
            "F1        This help\n"
            "Q         Quit\n\n"
            "Main tab workflow\n"
            "-----------------\n"
            "1. Filter + select a process in the picker.\n"
            "2. Set label / min-latency / sample-rate.\n"
            "3. Start Collector (needs sudo or cap_bpf).\n"
            "4. Press R or wait for auto-refresh.\n\n"
            "Compare tab workflow\n"
            "--------------------\n"
            "1. Open the Compare tab.\n"
            "2. Column A: filter, pick process, Start A.\n"
            "3. Column B: filter, pick process, Start B.\n"
            "   Both collectors run SIMULTANEOUSLY.\n"
            "   No stopping needed to start the second one.\n"
            "4. Press R — charts + diff table update live.\n\n"
            "Events file locations:\n"
            f"  Main: {MAIN_EVENTS_FILE}\n"
            f"  Compare A: {CMP_A_EVENTS_FILE}\n"
            f"  Compare B: {CMP_B_EVENTS_FILE}"
        )))


# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    LatencyDashboard().run()

