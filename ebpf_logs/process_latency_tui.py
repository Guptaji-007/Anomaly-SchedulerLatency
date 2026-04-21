import os
import signal
import subprocess
from collections import deque
from io import StringIO

import pandas as pd

try:
    import psutil
except ImportError:
    psutil = None

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, DataTable, Footer, Header, Input, Static


BASE_DIR = os.path.dirname(__file__)
COLLECTOR_BIN = os.path.join(BASE_DIR, "collector")
EVENTS_DEFAULT = os.path.join(BASE_DIR, "ebpf_events.csv")
COLLECTOR_LOG = os.path.join(BASE_DIR, "collector_tui.log")


def is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def read_log_tail(path: str, max_lines: int = 20) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return "".join(deque(f, maxlen=max_lines)).strip()
    except OSError:
        return ""


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
            rows.append(
                {
                    "pid": int(parts[0]),
                    "name": parts[1],
                    "status": parts[2] if len(parts) > 2 else "unknown",
                }
            )

    if not rows:
        return pd.DataFrame(columns=["pid", "name", "status"])
    df = pd.DataFrame(rows).drop_duplicates(subset=["pid"], keep="last")
    return df.sort_values(by=["name", "pid"]).reset_index(drop=True)


def load_ebpf_events(path: str, max_rows: int = 30000) -> pd.DataFrame:
    required = ["timestamp_ns", "pid", "tgid", "comm", "cpu_id", "priority", "latency_us", "label"]
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            header = f.readline().strip()
            tail_lines = list(deque(f, maxlen=max_rows))
        if not header:
            return pd.DataFrame(columns=required + ["timestamp_s"])
        blob = header + "\n" + "".join(tail_lines)
        df = pd.read_csv(StringIO(blob))
    except Exception:
        return pd.DataFrame(columns=required + ["timestamp_s"])

    missing = [c for c in required if c not in df.columns]
    if missing:
        return pd.DataFrame(columns=required + ["timestamp_s"])

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


class ProcessLatencyTUI(App):
    CSS = """
    Screen {
        layout: vertical;
    }

    #main {
        height: 1fr;
    }

    #left, #right {
        width: 1fr;
        height: 1fr;
        padding: 1;
    }

    #status {
        height: 3;
        border: solid green;
        padding: 0 1;
    }

    .section-title {
        text-style: bold;
        margin-top: 1;
    }

    DataTable {
        height: 1fr;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh_all", "Refresh"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.selected_pid: int | None = None
        self.collector_pid: int = 0
        self.events_path: str = EVENTS_DEFAULT

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("Ready", id="status")

        with Horizontal(id="main"):
            with Vertical(id="left"):
                yield Static("Controls", classes="section-title")
                yield Input(value=self.events_path, id="events_path", placeholder="Events CSV path")
                yield Input(value="0", id="label", placeholder="Label (0/1)")
                yield Input(value="0", id="min_latency", placeholder="Min latency us")
                yield Input(value="1", id="sample_rate", placeholder="Sample rate 1/N")
                yield Input(value="", id="manual_pid", placeholder="Manual PID override (optional)")
                yield Button("Refresh", id="refresh")
                yield Button("Start targeted collector", id="start")
                yield Button("Stop collector", id="stop")

                yield Static("Running Processes", classes="section-title")
                yield DataTable(id="process_table")

            with Vertical(id="right"):
                yield Static("Selected PID Analytics", classes="section-title")
                yield Static("No PID selected.", id="metrics")
                yield Static("Recent Events", classes="section-title")
                yield DataTable(id="event_table")

        yield Footer()

    def on_mount(self) -> None:
        process_table = self.query_one("#process_table", DataTable)
        process_table.add_columns("PID", "Name", "Status")

        event_table = self.query_one("#event_table", DataTable)
        event_table.add_columns("ts_ns", "tgid", "pid", "comm", "cpu", "prio", "lat_us", "label")

        self.set_interval(2.0, self.refresh_all)
        self.refresh_all()

    def set_status(self, text: str) -> None:
        self.query_one("#status", Static).update(text)

    def get_int_input(self, widget_id: str, default: int) -> int:
        raw = self.query_one(f"#{widget_id}", Input).value.strip()
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            return default

    def refresh_process_table(self, df: pd.DataFrame) -> None:
        table = self.query_one("#process_table", DataTable)
        table.clear(columns=False)
        for row in df.head(300).itertuples():
            table.add_row(str(row.pid), row.name, row.status, key=str(int(row.pid)))

    def refresh_event_table(self, df: pd.DataFrame) -> None:
        table = self.query_one("#event_table", DataTable)
        table.clear(columns=False)
        for row in df.tail(120).itertuples():
            table.add_row(
                str(int(row.timestamp_ns)),
                str(int(row.tgid)),
                str(int(row.pid)),
                str(row.comm),
                str(int(row.cpu_id)),
                str(int(row.priority)),
                f"{float(row.latency_us):.2f}",
                str(int(row.label)),
            )

    def refresh_metrics(self, proc_df: pd.DataFrame) -> None:
        metrics = self.query_one("#metrics", Static)
        if self.selected_pid is None:
            metrics.update("No PID selected.")
            return
        if proc_df.empty:
            metrics.update(f"PID {self.selected_pid}: no samples yet.")
            return

        lat = proc_df["latency_us"]
        p95 = float(lat.quantile(0.95))
        p99 = float(lat.quantile(0.99))
        txt = (
            f"PID {self.selected_pid} | samples={len(lat)} | "
            f"avg={float(lat.mean()):.2f} us | p95={p95:.2f} us | "
            f"p99={p99:.2f} us | max={float(lat.max()):.2f} us"
        )
        metrics.update(txt)

    def start_collector(self) -> None:
        if self.selected_pid is None:
            self.set_status("Select a PID first from process table or manual PID input.")
            return
        if self.collector_pid and is_pid_alive(self.collector_pid):
            self.set_status(f"Collector already running with PID {self.collector_pid}.")
            return
        if not os.path.exists(COLLECTOR_BIN):
            self.set_status(f"collector binary not found: {COLLECTOR_BIN}")
            return

        label = self.get_int_input("label", 0)
        min_latency = self.get_int_input("min_latency", 0)
        sample_rate = max(1, self.get_int_input("sample_rate", 1))

        cmd = [COLLECTOR_BIN, str(label), str(self.selected_pid), str(min_latency), str(sample_rate)]
        with open(COLLECTOR_LOG, "a", encoding="utf-8") as log_fp:
            proc = subprocess.Popen(
                cmd,
                cwd=BASE_DIR,
                stdout=log_fp,
                stderr=log_fp,
                start_new_session=True,
            )

        self.collector_pid = proc.pid
        self.set_status(
            f"Started collector pid={proc.pid} for target pid={self.selected_pid}. "
            f"If no events appear, check permissions/caps."
        )

    def stop_collector(self) -> None:
        if not self.collector_pid or not is_pid_alive(self.collector_pid):
            self.collector_pid = 0
            self.set_status("No tracked collector is running.")
            return
        try:
            os.kill(self.collector_pid, signal.SIGINT)
            self.set_status(f"Sent SIGINT to collector pid={self.collector_pid}")
        except OSError as e:
            self.set_status(f"Failed to stop collector: {e}")

    def action_refresh_all(self) -> None:
        self.refresh_all()

    def refresh_all(self) -> None:
        self.events_path = self.query_one("#events_path", Input).value.strip() or EVENTS_DEFAULT

        manual_pid_raw = self.query_one("#manual_pid", Input).value.strip()
        if manual_pid_raw:
            try:
                self.selected_pid = int(manual_pid_raw)
            except ValueError:
                pass

        proc_df = list_running_processes()
        self.refresh_process_table(proc_df)

        if not os.path.exists(self.events_path):
            self.refresh_event_table(pd.DataFrame(columns=["timestamp_ns", "tgid", "pid", "comm", "cpu_id", "priority", "latency_us", "label"]))
            self.refresh_metrics(pd.DataFrame())
            tail = read_log_tail(COLLECTOR_LOG, max_lines=3)
            if tail:
                self.set_status(f"No events file yet. Recent collector log: {tail.splitlines()[-1]}")
            else:
                self.set_status("No events file yet. Select PID and start targeted collector.")
            return

        events_df = load_ebpf_events(self.events_path)
        if self.selected_pid is None:
            self.refresh_event_table(pd.DataFrame(columns=events_df.columns))
            self.refresh_metrics(pd.DataFrame())
            self.set_status("Events loaded. Select a PID to view analytics.")
            return

        selected_df = events_df[events_df["tgid"] == self.selected_pid].copy()
        self.refresh_event_table(selected_df)
        self.refresh_metrics(selected_df)

        if selected_df.empty:
            self.set_status(f"No samples yet for pid {self.selected_pid}. Collector may still be warming up.")
        else:
            self.set_status(f"Showing analytics for pid {self.selected_pid}. Events file: {self.events_path}")

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "process_table":
            return
        try:
            self.selected_pid = int(str(event.row_key.value))
            self.query_one("#manual_pid", Input).value = str(self.selected_pid)
            self.set_status(f"Selected pid {self.selected_pid}")
            self.refresh_all()
        except Exception:
            self.set_status("Failed to parse selected PID.")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "refresh":
            self.refresh_all()
        elif event.button.id == "start":
            self.start_collector()
            self.refresh_all()
        elif event.button.id == "stop":
            self.stop_collector()
            self.refresh_all()


if __name__ == "__main__":
    ProcessLatencyTUI().run()
