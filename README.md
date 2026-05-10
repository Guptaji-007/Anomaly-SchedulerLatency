# Anomaly-SchedulerLatency

A kernel-level performance profiling project that uses **eBPF (Extended Berkeley Packet Filter)** to measure and analyze CPU scheduler latency anomalies.

## Getting Started


### 1. Prerequisites and Installation

Run the automated setup script to install all required dependencies (toolchain, eBPF libraries, Python packages):

```bash
sudo ./setup.sh
```

**What this does:**
- Automatically detects your OS (Ubuntu/Debian via `apt` or Fedora/RedHat via `dnf`).
- Installs `clang`, `llvm`, `bpftool`, `libbpf`, Linux kernel headers, and build tools natively for your distribution.
- Automatically creates a local Python `venv` and installs required dependencies (`numpy`, `pandas`, `textual`, `rich`) avoiding system package conflicts.

### 2. Compilation

Run the build script to compile all workloads, generate BPF skeletons, and build the user-space eBPF programs:

```bash
./build.sh
```

**What this does:**
- Compiles all C files in `/workload/` into testing executables.
- Generates `vmlinux.h` from your currently running kernel.
- Compiles `sl.bpf.c` and builds the user-space orchestrator.

### 3. Execution

Because eBPF interacts with the kernel, running the project **requires `sudo` privileges**. The interactive Terminal UI (TUI) handles everything internally, including automatically starting and stopping the eBPF background processes for you.

To launch the real-time latency anomaly dashboard, run:

```bash
cd ebpf_logs
sudo ../venv/bin/python3 tui.py
```

### (Optional) Run Sample Workloads

The `workload/` directory contains sample C programs configured to generate specific types of system contention (CPU bottlenecks, I/O wait, etc.). To test the scheduler tracing, open a **second terminal** and run one of the workloads:

```bash
cd workload
./3_heavy_contention
# Or try ./1_baseline, ./4_disk_io, ./8_context_switching, etc.
```

## Troubleshooting

- **`bpftool` not found**: Ensure `linux-tools-common` and `linux-tools-generic` are installed. If you still face issues, install `linux-tools-$(uname -r)`.
- **`vmlinux` BTF not found**: If `./build.sh` fails on generating `vmlinux.h`, ensure your kernel was compiled with `CONFIG_DEBUG_INFO_BTF=y`.
- **Permission Denied**: Attaching BPF programs requires elevated privileges. Make sure you run `tui.py` with `sudo`.
