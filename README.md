# Anomaly-SchedulerLatency

A kernel-level performance profiling project that uses **eBPF (Extended Berkeley Packet Filter)** and **Linux perf** tracing to measure and analyze CPU scheduler latency anomalies in multithreaded workloads.

## Project Overview

This project investigates how the Linux kernel's CPU scheduler affects task execution latency. It measures the time delay between when a task becomes ready to run (enters the runqueue) and when it actually gets CPU time (context switch from idle/another task). By combining eBPF-based kernel monitoring with userspace analysis, the project identifies scheduler-induced latency anomalies across different workload scenarios.

### Key Objectives

- **Measure Scheduler Latency**: Track the time a task waits in the ready queue before executing
- **Identify Anomalies**: Detect unusual latency patterns caused by scheduler behavior
- **Compare Scenarios**: Analyze latency across different workload types and system contention levels
- **Kernel Instrumentation**: Use eBPF to efficiently capture scheduler events at the kernel level

## Project Structure

```
Anomaly-SchedulerLatency/
├── ebpf_logs/          # eBPF-based kernel monitoring
│   ├── collector.c     # User-space program to load and manage eBPF program
│   ├── sl.bpf.c        # Main eBPF program for scheduler latency monitoring
│   ├── slu.c           # Alternative eBPF implementation variant
│   ├── vmlinux.h       # Kernel type definitions (generated)
│   ├── ebpf_avg.py     # Python script to analyze eBPF latency output
│   └── workflow.txt    # High-level workflow diagram
│
├── workload/           # Workload generators for testing
│   ├── workload.c      # Basic multi-threaded workload
│   ├── baseline_latency.c    # Minimal system activity
│   ├── contended_latency.c   # Contended CPU resources
│   ├── disk.c          # Disk I/O heavy workload
│   ├── heavy_contention.c    # High contention scenario
│   ├── mixed.c         # Mixed workload (CPU + I/O)
│   ├── pipeio.c        # Pipe I/O workload
│   ├── yield.c         # Workload with yield behavior
│   └── workload        # Compiled binary
│
├── p_lat.py            # Main latency analysis script for perf data
├── perf_script.txt     # Sample perf output (scheduler events)
├── output.txt          # Analysis results
└── .gitignore          # Git ignore file
```

## Key Components

### 1. eBPF Kernel Module (`ebpf_logs/`)

#### `sl.bpf.c` - Main eBPF Program
The eBPF program instruments the Linux kernel's scheduler to capture latency events:

- **Monitors**: `sched:sched_wakeup` and `sched:sched_switch` tracepoints
- **Tracks**: 
  - When a task enters the runqueue (wakeup event)
  - When a task finally executes (context switch event)
- **Calculates**: Time difference between wakeup and execution as scheduler latency
- **Output**: Events via ring buffer in nanosecond precision

**Key Data Structures:**
```c
struct event {
    __u32 pid;           // Process ID
    __u64 latency_ns;    // Latency in nanoseconds
};
```

**Maps Used:**
- `target_tgid_map`: Filter to specific workload thread group ID
- `wait_map`: Track when each task entered the runqueue
- `events`: Ring buffer for outputting events to userspace

#### `collector.c` - User-Space Program
- Loads the eBPF program into the kernel
- Attaches to scheduler tracepoints
- Manages communication between kernel and user-space
- Reads events from ring buffer and logs them

### 2. Workload Generators (`workload/`)

Different workload scenarios to simulate various system conditions:

| Workload | Purpose | Characteristics |
|----------|---------|-----------------|
| `workload.c` | Basic multi-threading | 2 threads, CPU-bound work + sleep |
| `baseline_latency.c` | Minimal contention | Isolate base scheduler latency |
| `contended_latency.c` | Resource contention | Competing for same CPU |
| `disk.c` | I/O bound | Disk access patterns |
| `heavy_contention.c` | Severe contention | Maximum competing tasks |
| `mixed.c` | CPU + I/O | Mixed workload patterns |
| `pipeio.c` | Pipe I/O | Inter-process communication |
| `yield.c` | Yield behavior | Voluntary CPU yields |

### 3. Analysis Scripts

#### `p_lat.py` - Perf-Based Latency Analysis
Parses Linux `perf record` output (scheduler events):

- **Input**: `perf_script.txt` (raw perf trace data)
- **Parsing**: Extracts `sched:sched_wakeup` and `sched:sched_switch` events
- **Detection**:
  - **Preemption**: Task running state → waiting state
  - **Execution**: Task waiting state → running state
  - **Latency Calculation**: Time between wakeup and execution
- **Output**: Statistics and latency measurements to `output.txt`

**Key Metrics Tracked:**
- Latency per task (nanoseconds)
- Preemption events
- Scheduling decisions
- Context switch patterns

#### `ebpf_avg.py` - eBPF Latency Statistics
Aggregates eBPF-collected latency data:

- **Input**: `ebpf_latency.txt` (eBPF output)
- **Parsing**: Extracts latency values in microseconds
- **Calculations**: Mean, standard deviation, percentiles
- **Output**: Summary statistics

## How It Works

### Workflow

```
1. User launches workload generator
   ↓
2. Load eBPF program into kernel
   ↓
3. Attach to kernel's scheduler tracepoints
   ↓
4. Workload processes create threads
   ↓
5. Kernel traces scheduler events in real-time
   ↓
6. eBPF captures latency data via ring buffer
   ↓
7. User-space program receives events
   ↓
8. Python scripts analyze and aggregate data
   ↓
9. Results saved (output.txt, statistics)
```

### Latency Measurement Process

For each task execution cycle:

1. **Task Wakeup** (from sleep): Record timestamp T₁ when task becomes ready
2. **Context Switch**: Record timestamp T₂ when task gets CPU time
3. **Latency = T₂ - T₁**: Scheduler latency for that scheduling quantum
4. **Aggregate**: Collect statistics across all scheduling events

### Example Event Flow

```
T=1000μs  → sched:sched_wakeup (workload:3164 ready)
T=1005μs  → sched:sched_switch (workload:3164 running)
           → Scheduler Latency = 5μs

T=1010μs  → sched:sched_switch (workload:3164 → swapper/0:0, task yields)
T=1020μs  → sched:sched_wakeup (workload:3164 ready again)
T=1028μs  → sched:sched_switch (workload:3164 running)
           → Scheduler Latency = 8μs
```

## Data Files

### Input Files

- **`perf_script.txt`**: Raw output from Linux perf tool showing scheduler events
  - Format: Timestamp, process name, PID, CPU, event type, state transitions
  - Used by `p_lat.py` for analysis

### Output Files

- **`output.txt`**: Results from `p_lat.py` analysis
  - Latency statistics
  - Anomaly detection results
  - Per-task metrics

- **`ebpf_latency.txt`** (generated): eBPF program output
  - Raw latency measurements in nanoseconds
  - One event per line
  - Used by `ebpf_avg.py`

## Building and Running

### Prerequisites

- Linux kernel with eBPF support (5.8+)
- `clang` and `llvm` (for eBPF compilation)
- `libbpf` libraries
- Python 3 with numpy
- Linux `perf` tool

### Build eBPF Program

```bash
cd ebpf_logs
clang -O2 -target bpf -c sl.bpf.c -o sl.bpf.o
```

### Run Workload with Profiling

```bash
# Terminal 1: Start eBPF collector
cd ebpf_logs
sudo ./collector

# Terminal 2: Record with perf
perf record -e sched:sched_wakeup,sched:sched_switch -p <workload_pid>

# Terminal 3: Run workload
cd workload
./workload
```

### Analyze Results

```bash
# Perf-based analysis
python p_lat.py

# eBPF-based analysis
python ebpf_logs/ebpf_avg.py
```

## Technical Details

### eBPF Capabilities

- **Ring Buffer**: Efficient kernel→userspace data transfer (avoiding buffer copies)
- **Tracepoint Attachment**: Hooks into kernel scheduler's `sched_wakeup` and `sched_switch`
- **In-Kernel Filtering**: Only traces target workload (via TGID)
- **Low Overhead**: Minimal performance impact on system

### Scheduler Tracepoints Monitored

1. **`sched:sched_wakeup`**
   - Fired when task is woken up (I/O complete, timer expires, etc.)
   - Indicates task moved to runqueue

2. **`sched:sched_switch`**
   - Fired on every context switch
   - Tracks which task got CPU and which was preempted
   - Captures task state (Running, Sleeping, Disk wait, etc.)

### Latency Anomalies

Common anomalies detected:

- **High Wake-to-Run Latency**: Task wakes up but takes long to get CPU
- **Preemption Waves**: Rapid preemption causing cascading latency
- **Priority Inversion**: Low-priority task blocks high-priority task
- **Load Imbalance**: Tasks waiting while other cores are idle

## Use Cases

1. **Real-Time System Analysis**: Measure latency bounds for real-time tasks
2. **Performance Debugging**: Identify scheduler-induced bottlenecks
3. **System Tuning**: Test impact of CPU affinity, scheduling policies
4. **Anomaly Detection**: Find unexpected scheduler behavior patterns
5. **Workload Characterization**: Understand how different workloads interact with scheduler

## Future Enhancements

- [ ] Visualize latency distributions (histograms, heatmaps)
- [ ] Real-time latency monitoring dashboard
- [ ] Lock contention analysis
- [ ] Multi-CPU scheduling analysis
- [ ] Correlate with other kernel events (context switching, migrations)

## References

- [Linux Kernel Scheduler](https://www.kernel.org/doc/html/latest/scheduler/sched-design-CFS.html)
- [eBPF Documentation](https://ebpf.io/)
- [Linux tracepoints](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)
- [libbpf Tutorial](https://nakryiko.com/posts/bpf-core-reference-guide/)

## License

See `.gitignore` for project configuration.

---

**Project Status**: Active Development  
**Last Updated**: March 2026
