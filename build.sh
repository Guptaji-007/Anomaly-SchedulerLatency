#!/bin/bash
set -e

# build.sh - Compiles all workloads, eBPF programs, and user-space collectors

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================="
echo "    Building Anomaly-SchedulerLatency"
echo "=========================================="

echo "[1/4] Compiling Workloads..."
cd "${ROOT_DIR}/workload"
chmod +x compile_all.sh
./compile_all.sh

# Also compile the generic 'workload.c' used by slu.c
if [ -f "workload.c" ]; then
    gcc -O2 -pthread workload.c -o workload
    echo "✓ Success: workload (generic)"
fi

echo ""
echo "[2/4] Generating vmlinux header..."
cd "${ROOT_DIR}/ebpf_logs"
if bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; then
    echo "✓ Success: vmlinux.h generated"
else
    echo "[!] Warning: failed to generate vmlinux.h from /sys/kernel/btf/vmlinux. Using existing file if available."
fi

echo ""
echo "[3/4] Compiling eBPF Programs & Collector..."
# Detect architecture for BPF tracing macros
ARCH=$(uname -m | sed 's/x86_64/x86/g; s/aarch64/arm64/g')

# Compile BPF program
# Fedora clang-21 has a known frontend crash when compiling some BPF programs.
# Disabling the CodeGenPrepare pass avoids the crash.
clang -g -O2 -target bpf -D__TARGET_ARCH_${ARCH} -mllvm -disable-cgp -c sl.bpf.c -o sl.bpf.o
echo "✓ Success: sl.bpf.o compiled"

# Generate skeleton
bpftool gen skeleton sl.bpf.o > sl.skel.h
echo "✓ Success: sl.skel.h generated"

# Compile user-space collector
clang -g -O2 -Wall -I. -c collector.c -o collector.o
clang -Wall -O2 -g collector.o -lbpf -lelf -lz -lm -o collector
echo "✓ Success: collector compiled"


echo ""
echo "[4/4] Compiling perf components..."
cd "${ROOT_DIR}/perf_ebpf_comp"

# slu.c tries to load 'sl.bpf.o' from current directory, so let's symlink or copy it for convenience
ln -sf ../ebpf_logs/sl.bpf.o sl.bpf.o

# The code in slu.c uses the directly loaded bpf object (bpf_object__open_file)
# Does not seem to use skeleton, but requires libbpf
clang -g -O2 -Wall -c slu.c -o slu.o
clang -Wall -O2 -g slu.o -lbpf -lelf -lz -o slu
echo "✓ Success: slu compiled"

# Make python files executable
chmod +x *.py
cd "${ROOT_DIR}"

echo "=========================================="
echo "[✓] Build Completed Successfully!"
echo "=========================================="
