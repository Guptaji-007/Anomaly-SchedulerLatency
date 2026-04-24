#!/bin/bash
# Compile all workload C files into executables

WORKLOAD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPILE_ERRORS=0

echo "=========================================="
echo "COMPILING ALL WORKLOADS"
echo "=========================================="

# List of workload files to compile
WORKLOADS=(
    "1_baseline"
    "2_cpu_contention"
    "3_heavy_contention"
    "4_disk_io"
    "5_memory_pressure"
    "6_lock_contention"
    "7_ipc_communication"
    "8_context_switching"
    "9_mixed"
)

for workload in "${WORKLOADS[@]}"; do
    C_FILE="${WORKLOAD_DIR}/${workload}.c"
    BIN="${WORKLOAD_DIR}/${workload}"
    
    if [ -f "$C_FILE" ]; then
        echo ""
        echo "Compiling: $workload"
        gcc -O2 -pthread "$C_FILE" -o "$BIN" 2>&1
        
        if [ $? -eq 0 ]; then
            echo "✓ Success: $BIN"
        else
            echo "✗ FAILED: $workload"
            ((COMPILE_ERRORS++))
        fi
    else
        echo "✗ Source not found: $C_FILE"
        ((COMPILE_ERRORS++))
    fi
done

echo ""
echo "=========================================="
if [ $COMPILE_ERRORS -eq 0 ]; then
    echo "✓ ALL WORKLOADS COMPILED SUCCESSFULLY"
else
    echo "✗ COMPILATION COMPLETED WITH $COMPILE_ERRORS ERRORS"
fi
echo "=========================================="

exit $COMPILE_ERRORS
