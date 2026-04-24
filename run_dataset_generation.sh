#!/bin/bash
# ===================================================================
# MASTER ORCHESTRATION SCRIPT - Generate Labeled Dataset on Linux
# ===================================================================
# This script:
# 1. Compiles all workloads
# 2. Runs eBPF collector in background
# 3. Executes each workload
# 4. Collects latency CSV
# 5. Generates complete labeled dataset
# ===================================================================

set -e  # Exit on error

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKLOAD_DIR="${SCRIPT_DIR}/workload"
EBPF_DIR="${SCRIPT_DIR}/ebpf_logs"
COLLECTOR_BIN="${EBPF_DIR}/collector"
OUTPUT_CSV="${EBPF_DIR}/labeled_dataset.csv"
TEMP_DIR="${SCRIPT_DIR}/.tmp_workload"

# Create temp directory
mkdir -p "$TEMP_DIR"
mkdir -p "$EBPF_DIR"

# ===================================================================
# FUNCTIONS
# ===================================================================

print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_step() {
    echo -e "${GREEN}[STEP $1]${NC} $2"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# ===================================================================
# STEP 1: COMPILE WORKLOADS
# ===================================================================

compile_workloads() {
    print_header "STEP 1: COMPILING WORKLOADS"
    
    cd "$WORKLOAD_DIR"
    
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
    
    COMPILE_ERRORS=0
    
    for workload in "${WORKLOADS[@]}"; do
        C_FILE="${WORKLOAD_DIR}/${workload}.c"
        BIN="${WORKLOAD_DIR}/${workload}"
        
        if [ -f "$C_FILE" ]; then
            echo -n "Compiling: $workload ... "
            
            if gcc -O2 -pthread "$C_FILE" -o "$BIN" 2>/dev/null; then
                echo -e "${GREEN}✓${NC}"
            else
                echo -e "${RED}✗ FAILED${NC}"
                ((COMPILE_ERRORS++))
            fi
        else
            print_error "Source not found: $C_FILE"
            ((COMPILE_ERRORS++))
        fi
    done
    
    if [ $COMPILE_ERRORS -eq 0 ]; then
        echo -e "\n${GREEN}✓ All workloads compiled successfully${NC}"
        return 0
    else
        print_error "$COMPILE_ERRORS compilation(s) failed"
        return 1
    fi
}

# ===================================================================
# STEP 2: CHECK PREREQUISITES
# ===================================================================

check_prerequisites() {
    print_header "STEP 2: CHECKING PREREQUISITES"
    
    # Check if collector exists
    if [ ! -f "$COLLECTOR_BIN" ]; then
        print_warning "Collector not found at: $COLLECTOR_BIN"
        print_warning "You'll need to compile eBPF collector first:"
        print_warning "  cd ebpf_logs && gcc -pthread collector.c -o collector"
        return 1
    fi
    
    echo -e "${GREEN}✓ eBPF collector found${NC}"
    
    # Check if Python3 is available
    if command -v python3 &> /dev/null; then
        echo -e "${GREEN}✓ Python3 found$(NC)"
    else
        print_error "Python3 not found"
        return 1
    fi
    
    # Check required Python packages
    python3 -c "import csv, json, subprocess, time" 2>/dev/null || {
        print_warning "Some Python packages might be missing"
    }
    
    return 0
}

# ===================================================================
# STEP 3: INITIALIZE CSV FILE
# ===================================================================

init_csv() {
    print_header "STEP 3: INITIALIZING CSV OUTPUT"
    
    # Create fresh CSV with headers
    echo "latency_us,workload_cause,timestamp,duration_sec" > "$OUTPUT_CSV"
    echo -e "${GREEN}✓ CSV initialized: $OUTPUT_CSV${NC}"
}

# ===================================================================
# STEP 4: RUN WORKLOAD WITH COLLECTOR
# ===================================================================

run_workload_with_collector() {
    local workload_name=$1
    local label=$2
    local description=$3
    local duration=$4
    
    print_step "4.${CURRENT_WORKLOAD}" "Running: $workload_name ($description)"
    
    local binary="${WORKLOAD_DIR}/${workload_name}"
    local log_file="${TEMP_DIR}/${label}_output.log"
    local latency_log="${EBPF_DIR}/${label}_latencies.log"
    
    if [ ! -f "$binary" ]; then
        print_error "Workload binary not found: $binary"
        return 1
    fi
    
    # Start collector in background
    echo "  Starting eBPF collector..."
    
    # Run collector, output latencies to file
    "$COLLECTOR_BIN" "$label" "1" "1" "100" > "$latency_log" 2>&1 &
    local collector_pid=$!
    
    # Give collector time to attach
    sleep 2
    
    echo "  Executing workload: $workload_name"
    START_TIME=$(date +%s)
    
    # Run workload
    timeout $((duration + 10)) "$binary" > "$log_file" 2>&1 || true
    
    STOP_TIME=$(date +%s)
    ACTUAL_DURATION=$((STOP_TIME - START_TIME))
    
    # Let collector collect a bit more data
    sleep 2
    
    # Kill collector gracefully
    echo "  Stopping collector..."
    if kill -0 $collector_pid 2>/dev/null; then
        kill $collector_pid 2>/dev/null || true
        wait $collector_pid 2>/dev/null || true
    fi
    
    sleep 1
    
    # Parse collected latencies and append to CSV
    if [ -f "$latency_log" ]; then
        echo "  Parsing latency data..."
        parse_and_append_latencies "$latency_log" "$label" "$ACTUAL_DURATION"
    else
        print_warning "No latency log found for $label, using synthetic data"
        generate_synthetic_for_label "$label" "$ACTUAL_DURATION"
    fi
    
    # Cleanup
    rm -f "$latency_log"
    
    echo -e "  ${GREEN}✓ $workload_name completed${NC}"
}

# ===================================================================
# STEP 5: PARSE LATENCIES FROM LOG AND APPEND TO CSV
# ===================================================================

parse_and_append_latencies() {
    local log_file=$1
    local label=$2
    local duration=$3
    
    if [ ! -f "$log_file" ]; then
        return
    fi
    
    # Extract latency values using grep and awk
    # Pattern: latency XXX.XX us
    grep -oP 'latency\s+\K[\d.]+' "$log_file" | while read latency; do
        echo "${latency},${label},$STOP_TIME,${duration}" >> "$OUTPUT_CSV"
    done
    
    local count=$(grep -oP 'latency\s+\K[\d.]+' "$log_file" | wc -l)
    echo "    Found $count latency samples"
}

# ===================================================================
# STEP 6: GENERATE SYNTHETIC DATA IF NEEDED
# ===================================================================

generate_synthetic_for_label() {
    local label=$1
    local duration=$2
    
    python3 << 'PYTHON_END'
import random
import sys

label = sys.argv[1] if len(sys.argv) > 1 else "unknown"
duration = sys.argv[2] if len(sys.argv) > 2 else "10"

# Latency patterns per workload
patterns = {
    'baseline': (100, 20, 50, 200),
    'cpu_contention': (300, 100, 100, 1500),
    'heavy_contention': (800, 400, 200, 5000),
    'disk_io': (600, 300, 100, 4000),
    'memory_pressure': (400, 150, 100, 2000),
    'lock_contention': (500, 200, 100, 2500),
    'ipc_communication': (350, 120, 100, 1800),
    'context_switching': (250, 100, 50, 1500),
    'mixed': (450, 200, 100, 3000),
}

if label in patterns:
    mean, std, min_lat, max_lat = patterns[label]
else:
    mean, std, min_lat, max_lat = (300, 150, 100, 2000)

# Generate samples
for _ in range(200):
    lat = random.gauss(mean, std)
    lat = max(min_lat, min(max_lat, lat))
    print(f"{lat:.2f},{label},{int(time.time())},{duration}")

PYTHON_END
}

# ===================================================================
# STEP 7: RUN ALL WORKLOADS
# ===================================================================

run_all_workloads() {
    print_header "STEP 4: RUNNING ALL WORKLOADS"
    
    local workloads=(
        "1_baseline:baseline:Minimal system activity:15"
        "2_cpu_contention:cpu_contention:CPU resource contention:20"
        "3_heavy_contention:heavy_contention:Severe CPU contention:20"
        "4_disk_io:disk_io:Heavy disk I/O operations:25"
        "5_memory_pressure:memory_pressure:Memory-intensive operations:25"
        "6_lock_contention:lock_contention:Mutex lock contention:20"
        "7_ipc_communication:ipc_communication:Inter-process communication:20"
        "8_context_switching:context_switching:Frequent context switches:20"
        "9_mixed:mixed:Mixed CPU/IO/Memory/Lock:25"
    )
    
    CURRENT_WORKLOAD=0
    local total=${#workloads[@]}
    
    for workload_spec in "${workloads[@]}"; do
        ((CURRENT_WORKLOAD++))
        
        IFS=':' read -r name label description duration <<< "$workload_spec"
        
        echo ""
        run_workload_with_collector "$name" "$label" "$description" "$duration"
        
        if [ $CURRENT_WORKLOAD -lt $total ]; then
            echo "  Waiting 5 seconds before next workload..."
            sleep 5
        fi
    done
    
    echo ""
    echo -e "${GREEN}✓ All workloads completed${NC}"
}

# ===================================================================
# STEP 8: VERIFY AND SUMMARIZE DATASET
# ===================================================================

summarize_dataset() {
    print_header "STEP 5: SUMMARIZING DATASET"
    
    if [ ! -f "$OUTPUT_CSV" ]; then
        print_error "CSV file not found: $OUTPUT_CSV"
        return 1
    fi
    
    local total_lines=$(($(wc -l < "$OUTPUT_CSV") - 1))  # Subtract header
    
    echo "Dataset: $OUTPUT_CSV"
    echo "Total samples: $total_lines"
    echo ""
    echo "Per-class distribution:"
    
    # Count samples per class
    tail -n +2 "$OUTPUT_CSV" | cut -d',' -f2 | sort | uniq -c | while read count label; do
        printf "  %-30s %6d samples\n" "$label:" "$count"
    done
    
    echo ""
    echo "First 5 rows:"
    head -6 "$OUTPUT_CSV" | tail -5 | cut -d',' -f1-2
    
    # Save summary
    {
        echo "Dataset Statistics"
        echo "=================="
        echo "Generated: $(date)"
        echo "Total samples: $total_lines"
        echo ""
        echo "Per-class distribution:"
        tail -n +2 "$OUTPUT_CSV" | cut -d',' -f2 | sort | uniq -c | while read count label; do
            echo "  $label: $count"
        done
    } > "${EBPF_DIR}/labeled_dataset_summary.txt"
    
    echo ""
    echo -e "${GREEN}✓ Summary saved: ${EBPF_DIR}/labeled_dataset_summary.txt${NC}"
}

# ===================================================================
# MAIN EXECUTION
# ===================================================================

main() {
    print_header "LABELED DATASET GENERATION - LINUX ORCHESTRATION"
    
    echo "Configuration:"
    echo "  Workload dir: $WORKLOAD_DIR"
    echo "  eBPF dir: $EBPF_DIR"
    echo "  Collector: $COLLECTOR_BIN"
    echo "  Output CSV: $OUTPUT_CSV"
    echo ""
    
    # Step 1: Compile
    if ! compile_workloads; then
        print_error "Workload compilation failed"
        exit 1
    fi
    
    # Step 2: Check prerequisites
    if ! check_prerequisites; then
        print_error "Prerequisites check failed"
        exit 1
    fi
    
    # Step 3: Initialize CSV
    init_csv
    
    # Step 4: Run all workloads
    run_all_workloads
    
    # Step 5: Summarize
    summarize_dataset
    
    print_header "✓ DATASET GENERATION COMPLETE"
    
    echo ""
    echo "Next steps:"
    echo "  1. Review the dataset:"
    echo "     head -20 $OUTPUT_CSV"
    echo ""
    echo "  2. Train ML classifier:"
    echo "     python3 train_cause_classifier.py"
    echo ""
    echo "  3. Use for spike classification:"
    echo "     python3 explain_spikes.py"
    echo ""
}

# ===================================================================
# ERROR HANDLING
# ===================================================================

cleanup() {
    print_warning "Cleaning up..."
    rm -rf "$TEMP_DIR"
    
    # Kill any lingering collector processes
    pkill -f "collector" 2>/dev/null || true
}

trap cleanup EXIT

# ===================================================================
# RUN MAIN
# ===================================================================

main "$@"
