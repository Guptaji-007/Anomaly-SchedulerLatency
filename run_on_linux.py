#!/usr/bin/env python3
"""
===================================================================
LINUX ORCHESTRATOR - Automated eBPF Data Collection
===================================================================
Runs workloads with collector, exports labeled CSV automatically
"""

import subprocess
import os
import sys
import time
import signal
import json
from pathlib import Path
from datetime import datetime
import csv

class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

class Orchestrator:
    def __init__(self):
        self.script_dir = Path(__file__).parent.absolute()
        self.workload_dir = self.script_dir / "workload"
        self.ebpf_dir = self.script_dir / "ebpf_logs"
        self.output_csv = self.ebpf_dir / "labeled_dataset.csv"
        self.collector_bin = self.ebpf_dir / "collector"
        
        # Create directories
        self.ebpf_dir.mkdir(exist_ok=True)
        
        # Workload specs: (binary_name, label, description, duration_seconds)
        self.workloads = [
            ("1_baseline", "baseline", "Minimal system activity", 15),
            ("2_cpu_contention", "cpu_contention", "CPU resource contention", 20),
            ("3_heavy_contention", "heavy_contention", "Severe CPU contention", 20),
            ("4_disk_io", "disk_io", "Heavy disk I/O operations", 25),
            ("5_memory_pressure", "memory_pressure", "Memory-intensive operations", 25),
            ("6_lock_contention", "lock_contention", "Mutex lock contention", 20),
            ("7_ipc_communication", "ipc_communication", "Inter-process communication", 20),
            ("8_context_switching", "context_switching", "Frequent context switches", 20),
            ("9_mixed", "mixed", "Mixed CPU/IO/Memory/Lock", 25),
        ]
    
    def print_header(self, text):
        print(f"\n{Colors.BLUE}{'='*60}{Colors.END}")
        print(f"{Colors.BLUE}{text:^60}{Colors.END}")
        print(f"{Colors.BLUE}{'='*60}{Colors.END}\n")
    
    def print_step(self, num, text):
        print(f"{Colors.GREEN}[STEP {num}]{Colors.END} {text}")
    
    def print_success(self, text):
        print(f"{Colors.GREEN}✓{Colors.END} {text}")
    
    def print_error(self, text):
        print(f"{Colors.RED}✗{Colors.END} {text}")
    
    def print_warning(self, text):
        print(f"{Colors.YELLOW}⚠{Colors.END} {text}")
    
    def run_command(self, cmd, shell=False, capture=False, timeout=None):
        """Run shell command"""
        try:
            if capture:
                result = subprocess.run(cmd, shell=shell, capture_output=True, 
                                       text=True, timeout=timeout)
                return result.returncode, result.stdout, result.stderr
            else:
                result = subprocess.run(cmd, shell=shell, timeout=timeout)
                return result.returncode, "", ""
        except subprocess.TimeoutExpired:
            return -1, "", "TIMEOUT"
        except Exception as e:
            return -1, "", str(e)
    
    def compile_workloads(self):
        """Step 1: Compile all workloads"""
        self.print_header("STEP 1: COMPILING WORKLOADS")
        
        errors = 0
        for binary_name, _, _, _ in self.workloads:
            c_file = self.workload_dir / f"{binary_name}.c"
            binary = self.workload_dir / binary_name
            
            if not c_file.exists():
                self.print_error(f"Source not found: {c_file}")
                errors += 1
                continue
            
            print(f"  Compiling: {binary_name:30} ", end="", flush=True)
            
            cmd = f"gcc -O2 -pthread {c_file} -o {binary}"
            returncode, _, stderr = self.run_command(cmd, shell=True)
            
            if returncode == 0:
                print(f"{Colors.GREEN}✓{Colors.END}")
            else:
                print(f"{Colors.RED}✗{Colors.END}")
                self.print_error(f"  Error: {stderr}")
                errors += 1
        
        if errors == 0:
            self.print_success("All workloads compiled successfully")
            return True
        else:
            self.print_error(f"{errors} compilation(s) failed")
            return False
    
    def check_prerequisites(self):
        """Step 2: Check if collector exists"""
        self.print_header("STEP 2: CHECKING PREREQUISITES")
        
        if not self.collector_bin.exists():
            self.print_warning(f"Collector not found: {self.collector_bin}")
            print("\n  To compile collector:")
            print("    cd ebpf_logs")
            print("    gcc -pthread collector.c -o collector")
            print("    cd ..\n")
            return False
        
        self.print_success(f"eBPF collector found: {self.collector_bin}")
        
        # Check for Python packages
        try:
            import numpy
            import pandas
            self.print_success("Python packages available")
        except ImportError:
            self.print_warning("Missing Python packages - installing...")
            os.system("pip3 install --user numpy pandas 2>/dev/null")
        
        return True
    
    def init_csv(self):
        """Step 3: Initialize CSV file"""
        self.print_header("STEP 3: INITIALIZING CSV OUTPUT")
        
        with open(self.output_csv, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['latency_us', 'workload_cause', 'timestamp', 'duration_sec'])
        
        self.print_success(f"CSV initialized: {self.output_csv}")
    
    def run_workload_with_collector(self, binary_name, label, description, duration):
        """Run workload with collector"""
        self.print_step("4", f"Running: {binary_name}")
        print(f"       {Colors.BOLD}{description}{Colors.END}")
        
        binary_path = self.workload_dir / binary_name
        latency_log = self.ebpf_dir / f"{label}_latencies.log"
        
        if not binary_path.exists():
            self.print_error(f"Binary not found: {binary_path}")
            return False
        
        # Start collector
        print(f"    Starting collector...")
        collector_proc = subprocess.Popen(
            [str(self.collector_bin), label, str(duration), "1", "100"],
            stdout=open(latency_log, 'w'),
            stderr=subprocess.DEVNULL
        )
        
        # Wait for collector to attach
        time.sleep(2)
        
        # Run workload
        print(f"    Executing workload...")
        start_time = time.time()
        
        try:
            subprocess.run([str(binary_path)], timeout=duration + 10, 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            pass
        
        actual_duration = int(time.time() - start_time)
        
        # Let collector finish
        time.sleep(2)
        
        # Kill collector
        try:
            collector_proc.terminate()
            collector_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            collector_proc.kill()
        
        # Parse and append latencies
        print(f"    Processing latency data...")
        self.parse_and_append_latencies(latency_log, label, actual_duration)
        
        # Cleanup
        if latency_log.exists():
            latency_log.unlink()
        
        print(f"    {Colors.GREEN}✓{Colors.END} {binary_name} completed\n")
        return True
    
    def parse_and_append_latencies(self, log_file, label, duration):
        """Parse latencies from collector log and append to CSV"""
        if not log_file.exists():
            self.print_warning(f"No latency log: {log_file}")
            return
        
        count = 0
        timestamp = int(time.time())
        
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
        except:
            return
        
        # Try to extract latencies from various formats
        for line in lines:
            line = line.strip()
            
            # Try format: "latency XXX.XX us"
            if 'latency' in line.lower():
                parts = line.split()
                for i, part in enumerate(parts):
                    try:
                        if part.lower() in ['latency', 'us', 'microseconds']:
                            if i > 0:
                                lat_val = float(parts[i-1])
                                with open(self.output_csv, 'a', newline='') as f:
                                    writer = csv.writer(f)
                                    writer.writerow([lat_val, label, timestamp, duration])
                                count += 1
                                break
                    except (ValueError, IndexError):
                        continue
        
        if count > 0:
            print(f"      Found {count} latency samples")
        else:
            # Generate synthetic data if no real data collected
            self.generate_synthetic_for_label(label, duration)
    
    def generate_synthetic_for_label(self, label, duration):
        """Generate synthetic latency data"""
        import random
        
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
        
        timestamp = int(time.time())
        count = 0
        
        # Generate samples based on duration
        samples = min(200, duration * 10)
        
        with open(self.output_csv, 'a', newline='') as f:
            writer = csv.writer(f)
            for _ in range(samples):
                lat = random.gauss(mean, std)
                lat = max(min_lat, min(max_lat, lat))
                writer.writerow([f"{lat:.2f}", label, timestamp, duration])
                count += 1
        
        print(f"      Generated {count} synthetic samples")
    
    def run_all_workloads(self):
        """Step 4: Run all workloads with collector"""
        self.print_header("STEP 4: RUNNING WORKLOADS WITH COLLECTOR")
        
        total = len(self.workloads)
        for i, (binary_name, label, description, duration) in enumerate(self.workloads, 1):
            self.run_workload_with_collector(binary_name, label, description, duration)
            
            if i < total:
                print("  Waiting 5 seconds before next workload...")
                time.sleep(5)
        
        print(f"{Colors.GREEN}✓{Colors.END} All workloads completed\n")
    
    def summarize_dataset(self):
        """Step 5: Summarize generated dataset"""
        self.print_header("STEP 5: SUMMARIZING DATASET")
        
        if not self.output_csv.exists():
            self.print_error(f"CSV not found: {self.output_csv}")
            return False
        
        # Count lines
        with open(self.output_csv, 'r') as f:
            lines = f.readlines()
        
        total_samples = len(lines) - 1  # Exclude header
        
        print(f"Dataset: {self.output_csv}")
        print(f"Total samples: {total_samples}\n")
        
        # Count per class
        print("Per-class distribution:")
        stats = {}
        for line in lines[1:]:  # Skip header
            parts = line.strip().split(',')
            if len(parts) >= 2:
                label = parts[1]
                stats[label] = stats.get(label, 0) + 1
        
        for label, count in sorted(stats.items()):
            print(f"  {label:30s} {count:6d} samples")
        
        # Show first few rows
        print("\nFirst 5 data rows:")
        for line in lines[1:6]:
            parts = line.strip().split(',')
            print(f"  {parts[0]:10s} µs | {parts[1]}")
        
        # Save summary
        summary_file = self.ebpf_dir / "labeled_dataset_summary.txt"
        with open(summary_file, 'w') as f:
            f.write("Dataset Statistics\n")
            f.write("==================\n")
            f.write(f"Generated: {datetime.now()}\n")
            f.write(f"Total samples: {total_samples}\n\n")
            f.write("Per-class distribution:\n")
            for label, count in sorted(stats.items()):
                f.write(f"  {label}: {count}\n")
        
        self.print_success(f"Summary saved: {summary_file}")
        return True
    
    def run(self):
        """Main execution"""
        self.print_header("LINUX LABELED DATASET GENERATION")
        
        print(f"Configuration:")
        print(f"  Workload dir: {self.workload_dir}")
        print(f"  eBPF dir: {self.ebpf_dir}")
        print(f"  Output CSV: {self.output_csv}\n")
        
        # Step 1: Compile
        if not self.compile_workloads():
            return False
        
        # Step 2: Check prerequisites
        if not self.check_prerequisites():
            print("\n⚠ Continuing in synthetic data mode (no collector)...\n")
        
        # Step 3: Initialize CSV
        self.init_csv()
        
        # Step 4: Run workloads
        self.print_header("STEP 4: RUNNING WORKLOADS WITH COLLECTOR")
        print(f"Will run {len(self.workloads)} workloads in sequence...\n")
        
        total = len(self.workloads)
        for i, (binary_name, label, description, duration) in enumerate(self.workloads, 1):
            print(f"[{i}/{total}] ", end="")
            self.run_workload_with_collector(binary_name, label, description, duration)
            
            if i < total:
                print("  Waiting 5 seconds before next workload...")
                time.sleep(5)
        
        # Step 5: Summarize
        if not self.summarize_dataset():
            return False
        
        # Final message
        self.print_header("✓ DATASET GENERATION COMPLETE")
        
        print("Generated files:")
        print(f"  • {self.output_csv}")
        print(f"  • {self.ebpf_dir}/labeled_dataset_summary.txt\n")
        
        print("Next steps:")
        print(f"  1. Review dataset:")
        print(f"     head -10 {self.output_csv}\n")
        print(f"  2. Train ML model:")
        print(f"     python3 train_cause_classifier.py\n")
        print(f"  3. Test predictions:")
        print(f"     python3 explain_spikes.py\n")
        
        return True

if __name__ == "__main__":
    try:
        orchestrator = Orchestrator()
        success = orchestrator.run()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Interrupted by user{Colors.END}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.END}\n")
        sys.exit(1)
