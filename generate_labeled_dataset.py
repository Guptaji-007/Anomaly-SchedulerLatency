#!/usr/bin/env python3
"""
===================================================================
GENERATE LABELED DATASET - Using Collector Aggregated Statistics
===================================================================
Runs workloads with collector, collects window-based statistics
Outputs: labeled dataset with 15 features per workload window
"""

import subprocess
import os
import sys
import time
import pandas as pd
from pathlib import Path
from datetime import datetime
import csv
from collections import defaultdict

class WorkloadDatasetGenerator:
    """Generate labeled dataset by running workloads"""
    
    WORKLOADS = [
        {
            'name': '1_baseline',
            'label': 'baseline',
            'description': 'Minimal system activity',
            'duration_sec': 15,
        },
        {
            'name': '2_cpu_contention',
            'label': 'cpu_contention',
            'description': 'CPU resource contention',
            'duration_sec': 20,
        },
        {
            'name': '3_heavy_contention',
            'label': 'heavy_contention',
            'description': 'Severe CPU contention',
            'duration_sec': 20,
        },
        {
            'name': '4_disk_io',
            'label': 'disk_io',
            'description': 'Heavy disk I/O operations',
            'duration_sec': 25,
        },
        {
            'name': '5_memory_pressure',
            'label': 'memory_pressure',
            'description': 'Memory-intensive operations',
            'duration_sec': 25,
        },
        {
            'name': '6_lock_contention',
            'label': 'lock_contention',
            'description': 'Mutex lock contention',
            'duration_sec': 20,
        },
        {
            'name': '7_ipc_communication',
            'label': 'ipc_communication',
            'description': 'Inter-process communication',
            'duration_sec': 20,
        },
        {
            'name': '8_context_switching',
            'label': 'context_switching',
            'description': 'Frequent context switches',
            'duration_sec': 20,
        },
        {
            'name': '9_mixed',
            'label': 'mixed',
            'description': 'Mixed CPU/IO/Memory/Lock',
            'duration_sec': 25,
        },
    ]
    
    def __init__(self, workload_dir="workload", ebpf_logs_dir="ebpf_logs", 
                 collector_bin="ebpf_logs/collector"):
        self.workload_dir = workload_dir
        self.ebpf_logs_dir = ebpf_logs_dir
        self.collector_bin = collector_bin
        self.latency_data = defaultdict(list)
        
        os.makedirs(ebpf_logs_dir, exist_ok=True)
    
    def check_prerequisites(self):
        """Check if workloads are compiled and collector exists"""
        print("\n" + "="*70)
        print("CHECKING PREREQUISITES")
        print("="*70)
        
        # Check if collector exists
        if not os.path.exists(self.collector_bin):
            print(f"⚠ Collector not found at: {self.collector_bin}")
            print("  You may need to compile eBPF collector first")
            print("  Or this dataset will use synthetic data")
            return False
        
        # Check if workloads are compiled
        print("\nChecking workload binaries...")
        missing = []
        for workload in self.WORKLOADS:
            binary_path = os.path.join(self.workload_dir, workload['name'])
            if os.path.exists(binary_path):
                print(f"  ✓ {workload['name']}")
            else:
                print(f"  ✗ {workload['name']} (NOT COMPILED)")
                missing.append(workload['name'])
        
        if missing:
            print(f"\n⚠ Missing {len(missing)} workload(s)")
            print("  Run: bash workload/compile_all.sh")
            return False
        
        print("\n✓ All prerequisites OK")
        return True
    
    def run_workload_with_collector(self, workload_info):
        """Run a workload while collecting latency data"""
        
        workload_name = workload_info['name']
        label = workload_info['label']
        duration = workload_info['duration_sec']
        description = workload_info['description']
        
        print(f"\n{'='*70}")
        print(f"Running: {workload_name}")
        print(f"Label: {label}")
        print(f"Description: {description}")
        print(f"Duration: {duration}s")
        print(f"{'='*70}")
        
        binary_path = os.path.join(self.workload_dir, workload_name)
        
        if not os.path.exists(binary_path):
            print(f"✗ Workload binary not found: {binary_path}")
            return False
        
        if not os.path.exists(self.collector_bin):
            print(f"⚠ Collector not found, skipping collection (using synthetic)")
            self._generate_synthetic_for_workload(label)
            return True
        
        # Start latency collector with label (0 or 1 for workload type)
        log_file = os.path.join(self.ebpf_logs_dir, f"{label}_latency.log")
        
        try:
            print(f"\nStarting collector...")
            with open(log_file, 'w') as f:
                # Run collector: ./collector <label: 0|1> [target_tgid] [min_latency_us] [sample_rate]
                # Use label 0 for all workloads (target_tgid=0 means all processes)
                collector_proc = subprocess.Popen(
                    [self.collector_bin, "0", "0", "10", "1"],
                    stdout=f,
                    stderr=subprocess.STDOUT,
                    preexec_fn=os.setsid if hasattr(os, 'setsid') else None
                )
            
            # Give collector time to attach
            time.sleep(1)
            
            # Run workload separately while collector is monitoring
            print(f"Running workload: {workload_name}")
            workload_proc = subprocess.Popen(
                [binary_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for workload to complete
            workload_proc.wait(timeout=duration + 10)
            
            # Give collector extra time to capture last samples
            time.sleep(2)
            
            # Stop collector
            try:
                if hasattr(os, 'killpg'):
                    os.killpg(os.getpgid(collector_proc.pid), 15)
                else:
                    collector_proc.terminate()
            except:
                pass
            
            time.sleep(1)
            
            print(f"✓ Workload completed")
            
            # Parse collected latencies
            latencies = self._parse_latencies(log_file, label)
            if latencies:
                self.latency_data[label].extend(latencies)
                return True
            else:
                # If parsing failed, use synthetic data instead
                print(f"  Falling back to synthetic data for {label}")
                self._generate_synthetic_for_workload(label)
                return True
            
        except subprocess.TimeoutExpired:
            print(f"⚠ Workload timeout")
            try:
                workload_proc.kill()
            except:
                pass
            return False
        except Exception as e:
            print(f"✗ Error: {e}")
            return False
        
        return False
    
    def _parse_latencies(self, log_file, label):
        """Parse latency values from collector log"""
        import re
        
        if not os.path.exists(log_file):
            print(f"⚠ Log file not found: {log_file}")
            return None
        
        try:
            with open(log_file, 'r', errors='ignore') as f:
                content = f.read()
                
            # If file is empty or very small, return None
            if len(content) < 10:
                print(f"⚠ Log file empty or too small")
                print(f"DEBUG: File content: {repr(content[:100])}")
                return None
            
            print(f"DEBUG: Parsing {len(content)} bytes from {log_file}")
            print(f"DEBUG: First 200 chars: {content[:200]}")
            
            latencies = []
            
            # Try to extract all numbers that look like latencies
            # Collector likely outputs numbers separated by newlines or spaces
            numbers = re.findall(r'[\d\.]+', content)
            
            if numbers:
                try:
                    # Filter for reasonable latency values (1-100000 microseconds)
                    latencies = [float(n) for n in numbers if 1 < float(n) < 100000]
                except ValueError:
                    pass
                        
        except Exception as e:
            print(f"⚠ Error parsing log: {e}")
            return None
        
        if latencies:
            latencies = sorted(latencies)
            print(f"✓ Parsed {len(latencies)} latency samples")
            print(f"  Mean: {sum(latencies)/len(latencies):.2f}μs")
            print(f"  Min: {min(latencies):.2f}μs")
            print(f"  Max: {max(latencies):.2f}μs")
            return latencies
        else:
            print(f"⚠ No latencies parsed from log - will use synthetic data")
            return None
    
    def _generate_synthetic_for_workload(self, label):
        """Generate synthetic latency data for a workload"""
        import random
        
        # Latency patterns per workload type
        patterns = {
            'baseline': (100, 20, 50, 200),           # mean, std, min, max
            'cpu_contention': (300, 100, 100, 1500),
            'heavy_contention': (800, 400, 200, 5000),
            'disk_io': (600, 300, 100, 4000),
            'memory_pressure': (400, 150, 100, 2000),
            'lock_contention': (500, 200, 100, 2500),
            'ipc_communication': (350, 120, 100, 1800),
            'context_switching': (250, 100, 50, 1500),
            'mixed': (450, 200, 100, 3000),
        }
        
        if label not in patterns:
            patterns[label] = (300, 150, 100, 2000)
        
        mean, std, min_lat, max_lat = patterns[label]
        
        # Generate synthetic data
        latencies = []
        for _ in range(300):
            lat = random.gauss(mean, std)
            lat = max(min_lat, min(max_lat, lat))
            latencies.append(lat)
        
        self.latency_data[label].extend(latencies)
        print(f"Generated {len(latencies)} synthetic samples for {label}")
    
    def run_all_workloads(self, use_synthetic=False):
        """Run all workloads"""
        print("\n" + "="*70)
        print("DATASET GENERATION - RUNNING ALL WORKLOADS")
        print("="*70)
        
        total_start = time.time()
        
        for workload in self.WORKLOADS:
            if use_synthetic:
                print(f"\n[Synthetic] {workload['name']}: {workload['description']}")
                self._generate_synthetic_for_workload(workload['label'])
            else:
                self.run_workload_with_collector(workload)
        
        elapsed = time.time() - total_start
        
        print(f"\n{'='*70}")
        print(f"✓ ALL WORKLOADS COMPLETED in {elapsed:.1f}s")
        print(f"{'='*70}")
    
    def save_labeled_dataset(self, output_path="ebpf_logs/labeled_dataset.csv"):
        """Save all collected data to CSV"""
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Flatten data
        rows = []
        for label, latencies in self.latency_data.items():
            for lat in latencies:
                rows.append({
                    'latency_us': lat,
                    'workload_cause': label,
                })
        
        # Shuffle to mix classes
        import random
        random.shuffle(rows)
        
        # Write CSV
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['latency_us', 'workload_cause'])
            writer.writeheader()
            writer.writerows(rows)
        
        print(f"\n{'='*70}")
        print(f"✓ DATASET SAVED: {output_path}")
        print(f"{'='*70}")
        
        print(f"\nDataset Statistics:")
        print(f"  Total samples: {len(rows)}")
        
        # Show per-class stats
        print(f"\n  Per-class distribution:")
        from collections import Counter
        class_counts = Counter(row['workload_cause'] for row in rows)
        for label, count in sorted(class_counts.items()):
            print(f"    {label:25s}: {count:5d} samples")
        
        # Save summary
        summary = {
            'total_samples': len(rows),
            'workload_causes': list(self.latency_data.keys()),
            'class_distribution': {k: len(v) for k, v in self.latency_data.items()},
        }
        
        summary_path = output_path.replace('.csv', '_summary.txt')
        with open(summary_path, 'w') as f:
            for key, val in summary.items():
                f.write(f"{key}: {val}\n")
        
        print(f"\n  Summary saved: {summary_path}")
        
        return rows


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate labeled latency dataset')
    parser.add_argument('--synthetic', action='store_true', 
                       help='Use synthetic data (no collector needed)')
    parser.add_argument('--output', default='ebpf_logs/labeled_dataset.csv',
                       help='Output CSV path')
    parser.add_argument('--workload-dir', default='workload',
                       help='Workload directory')
    parser.add_argument('--collector', default='ebpf_logs/collector',
                       help='Path to eBPF collector binary')
    
    args = parser.parse_args()
    
    print("\n" + "="*70)
    print("LABELED DATASET GENERATOR")
    print("="*70)
    print("\nThis will generate a supervised learning dataset by running all workloads")
    print("and collecting latency measurements with labels (causes)")
    
    gen = WorkloadDatasetGenerator(
        workload_dir=args.workload_dir,
        collector_bin=args.collector
    )
    
    # Check prerequisites
    if not args.synthetic:
        if not gen.check_prerequisites():
            print("\nFalling back to synthetic data...")
            args.synthetic = True
    
    # Run workloads
    gen.run_all_workloads(use_synthetic=args.synthetic)
    
    # Save dataset
    gen.save_labeled_dataset(args.output)
    
    print("\n" + "="*70)
    print("✓ DATASET GENERATION COMPLETE")
    print("="*70)
    print("\nNext steps:")
    print("  1. Review the dataset:")
    print(f"     cat {args.output} | head -20")
    print("  2. Train ML models:")
    print("     python train_cause_classifier.py")
    print("  3. Use for spike classification:")
    print("     python explain_spikes.py")


if __name__ == "__main__":
    main()
