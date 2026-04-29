"""
Utilities for ML Pipeline
Helper functions for data collection, integration testing, and deployment
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional
import json
import subprocess
import time
from datetime import datetime

from dataset_generator import DatasetGenerator
from realtime_detector import RealtimeDetector, DetectionLogger


class CollectorIntegration:
    """Helper class to integrate with eBPF collector"""
    
    @staticmethod
    def run_collector_for_workload(workload_path: str, label: int, 
                                   duration_sec: int = 30,
                                   output_csv: str = None) -> str:
        """
        Run collector for a specific workload
        
        Args:
            workload_path: Path to compiled workload binary
            label: Workload label (0-8)
            duration_sec: Collection duration
            output_csv: Output file path
            
        Returns:
            Path to generated CSV file
        """
        if output_csv is None:
            label_name = DatasetGenerator.LABEL_TO_NAME.get(label, f'workload_{label}')
            output_csv = f"ebpf_logs/{label_name}_events.csv"
        
        print(f"\n[Collector] Starting collection for label {label}...")
        print(f"  Workload: {workload_path}")
        print(f"  Duration: {duration_sec}s")
        print(f"  Output: {output_csv}")
        
        try:
            # Start workload in background
            workload_proc = subprocess.Popen([workload_path])
            
            # Start collector
            # This assumes collector binary exists and accepts label argument
            collector_cmd = [
                'ebpf_logs/collector',
                str(label),
                str(workload_proc.pid),
                '1000',  # min_latency_us
                '1'      # sample_rate
            ]
            
            collector_proc = subprocess.Popen(
                collector_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for collection duration
            time.sleep(duration_sec)
            
            # Stop collector
            collector_proc.terminate()
            collector_proc.wait(timeout=5)
            
            # Stop workload
            workload_proc.terminate()
            workload_proc.wait(timeout=5)
            
            print(f"  ✓ Collection complete: {output_csv}")
            
            return output_csv
        
        except Exception as e:
            print(f"  ✗ Error: {e}")
            raise
    
    @staticmethod
    def collect_all_workloads(workload_dir: str = 'workload',
                             duration_sec: int = 30,
                             output_dir: str = 'ebpf_logs') -> List[tuple]:
        """
        Collect data for all workloads
        
        Args:
            workload_dir: Directory containing workload binaries
            duration_sec: Collection duration per workload
            output_dir: Output directory for CSVs
            
        Returns:
            List of (csv_path, label) tuples
        """
        workload_binaries = [
            ('1_baseline', 0),
            ('2_cpu_contention', 1),
            ('3_heavy_contention', 2),
            ('4_disk_io', 3),
            ('5_memory_pressure', 4),
            ('6_lock_contention', 5),
            ('7_ipc_communication', 6),
            ('8_context_switching', 7),
            ('9_mixed', 8),
        ]
        
        collected_files = []
        
        for binary_name, label in workload_binaries:
            workload_path = Path(workload_dir) / binary_name
            
            if not workload_path.exists():
                print(f"Warning: {workload_path} not found, skipping...")
                continue
            
            try:
                csv_path = CollectorIntegration.run_collector_for_workload(
                    str(workload_path),
                    label,
                    duration_sec,
                    f"{output_dir}/{binary_name}_events.csv"
                )
                collected_files.append((csv_path, label))
            except Exception as e:
                print(f"Error collecting {binary_name}: {e}")
        
        return collected_files


class ValidationTest:
    """Validation and testing utilities"""
    
    @staticmethod
    def test_feature_extraction(events_csv: str) -> Dict:
        """Test feature extraction on sample data"""
        print(f"\nValidating feature extraction on {events_csv}...")
        
        gen = DatasetGenerator()
        df = gen.load_events(events_csv)
        
        print(f"  Loaded {len(df)} events")
        print(f"  Time span: {(df['ts_ns'].max() - df['ts_ns'].min()) / 1e9:.2f}s")
        print(f"  Latency range: [{df['latency_ns'].min()}, {df['latency_ns'].max()}]")
        
        # Extract features
        features = gen.extract_window_features(df)
        
        print(f"  Extracted {len(features)} features")
        print(f"  Latency mean: {features['latency_mean']:.2f} ns")
        print(f"  Latency p99: {features['latency_p99']:.2f} ns")
        print(f"  Event rate: {features['event_rate']:.2f} events/s")
        
        return features
    
    @staticmethod
    def test_model_loading(anomaly_model: str, cause_model: str) -> bool:
        """Test if models can be loaded successfully"""
        print(f"\nValidating model files...")
        
        try:
            print(f"  Loading anomaly detector: {anomaly_model}")
            detector_model = RealtimeDetector()
            detector_model.anomaly_detector = __import__('model_trainer').AnomalyDetector()
            detector_model.anomaly_detector.load(anomaly_model)
            print(f"    ✓ Loaded ({detector_model.anomaly_detector.stats})")
            
            print(f"  Loading cause classifier: {cause_model}")
            classifier = __import__('model_trainer').CauseClassifier()
            classifier.load(cause_model)
            print(f"    ✓ Loaded (classes: {classifier.classes})")
            
            return True
        
        except Exception as e:
            print(f"    ✗ Error: {e}")
            return False
    
    @staticmethod
    def test_detection_pipeline(detector: RealtimeDetector,
                               test_events: List[Dict],
                               expected_anomaly: bool = False) -> Dict:
        """Test detection pipeline with sample events"""
        print(f"\nTesting detection pipeline...")
        
        # Add events
        detector.add_events_batch(test_events)
        print(f"  Added {len(test_events)} events")
        
        # Run detection
        result = detector.full_detection()
        
        is_anomaly = result['anomaly_detection']['is_anomaly'] if result['anomaly_detection'] else False
        predicted_cause = result['cause_classification']['predicted_cause'] if result['cause_classification'] else 'unknown'
        
        print(f"  Anomaly detected: {is_anomaly}")
        print(f"  Predicted cause: {predicted_cause}")
        
        if expected_anomaly and not is_anomaly:
            print(f"  ⚠️  Expected anomaly but not detected")
        
        return result


class PerformanceProfiler:
    """Profile detection performance"""
    
    @staticmethod
    def profile_detection_speed(detector: RealtimeDetector,
                               n_samples: int = 1000) -> Dict:
        """Measure detection speed"""
        print(f"\nProfiling detection speed ({n_samples} samples)...")
        
        # Generate sample events
        import time
        
        times = {
            'anomaly_detection': [],
            'cause_classification': [],
            'full_detection': [],
        }
        
        for i in range(n_samples):
            # Random event
            event = {
                'pid': np.random.randint(100, 10000),
                'latency_ns': np.random.exponential(1000000),
                'ts_ns': int(time.time() * 1e9) + i * 1000,
                'cpu_id': np.random.randint(0, 8),
                'priority': np.random.randint(-20, 20),
                'comm': f'test_{i}',
            }
            detector.add_event(event)
            
            if i % 100 == 0 and i > 0:
                # Time each detection
                start = time.time()
                detector.detect_anomaly()
                times['anomaly_detection'].append((time.time() - start) * 1000)
                
                start = time.time()
                detector.classify_cause()
                times['cause_classification'].append((time.time() - start) * 1000)
                
                start = time.time()
                detector.full_detection()
                times['full_detection'].append((time.time() - start) * 1000)
        
        results = {}
        for key, vals in times.items():
            if vals:
                results[key] = {
                    'mean_ms': np.mean(vals),
                    'std_ms': np.std(vals),
                    'min_ms': np.min(vals),
                    'max_ms': np.max(vals),
                }
        
        print(f"  Anomaly detection: {results['anomaly_detection']['mean_ms']:.3f} ± {results['anomaly_detection']['std_ms']:.3f} ms")
        print(f"  Cause classification: {results['cause_classification']['mean_ms']:.3f} ± {results['cause_classification']['std_ms']:.3f} ms")
        print(f"  Full detection: {results['full_detection']['mean_ms']:.3f} ± {results['full_detection']['std_ms']:.3f} ms")
        
        return results


class ReportGenerator:
    """Generate analysis reports"""
    
    @staticmethod
    def generate_summary_report(pipeline_config: str,
                               detection_log: str,
                               output_file: str = None) -> Dict:
        """Generate comprehensive summary report"""
        
        if output_file is None:
            output_file = f"ml_model/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Load configurations
        with open(pipeline_config, 'r') as f:
            config = json.load(f)
        
        # Load detection results
        logger = DetectionLogger(detection_log)
        stats = logger.get_anomaly_statistics()
        
        # Compile report
        report = {
            'timestamp': datetime.now().isoformat(),
            'pipeline_config': config,
            'detection_statistics': stats,
        }
        
        # Save report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n✓ Report saved to {output_file}")
        
        return report
    
    @staticmethod
    def print_detection_summary(logger: DetectionLogger):
        """Print detection summary to console"""
        stats = logger.get_anomaly_statistics()
        
        print("\n" + "="*60)
        print("DETECTION SUMMARY")
        print("="*60)
        
        print(f"\nOverall Statistics:")
        print(f"  Total detections: {stats.get('total_detections')}")
        print(f"  Total anomalies: {stats.get('total_anomalies')}")
        print(f"  Anomaly rate: {stats.get('anomaly_percentage', 0):.2f}%")
        print(f"  Average anomaly score: {stats.get('average_anomaly_score', 0):.4f}")
        
        print(f"\nDetected Causes:")
        for cause, count in sorted(
            stats.get('cause_distribution', {}).items(),
            key=lambda x: x[1],
            reverse=True
        ):
            print(f"  {cause}: {count} ({100*count/stats.get('total_detections', 1):.1f}%)")


if __name__ == "__main__":
    print("Utility module - import and use classes directly")
