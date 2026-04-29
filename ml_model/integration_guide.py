"""
Integration Guide: ML Model with eBPF Collector
Step-by-step guide to connect the ML model with your eBPF collector
"""

# ============================================================================
# STEP 1: COLLECT DATA FROM WORKLOADS
# ============================================================================
"""
For each workload, you need to:

1. Start the workload in one terminal:
   $ cd workload
   $ ./1_baseline &

2. Run the collector in another terminal:
   $ cd ebpf_logs
   $ ./collector 0 <pid_of_baseline> 1000 1

   Where:
   - 0 is the workload label (baseline)
   - <pid_of_baseline> is the process ID
   - 1000 is min_latency_us
   - 1 is sample_rate

3. The collector outputs events to ebpf_logs/ebpf_events.csv

Repeat this for each workload (1-8) and save each as:
- ebpf_logs/baseline_events.csv (label 0)
- ebpf_logs/cpu_contention_events.csv (label 1)
- ebpf_logs/disk_io_events.csv (label 3)
etc.
"""


# ============================================================================
# STEP 2: PREPARE DATASET
# ============================================================================

def prepare_dataset_example():
    """Example: Convert collector events to ML features"""
    
    from ml_model.dataset_generator import DatasetGenerator
    
    gen = DatasetGenerator(window_size_ms=100, stride_ms=50)
    
    # List your collected files with their labels
    dataset_files = [
        ('ebpf_logs/baseline_events.csv', 0),
        ('ebpf_logs/cpu_contention_events.csv', 1),
        ('ebpf_logs/heavy_contention_events.csv', 2),
        ('ebpf_logs/disk_io_events.csv', 3),
        ('ebpf_logs/memory_pressure_events.csv', 4),
        ('ebpf_logs/lock_contention_events.csv', 5),
        ('ebpf_logs/ipc_communication_events.csv', 6),
        ('ebpf_logs/context_switching_events.csv', 7),
        ('ebpf_logs/mixed_events.csv', 8),
    ]
    
    # Combine all datasets
    dataset = gen.combine_datasets(dataset_files)
    
    # Save prepared dataset
    gen.save_dataset(dataset, 'ml_model/training_dataset.csv')
    
    print(f"Dataset prepared: {len(dataset)} samples")


# ============================================================================
# STEP 3: TRAIN MODELS
# ============================================================================

def train_models_example():
    """Example: Train anomaly detection and cause classification"""
    
    from ml_model.ml_pipeline import MLPipeline
    import pandas as pd
    
    # Load prepared dataset
    dataset = pd.read_csv('ml_model/training_dataset.csv')
    
    # Initialize pipeline
    pipeline = MLPipeline(output_dir='ml_model')
    
    # Train both models
    pipeline.train_anomaly_detector(dataset, contamination=0.1)
    pipeline.train_cause_classifier(dataset, model_type='random_forest')
    
    # Save configuration
    pipeline.save_pipeline_config()
    
    print("✓ Models trained and saved to ml_model/")


# ============================================================================
# STEP 4: REAL-TIME DETECTION
# ============================================================================

def realtime_detection_example():
    """Example: Run real-time detection on new collector data"""
    
    import csv
    import time
    from ml_model.realtime_detector import RealtimeDetector, DetectionLogger
    
    # Initialize detector with trained models
    detector = RealtimeDetector(
        anomaly_model_path='ml_model/anomaly_detector.pkl',
        cause_model_path='ml_model/cause_classifier.pkl',
        window_size_ms=100,
        alert_threshold=0.7
    )
    
    logger = DetectionLogger('ml_model/detection_results.jsonl')
    
    # Define callback for alerts
    def on_detection(result):
        """Called when detection result is available"""
        logger.log_detection(result)
        
        # Print alerts
        if 'alert' in result and result['alert']:
            print(f"\n⚠️  {result['alert_message']}")
        
        # Print periodic summary
        stats = logger.get_anomaly_statistics()
        if stats.get('total_detections', 0) % 100 == 0:
            print(f"\nProgress: {stats['total_detections']} detections, "
                  f"{stats.get('anomaly_percentage', 0):.1f}% anomalies")
    
    # Start background monitoring
    monitor_thread = detector.start_monitoring(
        callback=on_detection,
        interval_sec=1.0
    )
    
    # Stream events from collector CSV
    try:
        with open('ebpf_logs/ebpf_events.csv', 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                event = {
                    'pid': int(row['pid']),
                    'tgid': int(row['tgid']),
                    'latency_ns': int(row['latency_ns']),
                    'ts_ns': int(row['ts_ns']),
                    'cpu_id': int(row['cpu_id']),
                    'priority': int(row['priority']),
                    'comm': row['comm'],
                }
                
                detector.add_event(event)
                
                # Simulate real-time stream (remove for actual use)
                time.sleep(0.001)
    
    except FileNotFoundError:
        print("Error: ebpf_logs/ebpf_events.csv not found")
    
    finally:
        detector.stop_monitoring()
        print("\n✓ Monitoring stopped")
        
        # Print final statistics
        stats = logger.get_anomaly_statistics()
        print(f"\nFinal Statistics:")
        print(f"  Total detections: {stats.get('total_detections')}")
        print(f"  Total anomalies: {stats.get('total_anomalies')}")
        print(f"  Anomaly rate: {stats.get('anomaly_percentage', 0):.2f}%")


# ============================================================================
# STEP 5: CONTINUOUS MONITORING (Optional)
# ============================================================================

def continuous_monitoring_example():
    """Example: Continuous monitoring with live collector"""
    
    import subprocess
    import csv
    import time
    from pathlib import Path
    from ml_model.realtime_detector import RealtimeDetector, DetectionLogger
    
    # Path to collector output
    events_file = 'ebpf_logs/ebpf_events.csv'
    
    # Initialize detector
    detector = RealtimeDetector(
        anomaly_model_path='ml_model/anomaly_detector.pkl',
        cause_model_path='ml_model/cause_classifier.pkl'
    )
    
    logger = DetectionLogger('ml_model/detection_results.jsonl')
    
    print("Starting continuous monitoring...")
    print("(Collector should be writing to ebpf_logs/ebpf_events.csv)")
    
    # Track last processed line
    last_line = 0
    
    try:
        while True:
            # Check if file exists
            if not Path(events_file).exists():
                print(f"Waiting for {events_file}...")
                time.sleep(5)
                continue
            
            # Read new events
            with open(events_file, 'r') as f:
                lines = f.readlines()
            
            # Process new lines
            if len(lines) > last_line:
                reader = csv.DictReader(lines[last_line:])
                
                for row in reader:
                    event = {
                        'pid': int(row['pid']),
                        'latency_ns': int(row['latency_ns']),
                        'ts_ns': int(row['ts_ns']),
                        'cpu_id': int(row['cpu_id']),
                        'priority': int(row['priority']),
                        'comm': row['comm'],
                    }
                    
                    detector.add_event(event)
                
                # Run detection
                result = detector.full_detection()
                logger.log_detection(result)
                
                if 'alert' in result and result['alert']:
                    print(f"\n⚠️  {result['alert_message']}")
                
                last_line = len(lines)
            
            # Sleep before next check
            time.sleep(1)
    
    except KeyboardInterrupt:
        print("\n✓ Monitoring stopped")
        stats = logger.get_anomaly_statistics()
        print(f"\nFinal Statistics: {stats.get('total_anomalies')} anomalies detected")


# ============================================================================
# COMPLETE WORKFLOW SCRIPT
# ============================================================================

def main():
    """Complete workflow from data collection to deployment"""
    
    import argparse
    
    parser = argparse.ArgumentParser(
        description='ML Model integration with eBPF collector'
    )
    parser.add_argument(
        'action',
        choices=['prepare', 'train', 'detect', 'monitor'],
        help='Action to perform'
    )
    
    args = parser.parse_args()
    
    if args.action == 'prepare':
        print("\n[Step 1] Preparing dataset from collector events...")
        prepare_dataset_example()
    
    elif args.action == 'train':
        print("\n[Step 2] Training models...")
        train_models_example()
    
    elif args.action == 'detect':
        print("\n[Step 3] Running real-time detection...")
        realtime_detection_example()
    
    elif args.action == 'monitor':
        print("\n[Step 4] Starting continuous monitoring...")
        continuous_monitoring_example()


# ============================================================================
# QUICK START COMMANDS
# ============================================================================

"""
QUICK START:

1. Collect data from all workloads:
   for workload in 1_baseline 2_cpu_contention 3_heavy_contention; do
       ./workload/$workload &
       PID=$!
       sleep 1
       SL_BPF_OBJ=ebpf_logs/sl.bpf.o ./ebpf_logs/collector 0 $PID 1000 1
       wait $PID
       mv ebpf_logs/ebpf_events.csv ebpf_logs/${workload}_events.csv
   done

2. Prepare dataset:
   python ml_model/integration_guide.py prepare

3. Train models:
   python ml_model/integration_guide.py train

4. Run detection:
   python ml_model/integration_guide.py detect

5. Start continuous monitoring:
   python ml_model/integration_guide.py monitor

Alternative - Full end-to-end example (with synthetic data):
   python ml_model/example_e2e.py

For more details, see ml_model/README.md
"""

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) == 1:
        print(__doc__)
        print("\nUsage: python integration_guide.py [prepare|train|detect|monitor]")
    else:
        main()
